package trafficspool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/networkprovenance"
	"cyberstrike-ai/internal/traffic"
)

const (
	AggregateKindWebFuzz               = "web-fuzz"
	AggregateKindPathSweep             = "path-sweep"
	AggregateKindUnattributedPathSweep = "unattributed-path-sweep"
	AggregateKindRequestBurst          = "request-burst"
	maximumSummaryPaths                = 32
	maximumDistinctPaths               = 4096
	AggregationModeAll                 = "all"
	AggregationModeTools               = "tools"
	AggregationModeNone                = "none"
)

// CompactConfig bounds how long complete HTTP transactions may be held in
// memory while deciding whether they are ordinary traffic or one high-volume
// behaviour batch. Pending complete bodies are limited by CountThreshold.
type CompactConfig struct {
	BurstWindow       time.Duration
	IdleWindow        time.Duration
	MaximumBatchAge   time.Duration
	CountThreshold    int64
	DistinctThreshold int
	MaximumGroups     int
}

func DefaultCompactConfig() CompactConfig {
	return CompactConfig{
		BurstWindow: 30 * time.Second, IdleWindow: 3 * time.Second,
		MaximumBatchAge: 60 * time.Second, CountThreshold: 8,
		DistinctThreshold: 6, MaximumGroups: 256,
	}
}

type compactRecord struct {
	transaction traffic.Transaction
	messages    []traffic.Message
}

type compactBatch struct {
	representative compactRecord
	pending        []compactRecord
	firstAt        time.Time
	lastAt         time.Time
	firstObserved  time.Time
	lastObserved   time.Time
	count          int64
	highVolume     bool
	bytesUp        int64
	bytesDown      int64
	paths          map[string]struct{}
	statusCounts   map[int]int64
}

// CompactingSink keeps ordinary traffic complete while preventing Web fuzz
// and request bursts from writing every body to disk. It deliberately sits in
// front of the spool Writer so discarded high-volume bodies never enter the
// control-plane database or Docker logs.
type CompactingSink struct {
	mu          sync.Mutex
	destination func(context.Context, traffic.Transaction, []traffic.Message) error
	config      CompactConfig
	batches     map[string]*compactBatch
	stop        chan struct{}
	done        chan struct{}
	closeOnce   sync.Once
	closeErr    error
	mode        string
}

func NewCompactingSink(destination func(context.Context, traffic.Transaction, []traffic.Message) error, config CompactConfig) (*CompactingSink, error) {
	if destination == nil {
		return nil, errors.New("traffic compacting destination is required")
	}
	defaults := DefaultCompactConfig()
	if config.BurstWindow <= 0 {
		config.BurstWindow = defaults.BurstWindow
	}
	if config.IdleWindow <= 0 {
		config.IdleWindow = defaults.IdleWindow
	}
	if config.MaximumBatchAge <= 0 {
		config.MaximumBatchAge = defaults.MaximumBatchAge
	}
	if config.CountThreshold < 2 {
		config.CountThreshold = defaults.CountThreshold
	}
	if config.DistinctThreshold < 2 {
		config.DistinctThreshold = defaults.DistinctThreshold
	}
	if config.MaximumGroups < 1 {
		config.MaximumGroups = defaults.MaximumGroups
	}
	sink := &CompactingSink{
		destination: destination, config: config, batches: make(map[string]*compactBatch),
		stop: make(chan struct{}), done: make(chan struct{}), mode: AggregationModeAll,
	}
	go sink.run()
	return sink, nil
}

func normalizeAggregationMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case AggregationModeAll, AggregationModeTools:
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return AggregationModeNone
	}
}

// SetAggregationMode flushes the complete batch accumulated under the old
// policy before later traffic can be evaluated with the new one.
func (s *CompactingSink) SetAggregationMode(ctx context.Context, mode string) error {
	if s == nil {
		return errors.New("traffic compacting sink is unavailable")
	}
	mode = normalizeAggregationMode(mode)
	s.mu.Lock()
	defer s.mu.Unlock()
	if mode == s.mode {
		return nil
	}
	outputs := s.flushAllLocked()
	if err := s.writeRecords(ctx, outputs); err != nil {
		return err
	}
	s.mode = mode
	return nil
}

func shouldAggregateTransaction(mode string, item traffic.Transaction) bool {
	mode = normalizeAggregationMode(mode)
	if mode == AggregationModeAll {
		return true
	}
	if mode != AggregationModeTools {
		return false
	}
	p := networkprovenance.NetworkProvenanceV1{
		ConversationID: item.ConversationID, RuntimeMode: item.RuntimeMode,
		RuntimeGeneration: item.RuntimeGeneration, RuntimeInstanceID: item.RuntimeInstanceID,
		AgentID: item.AgentID, ToolName: item.ToolName, ExecutionID: item.ExecutionID,
		ToolCallID: item.ToolCallID, ActivityScopeID: item.ActivityScopeID,
		AttributionStatus: item.AttributionStatus, DeclaredActivityKind: item.DeclaredActivityKind,
	}
	return p.ValidVerified() && p.Normalized().DeclaredActivityKind == networkprovenance.ActivityKindFuzz
}

func (s *CompactingSink) Write(ctx context.Context, item traffic.Transaction, messages []traffic.Message) error {
	if s == nil || s.destination == nil {
		return errors.New("traffic compacting sink is unavailable")
	}
	if item.StartedAt.IsZero() {
		item.StartedAt = time.Now().UTC()
	} else {
		item.StartedAt = item.StartedAt.UTC()
	}
	now := time.Now().UTC()
	record := compactRecord{transaction: item, messages: append([]traffic.Message(nil), messages...)}

	s.mu.Lock()
	outputs := s.flushExpiredLocked(now)
	if !shouldAggregateTransaction(s.mode, item) {
		s.mu.Unlock()
		if err := s.writeRecords(ctx, outputs); err != nil {
			return err
		}
		return s.destination(ctx, record.transaction, record.messages)
	}
	key := compactGroupKey(item)
	current := s.batches[key]
	if current != nil && (occurrenceGap(current.lastAt, item.StartedAt) > s.config.IdleWindow ||
		(!current.highVolume && occurrenceSpan(current.firstAt, current.lastAt, item.StartedAt) > s.config.BurstWindow) ||
		now.Sub(current.firstObserved) >= s.config.MaximumBatchAge) {
		outputs = append(outputs, s.flushLocked(key)...)
		current = nil
	}
	if current == nil {
		if len(s.batches) >= s.config.MaximumGroups {
			outputs = append(outputs, s.flushOldestLocked()...)
		}
		current = &compactBatch{
			representative: record,
			firstAt:        item.StartedAt, lastAt: item.StartedAt,
			firstObserved: now, lastObserved: now,
			paths: make(map[string]struct{}), statusCounts: make(map[int]int64),
		}
		s.batches[key] = current
	}
	current.observe(record, now)
	if !current.highVolume && (current.count >= s.config.CountThreshold || len(current.paths) >= s.config.DistinctThreshold) {
		current.highVolume = true
		current.pending = nil
	}
	s.mu.Unlock()

	return s.writeRecords(ctx, outputs)
}

func (b *compactBatch) observe(record compactRecord, observedAt time.Time) {
	item := record.transaction
	b.count++
	b.lastObserved = observedAt
	if item.StartedAt.Before(b.firstAt) {
		b.firstAt = item.StartedAt
	}
	if item.StartedAt.After(b.lastAt) {
		b.lastAt = item.StartedAt
	}
	b.bytesUp += item.BytesUp
	b.bytesDown += item.BytesDown
	if !b.highVolume {
		b.pending = append(b.pending, record)
	}
	if len(b.paths) < maximumDistinctPaths {
		b.paths[item.Path] = struct{}{}
	}
	b.statusCounts[item.HTTPStatus]++
}

func (s *CompactingSink) run() {
	interval := s.config.IdleWindow / 2
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(s.done)
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			outputs := s.flushExpiredLocked(time.Now().UTC())
			s.mu.Unlock()
			if err := s.writeRecords(context.Background(), outputs); err != nil {
				log.Printf("traffic compactor flush failed: %v", err)
			}
		case <-s.stop:
			s.mu.Lock()
			outputs := s.flushAllLocked()
			s.mu.Unlock()
			s.closeErr = s.writeRecords(context.Background(), outputs)
			return
		}
	}
}

func (s *CompactingSink) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() { close(s.stop) })
	<-s.done
	return s.closeErr
}

func (s *CompactingSink) flushExpiredLocked(now time.Time) []compactRecord {
	keys := make([]string, 0)
	for key, current := range s.batches {
		if now.Sub(current.lastObserved) >= s.config.IdleWindow || now.Sub(current.firstObserved) >= s.config.MaximumBatchAge {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var outputs []compactRecord
	for _, key := range keys {
		outputs = append(outputs, s.flushLocked(key)...)
	}
	return outputs
}

func (s *CompactingSink) flushAllLocked() []compactRecord {
	keys := make([]string, 0, len(s.batches))
	for key := range s.batches {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var outputs []compactRecord
	for _, key := range keys {
		outputs = append(outputs, s.flushLocked(key)...)
	}
	return outputs
}

func (s *CompactingSink) flushOldestLocked() []compactRecord {
	var oldestKey string
	var oldest time.Time
	for key, current := range s.batches {
		if oldestKey == "" || current.firstObserved.Before(oldest) {
			oldestKey, oldest = key, current.firstObserved
		}
	}
	return s.flushLocked(oldestKey)
}

func (s *CompactingSink) flushLocked(key string) []compactRecord {
	current := s.batches[key]
	if current == nil {
		return nil
	}
	delete(s.batches, key)
	if !current.highVolume {
		return append([]compactRecord(nil), current.pending...)
	}

	representative := current.representative
	paths := make([]string, 0, len(current.paths))
	for path := range current.paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	summaryPaths := paths
	if len(summaryPaths) > maximumSummaryPaths {
		summaryPaths = summaryPaths[:maximumSummaryPaths]
	}
	statusCounts := make(map[string]int64, len(current.statusCounts))
	for status, count := range current.statusCounts {
		statusCounts[strconv.Itoa(status)] = count
	}
	summary, _ := json.Marshal(struct {
		DistinctPaths int              `json:"distinct_paths"`
		Paths         []string         `json:"representative_paths"`
		StatusCounts  map[string]int64 `json:"status_counts"`
	}{DistinctPaths: len(paths), Paths: summaryPaths, StatusCounts: statusCounts})

	firstAt, lastAt := current.firstAt.UTC(), current.lastAt.UTC()
	representative.transaction.AggregateKind = AggregateKindRequestBurst
	representative.transaction.ObservedActivityKind = networkprovenance.ObservedBurst
	if len(paths) >= s.config.DistinctThreshold {
		representative.transaction.ObservedActivityKind = networkprovenance.ObservedPathSweep
		switch {
		case representative.transaction.DeclaredActivityKind == networkprovenance.ActivityKindFuzz:
			representative.transaction.AggregateKind = AggregateKindWebFuzz
		case representative.transaction.AttributionStatus == networkprovenance.AttributionUnattributed || representative.transaction.AttributionStatus == networkprovenance.AttributionLegacyUnattributed:
			representative.transaction.AggregateKind = AggregateKindUnattributedPathSweep
		default:
			representative.transaction.AggregateKind = AggregateKindPathSweep
		}
	}
	representative.transaction.AggregateCount = current.count
	representative.transaction.AggregateFirstAt = &firstAt
	representative.transaction.AggregateLastAt = &lastAt
	representative.transaction.AggregateSummaryJSON = string(summary)
	representative.transaction.BytesUp = current.bytesUp
	representative.transaction.BytesDown = current.bytesDown
	return []compactRecord{representative}
}

func (s *CompactingSink) writeRecords(ctx context.Context, records []compactRecord) error {
	var result error
	for _, record := range records {
		if err := s.destination(ctx, record.transaction, record.messages); err != nil {
			result = errors.Join(result, fmt.Errorf("write traffic transaction %s: %w", record.transaction.ID, err))
		}
	}
	return result
}

func compactGroupKey(item traffic.Transaction) string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(item.Scheme)),
		strings.ToLower(strings.TrimSpace(item.Host)),
		strconv.Itoa(item.Port),
		strings.TrimSpace(item.RuleID),
		strings.TrimSpace(item.RuntimeMode),
		strconv.Itoa(item.RuntimeGeneration),
		strings.TrimSpace(item.RuntimeInstanceID),
		strings.TrimSpace(item.AgentID),
		strings.TrimSpace(item.ToolName),
		strings.TrimSpace(item.ExecutionID),
		strings.TrimSpace(item.ToolCallID),
		strings.TrimSpace(item.ActivityScopeID),
		strings.TrimSpace(item.AttributionStatus),
		strings.TrimSpace(item.DeclaredActivityKind),
		strings.TrimSpace(item.UpstreamRouteID),
	}, "|")
}

func occurrenceGap(previous, next time.Time) time.Duration {
	if previous.IsZero() || next.IsZero() || !next.After(previous) {
		return 0
	}
	return next.Sub(previous)
}

func occurrenceSpan(first, last, next time.Time) time.Duration {
	if next.Before(first) {
		first = next
	}
	if next.After(last) {
		last = next
	}
	return last.Sub(first)
}
