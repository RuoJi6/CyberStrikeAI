package egressactivity

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/networkprovenance"
)

const (
	ModeCompact = "compact"
	ModeFull    = "full"
	ModeOff     = "off"

	AggregationModeAll   = "all"
	AggregationModeTools = "tools"
	AggregationModeNone  = "none"
)

type Config struct {
	BurstWindow       time.Duration
	IdleWindow        time.Duration
	MaximumBatchAge   time.Duration
	SlowBurstWindow   time.Duration
	SlowIdleWindow    time.Duration
	SlowMaximumAge    time.Duration
	CountThreshold    int64
	DistinctThreshold int
}

func DefaultConfig() Config {
	return Config{
		BurstWindow: 3 * time.Second, IdleWindow: 750 * time.Millisecond,
		MaximumBatchAge: 30 * time.Second,
		// Direct TCP/UDP security checks are often paced by handshake or
		// authentication timeouts. Keep those behaviour batches open longer
		// without delaying HTTP, DNS, CONNECT or ICMP activity.
		SlowBurstWindow: 30 * time.Second, SlowIdleWindow: 15 * time.Second,
		SlowMaximumAge: 5 * time.Minute, CountThreshold: 8, DistinctThreshold: 6,
	}
}

type batch struct {
	first         egress.ActivityEvent
	pending       []egress.ActivityEvent
	firstAt       time.Time
	lastAt        time.Time
	firstObserved time.Time
	lastObserved  time.Time
	count         int64
	fuzz          bool
	bytesUp       int64
	bytesDown     int64
	targets       map[string]struct{}
	ports         map[int]struct{}
	variants      map[string]struct{}
}

// Aggregator detects high-volume network batches from protocol behaviour,
// rather than from a closed list of tool names. Candidate events are held for
// at most BurstWindow. Normal traffic is released unchanged; a detected batch
// is represented by its first complete sample plus bounded aggregate metadata.
type Aggregator struct {
	config  Config
	batches map[string]*batch
}

func New(config Config) *Aggregator {
	defaults := DefaultConfig()
	if config.BurstWindow <= 0 {
		config.BurstWindow = defaults.BurstWindow
	}
	if config.IdleWindow <= 0 {
		config.IdleWindow = defaults.IdleWindow
	}
	if config.MaximumBatchAge <= 0 {
		config.MaximumBatchAge = defaults.MaximumBatchAge
	}
	if config.SlowBurstWindow <= 0 {
		config.SlowBurstWindow = defaults.SlowBurstWindow
	}
	if config.SlowIdleWindow <= 0 {
		config.SlowIdleWindow = defaults.SlowIdleWindow
	}
	if config.SlowMaximumAge <= 0 {
		config.SlowMaximumAge = defaults.SlowMaximumAge
	}
	if config.CountThreshold < 2 {
		config.CountThreshold = defaults.CountThreshold
	}
	if config.DistinctThreshold < 2 {
		config.DistinctThreshold = defaults.DistinctThreshold
	}
	return &Aggregator{config: config, batches: make(map[string]*batch)}
}

func NormalizeMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case ModeFull:
		return ModeFull
	case ModeOff:
		return ModeOff
	default:
		return ModeCompact
	}
}

// NormalizeAggregationMode returns the safe evidence-preserving mode. Unknown
// values deliberately become none so a corrupt policy can never discard
// individual events.
func NormalizeAggregationMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case AggregationModeAll:
		return AggregationModeAll
	case AggregationModeTools:
		return AggregationModeTools
	default:
		return AggregationModeNone
	}
}

func ValidAggregationMode(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case AggregationModeAll, AggregationModeTools, AggregationModeNone:
		return true
	default:
		return false
	}
}

// ShouldAggregate applies the conversation policy to one normalized activity.
// Container non-HTTP activity cannot carry process-level attribution today, so
// tools retains the existing behavioural aggregation for those protocols.
func ShouldAggregate(mode string, event egress.ActivityEvent) bool {
	mode = NormalizeAggregationMode(mode)
	if mode == AggregationModeNone || event.RequestType == egress.ActivityRequestHealth {
		return false
	}
	if mode == AggregationModeAll {
		return true
	}
	switch event.RequestType {
	case egress.ActivityRequestHTTP, egress.ActivityRequestHTTPS, egress.ActivityRequestCONNECT:
		p := event.Provenance.Normalized()
		return p.ValidVerified() && p.DeclaredActivityKind == networkprovenance.ActivityKindFuzz
	default:
		return true
	}
}

func (a *Aggregator) Observe(event egress.ActivityEvent) []egress.ActivityEvent {
	return a.ObserveAt(event, event.Timestamp)
}

// ObserveAt separates gateway occurrence time from collector receipt time.
// Occurrence gaps define behavioural batch boundaries, so historical Docker
// log replay and live collection produce the same batches. Receipt time is
// used only to decide when an otherwise active stream has become quiet.
func (a *Aggregator) ObserveAt(event egress.ActivityEvent, observedAt time.Time) []egress.ActivityEvent {
	if event.RequestType == egress.ActivityRequestHealth {
		return []egress.ActivityEvent{event}
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	} else {
		observedAt = observedAt.UTC()
	}
	key := activityGroupKey(event)
	current := a.batches[key]
	outputs := make([]egress.ActivityEvent, 0, 2)
	if current != nil && occurrenceIdleGap(current, event.Timestamp) > a.idleWindow(current.first.RequestType) {
		outputs = append(outputs, a.flush(key)...)
		current = nil
	}
	outputs = append(outputs, a.FlushExpired(observedAt)...)
	current = a.batches[key]
	if current != nil && !current.fuzz && occurrenceSpan(current, event.Timestamp) > a.burstWindow(current.first.RequestType) {
		outputs = append(outputs, a.flush(key)...)
		current = nil
	}
	if current != nil && current.fuzz && observedAt.Sub(current.firstObserved) >= a.maximumAge(current.first.RequestType) {
		outputs = append(outputs, a.flush(key)...)
		current = nil
	}
	if current == nil {
		current = &batch{
			first: event, firstAt: event.Timestamp, lastAt: event.Timestamp,
			firstObserved: observedAt, lastObserved: observedAt,
			targets: make(map[string]struct{}), ports: make(map[int]struct{}), variants: make(map[string]struct{}),
		}
		a.batches[key] = current
	}
	current.observe(event, observedAt)
	if !current.fuzz && a.isHighVolume(current) {
		current.fuzz = true
		current.pending = nil
	}
	return outputs
}

func (a *Aggregator) FlushExpired(now time.Time) []egress.ActivityEvent {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	keys := make([]string, 0)
	for key, current := range a.batches {
		if now.Sub(current.lastObserved) >= a.batchIdleWindow(current) || now.Sub(current.firstObserved) >= a.maximumAge(current.first.RequestType) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	result := make([]egress.ActivityEvent, 0, len(keys))
	for _, key := range keys {
		result = append(result, a.flush(key)...)
	}
	return result
}

func (a *Aggregator) FlushAll() []egress.ActivityEvent {
	keys := make([]string, 0, len(a.batches))
	for key := range a.batches {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]egress.ActivityEvent, 0, len(keys))
	for _, key := range keys {
		result = append(result, a.flush(key)...)
	}
	return result
}

func (b *batch) observe(event egress.ActivityEvent, observedAt time.Time) {
	b.count++
	b.lastObserved = observedAt
	if event.Timestamp.Before(b.firstAt) {
		b.firstAt = event.Timestamp
	}
	if event.Timestamp.After(b.lastAt) {
		b.lastAt = event.Timestamp
	}
	b.bytesUp += event.BytesUp
	b.bytesDown += event.BytesDown
	if !b.fuzz {
		b.pending = append(b.pending, event)
	}
	target := strings.ToLower(strings.TrimSpace(event.Domain))
	if target == "" {
		target = strings.TrimSpace(event.ConnectedIP)
	}
	if target != "" {
		b.targets[target] = struct{}{}
	}
	if event.Port > 0 {
		b.ports[event.Port] = struct{}{}
	}
	variant := activityVariant(event)
	if variant != "" {
		b.variants[variant] = struct{}{}
	}
}

func (a *Aggregator) isHighVolume(current *batch) bool {
	if current.lastAt.Sub(current.firstAt) > a.burstWindow(current.first.RequestType) {
		return false
	}
	return current.count >= a.config.CountThreshold || len(current.targets) >= a.config.DistinctThreshold ||
		len(current.ports) >= a.config.DistinctThreshold || len(current.variants) >= a.config.DistinctThreshold
}

func isSlowConnectionType(requestType string) bool {
	return requestType == egress.ActivityRequestTCP || requestType == egress.ActivityRequestUDP
}

func (a *Aggregator) burstWindow(requestType string) time.Duration {
	if isSlowConnectionType(requestType) {
		return a.config.SlowBurstWindow
	}
	return a.config.BurstWindow
}

func (a *Aggregator) idleWindow(requestType string) time.Duration {
	if isSlowConnectionType(requestType) {
		return a.config.SlowIdleWindow
	}
	return a.config.IdleWindow
}

func (a *Aggregator) batchIdleWindow(current *batch) time.Duration {
	if current == nil || !isSlowConnectionType(current.first.RequestType) {
		return a.config.IdleWindow
	}
	// Once a multi-port or multi-target scan is identified, it can be emitted
	// promptly. Slow authentication/fuzz against one endpoint keeps the longer
	// quiet window so paced attempts remain one behavioural batch.
	if current.fuzz && (len(current.ports) >= a.config.DistinctThreshold || len(current.targets) >= a.config.DistinctThreshold) {
		return a.config.IdleWindow
	}
	return a.config.SlowIdleWindow
}

func (a *Aggregator) maximumAge(requestType string) time.Duration {
	if isSlowConnectionType(requestType) {
		return a.config.SlowMaximumAge
	}
	return a.config.MaximumBatchAge
}

func occurrenceIdleGap(current *batch, eventAt time.Time) time.Duration {
	if current == nil || eventAt.IsZero() || current.lastAt.IsZero() || !eventAt.After(current.lastAt) {
		return 0
	}
	return eventAt.Sub(current.lastAt)
}

func occurrenceSpan(current *batch, eventAt time.Time) time.Duration {
	if current == nil || eventAt.IsZero() || current.firstAt.IsZero() {
		return 0
	}
	firstAt, lastAt := current.firstAt, current.lastAt
	if eventAt.Before(firstAt) {
		firstAt = eventAt
	}
	if eventAt.After(lastAt) {
		lastAt = eventAt
	}
	return lastAt.Sub(firstAt)
}

func (a *Aggregator) flush(key string) []egress.ActivityEvent {
	current := a.batches[key]
	if current == nil {
		return nil
	}
	delete(a.batches, key)
	if !current.fuzz {
		return append([]egress.ActivityEvent(nil), current.pending...)
	}
	first := current.first
	first.AggregateCount = current.count
	first.AggregateKind = aggregateKind(first, len(current.targets), len(current.ports), len(current.variants), a.config.DistinctThreshold)
	first.Provenance.ObservedActivityKind = networkprovenance.ObservedBurst
	if (first.RequestType == egress.ActivityRequestHTTP || first.RequestType == egress.ActivityRequestHTTPS) && len(current.variants) >= a.config.DistinctThreshold {
		first.Provenance.ObservedActivityKind = networkprovenance.ObservedPathSweep
	}
	firstAt, lastAt := current.firstAt, current.lastAt
	first.AggregateFirstAt = &firstAt
	first.AggregateLastAt = &lastAt
	first.AggregateDistinctTargets = len(current.targets)
	first.AggregateDistinctPorts = len(current.ports)
	first.AggregateDistinctVariants = len(current.variants)
	first.BytesUp = current.bytesUp
	first.BytesDown = current.bytesDown
	return []egress.ActivityEvent{first}
}

func activityGroupKey(event egress.ActivityEvent) string {
	p := event.Provenance.Normalized()
	blockMatch, _ := json.Marshal(event.BlockMatch)
	base := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s", event.RequestType, event.Decision, event.RuleID, event.Reason, event.SnapshotID,
		p.RuntimeMode, p.RuntimeGeneration, p.RuntimeInstanceID, p.AgentID, p.ToolName, p.ExecutionID, p.ToolCallID, p.ActivityScopeID, p.AttributionStatus, p.DeclaredActivityKind)
	base += "|" + string(blockMatch)
	switch event.RequestType {
	case egress.ActivityRequestHTTP, egress.ActivityRequestHTTPS, egress.ActivityRequestCONNECT:
		return base + "|" + strings.ToLower(strings.TrimSpace(event.Domain))
	case egress.ActivityRequestDNS:
		return base + "|" + strings.ToLower(strings.TrimSpace(event.DNSQueryType))
	default:
		// Direct TCP/UDP/ICMP scans commonly vary both destination and port.
		// Conversation/runtime isolation is supplied by the owning stream.
		return base
	}
}

func activityVariant(event egress.ActivityEvent) string {
	switch event.RequestType {
	case egress.ActivityRequestHTTP, egress.ActivityRequestHTTPS:
		return strings.ToUpper(strings.TrimSpace(event.Method)) + " " + strings.TrimSpace(event.Path)
	case egress.ActivityRequestDNS:
		return strings.ToLower(strings.TrimSpace(event.Domain))
	default:
		return fmt.Sprintf("%s:%d", strings.ToLower(strings.TrimSpace(event.Domain)), event.Port)
	}
}

func aggregateKind(event egress.ActivityEvent, targets, ports, variants, threshold int) string {
	requestType := event.RequestType
	switch {
	case requestType == egress.ActivityRequestDNS && variants >= threshold:
		return "dns-enumeration"
	case (requestType == egress.ActivityRequestHTTP || requestType == egress.ActivityRequestHTTPS) && variants >= threshold:
		provenance := event.Provenance.Normalized()
		if provenance.DeclaredActivityKind == networkprovenance.ActivityKindFuzz {
			return "web-fuzz"
		}
		if provenance.AttributionStatus == networkprovenance.AttributionUnattributed || provenance.AttributionStatus == networkprovenance.AttributionLegacyUnattributed {
			return "unattributed-path-sweep"
		}
		return "path-sweep"
	case ports >= threshold:
		return "port-scan"
	case targets >= threshold:
		return "target-scan"
	case requestType == egress.ActivityRequestTCP || requestType == egress.ActivityRequestCONNECT:
		return "connection-burst"
	case requestType == egress.ActivityRequestUDP:
		return "datagram-burst"
	default:
		return "request-burst"
	}
}
