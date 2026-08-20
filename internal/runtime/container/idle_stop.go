package container

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type IdleRuntimeCandidate struct {
	ConversationID string    `json:"conversationId"`
	LastActivityAt time.Time `json:"lastActivityAt"`
}

type IdleStopReport struct {
	Candidates  int `json:"candidates"`
	ActiveTasks int `json:"activeTasks"`
	Stopped     int `json:"stopped"`
	Skipped     int `json:"skipped"`
	Failed      int `json:"failed"`
}

type IdleRuntimeStore interface {
	ListIdleRuntimeCandidates(ctx context.Context, inactiveBefore time.Time, limit int) ([]IdleRuntimeCandidate, error)
}

type ConversationTaskActivity interface {
	ConversationTaskRuntimeState(conversationID string) (running bool, startedAt time.Time)
}

type IdleStopLifecycle interface {
	StopIdle(ctx context.Context, conversationID string, inactiveBefore time.Time) (InitializationRecord, error)
}

type IdleStopSchedulerOptions struct {
	IdleAfter        time.Duration
	BatchSize        int
	OperationTimeout time.Duration
	Clock            func() time.Time
}

// IdleStopScheduler only requests the existing stop lifecycle operation. It
// has no delete or workspace-removal dependency by construction.
type IdleStopScheduler struct {
	store     IdleRuntimeStore
	lifecycle IdleStopLifecycle
	activity  ConversationTaskActivity
	options   IdleStopSchedulerOptions
}

func NewIdleStopScheduler(store IdleRuntimeStore, lifecycle IdleStopLifecycle, activity ConversationTaskActivity, options IdleStopSchedulerOptions) (*IdleStopScheduler, error) {
	if store == nil || lifecycle == nil || activity == nil {
		return nil, invalidSpec("idle stop scheduler requires a store, lifecycle controller and task activity provider")
	}
	if options.BatchSize == 0 {
		options.BatchSize = 128
	}
	if options.OperationTimeout == 0 {
		options.OperationTimeout = 30 * time.Second
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.IdleAfter <= 0 || options.BatchSize < 1 || options.BatchSize > 4096 || options.OperationTimeout <= 0 {
		return nil, invalidSpec("idle stop duration, batch size and operation timeout must be positive")
	}
	return &IdleStopScheduler{store: store, lifecycle: lifecycle, activity: activity, options: options}, nil
}

func (s *IdleStopScheduler) Reconcile(ctx context.Context) (IdleStopReport, error) {
	var report IdleStopReport
	if ctx == nil {
		return report, invalidSpec("context is required")
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	cutoff := s.options.Clock().UTC().Add(-s.options.IdleAfter)
	candidates, err := s.store.ListIdleRuntimeCandidates(ctx, cutoff, s.options.BatchSize)
	if err != nil {
		return report, fmt.Errorf("list idle container candidates: %w", err)
	}
	report.Candidates = len(candidates)
	var stopErrors []error
	for _, candidate := range candidates {
		conversationID := strings.TrimSpace(candidate.ConversationID)
		if conversationID == "" {
			report.Failed++
			stopErrors = append(stopErrors, invalidSpec("idle candidate conversation id is invalid"))
			continue
		}
		if running, _ := s.activity.ConversationTaskRuntimeState(conversationID); running {
			report.ActiveTasks++
			continue
		}
		operationCtx, cancel := context.WithTimeout(ctx, s.options.OperationTimeout)
		_, stopErr := s.lifecycle.StopIdle(operationCtx, conversationID, cutoff)
		cancel()
		if stopErr == nil {
			report.Stopped++
			continue
		}
		if errors.Is(stopErr, ErrRuntimeStateConflict) || errors.Is(stopErr, ErrNotFound) {
			report.Skipped++
			continue
		}
		report.Failed++
		stopErrors = append(stopErrors, fmt.Errorf("stop idle conversation %s: %w", conversationID, stopErr))
	}
	return report, errors.Join(stopErrors...)
}

func (s *IdleStopScheduler) RunPeriodic(ctx context.Context, interval time.Duration, observe func(IdleStopReport, error)) error {
	if ctx == nil {
		return invalidSpec("context is required")
	}
	if interval <= 0 {
		return invalidSpec("idle stop scan interval must be positive")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			report, err := s.Reconcile(ctx)
			if observe != nil {
				observe(report, err)
			}
		}
	}
}
