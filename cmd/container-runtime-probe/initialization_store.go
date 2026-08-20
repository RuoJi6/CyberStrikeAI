package main

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	containerruntime "cyberstrike-ai/internal/runtime/container"
)

// probeInitializationStore is intentionally process-local. The production
// application uses the SQLite-backed durable store; this implementation lets a
// static cross-compiled diagnostic binary exercise the same async coordinator.
type probeInitializationStore struct {
	mu      sync.Mutex
	records map[string]containerruntime.InitializationRecord
}

func newProbeInitializationStore() *probeInitializationStore {
	return &probeInitializationStore{records: make(map[string]containerruntime.InitializationRecord)}
}

func (s *probeInitializationStore) Get(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
	if err := contextError(ctx); err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[conversationID]
	if !ok {
		return record, fmt.Errorf("%w: probe container initialization", containerruntime.ErrNotFound)
	}
	return record, nil
}

func (s *probeInitializationStore) Queue(ctx context.Context, spec containerruntime.RuntimeSpec, retryFailed bool) (containerruntime.InitializationRecord, bool, error) {
	if err := contextError(ctx); err != nil {
		return containerruntime.InitializationRecord{}, false, err
	}
	if err := containerruntime.ValidateSpec(spec); err != nil {
		return containerruntime.InitializationRecord{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if record, ok := s.records[spec.ConversationID]; ok {
		if !reflect.DeepEqual(record.Spec, spec) {
			return record, false, fmt.Errorf("%w: probe runtime specification is immutable", containerruntime.ErrRuntimeStateConflict)
		}
		if retryFailed && record.Status == containerruntime.InitializationCreated && record.ReadinessStatus == containerruntime.ReadinessFailed {
			now := time.Now().UTC()
			record.ReadinessStatus = containerruntime.ReadinessPending
			record.ReadinessError = ""
			record.InventoryDigest = ""
			record.ToolCount = 0
			record.ReadinessStartedAt = nil
			record.ReadinessCompletedAt = nil
			record.LifecycleOperation = containerruntime.LifecycleOperationNone
			record.LifecycleState = containerruntime.LifecycleIdle
			record.LifecycleError = ""
			record.RuntimeGeneration = 0
			record.RuntimeObservedAt = nil
			record.LifecycleStartedAt = nil
			record.LifecycleCompletedAt = nil
			record.RuntimeDrift = ""
			record.UpdatedAt = now
			s.records[spec.ConversationID] = record
			return record, true, nil
		}
		if retryFailed && record.Status == containerruntime.InitializationFailed {
			now := time.Now().UTC()
			record.Status = containerruntime.InitializationQueued
			record.ProviderID = ""
			record.RuntimeStatus = ""
			record.LastError = ""
			record.RequestedAt = now
			record.StartedAt = nil
			record.CompletedAt = nil
			record.ReadinessStatus = readinessStatus(spec)
			record.ReadinessError = ""
			record.InventoryDigest = ""
			record.ToolCount = 0
			record.ReadinessStartedAt = nil
			record.ReadinessCompletedAt = nil
			record.UpdatedAt = now
			s.records[spec.ConversationID] = record
			return record, true, nil
		}
		return record, false, nil
	}
	now := time.Now().UTC()
	record := containerruntime.InitializationRecord{
		ConversationID:     spec.ConversationID,
		RuntimeID:          spec.ID,
		Status:             containerruntime.InitializationQueued,
		ImageDigest:        spec.Image.Digest,
		ImagePlatform:      spec.Image.Platform,
		ReadinessStatus:    readinessStatus(spec),
		LifecycleOperation: containerruntime.LifecycleOperationNone,
		LifecycleState:     containerruntime.LifecycleIdle,
		Spec:               spec,
		RequestedAt:        now,
		UpdatedAt:          now,
	}
	s.records[spec.ConversationID] = record
	return record, true, nil
}

func (s *probeInitializationStore) ClaimReadiness(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, bool, error) {
	if err := contextError(ctx); err != nil {
		return containerruntime.InitializationRecord{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[conversationID]
	if !ok {
		return record, false, fmt.Errorf("%w: probe container initialization", containerruntime.ErrNotFound)
	}
	if record.Status != containerruntime.InitializationCreated || record.ReadinessStatus != containerruntime.ReadinessPending {
		return record, false, nil
	}
	now := time.Now().UTC()
	record.ReadinessStatus = containerruntime.ReadinessValidating
	record.ReadinessError = ""
	record.ReadinessStartedAt = &now
	record.ReadinessCompletedAt = nil
	record.UpdatedAt = now
	s.records[conversationID] = record
	return record, true, nil
}

func (s *probeInitializationStore) Ready(ctx context.Context, conversationID string, report containerruntime.ReadinessReport) (containerruntime.InitializationRecord, error) {
	return s.finish(ctx, conversationID, func(record *containerruntime.InitializationRecord, now time.Time) error {
		if record.Status != containerruntime.InitializationCreated || record.ReadinessStatus != containerruntime.ReadinessValidating {
			return fmt.Errorf("%w: cannot complete probe readiness", containerruntime.ErrRuntimeStateConflict)
		}
		record.ReadinessStatus = containerruntime.ReadinessReady
		record.ReadinessError = ""
		record.InventoryDigest = report.InventoryDigest
		record.ToolCount = report.ToolCount
		record.ReadinessCompletedAt = &now
		return nil
	})
}

func (s *probeInitializationStore) FailReadiness(ctx context.Context, conversationID, message string) (containerruntime.InitializationRecord, error) {
	return s.finish(ctx, conversationID, func(record *containerruntime.InitializationRecord, now time.Time) error {
		if record.Status != containerruntime.InitializationCreated || record.ReadinessStatus != containerruntime.ReadinessValidating {
			return fmt.Errorf("%w: cannot fail probe readiness", containerruntime.ErrRuntimeStateConflict)
		}
		record.ReadinessStatus = containerruntime.ReadinessFailed
		record.ReadinessError = message
		record.ReadinessCompletedAt = &now
		return nil
	})
}

func (s *probeInitializationStore) Claim(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, bool, error) {
	if err := contextError(ctx); err != nil {
		return containerruntime.InitializationRecord{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[conversationID]
	if !ok {
		return record, false, fmt.Errorf("%w: probe container initialization", containerruntime.ErrNotFound)
	}
	if record.Status != containerruntime.InitializationQueued {
		return record, false, nil
	}
	now := time.Now().UTC()
	record.Status = containerruntime.InitializationCreating
	record.Attempt++
	record.StartedAt = &now
	record.CompletedAt = nil
	record.LastError = ""
	record.UpdatedAt = now
	s.records[conversationID] = record
	return record, true, nil
}

func (s *probeInitializationStore) Complete(ctx context.Context, conversationID string, runtime containerruntime.Runtime) (containerruntime.InitializationRecord, error) {
	return s.finish(ctx, conversationID, func(record *containerruntime.InitializationRecord, now time.Time) error {
		if record.Status != containerruntime.InitializationCreating || record.RuntimeID != runtime.ID {
			return fmt.Errorf("%w: cannot complete probe initialization", containerruntime.ErrRuntimeStateConflict)
		}
		record.Status = containerruntime.InitializationCreated
		record.ProviderID = runtime.ProviderID
		record.RuntimeStatus = runtime.Status
		record.LastError = ""
		record.CompletedAt = &now
		record.LifecycleOperation = containerruntime.LifecycleOperationNone
		record.LifecycleState = containerruntime.LifecycleIdle
		record.RuntimeGeneration = 1
		record.RuntimeObservedAt = &now
		record.LifecycleCompletedAt = &now
		return nil
	})
}

func (s *probeInitializationStore) Fail(ctx context.Context, conversationID, message string) (containerruntime.InitializationRecord, error) {
	return s.finish(ctx, conversationID, func(record *containerruntime.InitializationRecord, now time.Time) error {
		if record.Status != containerruntime.InitializationQueued && record.Status != containerruntime.InitializationCreating {
			return fmt.Errorf("%w: cannot fail probe initialization", containerruntime.ErrRuntimeStateConflict)
		}
		record.Status = containerruntime.InitializationFailed
		record.LastError = message
		record.CompletedAt = &now
		return nil
	})
}

func (s *probeInitializationStore) RecoverInterrupted(ctx context.Context) ([]containerruntime.InitializationRecord, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]containerruntime.InitializationRecord, 0)
	for conversationID, record := range s.records {
		if record.Status == containerruntime.InitializationCreating {
			record.Status = containerruntime.InitializationQueued
			record.StartedAt = nil
			record.CompletedAt = nil
			record.UpdatedAt = time.Now().UTC()
			s.records[conversationID] = record
		}
		if record.Status == containerruntime.InitializationCreated && record.ReadinessStatus == containerruntime.ReadinessValidating {
			record.ReadinessStatus = containerruntime.ReadinessPending
			record.ReadinessStartedAt = nil
			record.ReadinessCompletedAt = nil
			record.UpdatedAt = time.Now().UTC()
			s.records[conversationID] = record
		}
		if record.Status == containerruntime.InitializationQueued || (record.Status == containerruntime.InitializationCreated && record.ReadinessStatus == containerruntime.ReadinessPending) {
			records = append(records, record)
		}
	}
	return records, nil
}

func readinessStatus(spec containerruntime.RuntimeSpec) containerruntime.ReadinessStatus {
	if spec.Readiness.Enabled {
		return containerruntime.ReadinessPending
	}
	return containerruntime.ReadinessNotRequired
}

func (s *probeInitializationStore) finish(ctx context.Context, conversationID string, mutate func(*containerruntime.InitializationRecord, time.Time) error) (containerruntime.InitializationRecord, error) {
	if err := contextError(ctx); err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[conversationID]
	if !ok {
		return record, fmt.Errorf("%w: probe container initialization", containerruntime.ErrNotFound)
	}
	now := time.Now().UTC()
	if err := mutate(&record, now); err != nil {
		return record, err
	}
	record.UpdatedAt = now
	s.records[conversationID] = record
	return record, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", containerruntime.ErrInvalidSpecification)
	}
	return ctx.Err()
}

var _ containerruntime.InitializationStore = (*probeInitializationStore)(nil)
