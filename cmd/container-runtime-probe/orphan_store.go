package main

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	containerruntime "cyberstrike-ai/internal/runtime/container"
)

type probeOrphanStore struct {
	mu         sync.Mutex
	tombstones map[string]containerruntime.ResourceTombstone
}

func newProbeOrphanStore() *probeOrphanStore {
	return &probeOrphanStore{tombstones: make(map[string]containerruntime.ResourceTombstone)}
}

func (s *probeOrphanStore) ListManagedResourceClaims(ctx context.Context) ([]containerruntime.ManagedResourceClaim, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *probeOrphanStore) DiscoverResourceTombstone(ctx context.Context, resource containerruntime.ManagedResource, now time.Time) (containerruntime.ResourceTombstone, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return containerruntime.ResourceTombstone{}, false, err
	}
	key := probeTombstoneKey(resource)
	if existing, ok := s.tombstones[key]; ok {
		return existing, false, nil
	}
	tombstone := containerruntime.ResourceTombstone{
		Resource: resource, Status: containerruntime.ResourceTombstonePending,
		DiscoveredAt: now, UpdatedAt: now,
	}
	s.tombstones[key] = tombstone
	return tombstone, true, nil
}

func (s *probeOrphanStore) RecoverResourceTombstones(ctx context.Context, interruptedBefore, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var recovered int64
	for key, tombstone := range s.tombstones {
		if tombstone.Status != containerruntime.ResourceTombstoneDeleting || tombstone.UpdatedAt.After(interruptedBefore) {
			continue
		}
		tombstone.Status = containerruntime.ResourceTombstoneFailed
		tombstone.LastError = "interrupted probe cleanup"
		tombstone.NextRetryAt = probeTimePointer(now)
		tombstone.UpdatedAt = now
		s.tombstones[key] = tombstone
		recovered++
	}
	return recovered, nil
}

func (s *probeOrphanStore) ListRetryableResourceTombstones(ctx context.Context, now time.Time, limit int) ([]containerruntime.ResourceTombstone, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(s.tombstones))
	for key, tombstone := range s.tombstones {
		if tombstone.Status != containerruntime.ResourceTombstonePending && tombstone.Status != containerruntime.ResourceTombstoneFailed {
			continue
		}
		if tombstone.NextRetryAt != nil && tombstone.NextRetryAt.After(now) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	result := make([]containerruntime.ResourceTombstone, 0, len(keys))
	for _, key := range keys {
		result = append(result, s.tombstones[key])
	}
	return result, nil
}

func (s *probeOrphanStore) ClaimResourceTombstone(ctx context.Context, resource containerruntime.ManagedResource, now time.Time) (containerruntime.ResourceTombstone, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return containerruntime.ResourceTombstone{}, false, err
	}
	key := probeTombstoneKey(resource)
	tombstone, ok := s.tombstones[key]
	if !ok {
		return tombstone, false, fmt.Errorf("%w: probe tombstone", containerruntime.ErrNotFound)
	}
	if tombstone.Status != containerruntime.ResourceTombstonePending && tombstone.Status != containerruntime.ResourceTombstoneFailed {
		return tombstone, false, nil
	}
	if tombstone.NextRetryAt != nil && tombstone.NextRetryAt.After(now) {
		return tombstone, false, nil
	}
	tombstone.Status = containerruntime.ResourceTombstoneDeleting
	tombstone.Attempt++
	tombstone.LastError = ""
	tombstone.LastAttemptAt = probeTimePointer(now)
	tombstone.NextRetryAt = nil
	tombstone.UpdatedAt = now
	s.tombstones[key] = tombstone
	return tombstone, true, nil
}

func (s *probeOrphanStore) ResolveClaimedResourceTombstone(ctx context.Context, resource containerruntime.ManagedResource, now time.Time) error {
	return s.complete(ctx, resource, now, containerruntime.ResourceTombstonePending, containerruntime.ResourceTombstoneFailed)
}

func (s *probeOrphanStore) CompleteResourceTombstone(ctx context.Context, resource containerruntime.ManagedResource, now time.Time) error {
	return s.complete(ctx, resource, now, containerruntime.ResourceTombstoneDeleting)
}

func (s *probeOrphanStore) FailResourceTombstone(ctx context.Context, resource containerruntime.ManagedResource, message string, nextRetryAt, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	key := probeTombstoneKey(resource)
	tombstone, ok := s.tombstones[key]
	if !ok || tombstone.Status != containerruntime.ResourceTombstoneDeleting {
		return containerruntime.ErrRuntimeStateConflict
	}
	tombstone.Status = containerruntime.ResourceTombstoneFailed
	tombstone.LastError = message
	tombstone.NextRetryAt = probeTimePointer(nextRetryAt)
	tombstone.UpdatedAt = now
	s.tombstones[key] = tombstone
	return nil
}

func (s *probeOrphanStore) complete(ctx context.Context, resource containerruntime.ManagedResource, now time.Time, allowed ...containerruntime.ResourceTombstoneStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	key := probeTombstoneKey(resource)
	tombstone, ok := s.tombstones[key]
	if !ok || !probeTombstoneStatusAllowed(tombstone.Status, allowed) {
		return containerruntime.ErrRuntimeStateConflict
	}
	tombstone.Status = containerruntime.ResourceTombstoneCompleted
	tombstone.LastError = ""
	tombstone.NextRetryAt = nil
	tombstone.CompletedAt = probeTimePointer(now)
	tombstone.UpdatedAt = now
	s.tombstones[key] = tombstone
	return nil
}

func probeTombstoneKey(resource containerruntime.ManagedResource) string {
	return resource.Kind + "\x00" + resource.ProviderID
}

func probeTimePointer(value time.Time) *time.Time {
	copy := value
	return &copy
}

func probeTombstoneStatusAllowed(status containerruntime.ResourceTombstoneStatus, allowed []containerruntime.ResourceTombstoneStatus) bool {
	for _, candidate := range allowed {
		if status == candidate {
			return true
		}
	}
	return false
}
