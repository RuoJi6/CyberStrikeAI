package container

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ResourceKindConversationNetwork = "conversation-network"
	ResourceKindWorkspaceVolume     = "workspace-volume"
)

type ResourceTombstoneStatus string

const (
	ResourceTombstonePending   ResourceTombstoneStatus = "pending"
	ResourceTombstoneDeleting  ResourceTombstoneStatus = "deleting"
	ResourceTombstoneFailed    ResourceTombstoneStatus = "failed"
	ResourceTombstoneCompleted ResourceTombstoneStatus = "completed"
)

// ManagedResource is an engine resource discovered exclusively through the
// control-plane owner labels. ProviderID is never accepted from an HTTP API.
type ManagedResource struct {
	Kind           string    `json:"kind"`
	LogicalID      string    `json:"logicalId"`
	ProviderID     string    `json:"providerId"`
	Name           string    `json:"name"`
	ConversationID string    `json:"conversationId"`
	CreatedAt      time.Time `json:"createdAt"`
}

// ManagedResourceClaim describes durable control-plane ownership. A blank
// provider ID is a temporary wildcard only while creation is queued/running.
type ManagedResourceClaim struct {
	Kind           string
	LogicalID      string
	ProviderID     string
	ConversationID string
}

type ResourceTombstone struct {
	Resource      ManagedResource         `json:"resource"`
	Status        ResourceTombstoneStatus `json:"status"`
	Attempt       int                     `json:"attempt"`
	LastError     string                  `json:"lastError,omitempty"`
	DiscoveredAt  time.Time               `json:"discoveredAt"`
	LastAttemptAt *time.Time              `json:"lastAttemptAt,omitempty"`
	NextRetryAt   *time.Time              `json:"nextRetryAt,omitempty"`
	CompletedAt   *time.Time              `json:"completedAt,omitempty"`
	UpdatedAt     time.Time               `json:"updatedAt"`
}

type OrphanScanReport struct {
	Observed   int `json:"observed"`
	Retained   int `json:"retained"`
	Discovered int `json:"discovered"`
	Attempted  int `json:"attempted"`
	Deleted    int `json:"deleted"`
	Missing    int `json:"missing"`
	Failed     int `json:"failed"`
}

// ManagedResourceManager is deliberately separate from RuntimeManager:
// orphan cleanup may use provider IDs only after they were discovered from an
// owner-label scan and are revalidated immediately before deletion.
type ManagedResourceManager interface {
	ListOwnedResources(ctx context.Context) ([]ManagedResource, error)
	DeleteOwnedResource(ctx context.Context, resource ManagedResource) error
}

type OrphanStore interface {
	ListManagedResourceClaims(ctx context.Context) ([]ManagedResourceClaim, error)
	DiscoverResourceTombstone(ctx context.Context, resource ManagedResource, now time.Time) (ResourceTombstone, bool, error)
	RecoverResourceTombstones(ctx context.Context, interruptedBefore, now time.Time) (int64, error)
	ListRetryableResourceTombstones(ctx context.Context, now time.Time, limit int) ([]ResourceTombstone, error)
	ClaimResourceTombstone(ctx context.Context, resource ManagedResource, now time.Time) (ResourceTombstone, bool, error)
	ResolveClaimedResourceTombstone(ctx context.Context, resource ManagedResource, now time.Time) error
	CompleteResourceTombstone(ctx context.Context, resource ManagedResource, now time.Time) error
	FailResourceTombstone(ctx context.Context, resource ManagedResource, message string, nextRetryAt, now time.Time) error
}

type OrphanScannerOptions struct {
	RetryBase  time.Duration
	RetryMax   time.Duration
	StaleAfter time.Duration
	BatchSize  int
	Clock      func() time.Time
}

// OrphanScanner reconciles only explicitly owned resources. It never calls a
// global Docker prune operation and retains completed tombstones for audit.
type OrphanScanner struct {
	manager ManagedResourceManager
	store   OrphanStore
	options OrphanScannerOptions
}

func NewOrphanScanner(manager ManagedResourceManager, store OrphanStore, options OrphanScannerOptions) (*OrphanScanner, error) {
	if manager == nil || store == nil {
		return nil, invalidSpec("orphan scanner requires a managed resource manager and durable store")
	}
	if options.RetryBase == 0 {
		options.RetryBase = 5 * time.Second
	}
	if options.RetryMax == 0 {
		options.RetryMax = time.Hour
	}
	if options.StaleAfter == 0 {
		options.StaleAfter = 2 * time.Minute
	}
	if options.BatchSize == 0 {
		options.BatchSize = 128
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.RetryBase < 0 || options.RetryMax < options.RetryBase || options.StaleAfter < 0 || options.BatchSize < 1 || options.BatchSize > 4096 {
		return nil, invalidSpec("orphan scanner retry, stale and batch options are invalid")
	}
	return &OrphanScanner{manager: manager, store: store, options: options}, nil
}

func (s *OrphanScanner) Reconcile(ctx context.Context) (OrphanScanReport, error) {
	var report OrphanScanReport
	if ctx == nil {
		return report, invalidSpec("context is required")
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	now := s.options.Clock().UTC()
	var reconcileErrors []error
	if _, err := s.store.RecoverResourceTombstones(ctx, now.Add(-s.options.StaleAfter), now); err != nil {
		return report, fmt.Errorf("recover orphan cleanup tombstones: %w", err)
	}
	claims, err := s.store.ListManagedResourceClaims(ctx)
	if err != nil {
		return report, fmt.Errorf("list managed resource claims: %w", err)
	}
	resources, err := s.manager.ListOwnedResources(ctx)
	if err != nil {
		return report, fmt.Errorf("list owner-labelled engine resources: %w", err)
	}
	report.Observed = len(resources)
	for _, resource := range resources {
		if err := validateManagedResource(resource); err != nil {
			reconcileErrors = append(reconcileErrors, err)
			continue
		}
		if resourceIsClaimed(resource, claims) {
			report.Retained++
			continue
		}
		_, discovered, discoverErr := s.store.DiscoverResourceTombstone(ctx, resource, now)
		if discoverErr != nil {
			reconcileErrors = append(reconcileErrors, fmt.Errorf("persist orphan tombstone for %s: %w", resource.ProviderID, discoverErr))
			continue
		}
		if discovered {
			report.Discovered++
		}
	}

	tombstones, err := s.store.ListRetryableResourceTombstones(ctx, now, s.options.BatchSize)
	if err != nil {
		return report, errors.Join(append(reconcileErrors, fmt.Errorf("list retryable orphan tombstones: %w", err))...)
	}
	for _, tombstone := range tombstones {
		resource := tombstone.Resource
		if resourceIsClaimed(resource, claims) {
			if completeErr := s.store.ResolveClaimedResourceTombstone(ctx, resource, now); completeErr != nil {
				reconcileErrors = append(reconcileErrors, completeErr)
			}
			continue
		}
		claimed, won, claimErr := s.store.ClaimResourceTombstone(ctx, resource, now)
		if claimErr != nil {
			reconcileErrors = append(reconcileErrors, claimErr)
			continue
		}
		if !won {
			continue
		}
		report.Attempted++
		deleteErr := s.manager.DeleteOwnedResource(ctx, claimed.Resource)
		if deleteErr == nil || errors.Is(deleteErr, ErrNotFound) {
			if completeErr := s.store.CompleteResourceTombstone(ctx, claimed.Resource, now); completeErr != nil {
				reconcileErrors = append(reconcileErrors, completeErr)
				continue
			}
			if errors.Is(deleteErr, ErrNotFound) {
				report.Missing++
			} else {
				report.Deleted++
			}
			continue
		}
		nextRetry := now.Add(s.retryDelay(claimed.Attempt))
		if failErr := s.store.FailResourceTombstone(ctx, claimed.Resource, deleteErr.Error(), nextRetry, now); failErr != nil {
			reconcileErrors = append(reconcileErrors, errors.Join(deleteErr, failErr))
		} else {
			reconcileErrors = append(reconcileErrors, deleteErr)
		}
		report.Failed++
	}
	return report, errors.Join(reconcileErrors...)
}

// RunPeriodic retries persisted tombstones and discovers newly orphaned
// resources until shutdown. Reconcile remains public for startup and tests.
func (s *OrphanScanner) RunPeriodic(ctx context.Context, interval time.Duration, observe func(OrphanScanReport, error)) error {
	if ctx == nil {
		return invalidSpec("context is required")
	}
	if interval <= 0 {
		return invalidSpec("orphan scan interval must be positive")
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

func (s *OrphanScanner) retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := s.options.RetryBase
	for n := 1; n < attempt && delay < s.options.RetryMax; n++ {
		if delay > s.options.RetryMax/2 {
			return s.options.RetryMax
		}
		delay *= 2
	}
	if delay > s.options.RetryMax {
		return s.options.RetryMax
	}
	return delay
}

func resourceIsClaimed(resource ManagedResource, claims []ManagedResourceClaim) bool {
	for _, claim := range claims {
		if claim.Kind != resource.Kind || claim.LogicalID != resource.LogicalID || claim.ConversationID != resource.ConversationID {
			continue
		}
		if strings.TrimSpace(claim.ProviderID) == "" || claim.ProviderID == resource.ProviderID {
			return true
		}
	}
	return false
}

func validateManagedResource(resource ManagedResource) error {
	if !validManagedResourceKind(resource.Kind) || !generatedNamePattern.MatchString(strings.TrimSpace(resource.LogicalID)) ||
		!generatedNamePattern.MatchString(strings.TrimSpace(resource.ConversationID)) || strings.TrimSpace(resource.ProviderID) == "" || strings.TrimSpace(resource.Name) == "" {
		return fmt.Errorf("%w: managed resource identity is invalid", ErrInvalidSpecification)
	}
	return nil
}

func validManagedResourceKind(kind string) bool {
	switch kind {
	case ResourceKindAgent, ResourceKindConversationNetwork, ResourceKindWorkspaceVolume:
		return true
	default:
		return false
	}
}
