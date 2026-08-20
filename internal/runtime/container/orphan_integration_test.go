package container_test

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	container "cyberstrike-ai/internal/runtime/container"
	"go.uber.org/zap"
)

type fakeManagedResourceManager struct {
	mu        sync.Mutex
	resources map[string]container.ManagedResource
	failNext  map[string]error
	deleted   []string
}

func newFakeManagedResourceManager(resources ...container.ManagedResource) *fakeManagedResourceManager {
	manager := &fakeManagedResourceManager{resources: make(map[string]container.ManagedResource), failNext: make(map[string]error)}
	for _, resource := range resources {
		manager.resources[resource.ProviderID] = resource
	}
	return manager
}

func (f *fakeManagedResourceManager) ListOwnedResources(ctx context.Context) ([]container.ManagedResource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]container.ManagedResource, 0, len(f.resources))
	for _, resource := range f.resources {
		result = append(result, resource)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ProviderID < result[j].ProviderID })
	return result, nil
}

func (f *fakeManagedResourceManager) DeleteOwnedResource(ctx context.Context, resource container.ManagedResource) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	actual, ok := f.resources[resource.ProviderID]
	if !ok {
		return container.ErrNotFound
	}
	if actual.Kind != resource.Kind || actual.LogicalID != resource.LogicalID || actual.ConversationID != resource.ConversationID {
		return container.ErrRuntimeStateConflict
	}
	if err := f.failNext[resource.ProviderID]; err != nil {
		delete(f.failNext, resource.ProviderID)
		return err
	}
	delete(f.resources, resource.ProviderID)
	f.deleted = append(f.deleted, resource.ProviderID)
	return nil
}

func TestOrphanScannerRetainsClaimsAndDeletesOnlyOrphans(t *testing.T) {
	db := newOrphanIntegrationDB(t)
	ctx := context.Background()
	liveConversation, liveSpec, liveProvider := createRuntimeClaim(t, db, "live", true)
	queuedConversation, queuedSpec, _ := createRuntimeClaim(t, db, "queued", false)
	live := managedAgentResource(liveSpec, liveProvider)
	queued := managedAgentResource(queuedSpec, "provider-queued-created-before-complete")
	orphans := []container.ManagedResource{
		managedAgentResource(orphanRuntimeSpec("orphan-container"), "provider-orphan-container"),
		managedNamedResource(container.ResourceKindConversationNetwork, "orphan-network", liveConversation.ID),
		managedNamedResource(container.ResourceKindWorkspaceVolume, "orphan-volume", queuedConversation.ID),
	}
	manager := newFakeManagedResourceManager(append([]container.ManagedResource{live, queued}, orphans...)...)
	clock := time.Date(2026, 8, 20, 17, 0, 0, 0, time.UTC)
	scanner, err := container.NewOrphanScanner(manager, db, container.OrphanScannerOptions{Clock: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	report, err := scanner.Reconcile(ctx)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if report.Observed != 5 || report.Retained != 2 || report.Discovered != 3 || report.Deleted != 3 || report.Failed != 0 {
		t.Fatalf("report = %#v", report)
	}
	remaining, err := manager.ListOwnedResources(ctx)
	if err != nil || len(remaining) != 2 {
		t.Fatalf("remaining = %#v, %v", remaining, err)
	}
	for _, resource := range remaining {
		if resource.ProviderID != live.ProviderID && resource.ProviderID != queued.ProviderID {
			t.Fatalf("unexpected retained resource = %#v", resource)
		}
	}
	var completed int
	if err := db.QueryRow(`SELECT COUNT(*) FROM container_resource_tombstones WHERE status = 'completed'`).Scan(&completed); err != nil || completed != 3 {
		t.Fatalf("completed tombstones = %d, %v", completed, err)
	}
}

func TestOrphanScannerRetainsPersistentWorkspaceAfterRuntimeDeletion(t *testing.T) {
	db := newOrphanIntegrationDB(t)
	conversation, err := db.CreateConversation("retained persistent workspace", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer, WorkspacePersistent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	runtimeID := "conversation-" + conversation.ID
	volume := managedNamedResource(container.ResourceKindWorkspaceVolume, runtimeID, conversation.ID)
	manager := newFakeManagedResourceManager(volume)
	scanner, err := container.NewOrphanScanner(manager, db, container.OrphanScannerOptions{
		Clock: func() time.Time { return time.Date(2026, 8, 21, 1, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := scanner.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Observed != 1 || report.Retained != 1 || report.Discovered != 0 || report.Deleted != 0 {
		t.Fatalf("report = %#v", report)
	}
	remaining, err := manager.ListOwnedResources(context.Background())
	if err != nil || len(remaining) != 1 || remaining[0].ProviderID != volume.ProviderID {
		t.Fatalf("remaining = %#v, %v", remaining, err)
	}
}

func TestOrphanScannerPersistsFailureAndRetries(t *testing.T) {
	db := newOrphanIntegrationDB(t)
	resource := managedNamedResource(container.ResourceKindConversationNetwork, "retry-network", "retry-conversation")
	manager := newFakeManagedResourceManager(resource)
	manager.failNext[resource.ProviderID] = errors.New("network still attached")
	now := time.Date(2026, 8, 20, 17, 30, 0, 0, time.UTC)
	scanner, err := container.NewOrphanScanner(manager, db, container.OrphanScannerOptions{
		RetryBase: time.Second,
		RetryMax:  time.Minute,
		Clock:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := scanner.Reconcile(context.Background())
	if err == nil || first.Failed != 1 || first.Deleted != 0 {
		t.Fatalf("first reconcile = %#v, %v", first, err)
	}
	var status string
	var attempt int
	if err := db.QueryRow(`SELECT status, attempt FROM container_resource_tombstones WHERE provider_id = ?`, resource.ProviderID).Scan(&status, &attempt); err != nil || status != "failed" || attempt != 1 {
		t.Fatalf("failed tombstone = %q/%d, %v", status, attempt, err)
	}
	now = now.Add(2 * time.Second)
	second, err := scanner.Reconcile(context.Background())
	if err != nil || second.Deleted != 1 || second.Failed != 0 {
		t.Fatalf("second reconcile = %#v, %v", second, err)
	}
	if err := db.QueryRow(`SELECT status, attempt FROM container_resource_tombstones WHERE provider_id = ?`, resource.ProviderID).Scan(&status, &attempt); err != nil || status != "completed" || attempt != 2 {
		t.Fatalf("completed tombstone = %q/%d, %v", status, attempt, err)
	}
}

func newOrphanIntegrationDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "orphan.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func createRuntimeClaim(t *testing.T, db *database.DB, suffix string, complete bool) (*database.Conversation, container.RuntimeSpec, string) {
	t.Helper()
	conversation, err := db.CreateConversation("orphan "+suffix, database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	spec := orphanRuntimeSpec(conversation.ID)
	if _, _, err := db.Queue(context.Background(), spec, false); err != nil {
		t.Fatal(err)
	}
	providerID := "provider-" + suffix
	if complete {
		if _, claimed, err := db.Claim(context.Background(), conversation.ID); err != nil || !claimed {
			t.Fatalf("claim %s = %v, %v", suffix, claimed, err)
		}
		if _, err := db.Complete(context.Background(), conversation.ID, container.Runtime{ID: spec.ID, ProviderID: providerID, Status: container.StatusStopped}); err != nil {
			t.Fatal(err)
		}
	}
	return conversation, spec, providerID
}

func orphanRuntimeSpec(conversationID string) container.RuntimeSpec {
	return container.RuntimeSpec{
		ID:             container.RuntimeID("runtime-" + conversationID),
		ConversationID: conversationID,
		Image: container.ImageReference{
			Repository: "ghcr.io/example/sandbox",
			Digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Platform:   "linux/arm64",
		},
		Resources: container.ResourceLimits{
			NanoCPUs: 1_000_000_000, MemoryBytes: 512 << 20, PIDs: 128,
			NoFileSoft: 1024, NoFileHard: 2048, WorkspaceBytes: 1 << 30,
			MaxConcurrentExec: 2, MaxQueuedExec: 8, LogMaxBytes: 10 << 20, LogMaxFiles: 3,
		},
		Security: container.SecurityProfile{
			ReadOnlyRootFS: true, NoNewPrivileges: true, DropAllCapabilities: true,
			NetworkMode: container.NetworkNone, SeccompProfile: "default", TmpfsBytes: 64 << 20,
		},
		Workspace: container.WorkspaceSpec{MountPath: "/workspace"},
	}
}

func managedAgentResource(spec container.RuntimeSpec, providerID string) container.ManagedResource {
	return container.ManagedResource{
		Kind: container.ResourceKindAgent, LogicalID: string(spec.ID), ProviderID: providerID,
		Name: "cyberstrike-agent-" + string(spec.ID), ConversationID: spec.ConversationID,
	}
}

func managedNamedResource(kind, logicalID, conversationID string) container.ManagedResource {
	prefix := "cyberstrike-network-"
	if kind == container.ResourceKindWorkspaceVolume {
		prefix = "cyberstrike-workspace-"
	}
	name := prefix + logicalID
	return container.ManagedResource{Kind: kind, LogicalID: logicalID, ProviderID: name, Name: name, ConversationID: conversationID}
}
