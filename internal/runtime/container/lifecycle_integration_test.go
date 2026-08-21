package container_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	container "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/runtime/container/containertest"
	"go.uber.org/zap"
)

func TestLifecycleControllerPersistsStartStopRebuildAndDelete(t *testing.T) {
	db, manager, controller, conversationID := lifecycleFixture(t)

	started, err := controller.Start(context.Background(), conversationID)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if started.RuntimeStatus != container.StatusRunning || started.LifecycleState != container.LifecycleIdle || started.LifecycleOperation != container.LifecycleOperationStart || started.RuntimeGeneration != 1 {
		t.Fatalf("started record = %#v", started)
	}

	stopped, err := controller.Stop(context.Background(), conversationID)
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if stopped.RuntimeStatus != container.StatusStopped || stopped.LifecycleOperation != container.LifecycleOperationStop {
		t.Fatalf("stopped record = %#v", stopped)
	}

	rebuilt, err := controller.Rebuild(context.Background(), conversationID)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if rebuilt.RuntimeStatus != container.StatusStopped || rebuilt.RuntimeGeneration != 2 || rebuilt.ProviderID == stopped.ProviderID {
		t.Fatalf("rebuilt record = %#v", rebuilt)
	}
	if rebuilt.Spec.Security.NetworkMode != container.NetworkInternal {
		t.Fatalf("legacy runtime was not migrated to an internal network: %#v", rebuilt.Spec.Security)
	}
	observed, err := manager.Inspect(context.Background(), rebuilt.RuntimeID)
	if err != nil {
		t.Fatal(err)
	}
	if observed.SpecDigest != container.RuntimeSpecDigest(rebuilt.Spec) {
		t.Fatalf("rebuilt runtime digest = %q, want %q", observed.SpecDigest, container.RuntimeSpecDigest(rebuilt.Spec))
	}

	if err := controller.Delete(context.Background(), conversationID, false); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := db.GetContainerInitialization(context.Background(), conversationID); !errors.Is(err, container.ErrNotFound) {
		t.Fatalf("deleted record lookup = %v", err)
	}
	if _, err := manager.Inspect(context.Background(), rebuilt.RuntimeID); !errors.Is(err, container.ErrNotFound) {
		t.Fatalf("deleted provider lookup = %v", err)
	}
}

func TestLifecycleControllerExplicitRebuildAddsPinnedEgressGateway(t *testing.T) {
	db, manager, _, conversationID := lifecycleFixture(t)
	gateway := lifecycleGatewaySpec()
	controller, err := container.NewLifecycleControllerWithOptions(manager, db, container.LifecycleControllerOptions{EgressGateway: &gateway})
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := controller.Rebuild(context.Background(), conversationID)
	if err != nil {
		t.Fatalf("rebuild with gateway: %v", err)
	}
	if rebuilt.Spec.Security.NetworkMode != container.NetworkInternal || rebuilt.Spec.EgressGateway == nil || rebuilt.Spec.EgressGateway.Image.Digest != gateway.Image.Digest || rebuilt.RuntimeGeneration != 2 {
		t.Fatalf("rebuilt gateway topology = %#v", rebuilt)
	}
	observed, err := manager.Inspect(context.Background(), rebuilt.RuntimeID)
	if err != nil {
		t.Fatal(err)
	}
	if observed.SpecDigest != container.RuntimeSpecDigest(rebuilt.Spec) {
		t.Fatalf("gateway runtime digest = %q, want %q", observed.SpecDigest, container.RuntimeSpecDigest(rebuilt.Spec))
	}
}

func TestLifecycleControllerUpgradesExistingGatewayWithActiveBoundarySnapshot(t *testing.T) {
	db, manager, _, conversationID := lifecycleFixture(t)
	active, err := db.EnsureConversationBoundarySnapshot(context.Background(), conversationID)
	if err != nil {
		t.Fatal(err)
	}
	item2Gateway := lifecycleGatewaySpec()
	item2Controller, err := container.NewLifecycleControllerWithOptions(manager, db, container.LifecycleControllerOptions{EgressGateway: &item2Gateway})
	if err != nil {
		t.Fatal(err)
	}
	item2, err := item2Controller.Rebuild(context.Background(), conversationID)
	if err != nil {
		t.Fatalf("create item-2 gateway topology: %v", err)
	}
	if item2.Spec.EgressGateway == nil || item2.Spec.EgressGateway.BoundarySnapshot != nil {
		t.Fatalf("item-2 topology = %#v", item2.Spec)
	}
	item3Gateway := item2Gateway
	item3Gateway.Image.Digest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	provider := &recordingBoundarySnapshotProvider{snapshot: container.EgressBoundarySnapshotSpec{ID: active.SnapshotID, SHA256: active.SHA256}}
	item3Controller, err := container.NewLifecycleControllerWithOptions(manager, db, container.LifecycleControllerOptions{
		EgressGateway: &item3Gateway, BoundarySnapshots: provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	item3, err := item3Controller.Rebuild(context.Background(), conversationID)
	if err != nil {
		t.Fatalf("upgrade existing gateway with active snapshot: %v", err)
	}
	if len(provider.snapshotIDs) != 1 || provider.snapshotIDs[0] != "" || item3.Spec.EgressGateway == nil || item3.Spec.EgressGateway.Image.Digest != item3Gateway.Image.Digest || item3.Spec.EgressGateway.BoundarySnapshot == nil || item3.Spec.EgressGateway.BoundarySnapshot.ID != active.SnapshotID || item3.Spec.EgressGateway.BoundarySnapshot.SHA256 != active.SHA256 || item3.RuntimeGeneration != item2.RuntimeGeneration+1 {
		t.Fatalf("item-3 topology = calls %#v, record %#v", provider.snapshotIDs, item3)
	}
}

func TestLifecycleControllerExplicitRebuildBindsOnlyAuthorizedPendingSnapshot(t *testing.T) {
	db, manager, _, conversationID := lifecycleFixture(t)
	active, err := db.EnsureConversationBoundarySnapshot(context.Background(), conversationID)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := db.PrepareConversationBoundaryRebuild(context.Background(), conversationID, "")
	if err != nil {
		t.Fatal(err)
	}
	provider := &recordingBoundarySnapshotProvider{snapshot: container.EgressBoundarySnapshotSpec{
		ID: pending.SnapshotID, SHA256: pending.SHA256,
	}}
	gateway := lifecycleGatewaySpec()
	controller, err := container.NewLifecycleControllerWithOptions(manager, db, container.LifecycleControllerOptions{
		EgressGateway: &gateway, BoundarySnapshots: provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := container.WithBoundaryRebuildSnapshot(context.Background(), pending.SnapshotID)
	rebuilt, err := controller.Rebuild(ctx, conversationID)
	if err != nil {
		t.Fatalf("rebuild with pending boundary snapshot: %v", err)
	}
	if len(provider.snapshotIDs) != 1 || provider.snapshotIDs[0] != pending.SnapshotID || rebuilt.Spec.EgressGateway == nil || rebuilt.Spec.EgressGateway.BoundarySnapshot == nil || rebuilt.Spec.EgressGateway.BoundarySnapshot.ID != pending.SnapshotID || rebuilt.Spec.EgressGateway.BoundarySnapshot.SHA256 != pending.SHA256 {
		t.Fatalf("pending snapshot binding = calls %#v, record %#v", provider.snapshotIDs, rebuilt)
	}
	activated, err := db.GetConversationBoundarySnapshot(context.Background(), conversationID)
	if err != nil || activated.SnapshotID != pending.SnapshotID || activated.SnapshotID == active.SnapshotID {
		t.Fatalf("activated snapshot = %#v, %v", activated, err)
	}

	maintained, err := controller.Rebuild(context.Background(), conversationID)
	if err != nil {
		t.Fatalf("maintenance rebuild: %v", err)
	}
	if len(provider.snapshotIDs) != 1 || maintained.Spec.EgressGateway.BoundarySnapshot == nil || *maintained.Spec.EgressGateway.BoundarySnapshot != *rebuilt.Spec.EgressGateway.BoundarySnapshot {
		t.Fatalf("maintenance rebuild replaced immutable snapshot: calls %#v, record %#v", provider.snapshotIDs, maintained)
	}

	nextPending, err := db.PrepareConversationBoundaryRebuild(context.Background(), conversationID, "")
	if err != nil {
		t.Fatal(err)
	}
	provider.snapshot = container.EgressBoundarySnapshotSpec{ID: nextPending.SnapshotID, SHA256: nextPending.SHA256}
	nextCtx := container.WithBoundaryRebuildSnapshot(context.Background(), nextPending.SnapshotID)
	updated, err := controller.Rebuild(nextCtx, conversationID)
	if err != nil {
		t.Fatalf("replace active boundary snapshot with authorized pending snapshot: %v", err)
	}
	if len(provider.snapshotIDs) != 2 || provider.snapshotIDs[1] != nextPending.SnapshotID || updated.Spec.EgressGateway == nil || updated.Spec.EgressGateway.BoundarySnapshot == nil || updated.Spec.EgressGateway.BoundarySnapshot.ID != nextPending.SnapshotID || updated.Spec.EgressGateway.BoundarySnapshot.SHA256 != nextPending.SHA256 {
		t.Fatalf("updated pending snapshot binding = calls %#v, record %#v", provider.snapshotIDs, updated)
	}
	nextActive, err := db.GetConversationBoundarySnapshot(context.Background(), conversationID)
	if err != nil || nextActive.SnapshotID != nextPending.SnapshotID || nextActive.SnapshotID == activated.SnapshotID {
		t.Fatalf("updated active snapshot = %#v, %v", nextActive, err)
	}
}

func TestLifecycleControllerBoundarySnapshotResolutionFailureStopsBeforeManagerRebuild(t *testing.T) {
	db, manager, _, conversationID := lifecycleFixture(t)
	provider := &recordingBoundarySnapshotProvider{err: errors.New("snapshot unavailable")}
	gateway := lifecycleGatewaySpec()
	controller, err := container.NewLifecycleControllerWithOptions(manager, db, container.LifecycleControllerOptions{
		EgressGateway: &gateway, BoundarySnapshots: provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Rebuild(context.Background(), conversationID); err == nil || !strings.Contains(err.Error(), "snapshot unavailable") {
		t.Fatalf("snapshot resolution error = %v", err)
	}
	for _, call := range manager.Calls() {
		if call.Operation == containertest.OperationRebuild {
			t.Fatalf("manager rebuild ran without a trusted snapshot: %#v", manager.Calls())
		}
	}
	record, err := db.GetContainerInitialization(context.Background(), conversationID)
	if err != nil {
		t.Fatal(err)
	}
	if record.LifecycleState != container.LifecycleFailed || record.RuntimeDrift != "boundary_snapshot_unavailable" {
		t.Fatalf("snapshot failure record = %#v", record)
	}
}

func TestLifecycleControllerReconcileRecoversCommittedGatewayUpgrade(t *testing.T) {
	db, manager, _, conversationID := lifecycleFixture(t)
	record, err := db.GetContainerInitialization(context.Background(), conversationID)
	if err != nil {
		t.Fatal(err)
	}
	gateway := lifecycleGatewaySpec()
	replacement := record.Spec
	replacement.Security.NetworkMode = container.NetworkInternal
	replacement.EgressGateway = &gateway
	runtime, err := manager.Rebuild(context.Background(), record.RuntimeID, container.RebuildOptions{Spec: replacement})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := container.NewLifecycleControllerWithOptions(manager, db, container.LifecycleControllerOptions{EgressGateway: &gateway})
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := controller.Reconcile(context.Background(), conversationID)
	if err != nil {
		t.Fatalf("reconcile interrupted gateway upgrade: %v", err)
	}
	if reconciled.Spec.EgressGateway == nil || reconciled.Spec.EgressGateway.Image.Digest != gateway.Image.Digest || reconciled.ProviderID != runtime.ProviderID || reconciled.RuntimeDrift != "topology_migration_recovered" {
		t.Fatalf("reconciled gateway upgrade = %#v", reconciled)
	}
}

func TestLifecycleControllerReconcileRecoversCommittedDockerNetworkMigration(t *testing.T) {
	db, manager, controller, conversationID := lifecycleFixture(t)
	record, err := db.GetContainerInitialization(context.Background(), conversationID)
	if err != nil {
		t.Fatal(err)
	}
	replacement := record.Spec
	replacement.Security.NetworkMode = container.NetworkInternal
	runtime, err := manager.Rebuild(context.Background(), record.RuntimeID, container.RebuildOptions{Spec: replacement})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.SpecDigest != container.RuntimeSpecDigest(replacement) {
		t.Fatalf("simulated migrated runtime = %#v", runtime)
	}

	reconciled, err := controller.Reconcile(context.Background(), conversationID)
	if err != nil {
		t.Fatalf("reconcile interrupted network migration: %v", err)
	}
	if reconciled.Spec.Security.NetworkMode != container.NetworkInternal || reconciled.ProviderID != runtime.ProviderID || reconciled.RuntimeDrift != "topology_migration_recovered" {
		t.Fatalf("reconciled migration = %#v", reconciled)
	}
	if reconciled.RuntimeGeneration != record.RuntimeGeneration {
		t.Fatalf("reconciliation changed active generation: got %d, want %d", reconciled.RuntimeGeneration, record.RuntimeGeneration)
	}
}

func TestLifecycleControllerReconcilesObservedStateAndMissingProvider(t *testing.T) {
	_, manager, controller, conversationID := lifecycleFixture(t)
	record, err := controller.Start(context.Background(), conversationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Stop(context.Background(), record.RuntimeID, container.StopOptions{}); err != nil {
		t.Fatal(err)
	}

	reconciled, err := controller.Reconcile(context.Background(), conversationID)
	if err != nil {
		t.Fatalf("reconcile changed state: %v", err)
	}
	if reconciled.RuntimeStatus != container.StatusStopped || reconciled.RuntimeDrift != "runtime_state_changed" || reconciled.LifecycleState != container.LifecycleIdle {
		t.Fatalf("reconciled record = %#v", reconciled)
	}

	if err := manager.Delete(context.Background(), record.RuntimeID, container.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	missing, err := controller.Reconcile(context.Background(), conversationID)
	if err != nil {
		t.Fatalf("reconcile missing provider: %v", err)
	}
	if missing.RuntimeStatus != container.StatusFailed || missing.RuntimeDrift != "provider_missing" || missing.LifecycleState != container.LifecycleFailed {
		t.Fatalf("missing provider record = %#v", missing)
	}
}

func TestLifecycleControllerRejectsConcurrentDurableOperation(t *testing.T) {
	db, _, controller, conversationID := lifecycleFixture(t)
	if _, err := db.BeginLifecycle(context.Background(), conversationID, container.LifecycleOperationStop); err != nil {
		t.Fatal(err)
	}
	_, err := controller.Start(context.Background(), conversationID)
	if !errors.Is(err, container.ErrRuntimeStateConflict) {
		t.Fatalf("concurrent start error = %v", err)
	}
}

func TestLifecycleControllerIdleStopPreservesRuntimeAndWorkspace(t *testing.T) {
	db, manager, controller, conversationID := lifecycleFixture(t)
	if _, err := controller.Start(context.Background(), conversationID); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 8, 20, 6, 0, 0, 0, time.UTC)
	if _, err := db.Exec(`UPDATE conversations SET updated_at = ? WHERE id = ?`, old, conversationID); err != nil {
		t.Fatal(err)
	}
	stopped, err := controller.StopIdle(context.Background(), conversationID, old.Add(time.Hour))
	if err != nil {
		t.Fatalf("idle stop: %v", err)
	}
	if stopped.RuntimeStatus != container.StatusStopped || stopped.LifecycleOperation != container.LifecycleOperationStop {
		t.Fatalf("idle stopped record = %#v", stopped)
	}
	if _, err := manager.Inspect(context.Background(), stopped.RuntimeID); err != nil {
		t.Fatalf("idle stop deleted runtime: %v", err)
	}
	for _, call := range manager.Calls() {
		if call.Operation == containertest.OperationDelete {
			t.Fatalf("idle stop requested delete: %#v", manager.Calls())
		}
	}

	if _, err := controller.Start(context.Background(), conversationID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE conversations SET updated_at = ? WHERE id = ?`, old.Add(2*time.Hour), conversationID); err != nil {
		t.Fatal(err)
	}
	countStopCalls := func() int {
		count := 0
		for _, call := range manager.Calls() {
			if call.Operation == containertest.OperationStop {
				count++
			}
		}
		return count
	}
	stopCalls := countStopCalls()
	if _, err := controller.StopIdle(context.Background(), conversationID, old.Add(time.Hour)); !errors.Is(err, container.ErrRuntimeStateConflict) {
		t.Fatalf("recent conversation idle stop = %v", err)
	}
	if countStopCalls() != stopCalls {
		t.Fatalf("recent conversation reached Docker stop: %#v", manager.Calls())
	}
}

func TestLifecycleControllerRecoversInterruptedOperation(t *testing.T) {
	db, _, controller, conversationID := lifecycleFixture(t)
	if _, err := db.BeginLifecycle(context.Background(), conversationID, container.LifecycleOperationStop); err != nil {
		t.Fatal(err)
	}
	if err := controller.Recover(context.Background()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	record, err := db.GetContainerInitialization(context.Background(), conversationID)
	if err != nil {
		t.Fatal(err)
	}
	if record.LifecycleOperation != container.LifecycleOperationReconcile || record.LifecycleState != container.LifecycleIdle || record.RuntimeStatus != container.StatusStopped {
		t.Fatalf("recovered record = %#v", record)
	}
}

func TestLifecycleControllerFinishesInterruptedDeleteWhenProviderIsGone(t *testing.T) {
	db, manager, controller, conversationID := lifecycleFixture(t)
	record, err := db.BeginLifecycle(context.Background(), conversationID, container.LifecycleOperationDelete)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Delete(context.Background(), record.RuntimeID, container.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := controller.Recover(context.Background()); err != nil {
		t.Fatalf("recover delete: %v", err)
	}
	if _, err := db.GetContainerInitialization(context.Background(), conversationID); !errors.Is(err, container.ErrNotFound) {
		t.Fatalf("interrupted delete record = %v", err)
	}
}

func TestLifecycleControllerDeletesRetainedWorkspaceWithoutRuntimeRecord(t *testing.T) {
	db, _, _, conversationID := lifecycleFixture(t)
	manager := containertest.NewFakeManager(container.EngineInfo{Available: true})
	controller, err := container.NewLifecycleController(manager, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.DeleteRetainedWorkspace(context.Background(), conversationID); err != nil {
		t.Fatalf("idempotent retained workspace delete: %v", err)
	}
	calls := manager.Calls()
	if len(calls) != 1 || calls[0].Operation != containertest.OperationDelete || calls[0].RuntimeID != container.RuntimeID("conversation-"+conversationID) {
		t.Fatalf("calls = %#v", calls)
	}
}

func lifecycleFixture(t *testing.T) (*database.DB, *containertest.FakeManager, *container.LifecycleController, string) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "lifecycle.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conversation, err := db.CreateConversation("lifecycle", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	spec := lifecycleSpec(conversation.ID)
	manager := containertest.NewFakeManager(container.EngineInfo{Available: true, Architecture: "arm64", OperatingSys: "linux"})
	if _, _, err := db.Queue(context.Background(), spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(context.Background(), conversation.ID); err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	runtime, err := manager.Create(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Complete(context.Background(), conversation.ID, runtime); err != nil {
		t.Fatal(err)
	}
	controller, err := container.NewLifecycleController(manager, db)
	if err != nil {
		t.Fatal(err)
	}
	return db, manager, controller, conversation.ID
}

func lifecycleSpec(conversationID string) container.RuntimeSpec {
	return container.RuntimeSpec{
		ID:             container.RuntimeID("runtime-" + conversationID),
		ConversationID: conversationID,
		Image: container.ImageReference{
			Repository: "ghcr.io/usestrix/strix-sandbox",
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

func lifecycleGatewaySpec() container.EgressGatewaySpec {
	return container.EgressGatewaySpec{
		Image: container.ImageReference{
			Repository: "ghcr.io/example/cyberstrike-egress",
			Digest:     "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			Platform:   "linux/arm64",
		},
		Resources: container.EgressGatewayResources{
			NanoCPUs: 250_000_000, MemoryBytes: 128 << 20, PIDs: 64,
			NoFileSoft: 512, NoFileHard: 1024, TmpfsBytes: 16 << 20,
			LogMaxBytes: 2 << 20, LogMaxFiles: 2,
		},
	}
}

type recordingBoundarySnapshotProvider struct {
	snapshot    container.EgressBoundarySnapshotSpec
	err         error
	snapshotIDs []string
}

func (p *recordingBoundarySnapshotProvider) ResolveBoundarySnapshot(_ context.Context, _ string, snapshotID string) (container.EgressBoundarySnapshotSpec, error) {
	p.snapshotIDs = append(p.snapshotIDs, snapshotID)
	if p.err != nil {
		return container.EgressBoundarySnapshotSpec{}, p.err
	}
	return p.snapshot, nil
}
