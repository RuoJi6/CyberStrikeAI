package container_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

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

func lifecycleFixture(t *testing.T) (*database.DB, *containertest.FakeManager, *container.LifecycleController, string) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "lifecycle.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conversation, err := db.CreateConversation("lifecycle", database.ConversationCreateMeta{})
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
