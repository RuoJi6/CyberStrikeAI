package containertest_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/runtime/container/containertest"
)

func TestFakeManagerLifecycleAndCallRecording(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	manager := containertest.NewFakeManagerWithClock(container.EngineInfo{
		Available:    true,
		Version:      "fake-1",
		Architecture: "arm64",
		OperatingSys: "linux",
	}, func() time.Time { return now })

	ctx := context.Background()
	engine, err := manager.EngineInfo(ctx)
	if err != nil || engine.Architecture != "arm64" {
		t.Fatalf("engine info = %#v, %v", engine, err)
	}

	spec := validSpec()
	created, err := manager.Create(ctx, spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Status != container.StatusStopped || created.ProviderID == "" || created.Image.ResolvedDigest != spec.Image.Digest {
		t.Fatalf("created runtime = %#v", created)
	}
	if _, err := manager.Create(ctx, spec); !errors.Is(err, container.ErrAlreadyExists) {
		t.Fatalf("duplicate create = %v", err)
	}

	running, err := manager.Start(ctx, spec.ID)
	if err != nil || running.Status != container.StatusRunning {
		t.Fatalf("start = %#v, %v", running, err)
	}
	if _, err := manager.Start(ctx, spec.ID); !errors.Is(err, container.ErrRuntimeStateConflict) {
		t.Fatalf("second start = %v", err)
	}

	stopped, err := manager.Stop(ctx, spec.ID, container.StopOptions{Timeout: 5 * time.Second})
	if err != nil || stopped.Status != container.StatusStopped {
		t.Fatalf("stop = %#v, %v", stopped, err)
	}

	spec.Image.Digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	rebuilt, err := manager.Rebuild(ctx, spec.ID, container.RebuildOptions{Spec: spec})
	if err != nil || rebuilt.Image.Digest != spec.Image.Digest || rebuilt.ProviderID == created.ProviderID {
		t.Fatalf("rebuild = %#v, %v", rebuilt, err)
	}

	listed, err := manager.ListOwned(ctx)
	if err != nil || len(listed) != 1 || listed[0].ID != spec.ID {
		t.Fatalf("list = %#v, %v", listed, err)
	}
	inspected, err := manager.Inspect(ctx, spec.ID)
	if err != nil || inspected.ProviderID != rebuilt.ProviderID {
		t.Fatalf("inspect = %#v, %v", inspected, err)
	}

	if err := manager.Delete(ctx, spec.ID, container.DeleteOptions{RemoveWorkspace: false}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := manager.Inspect(ctx, spec.ID); !container.IsNotFound(err) {
		t.Fatalf("inspect after delete = %v", err)
	}

	gotOperations := make([]string, 0)
	for _, call := range manager.Calls() {
		gotOperations = append(gotOperations, call.Operation)
	}
	wantOperations := []string{
		containertest.OperationEngineInfo,
		containertest.OperationCreate,
		containertest.OperationCreate,
		containertest.OperationStart,
		containertest.OperationStart,
		containertest.OperationStop,
		containertest.OperationRebuild,
		containertest.OperationListOwned,
		containertest.OperationInspect,
		containertest.OperationDelete,
		containertest.OperationInspect,
	}
	if !reflect.DeepEqual(gotOperations, wantOperations) {
		t.Fatalf("operations = %v, want %v", gotOperations, wantOperations)
	}
}

func TestFakeManagerFailureAndCancellation(t *testing.T) {
	manager := containertest.NewFakeManager(container.EngineInfo{Available: true})
	forced := errors.New("forced engine failure")
	manager.FailNext(containertest.OperationEngineInfo, forced)
	if _, err := manager.EngineInfo(context.Background()); !errors.Is(err, forced) {
		t.Fatalf("forced failure = %v", err)
	}
	if _, err := manager.EngineInfo(context.Background()); err != nil {
		t.Fatalf("one-shot failure was not cleared: %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.ListOwned(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled list = %v", err)
	}
}

func TestFakeManagerUnavailableFailsClosed(t *testing.T) {
	manager := containertest.NewFakeManager(container.EngineInfo{Available: false})
	info, err := manager.EngineInfo(context.Background())
	if info.Available || !errors.Is(err, container.ErrEngineUnavailable) {
		t.Fatalf("engine info = %#v, %v", info, err)
	}
}

func TestFakeManagerImageInspection(t *testing.T) {
	manager := containertest.NewFakeManager(container.EngineInfo{Available: true})
	image := validSpec().Image
	manifest, err := manager.InspectManifest(context.Background(), image)
	if err != nil || manifest.Local || manifest.ManifestDigest != image.Digest {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
	local, err := manager.InspectLocalImage(context.Background(), image)
	if err != nil || !local.Local || local.ImageID == "" {
		t.Fatalf("local image = %#v, %v", local, err)
	}
	verified, err := manager.VerifyRuntimeImage(context.Background(), "provider-1", image)
	if err != nil || !verified.Local || verified.Reference.ResolvedDigest != image.Digest {
		t.Fatalf("runtime image = %#v, %v", verified, err)
	}
}

func validSpec() container.RuntimeSpec {
	return container.RuntimeSpec{
		ID:             "runtime-1",
		ConversationID: "conversation-1",
		Image: container.ImageReference{
			Repository: "ghcr.io/example/sandbox",
			Digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Platform:   "linux/arm64",
		},
		Resources: container.ResourceLimits{
			NanoCPUs:          1_000_000_000,
			MemoryBytes:       512 << 20,
			PIDs:              128,
			NoFileSoft:        1024,
			NoFileHard:        2048,
			WorkspaceBytes:    1 << 30,
			MaxConcurrentExec: 2,
		},
		Security: container.SecurityProfile{
			ReadOnlyRootFS:      true,
			NoNewPrivileges:     true,
			DropAllCapabilities: true,
			NetworkMode:         container.NetworkNone,
			SeccompProfile:      "default",
			TmpfsBytes:          64 << 20,
		},
		Workspace: container.WorkspaceSpec{
			Persistent: true,
			VolumeName: "cyberstrike-workspace-1",
			MountPath:  "/workspace",
		},
	}
}
