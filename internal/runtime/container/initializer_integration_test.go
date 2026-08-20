package container_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"go.uber.org/zap"
)

type blockingRuntimeCreator struct {
	mu            sync.Mutex
	calls         int
	failRemaining int
	started       chan struct{}
	release       chan struct{}
	startOnce     sync.Once
}

func (f *blockingRuntimeCreator) EngineInfo(context.Context) (containerruntime.EngineInfo, error) {
	return containerruntime.EngineInfo{Available: true}, nil
}

func (f *blockingRuntimeCreator) InspectManifest(context.Context, containerruntime.ImageReference) (containerruntime.ImageInspection, error) {
	return containerruntime.ImageInspection{}, nil
}

func (f *blockingRuntimeCreator) InspectLocalImage(context.Context, containerruntime.ImageReference) (containerruntime.ImageInspection, error) {
	return containerruntime.ImageInspection{}, nil
}

func (f *blockingRuntimeCreator) VerifyRuntimeImage(context.Context, string, containerruntime.ImageReference) (containerruntime.ImageInspection, error) {
	return containerruntime.ImageInspection{}, nil
}

func (f *blockingRuntimeCreator) Create(ctx context.Context, spec containerruntime.RuntimeSpec) (containerruntime.Runtime, error) {
	f.mu.Lock()
	f.calls++
	shouldFail := f.failRemaining > 0
	if shouldFail {
		f.failRemaining--
	}
	f.mu.Unlock()
	f.startOnce.Do(func() { close(f.started) })
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return containerruntime.Runtime{}, ctx.Err()
		}
	}
	if shouldFail {
		return containerruntime.Runtime{}, errors.New("synthetic engine failure")
	}
	now := time.Now().UTC()
	return containerruntime.Runtime{
		ID:             spec.ID,
		ConversationID: spec.ConversationID,
		ProviderID:     "provider-" + string(spec.ID),
		Status:         containerruntime.StatusStopped,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, nil
}

func (f *blockingRuntimeCreator) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestInitializerReturnsBeforeDockerAndDeduplicates(t *testing.T) {
	db, conversationID := newInitializerDB(t)
	release := make(chan struct{})
	creator := &blockingRuntimeCreator{started: make(chan struct{}), release: release}
	initializer := newTestInitializer(t, creator, db)
	spec := initializerSpec(conversationID)

	startedAt := time.Now()
	record, err := initializer.EnsureAsync(context.Background(), spec)
	if err != nil || record.Status != containerruntime.InitializationQueued {
		t.Fatalf("ensure = %#v, %v", record, err)
	}
	if elapsed := time.Since(startedAt); elapsed > 100*time.Millisecond {
		t.Fatalf("ensure blocked on Docker for %v", elapsed)
	}
	select {
	case <-creator.started:
	case <-time.After(time.Second):
		t.Fatal("background creator did not start")
	}
	if _, err := initializer.EnsureAsync(context.Background(), spec); err != nil {
		t.Fatalf("duplicate ensure: %v", err)
	}
	close(release)
	created := waitInitializationStatus(t, db, conversationID, containerruntime.InitializationCreated)
	if created.Attempt != 1 || created.ProviderID == "" || creator.callCount() != 1 {
		t.Fatalf("created = %#v, calls = %d", created, creator.callCount())
	}
}

func TestInitializerPersistsFailureAndRetriesExplicitly(t *testing.T) {
	db, conversationID := newInitializerDB(t)
	creator := &blockingRuntimeCreator{started: make(chan struct{}), failRemaining: 1}
	initializer := newTestInitializer(t, creator, db)
	spec := initializerSpec(conversationID)

	if _, err := initializer.EnsureAsync(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	failed := waitInitializationStatus(t, db, conversationID, containerruntime.InitializationFailed)
	if failed.Attempt != 1 || failed.LastError != "synthetic engine failure" {
		t.Fatalf("failed = %#v", failed)
	}
	if _, err := initializer.RetryAsync(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	created := waitInitializationStatus(t, db, conversationID, containerruntime.InitializationCreated)
	if created.Attempt != 2 || creator.callCount() != 2 {
		t.Fatalf("retried = %#v, calls = %d", created, creator.callCount())
	}
}

func TestInitializerRecoversInterruptedDurableWork(t *testing.T) {
	db, conversationID := newInitializerDB(t)
	spec := initializerSpec(conversationID)
	if _, _, err := db.Queue(context.Background(), spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(context.Background(), conversationID); err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	creator := &blockingRuntimeCreator{started: make(chan struct{})}
	initializer := newTestInitializer(t, creator, db)
	if err := initializer.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	created := waitInitializationStatus(t, db, conversationID, containerruntime.InitializationCreated)
	if created.Attempt != 2 || creator.callCount() != 1 {
		t.Fatalf("recovered = %#v, calls = %d", created, creator.callCount())
	}
}

func TestInitializerFailsClosedWhenQueueIsFull(t *testing.T) {
	db, firstConversationID := newInitializerDB(t)
	secondConversation, err := db.CreateConversation("initializer queue second", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	thirdConversation, err := db.CreateConversation("initializer queue third", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}

	release := make(chan struct{})
	creator := &blockingRuntimeCreator{started: make(chan struct{}), release: release}
	initializer, err := containerruntime.NewInitializer(creator, db, containerruntime.InitializerOptions{
		Workers:       1,
		QueueCapacity: 1,
		CreateTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := initializer.Close(ctx); err != nil {
			t.Errorf("close initializer: %v", err)
		}
	})

	if _, err := initializer.EnsureAsync(context.Background(), initializerSpec(firstConversationID)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-creator.started:
	case <-time.After(time.Second):
		t.Fatal("first background creation did not start")
	}
	if _, err := initializer.EnsureAsync(context.Background(), initializerSpec(secondConversation.ID)); err != nil {
		t.Fatal(err)
	}
	failed, err := initializer.EnsureAsync(context.Background(), initializerSpec(thirdConversation.ID))
	if !errors.Is(err, containerruntime.ErrInitializationQueueFull) {
		t.Fatalf("queue overflow error = %v", err)
	}
	if failed.Status != containerruntime.InitializationFailed || failed.LastError == "" || failed.Attempt != 0 {
		t.Fatalf("queue overflow record = %#v", failed)
	}
	close(release)
	waitInitializationStatus(t, db, firstConversationID, containerruntime.InitializationCreated)
	waitInitializationStatus(t, db, secondConversation.ID, containerruntime.InitializationCreated)
}

func TestInitializerRejectsNilContexts(t *testing.T) {
	db, conversationID := newInitializerDB(t)
	creator := &blockingRuntimeCreator{started: make(chan struct{})}
	initializer := newTestInitializer(t, creator, db)
	if _, err := initializer.EnsureAsync(nil, initializerSpec(conversationID)); !errors.Is(err, containerruntime.ErrInvalidSpecification) {
		t.Fatalf("ensure nil context error = %v", err)
	}
	if _, err := initializer.Get(nil, conversationID); !errors.Is(err, containerruntime.ErrInvalidSpecification) {
		t.Fatalf("get nil context error = %v", err)
	}
	if err := initializer.Recover(nil); !errors.Is(err, containerruntime.ErrInvalidSpecification) {
		t.Fatalf("recover nil context error = %v", err)
	}
	if err := initializer.Close(nil); !errors.Is(err, containerruntime.ErrInvalidSpecification) {
		t.Fatalf("close nil context error = %v", err)
	}
}

func newInitializerDB(t *testing.T) (*database.DB, string) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "initializer.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conversation, err := db.CreateConversation("initializer", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	return db, conversation.ID
}

func newTestInitializer(t *testing.T, creator containerruntime.RuntimeCreator, store containerruntime.InitializationStore) *containerruntime.Initializer {
	t.Helper()
	initializer, err := containerruntime.NewInitializer(creator, store, containerruntime.InitializerOptions{
		Workers:       1,
		QueueCapacity: 4,
		CreateTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := initializer.Close(ctx); err != nil {
			t.Errorf("close initializer: %v", err)
		}
	})
	return initializer
}

func waitInitializationStatus(t *testing.T, db *database.DB, conversationID string, expected containerruntime.InitializationStatus) containerruntime.InitializationRecord {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		record, err := db.GetContainerInitialization(context.Background(), conversationID)
		if err == nil && record.Status == expected {
			return record
		}
		time.Sleep(time.Millisecond)
	}
	record, err := db.GetContainerInitialization(context.Background(), conversationID)
	t.Fatalf("status did not reach %s: %#v, %v", expected, record, err)
	return containerruntime.InitializationRecord{}
}

func initializerSpec(conversationID string) containerruntime.RuntimeSpec {
	return containerruntime.RuntimeSpec{
		ID:             containerruntime.RuntimeID("runtime-" + conversationID),
		ConversationID: conversationID,
		Image: containerruntime.ImageReference{
			Repository: "ghcr.io/usestrix/strix-sandbox",
			Digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Platform:   "linux/arm64",
		},
		Resources: containerruntime.ResourceLimits{
			NanoCPUs: 1_000_000_000, MemoryBytes: 512 << 20, PIDs: 128,
			NoFileSoft: 1024, NoFileHard: 2048, WorkspaceBytes: 1 << 30,
			MaxConcurrentExec: 2, MaxQueuedExec: 8, LogMaxBytes: 10 << 20, LogMaxFiles: 3,
		},
		Security: containerruntime.SecurityProfile{
			ReadOnlyRootFS: true, NoNewPrivileges: true, DropAllCapabilities: true,
			NetworkMode: containerruntime.NetworkNone, SeccompProfile: "default", TmpfsBytes: 64 << 20,
		},
		Workspace: containerruntime.WorkspaceSpec{MountPath: "/workspace"},
	}
}
