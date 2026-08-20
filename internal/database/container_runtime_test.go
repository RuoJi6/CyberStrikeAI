package database

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	containerruntime "cyberstrike-ai/internal/runtime/container"
	"go.uber.org/zap"
)

func TestContainerInitializationStoreLifecycleAndCascade(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	conversation, err := db.CreateConversation("container lifecycle", ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	spec := databaseRuntimeSpec(conversation.ID)

	record, enqueued, err := db.Queue(context.Background(), spec, false)
	if err != nil || !enqueued || record.Status != containerruntime.InitializationQueued || record.Attempt != 0 {
		t.Fatalf("queue = %#v, %v, %v", record, enqueued, err)
	}
	record, enqueued, err = db.Queue(context.Background(), spec, false)
	if err != nil || enqueued || record.Status != containerruntime.InitializationQueued {
		t.Fatalf("duplicate queue = %#v, %v, %v", record, enqueued, err)
	}
	record, claimed, err := db.Claim(context.Background(), conversation.ID)
	if err != nil || !claimed || record.Status != containerruntime.InitializationCreating || record.Attempt != 1 || record.StartedAt == nil {
		t.Fatalf("claim = %#v, %v, %v", record, claimed, err)
	}
	_, claimed, err = db.Claim(context.Background(), conversation.ID)
	if err != nil || claimed {
		t.Fatalf("duplicate claim = %v, %v", claimed, err)
	}
	record, err = db.Complete(context.Background(), conversation.ID, containerruntime.Runtime{
		ID:         spec.ID,
		ProviderID: "provider-01",
		Status:     containerruntime.StatusStopped,
	})
	if err != nil || record.Status != containerruntime.InitializationCreated || record.ProviderID != "provider-01" || record.RuntimeStatus != containerruntime.StatusStopped || record.CompletedAt == nil {
		t.Fatalf("complete = %#v, %v", record, err)
	}
	_, enqueued, err = db.Queue(context.Background(), spec, true)
	if err != nil || enqueued {
		t.Fatalf("created retry = %v, %v", enqueued, err)
	}

	if err := db.DeleteConversation(conversation.ID); err != nil {
		t.Fatal(err)
	}
	_, err = db.GetContainerInitialization(context.Background(), conversation.ID)
	if !errors.Is(err, containerruntime.ErrNotFound) {
		t.Fatalf("cascade get error = %v", err)
	}
}

func TestContainerInitializationStoreFailureRetryAndRecovery(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	failedConversation, err := db.CreateConversation("failed", ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	failedSpec := databaseRuntimeSpec(failedConversation.ID)
	if _, _, err := db.Queue(context.Background(), failedSpec, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.Claim(context.Background(), failedConversation.ID); err != nil {
		t.Fatal(err)
	}
	failed, err := db.Fail(context.Background(), failedConversation.ID, "engine unavailable")
	if err != nil || failed.Status != containerruntime.InitializationFailed || failed.LastError != "engine unavailable" {
		t.Fatalf("fail = %#v, %v", failed, err)
	}
	retried, enqueued, err := db.Queue(context.Background(), failedSpec, true)
	if err != nil || !enqueued || retried.Status != containerruntime.InitializationQueued || retried.Attempt != 1 || retried.LastError != "" {
		t.Fatalf("retry = %#v, %v, %v", retried, enqueued, err)
	}

	interruptedConversation, err := db.CreateConversation("interrupted", ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	interruptedSpec := databaseRuntimeSpec(interruptedConversation.ID)
	if _, _, err := db.Queue(context.Background(), interruptedSpec, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.Claim(context.Background(), interruptedConversation.ID); err != nil {
		t.Fatal(err)
	}
	recovered, err := db.RecoverInterrupted(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 2 {
		t.Fatalf("recovered = %#v", recovered)
	}
	for _, record := range recovered {
		if record.Status != containerruntime.InitializationQueued || record.StartedAt != nil {
			t.Fatalf("recovered record = %#v", record)
		}
	}
}

func TestContainerInitializationQueueIsAtomicAndImmutable(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	conversation, err := db.CreateConversation("container queue concurrency", ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	spec := databaseRuntimeSpec(conversation.ID)
	var enqueued atomic.Int32
	start := make(chan struct{})
	errorsCh := make(chan error, 16)
	var workers sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, shouldEnqueue, queueErr := db.Queue(context.Background(), spec, false)
			if queueErr != nil {
				errorsCh <- queueErr
				return
			}
			if shouldEnqueue {
				enqueued.Add(1)
			}
		}()
	}
	close(start)
	workers.Wait()
	close(errorsCh)
	for queueErr := range errorsCh {
		t.Errorf("concurrent queue: %v", queueErr)
	}
	if got := enqueued.Load(); got != 1 {
		t.Fatalf("enqueue winners = %d, want 1", got)
	}

	changed := spec
	changed.Resources.MemoryBytes++
	if _, _, err := db.Queue(context.Background(), changed, false); !errors.Is(err, containerruntime.ErrRuntimeStateConflict) {
		t.Fatalf("changed immutable specification error = %v", err)
	}

	orphan := databaseRuntimeSpec("missing-conversation")
	if _, _, err := db.Queue(context.Background(), orphan, false); err == nil {
		t.Fatal("queue accepted a runtime without a conversation")
	}
}

func newContainerRuntimeTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "container-runtime.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func databaseRuntimeSpec(conversationID string) containerruntime.RuntimeSpec {
	return containerruntime.RuntimeSpec{
		ID:             containerruntime.RuntimeID("runtime-" + conversationID),
		ConversationID: conversationID,
		Image: containerruntime.ImageReference{
			Repository: "ghcr.io/usestrix/strix-sandbox",
			Digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Platform:   "linux/arm64",
		},
		Resources: containerruntime.ResourceLimits{
			NanoCPUs:          1_000_000_000,
			MemoryBytes:       512 << 20,
			PIDs:              128,
			NoFileSoft:        1024,
			NoFileHard:        2048,
			WorkspaceBytes:    1 << 30,
			MaxConcurrentExec: 2,
			MaxQueuedExec:     8,
			LogMaxBytes:       10 << 20,
			LogMaxFiles:       3,
		},
		Security: containerruntime.SecurityProfile{
			ReadOnlyRootFS:      true,
			NoNewPrivileges:     true,
			DropAllCapabilities: true,
			NetworkMode:         containerruntime.NetworkNone,
			SeccompProfile:      "default",
			TmpfsBytes:          64 << 20,
		},
		Workspace: containerruntime.WorkspaceSpec{MountPath: "/workspace"},
	}
}
