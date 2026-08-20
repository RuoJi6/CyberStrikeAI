package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	containerruntime "cyberstrike-ai/internal/runtime/container"
	"go.uber.org/zap"
)

func TestContainerInitializationReadinessLifecycleRetryAndRecovery(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	conversation, err := db.CreateConversation("readiness lifecycle", ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	spec := databaseReadinessRuntimeSpec(conversation.ID)
	record, enqueued, err := db.Queue(context.Background(), spec, false)
	if err != nil || !enqueued || record.ReadinessStatus != containerruntime.ReadinessPending {
		t.Fatalf("queue readiness = %#v, %v, %v", record, enqueued, err)
	}
	if _, claimed, err := db.Claim(context.Background(), conversation.ID); err != nil || !claimed {
		t.Fatalf("claim creation = %v, %v", claimed, err)
	}
	runtime := containerruntime.Runtime{ID: spec.ID, ProviderID: "provider-readiness", Status: containerruntime.StatusStopped}
	if _, err := db.Complete(context.Background(), conversation.ID, runtime); err != nil {
		t.Fatal(err)
	}
	record, claimed, err := db.ClaimReadiness(context.Background(), conversation.ID)
	if err != nil || !claimed || record.ReadinessStatus != containerruntime.ReadinessValidating || record.ReadinessStartedAt == nil {
		t.Fatalf("claim readiness = %#v, %v, %v", record, claimed, err)
	}
	record, err = db.FailReadiness(context.Background(), conversation.ID, "missing /bin/sh")
	if err != nil || record.Status != containerruntime.InitializationCreated || record.ReadinessStatus != containerruntime.ReadinessFailed || record.ReadinessError == "" || record.ReadinessCompletedAt == nil {
		t.Fatalf("fail readiness = %#v, %v", record, err)
	}
	record, enqueued, err = db.Queue(context.Background(), spec, true)
	if err != nil || !enqueued || record.Status != containerruntime.InitializationCreated || record.ReadinessStatus != containerruntime.ReadinessPending || record.ProviderID != runtime.ProviderID || record.Attempt != 1 {
		t.Fatalf("retry readiness = %#v, %v, %v", record, enqueued, err)
	}
	if _, claimed, err := db.Claim(context.Background(), conversation.ID); err != nil || claimed {
		t.Fatalf("readiness retry recreated container = %v, %v", claimed, err)
	}
	if _, claimed, err := db.ClaimReadiness(context.Background(), conversation.ID); err != nil || !claimed {
		t.Fatalf("reclaim readiness = %v, %v", claimed, err)
	}
	record, err = db.Ready(context.Background(), conversation.ID, containerruntime.ReadinessReport{
		InventoryDigest: spec.Readiness.InventoryDigest,
		ToolCount:       len(spec.Readiness.Inventory.Tools),
	})
	if err != nil || record.ReadinessStatus != containerruntime.ReadinessReady || record.InventoryDigest != spec.Readiness.InventoryDigest || record.ToolCount != 1 || record.ReadinessCompletedAt == nil {
		t.Fatalf("ready = %#v, %v", record, err)
	}
	if _, enqueued, err := db.Queue(context.Background(), spec, true); err != nil || enqueued {
		t.Fatalf("ready retry = %v, %v", enqueued, err)
	}

	interruptedConversation, err := db.CreateConversation("readiness interrupted", ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	interruptedSpec := databaseReadinessRuntimeSpec(interruptedConversation.ID)
	if _, _, err := db.Queue(context.Background(), interruptedSpec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(context.Background(), interruptedConversation.ID); err != nil || !claimed {
		t.Fatalf("claim interrupted creation = %v, %v", claimed, err)
	}
	if _, err := db.Complete(context.Background(), interruptedConversation.ID, containerruntime.Runtime{ID: interruptedSpec.ID, ProviderID: "provider-interrupted", Status: containerruntime.StatusStopped}); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.ClaimReadiness(context.Background(), interruptedConversation.ID); err != nil || !claimed {
		t.Fatalf("claim interrupted readiness = %v, %v", claimed, err)
	}
	recovered, err := db.RecoverInterrupted(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 1 || recovered[0].ConversationID != interruptedConversation.ID || recovered[0].Status != containerruntime.InitializationCreated || recovered[0].ReadinessStatus != containerruntime.ReadinessPending || recovered[0].ReadinessStartedAt != nil {
		t.Fatalf("recovered readiness = %#v", recovered)
	}
}

func TestContainerRuntimeTableMigratesPreReadinessSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-readiness.db")
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`CREATE TABLE conversation_container_runtimes (
		conversation_id TEXT PRIMARY KEY, runtime_id TEXT NOT NULL UNIQUE,
		initialization_status TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 0,
		provider_id TEXT NOT NULL DEFAULT '', runtime_status TEXT NOT NULL DEFAULT '',
		image_digest TEXT NOT NULL, image_platform TEXT NOT NULL, spec_json TEXT NOT NULL,
		last_error TEXT NOT NULL DEFAULT '', requested_at DATETIME NOT NULL,
		started_at DATETIME, completed_at DATETIME, updated_at DATETIME NOT NULL
	)`)
	if closeErr := raw.Close(); err != nil || closeErr != nil {
		t.Fatalf("create old schema: %v, close: %v", err, closeErr)
	}
	db, err := NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`PRAGMA table_info(conversation_container_runtimes)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue interface{}
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	for _, name := range []string{"readiness_status", "readiness_error", "inventory_digest", "tool_count", "readiness_started_at", "readiness_completed_at"} {
		if !columns[name] {
			t.Fatalf("migration did not add %s: %#v", name, columns)
		}
	}
}

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

func databaseReadinessRuntimeSpec(conversationID string) containerruntime.RuntimeSpec {
	spec := databaseRuntimeSpec(conversationID)
	spec.Readiness = containerruntime.ReadinessPolicy{
		Enabled:         true,
		InventoryDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Inventory: containerruntime.ToolInventory{
			SchemaVersion: containerruntime.ToolInventorySchemaVersion,
			ImageDigest:   spec.Image.Digest,
			ImagePlatform: spec.Image.Platform,
			Tools: []containerruntime.ToolInventoryEntry{
				{Name: "sh", Path: "/bin/sh", Version: "busybox-1", Category: "runtime"},
			},
		},
	}
	return spec
}
