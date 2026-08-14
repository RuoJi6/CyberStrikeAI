package handler

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

func TestConversationHandlerDeleteConversationCancelsRunningTask(t *testing.T) {
	tm := NewAgentTaskManager()
	ctx, cancel := context.WithCancelCause(context.Background())
	_, err := tm.StartTask("conv-1", "hello", cancel)
	if err != nil {
		t.Fatalf("StartTask: %v", err)
	}

	h := &AgentHandler{tasks: tm, logger: zap.NewNop()}
	h.CancelRunningTaskForConversation("conv-1")

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("task context was not cancelled")
	}
	if cause := context.Cause(ctx); cause != ErrTaskCancelled {
		t.Fatalf("expected ErrTaskCancelled, got %v", cause)
	}
}

func TestUserStoppingConversationSuppressesPendingASMContinuation(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "agent-stop-asm.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	item := &database.ASMAgentContinuation{
		ID: "continuation-stop-test", TaskIDsJSON: `[]`, ConversationID: "conv-asm-stop", OwnerUserID: "user-1",
		Behavior: "auto", RunningPrompt: "running", IdlePrompt: "idle", Status: "waiting",
	}
	if err := db.CreateASMAgentContinuation(item); err != nil {
		t.Fatal(err)
	}
	tm := NewAgentTaskManager()
	ctx, cancel := context.WithCancelCause(context.Background())
	if _, err := tm.StartTask("conv-asm-stop", "hello", cancel); err != nil {
		t.Fatal(err)
	}
	h := &AgentHandler{tasks: tm, db: db, logger: zap.NewNop()}
	h.CancelRunningTaskForConversation("conv-asm-stop")
	stored, err := db.GetASMAgentContinuation(item.ID)
	if err != nil || stored.Status != "user_stopped" {
		t.Fatalf("pending continuation was not suppressed: %#v err=%v", stored, err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("task context was not cancelled")
	}
}

func TestConversationStopSuppressesPendingASMContinuationWithoutRuntimeTaskManager(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "agent-stop-no-runtime.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	item := &database.ASMAgentContinuation{
		ID: "continuation-stop-no-runtime", TaskIDsJSON: `[]`, ConversationID: "conv-no-runtime", OwnerUserID: "user-1",
		Behavior: "auto", RunningPrompt: "running", IdlePrompt: "idle", Status: "waiting",
	}
	if err := db.CreateASMAgentContinuation(item); err != nil {
		t.Fatal(err)
	}
	h := &AgentHandler{db: db, logger: zap.NewNop()}
	h.CancelRunningTaskForConversation("conv-no-runtime")
	stored, err := db.GetASMAgentContinuation(item.ID)
	if err != nil || stored.Status != "user_stopped" {
		t.Fatalf("pending continuation was not suppressed without a runtime task manager: %#v err=%v", stored, err)
	}
}
