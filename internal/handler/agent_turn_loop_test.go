package handler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestAgentTurnLoopWaitsForForegroundTaskWithoutPolling(t *testing.T) {
	tasks := NewAgentTaskManager()
	conversationID := "conversation-turn-loop"
	if _, err := tasks.StartTask(conversationID, "foreground", func(error) {}); err != nil {
		t.Fatal(err)
	}

	managerCtx, cancelManager := context.WithCancel(context.Background())
	defer cancelManager()
	manager := NewAgentTurnLoopManager(managerCtx, tasks, zap.NewNop())
	called := make(chan struct{}, 1)
	result := make(chan error, 1)
	go func() {
		result <- manager.EnqueueAndWait(context.Background(), conversationID, "asm-continuation-1", func(context.Context) error {
			called <- struct{}{}
			return nil
		})
	}()

	select {
	case <-called:
		t.Fatal("deferred turn ran before the foreground task finished")
	case <-time.After(80 * time.Millisecond):
	}

	tasks.FinishTask(conversationID, "completed")
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("deferred turn did not run after the foreground task finished")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("EnqueueAndWait: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TurnLoop did not complete the deferred turn")
	}
}

func TestAgentTurnLoopSerializesDeferredTurnsPerConversation(t *testing.T) {
	tasks := NewAgentTaskManager()
	managerCtx, cancelManager := context.WithCancel(context.Background())
	defer cancelManager()
	manager := NewAgentTurnLoopManager(managerCtx, tasks, zap.NewNop())

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var active atomic.Int32
	var maxActive atomic.Int32
	run := func(id string, block bool) <-chan error {
		result := make(chan error, 1)
		go func() {
			result <- manager.EnqueueAndWait(context.Background(), "conversation-serial", id, func(context.Context) error {
				current := active.Add(1)
				for {
					old := maxActive.Load()
					if current <= old || maxActive.CompareAndSwap(old, current) {
						break
					}
				}
				defer active.Add(-1)
				if block {
					close(firstStarted)
					<-releaseFirst
				}
				return nil
			})
		}()
		return result
	}
	first := run("first", true)
	<-firstStarted
	second := run("second", false)
	time.Sleep(50 * time.Millisecond)
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("deferred turns overlapped: max active = %d", got)
	}
	close(releaseFirst)
	for index, result := range []<-chan error{first, second} {
		select {
		case err := <-result:
			if err != nil {
				t.Fatalf("turn %d failed: %v", index+1, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("turn %d did not finish", index+1)
		}
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("deferred turns were not serialized: max active = %d", got)
	}
}

func TestStartTaskAtPreservesContinuationElapsedOrigin(t *testing.T) {
	tasks := NewAgentTaskManager()
	logicalStartedAt := time.Now().Add(-5*time.Minute - 27*time.Second).Truncate(time.Millisecond)
	task, err := tasks.StartTaskAt("conversation-inherited", "ASM completed", func(error) {}, logicalStartedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !task.StartedAt.Equal(logicalStartedAt) {
		t.Fatalf("startedAt = %s, want inherited %s", task.StartedAt, logicalStartedAt)
	}
	tasks.FinishTask(task.ConversationID, "completed")
}
