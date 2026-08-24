package handler

import (
	"testing"
	"time"
)

func TestGetActiveTasksUsesStableCreationOrder(t *testing.T) {
	m := NewAgentTaskManager()
	started := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	m.mu.Lock()
	m.tasks = map[string]*AgentTask{
		"conversation-z":    {ConversationID: "conversation-z", StartedAt: started, Status: "running"},
		"conversation-late": {ConversationID: "conversation-late", StartedAt: started.Add(time.Minute), Status: "running"},
		"conversation-a":    {ConversationID: "conversation-a", StartedAt: started, Status: "running"},
	}
	m.mu.Unlock()

	want := []string{"conversation-a", "conversation-z", "conversation-late"}
	for attempt := 0; attempt < 20; attempt++ {
		gotTasks := m.GetActiveTasks()
		if len(gotTasks) != len(want) {
			t.Fatalf("GetActiveTasks() length = %d, want %d", len(gotTasks), len(want))
		}
		for i, task := range gotTasks {
			if task.ConversationID != want[i] {
				t.Fatalf("attempt %d order[%d] = %q, want %q", attempt, i, task.ConversationID, want[i])
			}
		}
	}
}

func TestGetActiveTasksIncludesServerClockElapsedTime(t *testing.T) {
	m := NewAgentTaskManager()
	m.mu.Lock()
	m.tasks = map[string]*AgentTask{
		"conversation-running": {
			ConversationID: "conversation-running",
			StartedAt:      time.Now().Add(-65 * time.Second),
			Status:         "running",
		},
	}
	m.mu.Unlock()

	tasks := m.GetActiveTasks()
	if len(tasks) != 1 {
		t.Fatalf("GetActiveTasks() length = %d, want 1", len(tasks))
	}
	if got := tasks[0].ElapsedMS; got < 64_000 || got > 67_000 {
		t.Fatalf("ElapsedMS = %d, want about 65000", got)
	}
}
