package database

import (
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestASMTaskPersistenceAndFilters(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "asm-task.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	item := &ASMTask{
		ID: "asmtask_test", ResourceID: "asm_test", ResourceName: "Test ARL", Provider: "arl",
		RemoteTaskID: "0123456789abcdef01234567", Name: "authorized scan", Target: "192.0.2.1",
		OptionsJSON: `{}`, Status: "submitted", SummaryJSON: `{}`, DetailJSON: `{}`,
	}
	if err := db.CreateASMTask(item); err != nil {
		t.Fatal(err)
	}
	items, total, err := db.ListASMTasks(ASMTaskFilter{Provider: "arl", Query: "192.0.2", Page: 1, PageSize: 10})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("unexpected task query: items=%#v total=%d err=%v", items, total, err)
	}
	now := time.Now().UTC()
	item.Status, item.Progress, item.Stage, item.LastSyncedAt = "completed", 100, "done", &now
	if err := db.UpdateASMTask(item); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetASMTask(item.ID)
	if err != nil || got.Status != "completed" || got.Progress != 100 || got.LastSyncedAt == nil {
		t.Fatalf("unexpected updated task: %#v err=%v", got, err)
	}
	if err := db.UpsertASMTaskResult(item.ID, "site", `{"results":[]}`); err != nil {
		t.Fatal(err)
	}
	payload, cachedAt, err := db.GetASMTaskResult(item.ID, "site")
	if err != nil || payload == "" || cachedAt == nil {
		t.Fatalf("unexpected result snapshot: payload=%q cachedAt=%v err=%v", payload, cachedAt, err)
	}
}
