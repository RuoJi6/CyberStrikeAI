package database

import (
	"path/filepath"
	"strings"
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

func TestASMResultItemsPaginationSearchAndSyncState(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "asm-result-items.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	task := &ASMTask{ID: "task-results", ResourceID: "resource", ResourceName: "ASM", Provider: "arl", RemoteTaskID: "remote", OptionsJSON: "{}", SummaryJSON: "{}", DetailJSON: "{}"}
	if err := db.CreateASMTask(task); err != nil {
		t.Fatal(err)
	}
	items := []ASMResultItem{
		{ItemKey: "a", ProviderKey: "provider-a", PayloadJSON: `{"site":"https://alpha.example"}`, SearchText: "https://alpha.example", SortOrder: 0},
		{ItemKey: "b", ProviderKey: "provider-b", PayloadJSON: `{"site":"https://beta.example"}`, SearchText: "https://beta.example", SortOrder: 1},
		{ItemKey: "c", ProviderKey: "provider-c", PayloadJSON: `{"site":"https://gamma.example"}`, SearchText: "https://gamma.example", SortOrder: 2},
	}
	if err := db.ReplaceASMResultItems(task.ID, "site", items); err != nil {
		t.Fatal(err)
	}
	page, total, err := db.ListASMResultItems(task.ID, "site", "", 2, 2)
	if err != nil || total != 3 || len(page) != 1 || !strings.Contains(page[0], "gamma") {
		t.Fatalf("unexpected page: total=%d rows=%v err=%v", total, page, err)
	}
	filtered, total, err := db.ListASMResultItems(task.ID, "site", "BETA", 1, 20)
	if err != nil || total != 1 || len(filtered) != 1 || !strings.Contains(filtered[0], "beta") {
		t.Fatalf("unexpected search: total=%d rows=%v err=%v", total, filtered, err)
	}
	now := time.Now().UTC()
	if err := db.UpsertASMResultSyncState(ASMResultSyncState{TaskID: task.ID, AssetType: "site", Status: "completed", ItemCount: 3, StartedAt: &now, SyncedAt: &now}); err != nil {
		t.Fatal(err)
	}
	states, err := db.ListASMResultSyncStates(task.ID)
	if err != nil || len(states) != 1 || states[0].Status != "completed" || states[0].ItemCount != 3 {
		t.Fatalf("unexpected states: %#v err=%v", states, err)
	}
	detail, err := db.GetASMResultItem(task.ID, "site", "provider-b")
	if err != nil || !strings.Contains(detail, "beta") {
		t.Fatalf("unexpected detail: %s err=%v", detail, err)
	}
}
