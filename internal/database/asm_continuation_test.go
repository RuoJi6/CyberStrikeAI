package database

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestListASMAgentContinuationsFiltersAccessStatusAndCounts(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "asm-continuations.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows := []*ASMAgentContinuation{
		{ID: "cont-waiting", TaskIDsJSON: `[]`, ConversationID: "conv-a", OwnerUserID: "user-a", Behavior: "auto", Status: "waiting"},
		{ID: "cont-stopped", TaskIDsJSON: `[]`, ConversationID: "conv-a", OwnerUserID: "user-a", Behavior: "auto", Status: "user_stopped", LastError: "用户主动停止"},
		{ID: "cont-completed", TaskIDsJSON: `[]`, ConversationID: "conv-b", OwnerUserID: "user-b", Behavior: "auto", Status: "completed"},
	}
	for _, item := range rows {
		if err := db.CreateASMAgentContinuation(item); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := db.GetASMAgentContinuation("cont-waiting")
	if err != nil || stored.DeliveryMode != "after_turn" {
		t.Fatalf("legacy/default delivery mode = %q, err=%v", stored.DeliveryMode, err)
	}

	items, total, err := db.ListASMAgentContinuations(ASMAgentContinuationFilter{
		Page: 1, PageSize: 20, Access: RBACListAccess{UserID: "user-a", Scope: RBACScopeOwn},
	})
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("unexpected own continuation page: total=%d items=%#v err=%v", total, items, err)
	}
	items, total, err = db.ListASMAgentContinuations(ASMAgentContinuationFilter{
		Page: 2, PageSize: 1, Access: RBACListAccess{UserID: "user-a", Scope: RBACScopeOwn},
	})
	if err != nil || total != 2 || len(items) != 1 {
		t.Fatalf("unexpected paginated continuation page: total=%d items=%#v err=%v", total, items, err)
	}
	items, total, err = db.ListASMAgentContinuations(ASMAgentContinuationFilter{
		Statuses: []string{"user_stopped"}, Query: "主动停止", Page: 1, PageSize: 20,
		Access: RBACListAccess{UserID: "user-a", Scope: RBACScopeOwn},
	})
	if err != nil || total != 1 || len(items) != 1 || items[0].ID != "cont-stopped" {
		t.Fatalf("unexpected stopped continuation filter: total=%d items=%#v err=%v", total, items, err)
	}
	counts, err := db.CountASMAgentContinuationsByStatus(RBACListAccess{Scope: RBACScopeAll})
	if err != nil || counts["waiting"] != 1 || counts["user_stopped"] != 1 || counts["completed"] != 1 {
		t.Fatalf("unexpected continuation counts: counts=%#v err=%v", counts, err)
	}
}
