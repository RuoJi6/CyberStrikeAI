package database

import (
	"context"
	"testing"

	containerruntime "cyberstrike-ai/internal/runtime/container"
)

func TestContainerRuntimeListPaginatesSearchesAndFiltersOnServer(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()

	create := func(title string, persistent bool) *Conversation {
		conversation, err := db.CreateConversation(title, ConversationCreateMeta{
			RuntimeMode: ConversationRuntimeModeContainer, WorkspacePersistent: persistent,
		})
		if err != nil {
			t.Fatal(err)
		}
		return conversation
	}
	running := create("alpha running", true)
	stopped := create("beta stopped", false)
	pending := create("gamma pending", false)
	failed := create("delta failed", false)
	notRequested := create("literal 100% idle", false)
	create("underscore_target", false)
	if _, err := db.CreateConversation("host excluded", ConversationCreateMeta{RuntimeMode: ConversationRuntimeModeHost}); err != nil {
		t.Fatal(err)
	}

	complete := func(conversation *Conversation, status containerruntime.Status) {
		spec := databaseRuntimeSpec(conversation.ID)
		if _, _, err := db.Queue(ctx, spec, false); err != nil {
			t.Fatal(err)
		}
		if _, claimed, err := db.Claim(ctx, conversation.ID); err != nil || !claimed {
			t.Fatalf("claim %s = %v, %v", conversation.ID, claimed, err)
		}
		if _, err := db.Complete(ctx, conversation.ID, containerruntime.Runtime{
			ID: spec.ID, ProviderID: "provider-" + conversation.ID, Status: status,
		}); err != nil {
			t.Fatal(err)
		}
	}
	complete(running, containerruntime.StatusRunning)
	complete(stopped, containerruntime.StatusStopped)
	if _, err := db.Exec(`UPDATE conversation_container_runtimes SET spec_json = json_set(spec_json, '$.EgressGateway', json('{}')) WHERE conversation_id = ?`, running.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.Queue(ctx, databaseRuntimeSpec(pending.ID), false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.Queue(ctx, databaseRuntimeSpec(failed.ID), false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Fail(ctx, failed.ID, "synthetic failure"); err != nil {
		t.Fatal(err)
	}

	query := ContainerRuntimeListQuery{Limit: 2, Status: "all", Scope: RBACScopeAll}
	rows, err := db.ListContainerConversationsForAccess(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("page rows = %d, want 2", len(rows))
	}
	summary, err := db.SummarizeContainerConversationsForAccess(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 6 || summary.Running != 1 || summary.Gateways != 1 || summary.Persistent != 1 || summary.Attention != 1 {
		t.Fatalf("summary = %#v", summary)
	}

	query.Limit = 10
	query.Status = "running"
	rows, err = db.ListContainerConversationsForAccess(ctx, query)
	if err != nil || len(rows) != 1 || rows[0].ID != running.ID {
		t.Fatalf("running rows = %#v, %v", rows, err)
	}
	query.Status = "stopped"
	rows, err = db.ListContainerConversationsForAccess(ctx, query)
	if err != nil || len(rows) != 1 || rows[0].ID != stopped.ID {
		t.Fatalf("stopped rows = %#v, %v", rows, err)
	}
	query.Status = "pending"
	rows, err = db.ListContainerConversationsForAccess(ctx, query)
	if err != nil || len(rows) != 1 || rows[0].ID != pending.ID {
		t.Fatalf("pending rows = %#v, %v", rows, err)
	}
	query.Status = "failed"
	rows, err = db.ListContainerConversationsForAccess(ctx, query)
	if err != nil || len(rows) != 1 || rows[0].ID != failed.ID {
		t.Fatalf("failed rows = %#v, %v", rows, err)
	}
	query.Status = "not_requested"
	query.Search = "%"
	rows, err = db.ListContainerConversationsForAccess(ctx, query)
	if err != nil || len(rows) != 1 || rows[0].ID != notRequested.ID {
		t.Fatalf("literal percent search rows = %#v, %v", rows, err)
	}
	query.Search = "_target"
	rows, err = db.ListContainerConversationsForAccess(ctx, query)
	if err != nil || len(rows) != 1 || rows[0].Title != "underscore_target" {
		t.Fatalf("literal underscore search rows = %#v, %v", rows, err)
	}
}

func TestNormalizeContainerRuntimeListStatusIsClosed(t *testing.T) {
	for _, status := range []string{"", "all", "not_requested", "pending", "running", "stopped", "failed", " RUNNING "} {
		if _, ok := NormalizeContainerRuntimeListStatus(status); !ok {
			t.Fatalf("status %q rejected", status)
		}
	}
	if _, ok := NormalizeContainerRuntimeListStatus("healthy"); ok {
		t.Fatal("unexpected status accepted")
	}
}
