package database

import (
	"context"
	"testing"
	"time"
)

func TestNewContainerConversationDefaultsToDedicatedWorkspaceAndDeletePolicy(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	conversation, err := db.CreateConversation("default container", ConversationCreateMeta{RuntimeMode: ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if !conversation.WorkspacePersistent || conversation.WorkspaceMode != ConversationWorkspaceModeDedicated {
		t.Fatalf("workspace = persistent:%v mode:%q", conversation.WorkspacePersistent, conversation.WorkspaceMode)
	}
	binding, err := db.GetConversationWorkspaceBinding(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Mode != ConversationWorkspaceModeDedicated || binding.Workspace == nil {
		t.Fatalf("binding = %#v", binding)
	}
	policy, err := db.GetConversationIdlePolicy(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Action != ConversationIdleActionDelete || policy.TimeoutSeconds != ConversationIdleTimeoutDefaultSeconds {
		t.Fatalf("idle policy = %#v", policy)
	}
}

func TestExplicitEphemeralWorkspaceAndLegacyIdleMigration(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	conversation, err := db.CreateConversation("ephemeral", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer, WorkspaceMode: ConversationWorkspaceModeEphemeral,
	})
	if err != nil {
		t.Fatal(err)
	}
	if conversation.WorkspacePersistent || conversation.WorkspaceMode != ConversationWorkspaceModeEphemeral {
		t.Fatalf("workspace = %#v", conversation)
	}
	if _, err := db.Exec(`UPDATE conversations SET idle_action = NULL, idle_timeout_seconds = NULL WHERE id = ?`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateLegacyConversationIdlePolicies(context.Background(), 2700); err != nil {
		t.Fatal(err)
	}
	policy, err := db.GetConversationIdlePolicy(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Action != ConversationIdleActionStop || policy.TimeoutSeconds != 2700 {
		t.Fatalf("migrated policy = %#v", policy)
	}
}

func TestConversationIdlePolicyValidationAndUpdate(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	conversation, err := db.CreateConversation("policy", ConversationCreateMeta{RuntimeMode: ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := db.SetConversationIdlePolicy(context.Background(), conversation.ID, ConversationIdlePolicy{Action: ConversationIdleActionNone, TimeoutSeconds: 60})
	if err != nil || updated.Action != ConversationIdleActionNone {
		t.Fatalf("updated = %#v, %v", updated, err)
	}
	if _, err := db.SetConversationIdlePolicy(context.Background(), conversation.ID, ConversationIdlePolicy{Action: ConversationIdleActionDelete, TimeoutSeconds: 59}); err == nil {
		t.Fatal("accepted timeout below one minute")
	}
	if _, err := db.SetConversationIdlePolicy(context.Background(), conversation.ID, ConversationIdlePolicy{Action: "pause", TimeoutSeconds: 60}); err == nil {
		t.Fatal("accepted unsupported idle action")
	}
	after, err := db.GetConversationLite(conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.UpdatedAt.Equal(conversation.UpdatedAt) && after.UpdatedAt.Sub(conversation.UpdatedAt) > time.Millisecond {
		t.Fatalf("changing idle policy reset last activity: before=%s after=%s", conversation.UpdatedAt, after.UpdatedAt)
	}
}

func TestExplicitEphemeralWorkspaceSurvivesHostRoundTrip(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	conversation, err := db.CreateConversation("explicit ephemeral", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer, WorkspaceMode: ConversationWorkspaceModeEphemeral,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetConversationRuntimeMode(conversation.ID, ConversationRuntimeModeHost); err != nil {
		t.Fatal(err)
	}
	if err := db.SetConversationRuntimeMode(conversation.ID, ConversationRuntimeModeContainer); err != nil {
		t.Fatal(err)
	}
	binding, err := db.GetConversationWorkspaceBinding(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Mode != ConversationWorkspaceModeEphemeral || binding.Workspace != nil {
		t.Fatalf("workspace changed during host round trip: %#v", binding)
	}
}
