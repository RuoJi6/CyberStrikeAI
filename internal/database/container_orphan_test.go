package database

import (
	"context"
	"testing"
	"time"

	containerruntime "cyberstrike-ai/internal/runtime/container"
)

func TestContainerResourceTombstoneLifecycleAndRetry(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 20, 16, 0, 0, 0, time.UTC)
	resource := containerruntime.ManagedResource{
		Kind:           containerruntime.ResourceKindAgent,
		LogicalID:      "orphan-runtime-01",
		ProviderID:     "provider-orphan-01",
		Name:           "cyberstrike-agent-orphan-runtime-01",
		ConversationID: "orphan-conversation-01",
	}
	tombstone, inserted, err := db.DiscoverResourceTombstone(ctx, resource, now)
	if err != nil || !inserted || tombstone.Status != containerruntime.ResourceTombstonePending || tombstone.Attempt != 0 {
		t.Fatalf("discover = %#v, %v, %v", tombstone, inserted, err)
	}
	if _, inserted, err := db.DiscoverResourceTombstone(ctx, resource, now.Add(time.Second)); err != nil || inserted {
		t.Fatalf("duplicate discover = %v, %v", inserted, err)
	}
	claimed, won, err := db.ClaimResourceTombstone(ctx, resource, now)
	if err != nil || !won || claimed.Status != containerruntime.ResourceTombstoneDeleting || claimed.Attempt != 1 || claimed.LastAttemptAt == nil {
		t.Fatalf("claim = %#v, %v, %v", claimed, won, err)
	}
	nextRetry := now.Add(time.Minute)
	if err := db.FailResourceTombstone(ctx, resource, "resource remains attached", nextRetry, now); err != nil {
		t.Fatal(err)
	}
	if due, err := db.ListRetryableResourceTombstones(ctx, now.Add(30*time.Second), 10); err != nil || len(due) != 0 {
		t.Fatalf("early retry = %#v, %v", due, err)
	}
	due, err := db.ListRetryableResourceTombstones(ctx, nextRetry, 10)
	if err != nil || len(due) != 1 || due[0].Status != containerruntime.ResourceTombstoneFailed || due[0].LastError == "" {
		t.Fatalf("due retry = %#v, %v", due, err)
	}
	claimed, won, err = db.ClaimResourceTombstone(ctx, resource, nextRetry)
	if err != nil || !won || claimed.Attempt != 2 {
		t.Fatalf("retry claim = %#v, %v, %v", claimed, won, err)
	}
	if err := db.CompleteResourceTombstone(ctx, resource, nextRetry); err != nil {
		t.Fatal(err)
	}
	completed, err := db.getResourceTombstone(ctx, resource.Kind, resource.ProviderID)
	if err != nil || completed.Status != containerruntime.ResourceTombstoneCompleted || completed.CompletedAt == nil || completed.NextRetryAt != nil || completed.LastError != "" {
		t.Fatalf("completed = %#v, %v", completed, err)
	}
}

func TestContainerResourceTombstoneRecoveryAndRuntimeClaims(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	conversation, err := db.CreateConversation("orphan claims", ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	spec := databaseRuntimeSpec(conversation.ID)
	if _, _, err := db.Queue(ctx, spec, false); err != nil {
		t.Fatal(err)
	}
	claims, err := db.ListManagedResourceClaims(ctx)
	if err != nil || len(claims) != 1 || claims[0].ProviderID != "" || claims[0].LogicalID != string(spec.ID) {
		t.Fatalf("queued claims = %#v, %v", claims, err)
	}
	if _, claimed, err := db.Claim(ctx, conversation.ID); err != nil || !claimed {
		t.Fatalf("claim runtime = %v, %v", claimed, err)
	}
	if _, err := db.Complete(ctx, conversation.ID, containerruntime.Runtime{ID: spec.ID, ProviderID: "provider-live-01", Status: containerruntime.StatusStopped}); err != nil {
		t.Fatal(err)
	}
	claims, err = db.ListManagedResourceClaims(ctx)
	if err != nil || len(claims) != 1 || claims[0].ProviderID != "provider-live-01" {
		t.Fatalf("created claims = %#v, %v", claims, err)
	}

	now := time.Date(2026, 8, 20, 16, 30, 0, 0, time.UTC)
	resource := containerruntime.ManagedResource{
		Kind:           containerruntime.ResourceKindWorkspaceVolume,
		LogicalID:      "workspace-orphan-01",
		ProviderID:     "cyberstrike-workspace-workspace-orphan-01",
		Name:           "cyberstrike-workspace-workspace-orphan-01",
		ConversationID: conversation.ID,
	}
	if _, _, err := db.DiscoverResourceTombstone(ctx, resource, now); err != nil {
		t.Fatal(err)
	}
	if _, won, err := db.ClaimResourceTombstone(ctx, resource, now); err != nil || !won {
		t.Fatalf("claim tombstone = %v, %v", won, err)
	}
	recovered, err := db.RecoverResourceTombstones(ctx, now.Add(time.Second), now.Add(2*time.Second))
	if err != nil || recovered != 1 {
		t.Fatalf("recover = %d, %v", recovered, err)
	}
	tombstone, err := db.getResourceTombstone(ctx, resource.Kind, resource.ProviderID)
	if err != nil || tombstone.Status != containerruntime.ResourceTombstoneFailed || tombstone.NextRetryAt == nil || tombstone.LastError == "" {
		t.Fatalf("recovered tombstone = %#v, %v", tombstone, err)
	}
}

func TestContainerResourceClaimsIncludePersistentWorkspaceVolume(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	conversation, err := db.CreateConversation("persistent claims", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer, WorkspacePersistent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	spec := databaseRuntimeSpec(conversation.ID)
	spec.ID = containerruntime.RuntimeID("conversation-" + conversation.ID)
	spec.Workspace.Persistent = true
	spec.Workspace.VolumeName = containerruntime.WorkspaceVolumeName(spec.ID)
	if _, _, err := db.Queue(context.Background(), spec, false); err != nil {
		t.Fatal(err)
	}
	claims, err := db.ListManagedResourceClaims(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 2 || claims[0].Kind != containerruntime.ResourceKindAgent || claims[1].Kind != containerruntime.ResourceKindWorkspaceVolume {
		t.Fatalf("claims = %#v", claims)
	}
	if claims[1].LogicalID != string(spec.ID) || claims[1].ProviderID != spec.Workspace.VolumeName || claims[1].ConversationID != conversation.ID {
		t.Fatalf("workspace claim = %#v", claims[1])
	}

	if _, claimed, err := db.Claim(context.Background(), conversation.ID); err != nil || !claimed {
		t.Fatalf("claim runtime = %v, %v", claimed, err)
	}
	if _, err := db.Complete(context.Background(), conversation.ID, containerruntime.Runtime{
		ID: spec.ID, ProviderID: "provider-persistent-01", Status: containerruntime.StatusStopped,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.BeginLifecycle(context.Background(), conversation.ID, containerruntime.LifecycleOperationDelete); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteLifecycle(context.Background(), conversation.ID, containerruntime.LifecycleOperationDelete); err != nil {
		t.Fatal(err)
	}
	claims, err = db.ListManagedResourceClaims(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || claims[0].Kind != containerruntime.ResourceKindWorkspaceVolume || claims[0].LogicalID != string(spec.ID) || claims[0].ProviderID != spec.Workspace.VolumeName || claims[0].ConversationID != conversation.ID {
		t.Fatalf("retained workspace claims = %#v", claims)
	}
}

func TestContainerResourceClaimsIncludeConversationNetwork(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	conversation, err := db.CreateConversation("internal network claims", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer,
	})
	if err != nil {
		t.Fatal(err)
	}
	spec := databaseRuntimeSpec(conversation.ID)
	spec.ID = containerruntime.RuntimeID("conversation-" + conversation.ID)
	spec.Security.NetworkMode = containerruntime.NetworkInternal
	if _, _, err := db.Queue(context.Background(), spec, false); err != nil {
		t.Fatal(err)
	}
	claims, err := db.ListManagedResourceClaims(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 2 || claims[0].Kind != containerruntime.ResourceKindAgent || claims[1].Kind != containerruntime.ResourceKindConversationNetwork {
		t.Fatalf("claims = %#v", claims)
	}
	if claims[1].LogicalID != string(spec.ID) || claims[1].ProviderID != "" || claims[1].ConversationID != conversation.ID {
		t.Fatalf("network claim = %#v", claims[1])
	}
}

func TestContainerResourceClaimsProtectLegacyNetworkDuringRebuildMigration(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	conversation, err := db.CreateConversation("legacy migration claims", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer,
	})
	if err != nil {
		t.Fatal(err)
	}
	spec := databaseRuntimeSpec(conversation.ID)
	spec.ID = containerruntime.RuntimeID("conversation-" + conversation.ID)
	if _, _, err := db.Queue(ctx, spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(ctx, conversation.ID); err != nil || !claimed {
		t.Fatalf("claim runtime = %v, %v", claimed, err)
	}
	if _, err := db.Complete(ctx, conversation.ID, containerruntime.Runtime{
		ID: spec.ID, ProviderID: "provider-legacy", Status: containerruntime.StatusStopped,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.BeginLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationRebuild); err != nil {
		t.Fatal(err)
	}
	assertMigrationNetworkClaim := func(stage string) {
		t.Helper()
		claims, err := db.ListManagedResourceClaims(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(claims) != 2 || claims[0].Kind != containerruntime.ResourceKindAgent || claims[1].Kind != containerruntime.ResourceKindConversationNetwork || claims[1].LogicalID != string(spec.ID) || claims[1].ProviderID != "" {
			t.Fatalf("%s claims = %#v", stage, claims)
		}
	}
	assertMigrationNetworkClaim("in-progress")
	if _, err := db.FailLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationRebuild, containerruntime.LifecycleFailure{
		Message: "interrupted", RuntimeStatus: containerruntime.StatusFailed, Drift: "rebuild_incomplete",
	}); err != nil {
		t.Fatal(err)
	}
	assertMigrationNetworkClaim("failed")
}

func TestDeleteConversationCanRetainPersistentWorkspaceClaim(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	conversation, err := db.CreateConversation("retain workspace after chat deletion", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer, WorkspacePersistent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteConversationWithWorkspaceRetention(conversation.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetConversationLite(conversation.ID); err == nil {
		t.Fatal("conversation still exists")
	}
	runtimeID := "conversation-" + conversation.ID
	volumeName := containerruntime.WorkspaceVolumeName(containerruntime.RuntimeID(runtimeID))
	var storedRuntimeID, storedVolumeName string
	if err := db.QueryRow(`
		SELECT runtime_id, volume_name FROM retained_container_workspaces
		WHERE original_conversation_id = ?
	`, conversation.ID).Scan(&storedRuntimeID, &storedVolumeName); err != nil {
		t.Fatal(err)
	}
	if storedRuntimeID != runtimeID || storedVolumeName != volumeName {
		t.Fatalf("retained identity = %q/%q", storedRuntimeID, storedVolumeName)
	}
	claims, err := db.ListManagedResourceClaims(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || claims[0].Kind != containerruntime.ResourceKindWorkspaceVolume || claims[0].ConversationID != conversation.ID || claims[0].LogicalID != runtimeID || claims[0].ProviderID != volumeName {
		t.Fatalf("retained claims = %#v", claims)
	}

	host, err := db.CreateConversation("host cannot retain workspace", ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteConversationWithWorkspaceRetention(host.ID, true); err == nil {
		t.Fatal("host conversation retained a nonexistent workspace")
	}
	if _, err := db.GetConversationLite(host.ID); err != nil {
		t.Fatalf("rejected host conversation deletion removed row: %v", err)
	}
}
