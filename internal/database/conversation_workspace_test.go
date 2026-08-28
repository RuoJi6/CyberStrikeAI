package database

import (
	"context"
	"path/filepath"
	"testing"

	containerruntime "cyberstrike-ai/internal/runtime/container"
	"go.uber.org/zap"
)

func TestSharedContainerWorkspaceCanAttachMultipleConversations(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "shared-workspace.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	project, err := db.CreateProject(&Project{Name: "shared workspace project"})
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	workspace, err := db.CreateSharedContainerWorkspace(context.Background(), "复用工作区", project.ID)
	if err != nil {
		t.Fatalf("CreateSharedContainerWorkspace: %v", err)
	}
	if workspace.Kind != ContainerWorkspaceKindShared || workspace.VolumeName != containerruntime.WorkspaceVolumeNameForID(workspace.ID) {
		t.Fatalf("workspace = %#v", workspace)
	}

	create := func(title string) *Conversation {
		conversation, createErr := db.CreateConversation(title, ConversationCreateMeta{
			ProjectID: project.ID, RuntimeMode: ConversationRuntimeModeContainer, WorkspaceID: workspace.ID,
		})
		if createErr != nil {
			t.Fatalf("CreateConversation(%q): %v", title, createErr)
		}
		return conversation
	}
	first, second := create("共享一"), create("共享二")

	for _, conversation := range []*Conversation{first, second} {
		binding, bindingErr := db.GetConversationWorkspaceBinding(context.Background(), conversation.ID)
		if bindingErr != nil {
			t.Fatalf("GetConversationWorkspaceBinding(%s): %v", conversation.ID, bindingErr)
		}
		if binding.Mode != ConversationWorkspaceModeShared || binding.Workspace == nil || binding.Workspace.ID != workspace.ID {
			t.Fatalf("binding = %#v", binding)
		}
	}
	got, err := db.GetContainerWorkspace(context.Background(), workspace.ID)
	if err != nil {
		t.Fatalf("GetContainerWorkspace: %v", err)
	}
	if got.AttachedConversations != 2 {
		t.Fatalf("attached conversations = %d, want 2", got.AttachedConversations)
	}
	attachments, err := db.ListContainerWorkspaceAttachments(context.Background(), workspace.ID)
	if err != nil || len(attachments) != 2 {
		t.Fatalf("attachments = %#v, err=%v", attachments, err)
	}

	claims, err := db.ListManagedResourceClaims(context.Background())
	if err != nil {
		t.Fatalf("ListManagedResourceClaims: %v", err)
	}
	workspaceClaims := 0
	for _, claim := range claims {
		if claim.Kind == containerruntime.ResourceKindWorkspaceVolume && claim.LogicalID == workspace.ID {
			workspaceClaims++
			if claim.ProviderID != workspace.VolumeName || claim.ConversationID != "" {
				t.Fatalf("shared workspace claim = %#v", claim)
			}
		}
	}
	if workspaceClaims != 1 {
		t.Fatalf("shared workspace claims = %d, want 1", workspaceClaims)
	}

	if err := db.DeleteConversation(first.ID); err != nil {
		t.Fatalf("DeleteConversation(first): %v", err)
	}
	got, err = db.GetContainerWorkspace(context.Background(), workspace.ID)
	if err != nil {
		t.Fatalf("shared workspace was removed with one conversation: %v", err)
	}
	if got.AttachedConversations != 1 {
		t.Fatalf("attachments after deleting first = %d, want 1", got.AttachedConversations)
	}
	if _, err := db.DeleteContainerWorkspaceRecord(context.Background(), workspace.ID); err == nil {
		t.Fatal("attached shared workspace was deleted")
	}

	binding, err := db.SetConversationWorkspaceBinding(context.Background(), second.ID, ConversationWorkspaceModeEphemeral, "")
	if err != nil {
		t.Fatalf("SetConversationWorkspaceBinding(ephemeral): %v", err)
	}
	if binding.Mode != ConversationWorkspaceModeEphemeral || binding.Workspace != nil {
		t.Fatalf("ephemeral binding = %#v", binding)
	}
	removed, err := db.DeleteContainerWorkspaceRecord(context.Background(), workspace.ID)
	if err != nil || removed.ID != workspace.ID {
		t.Fatalf("DeleteContainerWorkspaceRecord = %#v, err=%v", removed, err)
	}
}

func TestConversationWorkspaceBindingRejectsCrossProjectAndHostUse(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "workspace-scope.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	left, _ := db.CreateProject(&Project{Name: "left"})
	right, _ := db.CreateProject(&Project{Name: "right"})
	workspace, err := db.CreateSharedContainerWorkspace(context.Background(), "left only", left.ID)
	if err != nil {
		t.Fatalf("CreateSharedContainerWorkspace: %v", err)
	}
	if _, err := db.CreateConversation("wrong project", ConversationCreateMeta{
		ProjectID: right.ID, RuntimeMode: ConversationRuntimeModeContainer, WorkspaceID: workspace.ID,
	}); err == nil {
		t.Fatal("cross-project shared workspace was accepted")
	}
	host, err := db.CreateConversation("host", ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("CreateConversation(host): %v", err)
	}
	if _, err := db.SetConversationWorkspaceBinding(context.Background(), host.ID, ConversationWorkspaceModeShared, workspace.ID); err == nil {
		t.Fatal("host conversation accepted a shared workspace")
	}
	if _, err := db.GetContainerWorkspace(context.Background(), "missing"); err == nil {
		t.Fatal("missing workspace unexpectedly exists")
	}
}

func TestSwitchingAwayFromDedicatedWorkspaceRemovesDedicatedResourceRecord(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "dedicated-switch.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	conversation, err := db.CreateConversation("dedicated", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer, WorkspacePersistent: true,
	})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	before, err := db.GetConversationWorkspaceBinding(context.Background(), conversation.ID)
	if err != nil || before.Workspace == nil || before.Workspace.Kind != ContainerWorkspaceKindDedicated {
		t.Fatalf("dedicated binding = %#v, err=%v", before, err)
	}
	dedicatedID := before.Workspace.ID

	after, err := db.SetConversationWorkspaceBinding(context.Background(), conversation.ID, ConversationWorkspaceModeEphemeral, "")
	if err != nil {
		t.Fatalf("SetConversationWorkspaceBinding: %v", err)
	}
	if after.Mode != ConversationWorkspaceModeEphemeral || after.Workspace != nil {
		t.Fatalf("ephemeral binding = %#v", after)
	}
	if _, err := db.GetContainerWorkspace(context.Background(), dedicatedID); err == nil {
		t.Fatal("old dedicated workspace record still exists")
	}
}

func TestContainerWorkspaceIsAssignableRBACResource(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "workspace-rbac.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.CreateRBACUser("workspace-member", "Workspace Member", "hash", true, nil)
	if err != nil {
		t.Fatalf("CreateRBACUser: %v", err)
	}
	workspace, err := db.CreateSharedContainerWorkspace(context.Background(), "共享研发目录", "")
	if err != nil {
		t.Fatalf("CreateSharedContainerWorkspace: %v", err)
	}
	options, err := db.ListAssignableRBACResources("container_workspace", "研发", 10)
	if err != nil {
		t.Fatalf("ListAssignableRBACResources: %v", err)
	}
	if len(options) != 1 || options[0].ID != workspace.ID || options[0].Label != workspace.Name {
		t.Fatalf("workspace options = %#v", options)
	}
	if err := db.AssignResourceToUser(user.ID, "container_workspace", workspace.ID); err != nil {
		t.Fatalf("AssignResourceToUser: %v", err)
	}
	if !db.UserCanAccessResource(user.ID, RBACScopeAssigned, "container_workspace", workspace.ID) {
		t.Fatal("assigned user cannot access shared workspace")
	}
	if _, err := db.DeleteContainerWorkspaceRecord(context.Background(), workspace.ID); err != nil {
		t.Fatalf("DeleteContainerWorkspaceRecord: %v", err)
	}
	if db.UserCanAccessResource(user.ID, RBACScopeAssigned, "container_workspace", workspace.ID) {
		t.Fatal("deleted workspace left a stale RBAC assignment")
	}
}

func TestAssignedWorkspacePaginationFiltersBeforeLimit(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "workspace-page.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.CreateRBACUser("workspace-page-user", "Workspace Page User", "hash", true, nil)
	if err != nil {
		t.Fatalf("CreateRBACUser: %v", err)
	}
	assigned, err := db.CreateSharedContainerWorkspace(context.Background(), "assigned second", "")
	if err != nil {
		t.Fatalf("CreateSharedContainerWorkspace(assigned): %v", err)
	}
	unassigned, err := db.CreateSharedContainerWorkspace(context.Background(), "unassigned first", "")
	if err != nil {
		t.Fatalf("CreateSharedContainerWorkspace(unassigned): %v", err)
	}
	if err := db.AssignResourceToUser(user.ID, "container_workspace", assigned.ID); err != nil {
		t.Fatalf("AssignResourceToUser: %v", err)
	}
	items, total, err := db.ListAssignedSharedContainerWorkspaces(context.Background(), "", "", user.ID, 1, 0)
	if err != nil {
		t.Fatalf("ListAssignedSharedContainerWorkspaces: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != assigned.ID {
		t.Fatalf("assigned page = %#v total=%d (unassigned=%s)", items, total, unassigned.ID)
	}
}
