package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type fakeConversationContainerTerminalProvider struct {
	record    containerruntime.InitializationRecord
	workspace containerruntime.WorkspaceInfo
	err       error
}

func (f *fakeConversationContainerTerminalProvider) Get(context.Context, string) (containerruntime.InitializationRecord, error) {
	return f.record, f.err
}

func (f *fakeConversationContainerTerminalProvider) WorkspaceInfo(context.Context, containerruntime.RuntimeSpec) (containerruntime.WorkspaceInfo, error) {
	return f.workspace, f.err
}

func performConversationTerminalRequest(user *database.RBACUser, permissions map[string]bool, path string, handler gin.HandlerFunc, conversationID string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, path, bytes.NewReader(nil))
	c.Params = gin.Params{{Key: "id", Value: conversationID}}
	c.Set(security.ContextSessionKey, security.Session{
		UserID: user.ID, Username: user.Username, Permissions: permissions, Scope: database.RBACScopeAssigned,
	})
	handler(c)
	return w
}

func TestConversationContainerWorkspaceIsScopedAndStoppedRemainsVisible(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("stopped container", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer, WorkspacePersistent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", conversation.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	spec := handlerInitializationSpec(conversation.ID)
	spec.Workspace.Persistent = true
	spec.Workspace.VolumeName = "cyberstrike-workspace-secret-name"
	provider := &fakeConversationContainerTerminalProvider{
		record: containerruntime.InitializationRecord{
			ConversationID: conversation.ID, RuntimeID: spec.ID,
			Status: containerruntime.InitializationCreated, RuntimeStatus: containerruntime.StatusStopped, Spec: spec,
		},
		workspace: containerruntime.WorkspaceInfo{
			ContainerPath: "/workspace", HostPath: "/var/lib/docker/volumes/owned/_data",
			Storage: containerruntime.WorkspaceStorageNamedVolume, Persistent: true,
		},
	}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerInitializationProvider(provider)
	handler.SetContainerWorkspaceInspector(provider)

	response := performConversationTerminalRequest(owner, map[string]bool{"chat:read": true}, "/api/conversations/"+conversation.ID+"/container/workspace", handler.GetConversationContainerWorkspace, conversation.ID)
	if response.Code != http.StatusOK {
		t.Fatalf("workspace response = %d %s", response.Code, response.Body.String())
	}
	var payload conversationContainerWorkspaceResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ContainerPath != "/workspace" || payload.HostPath != "/var/lib/docker/volumes/owned/_data" || payload.InteractiveAvailable || payload.InteractiveReason != "container_not_running" {
		t.Fatalf("workspace payload = %#v", payload)
	}
	if strings.Contains(response.Body.String(), spec.Workspace.VolumeName) || strings.Contains(response.Body.String(), "provider") {
		t.Fatalf("workspace response leaked internal identity: %s", response.Body.String())
	}

	other, err := db.CreateRBACUser("terminal-other", "Other", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	denied := performConversationTerminalRequest(other, map[string]bool{"chat:read": true}, "/api/conversations/"+conversation.ID+"/container/workspace", handler.GetConversationContainerWorkspace, conversation.ID)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("foreign workspace response = %d %s", denied.Code, denied.Body.String())
	}
}

func TestConversationContainerTerminalRequiresPermissionAndRunningStateBeforeUpgrade(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("terminal guard", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", conversation.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	spec := handlerInitializationSpec(conversation.ID)
	provider := &fakeConversationContainerTerminalProvider{record: containerruntime.InitializationRecord{
		ConversationID: conversation.ID, RuntimeID: spec.ID, Status: containerruntime.InitializationCreated,
		RuntimeStatus: containerruntime.StatusRunning, Spec: spec,
	}}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerInitializationProvider(provider)

	missingPermission := performConversationTerminalRequest(owner, map[string]bool{"chat:read": true}, "/api/conversations/"+conversation.ID+"/container/terminal/ws", handler.OpenConversationContainerTerminalWS, conversation.ID)
	if missingPermission.Code != http.StatusForbidden || !strings.Contains(missingPermission.Body.String(), "terminal:execute") {
		t.Fatalf("missing permission response = %d %s", missingPermission.Code, missingPermission.Body.String())
	}

	provider.record.RuntimeStatus = containerruntime.StatusStopped
	stopped := performConversationTerminalRequest(owner, map[string]bool{"chat:read": true, "terminal:execute": true}, "/api/conversations/"+conversation.ID+"/container/terminal/ws", handler.OpenConversationContainerTerminalWS, conversation.ID)
	if stopped.Code != http.StatusConflict || !strings.Contains(stopped.Body.String(), "仅运行中") {
		t.Fatalf("stopped terminal response = %d %s", stopped.Code, stopped.Body.String())
	}
}
