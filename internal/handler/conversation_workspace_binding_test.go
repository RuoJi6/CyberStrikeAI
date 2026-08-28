package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestCreateContainerWorkspaceAssignsCreatorAccess(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	handler := NewConversationHandler(db, zap.NewNop())
	response := performConversationRequest(owner, http.MethodPost, "/api/container-workspaces", map[string]string{"name": "shared creator workspace"}, handler.CreateContainerWorkspace)
	if response.Code != http.StatusCreated {
		t.Fatalf("create response = %d %s", response.Code, response.Body.String())
	}
	var workspace database.ContainerWorkspace
	if err := json.Unmarshal(response.Body.Bytes(), &workspace); err != nil {
		t.Fatalf("decode workspace: %v", err)
	}
	if !db.UserCanAccessResource(owner.ID, database.RBACScopeAssigned, "container_workspace", workspace.ID) {
		t.Fatal("creator did not receive workspace assignment")
	}
	response = performConversationRequest(owner, http.MethodGet, "/api/container-workspaces/"+workspace.ID, nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: workspace.ID}}
		handler.GetContainerWorkspace(c)
	})
	if response.Code != http.StatusOK {
		t.Fatalf("creator get response = %d %s", response.Code, response.Body.String())
	}
}

func TestUpdateConversationWorkspaceBindingCleansDedicatedRuntimeAndSkipsNoop(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("switch workspace", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer, WorkspacePersistent: true,
	})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatalf("AssignResourceToUser(conversation): %v", err)
	}
	workspace, err := db.CreateSharedContainerWorkspace(context.Background(), "shared", "")
	if err != nil {
		t.Fatalf("CreateSharedContainerWorkspace: %v", err)
	}
	if err := db.AssignResourceToUser(owner.ID, "container_workspace", workspace.ID); err != nil {
		t.Fatalf("AssignResourceToUser(workspace): %v", err)
	}

	controller := &fakeConversationContainerLifecycle{}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerLifecycleController(controller)
	request := func(body map[string]string) int {
		response := performConversationRequest(owner, http.MethodPut, "/api/conversations/"+conversation.ID+"/workspace-binding", body, func(c *gin.Context) {
			c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
			handler.UpdateConversationWorkspaceBinding(c)
		})
		if response.Code != http.StatusOK {
			t.Fatalf("update response = %d %s", response.Code, response.Body.String())
		}
		return response.Code
	}

	request(map[string]string{"mode": database.ConversationWorkspaceModeShared, "workspaceId": workspace.ID})
	if controller.deleteCalls != 1 || !controller.removeWorkspace {
		t.Fatalf("lifecycle delete calls=%d removeWorkspace=%v", controller.deleteCalls, controller.removeWorkspace)
	}
	binding, err := db.GetConversationWorkspaceBinding(context.Background(), conversation.ID)
	if err != nil || binding.Mode != database.ConversationWorkspaceModeShared || binding.Workspace == nil || binding.Workspace.ID != workspace.ID {
		t.Fatalf("shared binding = %#v, err=%v", binding, err)
	}

	request(map[string]string{"mode": database.ConversationWorkspaceModeShared, "workspaceId": workspace.ID})
	if controller.deleteCalls != 1 {
		t.Fatalf("unchanged binding deleted runtime again: %d calls", controller.deleteCalls)
	}
}

func TestUpdateConversationWorkspaceBindingRejectsInvalidModeBeforeRuntimeDelete(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("invalid switch", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatalf("AssignResourceToUser: %v", err)
	}
	controller := &fakeConversationContainerLifecycle{}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerLifecycleController(controller)
	response := performConversationRequest(owner, http.MethodPut, "/api/conversations/"+conversation.ID+"/workspace-binding", map[string]string{"mode": "unknown"}, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.UpdateConversationWorkspaceBinding(c)
	})
	if response.Code != http.StatusBadRequest || controller.deleteCalls != 0 {
		t.Fatalf("invalid update response=%d %s deleteCalls=%d", response.Code, response.Body.String(), controller.deleteCalls)
	}
}
