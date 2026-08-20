package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"cyberstrike-ai/internal/database"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type fixedContainerInitializationProvider struct {
	record containerruntime.InitializationRecord
	err    error
}

func (f fixedContainerInitializationProvider) Get(context.Context, string) (containerruntime.InitializationRecord, error) {
	return f.record, f.err
}

type deletionLifecycleRecorder struct {
	actions         []string
	removeWorkspace bool
}

func (f *deletionLifecycleRecorder) Start(context.Context, string) (containerruntime.InitializationRecord, error) {
	return containerruntime.InitializationRecord{}, nil
}

func (f *deletionLifecycleRecorder) Stop(context.Context, string) (containerruntime.InitializationRecord, error) {
	f.actions = append(f.actions, "stop")
	return containerruntime.InitializationRecord{RuntimeStatus: containerruntime.StatusStopped}, nil
}

func (f *deletionLifecycleRecorder) Rebuild(context.Context, string) (containerruntime.InitializationRecord, error) {
	return containerruntime.InitializationRecord{}, nil
}

func (f *deletionLifecycleRecorder) Delete(_ context.Context, _ string, removeWorkspace bool) error {
	f.actions = append(f.actions, "delete")
	f.removeWorkspace = removeWorkspace
	return nil
}

func (f *deletionLifecycleRecorder) Reconcile(context.Context, string) (containerruntime.InitializationRecord, error) {
	return containerruntime.InitializationRecord{}, nil
}

type retainedWorkspaceDeletionRecorder struct {
	called bool
}

func (f *retainedWorkspaceDeletionRecorder) DeleteRetainedWorkspace(context.Context, string) error {
	f.called = true
	return nil
}

func TestDeletePersistentConversationRequiresExplicitWorkspaceAction(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("explicit workspace decision", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer, WorkspacePersistent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewConversationHandler(db, zap.NewNop())
	response := performConversationRequest(owner, http.MethodDelete, "/api/conversations/"+conversation.ID, nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.DeleteConversation(c)
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
	if _, err := db.GetConversationLite(conversation.ID); err != nil {
		t.Fatalf("conversation removed without explicit action: %v", err)
	}
}

func TestDeleteConversationRetainsWorkspaceClaimOrDeletesWorkspace(t *testing.T) {
	db, owner := setupConversationRBACTest(t)

	retained, err := db.CreateConversation("retain workspace", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer, WorkspacePersistent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	retainedLifecycle := &deletionLifecycleRecorder{}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerInitializationProvider(fixedContainerInitializationProvider{record: containerruntime.InitializationRecord{
		Status: containerruntime.InitializationCreated, RuntimeStatus: containerruntime.StatusStopped,
	}})
	handler.SetContainerLifecycleController(retainedLifecycle)
	response := performConversationRequest(owner, http.MethodDelete, "/api/conversations/"+retained.ID+"?workspace_action=retain", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: retained.ID}}
		c.Request.URL.RawQuery = "workspace_action=retain"
		handler.DeleteConversation(c)
	})
	if response.Code != http.StatusOK || len(retainedLifecycle.actions) != 1 || retainedLifecycle.actions[0] != "delete" || retainedLifecycle.removeWorkspace {
		t.Fatalf("retain response=%d %s lifecycle=%#v", response.Code, response.Body.String(), retainedLifecycle)
	}
	var retainedResponse map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &retainedResponse); err != nil {
		t.Fatal(err)
	}
	if retainedResponse["workspaceRetained"] != true || retainedResponse["workspaceDeleted"] != false {
		t.Fatalf("retain response = %#v", retainedResponse)
	}
	var retainedRows int
	if err := db.QueryRow("SELECT COUNT(*) FROM retained_container_workspaces WHERE original_conversation_id = ?", retained.ID).Scan(&retainedRows); err != nil || retainedRows != 1 {
		t.Fatalf("retained rows=%d err=%v", retainedRows, err)
	}

	deleted, err := db.CreateConversation("delete workspace", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer, WorkspacePersistent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	deletedLifecycle := &deletionLifecycleRecorder{}
	handler = NewConversationHandler(db, zap.NewNop())
	handler.SetContainerInitializationProvider(fixedContainerInitializationProvider{record: containerruntime.InitializationRecord{
		Status: containerruntime.InitializationCreated, RuntimeStatus: containerruntime.StatusRunning,
	}})
	handler.SetContainerLifecycleController(deletedLifecycle)
	response = performConversationRequest(owner, http.MethodDelete, "/api/conversations/"+deleted.ID+"?workspace_action=delete", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: deleted.ID}}
		c.Request.URL.RawQuery = "workspace_action=delete"
		handler.DeleteConversation(c)
	})
	if response.Code != http.StatusOK || len(deletedLifecycle.actions) != 2 || deletedLifecycle.actions[0] != "stop" || deletedLifecycle.actions[1] != "delete" || !deletedLifecycle.removeWorkspace {
		t.Fatalf("delete response=%d %s lifecycle=%#v", response.Code, response.Body.String(), deletedLifecycle)
	}
}

func TestDeleteConversationRemovesRetainedWorkspaceWithoutRuntimeRecord(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("delete retained workspace", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer, WorkspacePersistent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	workspace := &retainedWorkspaceDeletionRecorder{}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerInitializationProvider(fixedContainerInitializationProvider{err: containerruntime.ErrNotFound})
	handler.SetRetainedWorkspaceController(workspace)
	response := performConversationRequest(owner, http.MethodDelete, "/api/conversations/"+conversation.ID+"?workspace_action=delete", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		c.Request.URL.RawQuery = "workspace_action=delete"
		handler.DeleteConversation(c)
	})
	if response.Code != http.StatusOK || !workspace.called {
		t.Fatalf("response=%d %s workspace=%#v", response.Code, response.Body.String(), workspace)
	}
	if _, err := db.GetConversationLite(conversation.ID); err == nil {
		t.Fatal("conversation still exists")
	}
}
