package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type fakeConversationContainerLifecycle struct {
	record          containerruntime.InitializationRecord
	err             error
	action          string
	conversationID  string
	removeWorkspace bool
}

func (f *fakeConversationContainerLifecycle) call(_ context.Context, action, conversationID string) (containerruntime.InitializationRecord, error) {
	f.action = action
	f.conversationID = conversationID
	return f.record, f.err
}

func (f *fakeConversationContainerLifecycle) Start(ctx context.Context, id string) (containerruntime.InitializationRecord, error) {
	return f.call(ctx, "start", id)
}

func (f *fakeConversationContainerLifecycle) Stop(ctx context.Context, id string) (containerruntime.InitializationRecord, error) {
	return f.call(ctx, "stop", id)
}

func (f *fakeConversationContainerLifecycle) Rebuild(ctx context.Context, id string) (containerruntime.InitializationRecord, error) {
	return f.call(ctx, "rebuild", id)
}

func (f *fakeConversationContainerLifecycle) Delete(_ context.Context, id string, removeWorkspace bool) error {
	f.action = "delete"
	f.conversationID = id
	f.removeWorkspace = removeWorkspace
	return f.err
}

func (f *fakeConversationContainerLifecycle) Reconcile(ctx context.Context, id string) (containerruntime.InitializationRecord, error) {
	return f.call(ctx, "reconcile", id)
}

func TestConversationContainerLifecycleIsRBACScopedAndSanitized(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("container lifecycle", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", conversation.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	controller := &fakeConversationContainerLifecycle{record: containerruntime.InitializationRecord{
		ConversationID: conversation.ID, RuntimeStatus: containerruntime.StatusRunning,
		LifecycleOperation: containerruntime.LifecycleOperationStart, LifecycleState: containerruntime.LifecycleIdle,
	}}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerLifecycleController(controller)

	response := performConversationRequest(owner, http.MethodPost, "/api/conversations/"+conversation.ID+"/container/start", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.StartConversationContainer(c)
	})
	if response.Code != http.StatusOK || controller.action != "start" || controller.conversationID != conversation.ID {
		t.Fatalf("start response=%d %s call=%s/%s", response.Code, response.Body.String(), controller.action, controller.conversationID)
	}

	other, err := db.CreateRBACUser("container-lifecycle-other", "Other", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	controller.action = ""
	response = performConversationRequest(other, http.MethodPost, "/api/conversations/"+conversation.ID+"/container/stop", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.StopConversationContainer(c)
	})
	if response.Code != http.StatusForbidden || controller.action != "" {
		t.Fatalf("foreign response=%d %s call=%s", response.Code, response.Body.String(), controller.action)
	}

	controller.err = errors.New("secret engine path /var/run/docker.sock")
	response = performConversationRequest(owner, http.MethodPost, "/api/conversations/"+conversation.ID+"/container/start", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.StartConversationContainer(c)
	})
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "/var/run/docker.sock") {
		t.Fatalf("unsanitized failure=%d %s", response.Code, response.Body.String())
	}
}

func TestDeleteConversationContainerReportsWorkspacePolicy(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("delete runtime", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	controller := &fakeConversationContainerLifecycle{}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerLifecycleController(controller)

	response := performConversationRequest(owner, http.MethodDelete, "/api/conversations/"+conversation.ID+"/container?remove_workspace=true", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		c.Request.URL.RawQuery = "remove_workspace=true"
		handler.DeleteConversationContainer(c)
	})
	if response.Code != http.StatusOK || controller.action != "delete" || !controller.removeWorkspace {
		t.Fatalf("delete response=%d %s call=%s remove=%v", response.Code, response.Body.String(), controller.action, controller.removeWorkspace)
	}
	var ephemeral map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &ephemeral); err != nil {
		t.Fatal(err)
	}
	if ephemeral["workspacePersistent"] != false || ephemeral["workspaceDeleted"] != true || !strings.Contains(ephemeral["workspaceDeletionWarning"].(string), "删除容器会永久删除") {
		t.Fatalf("ephemeral response = %#v", ephemeral)
	}

	persistent, err := db.CreateConversation("persistent runtime", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer, WorkspacePersistent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", persistent.ID); err != nil {
		t.Fatal(err)
	}
	controller = &fakeConversationContainerLifecycle{}
	handler.SetContainerLifecycleController(controller)
	response = performConversationRequest(owner, http.MethodDelete, "/api/conversations/"+persistent.ID+"/container", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: persistent.ID}}
		handler.DeleteConversationContainer(c)
	})
	var retained map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &retained); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || controller.removeWorkspace || retained["workspacePersistent"] != true || retained["workspaceRetained"] != true || retained["workspaceDeleted"] != false {
		t.Fatalf("persistent response=%d %#v", response.Code, retained)
	}
}

func TestConversationContainerLifecycleMapsStateConflict(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("conflict runtime", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	controller := &fakeConversationContainerLifecycle{err: containerruntime.ErrRuntimeStateConflict}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerLifecycleController(controller)
	response := performConversationRequest(owner, http.MethodPost, "/api/conversations/"+conversation.ID+"/container/rebuild", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.RebuildConversationContainer(c)
	})
	if response.Code != http.StatusConflict {
		t.Fatalf("conflict response=%d %s", response.Code, response.Body.String())
	}
}
