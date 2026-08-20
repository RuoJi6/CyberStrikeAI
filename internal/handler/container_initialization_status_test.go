package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cyberstrike-ai/internal/database"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestGetContainerInitializationIsLightweightAndRBACScoped(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("container status", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", conversation.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerInitializationProvider(db)

	request := func(user *database.RBACUser) map[string]interface{} {
		response := performConversationRequest(user, http.MethodGet, "/api/conversations/"+conversation.ID+"/container-initialization", nil, func(c *gin.Context) {
			c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
			handler.GetContainerInitialization(c)
		})
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", response.Code, response.Body.String())
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		return payload
	}
	if payload := request(owner); payload["status"] != "not_requested" {
		t.Fatalf("not requested payload = %#v", payload)
	}

	spec := handlerInitializationSpec(conversation.ID)
	if _, _, err := db.Queue(context.Background(), spec, false); err != nil {
		t.Fatal(err)
	}
	if payload := request(owner); payload["status"] != string(containerruntime.InitializationQueued) || payload["runtimeId"] != string(spec.ID) {
		t.Fatalf("queued payload = %#v", payload)
	}

	other, err := db.CreateRBACUser("container-status-other", "Other", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := performConversationRequest(other, http.MethodGet, "/api/conversations/"+conversation.ID+"/container-initialization", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.GetContainerInitialization(c)
	})
	if response.Code != http.StatusForbidden {
		t.Fatalf("foreign status = %d: %s", response.Code, response.Body.String())
	}
}

func TestContainerInitializationStatusIsDocumentedInOpenAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)
	NewOpenAPIHandler(nil, zap.NewNop(), nil, nil).GetOpenAPISpec(context)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var spec map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths := spec["paths"].(map[string]interface{})
	path, ok := paths["/api/conversations/{id}/container-initialization"].(map[string]interface{})
	if !ok || path["get"] == nil {
		t.Fatalf("container initialization path = %#v", path)
	}
	components := spec["components"].(map[string]interface{})
	schemas := components["schemas"].(map[string]interface{})
	if _, ok := schemas["ContainerInitialization"]; !ok {
		t.Fatal("ContainerInitialization schema is missing")
	}
}

func handlerInitializationSpec(conversationID string) containerruntime.RuntimeSpec {
	return containerruntime.RuntimeSpec{
		ID:             containerruntime.RuntimeID("runtime-" + conversationID),
		ConversationID: conversationID,
		Image: containerruntime.ImageReference{
			Repository: "ghcr.io/usestrix/strix-sandbox",
			Digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Platform:   "linux/arm64",
		},
		Resources: containerruntime.ResourceLimits{
			NanoCPUs: 1_000_000_000, MemoryBytes: 512 << 20, PIDs: 128,
			NoFileSoft: 1024, NoFileHard: 2048, WorkspaceBytes: 1 << 30,
			MaxConcurrentExec: 2, MaxQueuedExec: 8, LogMaxBytes: 10 << 20, LogMaxFiles: 3,
		},
		Security: containerruntime.SecurityProfile{
			ReadOnlyRootFS: true, NoNewPrivileges: true, DropAllCapabilities: true,
			NetworkMode: containerruntime.NetworkNone, SeccompProfile: "default", TmpfsBytes: 64 << 20,
		},
		Workspace: containerruntime.WorkspaceSpec{MountPath: "/workspace"},
	}
}
