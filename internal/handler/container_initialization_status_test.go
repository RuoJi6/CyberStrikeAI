package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	initializationSchema, ok := schemas["ContainerInitialization"].(map[string]interface{})
	if !ok {
		t.Fatal("ContainerInitialization schema is missing")
	}
	properties := initializationSchema["properties"].(map[string]interface{})
	for _, field := range []string{
		"readinessStatus", "readinessError", "inventoryDigest", "toolCount", "readinessStartedAt", "readinessCompletedAt",
		"lifecycleOperation", "lifecycleState", "lifecycleError", "runtimeGeneration", "runtimeObservedAt",
		"lifecycleStartedAt", "lifecycleCompletedAt", "runtimeDrift",
	} {
		if _, ok := properties[field]; !ok {
			t.Fatalf("ContainerInitialization schema is missing %s", field)
		}
	}
	conversationSchema := schemas["Conversation"].(map[string]interface{})
	conversationProperties := conversationSchema["properties"].(map[string]interface{})
	if _, ok := conversationProperties["runtimeMode"]; !ok {
		t.Fatal("Conversation schema is missing runtimeMode")
	}
	createSchema := schemas["CreateConversationRequest"].(map[string]interface{})
	createProperties := createSchema["properties"].(map[string]interface{})
	if _, ok := createProperties["runtimeMode"]; !ok {
		t.Fatal("CreateConversationRequest schema is missing runtimeMode")
	}
	gateSchema, ok := schemas["ContainerExecutionGateResponse"].(map[string]interface{})
	if !ok {
		t.Fatal("ContainerExecutionGateResponse schema is missing")
	}
	gateProperties := gateSchema["properties"].(map[string]interface{})
	for _, field := range []string{"conversationId", "runtimeMode", "deferred", "message", "containerInitialization"} {
		if _, ok := gateProperties[field]; !ok {
			t.Fatalf("ContainerExecutionGateResponse schema is missing %s", field)
		}
	}
	for _, route := range []string{"/api/eino-agent", "/api/eino-agent/stream", "/api/multi-agent", "/api/multi-agent/stream"} {
		post := paths[route].(map[string]interface{})["post"].(map[string]interface{})
		requestBody := post["requestBody"].(map[string]interface{})
		content := requestBody["content"].(map[string]interface{})
		applicationJSON := content["application/json"].(map[string]interface{})
		requestSchema := applicationJSON["schema"].(map[string]interface{})
		requestProperties := requestSchema["properties"].(map[string]interface{})
		if _, ok := requestProperties["runtimeMode"]; !ok {
			t.Fatalf("%s request schema is missing runtimeMode", route)
		}
	}
	for _, route := range []string{"/api/eino-agent", "/api/multi-agent"} {
		post := paths[route].(map[string]interface{})["post"].(map[string]interface{})
		responses := post["responses"].(map[string]interface{})
		for _, status := range []string{"202", "409", "503"} {
			response, ok := responses[status].(map[string]interface{})
			if !ok {
				t.Fatalf("%s response %s is missing", route, status)
			}
			content := response["content"].(map[string]interface{})
			applicationJSON := content["application/json"].(map[string]interface{})
			responseSchema := applicationJSON["schema"].(map[string]interface{})
			if responseSchema["$ref"] != "#/components/schemas/ContainerExecutionGateResponse" {
				t.Fatalf("%s response %s schema = %#v", route, status, responseSchema)
			}
		}
	}
	for _, route := range []string{"/api/eino-agent/stream", "/api/multi-agent/stream"} {
		post := paths[route].(map[string]interface{})["post"].(map[string]interface{})
		responses := post["responses"].(map[string]interface{})
		response := responses["200"].(map[string]interface{})
		content := response["content"].(map[string]interface{})
		stream := content["text/event-stream"].(map[string]interface{})
		streamSchema := stream["schema"].(map[string]interface{})
		description, _ := streamSchema["description"].(string)
		if !strings.Contains(description, "container_initialization") {
			t.Fatalf("%s SSE description does not document container_initialization: %q", route, description)
		}
	}
	for path, method := range map[string]string{
		"/api/conversations/{id}/container/start":     "post",
		"/api/conversations/{id}/container/stop":      "post",
		"/api/conversations/{id}/container/rebuild":   "post",
		"/api/conversations/{id}/container/reconcile": "post",
		"/api/conversations/{id}/container":           "delete",
	} {
		item, ok := paths[path].(map[string]interface{})
		if !ok || item[method] == nil {
			t.Fatalf("container lifecycle path %s %s = %#v", method, path, item)
		}
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
