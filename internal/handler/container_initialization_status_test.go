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

type fakeContainerInitializationProvider struct {
	record containerruntime.InitializationRecord
}

func (f fakeContainerInitializationProvider) Get(context.Context, string) (containerruntime.InitializationRecord, error) {
	return f.record, nil
}

type fakeContainerRuntimeObserver struct {
	observation containerruntime.RuntimeObservation
	calls       int
}

func (f *fakeContainerRuntimeObserver) Observe(context.Context, containerruntime.RuntimeSpec) (containerruntime.RuntimeObservation, error) {
	f.calls++
	return f.observation, nil
}

func TestGetContainerInitializationObservationIsOptInAndSafe(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("observed container", database.ConversationCreateMeta{
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
	spec.EgressGateway = &containerruntime.EgressGatewaySpec{
		Image:            containerruntime.ImageReference{Repository: "gateway", Digest: "sha256:" + strings.Repeat("b", 64), Platform: "linux/arm64"},
		Resources:        containerruntime.EgressGatewayResources{NanoCPUs: 1, MemoryBytes: 2, PIDs: 3, NoFileSoft: 4, NoFileHard: 5, TmpfsBytes: 6, LogMaxBytes: 7, LogMaxFiles: 8},
		BoundarySnapshot: &containerruntime.EgressBoundarySnapshotSpec{ID: "snapshot-safe", SHA256: "sha256:" + strings.Repeat("c", 64)},
	}
	record := containerruntime.InitializationRecord{
		ConversationID: conversation.ID, RuntimeID: spec.ID, Status: containerruntime.InitializationCreated,
		RuntimeStatus: containerruntime.StatusRunning, ImageDigest: spec.Image.Digest, ImagePlatform: spec.Image.Platform,
		ReadinessStatus: containerruntime.ReadinessReady, Spec: spec,
	}
	observer := &fakeContainerRuntimeObserver{observation: containerruntime.RuntimeObservation{
		Agent: containerruntime.RuntimeComponentObservation{
			ProviderID: "provider-agent", Status: containerruntime.StatusRunning, ImageDigest: spec.Image.Digest,
			Resources: containerruntime.ResourceUsage{Available: true, MemoryUsageBytes: 1024, PIDs: 2},
		},
		Gateway: &containerruntime.RuntimeComponentObservation{
			ProviderID: "provider-gateway", Status: containerruntime.StatusRunning, ImageDigest: spec.EgressGateway.Image.Digest,
		},
		PolicyDNSStatus: "ready", PolicyDNSAddress: "172.30.0.2", WorkspaceStatus: "ready",
	}}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerInitializationProvider(fakeContainerInitializationProvider{record: record})
	handler.SetContainerRuntimeObserver(observer)

	request := func(query string) map[string]interface{} {
		response := performConversationRequest(owner, http.MethodGet, "/api/conversations/"+conversation.ID+"/container-initialization"+query, nil, func(c *gin.Context) {
			c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
			handler.GetContainerInitialization(c)
		})
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), spec.Workspace.VolumeName) {
			t.Fatalf("workspace volume name leaked: %s", response.Body.String())
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		return payload
	}
	if payload := request(""); payload["observation"] != nil || observer.calls != 0 {
		t.Fatalf("default status unexpectedly observed Docker: payload=%#v calls=%d", payload, observer.calls)
	}
	payload := request("?observe=1")
	if observer.calls != 1 || payload["conversationTitle"] != conversation.Title || payload["runtimeMode"] != database.ConversationRuntimeModeContainer {
		t.Fatalf("observed payload = %#v calls=%d", payload, observer.calls)
	}
	desired := payload["desired"].(map[string]interface{})
	if desired["boundarySnapshotSha256"] != spec.EgressGateway.BoundarySnapshot.SHA256 || desired["specDigest"] != containerruntime.RuntimeSpecDigest(spec) {
		t.Fatalf("desired status = %#v", desired)
	}
	observation := payload["observation"].(map[string]interface{})
	if observation["policyDnsAddress"] != "172.30.0.2" || observation["workspaceStatus"] != "ready" {
		t.Fatalf("observation = %#v", observation)
	}
}

func TestGetContainerInitializationSkipsObservationDuringLifecycleTransition(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("starting container", database.ConversationCreateMeta{
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
	record := containerruntime.InitializationRecord{
		ConversationID:     conversation.ID,
		RuntimeID:          spec.ID,
		Status:             containerruntime.InitializationCreated,
		RuntimeStatus:      containerruntime.StatusStopped,
		ReadinessStatus:    containerruntime.ReadinessReady,
		LifecycleOperation: containerruntime.LifecycleOperationStart,
		LifecycleState:     containerruntime.LifecycleInProgress,
		Spec:               spec,
	}
	observer := &fakeContainerRuntimeObserver{observation: containerruntime.RuntimeObservation{
		Agent: containerruntime.RuntimeComponentObservation{Status: containerruntime.StatusRunning},
	}}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerInitializationProvider(fakeContainerInitializationProvider{record: record})
	handler.SetContainerRuntimeObserver(observer)

	response := performConversationRequest(owner, http.MethodGet, "/api/conversations/"+conversation.ID+"/container-initialization?observe=1", nil, func(c *gin.Context) {
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
	if observer.calls != 0 {
		t.Fatalf("observer calls = %d, want 0 during lifecycle transition", observer.calls)
	}
	if payload["observation"] != nil || payload["observationError"] != nil {
		t.Fatalf("transition payload must not expose a terminal observation: %#v", payload)
	}
	if payload["lifecycleOperation"] != string(containerruntime.LifecycleOperationStart) ||
		payload["lifecycleState"] != string(containerruntime.LifecycleInProgress) {
		t.Fatalf("transition payload = %#v", payload)
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
	get := path["get"].(map[string]interface{})
	parameters := get["parameters"].([]interface{})
	foundObserve := false
	for _, raw := range parameters {
		parameter := raw.(map[string]interface{})
		if parameter["name"] == "observe" && parameter["in"] == "query" {
			foundObserve = true
		}
	}
	if !foundObserve {
		t.Fatal("container initialization observe query is undocumented")
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
		"lifecycleStartedAt", "lifecycleCompletedAt", "runtimeDrift", "conversationTitle", "runtimeMode",
		"workspacePersistent", "desired", "observation", "observationError",
		"boundaryPolicyId", "boundarySnapshotId", "networkAccess", "pendingBoundaryPolicyId", "pendingBoundarySnapshotId", "pendingNetworkAccess",
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
	if _, ok := conversationProperties["workspacePersistent"]; !ok {
		t.Fatal("Conversation schema is missing workspacePersistent")
	}
	createSchema := schemas["CreateConversationRequest"].(map[string]interface{})
	createProperties := createSchema["properties"].(map[string]interface{})
	if _, ok := createProperties["runtimeMode"]; !ok {
		t.Fatal("CreateConversationRequest schema is missing runtimeMode")
	}
	if _, ok := createProperties["workspacePersistent"]; !ok {
		t.Fatal("CreateConversationRequest schema is missing workspacePersistent")
	}
	if _, ok := createProperties["boundaryPolicyId"]; !ok {
		t.Fatal("CreateConversationRequest schema is missing boundaryPolicyId")
	}
	if _, ok := createProperties["runtimeControls"]; !ok {
		t.Fatal("CreateConversationRequest schema is missing runtimeControls")
	}
	if _, ok := createProperties["networkAccess"]; !ok {
		t.Fatal("CreateConversationRequest schema is missing networkAccess")
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
		if _, ok := requestProperties["workspacePersistent"]; !ok {
			t.Fatalf("%s request schema is missing workspacePersistent", route)
		}
		if _, ok := requestProperties["boundaryPolicyId"]; !ok {
			t.Fatalf("%s request schema is missing boundaryPolicyId", route)
		}
		if _, ok := requestProperties["networkAccess"]; !ok {
			t.Fatalf("%s request schema is missing networkAccess", route)
		}
	}
	rebuildPost := paths["/api/conversations/{id}/container/rebuild"].(map[string]interface{})["post"].(map[string]interface{})
	rebuildRequestBody, ok := rebuildPost["requestBody"].(map[string]interface{})
	if !ok {
		t.Fatal("container rebuild OpenAPI request body is missing")
	}
	rebuildContent := rebuildRequestBody["content"].(map[string]interface{})
	rebuildJSON := rebuildContent["application/json"].(map[string]interface{})
	rebuildSchema := rebuildJSON["schema"].(map[string]interface{})
	rebuildProperties := rebuildSchema["properties"].(map[string]interface{})
	for _, field := range []string{"boundaryPolicyId", "egressMode", "egressProxyId", "egressProxyGroupId", "runtimeControls", "networkAccess"} {
		if _, ok := rebuildProperties[field]; !ok {
			t.Fatalf("container rebuild request schema is missing %s", field)
		}
	}
	if description, _ := rebuildPost["description"].(string); !strings.Contains(description, "重建成功") || !strings.Contains(description, "原子激活") {
		t.Fatalf("container rebuild description does not document snapshot activation: %q", description)
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
		if !strings.Contains(description, "state=ready") || !strings.Contains(description, "自动继续原请求") {
			t.Fatalf("%s SSE description does not document automatic continuation: %q", route, description)
		}
	}
	agentTaskSchema := schemas["AgentTask"].(map[string]interface{})
	agentTaskStatus := agentTaskSchema["properties"].(map[string]interface{})["status"].(map[string]interface{})
	statusEnum := agentTaskStatus["enum"].([]interface{})
	hasInitializing := false
	for _, status := range statusEnum {
		if status == containerGateInitializing {
			hasInitializing = true
			break
		}
	}
	if !hasInitializing {
		t.Fatalf("AgentTask status enum does not include %q: %#v", containerGateInitializing, statusEnum)
	}
	for path, method := range map[string]string{
		"/api/conversations/{id}/container/start":            "post",
		"/api/conversations/{id}/container/stop":             "post",
		"/api/conversations/{id}/container/rebuild":          "post",
		"/api/conversations/{id}/container/network-settings": "get",
		"/api/conversations/{id}/container/reconcile":        "post",
		"/api/conversations/{id}/container":                  "delete",
		"/api/conversations/{id}/container/workspace":        "get",
		"/api/conversations/{id}/container/terminal/ws":      "get",
	} {
		item, ok := paths[path].(map[string]interface{})
		if !ok || item[method] == nil {
			t.Fatalf("container lifecycle path %s %s = %#v", method, path, item)
		}
	}
	workspaceSchema, ok := schemas["ConversationContainerWorkspace"].(map[string]interface{})
	if !ok {
		t.Fatal("ConversationContainerWorkspace schema is missing")
	}
	workspaceProperties := workspaceSchema["properties"].(map[string]interface{})
	for _, field := range []string{"containerPath", "hostPath", "storage", "persistent", "interactiveAvailable", "interactiveReason"} {
		if workspaceProperties[field] == nil {
			t.Fatalf("ConversationContainerWorkspace.%s is missing", field)
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
