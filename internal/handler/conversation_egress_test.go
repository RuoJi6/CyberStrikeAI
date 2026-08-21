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
	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func createConversationEgressHandlerResources(t *testing.T, db *database.DB, ownerID string) (database.EgressProxy, database.EgressProxyGroup) {
	t.Helper()
	proxy, err := db.CreateEgressProxy(context.Background(), database.EgressProxy{
		ID: "handler-proxy-" + ownerID, Name: "Handler proxy", Protocol: egress.UpstreamProtocolSOCKS5,
		Host: "proxy.example", Port: 1080, Enabled: true, OwnerUserID: ownerID,
		CredentialCiphertext: "v1.key.handler-forbidden-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := db.CreateEgressProxyGroup(context.Background(), database.EgressProxyGroup{
		ID: "handler-group-" + ownerID, Name: "Handler group", Enabled: true,
		FailureThreshold: 4, CooldownSeconds: 90, OwnerUserID: ownerID,
		Members: []database.EgressProxyGroupMember{{ProxyID: proxy.ID, Priority: 0, Weight: 1, Enabled: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return proxy, group
}

func conversationEgressRouter(db *database.DB, session security.Session) *gin.Engine {
	handler := NewConversationHandler(db, zap.NewNop())
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, session)
		c.Next()
	})
	router.Use(security.RBACMiddleware(db))
	router.POST("/api/conversations", handler.CreateConversation)
	router.GET("/api/conversations/:id/egress", handler.GetConversationEgress)
	router.PUT("/api/conversations/:id/egress", handler.UpdateConversationEgress)
	return router
}

func conversationEgressRequest(router *gin.Engine, method, path string, body interface{}) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, path, nil)
	} else {
		payload, _ := json.Marshal(body)
		request = httptest.NewRequest(method, path, bytes.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
	}
	router.ServeHTTP(recorder, request)
	return recorder
}

func conversationEgressSession(userID string, includeEgress bool) security.Session {
	permissions := map[string]bool{"chat:read": true, "chat:write": true}
	if includeEgress {
		permissions["egress:read"] = true
	}
	return security.Session{
		UserID: userID, Scope: database.RBACScopeOwn, Permissions: permissions,
		PermissionScopes: map[string]string{
			"chat:read": database.RBACScopeOwn, "chat:write": database.RBACScopeOwn,
			"egress:read": database.RBACScopeOwn,
		},
	}
}

func TestConversationEgressAPICreateUpdateFreezeAndRedact(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	proxy, group := createConversationEgressHandlerResources(t, db, user.ID)
	router := conversationEgressRouter(db, conversationEgressSession(user.ID, true))

	createdResponse := conversationEgressRequest(router, http.MethodPost, "/api/conversations", map[string]interface{}{
		"title": "bound conversation", "runtimeMode": database.ConversationRuntimeModeContainer,
		"egressMode": database.ConversationEgressModeProxy, "egressProxyId": proxy.ID,
	})
	if createdResponse.Code != http.StatusOK {
		t.Fatalf("create = %d: %s", createdResponse.Code, createdResponse.Body.String())
	}
	var conversation database.Conversation
	if err := json.Unmarshal(createdResponse.Body.Bytes(), &conversation); err != nil {
		t.Fatal(err)
	}
	get := conversationEgressRequest(router, http.MethodGet, "/api/conversations/"+conversation.ID+"/egress", nil)
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"state":"pending"`) || !strings.Contains(get.Body.String(), `"mode":"proxy"`) || !strings.Contains(get.Body.String(), proxy.ID) {
		t.Fatalf("get pending = %d: %s", get.Code, get.Body.String())
	}
	for _, forbidden := range []string{"handler-forbidden-secret", "credentialCiphertext", "currentWeight", "username", "password"} {
		if strings.Contains(get.Body.String(), forbidden) {
			t.Fatalf("GET response exposed %q: %s", forbidden, get.Body.String())
		}
	}
	updated := conversationEgressRequest(router, http.MethodPut, "/api/conversations/"+conversation.ID+"/egress", map[string]interface{}{
		"mode": database.ConversationEgressModeGroup, "egressProxyGroupId": group.ID,
	})
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), group.ID) || !strings.Contains(updated.Body.String(), `"failClosed":true`) {
		t.Fatalf("update pending = %d: %s", updated.Code, updated.Body.String())
	}
	if _, err := db.EnsureConversationEgressBinding(context.Background(), conversation.ID); err != nil {
		t.Fatal(err)
	}
	conflict := conversationEgressRequest(router, http.MethodPut, "/api/conversations/"+conversation.ID+"/egress", map[string]interface{}{"mode": database.ConversationEgressModeNone})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("update active = %d: %s", conflict.Code, conflict.Body.String())
	}
	active := conversationEgressRequest(router, http.MethodGet, "/api/conversations/"+conversation.ID+"/egress", nil)
	if active.Code != http.StatusOK || !strings.Contains(active.Body.String(), `"state":"active"`) || !strings.Contains(active.Body.String(), group.ID) {
		t.Fatalf("get active = %d: %s", active.Code, active.Body.String())
	}
}

func TestConversationEgressAPIEnforcesIndependentPermissionsAndScopes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	ownedProxy, _ := createConversationEgressHandlerResources(t, db, user.ID)
	foreignProxy, _ := createConversationEgressHandlerResources(t, db, "foreign-owner")

	withoutEgress := conversationEgressRouter(db, conversationEgressSession(user.ID, false))
	response := conversationEgressRequest(withoutEgress, http.MethodPost, "/api/conversations", map[string]interface{}{
		"title": "missing permission", "runtimeMode": "container", "egressMode": "proxy", "egressProxyId": ownedProxy.ID,
	})
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "egress:read") {
		t.Fatalf("missing egress permission = %d: %s", response.Code, response.Body.String())
	}

	ownedRouter := conversationEgressRouter(db, conversationEgressSession(user.ID, true))
	response = conversationEgressRequest(ownedRouter, http.MethodPost, "/api/conversations", map[string]interface{}{
		"title": "foreign proxy", "runtimeMode": "container", "egressMode": "proxy", "egressProxyId": foreignProxy.ID,
	})
	if response.Code != http.StatusForbidden {
		t.Fatalf("foreign proxy = %d: %s", response.Code, response.Body.String())
	}
	response = conversationEgressRequest(ownedRouter, http.MethodPost, "/api/conversations", map[string]interface{}{
		"title": "invalid host", "runtimeMode": "host", "egressMode": "none",
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("host egress = %d: %s", response.Code, response.Body.String())
	}
	response = conversationEgressRequest(ownedRouter, http.MethodPost, "/api/conversations", map[string]interface{}{
		"title": "id without mode", "runtimeMode": "container", "egressProxyId": ownedProxy.ID,
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("id without mode = %d: %s", response.Code, response.Body.String())
	}

	foreignConversation, err := db.CreateConversation("foreign conversation", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", foreignConversation.ID, "foreign-owner"); err != nil {
		t.Fatal(err)
	}
	response = conversationEgressRequest(ownedRouter, http.MethodGet, "/api/conversations/"+foreignConversation.ID+"/egress", nil)
	if response.Code != http.StatusForbidden {
		t.Fatalf("foreign conversation = %d: %s", response.Code, response.Body.String())
	}
}

func TestPrepareMultiAgentSessionSelectsConversationEgressOnlyForNewConversation(t *testing.T) {
	db, user := setupConversationRBACTest(t)
	proxy, _ := createConversationEgressHandlerResources(t, db, user.ID)
	handler := &AgentHandler{db: db, logger: zap.NewNop()}
	newContext := func(includeEgress bool) *gin.Context {
		context, _ := gin.CreateTestContext(httptest.NewRecorder())
		context.Request = httptest.NewRequest(http.MethodPost, "/api/eino-agent/stream", nil)
		context.Set(security.ContextSessionKey, conversationEgressSession(user.ID, includeEgress))
		return context
	}
	request := &ChatRequest{
		Message: "create egress conversation", RuntimeMode: database.ConversationRuntimeModeContainer,
		EgressMode: database.ConversationEgressModeProxy, EgressProxyID: proxy.ID,
	}
	if _, err := handler.prepareMultiAgentSession(request, newContext(false), "test"); err == nil || !strings.Contains(err.Error(), "egress:read") {
		t.Fatalf("missing egress permission error = %v", err)
	}
	prepared, err := handler.prepareMultiAgentSession(request, newContext(true), "test")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := db.GetConversationEgress(context.Background(), prepared.ConversationID)
	if err != nil || pending.State != database.ConversationEgressStatePending || pending.Proxy == nil || pending.Proxy.ID != proxy.ID {
		t.Fatalf("chat-created pending selection = %#v / %v", pending, err)
	}
	if _, err := handler.prepareMultiAgentSession(&ChatRequest{
		ConversationID: prepared.ConversationID, Message: "existing ignores request fields",
		EgressMode: database.ConversationEgressModeNone,
	}, newContext(true), "test"); err != nil {
		t.Fatal(err)
	}
	stillPending, err := db.GetConversationEgress(context.Background(), prepared.ConversationID)
	if err != nil || stillPending.Mode != database.ConversationEgressModeProxy || stillPending.Proxy == nil || stillPending.Proxy.ID != proxy.ID {
		t.Fatalf("existing conversation selection changed = %#v / %v", stillPending, err)
	}
}

func TestConversationEgressOpenAPIContracts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/api/openapi/spec", nil)
	NewOpenAPIHandler(nil, zap.NewNop(), nil, nil).GetOpenAPISpec(context)
	if recorder.Code != http.StatusOK {
		t.Fatalf("openapi = %d: %s", recorder.Code, recorder.Body.String())
	}
	var spec map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths := spec["paths"].(map[string]interface{})
	path, ok := paths["/api/conversations/{id}/egress"].(map[string]interface{})
	if !ok || path["get"] == nil || path["put"] == nil {
		t.Fatalf("conversation egress path = %#v", path)
	}
	schemas := spec["components"].(map[string]interface{})["schemas"].(map[string]interface{})
	for _, name := range []string{"ConversationEgressBinding", "ConversationEgressWrite", "ConversationEgressProxyGroupSummary"} {
		if _, ok := schemas[name]; !ok {
			t.Fatalf("missing schema %s", name)
		}
	}
	createProperties := schemas["CreateConversationRequest"].(map[string]interface{})["properties"].(map[string]interface{})
	for _, field := range []string{"egressMode", "egressProxyId", "egressProxyGroupId"} {
		if _, ok := createProperties[field]; !ok {
			t.Fatalf("CreateConversationRequest missing %s", field)
		}
	}
	for _, route := range []string{"/api/eino-agent", "/api/eino-agent/stream", "/api/multi-agent", "/api/multi-agent/stream"} {
		properties := paths[route].(map[string]interface{})["post"].(map[string]interface{})["requestBody"].(map[string]interface{})["content"].(map[string]interface{})["application/json"].(map[string]interface{})["schema"].(map[string]interface{})["properties"].(map[string]interface{})
		for _, field := range []string{"egressMode", "egressProxyId", "egressProxyGroupId"} {
			if _, ok := properties[field]; !ok {
				t.Fatalf("%s missing %s", route, field)
			}
		}
	}
	for _, forbidden := range []string{"credentialCiphertext", "credential_ciphertext", "currentWeight", "current_weight", "password", "username"} {
		if strings.Contains(recorder.Body.String(), forbidden) && forbidden != "username" && forbidden != "password" {
			// The general proxy write schema intentionally contains username and
			// password as writeOnly fields. Conversation schemas must not reference
			// credential ciphertext or scheduler state anywhere.
			t.Fatalf("OpenAPI exposed internal field %q", forbidden)
		}
	}
}
