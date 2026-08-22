package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/boundary"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newBoundaryPolicyHandlerTestDB(t *testing.T) (*database.DB, database.BoundaryPolicy) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "boundary-handler.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	policy, err := db.CreateBoundaryPolicy(ctx, database.BoundaryPolicy{
		Name: "simulation", OwnerUserID: "owner-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []database.BoundaryPolicyRule{
		{
			ID: "allow-api", PolicyID: policy.ID, Effect: boundary.EffectAllowAttack,
			Host: "api.example", Schemes: []string{"https"}, Ports: []int{443},
			PathPrefixes: []string{"/v1"}, Methods: []string{"POST"}, Position: 1,
		},
		{
			ID: "block-admin", PolicyID: policy.ID, Effect: boundary.EffectBlocked,
			Host: "api.example", PathPrefixes: []string{"/v1/admin"}, Position: 2,
		},
	} {
		if _, err := db.CreateBoundaryPolicyRule(ctx, rule); err != nil {
			t.Fatal(err)
		}
	}
	return db, policy
}

func boundarySimulationRouter(db *database.DB, session security.Session) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, session)
		c.Next()
	})
	router.Use(security.RBACMiddleware(db))
	handler := NewBoundaryPolicyHandler(db, zap.NewNop())
	router.GET("/api/boundary-policies", handler.List)
	router.POST("/api/boundary-policies/:id/simulate", handler.SimulatePolicy)
	return router
}

func TestBoundaryPolicyListIsScopedAndUsesSafeProjection(t *testing.T) {
	db, policy := newBoundaryPolicyHandlerTestDB(t)
	foreign, err := db.CreateBoundaryPolicy(context.Background(), database.BoundaryPolicy{
		Name: "foreign", Description: "not visible", OwnerUserID: "owner-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	perform := func(session security.Session) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/boundary-policies", nil)
		boundarySimulationRouter(db, session).ServeHTTP(recorder, request)
		return recorder
	}
	missing := perform(security.Session{UserID: "owner-1", Scope: database.RBACScopeOwn, Permissions: map[string]bool{}})
	if missing.Code != http.StatusForbidden {
		t.Fatalf("missing permission status = %d: %s", missing.Code, missing.Body.String())
	}
	owner := perform(security.Session{
		UserID: "owner-1", Scope: database.RBACScopeOwn,
		Permissions: map[string]bool{"boundary:read": true},
	})
	if owner.Code != http.StatusOK {
		t.Fatalf("owner status = %d: %s", owner.Code, owner.Body.String())
	}
	var ownerBody struct {
		Items []map[string]interface{} `json:"items"`
	}
	if err := json.Unmarshal(owner.Body.Bytes(), &ownerBody); err != nil {
		t.Fatal(err)
	}
	if len(ownerBody.Items) != 1 || ownerBody.Items[0]["id"] != policy.ID {
		t.Fatalf("owner items = %#v", ownerBody.Items)
	}
	for _, forbiddenField := range []string{"ownerUserId", "owner_user_id", "rules"} {
		if _, ok := ownerBody.Items[0][forbiddenField]; ok {
			t.Fatalf("safe summary leaked %s: %#v", forbiddenField, ownerBody.Items[0])
		}
	}
	admin := perform(security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{"boundary:read": true},
	})
	if admin.Code != http.StatusOK || !strings.Contains(admin.Body.String(), foreign.ID) {
		t.Fatalf("admin status/body = %d: %s", admin.Code, admin.Body.String())
	}
}

func performBoundarySimulation(router *gin.Engine, policyID string, body interface{}) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(body)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/boundary-policies/"+policyID+"/simulate", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestBoundaryPolicySimulationReturnsMatchedRuleAndNormalizedTarget(t *testing.T) {
	db, policy := newBoundaryPolicyHandlerTestDB(t)
	router := boundarySimulationRouter(db, security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{"boundary:read": true},
	})

	recorder := performBoundarySimulation(router, policy.ID, map[string]interface{}{
		"url": "HTTPS://API.EXAMPLE./v1/%72un?x=1", "method": "post",
		"resolvedIps": []string{"93.184.216.34"},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var response simulateBoundaryPolicyResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Allowed || response.PolicyID != policy.ID || response.Effect != boundary.EffectAllowAttack || response.MatchedRuleID != "allow-api" || response.Reason != boundary.ReasonAllowAttack {
		t.Fatalf("response = %#v", response)
	}
	if response.Target.Host != "api.example" || response.Target.Scheme != "https" || response.Target.Port != 443 || response.Target.Path != "/v1/run" || response.Target.Method != "POST" {
		t.Fatalf("target = %#v", response.Target)
	}
}

func TestBoundaryPolicySimulationFailsClosedWithReasons(t *testing.T) {
	db, policy := newBoundaryPolicyHandlerTestDB(t)
	router := boundarySimulationRouter(db, security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{"boundary:read": true},
	})
	tests := []struct {
		name, url, reason, ruleID string
		resolvedIPs               []string
	}{
		{name: "blocked path", url: "https://api.example/v1/admin/users", reason: boundary.ReasonBlockedPath, ruleID: "block-admin", resolvedIPs: []string{"93.184.216.34"}},
		{name: "default deny", url: "https://unknown.example/", reason: boundary.ReasonDefaultDeny, resolvedIPs: []string{"93.184.216.34"}},
		{name: "dns rebinding", url: "https://api.example/v1/run", reason: boundary.ReasonDNSRebinding, resolvedIPs: []string{"127.0.0.1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder := performBoundarySimulation(router, policy.ID, map[string]interface{}{
				"url": tc.url, "method": "POST", "resolvedIps": tc.resolvedIPs,
			})
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
			}
			var response simulateBoundaryPolicyResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Allowed || response.Reason != tc.reason || response.MatchedRuleID != tc.ruleID {
				t.Fatalf("response = %#v", response)
			}
		})
	}
}

func TestBoundaryPolicySimulationRejectsInvalidInputAndMissingPolicy(t *testing.T) {
	db, policy := newBoundaryPolicyHandlerTestDB(t)
	router := boundarySimulationRouter(db, security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{"boundary:read": true},
	})
	tests := []struct {
		name, id string
		body     interface{}
		want     int
	}{
		{name: "invalid URL", id: policy.ID, body: map[string]interface{}{"url": "not-a-url"}, want: http.StatusBadRequest},
		{name: "invalid IP", id: policy.ID, body: map[string]interface{}{"url": "https://api.example", "resolvedIps": []string{"999.1.1.1"}}, want: http.StatusBadRequest},
		{name: "too many IPs", id: policy.ID, body: map[string]interface{}{"url": "https://api.example", "resolvedIps": strings.Split(strings.Repeat("1.1.1.1,", 65), ",")[:65]}, want: http.StatusBadRequest},
		{name: "missing policy", id: "missing", body: map[string]interface{}{"url": "https://api.example"}, want: http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder := performBoundarySimulation(router, tc.id, tc.body)
			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, tc.want, recorder.Body.String())
			}
		})
	}
}

func TestBoundaryPolicySimulationEnforcesPermissionAndOwnScope(t *testing.T) {
	db, policy := newBoundaryPolicyHandlerTestDB(t)
	body := map[string]interface{}{"url": "https://api.example/v1/run", "method": "POST"}
	tests := []struct {
		name    string
		session security.Session
		want    int
	}{
		{name: "missing permission", session: security.Session{UserID: "owner-1", Scope: database.RBACScopeOwn, Permissions: map[string]bool{}}, want: http.StatusForbidden},
		{name: "owner", session: security.Session{UserID: "owner-1", Scope: database.RBACScopeOwn, Permissions: map[string]bool{"boundary:read": true}}, want: http.StatusOK},
		{name: "foreign owner", session: security.Session{UserID: "other", Scope: database.RBACScopeOwn, Permissions: map[string]bool{"boundary:read": true}}, want: http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder := performBoundarySimulation(boundarySimulationRouter(db, tc.session), policy.ID, body)
			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, tc.want, recorder.Body.String())
			}
		})
	}
}

func TestBoundaryPolicySimulationIsDocumentedInOpenAPI(t *testing.T) {
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/api/openapi/spec", nil)
	NewOpenAPIHandler(nil, zap.NewNop(), nil, nil).GetOpenAPISpec(context)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var spec map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths := spec["paths"].(map[string]interface{})
	listPath, ok := paths["/api/boundary-policies"].(map[string]interface{})
	if !ok || listPath["get"] == nil {
		t.Fatalf("boundary list path = %#v", listPath)
	}
	path, ok := paths["/api/boundary-policies/{id}/simulate"].(map[string]interface{})
	if !ok || path["post"] == nil {
		t.Fatalf("boundary simulation path = %#v", path)
	}
	conversationPath, ok := paths["/api/conversations/{id}/boundary"].(map[string]interface{})
	if !ok || conversationPath["get"] == nil {
		t.Fatalf("conversation boundary path = %#v", conversationPath)
	}
	schemas := spec["components"].(map[string]interface{})["schemas"].(map[string]interface{})
	if _, ok := schemas["BoundaryPolicySummary"].(map[string]interface{}); !ok {
		t.Fatal("BoundaryPolicySummary schema is missing")
	}
	snapshotSchema, ok := schemas["ConversationBoundarySnapshot"].(map[string]interface{})
	if !ok {
		t.Fatal("ConversationBoundarySnapshot schema is missing")
	}
	snapshotProperties := snapshotSchema["properties"].(map[string]interface{})
	if _, ok := snapshotProperties["runtimeGeneration"]; !ok {
		t.Fatal("ConversationBoundarySnapshot runtimeGeneration is missing")
	}
}

func TestGetConversationBoundarySnapshotEnforcesConversationScope(t *testing.T) {
	db, policy := newBoundaryPolicyHandlerTestDB(t)
	conversation, err := db.CreateConversation("bounded", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer, BoundaryPolicyID: policy.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", conversation.ID, "owner-1"); err != nil {
		t.Fatal(err)
	}
	want, err := db.EnsureConversationBoundarySnapshot(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewBoundaryPolicyHandler(db, zap.NewNop())
	perform := func(session security.Session) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		context, _ := gin.CreateTestContext(recorder)
		context.Request = httptest.NewRequest(http.MethodGet, "/api/conversations/"+conversation.ID+"/boundary", nil)
		context.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		context.Set(security.ContextSessionKey, session)
		handler.GetConversationSnapshot(context)
		return recorder
	}
	owner := perform(security.Session{
		UserID: "owner-1", Scope: database.RBACScopeOwn,
		Permissions:      map[string]bool{"chat:read": true},
		PermissionScopes: map[string]string{"chat:read": database.RBACScopeOwn},
	})
	if owner.Code != http.StatusOK {
		t.Fatalf("owner status = %d: %s", owner.Code, owner.Body.String())
	}
	var got database.ConversationBoundarySnapshot
	if err := json.Unmarshal(owner.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.SnapshotID != want.SnapshotID || got.SHA256 != want.SHA256 || got.CanonicalJSON != want.CanonicalJSON {
		t.Fatalf("snapshot = %#v; want %#v", got, want)
	}
	foreign := perform(security.Session{
		UserID: "foreign", Scope: database.RBACScopeOwn,
		Permissions:      map[string]bool{"chat:read": true},
		PermissionScopes: map[string]string{"chat:read": database.RBACScopeOwn},
	})
	if foreign.Code != http.StatusForbidden {
		t.Fatalf("foreign status = %d: %s", foreign.Code, foreign.Body.String())
	}
}
