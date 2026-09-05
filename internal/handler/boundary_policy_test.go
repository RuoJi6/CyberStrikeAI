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
	router.POST("/api/boundary-policies", handler.Create)
	router.GET("/api/boundary-policies/:id", handler.Get)
	router.GET("/api/boundary-policies/:id/usage", handler.Usage)
	router.PUT("/api/boundary-policies/:id", handler.Update)
	router.DELETE("/api/boundary-policies/:id", handler.Delete)
	router.POST("/api/boundary-policies/:id/rules", handler.CreateRule)
	router.PUT("/api/boundary-policies/:id/rules/:ruleId", handler.UpdateRule)
	router.DELETE("/api/boundary-policies/:id/rules/:ruleId", handler.DeleteRule)
	router.POST("/api/boundary-policies/:id/simulate", handler.SimulatePolicy)
	return router
}

func performBoundaryJSON(router *gin.Engine, method, path string, body interface{}) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(body)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestBoundaryPolicyDraftCRUDProvidesEditableRules(t *testing.T) {
	db, _ := newBoundaryPolicyHandlerTestDB(t)
	router := boundarySimulationRouter(db, security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{
			"boundary:read": true, "boundary:write": true, "boundary:delete": true,
		},
	})

	created := performBoundaryJSON(router, http.MethodPost, "/api/boundary-policies", map[string]interface{}{
		"name": "UI editable", "description": "draft", "tlsInspectionEnabled": true,
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", created.Code, created.Body.String())
	}
	var policy boundaryPolicyDetail
	if err := json.Unmarshal(created.Body.Bytes(), &policy); err != nil {
		t.Fatal(err)
	}
	if policy.ID == "" || policy.Name != "UI editable" || policy.DefaultAction != database.BoundaryDefaultActionDeny || policy.Rules == nil ||
		!policy.TLSInspectionEnabled || strings.Contains(created.Body.String(), `"tlsBypassDomains"`) {
		t.Fatalf("created policy = %#v", policy)
	}

	ruleCreated := performBoundaryJSON(router, http.MethodPost, "/api/boundary-policies/"+policy.ID+"/rules", map[string]interface{}{
		"effect": "allow-attack", "host": "API.Example.", "schemes": []string{"https"},
		"ports": []int{443}, "pathPrefixes": []string{"/v1"}, "methods": []string{"post"},
		"position": 1, "rateLimit": map[string]interface{}{"requestsPerSecond": 2, "burst": 3, "maxConcurrent": 1},
	})
	if ruleCreated.Code != http.StatusCreated {
		t.Fatalf("create rule status = %d: %s", ruleCreated.Code, ruleCreated.Body.String())
	}
	var rule database.BoundaryPolicyRule
	if err := json.Unmarshal(ruleCreated.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.ID == "" || rule.Host != "api.example" || len(rule.Methods) != 1 || rule.Methods[0] != "POST" {
		t.Fatalf("created rule = %#v", rule)
	}

	ruleUpdated := performBoundaryJSON(router, http.MethodPut, "/api/boundary-policies/"+policy.ID+"/rules/"+rule.ID, map[string]interface{}{
		"effect": "blocked", "host": "blocked.example", "schemes": []string{"http", "https"}, "position": 2,
		"rateLimit": map[string]interface{}{"requestsPerSecond": 0, "burst": 0, "maxConcurrent": 0},
	})
	if ruleUpdated.Code != http.StatusOK || !strings.Contains(ruleUpdated.Body.String(), "blocked.example") {
		t.Fatalf("update rule status = %d: %s", ruleUpdated.Code, ruleUpdated.Body.String())
	}

	blacklistCreated := performBoundaryJSON(router, http.MethodPost, "/api/boundary-policies/"+policy.ID+"/rules", map[string]interface{}{
		"effect": "blocked", "host": "", "pathPrefixes": []string{"/api/*", "=/desasdasdasd/sdadsd"}, "position": 3,
	})
	if blacklistCreated.Code != http.StatusCreated || !strings.Contains(blacklistCreated.Body.String(), `"host":"*"`) || !strings.Contains(blacklistCreated.Body.String(), `"pathPrefixes":["/api","=/desasdasdasd/sdadsd"]`) {
		t.Fatalf("create blacklist status = %d: %s", blacklistCreated.Code, blacklistCreated.Body.String())
	}
	wildcardAllow := performBoundaryJSON(router, http.MethodPost, "/api/boundary-policies/"+policy.ID+"/rules", map[string]interface{}{
		"effect": "allow-visit", "host": "*.example.com",
	})
	if wildcardAllow.Code != http.StatusBadRequest {
		t.Fatalf("wildcard allow status = %d: %s", wildcardAllow.Code, wildcardAllow.Body.String())
	}

	policyUpdated := performBoundaryJSON(router, http.MethodPut, "/api/boundary-policies/"+policy.ID, map[string]interface{}{
		"name": "UI edited", "description": "updated draft", "tlsInspectionEnabled": false,
		"defaultAction": "allow",
	})
	if policyUpdated.Code != http.StatusOK || !strings.Contains(policyUpdated.Body.String(), "blocked.example") ||
		!strings.Contains(policyUpdated.Body.String(), `"tlsInspectionEnabled":true`) || !strings.Contains(policyUpdated.Body.String(), `"defaultAction":"allow"`) {
		t.Fatalf("update policy status = %d: %s", policyUpdated.Code, policyUpdated.Body.String())
	}

	detail := performBoundaryJSON(router, http.MethodGet, "/api/boundary-policies/"+policy.ID, nil)
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "UI edited") {
		t.Fatalf("detail status = %d: %s", detail.Code, detail.Body.String())
	}

	deletedRule := performBoundaryJSON(router, http.MethodDelete, "/api/boundary-policies/"+policy.ID+"/rules/"+rule.ID, nil)
	if deletedRule.Code != http.StatusNoContent {
		t.Fatalf("delete rule status = %d: %s", deletedRule.Code, deletedRule.Body.String())
	}
	deletedPolicy := performBoundaryJSON(router, http.MethodDelete, "/api/boundary-policies/"+policy.ID, nil)
	if deletedPolicy.Code != http.StatusNoContent {
		t.Fatalf("delete policy status = %d: %s", deletedPolicy.Code, deletedPolicy.Body.String())
	}
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

func TestBoundaryPolicyListSupportsSearchPaginationAndUsageProjection(t *testing.T) {
	db, policy := newBoundaryPolicyHandlerTestDB(t)
	for _, name := range []string{"Alpha policy", "Beta policy", "Gamma policy"} {
		if _, err := db.CreateBoundaryPolicy(context.Background(), database.BoundaryPolicy{Name: name, OwnerUserID: "owner-1"}); err != nil {
			t.Fatal(err)
		}
	}
	router := boundarySimulationRouter(db, security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{"boundary:read": true, "chat:read": true},
	})
	response := performBoundaryJSON(router, http.MethodGet, "/api/boundary-policies?page=1&page_size=2&search=policy", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("list status = %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Items      []boundaryPolicySummary `json:"items"`
		Page       int                     `json:"page"`
		PageSize   int                     `json:"pageSize"`
		Total      int                     `json:"total"`
		TotalPages int                     `json:"totalPages"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Page != 1 || payload.PageSize != 2 || payload.Total != 3 || payload.TotalPages != 2 || len(payload.Items) != 2 {
		t.Fatalf("payload = %#v", payload)
	}
	for _, item := range payload.Items {
		if item.Protocols == nil {
			t.Fatalf("protocol projection is nil: %#v", item)
		}
	}
	usage := performBoundaryJSON(router, http.MethodGet, "/api/boundary-policies/"+policy.ID+"/usage", nil)
	if usage.Code != http.StatusOK || !strings.Contains(usage.Body.String(), `"total":0`) {
		t.Fatalf("usage status = %d: %s", usage.Code, usage.Body.String())
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
		{name: "blocked path", url: "https://api.example/v1/admin/users", reason: boundary.ReasonBlockedPathSubtree, ruleID: "block-admin", resolvedIPs: []string{"93.184.216.34"}},
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

func TestBoundaryPolicySimulationSupportsPathOnlyBlacklist(t *testing.T) {
	db, _ := newBoundaryPolicyHandlerTestDB(t)
	policy, err := db.CreateBoundaryPolicy(context.Background(), database.BoundaryPolicy{
		Name: "path blacklist", OwnerUserID: "owner-1", DefaultAction: database.BoundaryDefaultActionAllow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateBoundaryPolicyRule(context.Background(), database.BoundaryPolicyRule{
		ID: "blocked-path-only", PolicyID: policy.ID, Effect: boundary.EffectBlocked,
		PathPrefixes: []string{"/blocked/*"}, Methods: []string{"GET"},
	}); err != nil {
		t.Fatal(err)
	}
	router := boundarySimulationRouter(db, security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{"boundary:read": true},
	})
	for _, tc := range []struct {
		path, reason string
		allowed      bool
	}{
		{path: "/", reason: boundary.ReasonAllowVisit, allowed: true},
		{path: "/blocked/child", reason: boundary.ReasonBlockedPathSubtree, allowed: false},
	} {
		recorder := performBoundarySimulation(router, policy.ID, map[string]interface{}{
			"url": "https://example.com" + tc.path, "method": "GET", "resolvedIps": []string{"93.184.216.34"},
		})
		if recorder.Code != http.StatusOK {
			t.Fatalf("simulate %s status = %d: %s", tc.path, recorder.Code, recorder.Body.String())
		}
		var response simulateBoundaryPolicyResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Allowed != tc.allowed || response.Reason != tc.reason {
			t.Fatalf("simulate %s = %#v", tc.path, response)
		}
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
	if _, exists := paths["/api/egress-auth-profiles"]; exists {
		t.Fatal("retired credential profile collection remains in OpenAPI")
	}
	if _, exists := paths["/api/egress-auth-profiles/{id}"]; exists {
		t.Fatal("retired credential profile detail remains in OpenAPI")
	}
	listPath, ok := paths["/api/boundary-policies"].(map[string]interface{})
	if !ok || listPath["get"] == nil || listPath["post"] == nil {
		t.Fatalf("boundary list path = %#v", listPath)
	}
	createOperation := listPath["post"].(map[string]interface{})
	createDescription, _ := createOperation["description"].(string)
	if !strings.Contains(createDescription, "HTTPS 完整审计始终开启并尝试解密所有目标，不依赖是否选择边界策略") || strings.Contains(createDescription, "默认关闭") {
		t.Fatalf("boundary create description still couples HTTPS inspection to policy selection: %q", createDescription)
	}
	detailPath, ok := paths["/api/boundary-policies/{id}"].(map[string]interface{})
	if !ok || detailPath["get"] == nil || detailPath["put"] == nil || detailPath["delete"] == nil {
		t.Fatalf("boundary detail CRUD path = %#v", detailPath)
	}
	rulesPath, ok := paths["/api/boundary-policies/{id}/rules/{ruleId}"].(map[string]interface{})
	if !ok || rulesPath["put"] == nil || rulesPath["delete"] == nil {
		t.Fatalf("boundary rule CRUD path = %#v", rulesPath)
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
	for _, name := range []string{"BoundaryPolicyWrite", "BoundaryPolicyDetail", "BoundaryRuleWrite", "BoundaryRule"} {
		if _, ok := schemas[name].(map[string]interface{}); !ok {
			t.Fatalf("%s schema is missing", name)
		}
	}
	boundaryWrite := schemas["BoundaryPolicyWrite"].(map[string]interface{})
	boundaryWriteProperties := boundaryWrite["properties"].(map[string]interface{})
	if _, exposed := boundaryWriteProperties["tlsInspectionEnabled"]; exposed {
		t.Fatal("BoundaryPolicyWrite must not expose a TLS inspection switch")
	}
	if _, exposed := boundaryWriteProperties["tlsBypassDomains"]; exposed {
		t.Fatal("BoundaryPolicyWrite must not expose legacy TLS bypass domains")
	}
	snapshotSchema, ok := schemas["ConversationBoundarySnapshot"].(map[string]interface{})
	if !ok {
		t.Fatal("ConversationBoundarySnapshot schema is missing")
	}
	snapshotProperties := snapshotSchema["properties"].(map[string]interface{})
	if _, ok := snapshotProperties["runtimeGeneration"]; !ok {
		t.Fatal("ConversationBoundarySnapshot runtimeGeneration is missing")
	}
	documentSchema := snapshotProperties["document"].(map[string]interface{})
	documentProperties := documentSchema["properties"].(map[string]interface{})
	schemaVersions, ok := documentProperties["schemaVersion"].(map[string]interface{})["enum"].([]interface{})
	if !ok || len(schemaVersions) != 6 || schemaVersions[5] != float64(6) {
		t.Fatalf("ConversationBoundarySnapshot schema versions = %#v", schemaVersions)
	}
	if _, ok := documentProperties["tlsInspection"]; !ok {
		t.Fatal("ConversationBoundarySnapshot tlsInspection is missing")
	}
	if _, ok := documentProperties["networkAccess"]; !ok {
		t.Fatal("ConversationBoundarySnapshot networkAccess is missing")
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
