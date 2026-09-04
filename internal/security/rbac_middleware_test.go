package security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
)

func TestRBACMiddlewareUsesMatchedFullPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextSessionKey, Session{
			UserID:      "u1",
			Username:    "operator",
			Permissions: map[string]bool{"project:read": true},
			Scope:       database.RBACScopeAll,
		})
		c.Next()
	})
	router.Use(RBACMiddleware(nil))
	router.GET("/api/projects/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/projects/p1", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestRBACMiddlewareRejectsMissingPermission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextSessionKey, Session{
			UserID:      "u1",
			Username:    "viewer",
			Permissions: map[string]bool{"project:read": true},
			Scope:       database.RBACScopeAll,
		})
		c.Next()
	})
	router.Use(RBACMiddleware(nil))
	router.POST("/api/projects", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestRBACMiddlewareRejectsUnmappedProtectedRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextSessionKey, Session{
			UserID:      "u1",
			Username:    "admin",
			Permissions: allPermissions(),
			Scope:       database.RBACScopeAll,
		})
		c.Next()
	})
	router.Use(RBACMiddleware(nil))
	router.GET("/api/new-module", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/new-module", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestRBACMiddlewareMapsOpenAPISpec(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextSessionKey, Session{
			UserID:      "u1",
			Username:    "viewer",
			Permissions: map[string]bool{"openapi:read": true},
			Scope:       database.RBACScopeAll,
		})
		c.Next()
	})
	router.Use(RBACMiddleware(nil))
	router.GET("/api/openapi/spec", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/openapi/spec", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestRBACResourcePickerRequiresWritePermission(t *testing.T) {
	if got := permissionForRequest(http.MethodGet, "/api/rbac/resources"); got != "rbac:write" {
		t.Fatalf("picker permission = %q, want rbac:write", got)
	}
	if got := permissionForRequest(http.MethodGet, "/api/rbac/resource-assignments"); got != "rbac:read" {
		t.Fatalf("assignment list permission = %q, want rbac:read", got)
	}
}

func TestBoundarySimulationUsesReadPermissionDespitePOST(t *testing.T) {
	if got := permissionForRequest(http.MethodGet, "/api/boundary-policies"); got != "boundary:read" {
		t.Fatalf("boundary list permission = %q, want boundary:read", got)
	}
	if got := permissionForRequest(http.MethodPost, "/api/boundary-policies/:id/simulate"); got != "boundary:read" {
		t.Fatalf("boundary simulation permission = %q, want boundary:read", got)
	}
}

func TestBoundaryDraftRoutesUseCRUDPermissions(t *testing.T) {
	for _, test := range []struct{ method, path, want string }{
		{http.MethodPost, "/api/boundary-policies", "boundary:write"},
		{http.MethodGet, "/api/boundary-policies/:id", "boundary:read"},
		{http.MethodPut, "/api/boundary-policies/:id", "boundary:write"},
		{http.MethodDelete, "/api/boundary-policies/:id", "boundary:delete"},
		{http.MethodPost, "/api/boundary-policies/:id/rules", "boundary:write"},
		{http.MethodPut, "/api/boundary-policies/:id/rules/:ruleId", "boundary:write"},
		{http.MethodDelete, "/api/boundary-policies/:id/rules/:ruleId", "boundary:delete"},
	} {
		if got := permissionForRequest(test.method, test.path); got != test.want {
			t.Fatalf("%s %s permission = %q, want %q", test.method, test.path, got, test.want)
		}
	}
}

func TestEgressProxyRoutesUseCRUDPermissions(t *testing.T) {
	tests := map[string]string{
		http.MethodGet:    "egress:read",
		http.MethodPost:   "egress:write",
		http.MethodPut:    "egress:write",
		http.MethodDelete: "egress:delete",
	}
	for _, prefix := range []string{"/api/egress-proxies", "/api/egress-proxy-groups"} {
		for method, want := range tests {
			path := prefix
			if method == http.MethodPut || method == http.MethodDelete {
				path += "/:id"
			}
			if got := permissionForRequest(method, path); got != want {
				t.Fatalf("%s %s permission = %q, want %q", method, prefix, got, want)
			}
		}
	}
	if got := permissionForRequest(http.MethodGet, "/api/egress-auth-profiles"); got != "" {
		t.Fatalf("retired credential profile endpoint permission = %q", got)
	}
}

func TestContainerRuntimeListUsesConversationReadPermission(t *testing.T) {
	for _, path := range []string{"/api/container-runtimes", "/api/container-runtime-rollout"} {
		if got := permissionForRequest(http.MethodGet, path); got != "chat:read" {
			t.Fatalf("%s permission = %q, want chat:read", path, got)
		}
	}
}

func TestConversationEgressActivityUsesConversationReadPermission(t *testing.T) {
	if got := permissionForRequest(http.MethodGet, "/api/conversations/:id/egress-activity/stream"); got != "chat:read" {
		t.Fatalf("egress activity stream permission = %q, want chat:read", got)
	}
}

func TestPersistentEgressAuditRoutesUseAuditReadPermission(t *testing.T) {
	for _, path := range []string{
		"/api/egress-audit-events",
		"/api/egress-audit-events/integrity",
		"/api/egress-audit-events/export",
		"/api/egress-audit-events/:id",
	} {
		if got := permissionForRequest(http.MethodGet, path); got != "audit:read" {
			t.Fatalf("%s permission = %q, want audit:read", path, got)
		}
	}
	if got := permissionForRequest(http.MethodPost, "/api/egress-audit-events"); got != "audit:read" {
		t.Fatalf("non-GET persistent audit permission = %q, want audit:read", got)
	}
	if got := permissionForRequest(http.MethodDelete, "/api/egress-audit-events"); got != "audit:delete" {
		t.Fatalf("persistent audit delete permission = %q, want audit:delete", got)
	}
}

func TestEgressDefaultRoutesUseSelectionPermissions(t *testing.T) {
	for _, tc := range []struct {
		method string
		path   string
		want   string
	}{
		{http.MethodGet, "/api/egress-defaults/user", "egress:read"},
		{http.MethodPut, "/api/egress-defaults/user", "egress:write"},
		{http.MethodDelete, "/api/egress-defaults/user", "egress:write"},
		{http.MethodGet, "/api/egress-defaults/preview", "egress:read"},
		{http.MethodGet, "/api/projects/:id/egress-default", "project:read"},
		{http.MethodPut, "/api/projects/:id/egress-default", "project:write"},
		{http.MethodDelete, "/api/projects/:id/egress-default", "project:write"},
		{http.MethodDelete, "/api/conversations/:id/egress", "chat:write"},
	} {
		if got := permissionForRequest(tc.method, tc.path); got != tc.want {
			t.Fatalf("%s %s permission = %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestConversationContainerWorkspaceRoutesUseConversationReadPermission(t *testing.T) {
	for _, path := range []string{
		"/api/conversations/:id/container/workspace",
		"/api/conversations/:id/container/terminal/ws",
	} {
		if got := permissionForRequest(http.MethodGet, path); got != "chat:read" {
			t.Fatalf("GET %s permission = %q, want chat:read", path, got)
		}
	}
}

func TestRBACMiddlewareMapsTokenUsageStatsToDashboardRead(t *testing.T) {
	if got := permissionForRequest(http.MethodGet, "/api/usage/tokens"); got != "dashboard:read" {
		t.Fatalf("token usage permission = %q, want dashboard:read", got)
	}
}

func TestMCPInvocationPermissionIsSeparateFromMCPAdministration(t *testing.T) {
	if got := permissionForRequest(http.MethodPost, "/api/mcp"); got != "mcp:execute" {
		t.Fatalf("MCP invocation permission = %q, want mcp:execute", got)
	}
	if got := permissionForRequest(http.MethodPut, "/api/external-mcp/example"); got != "mcp:write" {
		t.Fatalf("external MCP admin permission = %q, want mcp:write", got)
	}
}

func TestConfigToolsReadAllowsMCPReadWithoutConfigRead(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextSessionKey, Session{
			UserID:      "viewer",
			Username:    "viewer",
			Permissions: map[string]bool{"mcp:read": true},
			Scope:       database.RBACScopeAssigned,
		})
		c.Next()
	})
	router.Use(RBACMiddleware(nil))
	router.GET("/api/config/tools", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"tools": []any{}})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config/tools", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestWorkflowRunPermissionIsSeparateFromDefinitionManagement(t *testing.T) {
	if got := permissionForRequest(http.MethodPost, "/api/workflows/runs/run-1/resume"); got != "workflow:execute" {
		t.Fatalf("resume permission = %q, want workflow:execute", got)
	}
	if got := permissionForRequest(http.MethodPost, "/api/workflows/generate-draft"); got != "workflow:write" {
		t.Fatalf("generate draft permission = %q, want workflow:write", got)
	}
	if got := permissionForRequest(http.MethodPut, "/api/workflows/workflow-1"); got != "workflow:write" {
		t.Fatalf("definition permission = %q, want workflow:write", got)
	}
	if isProcessGlobalMutationPath("/workflows/generate-draft") {
		t.Fatalf("generate draft should not be treated as a process-global mutation")
	}
}

func TestTrafficTransformSourceUsesSeparateReadPermission(t *testing.T) {
	if got := permissionForRequest(http.MethodGet, "/api/traffic-transforms"); got != "traffic_transform:read" {
		t.Fatalf("dashboard permission = %q, want traffic_transform:read", got)
	}
	if got := permissionForRequest(http.MethodGet, "/api/traffic-transform-revisions/rev-1/source"); got != "traffic_transform:read_source" {
		t.Fatalf("source permission = %q, want traffic_transform:read_source", got)
	}
	if got := permissionForRequest(http.MethodPost, "/api/traffic-transforms/manual"); got != "traffic_transform:write" {
		t.Fatalf("manual authoring permission = %q, want traffic_transform:write", got)
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		if got := permissionForRequest(method, "/api/traffic-transforms/transform-1"); got != "traffic_transform:write" {
			t.Fatalf("script lifecycle permission for %s = %q, want traffic_transform:write", method, got)
		}
	}
	for _, request := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/traffic-transform-bindings"},
		{http.MethodPut, "/api/traffic-transform-bindings/binding-1/scope"},
		{http.MethodPost, "/api/traffic-transform-bindings/binding-1/activate"},
		{http.MethodPost, "/api/traffic-transform-bindings/binding-1/disable"},
		{http.MethodDelete, "/api/traffic-transform-bindings/binding-1"},
	} {
		if got := permissionForRequest(request.method, request.path); got != "traffic_transform:activate_observe" {
			t.Fatalf("binding control permission for %s %s = %q", request.method, request.path, got)
		}
	}
	if got := permissionForRequest(http.MethodPost, "/api/traffic-transactions/tx-1/replay"); got != "traffic:replay" {
		t.Fatalf("replay permission = %q, want traffic:replay", got)
	}
}

func TestRBACDenyHookReceivesDeniedDecision(t *testing.T) {
	gin.SetMode(gin.TestMode)
	called := false
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextSessionKey, Session{UserID: "viewer", Permissions: map[string]bool{"project:read": true}, Scope: database.RBACScopeAssigned})
		c.Next()
	})
	router.Use(RBACMiddlewareWithDenyHook(nil, func(_ *gin.Context, reason, permission string) {
		called = reason == "permission_denied" && permission == "project:write"
	}))
	router.POST("/api/projects", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/projects", nil))
	if w.Code != http.StatusForbidden || !called {
		t.Fatalf("denial = status %d, hook called %v", w.Code, called)
	}
}

func TestRBACMiddlewareBindsPermissionSpecificScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextSessionKey, Session{
			UserID: "mixed", Scope: database.RBACScopeAll,
			Permissions:      map[string]bool{"project:read": true, "project:write": true},
			PermissionScopes: map[string]string{"project:read": database.RBACScopeAll, "project:write": database.RBACScopeOwn},
		})
		c.Next()
	})
	router.Use(RBACMiddleware(nil))
	handler := func(c *gin.Context) {
		session, _ := CurrentSession(c)
		c.String(http.StatusOK, session.Scope)
	}
	router.GET("/api/projects/:id", handler)
	router.PUT("/api/projects/:id", handler)

	for _, tc := range []struct{ method, want string }{
		{http.MethodGet, database.RBACScopeAll},
		{http.MethodPut, database.RBACScopeOwn},
	} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(tc.method, "/api/projects/p1", nil))
		if w.Code != http.StatusOK || w.Body.String() != tc.want {
			t.Fatalf("%s scope response = %d/%q, want 200/%q", tc.method, w.Code, w.Body.String(), tc.want)
		}
	}
}

func TestRBACMiddlewareRejectsAssignedScopeForGlobalMonitorAggregates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		method     string
		path       string
		permission string
	}{
		{method: http.MethodGet, path: "/api/monitor/stats", permission: "monitor:read"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set(ContextSessionKey, Session{
					UserID: "assigned-user", Permissions: map[string]bool{tc.permission: true}, Scope: database.RBACScopeAssigned,
				})
				c.Next()
			})
			router.Use(RBACMiddleware(&database.DB{}))
			router.Handle(tc.method, tc.path, func(c *gin.Context) { c.Status(http.StatusOK) })

			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
			}
		})
	}
}

func TestAssignedScopeCannotMutateProcessGlobalAssets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, path := range []string{"/api/roles/demo", "/api/skills/demo", "/api/external-mcp/demo", "/api/workflows/demo", "/api/knowledge/items/demo"} {
		t.Run(path, func(t *testing.T) {
			permission := permissionForRequest(http.MethodPut, path)
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set(ContextSessionKey, Session{UserID: "operator", Scope: database.RBACScopeAssigned, Permissions: map[string]bool{permission: true}, PermissionScopes: map[string]string{permission: database.RBACScopeAssigned}})
				c.Next()
			})
			router.Use(RBACMiddleware(&database.DB{}))
			router.PUT(path, func(c *gin.Context) { c.Status(http.StatusNoContent) })
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodPut, path, nil))
			if w.Code != http.StatusForbidden {
				t.Fatalf("global mutation status = %d, want 403", w.Code)
			}
		})
	}
}
