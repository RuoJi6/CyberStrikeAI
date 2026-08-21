package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newEgressProxyGroupHandlerTest(t *testing.T, session security.Session) (*database.DB, *gin.Engine) {
	t.Helper()
	db, _, router := newEgressProxyHandlerTest(t, session)
	h := NewEgressProxyGroupHandler(db, zap.NewNop())
	router.GET("/api/egress-proxy-groups", h.List)
	router.POST("/api/egress-proxy-groups", h.Create)
	router.GET("/api/egress-proxy-groups/:id", h.Get)
	router.PUT("/api/egress-proxy-groups/:id", h.Update)
	router.DELETE("/api/egress-proxy-groups/:id", h.Delete)
	return db, router
}

func createGroupHandlerProxy(t *testing.T, db *database.DB, id, owner string, enabled bool) {
	t.Helper()
	if _, err := db.CreateEgressProxy(t.Context(), database.EgressProxy{
		ID: id, Name: "Proxy " + id, Protocol: egress.UpstreamProtocolHTTPS,
		Host: id + ".example", Port: 8443, Enabled: enabled, OwnerUserID: owner,
		CredentialCiphertext: "v1.key.ciphertext",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEgressProxyGroupAPICRUDDefaultsHealthAndSafeProjection(t *testing.T) {
	db, router := newEgressProxyGroupHandlerTest(t, security.Session{
		UserID: "owner-1", Scope: database.RBACScopeOwn, Permissions: allEgressPermissions(),
	})
	createGroupHandlerProxy(t, db, "proxy-a", "owner-1", true)
	createGroupHandlerProxy(t, db, "proxy-b", "owner-1", true)
	create := egressProxyRequest(router, http.MethodPost, "/api/egress-proxy-groups", `{
		"name":" Primary group ",
		"members":[
			{"proxyId":"proxy-b","priority":10,"weight":1},
			{"proxyId":"proxy-a","priority":10,"weight":3}
		]
	}`)
	if create.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", create.Code, create.Body.String())
	}
	for _, forbidden := range []string{"credentialCiphertext", "credential_ciphertext", "currentWeight", "current_weight", "username", "password"} {
		if strings.Contains(create.Body.String(), forbidden) {
			t.Fatalf("create response exposed %q: %s", forbidden, create.Body.String())
		}
	}
	var created database.EgressProxyGroup
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Name != "Primary group" || !created.Enabled || !created.FailClosed || created.FailureThreshold != 3 || created.CooldownSeconds != 60 || len(created.Members) != 2 {
		t.Fatalf("created = %#v", created)
	}
	if created.Members[0].ProxyID != "proxy-a" || !created.Members[0].Proxy.CredentialsConfigured {
		t.Fatalf("sorted/safe members = %#v", created.Members)
	}

	base := time.Now().UTC().Truncate(time.Second)
	for range 3 {
		if _, err := db.RecordEgressProxyGroupMemberResult(t.Context(), created.ID, "proxy-a", false, base); err != nil {
			t.Fatal(err)
		}
	}
	get := egressProxyRequest(router, http.MethodGet, "/api/egress-proxy-groups/"+created.ID, "")
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"status":"circuit_open"`) {
		t.Fatalf("get = %d: %s", get.Code, get.Body.String())
	}
	update := egressProxyRequest(router, http.MethodPut, "/api/egress-proxy-groups/"+created.ID,
		`{"name":"Updated group","enabled":false,"failureThreshold":4,"cooldownSeconds":120}`)
	if update.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", update.Code, update.Body.String())
	}
	var updated database.EgressProxyGroup
	if err := json.Unmarshal(update.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Updated group" || updated.Enabled || updated.FailureThreshold != 4 || updated.CooldownSeconds != 120 || len(updated.Members) != 2 || updated.Members[0].CircuitOpenUntil == nil {
		t.Fatalf("updated = %#v", updated)
	}
	list := egressProxyRequest(router, http.MethodGet, "/api/egress-proxy-groups", "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), created.ID) {
		t.Fatalf("list = %d: %s", list.Code, list.Body.String())
	}
	deleted := egressProxyRequest(router, http.MethodDelete, "/api/egress-proxy-groups/"+created.ID, "")
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete = %d: %s", deleted.Code, deleted.Body.String())
	}
	missing := egressProxyRequest(router, http.MethodGet, "/api/egress-proxy-groups/"+created.ID, "")
	if missing.Code != http.StatusForbidden {
		// Own-scoped RBAC denies a deleted resource before the handler, avoiding
		// an existence oracle.
		t.Fatalf("get deleted = %d: %s", missing.Code, missing.Body.String())
	}
}

func TestEgressProxyGroupAPIRejectsInvalidAndInaccessibleMembers(t *testing.T) {
	db, router := newEgressProxyGroupHandlerTest(t, security.Session{
		UserID: "owner-1", Scope: database.RBACScopeOwn, Permissions: allEgressPermissions(),
	})
	createGroupHandlerProxy(t, db, "owned", "owner-1", true)
	createGroupHandlerProxy(t, db, "hidden", "owner-2", true)
	tests := []string{
		`{"name":"Missing members"}`,
		`{"name":"Null members","members":null}`,
		`{"name":"Empty members","members":[]}`,
		`{"name":"Duplicate","members":[{"proxyId":"owned","priority":0,"weight":1},{"proxyId":"owned","priority":1,"weight":1}]}`,
		`{"name":"Bad weight","members":[{"proxyId":"owned","priority":0,"weight":0}]}`,
		`{"name":"Unknown field","members":[{"proxyId":"owned","priority":0,"weight":1,"secret":"no"}]}`,
		`{"name":"Missing proxy","members":[{"proxyId":"missing","priority":0,"weight":1}]}`,
		`{"name":"Hidden proxy","members":[{"proxyId":"hidden","priority":0,"weight":1}]}`,
	}
	for _, body := range tests {
		response := egressProxyRequest(router, http.MethodPost, "/api/egress-proxy-groups", body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid body %s => %d: %s", body, response.Code, response.Body.String())
		}
	}
	var groups int
	if err := db.QueryRow(`SELECT COUNT(*) FROM egress_proxy_groups`).Scan(&groups); err != nil || groups != 0 {
		t.Fatalf("invalid requests wrote groups = %d / %v", groups, err)
	}
}

func TestEgressProxyGroupAPIEnforcesGroupResourceScope(t *testing.T) {
	db, ownerRouter := newEgressProxyGroupHandlerTest(t, security.Session{
		UserID: "owner-1", Scope: database.RBACScopeOwn, Permissions: allEgressPermissions(),
	})
	createGroupHandlerProxy(t, db, "owned", "owner-1", true)
	created := egressProxyRequest(ownerRouter, http.MethodPost, "/api/egress-proxy-groups", `{
		"name":"Owned group","members":[{"proxyId":"owned","priority":0,"weight":1}]
	}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("owner create = %d: %s", created.Code, created.Body.String())
	}
	var group database.EgressProxyGroup
	if err := json.Unmarshal(created.Body.Bytes(), &group); err != nil {
		t.Fatal(err)
	}
	h := NewEgressProxyGroupHandler(db, zap.NewNop())
	stranger := gin.New()
	stranger.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "stranger", Scope: database.RBACScopeOwn, Permissions: allEgressPermissions()})
		c.Next()
	})
	stranger.Use(security.RBACMiddleware(db))
	stranger.GET("/api/egress-proxy-groups", h.List)
	stranger.GET("/api/egress-proxy-groups/:id", h.Get)
	if response := egressProxyRequest(stranger, http.MethodGet, "/api/egress-proxy-groups/"+group.ID, ""); response.Code != http.StatusForbidden {
		t.Fatalf("stranger get = %d: %s", response.Code, response.Body.String())
	}
	list := egressProxyRequest(stranger, http.MethodGet, "/api/egress-proxy-groups", "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"items":[]`) {
		t.Fatalf("stranger list = %d: %s", list.Code, list.Body.String())
	}
}

func TestEgressProxySearchAPIIsScopedPaginatedAndLiteral(t *testing.T) {
	db, _, router := newEgressProxyHandlerTest(t, security.Session{
		UserID: "owner-1", Scope: database.RBACScopeOwn, Permissions: allEgressPermissions(),
	})
	createGroupHandlerProxy(t, db, "first", "owner-1", true)
	createGroupHandlerProxy(t, db, "second", "owner-1", true)
	createGroupHandlerProxy(t, db, "hidden", "owner-2", true)
	if _, err := db.Exec(`UPDATE egress_proxies SET name = 'Literal % member' WHERE id = 'second'`); err != nil {
		t.Fatal(err)
	}
	response := egressProxyRequest(router, http.MethodGet, "/api/egress-proxies?search=%25&limit=1&offset=0", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"total":1`) || !strings.Contains(response.Body.String(), `"id":"second"`) || strings.Contains(response.Body.String(), `"id":"hidden"`) {
		t.Fatalf("search = %d: %s", response.Code, response.Body.String())
	}
	for _, path := range []string{
		"/api/egress-proxies?limit=0", "/api/egress-proxies?limit=101", "/api/egress-proxies?offset=-1", "/api/egress-proxies?limit=wat",
	} {
		if invalid := egressProxyRequest(router, http.MethodGet, path, ""); invalid.Code != http.StatusBadRequest {
			t.Fatalf("invalid search %s = %d: %s", path, invalid.Code, invalid.Body.String())
		}
	}
}

func TestEgressProxyGroupOpenAPIContracts(t *testing.T) {
	recorder := egressProxyRequest(openAPITestRouter(t), http.MethodGet, "/api/openapi/spec", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var spec map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths := spec["paths"].(map[string]interface{})
	for _, path := range []string{"/api/egress-proxy-groups", "/api/egress-proxy-groups/{id}"} {
		if _, ok := paths[path].(map[string]interface{}); !ok {
			t.Fatalf("missing OpenAPI path %s", path)
		}
	}
	schemas := spec["components"].(map[string]interface{})["schemas"].(map[string]interface{})
	group := schemas["EgressProxyGroup"].(map[string]interface{})
	properties := group["properties"].(map[string]interface{})
	if properties["failClosed"].(map[string]interface{})["readOnly"] != true {
		t.Fatalf("failClosed schema = %#v", properties["failClosed"])
	}
	encoded, _ := json.Marshal(group)
	for _, forbidden := range []string{"credentialCiphertext", "currentWeight", "username", "password"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("group schema exposes %q: %s", forbidden, encoded)
		}
	}
}

func openAPITestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/openapi/spec", NewOpenAPIHandler(nil, zap.NewNop(), nil, nil).GetOpenAPISpec)
	return router
}
