package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func newEgressProxyHandlerTest(t *testing.T, session security.Session) (*database.DB, *egress.CredentialCipher, *gin.Engine) {
	return newEgressProxyHandlerTestWithLogger(t, session, zap.NewNop())
}

func newEgressProxyHandlerTestWithLogger(t *testing.T, session security.Session, logger *zap.Logger) (*database.DB, *egress.CredentialCipher, *gin.Engine) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "egress-handler.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cipher, err := egress.NewCredentialCipher(bytes.Repeat([]byte{0x34}, 32))
	if err != nil {
		t.Fatal(err)
	}
	h := NewEgressProxyHandler(db, cipher, logger)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, session)
		c.Next()
	})
	router.Use(security.RBACMiddleware(db))
	router.GET("/api/egress-proxies", h.List)
	router.POST("/api/egress-proxies", h.Create)
	router.GET("/api/egress-proxies/:id", h.Get)
	router.PUT("/api/egress-proxies/:id", h.Update)
	router.DELETE("/api/egress-proxies/:id", h.Delete)
	return db, cipher, router
}

func TestEgressProxyAPIErrorLogsNeverContainCredentials(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	db, _, router := newEgressProxyHandlerTestWithLogger(t, security.Session{
		UserID: "owner-1", Scope: database.RBACScopeAll, Permissions: allEgressPermissions(),
	}, zap.New(core))
	if _, err := db.Exec(`DROP TABLE egress_proxies`); err != nil {
		t.Fatal(err)
	}
	username, password := "log-forbidden-user", "log-forbidden-secret"
	response := egressProxyRequest(router, http.MethodPost, "/api/egress-proxies", `{
		"name":"Broken storage","protocol":"http","host":"proxy.example","port":8080,
		"credentials":{"username":"`+username+`","password":"`+password+`"}
	}`)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	assertEgressResponseRedacted(t, response.Body.String(), username, password)
	for _, entry := range observed.All() {
		encoded, err := json.Marshal(entry.ContextMap())
		if err != nil {
			t.Fatal(err)
		}
		logText := entry.Message + " " + string(encoded)
		if strings.Contains(logText, username) || strings.Contains(logText, password) {
			t.Fatalf("log exposed credentials: %s", logText)
		}
	}
}

func egressProxyRequest(router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	router.ServeHTTP(recorder, request)
	return recorder
}

func allEgressPermissions() map[string]bool {
	return map[string]bool{"egress:read": true, "egress:write": true, "egress:delete": true}
}

func TestEgressProxyAPIEncryptsAndRedactsEveryResponse(t *testing.T) {
	db, cipher, router := newEgressProxyHandlerTest(t, security.Session{
		UserID: "owner-1", Scope: database.RBACScopeAll, Permissions: allEgressPermissions(),
	})
	secret := "stage5-super-secret"
	username := "proxy-user"
	create := egressProxyRequest(router, http.MethodPost, "/api/egress-proxies", `{
		"name":"Primary","protocol":"https","host":"Proxy.Example.COM.","port":8443,
		"credentials":{"username":"`+username+`","password":"`+secret+`"}
	}`)
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", create.Code, create.Body.String())
	}
	assertEgressResponseRedacted(t, create.Body.String(), username, secret)
	var created database.EgressProxy
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !created.CredentialsConfigured || created.ID == "" || created.Host != "proxy.example.com" {
		t.Fatalf("created = %#v", created)
	}
	var ciphertext string
	if err := db.QueryRow(`SELECT credential_ciphertext FROM egress_proxies WHERE id = ?`, created.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if ciphertext == "" || strings.Contains(ciphertext, secret) || strings.Contains(ciphertext, username) {
		t.Fatalf("unsafe ciphertext = %q", ciphertext)
	}
	plaintext, err := cipher.Decrypt(created.ID, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plaintext), username) || !strings.Contains(string(plaintext), secret) {
		t.Fatalf("decrypted credential mismatch")
	}
	assertEgressSQLiteFilesRedacted(t, db, username, secret)

	for _, request := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/egress-proxies", ""},
		{http.MethodGet, "/api/egress-proxies/" + created.ID, ""},
		{http.MethodPut, "/api/egress-proxies/" + created.ID, `{"name":"Updated","protocol":"socks5","host":"127.0.0.1","port":1080,"enabled":false}`},
	} {
		response := egressProxyRequest(router, request.method, request.path, request.body)
		if response.Code != http.StatusOK {
			t.Fatalf("%s %s status = %d: %s", request.method, request.path, response.Code, response.Body.String())
		}
		assertEgressResponseRedacted(t, response.Body.String(), username, secret)
	}
	var preserved string
	if err := db.QueryRow(`SELECT credential_ciphertext FROM egress_proxies WHERE id = ?`, created.ID).Scan(&preserved); err != nil {
		t.Fatal(err)
	}
	if preserved != ciphertext {
		t.Fatalf("omitted credentials changed ciphertext")
	}

	clear := egressProxyRequest(router, http.MethodPut, "/api/egress-proxies/"+created.ID,
		`{"name":"Updated","protocol":"socks5","host":"127.0.0.1","port":1080,"credentials":null}`)
	if clear.Code != http.StatusOK || strings.Contains(clear.Body.String(), secret) || strings.Contains(clear.Body.String(), username) {
		t.Fatalf("clear status/body = %d / %s", clear.Code, clear.Body.String())
	}
	var cleared database.EgressProxy
	if err := json.Unmarshal(clear.Body.Bytes(), &cleared); err != nil {
		t.Fatal(err)
	}
	if cleared.CredentialsConfigured || cleared.CredentialUpdatedAt != nil {
		t.Fatalf("clear response = %#v", cleared)
	}
}

func assertEgressSQLiteFilesRedacted(t *testing.T, db *database.DB, forbidden ...string) {
	t.Helper()
	var sequence int
	var name, dbPath string
	if err := db.QueryRow(`PRAGMA database_list`).Scan(&sequence, &name, &dbPath); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(dbPath + "*")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range forbidden {
			if bytes.Contains(content, []byte(value)) {
				t.Fatalf("SQLite file %s contains plaintext credential %q", filepath.Base(path), value)
			}
		}
	}
}

func TestEgressProxyAPIRBACAndValidation(t *testing.T) {
	db, _, ownerRouter := newEgressProxyHandlerTest(t, security.Session{
		UserID: "owner-1", Scope: database.RBACScopeOwn, Permissions: allEgressPermissions(),
	})
	created, err := db.CreateEgressProxy(httptest.NewRequest(http.MethodGet, "/", nil).Context(), database.EgressProxy{
		ID: "owned-proxy", Name: "Owned", Protocol: egress.UpstreamProtocolHTTP,
		Host: "proxy.example", Port: 8080, Enabled: true, OwnerUserID: "owner-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := egressProxyRequest(ownerRouter, http.MethodGet, "/api/egress-proxies/"+created.ID, ""); got.Code != http.StatusOK {
		t.Fatalf("owner get = %d: %s", got.Code, got.Body.String())
	}

	// Use a direct middleware router around the original DB to prove resource
	// ownership is enforced before the handler.
	cipher, _ := egress.NewCredentialCipher(bytes.Repeat([]byte{0x35}, 32))
	h := NewEgressProxyHandler(db, cipher, zap.NewNop())
	strangerRouter := gin.New()
	strangerRouter.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "stranger", Scope: database.RBACScopeOwn, Permissions: allEgressPermissions()})
		c.Next()
	})
	strangerRouter.Use(security.RBACMiddleware(db))
	strangerRouter.GET("/api/egress-proxies", h.List)
	strangerRouter.GET("/api/egress-proxies/:id", h.Get)
	if got := egressProxyRequest(strangerRouter, http.MethodGet, "/api/egress-proxies/"+created.ID, ""); got.Code != http.StatusForbidden {
		t.Fatalf("stranger get = %d: %s", got.Code, got.Body.String())
	}
	list := egressProxyRequest(strangerRouter, http.MethodGet, "/api/egress-proxies", "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"items":[]`) {
		t.Fatalf("stranger list = %d: %s", list.Code, list.Body.String())
	}

	for _, body := range []string{
		`{"name":"Bad URL","protocol":"http","host":"http://proxy.example","port":8080}`,
		`{"name":"Bad protocol","protocol":"ftp","host":"proxy.example","port":21}`,
		`{"name":"Bad credentials","protocol":"http","host":"proxy.example","port":8080,"credentials":{"username":"","password":"do-not-echo"}}`,
	} {
		response := egressProxyRequest(ownerRouter, http.MethodPost, "/api/egress-proxies", body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid create status = %d: %s", response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "do-not-echo") {
			t.Fatalf("validation response echoed credential: %s", response.Body.String())
		}
	}
}

func assertEgressResponseRedacted(t *testing.T, response string, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if strings.Contains(response, value) {
			t.Fatalf("response exposed %q: %s", value, response)
		}
	}
	for _, field := range []string{"credentialCiphertext", "credential_ciphertext", `"credentials"`, `"username"`, `"password"`} {
		if strings.Contains(response, field) {
			t.Fatalf("response exposed credential field %q: %s", field, response)
		}
	}
}

func TestEgressProxyOpenAPISeparatesWriteOnlyCredentialsFromResponses(t *testing.T) {
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
	if path, ok := paths["/api/egress-proxies"].(map[string]interface{}); !ok || path["get"] == nil || path["post"] == nil {
		t.Fatalf("egress collection path = %#v", path)
	}
	if path, ok := paths["/api/egress-proxies/{id}"].(map[string]interface{}); !ok || path["get"] == nil || path["put"] == nil || path["delete"] == nil {
		t.Fatalf("egress item path = %#v", path)
	}
	schemas := spec["components"].(map[string]interface{})["schemas"].(map[string]interface{})
	responseProperties := schemas["EgressProxy"].(map[string]interface{})["properties"].(map[string]interface{})
	for _, forbidden := range []string{"credentials", "username", "password", "credentialCiphertext"} {
		if _, exists := responseProperties[forbidden]; exists {
			t.Fatalf("response schema exposes %q", forbidden)
		}
	}
	writeProperties := schemas["EgressProxyWrite"].(map[string]interface{})["properties"].(map[string]interface{})
	credentials := writeProperties["credentials"].(map[string]interface{})
	if writeOnly, _ := credentials["writeOnly"].(bool); !writeOnly {
		t.Fatalf("credentials schema is not writeOnly: %#v", credentials)
	}
}
