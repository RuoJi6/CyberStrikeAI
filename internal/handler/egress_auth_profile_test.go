package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newEgressAuthProfileHandlerTest(t *testing.T, session security.Session, logger *zap.Logger) (*database.DB, *egress.CredentialCipher, *gin.Engine) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "auth-profile-handler.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cipher, err := egress.NewCredentialCipher(bytes.Repeat([]byte{0x56}, 32))
	if err != nil {
		t.Fatal(err)
	}
	handler := NewEgressAuthProfileHandler(db, cipher, logger)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, session)
		c.Next()
	})
	router.Use(security.RBACMiddleware(db))
	router.GET("/api/egress-auth-profiles", handler.List)
	router.POST("/api/egress-auth-profiles", handler.Create)
	router.GET("/api/egress-auth-profiles/:id", handler.Get)
	router.PUT("/api/egress-auth-profiles/:id", handler.Update)
	router.DELETE("/api/egress-auth-profiles/:id", handler.Delete)
	return db, cipher, router
}

func TestEgressAuthProfileAPIEncryptsRedactsPreservesAndClearsCredential(t *testing.T) {
	db, cipher, router := newEgressAuthProfileHandlerTest(t, security.Session{
		UserID: "owner-1", Scope: database.RBACScopeAll, Permissions: allEgressPermissions(),
	}, zap.NewNop())
	secret := "Bearer handler-gateway-secret"
	create := egressProxyRequest(router, http.MethodPost, "/api/egress-auth-profiles", `{
		"name":"Target API","headerName":"authorization","credential":"`+secret+`"
	}`)
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", create.Code, create.Body.String())
	}
	if strings.Contains(create.Body.String(), secret) || strings.Contains(create.Body.String(), "credentialCiphertext") || strings.Contains(create.Body.String(), `"credential"`) {
		t.Fatalf("create response exposed credential: %s", create.Body.String())
	}
	var created database.EgressAuthProfile
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	stored, err := db.GetEgressAuthProfile(t.Context(), created.ID)
	if err != nil || stored.CredentialCiphertext == "" || strings.Contains(stored.CredentialCiphertext, secret) {
		t.Fatalf("stored auth profile = %#v, %v", stored, err)
	}
	plaintext, err := cipher.DecryptAuthProfile(stored.ID, stored.CredentialCiphertext)
	if err != nil || string(plaintext) != secret {
		t.Fatalf("decrypted credential = %q, %v", plaintext, err)
	}
	preserve := egressProxyRequest(router, http.MethodPut, "/api/egress-auth-profiles/"+created.ID,
		`{"name":"Renamed","headerName":"x-api-key","enabled":true}`)
	if preserve.Code != http.StatusOK {
		t.Fatalf("preserve status = %d: %s", preserve.Code, preserve.Body.String())
	}
	preserved, err := db.GetEgressAuthProfile(t.Context(), created.ID)
	if err != nil || preserved.CredentialCiphertext != stored.CredentialCiphertext || preserved.HeaderName != "X-Api-Key" {
		t.Fatalf("preserved auth profile = %#v, %v", preserved, err)
	}
	clear := egressProxyRequest(router, http.MethodPut, "/api/egress-auth-profiles/"+created.ID,
		`{"name":"Renamed","headerName":"x-api-key","credential":null}`)
	if clear.Code != http.StatusOK || strings.Contains(clear.Body.String(), secret) {
		t.Fatalf("clear status = %d: %s", clear.Code, clear.Body.String())
	}
	cleared, err := db.GetEgressAuthProfile(t.Context(), created.ID)
	if err != nil || cleared.CredentialsConfigured || cleared.CredentialCiphertext != "" || cleared.CredentialUpdatedAt != nil {
		t.Fatalf("cleared auth profile = %#v, %v", cleared, err)
	}
}

func TestEgressAuthProfileAPIRejectsInjectionWithoutEchoingCredential(t *testing.T) {
	_, _, router := newEgressAuthProfileHandlerTest(t, security.Session{
		UserID: "owner-1", Scope: database.RBACScopeAll, Permissions: allEgressPermissions(),
	}, zap.NewNop())
	secret := `forbidden-secret\r\nInjected: true`
	response := egressProxyRequest(router, http.MethodPost, "/api/egress-auth-profiles", `{
		"name":"Bad","headerName":"Authorization","credential":"`+secret+`"
	}`)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "forbidden-secret") {
		t.Fatalf("invalid credential response = %d: %s", response.Code, response.Body.String())
	}
	for _, headerName := range []string{"Host", "Proxy-Authorization", "X-Forwarded-For"} {
		response := egressProxyRequest(router, http.MethodPost, "/api/egress-auth-profiles", `{
			"name":"Bad","headerName":"`+headerName+`","credential":"hidden"
		}`)
		if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "hidden") {
			t.Fatalf("header %s response = %d: %s", headerName, response.Code, response.Body.String())
		}
	}
}

func TestEgressAuthProfileOpenAPIKeepsCredentialWriteOnly(t *testing.T) {
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/api/openapi/spec", nil)
	NewOpenAPIHandler(nil, zap.NewNop(), nil, nil).GetOpenAPISpec(context)
	if recorder.Code != http.StatusOK {
		t.Fatalf("openapi status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var spec map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths := spec["paths"].(map[string]interface{})
	if path, ok := paths["/api/egress-auth-profiles"].(map[string]interface{}); !ok || path["get"] == nil || path["post"] == nil {
		t.Fatalf("auth profile collection path = %#v", path)
	}
	if path, ok := paths["/api/egress-auth-profiles/{id}"].(map[string]interface{}); !ok || path["get"] == nil || path["put"] == nil || path["delete"] == nil {
		t.Fatalf("auth profile item path = %#v", path)
	}
	schemas := spec["components"].(map[string]interface{})["schemas"].(map[string]interface{})
	responseProperties := schemas["EgressAuthProfile"].(map[string]interface{})["properties"].(map[string]interface{})
	for _, forbidden := range []string{"credential", "credentialCiphertext", "headerValue"} {
		if _, exists := responseProperties[forbidden]; exists {
			t.Fatalf("auth profile response schema exposes %q", forbidden)
		}
	}
	writeProperties := schemas["EgressAuthProfileWrite"].(map[string]interface{})["properties"].(map[string]interface{})
	credential := writeProperties["credential"].(map[string]interface{})
	if writeOnly, _ := credential["writeOnly"].(bool); !writeOnly {
		t.Fatalf("auth profile credential is not writeOnly: %#v", credential)
	}
}
