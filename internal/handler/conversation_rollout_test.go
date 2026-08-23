package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestCreateConversationEnforcesContainerRollout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerRolloutAuthorizer(func(userID, projectID string) (bool, bool) {
		return true, userID == "allowed-user"
	})

	denied := performConversationRequest(user, http.MethodPost, "/api/conversations", map[string]interface{}{
		"title": "denied", "runtimeMode": database.ConversationRuntimeModeContainer,
	}, handler.CreateConversation)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("container denial status = %d: %s", denied.Code, denied.Body.String())
	}

	host := performConversationRequest(user, http.MethodPost, "/api/conversations", map[string]interface{}{
		"title": "host", "runtimeMode": database.ConversationRuntimeModeHost,
	}, handler.CreateConversation)
	if host.Code != http.StatusOK {
		t.Fatalf("host status = %d: %s", host.Code, host.Body.String())
	}

	handler.SetContainerRolloutAuthorizer(func(userID, projectID string) (bool, bool) { return true, true })
	allowed := performConversationRequest(user, http.MethodPost, "/api/conversations", map[string]interface{}{
		"title": "allowed", "runtimeMode": database.ConversationRuntimeModeContainer,
	}, handler.CreateConversation)
	if allowed.Code != http.StatusOK {
		t.Fatalf("allowed container status = %d: %s", allowed.Code, allowed.Body.String())
	}
}

func TestGetContainerRuntimeRolloutUsesSessionAndProtectsProjectScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	project, err := db.CreateProject(&database.Project{Name: "rollout project"})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerRolloutAuthorizer(func(userID, projectID string) (bool, bool) {
		return true, userID == user.ID && projectID == project.ID
	})
	request := func(projectID string, projectRead bool) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/container-runtime-rollout?project_id="+projectID, bytes.NewReader(nil))
		c.Set(security.ContextSessionKey, security.Session{
			UserID: user.ID, Username: user.Username, Scope: database.RBACScopeAssigned,
			Permissions: map[string]bool{"project:read": projectRead},
		})
		handler.GetContainerRuntimeRollout(c)
		return w
	}
	notFound := request("missing-project", true)
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("missing project status = %d: %s", notFound.Code, notFound.Body.String())
	}

	forbidden := request(project.ID, false)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("unscoped project status = %d: %s", forbidden.Code, forbidden.Body.String())
	}
	if err := db.AssignResourceToUser(user.ID, "project", project.ID); err != nil {
		t.Fatal(err)
	}
	allowed := request(project.ID, true)
	if allowed.Code != http.StatusOK {
		t.Fatalf("allowed rollout status = %d: %s", allowed.Code, allowed.Body.String())
	}
	var payload struct {
		Enabled bool   `json:"enabled"`
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(allowed.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Enabled || !payload.Allowed || payload.Reason != "allowed" {
		t.Fatalf("rollout payload = %#v", payload)
	}
}
