package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestCreateConversationRequiresProjectAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	project, err := db.CreateProject(&database.Project{Name: "hidden"})
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	handler := NewConversationHandler(db, zap.NewNop())

	w := performConversationRequest(user, http.MethodPost, "/api/conversations", map[string]string{
		"title":     "blocked",
		"projectId": project.ID,
	}, handler.CreateConversation)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusForbidden, w.Body.String())
	}

	if err := db.AssignResourceToUser(user.ID, "project", project.ID); err != nil {
		t.Fatalf("AssignResourceToUser: %v", err)
	}
	w = performConversationRequest(user, http.MethodPost, "/api/conversations", map[string]string{
		"title":     "allowed",
		"projectId": project.ID,
	}, handler.CreateConversation)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestCreateConversationPersistsRuntimeModeAndRejectsInvalidValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	handler := NewConversationHandler(db, zap.NewNop())

	w := performConversationRequest(user, http.MethodPost, "/api/conversations", map[string]interface{}{
		"title":               "container conversation",
		"runtimeMode":         database.ConversationRuntimeModeContainer,
		"workspacePersistent": true,
	}, handler.CreateConversation)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var created database.Conversation
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if created.RuntimeMode != database.ConversationRuntimeModeContainer {
		t.Fatalf("response runtimeMode = %q", created.RuntimeMode)
	}
	if !created.WorkspacePersistent {
		t.Fatal("response workspacePersistent is false")
	}
	stored, err := db.GetConversationLite(created.ID)
	if err != nil {
		t.Fatalf("GetConversationLite: %v", err)
	}
	if stored.RuntimeMode != database.ConversationRuntimeModeContainer {
		t.Fatalf("stored runtimeMode = %q", stored.RuntimeMode)
	}
	if !stored.WorkspacePersistent {
		t.Fatal("stored workspacePersistent is false")
	}

	w = performConversationRequest(user, http.MethodPost, "/api/conversations", map[string]string{
		"title":       "invalid",
		"runtimeMode": "docker",
	}, handler.CreateConversation)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want %d: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	w = performConversationRequest(user, http.MethodPost, "/api/conversations", map[string]interface{}{
		"title": "invalid host persistence", "runtimeMode": "host", "workspacePersistent": true,
	}, handler.CreateConversation)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("host persistence status = %d, want %d: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

type conversationRuntimeModeIdleRunner struct {
	busy bool
}

func (r conversationRuntimeModeIdleRunner) RunWhenConversationTaskIdle(_ string, fn func() error) error {
	if r.busy {
		return ErrTaskAlreadyRunning
	}
	return fn()
}

func TestSetConversationRuntimeModeOnlyWhenTaskIsIdle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerRolloutAuthorizer(func(string, string) (bool, bool) { return true, true })

	createdResponse := performConversationRequest(user, http.MethodPost, "/api/conversations", map[string]interface{}{
		"title":       "switchable",
		"runtimeMode": database.ConversationRuntimeModeHost,
	}, handler.CreateConversation)
	if createdResponse.Code != http.StatusOK {
		t.Fatalf("create status = %d: %s", createdResponse.Code, createdResponse.Body.String())
	}
	var conversation database.Conversation
	if err := json.Unmarshal(createdResponse.Body.Bytes(), &conversation); err != nil {
		t.Fatalf("decode conversation: %v", err)
	}

	handler.SetTaskIdleRunner(conversationRuntimeModeIdleRunner{})
	switchRequest := func(mode string) *httptest.ResponseRecorder {
		return performConversationRequest(user, http.MethodPut, "/api/conversations/"+conversation.ID+"/runtime-mode", map[string]interface{}{
			"runtimeMode": mode,
		}, func(c *gin.Context) {
			c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
			handler.SetConversationRuntimeMode(c)
		})
	}

	w := switchRequest(database.ConversationRuntimeModeContainer)
	if w.Code != http.StatusOK {
		t.Fatalf("switch status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
	stored, err := db.GetConversationLite(conversation.ID)
	if err != nil {
		t.Fatalf("GetConversationLite: %v", err)
	}
	if stored.RuntimeMode != database.ConversationRuntimeModeContainer {
		t.Fatalf("stored runtime mode = %q", stored.RuntimeMode)
	}
	binding, err := db.GetConversationWorkspaceBinding(context.Background(), conversation.ID)
	if err != nil || binding.Mode != database.ConversationWorkspaceModeDedicated || binding.Workspace == nil {
		t.Fatalf("first container switch workspace = %#v, %v", binding, err)
	}
	idlePolicy, err := db.GetConversationIdlePolicy(context.Background(), conversation.ID)
	if err != nil || idlePolicy.Action != database.ConversationIdleActionDelete || idlePolicy.TimeoutSeconds != 1800 {
		t.Fatalf("first container switch idle policy = %#v, %v", idlePolicy, err)
	}

	handler.SetTaskIdleRunner(conversationRuntimeModeIdleRunner{busy: true})
	w = switchRequest(database.ConversationRuntimeModeHost)
	if w.Code != http.StatusConflict {
		t.Fatalf("busy switch status = %d, want %d: %s", w.Code, http.StatusConflict, w.Body.String())
	}
	stored, err = db.GetConversationLite(conversation.ID)
	if err != nil {
		t.Fatalf("GetConversationLite after conflict: %v", err)
	}
	if stored.RuntimeMode != database.ConversationRuntimeModeContainer {
		t.Fatalf("busy switch changed runtime mode to %q", stored.RuntimeMode)
	}
}

func TestSetConversationRuntimeModeEnforcesRolloutAndOwnership(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, owner := setupConversationRBACTest(t)
	handler := NewConversationHandler(db, zap.NewNop())

	createdResponse := performConversationRequest(owner, http.MethodPost, "/api/conversations", map[string]interface{}{
		"title": "owned",
	}, handler.CreateConversation)
	var conversation database.Conversation
	if err := json.Unmarshal(createdResponse.Body.Bytes(), &conversation); err != nil {
		t.Fatalf("decode conversation: %v", err)
	}

	handler.SetContainerRolloutAuthorizer(func(string, string) (bool, bool) { return true, false })
	request := func(user *database.RBACUser) *httptest.ResponseRecorder {
		return performConversationRequest(user, http.MethodPut, "/api/conversations/"+conversation.ID+"/runtime-mode", map[string]interface{}{
			"runtimeMode": database.ConversationRuntimeModeContainer,
		}, func(c *gin.Context) {
			c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
			handler.SetConversationRuntimeMode(c)
		})
	}
	w := request(owner)
	if w.Code != http.StatusForbidden {
		t.Fatalf("rollout status = %d, want %d: %s", w.Code, http.StatusForbidden, w.Body.String())
	}

	other, err := db.CreateRBACUser("operator2", "Operator Two", "hash", true, nil)
	if err != nil {
		t.Fatalf("CreateRBACUser: %v", err)
	}
	w = request(other)
	if w.Code != http.StatusForbidden {
		t.Fatalf("ownership status = %d, want %d: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestCreateConversationSelectsBoundaryPolicyWithIndependentRBAC(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	policy, err := db.CreateBoundaryPolicy(context.Background(), database.BoundaryPolicy{
		Name: "assigned boundary", OwnerUserID: "another-owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewConversationHandler(db, zap.NewNop())
	request := map[string]interface{}{
		"title": "bounded", "runtimeMode": database.ConversationRuntimeModeContainer,
		"boundaryPolicyId": policy.ID,
	}
	perform := func(session security.Session, body interface{}) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/conversations", bytes.NewReader(payload))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Set(security.ContextSessionKey, session)
		handler.CreateConversation(c)
		return w
	}
	baseSession := security.Session{
		UserID: user.ID, Username: user.Username, Scope: database.RBACScopeAssigned,
		Permissions: map[string]bool{"chat:write": true},
		PermissionScopes: map[string]string{
			"chat:write": database.RBACScopeAssigned, "boundary:read": database.RBACScopeOwn,
		},
	}
	response := perform(baseSession, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing boundary permission status = %d: %s", response.Code, response.Body.String())
	}
	baseSession.Permissions["boundary:read"] = true
	response = perform(baseSession, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unassigned policy status = %d: %s", response.Code, response.Body.String())
	}
	if _, err := db.Exec(`UPDATE boundary_policies SET owner_user_id = ? WHERE id = ?`, user.ID, policy.ID); err != nil {
		t.Fatal(err)
	}
	response = perform(baseSession, request)
	if response.Code != http.StatusOK {
		t.Fatalf("owned policy status = %d: %s", response.Code, response.Body.String())
	}
	var created database.Conversation
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	var selectedPolicyID string
	if err := db.QueryRow(`SELECT policy_id FROM conversation_boundary_policy_selections WHERE conversation_id = ?`, created.ID).Scan(&selectedPolicyID); err != nil {
		t.Fatal(err)
	}
	if selectedPolicyID != policy.ID {
		t.Fatalf("selected policy = %q", selectedPolicyID)
	}
	if _, err := db.GetConversationBoundarySnapshot(context.Background(), created.ID); !errors.Is(err, database.ErrConversationBoundarySnapshotNotFound) {
		t.Fatalf("snapshot was bound before first start: %v", err)
	}
	hostRequest := map[string]interface{}{
		"title": "invalid host", "runtimeMode": database.ConversationRuntimeModeHost,
		"boundaryPolicyId": policy.ID,
	}
	response = perform(baseSession, hostRequest)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("host policy status = %d: %s", response.Code, response.Body.String())
	}
}

func TestSetConversationProjectRequiresProjectAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	project, err := db.CreateProject(&database.Project{Name: "hidden"})
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	conv, err := db.CreateConversation("owned", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	if err := db.SetResourceOwner("conversation", conv.ID, user.ID); err != nil {
		t.Fatalf("SetResourceOwner: %v", err)
	}
	if err := db.AssignResourceToUser(user.ID, "conversation", conv.ID); err != nil {
		t.Fatalf("AssignResourceToUser conversation: %v", err)
	}
	handler := NewConversationHandler(db, zap.NewNop())

	w := performConversationRequest(user, http.MethodPut, "/api/conversations/"+conv.ID+"/project", map[string]string{
		"projectId": project.ID,
	}, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conv.ID}}
		handler.SetConversationProject(c)
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusForbidden, w.Body.String())
	}

	if err := db.AssignResourceToUser(user.ID, "project", project.ID); err != nil {
		t.Fatalf("AssignResourceToUser project: %v", err)
	}
	w = performConversationRequest(user, http.MethodPut, "/api/conversations/"+conv.ID+"/project", map[string]string{
		"projectId": project.ID,
	}, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conv.ID}}
		handler.SetConversationProject(c)
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func setupConversationRBACTest(t *testing.T) (*database.DB, *database.RBACUser) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "conversation-rbac.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.CreateRBACUser("operator1", "Operator One", "hash", true, nil)
	if err != nil {
		t.Fatalf("CreateRBACUser: %v", err)
	}
	return db, user
}

func performConversationRequest(user *database.RBACUser, method, path string, body interface{}, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, path, bytes.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set(security.ContextSessionKey, security.Session{
		UserID:      user.ID,
		Username:    user.Username,
		Permissions: map[string]bool{"chat:write": true},
		Scope:       database.RBACScopeAssigned,
	})
	handler(c)
	return w
}
