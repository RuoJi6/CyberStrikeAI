package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func containerGateRequest(t *testing.T, user *database.RBACUser, body map[string]interface{}, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/eino-agent/stream", bytes.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set(security.ContextSessionKey, security.Session{
		UserID:      user.ID,
		Scope:       database.RBACScopeAssigned,
		Permissions: map[string]bool{"chat:write": true},
	})
	handler(c)
	return w
}

func TestContainerConversationQueuesInitializationAndReturnsDeferredSSE(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	h := &AgentHandler{db: db, logger: zap.NewNop()}
	var scheduledConversationID string
	h.SetConversationContainerInitializationScheduler(ConversationContainerInitializationSchedulerFunc(func(_ context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
		scheduledConversationID = conversationID
		return containerruntime.InitializationRecord{
			ConversationID:  conversationID,
			RuntimeID:       containerruntime.RuntimeID("conversation-" + conversationID),
			Status:          containerruntime.InitializationQueued,
			ReadinessStatus: containerruntime.ReadinessPending,
			RequestedAt:     time.Now(),
			UpdatedAt:       time.Now(),
		}, nil
	}))

	w := containerGateRequest(t, user, map[string]interface{}{
		"message":     "initialize only",
		"runtimeMode": database.ConversationRuntimeModeContainer,
	}, h.EinoSingleAgentLoopStream)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{`"type":"conversation"`, `"type":"message_saved"`, `"type":"container_initialization"`, `"state":"initializing"`, `"deferred":true`, `"type":"done"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("SSE missing %s: %s", want, body)
		}
	}
	for _, forbidden := range []string{`"type":"progress"`, `"type":"tool_call"`, `"type":"response"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("SSE unexpectedly started Agent execution (%s): %s", forbidden, body)
		}
	}
	if scheduledConversationID == "" {
		t.Fatal("container initialization was not scheduled")
	}
	conversation, err := db.GetConversationLite(scheduledConversationID)
	if err != nil {
		t.Fatal(err)
	}
	if conversation.RuntimeMode != database.ConversationRuntimeModeContainer {
		t.Fatalf("runtime mode = %q", conversation.RuntimeMode)
	}
	messages, err := db.GetMessages(scheduledConversationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].Role != "user" || messages[1].Role != "assistant" {
		t.Fatalf("messages = %#v", messages)
	}
	if strings.Contains(messages[1].Content, "处理中") || !strings.Contains(messages[1].Content, "不会回退到宿主机") {
		t.Fatalf("assistant gate notice = %q", messages[1].Content)
	}
}

func TestContainerConversationFailsClosedWhenInitializerUnavailableOrReady(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("unavailable", func(t *testing.T) {
		db, user := setupConversationRBACTest(t)
		h := &AgentHandler{db: db, logger: zap.NewNop()}
		w := containerGateRequest(t, user, map[string]interface{}{
			"message":     "must not run on host",
			"runtimeMode": database.ConversationRuntimeModeContainer,
		}, h.EinoSingleAgentLoop)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"state":"unavailable"`) || !strings.Contains(w.Body.String(), "不会回退到宿主机") {
			t.Fatalf("response = %s", w.Body.String())
		}
	})

	t.Run("ready but backend pending", func(t *testing.T) {
		db, user := setupConversationRBACTest(t)
		h := &AgentHandler{db: db, logger: zap.NewNop()}
		h.SetConversationContainerInitializationScheduler(ConversationContainerInitializationSchedulerFunc(func(_ context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
			return containerruntime.InitializationRecord{
				ConversationID:  conversationID,
				RuntimeID:       containerruntime.RuntimeID("conversation-" + conversationID),
				Status:          containerruntime.InitializationCreated,
				ReadinessStatus: containerruntime.ReadinessReady,
				UpdatedAt:       time.Now(),
			}, nil
		}))
		w := containerGateRequest(t, user, map[string]interface{}{
			"message":     "still must not run on host",
			"runtimeMode": database.ConversationRuntimeModeContainer,
		}, h.EinoSingleAgentLoop)
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"state":"execution_backend_pending"`) || !strings.Contains(w.Body.String(), "不会回退到宿主机") {
			t.Fatalf("response = %s", w.Body.String())
		}
	})

	t.Run("queue error", func(t *testing.T) {
		db, user := setupConversationRBACTest(t)
		h := &AgentHandler{db: db, logger: zap.NewNop()}
		h.SetConversationContainerInitializationScheduler(ConversationContainerInitializationSchedulerFunc(func(_ context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
			return containerruntime.InitializationRecord{ConversationID: conversationID}, errors.New("synthetic queue failure")
		}))
		w := containerGateRequest(t, user, map[string]interface{}{
			"message":     "queue failure must not run",
			"runtimeMode": database.ConversationRuntimeModeContainer,
		}, h.EinoSingleAgentLoop)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"state":"failed"`) {
			t.Fatalf("response status=%d body=%s", w.Code, w.Body.String())
		}
	})
}

func TestRobotCannotBypassContainerInitializationGate(t *testing.T) {
	db, user := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("robot container", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", conversation.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(user.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}

	h := &AgentHandler{db: db, logger: zap.NewNop()}
	var scheduledConversationID string
	h.SetConversationContainerInitializationScheduler(ConversationContainerInitializationSchedulerFunc(func(_ context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
		scheduledConversationID = conversationID
		return containerruntime.InitializationRecord{
			ConversationID:  conversationID,
			RuntimeID:       containerruntime.RuntimeID("conversation-" + conversationID),
			Status:          containerruntime.InitializationQueued,
			ReadinessStatus: containerruntime.ReadinessPending,
			UpdatedAt:       time.Now(),
		}, nil
	}))
	principal := authctx.NewPrincipal(user.ID, user.Username, database.RBACScopeAssigned, map[string]bool{
		"agent:execute": true,
		"chat:read":     true,
		"chat:write":    true,
	})

	response, gotConversationID, err := h.ProcessMessageForRobot(
		context.Background(), "wecom", principal, conversation.ID, "must stay out of host", "", "eino_single",
	)
	if err != nil {
		t.Fatalf("ProcessMessageForRobot: %v", err)
	}
	if gotConversationID != conversation.ID || scheduledConversationID != conversation.ID {
		t.Fatalf("conversation=%q scheduled=%q", gotConversationID, scheduledConversationID)
	}
	if !strings.Contains(response, "不会回退到宿主机") {
		t.Fatalf("response = %q", response)
	}
	if h.tasks != nil && h.tasks.GetTask(conversation.ID) != nil {
		t.Fatal("robot container request unexpectedly started an Agent task")
	}
	messages, err := db.GetMessages(conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].Role != "user" || messages[1].Role != "assistant" {
		t.Fatalf("messages = %#v", messages)
	}
	if strings.Contains(messages[1].Content, "处理中") || !strings.Contains(messages[1].Content, "不会回退到宿主机") {
		t.Fatalf("assistant gate notice = %q", messages[1].Content)
	}
}
