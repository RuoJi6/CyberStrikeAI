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

func setTestContainerExecutionPreparer(h *AgentHandler) {
	h.SetConversationContainerExecutionPreparer(ConversationContainerExecutionPreparerFunc(func(_ context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
		now := time.Now()
		return containerruntime.InitializationRecord{
			ConversationID:     conversationID,
			RuntimeID:          containerruntime.RuntimeID("conversation-" + conversationID),
			Status:             containerruntime.InitializationCreated,
			ReadinessStatus:    containerruntime.ReadinessReady,
			RuntimeStatus:      containerruntime.StatusRunning,
			LifecycleOperation: containerruntime.LifecycleOperationStart,
			LifecycleState:     containerruntime.LifecycleIdle,
			UpdatedAt:          now,
		}, nil
	}))
}

func containerGateRequest(t *testing.T, user *database.RBACUser, body map[string]interface{}, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	return containerGateRequestWithContext(t, context.Background(), user, body, handler)
}

func containerGateRequestWithContext(t *testing.T, requestContext context.Context, user *database.RBACUser, body map[string]interface{}, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/eino-agent/stream", bytes.NewReader(payload)).WithContext(requestContext)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set(security.ContextSessionKey, security.Session{
		UserID:      user.ID,
		Scope:       database.RBACScopeAssigned,
		Permissions: map[string]bool{"chat:write": true},
	})
	handler(c)
	return w
}

func TestContainerConversationInitializationSurvivesDisconnectAndContinuesOriginalRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	taskBus := NewTaskEventBus()
	tasks := NewAgentTaskManager()
	tasks.SetTaskEventBus(taskBus)
	h := &AgentHandler{db: db, logger: zap.NewNop(), tasks: tasks, taskEventBus: taskBus}
	h.SetConversationContainerExecutionReady(true)
	setTestContainerExecutionPreparer(h)
	scheduled := make(chan string, 1)
	allowReady := make(chan struct{})
	callCount := 0
	h.SetConversationContainerInitializationScheduler(ConversationContainerInitializationSchedulerFunc(func(_ context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
		callCount++
		if callCount == 1 {
			scheduled <- conversationID
		}
		status := containerruntime.InitializationQueued
		readiness := containerruntime.ReadinessPending
		select {
		case <-allowReady:
			status = containerruntime.InitializationCreated
			readiness = containerruntime.ReadinessReady
		default:
		}
		now := time.Now()
		return containerruntime.InitializationRecord{
			ConversationID:  conversationID,
			RuntimeID:       containerruntime.RuntimeID("conversation-" + conversationID),
			Status:          status,
			ReadinessStatus: readiness,
			RequestedAt:     now,
			UpdatedAt:       now,
		}, nil
	}))

	requestContext, disconnect := context.WithCancel(context.Background())
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- containerGateRequestWithContext(t, requestContext, user, map[string]interface{}{
			"message":     "continue after initialization",
			"runtimeMode": database.ConversationRuntimeModeContainer,
		}, h.EinoSingleAgentLoopStream)
	}()

	var scheduledConversationID string
	select {
	case scheduledConversationID = <-scheduled:
	case <-time.After(2 * time.Second):
		t.Fatal("container initialization was not scheduled")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		task := tasks.GetTask(scheduledConversationID)
		if task != nil && task.Status == containerGateInitializing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("task did not enter initializing state: %#v", task)
		}
		time.Sleep(10 * time.Millisecond)
	}

	sub, replay := taskBus.Subscribe(scheduledConversationID)
	defer taskBus.Unsubscribe(scheduledConversationID, sub)
	disconnect()
	close(allowReady)
	var replayBody bytes.Buffer
	replayDone := make(chan struct{})
	go func() {
		for chunk := range replay {
			replayBody.Write(chunk)
		}
		close(replayDone)
	}()

	var w *httptest.ResponseRecorder
	select {
	case w = <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("detached container request did not continue after readiness")
	}
	select {
	case <-replayDone:
	case <-time.After(time.Second):
		t.Fatal("task replay stream did not close after terminal event")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	initialBody := w.Body.String()
	for _, want := range []string{`"type":"conversation"`, `"type":"message_saved"`, `"type":"container_initialization"`, `"state":"initializing"`, `"deferred":false`, `"waiting":true`} {
		if !strings.Contains(initialBody, want) {
			t.Fatalf("initial SSE missing %s: %s", want, initialBody)
		}
	}
	if strings.Contains(initialBody, "请在容器就绪后重试") {
		t.Fatalf("initial SSE still asks the user to retry: %s", initialBody)
	}
	replayed := replayBody.String()
	for _, want := range []string{`"type":"container_initialization"`, `"state":"ready"`, `"continuing":true`, `"type":"error"`, `"type":"done"`} {
		if !strings.Contains(replayed, want) {
			t.Fatalf("replayed SSE missing %s after request disconnect: %s", want, replayed)
		}
	}
	if task := tasks.GetTask(scheduledConversationID); task != nil {
		t.Fatalf("completed detached task remained active: %#v", task)
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
	details, err := db.GetProcessDetails(messages[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	detailStates := make([]string, 0, len(details))
	for _, detail := range details {
		if detail.EventType == "container_initialization" {
			detailStates = append(detailStates, detail.Data)
		}
	}
	joinedDetails := strings.Join(detailStates, "\n")
	if !strings.Contains(joinedDetails, `"state":"initializing"`) || !strings.Contains(joinedDetails, `"state":"ready"`) {
		t.Fatalf("container initialization details were not durable: %s", joinedDetails)
	}
}

func TestContainerConversationStopCancelsInitializationAndOriginalRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	taskBus := NewTaskEventBus()
	tasks := NewAgentTaskManager()
	tasks.SetTaskEventBus(taskBus)
	h := &AgentHandler{db: db, logger: zap.NewNop(), tasks: tasks, taskEventBus: taskBus}
	h.SetConversationContainerExecutionReady(true)
	setTestContainerExecutionPreparer(h)
	scheduled := make(chan string, 1)
	h.SetConversationContainerInitializationScheduler(ConversationContainerInitializationSchedulerFunc(func(_ context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
		select {
		case scheduled <- conversationID:
		default:
		}
		now := time.Now()
		return containerruntime.InitializationRecord{
			ConversationID: conversationID, RuntimeID: containerruntime.RuntimeID("conversation-" + conversationID),
			Status: containerruntime.InitializationQueued, ReadinessStatus: containerruntime.ReadinessPending,
			RequestedAt: now, UpdatedAt: now,
		}, nil
	}))

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- containerGateRequest(t, user, map[string]interface{}{
			"message": "stop while starting", "runtimeMode": database.ConversationRuntimeModeContainer,
		}, h.EinoSingleAgentLoopStream)
	}()
	conversationID := <-scheduled
	deadline := time.Now().Add(2 * time.Second)
	for {
		task := tasks.GetTask(conversationID)
		if task != nil && task.Status == containerGateInitializing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("task did not enter initializing state: %#v", task)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cancelled, err := tasks.CancelTask(conversationID, ErrTaskCancelled); err != nil || !cancelled {
		t.Fatalf("CancelTask() cancelled=%v err=%v", cancelled, err)
	}

	var w *httptest.ResponseRecorder
	select {
	case w = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled initialization did not terminate")
	}
	body := w.Body.String()
	for _, want := range []string{`"state":"initializing"`, `"type":"cancelled"`, `"type":"done"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("cancel SSE missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, `"state":"ready"`) {
		t.Fatalf("cancelled request unexpectedly continued: %s", body)
	}
	if task := tasks.GetTask(conversationID); task != nil {
		t.Fatalf("cancelled task remained active: %#v", task)
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

func TestReadyContainerPassesGateOnlyAfterExecutionBackendWired(t *testing.T) {
	h := &AgentHandler{logger: zap.NewNop()}
	running := false
	h.SetConversationContainerInitializationScheduler(ConversationContainerInitializationSchedulerFunc(func(_ context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
		record := containerruntime.InitializationRecord{
			ConversationID:  conversationID,
			RuntimeID:       containerruntime.RuntimeID("conversation-" + conversationID),
			Status:          containerruntime.InitializationCreated,
			ReadinessStatus: containerruntime.ReadinessReady,
		}
		if running {
			record.RuntimeStatus = containerruntime.StatusRunning
			record.LifecycleState = containerruntime.LifecycleIdle
		}
		return record, nil
	}))
	conversation := &database.Conversation{ID: "conversation-ready", RuntimeMode: database.ConversationRuntimeModeContainer}
	if gate := h.prepareConversationContainerExecutionGate(context.Background(), conversation); gate == nil || gate.State != containerGateBackendPending {
		t.Fatalf("unwired ready gate = %#v", gate)
	}
	h.SetConversationContainerExecutionReady(true)
	setTestContainerExecutionPreparer(h)
	if gate := h.prepareConversationContainerExecutionGate(context.Background(), conversation); gate == nil || gate.State != containerGateInitializing {
		t.Fatalf("wired stopped container should enter explicit startup phase: %#v", gate)
	}
	running = true
	if gate := h.prepareConversationContainerExecutionGate(context.Background(), conversation); gate != nil {
		t.Fatalf("already-running ready container remained gated: %#v", gate)
	}
}
