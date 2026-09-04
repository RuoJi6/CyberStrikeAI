package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type failingAggregationController struct {
	calls int
}

func (controller *failingAggregationController) ApplyConversationAggregationSetting(context.Context, string, bool, string) error {
	controller.calls++
	if controller.calls == 1 {
		return errors.New("injected apply failure")
	}
	return nil
}

func (*failingAggregationController) RefreshConversationAggregation(context.Context) error {
	return nil
}

func TestConversationEgressAuditSettingHandlerGetsAndUpdatesContainerConversation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "conversation-egress-audit.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conversation, err := db.CreateConversation("audit toggle", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewConversationHandler(db, zap.NewNop())

	getRecorder := httptest.NewRecorder()
	getContext, _ := gin.CreateTestContext(getRecorder)
	getContext.Request = httptest.NewRequest(http.MethodGet, "/api/conversations/"+conversation.ID+"/egress-audit", nil)
	getContext.Params = gin.Params{{Key: "id", Value: conversation.ID}}
	getContext.Set(security.ContextSessionKey, security.Session{UserID: "admin", Username: "admin", Scope: database.RBACScopeAll})
	handler.GetConversationEgressAuditSetting(getContext)
	if getRecorder.Code != http.StatusOK || !strings.Contains(getRecorder.Body.String(), `"enabled":true`) || !strings.Contains(getRecorder.Body.String(), `"aggregationMode":"tools"`) {
		t.Fatalf("get setting = %d %s", getRecorder.Code, getRecorder.Body.String())
	}

	putRecorder := httptest.NewRecorder()
	putContext, _ := gin.CreateTestContext(putRecorder)
	putContext.Request = httptest.NewRequest(http.MethodPut, "/api/conversations/"+conversation.ID+"/egress-audit", strings.NewReader(`{"enabled":false}`))
	putContext.Request.Header.Set("Content-Type", "application/json")
	putContext.Params = gin.Params{{Key: "id", Value: conversation.ID}}
	putContext.Set(security.ContextSessionKey, security.Session{UserID: "admin", Username: "admin", Scope: database.RBACScopeAll})
	handler.UpdateConversationEgressAuditSetting(putContext)
	if putRecorder.Code != http.StatusOK || !strings.Contains(putRecorder.Body.String(), `"enabled":false`) {
		t.Fatalf("put setting = %d %s", putRecorder.Code, putRecorder.Body.String())
	}
	if enabled, err := db.GetConversationEgressAuditEnabled(t.Context(), conversation.ID); err != nil || enabled {
		t.Fatalf("stored setting = %v, %v", enabled, err)
	}

	fullRecorder := httptest.NewRecorder()
	fullContext, _ := gin.CreateTestContext(fullRecorder)
	fullContext.Request = httptest.NewRequest(http.MethodPut, "/api/conversations/"+conversation.ID+"/egress-audit", strings.NewReader(`{"mode":"full"}`))
	fullContext.Request.Header.Set("Content-Type", "application/json")
	fullContext.Params = gin.Params{{Key: "id", Value: conversation.ID}}
	fullContext.Set(security.ContextSessionKey, security.Session{UserID: "admin", Username: "admin", Scope: database.RBACScopeAll})
	handler.UpdateConversationEgressAuditSetting(fullContext)
	if fullRecorder.Code != http.StatusOK || !strings.Contains(fullRecorder.Body.String(), `"mode":"full"`) {
		t.Fatalf("put full setting = %d %s", fullRecorder.Code, fullRecorder.Body.String())
	}
	setting, err := db.GetConversationEgressAuditSetting(t.Context(), conversation.ID)
	if err != nil || !setting.Enabled || setting.Mode != database.EgressAuditModeFull || setting.AggregationMode != database.EgressAggregationModeNone {
		t.Fatalf("stored full setting = %#v, %v", setting, err)
	}
}

func TestConversationEgressAggregationSupportsHostAndRejectsLegacyConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "host-egress-aggregation.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conversation, err := db.CreateConversation("host aggregation", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeHost})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewConversationHandler(db, zap.NewNop())
	request := func(body string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/api/conversations/"+conversation.ID+"/egress-audit", strings.NewReader(body))
		ctx.Request.Header.Set("Content-Type", "application/json")
		ctx.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		ctx.Set(security.ContextSessionKey, security.Session{UserID: "admin", Scope: database.RBACScopeAll})
		handler.UpdateConversationEgressAuditSetting(ctx)
		return recorder
	}
	if recorder := request(`{"enabled":true,"aggregationMode":"all"}`); recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"aggregationMode":"all"`) {
		t.Fatalf("host aggregation update = %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := request(`{"mode":"full","aggregationMode":"tools"}`); recorder.Code != http.StatusBadRequest {
		t.Fatalf("conflicting compatibility fields = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestConversationEgressAggregationApplyFailureKeepsStoredSetting(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "aggregation-rollback.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conversation, err := db.CreateConversation("rollback", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewConversationHandler(db, zap.NewNop())
	controller := &failingAggregationController{}
	handler.SetEgressAggregationController(controller)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/conversations/"+conversation.ID+"/egress-audit", strings.NewReader(`{"aggregationMode":"none"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: conversation.ID}}
	ctx.Set(security.ContextSessionKey, security.Session{UserID: "admin", Scope: database.RBACScopeAll})
	handler.UpdateConversationEgressAuditSetting(ctx)
	if recorder.Code != http.StatusInternalServerError || controller.calls != 2 {
		t.Fatalf("failed apply response = %d %s, calls=%d", recorder.Code, recorder.Body.String(), controller.calls)
	}
	setting, err := db.GetConversationEgressAuditSetting(context.Background(), conversation.ID)
	if err != nil || setting.AggregationMode != database.EgressAggregationModeTools {
		t.Fatalf("setting changed after failed apply: %#v, %v", setting, err)
	}
}
