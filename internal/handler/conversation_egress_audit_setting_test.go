package handler

import (
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
	if getRecorder.Code != http.StatusOK || !strings.Contains(getRecorder.Body.String(), `"enabled":true`) {
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
}
