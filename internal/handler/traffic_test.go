package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/traffic"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestTrafficConversationOptionsUseTrafficReadScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-options.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, _ := db.CreateConversation("searchable evidence", database.ConversationCreateMeta{})
	if _, err := db.Exec(`UPDATE conversations SET owner_user_id = ? WHERE id = ?`, "owner-a", conversation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateTrafficTransaction(context.Background(), &traffic.Transaction{
		ConversationID: conversation.ID, RuntimeMode: traffic.RuntimeModeContainer,
		CaptureCoverage: traffic.CaptureCoverageEnforced, Scheme: "https", Host: "example.test", Port: 443,
		Method: "GET", Path: "/", StartedAt: time.Now().UTC(),
	}, nil); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/traffic-transactions/conversations", nil)
	c.Set(security.ContextSessionKey, security.Session{UserID: "owner-a", Scope: database.RBACScopeOwn})
	NewTrafficHandler(db, zap.NewNop()).Conversations(c)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), conversation.ID) || !strings.Contains(recorder.Body.String(), "searchable evidence") {
		t.Fatalf("conversation options = %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("conversation option headers = %#v", recorder.Header())
	}
}
