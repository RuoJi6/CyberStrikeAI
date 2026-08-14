package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestApplyConfigReregistersASMToolsAfterClear(t *testing.T) {
	cfg := config.Default()
	cfg.Security.ToolsDir = ""
	server := mcp.NewServer(zap.NewNop())
	executor := security.NewExecutor(&cfg.Security, server, zap.NewNop())
	handler := NewConfigHandler("", cfg, server, executor, nil, nil, nil, zap.NewNop())

	registrations := 0
	handler.SetASMToolRegistrar(func() error {
		registrations++
		server.RegisterTool(mcp.Tool{
			Name: builtin.ToolASMGetTask, Description: "test", InputSchema: map[string]interface{}{"type": "object"},
		}, func(context.Context, map[string]interface{}) (*mcp.ToolResult, error) {
			return &mcp.ToolResult{}, nil
		})
		return nil
	})

	gin.SetMode(gin.TestMode)
	for apply := 1; apply <= 2; apply++ {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/api/config/apply", nil)
		handler.ApplyConfig(ctx)
		if recorder.Code != http.StatusOK {
			t.Fatalf("apply %d failed: status=%d body=%s", apply, recorder.Code, recorder.Body.String())
		}
		found := false
		for _, tool := range server.GetAllTools() {
			if tool.Name == builtin.ToolASMGetTask {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("ASM tool missing after config apply %d", apply)
		}
	}
	if registrations != 2 {
		t.Fatalf("expected ASM registrar on every apply, got %d calls", registrations)
	}
}
