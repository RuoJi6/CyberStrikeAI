package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"cyberstrike-ai/internal/database"
	containerruntime "cyberstrike-ai/internal/runtime/container"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	containerGateInitializing   = "initializing"
	containerGateFailed         = "failed"
	containerGateUnavailable    = "unavailable"
	containerGateBackendPending = "execution_backend_pending"
)

// ConversationContainerInitializationScheduler is the narrow chat-to-runtime
// boundary. The app supplies a function that builds a trusted RuntimeSpec and
// invokes the stage-1 durable initializer; handlers never construct Docker
// commands or accept image/runtime fields from the request.
type ConversationContainerInitializationScheduler interface {
	EnsureConversationAsync(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error)
}

type ConversationContainerInitializationSchedulerFunc func(context.Context, string) (containerruntime.InitializationRecord, error)

func (f ConversationContainerInitializationSchedulerFunc) EnsureConversationAsync(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
	return f(ctx, conversationID)
}

type conversationContainerExecutionGate struct {
	State     string
	Record    containerruntime.InitializationRecord
	HasRecord bool
	Retryable bool
}

func (h *AgentHandler) prepareConversationContainerExecutionGate(ctx context.Context, conversation *database.Conversation) *conversationContainerExecutionGate {
	if conversation == nil || conversation.RuntimeMode != database.ConversationRuntimeModeContainer {
		return nil
	}
	if h.containerInitializer == nil {
		return &conversationContainerExecutionGate{State: containerGateUnavailable, Retryable: true}
	}
	record, err := h.containerInitializer.EnsureConversationAsync(ctx, conversation.ID)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("容器模式首次执行无法加入后台初始化队列",
				zap.String("conversationId", conversation.ID),
				zap.Error(err),
			)
		}
		return &conversationContainerExecutionGate{
			State:     containerGateFailed,
			Record:    record,
			HasRecord: strings.TrimSpace(record.ConversationID) != "",
			Retryable: true,
		}
	}

	gate := &conversationContainerExecutionGate{Record: record, HasRecord: true, Retryable: true}
	switch {
	case record.Status == containerruntime.InitializationFailed || record.ReadinessStatus == containerruntime.ReadinessFailed:
		gate.State = containerGateFailed
	case record.Status == containerruntime.InitializationCreated &&
		(record.ReadinessStatus == containerruntime.ReadinessReady || record.ReadinessStatus == containerruntime.ReadinessNotRequired):
		// Stage 2 item 2 only establishes fail-closed initialization gating.
		// Item 3 will install the container ExecutionBackend and remove this gate.
		gate.State = containerGateBackendPending
		gate.Retryable = false
	default:
		gate.State = containerGateInitializing
	}
	return gate
}

func containerExecutionGateMessage(gate *conversationContainerExecutionGate) string {
	if gate == nil {
		return ""
	}
	switch gate.State {
	case containerGateInitializing:
		return "容器初始化已在后台启动。当前请求未执行，也不会回退到宿主机；请在容器就绪后重试。"
	case containerGateBackendPending:
		return "对话容器已就绪，但容器命令执行后端尚未接入。当前请求未执行，也不会回退到宿主机。"
	case containerGateFailed:
		return "对话容器初始化失败。当前请求未执行，也不会回退到宿主机；请在容器管理中重试或查看失败原因。"
	default:
		return "容器运行时当前不可用。当前请求未执行，也不会回退到宿主机。"
	}
}

func containerExecutionGateHTTPStatus(gate *conversationContainerExecutionGate) int {
	if gate != nil && gate.State == containerGateInitializing {
		return http.StatusAccepted
	}
	if gate != nil && gate.State == containerGateBackendPending {
		return http.StatusConflict
	}
	return http.StatusServiceUnavailable
}

func (h *AgentHandler) finalizeConversationContainerExecutionGate(prep *multiAgentPrepared) (string, map[string]interface{}) {
	gate := prep.ContainerExecutionGate
	message := containerExecutionGateMessage(gate)
	payload := map[string]interface{}{
		"conversationId": prep.ConversationID,
		"messageId":      prep.AssistantMessageID,
		"runtimeMode":    database.ConversationRuntimeModeContainer,
		"state":          gate.State,
		"retryable":      gate.Retryable,
		"deferred":       true,
	}
	if gate.HasRecord {
		payload["runtimeId"] = gate.Record.RuntimeID
		payload["status"] = gate.Record.Status
		payload["readinessStatus"] = gate.Record.ReadinessStatus
		payload["attempt"] = gate.Record.Attempt
		payload["updatedAt"] = gate.Record.UpdatedAt
	}
	if h.db != nil && prep.AssistantMessageID != "" {
		if _, err := h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", message, time.Now(), prep.AssistantMessageID); err != nil && h.logger != nil {
			h.logger.Warn("保存容器初始化门控消息失败", zap.String("conversationId", prep.ConversationID), zap.Error(err))
		}
		if err := h.db.AddProcessDetail(prep.AssistantMessageID, prep.ConversationID, "container_initialization", message, payload); err != nil && h.logger != nil {
			h.logger.Warn("保存容器初始化门控详情失败", zap.String("conversationId", prep.ConversationID), zap.Error(err))
		}
	}
	return message, payload
}

func (h *AgentHandler) finishConversationContainerExecutionStream(prep *multiAgentPrepared, sendEvent func(string, string, interface{})) bool {
	if prep == nil || prep.ContainerExecutionGate == nil {
		return false
	}
	message, payload := h.finalizeConversationContainerExecutionGate(prep)
	sendEvent("container_initialization", message, payload)
	sendEvent("done", "", map[string]interface{}{
		"conversationId":          prep.ConversationID,
		"containerInitialization": true,
		"deferred":                true,
	})
	return true
}

func (h *AgentHandler) finishConversationContainerExecutionJSON(c *gin.Context, prep *multiAgentPrepared) bool {
	if prep == nil || prep.ContainerExecutionGate == nil {
		return false
	}
	message, payload := h.finalizeConversationContainerExecutionGate(prep)
	c.JSON(containerExecutionGateHTTPStatus(prep.ContainerExecutionGate), gin.H{
		"conversationId":          prep.ConversationID,
		"messageId":               prep.AssistantMessageID,
		"runtimeMode":             database.ConversationRuntimeModeContainer,
		"containerInitialization": payload,
		"deferred":                true,
		"message":                 message,
	})
	return true
}
