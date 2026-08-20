package handler

import (
	"context"
	"errors"
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
	containerGateReady          = "ready"
	containerGateFailed         = "failed"
	containerGateUnavailable    = "unavailable"
	containerGateBackendPending = "execution_backend_pending"

	containerInitializationPollInterval = 500 * time.Millisecond
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

	return h.conversationContainerExecutionGateFromRecord(record)
}

func (h *AgentHandler) conversationContainerExecutionGateFromRecord(record containerruntime.InitializationRecord) *conversationContainerExecutionGate {
	gate := &conversationContainerExecutionGate{
		Record:    record,
		HasRecord: strings.TrimSpace(record.ConversationID) != "",
		Retryable: true,
	}
	switch {
	case record.Status == containerruntime.InitializationFailed || record.ReadinessStatus == containerruntime.ReadinessFailed:
		gate.State = containerGateFailed
	case record.Status == containerruntime.InitializationCreated &&
		(record.ReadinessStatus == containerruntime.ReadinessReady || record.ReadinessStatus == containerruntime.ReadinessNotRequired):
		if h.containerExecutionReady {
			return nil
		}
		gate.State = containerGateBackendPending
		gate.Retryable = false
	default:
		gate.State = containerGateInitializing
	}
	return gate
}

func conversationContainerExecutionPayload(prep *multiAgentPrepared, gate *conversationContainerExecutionGate) map[string]interface{} {
	payload := map[string]interface{}{
		"conversationId": prep.ConversationID,
		"messageId":      prep.AssistantMessageID,
		"runtimeMode":    database.ConversationRuntimeModeContainer,
		"state":          gate.State,
		"retryable":      gate.Retryable,
	}
	if gate.HasRecord {
		payload["runtimeId"] = gate.Record.RuntimeID
		payload["status"] = gate.Record.Status
		payload["readinessStatus"] = gate.Record.ReadinessStatus
		payload["attempt"] = gate.Record.Attempt
		payload["requestedAt"] = gate.Record.RequestedAt
		payload["startedAt"] = gate.Record.StartedAt
		payload["updatedAt"] = gate.Record.UpdatedAt
		if gate.Record.LastError != "" {
			payload["lastError"] = gate.Record.LastError
		}
		if gate.Record.ReadinessError != "" {
			payload["readinessError"] = gate.Record.ReadinessError
		}
	}
	return payload
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
	payload := conversationContainerExecutionPayload(prep, gate)
	payload["deferred"] = true
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

func (h *AgentHandler) persistConversationContainerInitializationDetail(prep *multiAgentPrepared, message string, payload map[string]interface{}) {
	if h.db == nil || prep == nil || prep.AssistantMessageID == "" {
		return
	}
	if err := h.db.AddProcessDetail(prep.AssistantMessageID, prep.ConversationID, "container_initialization", message, payload); err != nil && h.logger != nil {
		h.logger.Warn("保存容器初始化进度失败", zap.String("conversationId", prep.ConversationID), zap.Error(err))
	}
}

// awaitConversationContainerExecution keeps the original chat turn alive while
// the durable initializer creates and validates its container. The caller must
// register the detached Agent task before entering this function so refreshes
// and page switches cannot cancel the wait; only CancelTask cancels taskCtx.
// It returns true when the turn reached a terminal state and the caller should
// stop dispatching the original request.
func (h *AgentHandler) awaitConversationContainerExecution(
	taskCtx context.Context,
	prep *multiAgentPrepared,
	sendEvent func(string, string, interface{}),
) (terminal bool, taskStatus string) {
	if prep == nil || prep.ContainerExecutionGate == nil {
		return false, ""
	}
	if prep.ContainerExecutionGate.State != containerGateInitializing {
		message, payload := h.finalizeConversationContainerExecutionGate(prep)
		sendEvent("container_initialization", message, payload)
		sendEvent("done", "", map[string]interface{}{
			"conversationId":          prep.ConversationID,
			"containerInitialization": true,
			"deferred":                true,
		})
		return true, "failed"
	}

	h.tasks.UpdateTaskStatus(prep.ConversationID, containerGateInitializing)
	waitingMessage := "对话容器正在启动；容器就绪后将自动继续当前请求。刷新或切换页面不会中断，可点击“停止任务”取消。"
	waitingPayload := conversationContainerExecutionPayload(prep, prep.ContainerExecutionGate)
	waitingPayload["deferred"] = false
	waitingPayload["waiting"] = true
	h.persistConversationContainerInitializationDetail(prep, waitingMessage, waitingPayload)
	sendEvent("container_initialization", waitingMessage, waitingPayload)

	finishCancelled := func() (bool, string) {
		status := "cancelled"
		h.tasks.UpdateTaskStatus(prep.ConversationID, status)
		message := "任务已被用户取消，容器初始化后的原请求不会继续执行。"
		if h.db != nil && prep.AssistantMessageID != "" {
			_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", message, time.Now(), prep.AssistantMessageID)
			_ = h.db.AddProcessDetail(prep.AssistantMessageID, prep.ConversationID, "cancelled", message, nil)
		}
		sendEvent("cancelled", message, map[string]interface{}{
			"conversationId": prep.ConversationID,
			"messageId":      prep.AssistantMessageID,
		})
		sendEvent("done", "", map[string]interface{}{"conversationId": prep.ConversationID})
		return true, status
	}
	finishTimeout := func() (bool, string) {
		status := "timeout"
		h.tasks.UpdateTaskStatus(prep.ConversationID, status)
		message := "等待对话容器启动超时，原请求已终止。"
		if h.db != nil && prep.AssistantMessageID != "" {
			_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", message, time.Now(), prep.AssistantMessageID)
			_ = h.db.AddProcessDetail(prep.AssistantMessageID, prep.ConversationID, "timeout", message, nil)
		}
		sendEvent("error", message, map[string]interface{}{
			"conversationId": prep.ConversationID,
			"messageId":      prep.AssistantMessageID,
			"errorType":      "timeout",
		})
		sendEvent("done", "", map[string]interface{}{"conversationId": prep.ConversationID})
		return true, status
	}

	ticker := time.NewTicker(containerInitializationPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-taskCtx.Done():
			if errors.Is(context.Cause(taskCtx), ErrTaskCancelled) {
				return finishCancelled()
			}
			return finishTimeout()
		case <-ticker.C:
			record, err := h.containerInitializer.EnsureConversationAsync(taskCtx, prep.ConversationID)
			if err != nil {
				if taskCtx.Err() != nil {
					if errors.Is(context.Cause(taskCtx), ErrTaskCancelled) {
						return finishCancelled()
					}
					return finishTimeout()
				}
				prep.ContainerExecutionGate = &conversationContainerExecutionGate{
					State:     containerGateFailed,
					Record:    record,
					HasRecord: strings.TrimSpace(record.ConversationID) != "",
					Retryable: true,
				}
				message, payload := h.finalizeConversationContainerExecutionGate(prep)
				payload["error"] = err.Error()
				sendEvent("container_initialization", message, payload)
				sendEvent("done", "", map[string]interface{}{"conversationId": prep.ConversationID})
				h.tasks.UpdateTaskStatus(prep.ConversationID, "failed")
				return true, "failed"
			}

			gate := h.conversationContainerExecutionGateFromRecord(record)
			if gate != nil && gate.State == containerGateInitializing {
				prep.ContainerExecutionGate = gate
				continue
			}
			if gate != nil {
				prep.ContainerExecutionGate = gate
				message, payload := h.finalizeConversationContainerExecutionGate(prep)
				sendEvent("container_initialization", message, payload)
				sendEvent("done", "", map[string]interface{}{"conversationId": prep.ConversationID})
				h.tasks.UpdateTaskStatus(prep.ConversationID, "failed")
				return true, "failed"
			}

			conversation, conversationErr := h.db.GetConversation(prep.ConversationID)
			if conversationErr != nil {
				prep.ContainerExecutionGate = &conversationContainerExecutionGate{
					State: containerGateFailed, Record: record, HasRecord: true, Retryable: true,
				}
				message, payload := h.finalizeConversationContainerExecutionGate(prep)
				payload["error"] = conversationErr.Error()
				sendEvent("container_initialization", message, payload)
				sendEvent("done", "", map[string]interface{}{"conversationId": prep.ConversationID})
				h.tasks.UpdateTaskStatus(prep.ConversationID, "failed")
				return true, "failed"
			}
			if syncErr := h.syncConversationUploadsToWorkspace(taskCtx, conversation); syncErr != nil {
				prep.ContainerExecutionGate = &conversationContainerExecutionGate{
					State: containerGateFailed, Record: record, HasRecord: true, Retryable: true,
				}
				message, payload := h.finalizeConversationContainerExecutionGate(prep)
				payload["error"] = syncErr.Error()
				sendEvent("container_initialization", message, payload)
				sendEvent("done", "", map[string]interface{}{"conversationId": prep.ConversationID})
				h.tasks.UpdateTaskStatus(prep.ConversationID, "failed")
				return true, "failed"
			}

			readyGate := &conversationContainerExecutionGate{
				State: containerGateReady, Record: record, HasRecord: true, Retryable: false,
			}
			readyMessage := "对话容器已就绪，正在继续执行原请求。"
			readyPayload := conversationContainerExecutionPayload(prep, readyGate)
			readyPayload["deferred"] = false
			readyPayload["continuing"] = true
			h.persistConversationContainerInitializationDetail(prep, readyMessage, readyPayload)
			sendEvent("container_initialization", readyMessage, readyPayload)
			h.tasks.UpdateTaskStatus(prep.ConversationID, "running")
			prep.ContainerExecutionGate = nil
			return false, ""
		}
	}
}

func (h *AgentHandler) finishConversationContainerExecutionStream(prep *multiAgentPrepared, sendEvent func(string, string, interface{})) bool {
	if prep == nil || prep.ContainerExecutionGate == nil {
		return false
	}
	if prep.ContainerExecutionGate.State == containerGateInitializing {
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
