package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"cyberstrike-ai/internal/audit"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func (h *ConversationHandler) StartConversationContainer(c *gin.Context) {
	h.runConversationContainerLifecycle(c, "start", "启动对话容器", h.containerLifecycleStart)
}

func (h *ConversationHandler) StopConversationContainer(c *gin.Context) {
	h.runConversationContainerLifecycle(c, "stop", "停止对话容器", h.containerLifecycleStop)
}

func (h *ConversationHandler) RebuildConversationContainer(c *gin.Context) {
	h.runConversationContainerLifecycle(c, "rebuild", "重建对话容器", h.containerLifecycleRebuild)
}

func (h *ConversationHandler) ReconcileConversationContainer(c *gin.Context) {
	h.runConversationContainerLifecycle(c, "reconcile", "对账对话容器状态", h.containerLifecycleReconcile)
}

func (h *ConversationHandler) DeleteConversationContainer(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	if h.containerLifecycle == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "容器生命周期服务未配置"})
		return
	}
	removeWorkspace := queryBoolean(c.Query("remove_workspace"))
	if err := h.containerLifecycle.Delete(c.Request.Context(), id, removeWorkspace); err != nil {
		h.writeContainerLifecycleError(c, id, "delete", err)
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "container", "delete", "删除对话容器", "conversation", id, map[string]interface{}{
			"remove_workspace": removeWorkspace,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"success":          true,
		"conversationId":   id,
		"containerDeleted": true,
		"workspaceDeleted": removeWorkspace,
	})
}

type conversationContainerLifecycleCall func(context.Context, string) (containerruntime.InitializationRecord, error)

func (h *ConversationHandler) runConversationContainerLifecycle(c *gin.Context, action, message string, call conversationContainerLifecycleCall) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	if h.containerLifecycle == nil || call == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "容器生命周期服务未配置"})
		return
	}
	record, err := call(c.Request.Context(), id)
	if err != nil {
		h.writeContainerLifecycleError(c, id, action, err)
		return
	}
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category:     "container",
			Action:       action,
			Result:       "success",
			ResourceType: "conversation",
			ResourceID:   id,
			Message:      message,
			Detail: map[string]interface{}{
				"runtime_status":  record.RuntimeStatus,
				"lifecycle_state": record.LifecycleState,
				"runtime_drift":   record.RuntimeDrift,
			},
		})
	}
	c.JSON(http.StatusOK, record)
}

func (h *ConversationHandler) authorizeConversationContainer(c *gin.Context) (string, bool) {
	id := strings.TrimSpace(c.Param("id"))
	session, ok := security.CurrentSession(c)
	if !ok || !h.db.UserCanAccessResource(session.UserID, session.Scope, "conversation", id) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该对话"})
		return "", false
	}
	if _, err := h.db.GetConversationLite(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return "", false
	}
	return id, true
}

func (h *ConversationHandler) containerLifecycleStart(ctx context.Context, id string) (containerruntime.InitializationRecord, error) {
	return h.containerLifecycle.Start(ctx, id)
}

func (h *ConversationHandler) containerLifecycleStop(ctx context.Context, id string) (containerruntime.InitializationRecord, error) {
	return h.containerLifecycle.Stop(ctx, id)
}

func (h *ConversationHandler) containerLifecycleRebuild(ctx context.Context, id string) (containerruntime.InitializationRecord, error) {
	return h.containerLifecycle.Rebuild(ctx, id)
}

func (h *ConversationHandler) containerLifecycleReconcile(ctx context.Context, id string) (containerruntime.InitializationRecord, error) {
	return h.containerLifecycle.Reconcile(ctx, id)
}

func (h *ConversationHandler) writeContainerLifecycleError(c *gin.Context, conversationID, action string, err error) {
	status := http.StatusInternalServerError
	message := "容器操作失败"
	switch {
	case errors.Is(err, containerruntime.ErrNotFound):
		status, message = http.StatusNotFound, "对话容器不存在"
	case errors.Is(err, containerruntime.ErrInvalidSpecification):
		status, message = http.StatusBadRequest, "容器操作参数无效"
	case errors.Is(err, containerruntime.ErrRuntimeStateConflict), errors.Is(err, containerruntime.ErrRuntimeNotReady):
		status, message = http.StatusConflict, "容器当前状态不允许此操作"
	case errors.Is(err, context.DeadlineExceeded):
		status, message = http.StatusGatewayTimeout, "容器操作超时"
	case errors.Is(err, context.Canceled), errors.Is(err, containerruntime.ErrEngineUnavailable):
		status, message = http.StatusServiceUnavailable, "容器运行时暂不可用"
	}
	h.logger.Error("对话容器生命周期操作失败",
		zap.String("conversationId", conversationID), zap.String("action", action), zap.Error(err))
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category: "container", Action: action, Result: "failure",
			ResourceType: "conversation", ResourceID: conversationID, Message: message,
		})
	}
	c.JSON(status, gin.H{"error": message})
}

func queryBoolean(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
