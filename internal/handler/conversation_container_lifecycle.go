package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/database"
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
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	if h.containerLifecycle == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "容器生命周期服务未配置"})
		return
	}
	var request RebuildConversationContainerRequest
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数无效"})
		return
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数无效"})
		return
	}

	var staged *database.ConversationBoundarySnapshot
	var previous database.ConversationBoundarySnapshot
	if len(request.BoundaryPolicyID) != 0 {
		session, hasSession := security.CurrentSession(c)
		if !hasSession || !session.Permissions["boundary:read"] {
			c.JSON(http.StatusForbidden, gin.H{"error": "缺少 boundary:read 权限"})
			return
		}
		if bytes.Equal(bytes.TrimSpace(request.BoundaryPolicyID), []byte("null")) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "boundaryPolicyId 必须为字符串"})
			return
		}
		var requestedPolicyID string
		if err := json.Unmarshal(request.BoundaryPolicyID, &requestedPolicyID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "boundaryPolicyId 必须为字符串"})
			return
		}
		policyID := strings.TrimSpace(requestedPolicyID)
		if policyID != "" && !h.conversationBoundaryPolicyAllowed(c, policyID) {
			return
		}
		var err error
		previous, err = h.db.GetConversationBoundarySnapshot(c.Request.Context(), id)
		if err != nil {
			h.writeBoundaryRebuildPreparationError(c, err)
			return
		}
		prepared, err := h.db.PrepareConversationBoundaryRebuild(c.Request.Context(), id, policyID)
		if err != nil {
			h.writeBoundaryRebuildPreparationError(c, err)
			return
		}
		staged = &prepared
	}

	rebuildCtx := c.Request.Context()
	if staged != nil {
		rebuildCtx = containerruntime.WithBoundaryRebuildSnapshot(rebuildCtx, staged.SnapshotID)
	}
	record, err := h.containerLifecycle.Rebuild(rebuildCtx, id)
	if err != nil {
		h.cancelStagedBoundaryRebuild(id, staged)
		h.writeContainerLifecycleError(c, id, "rebuild", err)
		return
	}
	if staged != nil {
		active, activeErr := h.db.GetConversationBoundarySnapshot(c.Request.Context(), id)
		if activeErr != nil || active.SnapshotID != staged.SnapshotID || active.RuntimeGeneration != record.RuntimeGeneration {
			h.logger.Error("边界快照未随容器重建原子激活",
				zap.String("conversationId", id), zap.String("snapshotId", staged.SnapshotID), zap.Error(activeErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "容器已重建，但边界快照激活失败；执行已失败关闭"})
			return
		}
	}
	if h.audit != nil {
		detail := map[string]interface{}{
			"runtime_status": record.RuntimeStatus, "lifecycle_state": record.LifecycleState,
			"runtime_drift": record.RuntimeDrift, "runtime_generation": record.RuntimeGeneration,
			"boundary_changed": staged != nil,
		}
		if staged != nil {
			detail["previous_boundary_sha256"] = previous.SHA256
			detail["boundary_snapshot_id"] = staged.SnapshotID
			detail["boundary_sha256"] = staged.SHA256
		}
		h.audit.Record(c, audit.Entry{
			Category: "container", Action: "rebuild", Result: "success",
			ResourceType: "conversation", ResourceID: id, Message: "重建对话容器", Detail: detail,
		})
	}
	c.JSON(http.StatusOK, record)
}

type RebuildConversationContainerRequest struct {
	// nil means a maintenance rebuild using the active snapshot. An explicit
	// empty JSON string creates and activates a new no-boundary/default-allow snapshot.
	BoundaryPolicyID json.RawMessage `json:"boundaryPolicyId,omitempty"`
}

func (h *ConversationHandler) ReconcileConversationContainer(c *gin.Context) {
	h.runConversationContainerLifecycle(c, "reconcile", "对账对话容器状态", h.containerLifecycleReconcile)
}

func (h *ConversationHandler) GetConversationEgressHealth(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	state, err := h.db.GetConversationEgressHealthState(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取出站健康状态失败"})
		return
	}
	c.JSON(http.StatusOK, state)
}

func (h *ConversationHandler) RecoverConversationEgressHealth(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	if h.egressHealthController == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "出站健康恢复服务未配置"})
		return
	}
	record, err := h.db.GetContainerInitialization(c.Request.Context(), id)
	if err != nil || record.Status != containerruntime.InitializationCreated || record.RuntimeStatus != containerruntime.StatusRunning || record.Spec.EgressGateway == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "对话出站网关未就绪"})
		return
	}
	if err := h.egressHealthController.RecoverEgressHealth(c.Request.Context(), record.Spec); err != nil {
		h.writeContainerLifecycleError(c, id, "recover-egress-health", err)
		return
	}
	conversation, err := h.db.GetConversationLite(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取对话失败"})
		return
	}
	state, err := h.db.RecordManualEgressRecovery(c.Request.Context(), database.EgressAuditRuntimeTarget{
		Record: record, ConversationTitle: conversation.Title,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "记录出站健康恢复失败"})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "container", "recover-egress-health", "手动恢复对话出站网关", "conversation", id, map[string]interface{}{
			"runtime_generation": record.RuntimeGeneration,
			"snapshot_id":        state.SnapshotID,
		})
	}
	c.JSON(http.StatusOK, state)
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
	workspacePersistent, err := h.db.GetConversationWorkspacePersistent(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
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
		"success":                  true,
		"conversationId":           id,
		"containerDeleted":         true,
		"workspacePersistent":      workspacePersistent,
		"workspaceDeleted":         !workspacePersistent || removeWorkspace,
		"workspaceRetained":        workspacePersistent && !removeWorkspace,
		"workspaceDeletionWarning": workspaceDeletionWarning(workspacePersistent),
	})
}

func workspaceDeletionWarning(persistent bool) string {
	if persistent {
		return "该对话使用专属 Docker named volume；删除容器默认保留工作区，remove_workspace=true 时一并删除"
	}
	return "该对话未启用持久化；删除容器会永久删除 /workspace 中的全部文件"
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
	if _, err := h.db.EnsureConversationEgressBinding(ctx, id); err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("bind conversation upstream egress: %w", err)
	}
	if _, err := h.db.EnsureConversationBoundarySnapshot(ctx, id); err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("bind conversation boundary snapshot: %w", err)
	}
	return h.containerLifecycle.Start(ctx, id)
}

func (h *ConversationHandler) containerLifecycleStop(ctx context.Context, id string) (containerruntime.InitializationRecord, error) {
	return h.containerLifecycle.Stop(ctx, id)
}

func (h *ConversationHandler) cancelStagedBoundaryRebuild(conversationID string, staged *database.ConversationBoundarySnapshot) {
	if staged == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.db.CancelConversationBoundaryRebuild(ctx, conversationID, staged.SnapshotID); err != nil {
		h.logger.Error("取消失败的边界快照重建请求失败",
			zap.String("conversationId", conversationID), zap.String("snapshotId", staged.SnapshotID), zap.Error(err))
	}
}

func (h *ConversationHandler) writeBoundaryRebuildPreparationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, database.ErrConversationBoundaryRebuildPending), errors.Is(err, containerruntime.ErrRuntimeStateConflict):
		c.JSON(http.StatusConflict, gin.H{"error": "对话已有边界快照重建请求正在处理"})
	case errors.Is(err, database.ErrConversationBoundarySnapshotNotFound), errors.Is(err, containerruntime.ErrNotFound), errors.Is(err, sql.ErrNoRows):
		c.JSON(http.StatusNotFound, gin.H{"error": "对话容器或边界快照不存在"})
	default:
		h.logger.Error("创建边界重建快照失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建边界重建快照失败"})
	}
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
