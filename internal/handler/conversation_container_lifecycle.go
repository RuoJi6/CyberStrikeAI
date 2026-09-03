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

// GetConversationContainerNetworkSettings returns the active immutable
// boundary/upstream selections without exposing route credentials.
func (h *ConversationHandler) GetConversationContainerNetworkSettings(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	session, hasSession := security.CurrentSession(c)
	if !hasSession || !session.Permissions["boundary:read"] || !session.Permissions["egress:read"] {
		c.JSON(http.StatusForbidden, gin.H{"error": "缺少边界或出口读取权限"})
		return
	}
	snapshot, err := h.db.GetConversationBoundarySnapshot(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "对话容器边界快照尚未就绪"})
		return
	}
	binding, err := h.db.GetConversationEgress(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取对话上游出口失败"})
		return
	}
	record, err := h.db.GetContainerInitialization(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "对话容器尚未就绪"})
		return
	}
	runtimeControls, err := h.db.GetConversationRuntimeControls(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取容器运行控制失败"})
		return
	}
	proxyID, proxyGroupID := "", ""
	if binding.Proxy != nil {
		proxyID = binding.Proxy.ID
	}
	if binding.ProxyGroup != nil {
		proxyGroupID = binding.ProxyGroup.ID
	}
	activeNetworkAccess := database.ConversationNetworkAccess{}
	if snapshot.Document.NetworkAccess != nil {
		activeNetworkAccess = *snapshot.Document.NetworkAccess
	}
	response := gin.H{
		"conversationId":        id,
		"boundaryPolicyId":      snapshot.PolicyID,
		"boundarySnapshotId":    snapshot.SnapshotID,
		"boundaryDefaultAction": snapshot.Document.DefaultAction,
		"egressMode":            binding.Mode,
		"egressSource":          binding.Source,
		"egressProxyId":         proxyID,
		"egressProxyGroupId":    proxyGroupID,
		"runtimeStatus":         record.RuntimeStatus,
		"lifecycleState":        record.LifecycleState,
		"runtimeGeneration":     record.RuntimeGeneration,
		"runtimeControls":       runtimeControls,
		"networkAccess":         activeNetworkAccess,
		"effectiveNanoCpus":     record.Spec.Resources.NanoCPUs,
		"effectiveMemoryBytes":  record.Spec.Resources.MemoryBytes,
	}
	if pending, pendingErr := h.db.GetPendingConversationBoundaryRebuildSnapshot(c.Request.Context(), id); pendingErr == nil {
		pendingNetworkAccess := database.ConversationNetworkAccess{}
		if pending.Document.NetworkAccess != nil {
			pendingNetworkAccess = *pending.Document.NetworkAccess
		}
		response["pendingBoundarySnapshotId"] = pending.SnapshotID
		response["pendingBoundaryPolicyId"] = pending.PolicyID
		response["pendingNetworkAccess"] = pendingNetworkAccess
	} else if !errors.Is(pendingErr, database.ErrConversationBoundarySnapshotNotFound) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取待生效容器网络配置失败"})
		return
	}
	c.JSON(http.StatusOK, response)
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
	boundaryChanged := len(request.BoundaryPolicyID) != 0
	networkAccessChanged := request.NetworkAccess != nil
	if boundaryChanged || networkAccessChanged {
		session, hasSession := security.CurrentSession(c)
		if !hasSession || !session.Permissions["boundary:read"] {
			c.JSON(http.StatusForbidden, gin.H{"error": "缺少 boundary:read 权限"})
			return
		}
		var err error
		previous, err = h.db.GetConversationBoundarySnapshot(c.Request.Context(), id)
		if err != nil {
			h.writeBoundaryRebuildPreparationError(c, err)
			return
		}
		policyID := previous.PolicyID
		requestedNetworkAccess := database.ConversationNetworkAccess{}
		if previous.Document.NetworkAccess != nil {
			requestedNetworkAccess = *previous.Document.NetworkAccess
		}
		if request.NetworkAccess != nil {
			requestedNetworkAccess = *request.NetworkAccess
		}
		if boundaryChanged {
			if bytes.Equal(bytes.TrimSpace(request.BoundaryPolicyID), []byte("null")) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "boundaryPolicyId 必须为字符串"})
				return
			}
			var requestedPolicyID string
			if err := json.Unmarshal(request.BoundaryPolicyID, &requestedPolicyID); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "boundaryPolicyId 必须为字符串"})
				return
			}
			policyID = strings.TrimSpace(requestedPolicyID)
			if policyID != "" {
				if !h.conversationBoundaryPolicyAllowed(c, policyID) {
					return
				}
			}
		}
		prepared, err := h.db.PrepareConversationBoundaryRebuild(c.Request.Context(), id, policyID, requestedNetworkAccess)
		if err != nil {
			h.writeBoundaryRebuildPreparationError(c, err)
			return
		}
		staged = &prepared
	}

	var stagedRoute *containerruntime.EgressUpstreamRouteSpec
	egressChanged := len(request.EgressMode) != 0
	if egressChanged {
		if h.egressRebuildPreparer == nil {
			h.cancelStagedBoundaryRebuild(id, staged)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "上游出口重建服务未配置"})
			return
		}
		if bytes.Equal(bytes.TrimSpace(request.EgressMode), []byte("null")) {
			h.cancelStagedBoundaryRebuild(id, staged)
			c.JSON(http.StatusBadRequest, gin.H{"error": "egressMode 必须为字符串"})
			return
		}
		var requestedMode string
		if err := json.Unmarshal(request.EgressMode, &requestedMode); err != nil {
			h.cancelStagedBoundaryRebuild(id, staged)
			c.JSON(http.StatusBadRequest, gin.H{"error": "egressMode 必须为字符串"})
			return
		}
		requestedMode = strings.TrimSpace(requestedMode)
		inherit := requestedMode == ""
		proxyID, proxyGroupID := strings.TrimSpace(request.EgressProxyID), strings.TrimSpace(request.EgressProxyGroupID)
		if inherit {
			if proxyID != "" || proxyGroupID != "" {
				h.cancelStagedBoundaryRebuild(id, staged)
				c.JSON(http.StatusBadRequest, gin.H{"error": "继承上游出口时不能指定代理资源"})
				return
			}
		} else {
			session, hasSession := security.CurrentSession(c)
			if !hasSession {
				h.cancelStagedBoundaryRebuild(id, staged)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
				return
			}
			mode, normalizedProxyID, normalizedGroupID, configured, requestErr := normalizeConversationEgressForSession(
				c.Request.Context(), h.db, session, database.ConversationRuntimeModeContainer,
				requestedMode, proxyID, proxyGroupID,
			)
			if requestErr != nil || !configured {
				h.cancelStagedBoundaryRebuild(id, staged)
				if requestErr != nil {
					c.JSON(requestErr.Status, gin.H{"error": requestErr.Message})
				} else {
					c.JSON(http.StatusBadRequest, gin.H{"error": "egressMode 无效"})
				}
				return
			}
			requestedMode, proxyID, proxyGroupID = mode, normalizedProxyID, normalizedGroupID
		}
		var err error
		stagedRoute, err = h.egressRebuildPreparer(c.Request.Context(), id, requestedMode, proxyID, proxyGroupID, inherit)
		if err != nil {
			h.cancelStagedBoundaryRebuild(id, staged)
			h.writeBoundaryRebuildPreparationError(c, err)
			return
		}
	}

	var previousRuntimeControls database.ConversationRuntimeControls
	var requestedRuntimeControls database.ConversationRuntimeControls
	runtimeControlsChanged := request.RuntimeControls != nil
	if runtimeControlsChanged {
		var err error
		requestedRuntimeControls, err = database.NormalizeConversationRuntimeControls(*request.RuntimeControls)
		if err != nil {
			h.cancelStagedBoundaryRebuild(id, staged)
			if egressChanged {
				h.cancelStagedEgressRebuild(id)
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		previousRuntimeControls, err = h.db.GetConversationRuntimeControls(c.Request.Context(), id)
		if err != nil {
			h.cancelStagedBoundaryRebuild(id, staged)
			if egressChanged {
				h.cancelStagedEgressRebuild(id)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "读取当前容器运行控制失败"})
			return
		}
	}

	rebuildCtx := c.Request.Context()
	if staged != nil {
		rebuildCtx = containerruntime.WithBoundaryRebuildSnapshot(rebuildCtx, staged.SnapshotID)
	}
	if egressChanged {
		rebuildCtx = containerruntime.WithEgressRebuildRoute(rebuildCtx, stagedRoute)
	}
	current, err := h.db.GetContainerInitialization(c.Request.Context(), id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, containerruntime.ErrNotFound) {
		h.cancelStagedBoundaryRebuild(id, staged)
		if egressChanged {
			h.cancelStagedEgressRebuild(id)
		}
		h.writeContainerLifecycleError(c, id, "rebuild", err)
		return
	}
	if err == nil && current.RuntimeStatus == containerruntime.StatusRunning {
		if _, err := h.containerLifecycle.Stop(c.Request.Context(), id); err != nil {
			h.cancelStagedBoundaryRebuild(id, staged)
			if egressChanged {
				h.cancelStagedEgressRebuild(id)
			}
			h.writeContainerLifecycleError(c, id, "stop", err)
			return
		}
	} else if err == nil && (current.RuntimeStatus == containerruntime.StatusCreating ||
		current.RuntimeStatus == containerruntime.StatusStarting || current.RuntimeStatus == containerruntime.StatusStopping) {
		h.cancelStagedBoundaryRebuild(id, staged)
		if egressChanged {
			h.cancelStagedEgressRebuild(id)
		}
		c.JSON(http.StatusConflict, gin.H{"error": "对话容器状态正在变化，请稍后重试"})
		return
	}
	if runtimeControlsChanged {
		resources := current.Spec.Resources
		if h.containerResourceDefaults.NanoCPUs > 0 {
			resources.NanoCPUs = h.containerResourceDefaults.NanoCPUs
		}
		if h.containerResourceDefaults.MemoryBytes > 0 {
			resources.MemoryBytes = h.containerResourceDefaults.MemoryBytes
		}
		if requestedRuntimeControls.CustomResourcesEnabled {
			resources.NanoCPUs = requestedRuntimeControls.NanoCPUs
			resources.MemoryBytes = requestedRuntimeControls.MemoryBytes
		}
		var traffic *containerruntime.EgressTrafficLimits
		if requestedRuntimeControls.ScanRateEnabled {
			traffic = &containerruntime.EgressTrafficLimits{
				HTTPRequestsPerSecond:   requestedRuntimeControls.HTTPRequestsPerSecond,
				TCPConnectionsPerSecond: requestedRuntimeControls.TCPConnectionsPerSecond,
				UDPDatagramsPerSecond:   requestedRuntimeControls.UDPDatagramsPerSecond,
			}
		}
		rebuildCtx = containerruntime.WithRuntimeControls(rebuildCtx, resources, traffic)
		if _, err := h.db.SetConversationRuntimeControls(c.Request.Context(), id, requestedRuntimeControls); err != nil {
			h.cancelStagedBoundaryRebuild(id, staged)
			if egressChanged {
				h.cancelStagedEgressRebuild(id)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	record, err := h.containerLifecycle.Rebuild(rebuildCtx, id)
	if err != nil {
		if runtimeControlsChanged {
			_, _ = h.db.SetConversationRuntimeControls(context.Background(), id, previousRuntimeControls)
		}
		h.cancelStagedBoundaryRebuild(id, staged)
		if egressChanged {
			h.cancelStagedEgressRebuild(id)
		}
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
			"boundary_changed":         staged != nil,
			"network_access_changed":   networkAccessChanged,
			"egress_changed":           egressChanged,
			"runtime_controls_changed": runtimeControlsChanged,
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
	// An explicit empty string re-resolves project/user inheritance. Omission
	// preserves the active immutable binding during a maintenance rebuild.
	EgressMode         json.RawMessage                       `json:"egressMode,omitempty"`
	EgressProxyID      string                                `json:"egressProxyId,omitempty"`
	EgressProxyGroupID string                                `json:"egressProxyGroupId,omitempty"`
	RuntimeControls    *database.ConversationRuntimeControls `json:"runtimeControls,omitempty"`
	NetworkAccess      *database.ConversationNetworkAccess   `json:"networkAccess,omitempty"`
}

func (h *ConversationHandler) ReconcileConversationContainer(c *gin.Context) {
	h.runConversationContainerLifecycle(c, "reconcile", "校准对话容器状态", h.containerLifecycleReconcile)
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
	if err := h.runContainerMutationWhenTaskIdle(c, id, func() error {
		return h.containerLifecycle.Delete(c.Request.Context(), id, removeWorkspace)
	}); err != nil {
		if errors.Is(err, ErrTaskAlreadyRunning) {
			c.JSON(http.StatusConflict, gin.H{"error": "对话仍有活动任务；确认中断后请使用 interrupt=1 重试", "taskActive": true})
			return
		}
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
		return "该对话使用 Docker named volume；删除容器默认保留专属或共享工作区，remove_workspace=true 时按工作区规则处理"
	}
	return "该对话使用 Docker tmpfs 临时工作区；删除容器会永久删除 /workspace 中的全部文件"
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
	var record containerruntime.InitializationRecord
	var callErr error
	err := h.runContainerMutationWhenTaskIdle(c, id, func() error {
		record, callErr = call(c.Request.Context(), id)
		return callErr
	})
	if err != nil {
		if errors.Is(err, ErrTaskAlreadyRunning) {
			c.JSON(http.StatusConflict, gin.H{"error": "对话仍有活动任务；确认中断后请使用 interrupt=1 重试", "taskActive": true})
			return
		}
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

func (h *ConversationHandler) runContainerMutationWhenTaskIdle(c *gin.Context, conversationID string, fn func() error) error {
	if fn == nil {
		return errors.New("container lifecycle callback is required")
	}
	interrupt := queryBoolean(c.Query("interrupt"))
	if h.taskState != nil {
		if running, _ := h.taskState.ConversationTaskRuntimeState(conversationID); running {
			if !interrupt {
				return ErrTaskAlreadyRunning
			}
			if h.taskStopper != nil {
				h.taskStopper.CancelRunningTaskForConversation(conversationID)
			}
		}
	}
	if h.taskIdle == nil {
		return fn()
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := h.taskIdle.RunWhenConversationTaskIdle(conversationID, fn)
		if !errors.Is(err, ErrTaskAlreadyRunning) || !interrupt {
			return err
		}
		if time.Now().After(deadline) {
			return ErrTaskAlreadyRunning
		}
		select {
		case <-c.Request.Context().Done():
			return c.Request.Context().Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
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
	if h.containerInitializations != nil {
		record, err := h.containerInitializations.Get(ctx, id)
		switch {
		case errors.Is(err, containerruntime.ErrNotFound):
			if h.containerStarter == nil {
				return containerruntime.InitializationRecord{}, fmt.Errorf("%w: container initializer is not configured", containerruntime.ErrEngineUnavailable)
			}
			return h.containerStarter.StartConversationAsync(ctx, id)
		case err != nil:
			return containerruntime.InitializationRecord{}, err
		case record.Status == containerruntime.InitializationQueued || record.Status == containerruntime.InitializationCreating:
			return record, nil
		case record.Status == containerruntime.InitializationFailed || record.ReadinessStatus == containerruntime.ReadinessFailed:
			if h.containerStarter == nil {
				return containerruntime.InitializationRecord{}, fmt.Errorf("%w: container initializer is not configured", containerruntime.ErrEngineUnavailable)
			}
			return h.containerStarter.StartConversationAsync(ctx, id)
		}
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

func (h *ConversationHandler) cancelStagedEgressRebuild(conversationID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.db.CancelConversationEgressRebuild(ctx, conversationID); err != nil {
		h.logger.Error("取消失败的上游出口重建请求失败",
			zap.String("conversationId", conversationID), zap.Error(err))
	}
}

func (h *ConversationHandler) writeBoundaryRebuildPreparationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, database.ErrConversationEgressRebuildPending):
		c.JSON(http.StatusConflict, gin.H{"error": "对话已有上游出口重建请求正在处理"})
	case errors.Is(err, database.ErrConversationEgressRuntimeNotIdle):
		c.JSON(http.StatusConflict, gin.H{"error": "对话容器正在执行其他生命周期操作"})
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
