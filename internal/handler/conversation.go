package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egressactivity"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ConversationTaskStopper cancels in-flight agent work when a conversation is removed.
type ConversationTaskStopper interface {
	CancelRunningTaskForConversation(conversationID string)
}

// ConversationTaskStateProvider reports whether the in-memory agent task for
// a conversation is still genuinely running. Plan files may survive a service
// restart or cancellation, so their status alone is not authoritative.
type ConversationTaskStateProvider interface {
	ConversationTaskRuntimeState(conversationID string) (running bool, startedAt time.Time)
}

// ConversationTaskIdleRunner serializes an update with task registration so
// execution settings can change only after the current turn has fully ended.
type ConversationTaskIdleRunner interface {
	RunWhenConversationTaskIdle(conversationID string, fn func() error) error
}

type ConversationContainerInitializationProvider interface {
	Get(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error)
}

// ConversationContainerInitializationStarter recreates a deleted runtime or
// explicitly retries a failed initialization using a server-built trusted
// specification. The handler never accepts image or Docker fields from the
// client.
type ConversationContainerInitializationStarter interface {
	StartConversationAsync(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error)
}

type ConversationContainerInitializationStarterFunc func(context.Context, string) (containerruntime.InitializationRecord, error)

func (f ConversationContainerInitializationStarterFunc) StartConversationAsync(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
	return f(ctx, conversationID)
}

type ConversationContainerRuntimeObserver interface {
	Observe(ctx context.Context, spec containerruntime.RuntimeSpec) (containerruntime.RuntimeObservation, error)
}

type ConversationContainerWorkspaceInspector interface {
	WorkspaceInfo(ctx context.Context, spec containerruntime.RuntimeSpec) (containerruntime.WorkspaceInfo, error)
}

type ConversationContainerInteractiveExecutor interface {
	OpenInteractiveExec(ctx context.Context, spec containerruntime.RuntimeSpec, request containerruntime.InteractiveExecRequest) (containerruntime.InteractiveExecSession, error)
}

type ConversationEgressActivityStreamer interface {
	StreamEgressActivity(context.Context, containerruntime.RuntimeSpec, containerruntime.ActivityStreamOptions, containerruntime.RuntimeActivitySink) error
}

type ConversationEgressHealthController interface {
	RecoverEgressHealth(context.Context, containerruntime.RuntimeSpec) error
}

type ConversationEgressRebuildPreparer func(context.Context, string, string, string, string, bool) (*containerruntime.EgressUpstreamRouteSpec, error)

type ConversationContainerLifecycleController interface {
	Start(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error)
	Stop(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error)
	Rebuild(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error)
	Delete(ctx context.Context, conversationID string, removeWorkspace bool) error
	Reconcile(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error)
}

type ConversationRetainedWorkspaceController interface {
	DeleteRetainedWorkspace(ctx context.Context, conversationID string) error
}

type ConversationSharedWorkspaceController interface {
	DeleteSharedWorkspace(ctx context.Context, workspaceID string) error
}

type ConversationEgressAggregationController interface {
	ApplyConversationAggregationSetting(context.Context, string, bool, string) error
	RefreshConversationAggregation(context.Context) error
}

// ConversationHandler 对话处理器
type ConversationHandler struct {
	db                        *database.DB
	logger                    *zap.Logger
	audit                     *audit.Service
	taskStopper               ConversationTaskStopper
	taskState                 ConversationTaskStateProvider
	taskIdle                  ConversationTaskIdleRunner
	containerInitializations  ConversationContainerInitializationProvider
	containerStarter          ConversationContainerInitializationStarter
	containerObserver         ConversationContainerRuntimeObserver
	containerWorkspace        ConversationContainerWorkspaceInspector
	containerInteractive      ConversationContainerInteractiveExecutor
	egressActivityStreamer    ConversationEgressActivityStreamer
	egressActivityIngestor    *egressactivity.Ingestor
	egressHealthController    ConversationEgressHealthController
	egressRebuildPreparer     ConversationEgressRebuildPreparer
	containerLifecycle        ConversationContainerLifecycleController
	containerResourceDefaults containerruntime.ResourceLimits
	retainedWorkspace         ConversationRetainedWorkspaceController
	sharedWorkspace           ConversationSharedWorkspaceController
	containerRollout          func(userID, projectID string) (enabled, allowed bool)
	egressAggregation         ConversationEgressAggregationController
	egressAggregationMu       sync.Mutex
	egressAggregationLocks    map[string]*sync.Mutex
}

func (h *ConversationHandler) SetEgressAggregationController(controller ConversationEgressAggregationController) {
	h.egressAggregation = controller
}

// SetAudit wires platform audit logging.
func (h *ConversationHandler) SetAudit(s *audit.Service) {
	h.audit = s
}

// SetTaskStopper wires cancellation of in-flight agent tasks on conversation delete.
func (h *ConversationHandler) SetTaskStopper(stopper ConversationTaskStopper) {
	h.taskStopper = stopper
}

// SetTaskStateProvider wires the live agent task registry used by supplemental
// conversation UI such as the agent-maintained plan list.
func (h *ConversationHandler) SetTaskStateProvider(provider ConversationTaskStateProvider) {
	h.taskState = provider
}

func (h *ConversationHandler) SetTaskIdleRunner(runner ConversationTaskIdleRunner) {
	h.taskIdle = runner
}

func (h *ConversationHandler) SetContainerInitializationProvider(provider ConversationContainerInitializationProvider) {
	h.containerInitializations = provider
}

func (h *ConversationHandler) SetContainerInitializationStarter(starter ConversationContainerInitializationStarter) {
	h.containerStarter = starter
}

func (h *ConversationHandler) SetContainerRuntimeObserver(observer ConversationContainerRuntimeObserver) {
	h.containerObserver = observer
}

func (h *ConversationHandler) SetContainerWorkspaceInspector(inspector ConversationContainerWorkspaceInspector) {
	h.containerWorkspace = inspector
}

func (h *ConversationHandler) SetContainerInteractiveExecutor(executor ConversationContainerInteractiveExecutor) {
	h.containerInteractive = executor
}

func (h *ConversationHandler) SetEgressActivityStreamer(streamer ConversationEgressActivityStreamer) {
	h.egressActivityStreamer = streamer
}

func (h *ConversationHandler) SetEgressActivityIngestor(ingestor *egressactivity.Ingestor) {
	h.egressActivityIngestor = ingestor
}

func (h *ConversationHandler) SetEgressHealthController(controller ConversationEgressHealthController) {
	h.egressHealthController = controller
}

func (h *ConversationHandler) SetConversationEgressRebuildPreparer(preparer ConversationEgressRebuildPreparer) {
	h.egressRebuildPreparer = preparer
}

func (h *ConversationHandler) SetContainerLifecycleController(controller ConversationContainerLifecycleController) {
	h.containerLifecycle = controller
}

func (h *ConversationHandler) SetContainerResourceDefaults(resources containerruntime.ResourceLimits) {
	h.containerResourceDefaults = resources
}

func (h *ConversationHandler) SetRetainedWorkspaceController(controller ConversationRetainedWorkspaceController) {
	h.retainedWorkspace = controller
}

func (h *ConversationHandler) SetSharedWorkspaceController(controller ConversationSharedWorkspaceController) {
	h.sharedWorkspace = controller
}

func (h *ConversationHandler) SetContainerRolloutAuthorizer(authorizer func(userID, projectID string) (enabled, allowed bool)) {
	h.containerRollout = authorizer
}

// NewConversationHandler 创建新的对话处理器
func NewConversationHandler(db *database.DB, logger *zap.Logger) *ConversationHandler {
	return &ConversationHandler{
		db: db, logger: logger, egressAggregationLocks: make(map[string]*sync.Mutex),
	}
}

// CreateConversationRequest 创建对话请求
type CreateConversationRequest struct {
	Title                 string                                `json:"title"`
	ProjectID             string                                `json:"projectId,omitempty"`
	RuntimeMode           string                                `json:"runtimeMode,omitempty"`
	WorkspaceMode         string                                `json:"workspaceMode,omitempty"`
	WorkspacePersistent   *bool                                 `json:"workspacePersistent,omitempty"`
	WorkspaceID           string                                `json:"workspaceId,omitempty"`
	IdlePolicy            *database.ConversationIdlePolicy      `json:"idlePolicy,omitempty"`
	BoundaryPolicyID      string                                `json:"boundaryPolicyId,omitempty"`
	EgressMode            string                                `json:"egressMode,omitempty"`
	EgressProxyID         string                                `json:"egressProxyId,omitempty"`
	EgressProxyGroupID    string                                `json:"egressProxyGroupId,omitempty"`
	EgressAuditEnabled    *bool                                 `json:"egressAuditEnabled,omitempty"`
	EgressAuditMode       string                                `json:"egressAuditMode,omitempty"`
	EgressAggregationMode string                                `json:"egressAggregationMode,omitempty"`
	RuntimeControls       *database.ConversationRuntimeControls `json:"runtimeControls,omitempty"`
	NetworkAccess         *database.ConversationNetworkAccess   `json:"networkAccess,omitempty"`
}

// SetConversationProjectRequest 设置对话所属项目
type SetConversationProjectRequest struct {
	ProjectID string `json:"projectId"` // 空字符串表示解除绑定
}

type SetConversationRuntimeModeRequest struct {
	RuntimeMode string `json:"runtimeMode"`
}

// CreateConversation 创建新对话
func (h *ConversationHandler) CreateConversation(c *gin.Context) {
	var req CreateConversationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	title := req.Title
	if title == "" {
		title = "新对话"
	}

	meta := audit.ConversationCreateMetaFromGin(c, "api")
	meta.ProjectID = strings.TrimSpace(req.ProjectID)
	runtimeMode, err := database.NormalizeConversationRuntimeMode(req.RuntimeMode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "runtimeMode 必须为 host 或 container"})
		return
	}
	meta.RuntimeMode = runtimeMode
	if req.WorkspacePersistent != nil && *req.WorkspacePersistent && runtimeMode != database.ConversationRuntimeModeContainer {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workspacePersistent 只能用于 container 对话"})
		return
	}
	meta.WorkspaceMode = strings.ToLower(strings.TrimSpace(req.WorkspaceMode))
	if meta.WorkspaceMode == "" && req.WorkspacePersistent != nil {
		if *req.WorkspacePersistent {
			meta.WorkspaceMode = database.ConversationWorkspaceModeDedicated
		} else {
			meta.WorkspaceMode = database.ConversationWorkspaceModeEphemeral
		}
	}
	if meta.WorkspaceMode != "" && runtimeMode != database.ConversationRuntimeModeContainer {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workspaceMode 只能用于 container 对话"})
		return
	}
	meta.WorkspacePersistent = meta.WorkspaceMode == database.ConversationWorkspaceModeDedicated || meta.WorkspaceMode == database.ConversationWorkspaceModeShared
	meta.WorkspaceID = strings.TrimSpace(req.WorkspaceID)
	if req.IdlePolicy != nil {
		if runtimeMode != database.ConversationRuntimeModeContainer {
			c.JSON(http.StatusBadRequest, gin.H{"error": "idlePolicy 只能用于 container 对话"})
			return
		}
		normalizedIdle, idleErr := database.NormalizeConversationIdlePolicy(*req.IdlePolicy)
		if idleErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": idleErr.Error()})
			return
		}
		meta.IdlePolicy = &normalizedIdle
	}
	if req.RuntimeControls != nil {
		if runtimeMode != database.ConversationRuntimeModeContainer {
			c.JSON(http.StatusBadRequest, gin.H{"error": "runtimeControls 只能用于 container 对话"})
			return
		}
		normalized, controlsErr := database.NormalizeConversationRuntimeControls(*req.RuntimeControls)
		if controlsErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": controlsErr.Error()})
			return
		}
		meta.RuntimeControls = normalized
	}
	if req.NetworkAccess != nil {
		if runtimeMode != database.ConversationRuntimeModeContainer {
			c.JSON(http.StatusBadRequest, gin.H{"error": "networkAccess 只能用于 container 对话"})
			return
		}
		if req.NetworkAccess.AllowRestrictedTargets {
			session, hasSession := security.CurrentSession(c)
			if !hasSession || !session.Permissions["boundary:read"] {
				c.JSON(http.StatusForbidden, gin.H{"error": "启用受限目标访问需要 boundary:read 权限"})
				return
			}
		}
		meta.NetworkAccess = *req.NetworkAccess
	}
	meta.EgressAuditEnabled = req.EgressAuditEnabled
	if strings.TrimSpace(req.EgressAuditMode) != "" {
		auditMode, modeErr := database.NormalizeConversationEgressAuditMode(req.EgressAuditMode)
		if modeErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "egressAuditMode 必须为 compact、full 或 off"})
			return
		}
		if req.EgressAuditEnabled != nil && (*req.EgressAuditEnabled != (auditMode != database.EgressAuditModeOff)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "egressAuditEnabled 与旧版 egressAuditMode 冲突"})
			return
		}
		meta.EgressAuditMode = auditMode
	}
	if strings.TrimSpace(req.EgressAggregationMode) != "" {
		aggregationMode, modeErr := database.NormalizeConversationEgressAggregationMode(req.EgressAggregationMode)
		if modeErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "egressAggregationMode 必须为 all、tools 或 none"})
			return
		}
		if meta.EgressAuditMode != "" {
			legacyAggregation := database.EgressAggregationModeAll
			if meta.EgressAuditMode == database.EgressAuditModeFull {
				legacyAggregation = database.EgressAggregationModeNone
			}
			if meta.EgressAuditMode != database.EgressAuditModeOff && legacyAggregation != aggregationMode {
				c.JSON(http.StatusBadRequest, gin.H{"error": "egressAggregationMode 与旧版 egressAuditMode 冲突"})
				return
			}
		}
		meta.EgressAggregationMode = aggregationMode
	}
	meta.BoundaryPolicyID = strings.TrimSpace(req.BoundaryPolicyID)
	if meta.BoundaryPolicyID != "" {
		if runtimeMode != database.ConversationRuntimeModeContainer {
			c.JSON(http.StatusBadRequest, gin.H{"error": "boundaryPolicyId 只能用于 container 对话"})
			return
		}
		if !h.conversationBoundaryPolicyAllowed(c, meta.BoundaryPolicyID) {
			return
		}
	}
	session, _ := security.CurrentSession(c)
	egressMode, egressProxyID, egressProxyGroupID, _, requestErr := normalizeConversationEgressForSession(
		c.Request.Context(), h.db, session, runtimeMode,
		req.EgressMode, req.EgressProxyID, req.EgressProxyGroupID,
	)
	if requestErr != nil {
		c.JSON(requestErr.Status, gin.H{"error": requestErr.Message})
		return
	}
	meta.EgressMode = egressMode
	meta.EgressProxyID = egressProxyID
	meta.EgressProxyGroupID = egressProxyGroupID
	if !h.conversationProjectAllowed(c, meta.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问目标项目"})
		return
	}
	if runtimeMode == database.ConversationRuntimeModeContainer && !h.containerRolloutAllowed(session.UserID, meta.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "当前用户或项目尚未开放容器执行，请使用本机执行"})
		return
	}
	conv, err := h.db.CreateConversation(title, meta)
	if err != nil {
		h.logger.Error("创建对话失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if session, ok := security.CurrentSession(c); ok {
		_ = h.db.SetResourceOwner("conversation", conv.ID, session.UserID)
		_ = h.db.AssignResourceToUser(session.UserID, "conversation", conv.ID)
		if conv.ProjectID != "" {
			_ = h.db.AssignResourceToUser(session.UserID, "project", conv.ProjectID)
		}
	}
	if h.egressAggregation != nil {
		setting, settingErr := h.db.GetConversationEgressAuditSetting(c.Request.Context(), conv.ID)
		if settingErr != nil {
			h.logger.Error("读取新对话流量聚合策略失败", zap.String("conversationId", conv.ID), zap.Error(settingErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "初始化对话流量聚合策略失败"})
			return
		}
		if applyErr := h.egressAggregation.ApplyConversationAggregationSetting(c.Request.Context(), conv.ID, setting.Enabled, setting.AggregationMode); applyErr != nil {
			h.logger.Error("初始化对话流量聚合策略失败", zap.String("conversationId", conv.ID), zap.Error(applyErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "初始化对话流量聚合策略失败"})
			return
		}
	}

	c.JSON(http.StatusOK, conv)
}

func (h *ConversationHandler) containerRolloutAllowed(userID, projectID string) bool {
	if h == nil || h.containerRollout == nil {
		return true
	}
	_, allowed := h.containerRollout(strings.TrimSpace(userID), strings.TrimSpace(projectID))
	return allowed
}

// SetConversationRuntimeMode switches the execution location used by future
// turns. History is unchanged and an in-flight/cancelling turn keeps the mode
// locked until it has fully left the task registry.
func (h *ConversationHandler) SetConversationRuntimeMode(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	if !h.db.UserCanAccessResource(session.UserID, session.Scope, "conversation", id) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该对话"})
		return
	}

	var req SetConversationRuntimeModeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "runtimeMode 必须为 host 或 container"})
		return
	}
	mode, err := database.NormalizeConversationRuntimeMode(req.RuntimeMode)
	if err != nil || strings.TrimSpace(req.RuntimeMode) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "runtimeMode 必须为 host 或 container"})
		return
	}
	conversation, err := h.db.GetConversationLite(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}
	if mode == database.ConversationRuntimeModeContainer &&
		!h.containerRolloutAllowed(session.UserID, conversation.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "当前用户或项目尚未开放容器执行"})
		return
	}

	update := func() error { return h.db.SetConversationRuntimeMode(id, mode) }
	if h.taskIdle != nil {
		err = h.taskIdle.RunWhenConversationTaskIdle(id, update)
	} else {
		if h.taskState != nil {
			if running, _ := h.taskState.ConversationTaskRuntimeState(id); running {
				err = ErrTaskAlreadyRunning
			} else {
				err = update()
			}
		} else {
			err = update()
		}
	}
	if errors.Is(err, ErrTaskAlreadyRunning) {
		c.JSON(http.StatusConflict, gin.H{"error": "当前任务尚未完成，完成后才能切换执行位置"})
		return
	}
	if err != nil {
		h.logger.Error("切换对话执行位置失败", zap.String("conversationId", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "切换执行位置失败"})
		return
	}

	if h.audit != nil && conversation.RuntimeMode != mode {
		h.audit.Record(c, audit.Entry{
			Category: "conversation", Action: "switch_runtime_mode", Result: "success",
			ResourceType: "conversation", ResourceID: id, Message: "切换对话执行位置",
			Detail: map[string]interface{}{"from": conversation.RuntimeMode, "to": mode},
		})
	}
	updatedConversation, err := h.db.GetConversationLite(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "切换成功但读取最新工作区失败"})
		return
	}
	binding, _ := h.db.GetConversationWorkspaceBinding(c.Request.Context(), id)
	idlePolicy, _ := h.db.GetConversationIdlePolicy(c.Request.Context(), id)
	c.JSON(http.StatusOK, gin.H{
		"conversationId":      id,
		"runtimeMode":         mode,
		"workspacePersistent": updatedConversation.WorkspacePersistent,
		"workspaceMode":       binding.Mode,
		"idlePolicy":          idlePolicy,
	})
}

func (h *ConversationHandler) GetContainerRuntimeRollout(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	projectID := strings.TrimSpace(c.Query("project_id"))
	if projectID != "" {
		if _, err := h.db.GetProject(projectID); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "目标项目不存在"})
			return
		}
		if !session.Permissions["project:read"] ||
			!h.db.UserCanAccessResource(session.UserID, session.ScopeFor("project:read"), "project", projectID) {
			c.JSON(http.StatusForbidden, gin.H{"error": "无权访问目标项目"})
			return
		}
	}
	enabled, allowed := false, false
	if h != nil && h.containerRollout != nil {
		enabled, allowed = h.containerRollout(session.UserID, projectID)
	}
	c.JSON(http.StatusOK, gin.H{
		"enabled": enabled,
		"allowed": allowed,
		"reason": func() string {
			if !enabled {
				return "container_runtime_disabled"
			}
			if !allowed {
				return "rollout_not_allowed"
			}
			return "allowed"
		}(),
	})
}

func (h *ConversationHandler) conversationBoundaryPolicyAllowed(c *gin.Context, policyID string) bool {
	session, ok := security.CurrentSession(c)
	if !ok || !session.Permissions["boundary:read"] {
		c.JSON(http.StatusForbidden, gin.H{"error": "缺少 boundary:read 权限"})
		return false
	}
	if _, err := h.db.GetBoundaryPolicy(c.Request.Context(), policyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "边界策略不存在"})
			return false
		}
		h.logger.Error("读取对话边界策略失败", zap.String("policy_id", policyID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取边界策略失败"})
		return false
	}
	if !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("boundary:read"), "boundary_policy", policyID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该边界策略"})
		return false
	}
	return true
}

// SetConversationProject 设置或清除对话绑定的项目
func (h *ConversationHandler) SetConversationProject(c *gin.Context) {
	id := c.Param("id")
	var req SetConversationProjectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := h.db.GetConversation(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}
	projectID := strings.TrimSpace(req.ProjectID)
	if !h.conversationProjectAllowed(c, projectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问目标项目"})
		return
	}
	if err := h.db.SetConversationProjectID(id, projectID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "projectId": projectID})
}

func (h *ConversationHandler) conversationProjectAllowed(c *gin.Context, projectID string) bool {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return true
	}
	session, ok := security.CurrentSession(c)
	if !ok {
		return false
	}
	return h.db.UserCanAccessResource(session.UserID, session.Scope, "project", projectID)
}

// ListConversations 列出对话
func (h *ConversationHandler) ListConversations(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")
	search := c.Query("search") // 获取搜索参数
	projectID := strings.TrimSpace(c.Query("project_id"))

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	sortBy := strings.TrimSpace(c.Query("sort_by"))
	session, _ := security.CurrentSession(c)

	var conversations []*database.Conversation
	var total int
	var err error
	conversations, err = h.db.ListConversationsForAccess(limit, offset, search, sortBy, projectID, session.UserID, session.Scope)
	if err == nil {
		total, err = h.db.CountConversationsForAccess(search, projectID, session.UserID, session.Scope)
	}
	if err != nil {
		h.logger.Error("获取对话列表失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if conversations == nil {
		conversations = []*database.Conversation{}
	}
	c.JSON(http.StatusOK, gin.H{
		"conversations": conversations,
		"total":         total,
		"limit":         limit,
		"offset":        offset,
	})
}

// ListContainerRuntimes returns one RBAC-scoped, server-paginated projection
// for the container management UI. It deliberately omits live Docker
// observation; the selected-row detail endpoint remains the only opt-in
// observation path.
func (h *ConversationHandler) ListContainerRuntimes(c *gin.Context) {
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "page 必须是正整数"})
		return
	}
	pageSize, err := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if err != nil || (pageSize != 10 && pageSize != 20 && pageSize != 50 && pageSize != 100) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "page_size 仅支持 10、20、50 或 100"})
		return
	}
	search := strings.TrimSpace(c.Query("search"))
	if utf8.RuneCountInString(search) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "search 最多 200 个字符"})
		return
	}
	status, ok := database.NormalizeContainerRuntimeListStatus(c.Query("status"))
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status 不受支持"})
		return
	}
	if h.containerInitializations == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "容器初始化状态服务未配置"})
		return
	}
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权访问"})
		return
	}
	query := database.ContainerRuntimeListQuery{
		Limit: pageSize, Offset: (page - 1) * pageSize, Search: search, Status: status,
		UserID: session.UserID, Scope: session.Scope,
	}
	conversations, err := h.db.ListContainerConversationsForAccess(c.Request.Context(), query)
	if err != nil {
		h.logger.Error("获取容器运行时列表失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取容器运行时列表失败"})
		return
	}
	summary, err := h.db.SummarizeContainerConversationsForAccess(c.Request.Context(), query)
	if err != nil {
		h.logger.Error("统计容器运行时列表失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "统计容器运行时列表失败"})
		return
	}
	items := make([]containerRuntimeListItemView, 0, len(conversations))
	for _, conversation := range conversations {
		item := containerRuntimeListItemView{
			ConversationID: conversation.ID, ConversationTitle: conversation.Title,
			RuntimeMode: conversation.RuntimeMode, WorkspacePersistent: conversation.WorkspacePersistent,
			Status: "not_requested", UpdatedAt: conversation.UpdatedAt,
		}
		item.NetworkAccess, _ = h.db.GetConversationNetworkAccess(c.Request.Context(), conversation.ID)
		if binding, bindingErr := h.db.GetConversationWorkspaceBinding(c.Request.Context(), conversation.ID); bindingErr == nil {
			item.WorkspaceMode = binding.Mode
		}
		record, getErr := h.containerInitializations.Get(c.Request.Context(), conversation.ID)
		if getErr == nil {
			item.apply(record)
			if record.Spec.EgressGateway != nil {
				health, healthErr := h.db.GetConversationEgressHealthState(c.Request.Context(), conversation.ID)
				if healthErr == nil {
					item.EgressHealth = &health
				}
			}
		} else if !errors.Is(getErr, containerruntime.ErrNotFound) {
			item.Status = "unavailable"
			item.ObservationError = "status_unavailable"
		}
		if snapshot, snapshotErr := h.db.GetConversationBoundarySnapshot(c.Request.Context(), conversation.ID); snapshotErr == nil {
			item.BoundaryPolicyID = snapshot.PolicyID
			item.BoundarySnapshotID = snapshot.SnapshotID
			if snapshot.Document.NetworkAccess != nil {
				item.NetworkAccess = *snapshot.Document.NetworkAccess
			}
		} else if selectedPolicyID, selectionErr := h.db.GetConversationBoundaryPolicySelection(c.Request.Context(), conversation.ID); selectionErr == nil {
			item.BoundaryPolicyID = selectedPolicyID
		}
		if pending, pendingErr := h.db.GetPendingConversationBoundaryRebuildSnapshot(c.Request.Context(), conversation.ID); pendingErr == nil {
			item.PendingBoundarySnapshotID = pending.SnapshotID
			item.PendingBoundaryPolicyID = pending.PolicyID
			if pending.Document.NetworkAccess != nil {
				pendingAccess := *pending.Document.NetworkAccess
				item.PendingNetworkAccess = &pendingAccess
			}
		}
		if item.BoundaryPolicyID != "" {
			if policy, policyErr := h.db.GetBoundaryPolicy(c.Request.Context(), item.BoundaryPolicyID); policyErr == nil {
				item.BoundaryPolicyName = policy.Name
			}
		}
		item.IdlePolicy, _ = h.db.GetConversationIdlePolicy(c.Request.Context(), conversation.ID)
		item.IdleExpiresAt = database.ConversationIdleExpiresAt(conversation.UpdatedAt, item.IdlePolicy)
		items = append(items, item)
	}
	totalPages := 0
	if summary.Total > 0 {
		totalPages = (summary.Total + pageSize - 1) / pageSize
	}
	c.JSON(http.StatusOK, gin.H{
		"items": items, "page": page, "pageSize": pageSize,
		"total": summary.Total, "totalPages": totalPages,
		"search": search, "status": status, "summary": summary,
	})
}

type containerRuntimeListItemView struct {
	ConversationID            string                              `json:"conversationId"`
	ConversationTitle         string                              `json:"conversationTitle"`
	RuntimeMode               string                              `json:"runtimeMode"`
	WorkspaceMode             string                              `json:"workspaceMode"`
	WorkspacePersistent       bool                                `json:"workspacePersistent"`
	Status                    string                              `json:"status"`
	RuntimeStatus             containerruntime.Status             `json:"runtimeStatus,omitempty"`
	ImageDigest               string                              `json:"imageDigest,omitempty"`
	ImagePlatform             string                              `json:"imagePlatform,omitempty"`
	LastError                 string                              `json:"lastError,omitempty"`
	ReadinessStatus           containerruntime.ReadinessStatus    `json:"readinessStatus,omitempty"`
	ReadinessError            string                              `json:"readinessError,omitempty"`
	ToolCount                 int                                 `json:"toolCount,omitempty"`
	LifecycleOperation        containerruntime.LifecycleOperation `json:"lifecycleOperation,omitempty"`
	LifecycleState            containerruntime.LifecycleState     `json:"lifecycleState,omitempty"`
	LifecycleError            string                              `json:"lifecycleError,omitempty"`
	RuntimeGeneration         int                                 `json:"runtimeGeneration,omitempty"`
	RuntimeDrift              string                              `json:"runtimeDrift,omitempty"`
	UpdatedAt                 time.Time                           `json:"updatedAt"`
	Desired                   *conversationContainerDesiredView   `json:"desired,omitempty"`
	ObservationError          string                              `json:"observationError,omitempty"`
	EgressHealth              *database.EgressHealthState         `json:"egressHealth,omitempty"`
	BoundaryPolicyID          string                              `json:"boundaryPolicyId"`
	BoundaryPolicyName        string                              `json:"boundaryPolicyName"`
	BoundarySnapshotID        string                              `json:"boundarySnapshotId,omitempty"`
	NetworkAccess             database.ConversationNetworkAccess  `json:"networkAccess"`
	PendingBoundarySnapshotID string                              `json:"pendingBoundarySnapshotId,omitempty"`
	PendingBoundaryPolicyID   string                              `json:"pendingBoundaryPolicyId,omitempty"`
	PendingNetworkAccess      *database.ConversationNetworkAccess `json:"pendingNetworkAccess,omitempty"`
	IdlePolicy                database.ConversationIdlePolicy     `json:"idlePolicy"`
	IdleExpiresAt             *time.Time                          `json:"idleExpiresAt,omitempty"`
}

func (item *containerRuntimeListItemView) apply(record containerruntime.InitializationRecord) {
	item.Status = string(record.Status)
	item.RuntimeStatus = record.RuntimeStatus
	item.ImageDigest = record.ImageDigest
	item.ImagePlatform = record.ImagePlatform
	item.LastError = record.LastError
	item.ReadinessStatus = record.ReadinessStatus
	item.ReadinessError = record.ReadinessError
	item.ToolCount = record.ToolCount
	item.LifecycleOperation = record.LifecycleOperation
	item.LifecycleState = record.LifecycleState
	item.LifecycleError = record.LifecycleError
	item.RuntimeGeneration = record.RuntimeGeneration
	item.RuntimeDrift = record.RuntimeDrift
	item.UpdatedAt = record.UpdatedAt
	item.Desired = desiredConversationContainerView(record.Spec)
}

// UpdateConversationPinnedRequest 更新对话置顶状态请求
type UpdateConversationPinnedRequest struct {
	Pinned bool `json:"pinned"`
}

// UpdateConversationPinned 更新对话置顶状态
func (h *ConversationHandler) UpdateConversationPinned(c *gin.Context) {
	conversationID := c.Param("id")
	session, ok := security.CurrentSession(c)
	if !ok || !h.db.UserCanAccessResource(session.UserID, session.Scope, "conversation", conversationID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该资源"})
		return
	}

	var req UpdateConversationPinnedRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.db.UpdateConversationPinned(conversationID, req.Pinned); err != nil {
		h.logger.Error("更新对话置顶状态失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// GetConversation 获取对话
func (h *ConversationHandler) GetConversation(c *gin.Context) {
	id := c.Param("id")

	// 默认轻量加载，只有用户需要展开详情时再按需拉取
	// include_process_details=1/true 时返回全量 processDetails（兼容旧行为）
	includeStr := c.DefaultQuery("include_process_details", "0")
	include := includeStr == "1" || includeStr == "true" || includeStr == "yes"

	var (
		conv *database.Conversation
		err  error
	)
	if include {
		conv, err = h.db.GetConversation(id)
	} else {
		conv, err = h.db.GetConversationLite(id)
	}
	if err != nil {
		h.logger.Error("获取对话失败", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}

	c.JSON(http.StatusOK, conv)
}

// GetContainerInitialization returns durable background creation state without
// loading conversation messages or waiting for Docker operations.
func (h *ConversationHandler) GetContainerInitialization(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	id := strings.TrimSpace(c.Param("id"))
	session, ok := security.CurrentSession(c)
	if !ok || !h.db.UserCanAccessResource(session.UserID, session.Scope, "conversation", id) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该对话"})
		return
	}
	conversation, err := h.db.GetConversationLite(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}
	if h.containerInitializations == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "容器初始化状态服务未配置"})
		return
	}
	record, err := h.containerInitializations.Get(c.Request.Context(), id)
	if errors.Is(err, containerruntime.ErrNotFound) {
		idlePolicy, _ := h.db.GetConversationIdlePolicy(c.Request.Context(), id)
		networkAccess, _ := h.db.GetConversationNetworkAccess(c.Request.Context(), id)
		c.JSON(http.StatusOK, gin.H{
			"conversationId":      id,
			"conversationTitle":   conversation.Title,
			"runtimeMode":         conversation.RuntimeMode,
			"workspaceMode":       conversation.WorkspaceMode,
			"workspacePersistent": conversation.WorkspacePersistent,
			"status":              "not_requested",
			"idlePolicy":          idlePolicy,
			"idleExpiresAt":       database.ConversationIdleExpiresAt(conversation.UpdatedAt, idlePolicy),
			"networkAccess":       networkAccess,
		})
		return
	}
	if err != nil {
		h.logger.Error("获取容器初始化状态失败", zap.String("conversationId", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取容器初始化状态失败"})
		return
	}
	view := conversationContainerInitializationView{
		InitializationRecord: record,
		ConversationTitle:    conversation.Title,
		RuntimeMode:          conversation.RuntimeMode,
		WorkspaceMode:        conversation.WorkspaceMode,
		WorkspacePersistent:  conversation.WorkspacePersistent,
		Desired:              desiredConversationContainerView(record.Spec),
	}
	view.IdlePolicy, _ = h.db.GetConversationIdlePolicy(c.Request.Context(), id)
	view.IdleExpiresAt = database.ConversationIdleExpiresAt(conversation.UpdatedAt, view.IdlePolicy)
	if snapshot, snapshotErr := h.db.GetConversationBoundarySnapshot(c.Request.Context(), id); snapshotErr == nil {
		view.BoundaryPolicyID = snapshot.PolicyID
		view.BoundarySnapshotID = snapshot.SnapshotID
		if snapshot.Document.NetworkAccess != nil {
			view.NetworkAccess = *snapshot.Document.NetworkAccess
		}
	}
	if pending, pendingErr := h.db.GetPendingConversationBoundaryRebuildSnapshot(c.Request.Context(), id); pendingErr == nil {
		view.PendingBoundaryPolicyID = pending.PolicyID
		view.PendingBoundarySnapshotID = pending.SnapshotID
		if pending.Document.NetworkAccess != nil {
			pendingAccess := *pending.Document.NetworkAccess
			view.PendingNetworkAccess = &pendingAccess
		}
	}
	observe := c.Query("observe") == "1" || strings.EqualFold(c.Query("observe"), "true")
	// A start/stop/rebuild operation intentionally moves the Agent and gateway
	// through different engine states. Observing the immutable topology in that
	// window can report a transient runtime drift even though the durable
	// lifecycle operation is still progressing normally. Keep the lifecycle
	// state authoritative until the operation reaches idle/failed, then perform
	// the full live verification on the next poll.
	if observe && record.Status == containerruntime.InitializationCreated && record.LifecycleState != containerruntime.LifecycleInProgress {
		if h.containerObserver == nil {
			view.ObservationError = "observer_unavailable"
		} else {
			observation, observeErr := h.containerObserver.Observe(c.Request.Context(), record.Spec)
			if observeErr != nil {
				view.ObservationError = containerObservationErrorCode(observeErr)
			} else {
				view.Observation = &observation
			}
		}
	}
	c.JSON(http.StatusOK, view)
}

type conversationContainerInitializationView struct {
	containerruntime.InitializationRecord
	ConversationTitle         string                               `json:"conversationTitle"`
	RuntimeMode               string                               `json:"runtimeMode"`
	WorkspaceMode             string                               `json:"workspaceMode"`
	WorkspacePersistent       bool                                 `json:"workspacePersistent"`
	Desired                   *conversationContainerDesiredView    `json:"desired,omitempty"`
	Observation               *containerruntime.RuntimeObservation `json:"observation,omitempty"`
	ObservationError          string                               `json:"observationError,omitempty"`
	IdlePolicy                database.ConversationIdlePolicy      `json:"idlePolicy"`
	IdleExpiresAt             *time.Time                           `json:"idleExpiresAt,omitempty"`
	BoundaryPolicyID          string                               `json:"boundaryPolicyId"`
	BoundarySnapshotID        string                               `json:"boundarySnapshotId,omitempty"`
	NetworkAccess             database.ConversationNetworkAccess   `json:"networkAccess"`
	PendingBoundaryPolicyID   string                               `json:"pendingBoundaryPolicyId,omitempty"`
	PendingBoundarySnapshotID string                               `json:"pendingBoundarySnapshotId,omitempty"`
	PendingNetworkAccess      *database.ConversationNetworkAccess  `json:"pendingNetworkAccess,omitempty"`
}

type conversationContainerDesiredView struct {
	SpecDigest          string                                  `json:"specDigest"`
	ImageDigest         string                                  `json:"imageDigest"`
	ImagePlatform       string                                  `json:"imagePlatform"`
	GatewayImageDigest  string                                  `json:"gatewayImageDigest,omitempty"`
	BoundarySnapshotSHA string                                  `json:"boundarySnapshotSha256,omitempty"`
	Workspace           conversationContainerWorkspaceView      `json:"workspace"`
	Resources           conversationContainerResourceLimitsView `json:"resources"`
	GatewayResources    *conversationGatewayResourceLimitsView  `json:"gatewayResources,omitempty"`
}

type conversationContainerWorkspaceView struct {
	Persistent bool   `json:"persistent"`
	MountPath  string `json:"mountPath"`
	LimitBytes int64  `json:"limitBytes"`
}

type conversationContainerResourceLimitsView struct {
	NanoCPUs          int64  `json:"nanoCpus"`
	MemoryBytes       int64  `json:"memoryBytes"`
	PIDs              int64  `json:"pids"`
	NoFileSoft        uint64 `json:"noFileSoft"`
	NoFileHard        uint64 `json:"noFileHard"`
	WorkspaceBytes    int64  `json:"workspaceBytes"`
	MaxConcurrentExec int    `json:"maxConcurrentExec"`
	MaxQueuedExec     int    `json:"maxQueuedExec"`
	LogMaxBytes       int64  `json:"logMaxBytes"`
	LogMaxFiles       int    `json:"logMaxFiles"`
}

type conversationGatewayResourceLimitsView struct {
	NanoCPUs    int64  `json:"nanoCpus"`
	MemoryBytes int64  `json:"memoryBytes"`
	PIDs        int64  `json:"pids"`
	NoFileSoft  uint64 `json:"noFileSoft"`
	NoFileHard  uint64 `json:"noFileHard"`
	TmpfsBytes  int64  `json:"tmpfsBytes"`
	LogMaxBytes int64  `json:"logMaxBytes"`
	LogMaxFiles int    `json:"logMaxFiles"`
}

func conversationContainerResourceLimits(limits containerruntime.ResourceLimits) conversationContainerResourceLimitsView {
	return conversationContainerResourceLimitsView{
		NanoCPUs: limits.NanoCPUs, MemoryBytes: limits.MemoryBytes, PIDs: limits.PIDs,
		NoFileSoft: limits.NoFileSoft, NoFileHard: limits.NoFileHard, WorkspaceBytes: limits.WorkspaceBytes,
		MaxConcurrentExec: limits.MaxConcurrentExec, MaxQueuedExec: limits.MaxQueuedExec,
		LogMaxBytes: limits.LogMaxBytes, LogMaxFiles: limits.LogMaxFiles,
	}
}

func conversationGatewayResourceLimits(limits containerruntime.EgressGatewayResources) conversationGatewayResourceLimitsView {
	return conversationGatewayResourceLimitsView{
		NanoCPUs: limits.NanoCPUs, MemoryBytes: limits.MemoryBytes, PIDs: limits.PIDs,
		NoFileSoft: limits.NoFileSoft, NoFileHard: limits.NoFileHard, TmpfsBytes: limits.TmpfsBytes,
		LogMaxBytes: limits.LogMaxBytes, LogMaxFiles: limits.LogMaxFiles,
	}
}

func desiredConversationContainerView(spec containerruntime.RuntimeSpec) *conversationContainerDesiredView {
	if strings.TrimSpace(string(spec.ID)) == "" {
		return nil
	}
	view := &conversationContainerDesiredView{
		SpecDigest:    containerruntime.RuntimeSpecDigest(spec),
		ImageDigest:   spec.Image.Digest,
		ImagePlatform: spec.Image.Platform,
		Workspace: conversationContainerWorkspaceView{
			Persistent: spec.Workspace.Persistent,
			MountPath:  spec.Workspace.MountPath,
			LimitBytes: spec.Resources.WorkspaceBytes,
		},
		Resources: conversationContainerResourceLimits(spec.Resources),
	}
	if spec.EgressGateway != nil {
		view.GatewayImageDigest = spec.EgressGateway.Image.Digest
		resources := conversationGatewayResourceLimits(spec.EgressGateway.Resources)
		view.GatewayResources = &resources
		if spec.EgressGateway.BoundarySnapshot != nil {
			view.BoundarySnapshotSHA = spec.EgressGateway.BoundarySnapshot.SHA256
		}
	}
	return view
}

func containerObservationErrorCode(err error) string {
	switch {
	case errors.Is(err, containerruntime.ErrNotFound):
		return "provider_missing"
	case errors.Is(err, containerruntime.ErrRuntimeStateConflict), errors.Is(err, containerruntime.ErrRuntimeNotReady):
		return "runtime_drift"
	case errors.Is(err, containerruntime.ErrEngineUnavailable):
		return "engine_unavailable"
	default:
		return "observation_failed"
	}
}

// GetConversationPlanTasks returns the task list maintained by the agent's
// TaskCreate/TaskUpdate tools for this conversation.
func (h *ConversationHandler) GetConversationPlanTasks(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	session, ok := security.CurrentSession(c)
	if !ok || !h.db.UserCanAccessResource(session.UserID, session.Scope, "conversation", id) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该对话"})
		return
	}
	if _, err := h.db.GetConversationLite(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}
	running := false
	startedAt := time.Time{}
	if h.taskState != nil {
		running, startedAt = h.taskState.ConversationTaskRuntimeState(id)
	}
	if !running {
		c.JSON(http.StatusOK, gin.H{
			"tasks": []database.ConversationPlanTask{}, "total": 0,
			"completed": 0, "activeStep": 0, "running": false,
		})
		return
	}
	tasks, err := h.db.ListConversationPlanTasksSince(id, startedAt)
	if err != nil {
		h.logger.Error("获取对话任务列表失败", zap.String("conversationId", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取任务列表失败"})
		return
	}

	completed := 0
	activeStep := 0
	for i, task := range tasks {
		status := strings.ToLower(strings.TrimSpace(task.Status))
		if status == "completed" {
			completed++
		}
		if activeStep == 0 && status == "in_progress" {
			activeStep = i + 1
		}
	}
	if activeStep == 0 {
		for i, task := range tasks {
			if strings.ToLower(strings.TrimSpace(task.Status)) != "completed" {
				activeStep = i + 1
				break
			}
		}
	}
	if activeStep == 0 && len(tasks) > 0 {
		activeStep = len(tasks)
	}

	c.JSON(http.StatusOK, gin.H{
		"tasks":      tasks,
		"total":      len(tasks),
		"completed":  completed,
		"activeStep": activeStep,
		"running":    true,
	})
}

const (
	defaultProcessDetailsPageLimit = 50
	maxProcessDetailsPageLimit     = 500
)

// GetMessageProcessDetails 获取指定消息的过程详情（按需加载）
// 查询参数：
//   - summary=1：仅返回摘要（total / iterationCount / maxIteration）
//   - limit + offset：分页返回 processDetails（未指定 limit 时默认 50 条）
//   - anchorId：返回包含该过程详情锚点的一页，适合从工具按钮精准定位
//   - full=1：显式返回全量 processDetails（用于导出/兼容旧集成，不建议 UI 展开时使用）
func (h *ConversationHandler) GetMessageProcessDetails(c *gin.Context) {
	messageID := c.Param("id")
	if messageID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "message id required"})
		return
	}

	summaryStr := strings.TrimSpace(c.Query("summary"))
	if summaryStr == "1" || strings.EqualFold(summaryStr, "true") || strings.EqualFold(summaryStr, "yes") {
		summary, err := h.db.GetProcessDetailsSummary(messageID)
		if err != nil {
			h.logger.Error("获取过程详情摘要失败", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"summary": summary})
		return
	}

	fullStr := strings.TrimSpace(c.Query("full"))
	if fullStr == "1" || strings.EqualFold(fullStr, "true") || strings.EqualFold(fullStr, "yes") {
		details, err := h.db.GetProcessDetails(messageID)
		if err != nil {
			h.logger.Error("获取过程详情失败", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		details = database.DedupeConsecutiveProcessDetails(details)
		out := processDetailsToJSON(h.logger, h.db, details, true)
		c.JSON(http.StatusOK, gin.H{
			"processDetails": out,
			"total":          len(out),
			"offset":         0,
			"limit":          len(out),
			"hasMore":        false,
		})
		return
	}

	limitStr := strings.TrimSpace(c.Query("limit"))
	limit := defaultProcessDetailsPageLimit
	if limitStr != "" {
		parsedLimit, err := strconv.Atoi(limitStr)
		if err != nil || parsedLimit <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limit"})
			return
		}
		limit = parsedLimit
	}
	if limit > maxProcessDetailsPageLimit {
		limit = maxProcessDetailsPageLimit
	}
	offset, _ := strconv.Atoi(strings.TrimSpace(c.Query("offset")))
	if offset < 0 {
		offset = 0
	}
	anchorID := strings.TrimSpace(c.Query("anchorId"))
	if anchorID != "" {
		anchorOffset, err := h.db.GetProcessDetailOffset(messageID, anchorID)
		if err != nil {
			h.logger.Warn("获取过程详情锚点位置失败", zap.Error(err), zap.String("messageID", messageID), zap.String("anchorID", anchorID))
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		offset = anchorOffset - limit/3
		if offset < 0 {
			offset = 0
		}
	}

	details, total, err := h.db.GetProcessDetailsPage(messageID, limit, offset)
	if err != nil {
		h.logger.Error("分页获取过程详情失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	details = database.DedupeConsecutiveProcessDetails(details)
	out := processDetailsToJSON(h.logger, h.db, details, false)
	// A page may end between tool_call and tool_result. Return the full-history
	// execution summary so the UI can render terminal status without pretending
	// that an unloaded result is still running.
	summary, summaryErr := h.db.GetProcessDetailsSummary(messageID)
	if summaryErr != nil {
		h.logger.Warn("获取分页工具执行状态失败", zap.Error(summaryErr), zap.String("messageID", messageID))
	}
	var toolExecutions []database.ProcessDetailsToolExecution
	if summary != nil {
		toolExecutions = summary.ToolExecutions
	}
	c.JSON(http.StatusOK, gin.H{
		"processDetails": out,
		"toolExecutions": toolExecutions,
		"total":          total,
		"offset":         offset,
		"limit":          limit,
		"hasMore":        offset+len(out) < total,
	})
}

// GetProcessDetail 获取单条完整过程详情。列表接口默认不给工具 payload，用户点开单条工具时再拉这里。
func (h *ConversationHandler) GetProcessDetail(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "process detail id required"})
		return
	}
	detail, err := h.db.GetProcessDetailByID(id)
	if err != nil {
		h.logger.Error("获取过程详情失败", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "过程详情不存在"})
		return
	}
	out := processDetailsToJSON(h.logger, h.db, []database.ProcessDetail{*detail}, true)
	if len(out) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "过程详情不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"processDetail": out[0]})
}

func processDetailsToJSON(logger *zap.Logger, db *database.DB, details []database.ProcessDetail, includeToolPayload bool) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(details))
	for _, d := range details {
		var data interface{}
		if d.Data != "" {
			if err := json.Unmarshal([]byte(d.Data), &data); err != nil {
				logger.Warn("解析过程详情数据失败", zap.Error(err))
			}
		}
		if m, ok := data.(map[string]interface{}); ok {
			enrichEmptyToolCallArgumentsFromExecution(logger, db, d, m)
		}
		if !includeToolPayload {
			data = summarizeProcessDetailData(d.EventType, data)
		}
		out = append(out, map[string]interface{}{
			"id":             d.ID,
			"messageId":      d.MessageID,
			"conversationId": d.ConversationID,
			"eventType":      d.EventType,
			"message":        d.Message,
			"data":           data,
			"createdAt":      d.CreatedAt,
		})
	}
	return out
}

func enrichEmptyToolCallArgumentsFromExecution(logger *zap.Logger, db *database.DB, detail database.ProcessDetail, data map[string]interface{}) {
	if db == nil || detail.EventType != "tool_call" || !toolCallArgumentsEmpty(data) {
		return
	}
	toolName := strings.TrimSpace(fmt.Sprint(data["toolName"]))
	if toolName == "" || detail.ConversationID == "" || detail.CreatedAt.IsZero() {
		return
	}
	execID, args, err := db.FindNearestToolExecutionArguments(detail.ConversationID, toolName, detail.CreatedAt, 5*time.Second)
	if err != nil {
		if logger != nil {
			logger.Debug("未能从工具执行记录补全过程详情参数",
				zap.Error(err),
				zap.String("processDetailId", detail.ID),
				zap.String("toolName", toolName))
		}
		return
	}
	if len(args) == 0 {
		return
	}
	data["argumentsObj"] = args
	if b, err := json.Marshal(args); err == nil {
		data["arguments"] = string(b)
	}
	if strings.TrimSpace(execID) != "" {
		data["executionId"] = strings.TrimSpace(execID)
	}
}

func toolCallArgumentsEmpty(data map[string]interface{}) bool {
	if data == nil {
		return true
	}
	if args, ok := data["argumentsObj"].(map[string]interface{}); ok && len(args) > 0 {
		return false
	}
	if raw, ok := data["arguments"]; ok {
		s := strings.TrimSpace(fmt.Sprint(raw))
		return s == "" || s == "{}" || s == "null"
	}
	return true
}

func summarizeProcessDetailData(eventType string, data interface{}) interface{} {
	m, ok := data.(map[string]interface{})
	if !ok || (eventType != "tool_call" && eventType != "tool_result") {
		return data
	}
	allow := map[string]bool{
		"toolName": true, "toolCallId": true, "index": true, "total": true,
		"arguments": true, "argumentsObj": true,
		"success": true, "isError": true, "executionId": true,
		"einoAgent": true, "einoRole": true, "einoScope": true, "orchestration": true,
		"agentFacing": true,
		"status":      true, "modelFacingIsError": true, "resultPreview": true,
	}
	out := make(map[string]interface{}, len(allow)+1)
	for k, v := range m {
		if allow[k] {
			out[k] = v
		}
	}
	out["_payloadDeferred"] = true
	return out
}

// UpdateConversationRequest 更新对话请求
type UpdateConversationRequest struct {
	Title string `json:"title"`
}

// UpdateConversation 更新对话
func (h *ConversationHandler) UpdateConversation(c *gin.Context) {
	id := c.Param("id")

	var req UpdateConversationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "标题不能为空"})
		return
	}

	if err := h.db.UpdateConversationTitle(id, req.Title); err != nil {
		h.logger.Error("更新对话失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 返回更新后的对话
	conv, err := h.db.GetConversation(id)
	if err != nil {
		h.logger.Error("获取更新后的对话失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, conv)
}

// DeleteConversation 删除对话
func (h *ConversationHandler) DeleteConversation(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	conversation, err := h.db.GetConversationLite(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}
	workspacePersistent := conversation.RuntimeMode == database.ConversationRuntimeModeContainer && conversation.WorkspacePersistent
	workspaceShared := false
	if workspacePersistent {
		if binding, bindingErr := h.db.GetConversationWorkspaceBinding(c.Request.Context(), id); bindingErr == nil {
			workspaceShared = binding.Mode == database.ConversationWorkspaceModeShared
		}
	}
	workspaceAction := strings.ToLower(strings.TrimSpace(c.Query("workspace_action")))
	if workspaceAction != "" && workspaceAction != "retain" && workspaceAction != "delete" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workspace_action 必须为 retain 或 delete"})
		return
	}
	if workspacePersistent && !workspaceShared && workspaceAction == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "删除持久工作区对话时必须明确选择 workspace_action=retain 或 delete"})
		return
	}
	if !workspacePersistent && workspaceAction == "retain" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该对话没有可保留的持久工作区"})
		return
	}
	if workspaceAction == "" {
		workspaceAction = "delete"
	}
	if workspaceShared {
		// A shared workspace is an independent resource. Removing one chat only
		// detaches it and must never delete the volume used by other chats.
		workspaceAction = "retain"
	}

	if h.taskStopper != nil {
		h.taskStopper.CancelRunningTaskForConversation(id)
	}

	removeWorkspace := workspaceAction == "delete"
	if conversation.RuntimeMode == database.ConversationRuntimeModeContainer {
		if err := h.deleteConversationRuntime(c.Request.Context(), id, workspacePersistent, removeWorkspace); err != nil {
			h.writeContainerLifecycleError(c, id, "delete_conversation", err)
			return
		}
	}

	retainDedicatedWorkspace := workspacePersistent && !workspaceShared && !removeWorkspace
	if err := h.db.DeleteConversationWithWorkspaceRetention(id, retainDedicatedWorkspace); err != nil {
		h.logger.Error("删除对话失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category:     "conversation",
			Action:       "delete",
			Result:       "success",
			ResourceType: "conversation",
			ResourceID:   id,
			Message:      "删除对话",
			Detail: map[string]interface{}{
				"workspace_action":     workspaceAction,
				"workspace_persistent": workspacePersistent,
				"workspace_retained":   workspacePersistent && !removeWorkspace,
				"workspace_deleted":    workspacePersistent && removeWorkspace,
			},
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message":             "删除成功",
		"conversationId":      id,
		"workspaceAction":     workspaceAction,
		"workspacePersistent": workspacePersistent,
		"workspaceRetained":   workspacePersistent && !removeWorkspace,
		"workspaceDeleted":    workspacePersistent && removeWorkspace,
		"workspaceShared":     workspaceShared,
	})
}

func (h *ConversationHandler) deleteConversationRuntime(ctx context.Context, conversationID string, workspacePersistent, removeWorkspace bool) error {
	if h.containerInitializations == nil {
		if workspacePersistent && removeWorkspace {
			if h.retainedWorkspace == nil {
				return containerruntime.ErrEngineUnavailable
			}
			return h.retainedWorkspace.DeleteRetainedWorkspace(ctx, conversationID)
		}
		return nil
	}
	record, err := h.containerInitializations.Get(ctx, conversationID)
	if err != nil {
		if !errors.Is(err, containerruntime.ErrNotFound) {
			return err
		}
		if workspacePersistent && removeWorkspace {
			if h.retainedWorkspace == nil {
				return containerruntime.ErrEngineUnavailable
			}
			return h.retainedWorkspace.DeleteRetainedWorkspace(ctx, conversationID)
		}
		return nil
	}
	if record.Status == containerruntime.InitializationQueued || record.Status == containerruntime.InitializationCreating {
		return fmt.Errorf("%w: runtime initialization is %s", containerruntime.ErrRuntimeStateConflict, record.Status)
	}
	if record.Status == containerruntime.InitializationFailed {
		if workspacePersistent && removeWorkspace {
			if h.retainedWorkspace == nil {
				return containerruntime.ErrEngineUnavailable
			}
			return h.retainedWorkspace.DeleteRetainedWorkspace(ctx, conversationID)
		}
		return nil
	}
	if h.containerLifecycle == nil {
		return containerruntime.ErrEngineUnavailable
	}
	if record.RuntimeStatus == containerruntime.StatusRunning || record.RuntimeStatus == containerruntime.StatusStarting {
		if _, err := h.containerLifecycle.Stop(ctx, conversationID); err != nil {
			return err
		}
	}
	return h.containerLifecycle.Delete(ctx, conversationID, workspacePersistent && removeWorkspace)
}

// DeleteTurnRequest 删除一轮对话（POST /api/conversations/:id/delete-turn）
type DeleteTurnRequest struct {
	MessageID string `json:"messageId"`
}

// DeleteConversationTurn 删除锚点消息所在轮次（从该轮 user 到下一轮 user 之前），并清空 last_react_*。
func (h *ConversationHandler) DeleteConversationTurn(c *gin.Context) {
	conversationID := c.Param("id")
	if conversationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "conversation id required"})
		return
	}

	var req DeleteTurnRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.MessageID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "messageId required"})
		return
	}

	if _, err := h.db.GetConversation(conversationID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}

	deletedIDs, err := h.db.DeleteConversationTurn(conversationID, req.MessageID)
	if err != nil {
		h.logger.Warn("删除对话轮次失败",
			zap.String("conversationId", conversationID),
			zap.String("messageId", req.MessageID),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.audit != nil {
		h.audit.RecordOK(c, "conversation", "delete_turn", "删除对话轮次", "conversation", conversationID, map[string]interface{}{
			"message_id": req.MessageID,
			"deleted":    len(deletedIDs),
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"deletedMessageIds": deletedIDs,
		"message":           "ok",
	})
}
