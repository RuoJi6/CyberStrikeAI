package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/asm"
	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type ASMHandler struct {
	service      *asm.Service
	logger       *zap.Logger
	audit        *audit.Service
	db           *database.DB
	agentHandler *AgentHandler
}

func NewASMHandler(service *asm.Service, logger *zap.Logger) *ASMHandler {
	return &ASMHandler{service: service, logger: logger}
}

func (h *ASMHandler) SetAudit(service *audit.Service) { h.audit = service }

// SetAgentProvisioning wires task-center scans to durable Agent conversations.
func (h *ASMHandler) SetAgentProvisioning(db *database.DB, agentHandler *AgentHandler) {
	h.db = db
	h.agentHandler = agentHandler
}

type asmResourceRequest struct {
	Name              string                         `json:"name" binding:"required"`
	Provider          string                         `json:"provider" binding:"required"`
	BaseURL           string                         `json:"base_url" binding:"required"`
	Username          string                         `json:"username"`
	Credential        string                         `json:"credential"`
	AuthType          string                         `json:"auth_type"`
	VerifyTLS         *bool                          `json:"verify_tls"`
	Enabled           *bool                          `json:"enabled"`
	AgentContinuation *asm.AgentContinuationSettings `json:"agent_continuation"`
}

type asmResourcePatchRequest struct {
	Name              *string                        `json:"name"`
	Provider          *string                        `json:"provider"`
	BaseURL           *string                        `json:"base_url"`
	Username          *string                        `json:"username"`
	Credential        *string                        `json:"credential"`
	AuthType          *string                        `json:"auth_type"`
	VerifyTLS         *bool                          `json:"verify_tls"`
	Enabled           *bool                          `json:"enabled"`
	AgentContinuation *asm.AgentContinuationSettings `json:"agent_continuation"`
}

type asmTaskRequest struct {
	Name         string                      `json:"name"`
	Target       string                      `json:"target" binding:"required"`
	Options      map[string]interface{}      `json:"options"`
	AgentTrigger *asmTaskAgentTriggerRequest `json:"agent_trigger"`
}

type asmTaskAgentTriggerRequest struct {
	Enabled        bool   `json:"enabled"`
	ProjectID      string `json:"project_id"`
	RoleName       string `json:"role_name"`
	AgentMode      string `json:"agent_mode"`
	ReviewMode     string `json:"review_mode"`
	Reviewer       string `json:"reviewer"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	Prompt         string `json:"prompt"`
}

type asmTemplateRequest struct {
	Name           string                 `json:"name"`
	PresetID       string                 `json:"preset_id"`
	BaseTemplateID string                 `json:"base_template_id"`
	Options        map[string]interface{} `json:"options"`
}

func (h *ASMHandler) List(c *gin.Context) {
	items, err := h.service.ListResources(false)
	if err != nil {
		h.logger.Error("查询 ASM 资源失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"resources": items, "providers": h.service.Providers()})
}

func (h *ASMHandler) Create(c *gin.Context) {
	var req asmResourceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数: " + err.Error()})
		return
	}
	item, err := h.service.CreateResource(asm.CreateResourceInput{
		Name: req.Name, Provider: req.Provider, BaseURL: req.BaseURL,
		Username: req.Username, Credential: req.Credential, AuthType: req.AuthType,
		VerifyTLS: req.VerifyTLS, Enabled: req.Enabled, AgentContinuation: req.AgentContinuation,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{Category: "asm", Action: "create", Result: "success", ResourceType: "asm_resource", ResourceID: item.ID, Message: "创建 ASM 资源", Detail: map[string]interface{}{"provider": item.Provider, "name": item.Name}})
	}
	c.JSON(http.StatusCreated, item)
}

func (h *ASMHandler) Update(c *gin.Context) {
	var req asmResourcePatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数: " + err.Error()})
		return
	}
	item, err := h.service.UpdateResource(c.Param("id"), asm.UpdateResourceInput{
		Name: req.Name, Provider: req.Provider, BaseURL: req.BaseURL,
		Username: req.Username, Credential: req.Credential, AuthType: req.AuthType,
		VerifyTLS: req.VerifyTLS, Enabled: req.Enabled, AgentContinuation: req.AgentContinuation,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{Category: "asm", Action: "update", Result: "success", ResourceType: "asm_resource", ResourceID: item.ID, Message: "更新 ASM 资源", Detail: map[string]interface{}{"provider": item.Provider, "name": item.Name}})
	}
	c.JSON(http.StatusOK, item)
}

func (h *ASMHandler) Delete(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if err := h.service.DeleteResource(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{Category: "asm", Action: "delete", Result: "success", ResourceType: "asm_resource", ResourceID: id, Message: "删除 ASM 资源"})
	}
	c.JSON(http.StatusOK, gin.H{"message": "ASM 资源已删除"})
}

func (h *ASMHandler) Test(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	result, err := h.service.TestConnection(c.Request.Context(), id)
	if err != nil {
		if h.audit != nil {
			h.audit.Record(c, audit.Entry{Category: "asm", Action: "test", Result: "failure", ResourceType: "asm_resource", ResourceID: id, Message: "ASM 连接测试失败", Detail: map[string]interface{}{"error": err.Error()}})
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{Category: "asm", Action: "test", Result: "success", ResourceType: "asm_resource", ResourceID: id, Message: "ASM 连接测试成功"})
	}
	c.JSON(http.StatusOK, gin.H{"message": "连接成功", "result": result})
}

func (h *ASMHandler) TaskProfile(c *gin.Context) {
	result, err := h.service.GetTaskProfile(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *ASMHandler) TaskOptions(c *gin.Context) {
	result, err := h.service.ListTaskOptions(c.Request.Context(), c.Param("id"), asm.TaskOptionFilter{
		Kind: c.Query("kind"), Query: c.Query("query"), ID: c.Query("option_id"),
		Page: asmQueryInt(c, "page", 1), PageSize: asmQueryInt(c, "page_size", 100),
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *ASMHandler) CreateTask(c *gin.Context) {
	var req asmTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的任务参数: " + err.Error()})
		return
	}
	if err := h.validateTaskAgentTrigger(c, req.AgentTrigger); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resourceID := strings.TrimSpace(c.Param("id"))
	creationSource := "task_center"
	if req.AgentTrigger != nil && req.AgentTrigger.Enabled {
		creationSource = "task_center_auto_agent"
	}
	result, err := h.service.CreateTask(c.Request.Context(), resourceID, asm.TaskRequest{
		Name: req.Name, Target: req.Target, Options: req.Options, CreationSource: creationSource,
	})
	if err != nil {
		if h.audit != nil {
			h.audit.Record(c, audit.Entry{Category: "asm", Action: "create_task", Result: "failure", ResourceType: "asm_resource", ResourceID: resourceID, Message: "手动创建 ASM 任务失败", Detail: map[string]interface{}{"error": err.Error()}})
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if req.AgentTrigger != nil && req.AgentTrigger.Enabled {
		result, err = h.provisionTaskCenterAgent(c, resourceID, req, result)
		if err != nil {
			h.logger.Error("创建 ASM 任务成功，但配置自动 Agent 失败", zap.String("resource_id", resourceID), zap.Error(err))
			object := asmTaskResultObject(result)
			object["agent_continuation"] = map[string]interface{}{
				"status": "failed", "trigger_source": "task_center", "message": err.Error(),
			}
			result = object
		}
	}
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{Category: "asm", Action: "create_task", Result: "success", ResourceType: "asm_resource", ResourceID: resourceID, Message: "从 ASM 任务中心创建任务", Detail: map[string]interface{}{"name": req.Name, "target": req.Target}})
	}
	c.JSON(http.StatusCreated, result)
}

func asmTaskResultObject(value interface{}) map[string]interface{} {
	if object, ok := value.(map[string]interface{}); ok {
		return object
	}
	raw, _ := json.Marshal(value)
	object := map[string]interface{}{}
	_ = json.Unmarshal(raw, &object)
	return object
}

func (h *ASMHandler) validateTaskAgentTrigger(c *gin.Context, trigger *asmTaskAgentTriggerRequest) error {
	if trigger == nil || !trigger.Enabled {
		return nil
	}
	if h.db == nil || h.agentHandler == nil {
		return fmt.Errorf("Agent 自动分析服务尚未就绪")
	}
	session, ok := security.CurrentSession(c)
	if !ok || strings.TrimSpace(session.UserID) == "" {
		return fmt.Errorf("需要登录后才能配置 Agent 自动分析")
	}
	for _, permission := range []string{"agent:execute", "chat:read", "chat:write"} {
		if !session.Permissions[permission] {
			return fmt.Errorf("当前用户缺少 %s 权限", permission)
		}
	}
	projectID := strings.TrimSpace(trigger.ProjectID)
	if projectID != "" && (!session.Permissions["project:read"] || !h.db.UserCanAccessResource(session.UserID, session.Scope, "project", projectID)) {
		return fmt.Errorf("无权在所选项目中创建 Agent 对话")
	}
	mode := strings.ToLower(strings.TrimSpace(trigger.AgentMode))
	if mode == "" {
		mode = "eino_single"
	}
	switch mode {
	case "eino_single":
	case "deep", "plan_execute", "supervisor":
		if h.agentHandler.config == nil || !h.agentHandler.config.MultiAgent.Enabled {
			return fmt.Errorf("当前系统未启用 Eino 多代理，不能使用 %s 模式", mode)
		}
	default:
		return fmt.Errorf("不支持的 Agent 模式: %s", mode)
	}
	role := strings.TrimSpace(trigger.RoleName)
	if role != "" && role != "默认" {
		if h.agentHandler.config == nil || h.agentHandler.config.Roles == nil {
			return fmt.Errorf("角色 %s 不存在", role)
		}
		cfg, exists := h.agentHandler.config.Roles[role]
		if !exists || !cfg.Enabled {
			return fmt.Errorf("角色 %s 不存在或未启用", role)
		}
	}
	reviewMode := strings.ToLower(strings.TrimSpace(trigger.ReviewMode))
	if reviewMode == "" {
		reviewMode = "off"
	}
	if reviewMode != "off" && reviewMode != "approval" && reviewMode != "review_edit" {
		return fmt.Errorf("不支持的审查模式: %s", reviewMode)
	}
	reviewer := strings.ToLower(strings.TrimSpace(trigger.Reviewer))
	if reviewer == "" {
		reviewer = "human"
	}
	if reviewer != "human" && reviewer != "audit_agent" {
		return fmt.Errorf("不支持的审批方: %s", reviewer)
	}
	if trigger.TimeoutSeconds < 0 || trigger.TimeoutSeconds > 86400 {
		return fmt.Errorf("审批等待时限必须在 0 到 86400 秒之间")
	}
	if len([]rune(strings.TrimSpace(trigger.Prompt))) > 8000 {
		return fmt.Errorf("Agent 提示词不能超过 8000 个字符")
	}
	return nil
}

func (h *ASMHandler) provisionTaskCenterAgent(c *gin.Context, resourceID string, req asmTaskRequest, result interface{}) (interface{}, error) {
	trigger := req.AgentTrigger
	session, ok := security.CurrentSession(c)
	if trigger == nil || !trigger.Enabled || !ok {
		return result, nil
	}
	mode := strings.ToLower(strings.TrimSpace(trigger.AgentMode))
	if mode == "" {
		mode = "eino_single"
	}
	role := strings.TrimSpace(trigger.RoleName)
	if role == "" {
		role = "默认"
	}
	titleSource := strings.TrimSpace(req.Name)
	if titleSource == "" {
		titleSource = strings.TrimSpace(req.Target)
	}
	meta := audit.ConversationCreateMeta("asm_task_center_auto_agent")
	meta.ProjectID = strings.TrimSpace(trigger.ProjectID)
	meta.RoleName = role
	meta.AgentMode = mode
	meta.ClientIP = c.ClientIP()
	conv, err := h.db.CreateConversation(safeTruncateString("ASM 自动分析 · "+titleSource, 100), meta)
	if err != nil {
		return result, fmt.Errorf("创建自动分析对话失败: %w", err)
	}
	cleanup := func() {
		_, _ = h.db.Exec("DELETE FROM hitl_conversation_configs WHERE conversation_id = ?", conv.ID)
		_ = h.db.DeleteConversation(conv.ID)
	}
	if err = h.db.SetResourceOwner("conversation", conv.ID, session.UserID); err != nil {
		cleanup()
		return result, fmt.Errorf("设置自动分析对话所属用户失败: %w", err)
	}
	if err = h.db.AssignResourceToUser(session.UserID, "conversation", conv.ID); err != nil {
		cleanup()
		return result, fmt.Errorf("授权自动分析对话失败: %w", err)
	}
	reviewMode := strings.ToLower(strings.TrimSpace(trigger.ReviewMode))
	if reviewMode == "" {
		reviewMode = "off"
	}
	reviewer := strings.ToLower(strings.TrimSpace(trigger.Reviewer))
	if reviewer == "" {
		reviewer = "human"
	}
	if h.agentHandler.hitlManager != nil {
		hitl := &HITLRequest{
			Enabled: reviewMode != "off", Mode: reviewMode, Reviewer: reviewer,
			TimeoutSeconds: trigger.TimeoutSeconds, SensitiveTools: []string{},
		}
		if err = h.agentHandler.hitlManager.SaveConversationConfig(conv.ID, hitl); err != nil {
			cleanup()
			return result, fmt.Errorf("保存自动分析审查设置失败: %w", err)
		}
	}
	linked, err := h.service.AttachManualAgentContinuation(resourceID, result, asm.ManualAgentContinuationInput{
		ConversationID: conv.ID, OwnerUserID: session.UserID, Prompt: trigger.Prompt,
	})
	if err != nil {
		cleanup()
		return result, fmt.Errorf("创建 Agent 联动失败: %w", err)
	}
	return linked, nil
}

func (h *ASMHandler) CreateTemplate(c *gin.Context) {
	var req asmTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的模板参数: " + err.Error()})
		return
	}
	resourceID := strings.TrimSpace(c.Param("id"))
	result, err := h.service.CreateTemplate(c.Request.Context(), resourceID, asm.TemplateRequest{
		Name: req.Name, PresetID: req.PresetID, BaseTemplateID: req.BaseTemplateID, Options: req.Options,
	})
	if err != nil {
		if h.audit != nil {
			h.audit.Record(c, audit.Entry{Category: "asm", Action: "create_template", Result: "failure", ResourceType: "asm_resource", ResourceID: resourceID, Message: "创建 ASM 扫描模板失败", Detail: map[string]interface{}{"name": req.Name, "preset_id": req.PresetID, "error": err.Error()}})
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{Category: "asm", Action: "create_template", Result: "success", ResourceType: "asm_resource", ResourceID: resourceID, Message: "创建 ASM 扫描模板", Detail: map[string]interface{}{"name": req.Name, "preset_id": req.PresetID, "base_template_id": req.BaseTemplateID}})
	}
	c.JSON(http.StatusCreated, result)
}

func asmQueryInt(c *gin.Context, key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(c.Query(key)))
	if err != nil || value < 1 {
		return fallback
	}
	return value
}

func (h *ASMHandler) ListTaskHistory(c *gin.Context) {
	page, err := h.service.ListTaskHistory(asm.TaskHistoryFilter{
		Provider: c.Query("provider"), ResourceID: c.Query("resource_id"),
		Status: c.Query("status"), Query: c.Query("query"),
		Page: asmQueryInt(c, "page", 1), PageSize: asmQueryInt(c, "page_size", 20),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, page)
}

func (h *ASMHandler) ListAgentContinuations(c *gin.Context) {
	access := database.RBACListAccess{}
	if session, ok := security.CurrentSession(c); ok {
		access = database.RBACListAccess{UserID: session.UserID, Scope: session.Scope}
	}
	statuses := make([]string, 0)
	for _, value := range strings.Split(c.Query("status"), ",") {
		if status := strings.TrimSpace(value); status != "" {
			statuses = append(statuses, status)
		}
	}
	page, err := h.service.ListAgentContinuations(asm.AgentContinuationHistoryFilter{
		Statuses: statuses, Query: c.Query("query"),
		Page: asmQueryInt(c, "page", 1), PageSize: asmQueryInt(c, "page_size", 50), Access: access,
	})
	if err != nil {
		h.logger.Error("查询 ASM Agent 联动状态失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, page)
}

func (h *ASMHandler) GetTaskHistory(c *gin.Context) {
	item, err := h.service.GetTaskHistory(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, item)
}

func (h *ASMHandler) SyncTaskHistory(c *gin.Context) {
	item, err := h.service.SyncTaskHistory(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "task": item})
		return
	}
	c.JSON(http.StatusOK, item)
}

func (h *ASMHandler) StopTaskHistory(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	item, err := h.service.StopTaskHistory(c.Request.Context(), id)
	if err != nil {
		if h.audit != nil {
			h.audit.Record(c, audit.Entry{Category: "asm", Action: "stop_task", Result: "failure", ResourceType: "asm_task", ResourceID: id, Message: "停止 ASM 任务失败", Detail: map[string]interface{}{"error": err.Error()}})
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "task": item})
		return
	}
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{Category: "asm", Action: "stop_task", Result: "success", ResourceType: "asm_task", ResourceID: id, Message: "从 ASM 任务中心停止任务"})
	}
	c.JSON(http.StatusOK, item)
}

func (h *ASMHandler) TaskHistoryResults(c *gin.Context) {
	result, err := h.service.ListTaskHistoryResults(c.Request.Context(), c.Param("id"), asm.AssetFilter{
		Type: c.Query("asset_type"), Query: c.Query("query"),
		Page: asmQueryInt(c, "page", 1), PageSize: asmQueryInt(c, "page_size", 50),
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *ASMHandler) TaskHistoryResultDetail(c *gin.Context) {
	result, err := h.service.GetTaskHistoryResultDetail(c.Request.Context(), c.Param("id"), asm.AssetDetailFilter{
		Type: c.Query("asset_type"), Key: c.Query("key"),
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *ASMHandler) SyncTaskResults(c *gin.Context) {
	result, err := h.service.RequestTaskResultsSync(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, result)
}

func (h *ASMHandler) SyncTaskScreenshots(c *gin.Context) {
	result, err := h.service.SyncTaskScreenshots(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "result": result})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *ASMHandler) ScreenshotContent(c *gin.Context) {
	item, err := h.service.GetScreenshotFile(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Type", item.ContentType)
	c.Header("Content-Disposition", "inline")
	c.Header("Cache-Control", "private, max-age=3600")
	c.Header("X-Content-Type-Options", "nosniff")
	c.File(item.FilePath)
}
