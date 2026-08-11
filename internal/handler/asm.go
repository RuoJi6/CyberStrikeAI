package handler

import (
	"net/http"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/asm"
	"cyberstrike-ai/internal/audit"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type ASMHandler struct {
	service *asm.Service
	logger  *zap.Logger
	audit   *audit.Service
}

func NewASMHandler(service *asm.Service, logger *zap.Logger) *ASMHandler {
	return &ASMHandler{service: service, logger: logger}
}

func (h *ASMHandler) SetAudit(service *audit.Service) { h.audit = service }

type asmResourceRequest struct {
	Name       string `json:"name" binding:"required"`
	Provider   string `json:"provider" binding:"required"`
	BaseURL    string `json:"base_url" binding:"required"`
	Username   string `json:"username"`
	Credential string `json:"credential"`
	AuthType   string `json:"auth_type"`
	VerifyTLS  *bool  `json:"verify_tls"`
	Enabled    *bool  `json:"enabled"`
}

type asmResourcePatchRequest struct {
	Name       *string `json:"name"`
	Provider   *string `json:"provider"`
	BaseURL    *string `json:"base_url"`
	Username   *string `json:"username"`
	Credential *string `json:"credential"`
	AuthType   *string `json:"auth_type"`
	VerifyTLS  *bool   `json:"verify_tls"`
	Enabled    *bool   `json:"enabled"`
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
		VerifyTLS: req.VerifyTLS, Enabled: req.Enabled,
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
		VerifyTLS: req.VerifyTLS, Enabled: req.Enabled,
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
