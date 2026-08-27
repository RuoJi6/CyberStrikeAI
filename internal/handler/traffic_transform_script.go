package handler

import (
	"database/sql"
	"net/http"
	"strings"

	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/traffictransform"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type updateTrafficTransformRequest struct {
	BaseRevisionID string `json:"baseRevisionId"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	Source         string `json:"source"`
}

// UpdateTrafficTransform edits mutable metadata and, when source changes,
// creates and validates a new immutable revision before atomically promoting
// it to the script's observe-mode bindings.
func (h *TrafficHandler) UpdateTrafficTransform(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	if !session.Permissions["traffic_transform:read_source"] {
		c.JSON(http.StatusForbidden, gin.H{"error": "编辑脚本源码需要 traffic_transform:read_source 权限"})
		return
	}
	transform, err := h.db.GetTrafficTransform(c.Request.Context(), strings.TrimSpace(c.Param("id")))
	if err != nil || !h.canAccessTransform(session, transform, "traffic_transform:write") || !h.canAccessTransform(session, transform, "traffic_transform:read_source") {
		c.JSON(http.StatusNotFound, gin.H{"error": "脚本不存在"})
		return
	}
	var request updateTrafficTransformRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "脚本更新请求无效"})
		return
	}
	request.BaseRevisionID = strings.TrimSpace(request.BaseRevisionID)
	if request.BaseRevisionID == "" || (transform.CurrentRevisionID != "" && request.BaseRevisionID != transform.CurrentRevisionID) {
		c.JSON(http.StatusConflict, gin.H{"error": "脚本已产生新版本，请刷新后重试"})
		return
	}
	baseRevision, err := h.db.GetTrafficTransformRevision(c.Request.Context(), request.BaseRevisionID)
	if err != nil || baseRevision.TransformID != transform.ID || baseRevision.ValidationStatus != traffictransform.ValidationPassed {
		c.JSON(http.StatusConflict, gin.H{"error": "当前脚本版本不存在或尚未通过验证"})
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	request.Description = strings.TrimSpace(request.Description)
	if request.Source == baseRevision.Source {
		updated, updateErr := h.db.UpdateTrafficTransformMetadata(c.Request.Context(), transform.ID, request.Name, request.Description)
		if updateErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": updateErr.Error()})
			return
		}
		baseRevision.Source = ""
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{"transform": updated, "revision": baseRevision})
		return
	}
	if h.transformRunner == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Traffic Transform Runner 未配置"})
		return
	}
	prepared, staticReport := traffictransform.PrepareRevision(traffictransform.Revision{
		ID: uuid.NewString(), TransformID: transform.ID, Source: request.Source,
		Hooks:        append([]traffictransform.Hook(nil), baseRevision.Hooks...),
		Requirements: append([]string(nil), baseRevision.Requirements...),
	}, traffictransform.DefaultRunnerInventory())
	if !staticReport.Valid {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "脚本静态检查未通过", "validation": staticReport})
		return
	}
	loaded, err := h.transformRunner.LoadRevision(c.Request.Context(), prepared)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Runner 验证失败: " + err.Error()})
		return
	}
	revision, _, err := h.db.CreateTrafficTransformRevision(c.Request.Context(), &prepared, traffictransform.DefaultRunnerInventory())
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "无法创建脚本版本: " + err.Error()})
		return
	}
	validation := traffictransform.ValidationReport{
		Valid: true, SourceSHA256: revision.SourceSHA256,
		Hooks: append([]traffictransform.Hook(nil), loaded.Hooks...), Runner: loaded.RunnerGeneration,
	}
	if err := h.db.SetTrafficTransformRevisionValidation(c.Request.Context(), revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, validation); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "写入验证结果失败"})
		return
	}
	revision.ValidationStatus = traffictransform.ValidationPassed
	updated, err := h.db.PromoteTrafficTransformRevision(c.Request.Context(), transform.ID, revision.ID, request.Name, request.Description)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "无法启用新版本: " + err.Error()})
		return
	}
	revision.Source = ""
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"transform": updated, "revision": revision, "validation": validation})
}

// DeleteTrafficTransform hides a script from management after all scopes are
// removed. The database keeps immutable revisions and run evidence.
func (h *TrafficHandler) DeleteTrafficTransform(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	transform, err := h.db.GetTrafficTransform(c.Request.Context(), strings.TrimSpace(c.Param("id")))
	if err != nil || !h.canAccessTransform(session, transform, "traffic_transform:write") {
		c.JSON(http.StatusNotFound, gin.H{"error": "脚本不存在"})
		return
	}
	if err := h.db.DeleteTrafficTransform(c.Request.Context(), transform.ID); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "脚本不存在"})
			return
		}
		c.JSON(http.StatusConflict, gin.H{"error": "请先停用并删除该脚本的全部作用范围"})
		return
	}
	c.Status(http.StatusNoContent)
}
