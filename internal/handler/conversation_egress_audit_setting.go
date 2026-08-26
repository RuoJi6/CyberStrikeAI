package handler

import (
	"net/http"

	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
)

type conversationEgressAuditSettingRequest struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Mode    string `json:"mode,omitempty"`
}

func (h *ConversationHandler) GetConversationEgressAuditSetting(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	setting, err := h.db.GetConversationEgressAuditSetting(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取对话出站审计设置失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"conversationId": id, "enabled": setting.Enabled, "mode": setting.Mode})
}

func (h *ConversationHandler) UpdateConversationEgressAuditSetting(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	var request conversationEgressAuditSettingRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "出站审计设置格式无效"})
		return
	}
	mode := request.Mode
	if mode == "" && request.Enabled != nil {
		if *request.Enabled {
			current, err := h.db.GetConversationEgressAuditSetting(c.Request.Context(), id)
			if err == nil && current.Mode == database.EgressAuditModeFull {
				mode = database.EgressAuditModeFull
			} else {
				mode = database.EgressAuditModeCompact
			}
		} else {
			mode = database.EgressAuditModeOff
		}
	}
	mode, err := database.NormalizeConversationEgressAuditMode(mode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode 必须为 compact、full 或 off"})
		return
	}
	if err := h.db.SetConversationEgressAuditMode(c.Request.Context(), id, mode); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新对话出站审计设置失败"})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "container", "update-egress-audit", "更新对话出站审计设置", "conversation", id, map[string]interface{}{
			"enabled": mode != database.EgressAuditModeOff,
			"mode":    mode,
		})
	}
	c.JSON(http.StatusOK, gin.H{"conversationId": id, "enabled": mode != database.EgressAuditModeOff, "mode": mode})
}
