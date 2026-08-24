package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type conversationEgressAuditSettingRequest struct {
	Enabled *bool `json:"enabled" binding:"required"`
}

func (h *ConversationHandler) GetConversationEgressAuditSetting(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	enabled, err := h.db.GetConversationEgressAuditEnabled(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取对话出站审计设置失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"conversationId": id, "enabled": enabled})
}

func (h *ConversationHandler) UpdateConversationEgressAuditSetting(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	var request conversationEgressAuditSettingRequest
	if err := c.ShouldBindJSON(&request); err != nil || request.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enabled 必须为布尔值"})
		return
	}
	if err := h.db.SetConversationEgressAuditEnabled(c.Request.Context(), id, *request.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新对话出站审计设置失败"})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "container", "update-egress-audit", "更新对话出站审计设置", "conversation", id, map[string]interface{}{
			"enabled": *request.Enabled,
		})
	}
	c.JSON(http.StatusOK, gin.H{"conversationId": id, "enabled": *request.Enabled})
}
