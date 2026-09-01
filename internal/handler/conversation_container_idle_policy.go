package handler

import (
	"net/http"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/database"
	"github.com/gin-gonic/gin"
)

type updateConversationIdlePolicyRequest struct {
	Action         string `json:"action"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

func (h *ConversationHandler) GetConversationContainerIdlePolicy(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	policy, err := h.db.GetConversationIdlePolicy(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取容器空闲策略失败"})
		return
	}
	conversation, err := h.db.GetConversationLite(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"conversationId": id,
		"idlePolicy":     policy,
		"idleExpiresAt":  database.ConversationIdleExpiresAt(conversation.UpdatedAt, policy),
	})
}

func (h *ConversationHandler) UpdateConversationContainerIdlePolicy(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	var request updateConversationIdlePolicyRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数无效"})
		return
	}
	policy, err := database.NormalizeConversationIdlePolicy(database.ConversationIdlePolicy{
		Action: request.Action, TimeoutSeconds: request.TimeoutSeconds,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	policy, err = h.db.SetConversationIdlePolicy(c.Request.Context(), id, policy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存容器空闲策略失败"})
		return
	}
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category: "container", Action: "update-idle-policy", Result: "success",
			ResourceType: "conversation", ResourceID: id, Message: "更新对话容器空闲策略",
			Detail: map[string]interface{}{"action": policy.Action, "timeout_seconds": policy.TimeoutSeconds},
		})
	}
	conversation, err := h.db.GetConversationLite(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"conversationId": id,
		"idlePolicy":     policy,
		"idleExpiresAt":  database.ConversationIdleExpiresAt(conversation.UpdatedAt, policy),
	})
}
