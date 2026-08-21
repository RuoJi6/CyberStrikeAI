package handler

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type ConversationEgressRequest struct {
	Mode               string `json:"mode"`
	EgressProxyID      string `json:"egressProxyId,omitempty"`
	EgressProxyGroupID string `json:"egressProxyGroupId,omitempty"`
}

type conversationEgressRequestError struct {
	Status  int
	Message string
}

func (e *conversationEgressRequestError) Error() string { return e.Message }

func normalizeConversationEgressForSession(
	ctx context.Context,
	db *database.DB,
	session security.Session,
	runtimeMode, mode, proxyID, proxyGroupID string,
) (normalizedMode, normalizedProxyID, normalizedProxyGroupID string, configured bool, requestErr *conversationEgressRequestError) {
	mode, proxyID, proxyGroupID, configured, err := database.NormalizeConversationEgressSelection(mode, proxyID, proxyGroupID)
	if err != nil {
		return "", "", "", false, &conversationEgressRequestError{Status: http.StatusBadRequest, Message: err.Error()}
	}
	if !configured {
		return "", "", "", false, nil
	}
	if runtimeMode != database.ConversationRuntimeModeContainer {
		return "", "", "", false, &conversationEgressRequestError{Status: http.StatusBadRequest, Message: "egress 只能用于 container 对话"}
	}
	if !session.Permissions["egress:read"] {
		return "", "", "", false, &conversationEgressRequestError{Status: http.StatusForbidden, Message: "缺少 egress:read 权限"}
	}
	resourceType, resourceID := "", ""
	switch mode {
	case database.ConversationEgressModeProxy:
		resourceType, resourceID = "egress_proxy", proxyID
		if _, err := db.GetEgressProxy(ctx, resourceID); err != nil {
			status := http.StatusInternalServerError
			message := "读取上游代理失败"
			if errors.Is(err, database.ErrEgressProxyNotFound) || errors.Is(err, sql.ErrNoRows) {
				status, message = http.StatusNotFound, "上游代理不存在"
			}
			return "", "", "", false, &conversationEgressRequestError{Status: status, Message: message}
		}
	case database.ConversationEgressModeGroup:
		resourceType, resourceID = "egress_proxy_group", proxyGroupID
		if _, err := db.GetEgressProxyGroup(ctx, resourceID); err != nil {
			status := http.StatusInternalServerError
			message := "读取上游代理组失败"
			if errors.Is(err, database.ErrEgressProxyGroupNotFound) || errors.Is(err, sql.ErrNoRows) {
				status, message = http.StatusNotFound, "上游代理组不存在"
			}
			return "", "", "", false, &conversationEgressRequestError{Status: status, Message: message}
		}
	}
	if resourceID != "" && !db.UserCanAccessResource(session.UserID, session.ScopeFor("egress:read"), resourceType, resourceID) {
		return "", "", "", false, &conversationEgressRequestError{Status: http.StatusForbidden, Message: "无权访问该上游出口资源"}
	}
	return mode, proxyID, proxyGroupID, true, nil
}

func (h *ConversationHandler) conversationEgressAccess(c *gin.Context, permission string) (security.Session, string, bool) {
	conversationID := strings.TrimSpace(c.Param("id"))
	session, ok := security.CurrentSession(c)
	if !ok || !session.Permissions[permission] || !h.db.UserCanAccessResource(session.UserID, session.ScopeFor(permission), "conversation", conversationID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该对话"})
		return security.Session{}, "", false
	}
	return session, conversationID, true
}

// GetConversationEgress returns the editable pre-start selection or the
// immutable binding that was frozen before container initialization.
func (h *ConversationHandler) GetConversationEgress(c *gin.Context) {
	session, conversationID, ok := h.conversationEgressAccess(c, "chat:read")
	if !ok {
		return
	}
	if !session.Permissions["egress:read"] {
		c.JSON(http.StatusForbidden, gin.H{"error": "缺少 egress:read 权限"})
		return
	}
	view, err := h.db.GetConversationEgress(c.Request.Context(), conversationID)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}
	if err != nil {
		if strings.Contains(err.Error(), "container conversation") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "只有 container 对话支持上游出口绑定"})
			return
		}
		h.logger.Error("读取对话上游出口失败", zap.String("conversation_id", conversationID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取对话上游出口失败"})
		return
	}
	c.JSON(http.StatusOK, view)
}

// UpdateConversationEgress replaces the pending selection. The database
// rejects it with 409 once first-start binding has become active.
func (h *ConversationHandler) UpdateConversationEgress(c *gin.Context) {
	session, conversationID, ok := h.conversationEgressAccess(c, "chat:write")
	if !ok {
		return
	}
	var req ConversationEgressRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	conversation, err := h.db.GetConversationLite(conversationID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}
	mode, proxyID, proxyGroupID, configured, requestErr := normalizeConversationEgressForSession(
		c.Request.Context(), h.db, session, conversation.RuntimeMode,
		req.Mode, req.EgressProxyID, req.EgressProxyGroupID,
	)
	if requestErr != nil {
		c.JSON(requestErr.Status, gin.H{"error": requestErr.Message})
		return
	}
	if !configured {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode 必须为 none、proxy 或 group"})
		return
	}
	view, err := h.db.SetConversationEgressSelection(c.Request.Context(), conversationID, mode, proxyID, proxyGroupID)
	if errors.Is(err, database.ErrConversationEgressBindingActive) {
		c.JSON(http.StatusConflict, gin.H{"error": "对话上游出口已在首次容器启动时锁定"})
		return
	}
	if errors.Is(err, database.ErrEgressProxyNotFound) || errors.Is(err, database.ErrEgressProxyGroupNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "上游出口资源不存在"})
		return
	}
	if err != nil {
		h.logger.Error("更新对话上游出口失败", zap.String("conversation_id", conversationID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新对话上游出口失败"})
		return
	}
	c.JSON(http.StatusOK, view)
}
