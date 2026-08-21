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

// ClearConversationEgress removes the pending conversation override and
// returns the effective project/user inheritance preview. It never changes an
// already-active binding.
func (h *ConversationHandler) ClearConversationEgress(c *gin.Context) {
	session, conversationID, ok := h.conversationEgressAccess(c, "chat:write")
	if !ok {
		return
	}
	if !session.Permissions["egress:read"] {
		c.JSON(http.StatusForbidden, gin.H{"error": "缺少 egress:read 权限"})
		return
	}
	view, err := h.db.ClearConversationEgressSelection(c.Request.Context(), conversationID)
	if errors.Is(err, database.ErrConversationEgressBindingActive) {
		c.JSON(http.StatusConflict, gin.H{"error": "对话上游出口已在首次容器启动时锁定"})
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}
	if err != nil {
		if strings.Contains(err.Error(), "container conversation") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "只有 container 对话支持上游出口绑定"})
			return
		}
		h.logger.Error("清除对话上游出口覆盖失败", zap.String("conversation_id", conversationID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "清除对话上游出口覆盖失败"})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "egress", "conversation_default_inherit", "恢复对话上游出口继承", "conversation", conversationID, egressDefaultAuditDetail(view.Mode, view.Source, view.Proxy, view.ProxyGroup))
	}
	c.JSON(http.StatusOK, view)
}

func (h *ConversationHandler) GetUserEgressDefault(c *gin.Context) {
	session, ok := requireEgressDefaultPermission(c, "egress:read")
	if !ok {
		return
	}
	view, err := h.db.GetUserEgressDefault(c.Request.Context(), session.UserID)
	if err != nil {
		h.writeEgressDefaultError(c, "读取用户上游出口默认值失败", err)
		return
	}
	c.JSON(http.StatusOK, view)
}

func (h *ConversationHandler) UpdateUserEgressDefault(c *gin.Context) {
	session, ok := requireEgressDefaultPermission(c, "egress:write")
	if !ok {
		return
	}
	if !session.Permissions["egress:read"] {
		c.JSON(http.StatusForbidden, gin.H{"error": "缺少 egress:read 权限"})
		return
	}
	normalized, requestErr := h.parseEgressDefaultRequest(c, session)
	if requestErr != nil {
		c.JSON(requestErr.Status, gin.H{"error": requestErr.Message})
		return
	}
	view, err := h.db.SetUserEgressDefault(c.Request.Context(), session.UserID, normalized[0], normalized[1], normalized[2])
	if err != nil {
		h.writeEgressDefaultError(c, "更新用户上游出口默认值失败", err)
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "egress", "user_default_update", "更新用户上游出口默认值", "user", session.UserID, egressDefaultAuditDetail(view.Mode, view.Source, view.Proxy, view.ProxyGroup))
	}
	c.JSON(http.StatusOK, view)
}

func (h *ConversationHandler) DeleteUserEgressDefault(c *gin.Context) {
	session, ok := requireEgressDefaultPermission(c, "egress:write")
	if !ok {
		return
	}
	if err := h.db.DeleteUserEgressDefault(c.Request.Context(), session.UserID); err != nil {
		h.writeEgressDefaultError(c, "删除用户上游出口默认值失败", err)
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "egress", "user_default_delete", "删除用户上游出口默认值", "user", session.UserID, nil)
	}
	c.Status(http.StatusNoContent)
}

func (h *ConversationHandler) GetProjectEgressDefault(c *gin.Context) {
	session, projectID, ok := h.projectEgressDefaultAccess(c, "project:read")
	if !ok {
		return
	}
	_ = session
	view, err := h.db.GetProjectEgressDefault(c.Request.Context(), projectID)
	if err != nil {
		h.writeEgressDefaultError(c, "读取项目上游出口默认值失败", err)
		return
	}
	c.JSON(http.StatusOK, view)
}

func (h *ConversationHandler) UpdateProjectEgressDefault(c *gin.Context) {
	session, projectID, ok := h.projectEgressDefaultAccess(c, "project:write")
	if !ok {
		return
	}
	normalized, requestErr := h.parseEgressDefaultRequest(c, session)
	if requestErr != nil {
		c.JSON(requestErr.Status, gin.H{"error": requestErr.Message})
		return
	}
	view, err := h.db.SetProjectEgressDefault(c.Request.Context(), projectID, normalized[0], normalized[1], normalized[2])
	if err != nil {
		h.writeEgressDefaultError(c, "更新项目上游出口默认值失败", err)
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "egress", "project_default_update", "更新项目上游出口默认值", "project", projectID, egressDefaultAuditDetail(view.Mode, view.Source, view.Proxy, view.ProxyGroup))
	}
	c.JSON(http.StatusOK, view)
}

func (h *ConversationHandler) DeleteProjectEgressDefault(c *gin.Context) {
	_, projectID, ok := h.projectEgressDefaultAccess(c, "project:write")
	if !ok {
		return
	}
	if err := h.db.DeleteProjectEgressDefault(c.Request.Context(), projectID); err != nil {
		h.writeEgressDefaultError(c, "删除项目上游出口默认值失败", err)
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "egress", "project_default_delete", "删除项目上游出口默认值", "project", projectID, nil)
	}
	c.Status(http.StatusNoContent)
}

// PreviewEgressDefault resolves a new container conversation's effective
// default without creating a conversation or freezing any binding.
func (h *ConversationHandler) PreviewEgressDefault(c *gin.Context) {
	session, ok := requireEgressDefaultPermission(c, "egress:read")
	if !ok {
		return
	}
	projectID := strings.TrimSpace(c.Query("projectId"))
	if projectID != "" {
		if !session.Permissions["project:read"] {
			c.JSON(http.StatusForbidden, gin.H{"error": "缺少 project:read 权限"})
			return
		}
		if _, err := h.db.GetProject(projectID); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "项目不存在"})
			return
		}
		if !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("project:read"), "project", projectID) {
			c.JSON(http.StatusForbidden, gin.H{"error": "无权访问目标项目"})
			return
		}
	}
	view, err := h.db.GetEgressInheritancePreview(c.Request.Context(), session.UserID, projectID)
	if err != nil {
		h.writeEgressDefaultError(c, "预览上游出口继承失败", err)
		return
	}
	c.JSON(http.StatusOK, view)
}

func requireEgressDefaultPermission(c *gin.Context, permission string) (security.Session, bool) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return security.Session{}, false
	}
	if !session.Permissions[permission] {
		c.JSON(http.StatusForbidden, gin.H{"error": "缺少 " + permission + " 权限"})
		return security.Session{}, false
	}
	return session, true
}

func (h *ConversationHandler) projectEgressDefaultAccess(c *gin.Context, permission string) (security.Session, string, bool) {
	session, ok := requireEgressDefaultPermission(c, permission)
	if !ok {
		return security.Session{}, "", false
	}
	if !session.Permissions["egress:read"] {
		c.JSON(http.StatusForbidden, gin.H{"error": "缺少 egress:read 权限"})
		return security.Session{}, "", false
	}
	projectID := strings.TrimSpace(c.Param("id"))
	if _, err := h.db.GetProject(projectID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "项目不存在"})
		return security.Session{}, "", false
	}
	if !h.db.UserCanAccessResource(session.UserID, session.ScopeFor(permission), "project", projectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问目标项目"})
		return security.Session{}, "", false
	}
	return session, projectID, true
}

func (h *ConversationHandler) parseEgressDefaultRequest(c *gin.Context, session security.Session) ([3]string, *conversationEgressRequestError) {
	var req ConversationEgressRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return [3]string{}, &conversationEgressRequestError{Status: http.StatusBadRequest, Message: err.Error()}
	}
	mode, proxyID, proxyGroupID, configured, requestErr := normalizeConversationEgressForSession(
		c.Request.Context(), h.db, session, database.ConversationRuntimeModeContainer,
		req.Mode, req.EgressProxyID, req.EgressProxyGroupID,
	)
	if requestErr != nil {
		return [3]string{}, requestErr
	}
	if !configured {
		return [3]string{}, &conversationEgressRequestError{Status: http.StatusBadRequest, Message: "mode 必须为 none、proxy 或 group"}
	}
	return [3]string{mode, proxyID, proxyGroupID}, nil
}

func (h *ConversationHandler) writeEgressDefaultError(c *gin.Context, message string, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "默认值作用域或上游出口资源不存在"})
		return
	}
	if errors.Is(err, database.ErrEgressProxyNotFound) || errors.Is(err, database.ErrEgressProxyGroupNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "上游出口资源不存在"})
		return
	}
	h.logger.Error(message, zap.Error(err))
	c.JSON(http.StatusInternalServerError, gin.H{"error": message})
}

func egressDefaultAuditDetail(mode, source string, proxy *database.EgressProxySummary, group *database.EgressProxyGroupSummary) map[string]interface{} {
	detail := map[string]interface{}{"mode": mode, "source": source}
	if proxy != nil {
		detail["proxy_id"] = proxy.ID
	}
	if group != nil {
		detail["proxy_group_id"] = group.ID
	}
	return detail
}
