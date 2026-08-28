package audit

import (
	"strings"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
)

// RegisterConversationCreateHook records platform audit rows for every new conversation.
func RegisterConversationCreateHook(s *Service) {
	if s == nil {
		return
	}
	database.SetConversationCreateHook(func(conv *database.Conversation, meta database.ConversationCreateMeta) {
		detail := map[string]interface{}{
			"title":                conv.Title,
			"source":               meta.Source,
			"runtime_mode":         conv.RuntimeMode,
			"workspace_persistent": conv.WorkspacePersistent,
		}
		if meta.WebShellConnectionID != "" {
			detail["webshell_connection_id"] = meta.WebShellConnectionID
		}
		if meta.WorkspaceID != "" {
			detail["workspace_id"] = meta.WorkspaceID
		}
		if meta.EgressMode != "" {
			detail["egress_mode"] = meta.EgressMode
		}
		if meta.EgressProxyID != "" {
			detail["egress_proxy_id"] = meta.EgressProxyID
		}
		if meta.EgressProxyGroupID != "" {
			detail["egress_proxy_group_id"] = meta.EgressProxyGroupID
		}
		if meta.EgressAuditEnabled != nil {
			detail["egress_audit_enabled"] = *meta.EgressAuditEnabled
		}
		if meta.EgressAuditMode != "" {
			detail["egress_audit_mode"] = meta.EgressAuditMode
		}
		s.Record(nil, Entry{
			Category:     "conversation",
			Action:       "create",
			Result:       "success",
			Message:      "创建对话",
			ResourceType: "conversation",
			ResourceID:   conv.ID,
			Detail:       detail,
			ClientIP:     meta.ClientIP,
			SessionHint:  meta.SessionHint,
		})
	})
}

// ConversationCreateMeta builds audit metadata for conversation creation.
func ConversationCreateMeta(source string) database.ConversationCreateMeta {
	return database.ConversationCreateMeta{Source: strings.TrimSpace(source)}
}

// ConversationCreateMetaFromGin includes client IP and session hint when available.
func ConversationCreateMetaFromGin(c *gin.Context, source string) database.ConversationCreateMeta {
	m := ConversationCreateMeta(source)
	if c == nil {
		return m
	}
	m.ClientIP = c.ClientIP()
	if token := c.GetString(security.ContextAuthTokenKey); token != "" {
		m.SessionHint = sessionHint(token)
	}
	return m
}
