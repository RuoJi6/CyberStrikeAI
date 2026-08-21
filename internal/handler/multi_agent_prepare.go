package handler

import (
	"fmt"
	"strings"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// multiAgentPrepared 多代理请求在调用 Eino 前的会话与消息准备结果。
type multiAgentPrepared struct {
	ConversationID         string
	CreatedNew             bool
	History                []agent.ChatMessage
	FinalMessage           string
	RoleTools              []string
	AssistantMessageID     string
	UserMessageID          string
	ContainerExecutionGate *conversationContainerExecutionGate
}

func chatRequestAgentMode(req *ChatRequest, source string) string {
	if strings.HasPrefix(strings.TrimSpace(source), "multi_agent") {
		return config.NormalizeMultiAgentOrchestration(req.Orchestration)
	}
	return "eino_single"
}

func (h *AgentHandler) prepareMultiAgentSession(req *ChatRequest, c *gin.Context, source string) (*multiAgentPrepared, error) {
	if len(req.Attachments) > maxAttachments {
		return nil, fmt.Errorf("附件最多 %d 个", maxAttachments)
	}

	conversationID := strings.TrimSpace(req.ConversationID)
	projectID := strings.TrimSpace(effectiveProjectID(h.config, req.ProjectID))
	webshellID := strings.TrimSpace(req.WebShellConnectionID)
	session, hasSession := security.CurrentSession(c)
	if !hasSession || !session.Permissions["chat:write"] {
		return nil, fmt.Errorf("无权写入对话")
	}
	canAccess := func(resourceType, resourceID string) bool {
		if !hasSession || h.db == nil || strings.TrimSpace(resourceID) == "" {
			return false
		}
		return h.db.UserCanAccessResource(session.UserID, session.Scope, resourceType, resourceID)
	}
	if projectID != "" && (!session.Permissions["project:read"] || !canAccess("project", projectID)) {
		return nil, fmt.Errorf("无权访问目标项目")
	}
	if webshellID != "" && (!session.Permissions["webshell:write"] || !canAccess("webshell", webshellID)) {
		return nil, fmt.Errorf("无权访问该 WebShell 连接")
	}
	createdNew := false
	var conv *database.Conversation
	if conversationID == "" {
		runtimeMode, runtimeModeErr := database.NormalizeConversationRuntimeMode(req.RuntimeMode)
		if runtimeModeErr != nil {
			return nil, fmt.Errorf("新对话 runtimeMode 必须为 host 或 container")
		}
		if req.WorkspacePersistent && runtimeMode != database.ConversationRuntimeModeContainer {
			return nil, fmt.Errorf("新对话 workspacePersistent 只能用于 container")
		}
		boundaryPolicyID := strings.TrimSpace(req.BoundaryPolicyID)
		if boundaryPolicyID != "" {
			if runtimeMode != database.ConversationRuntimeModeContainer {
				return nil, fmt.Errorf("新对话 boundaryPolicyId 只能用于 container")
			}
			if !session.Permissions["boundary:read"] {
				return nil, fmt.Errorf("缺少 boundary:read 权限")
			}
			if _, policyErr := h.db.GetBoundaryPolicy(c.Request.Context(), boundaryPolicyID); policyErr != nil {
				return nil, fmt.Errorf("边界策略不存在")
			}
			if !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("boundary:read"), "boundary_policy", boundaryPolicyID) {
				return nil, fmt.Errorf("无权访问该边界策略")
			}
		}
		title := safeTruncateString(req.Message, 50)
		var err error
		meta := audit.ConversationCreateMetaFromGin(c, source)
		meta.ProjectID = projectID
		meta.RoleName = req.Role
		meta.AgentMode = chatRequestAgentMode(req, source)
		meta.RuntimeMode = runtimeMode
		meta.WorkspacePersistent = req.WorkspacePersistent
		meta.BoundaryPolicyID = boundaryPolicyID
		if webshellID != "" {
			meta.Source = source + "_webshell"
			meta.WebShellConnectionID = webshellID
			conv, err = h.db.CreateConversationWithWebshell(meta.WebShellConnectionID, title, meta)
		} else {
			conv, err = h.db.CreateConversation(title, meta)
		}
		if err != nil {
			return nil, fmt.Errorf("创建对话失败: %w", err)
		}
		conversationID = conv.ID
		createdNew = true
		if hasSession {
			_ = h.db.SetResourceOwner("conversation", conversationID, session.UserID)
			_ = h.db.AssignResourceToUser(session.UserID, "conversation", conversationID)
		}
	} else {
		var err error
		conv, err = h.db.GetConversation(conversationID)
		if err != nil {
			return nil, fmt.Errorf("对话不存在")
		}
		if !canAccess("conversation", conversationID) {
			return nil, fmt.Errorf("无权访问该对话")
		}
	}
	if err := h.db.SetConversationRoleName(conversationID, req.Role); err != nil {
		h.logger.Warn("更新对话角色失败", zap.String("conversationId", conversationID), zap.String("role", req.Role), zap.Error(err))
	}
	if err := h.db.SetConversationAgentMode(conversationID, chatRequestAgentMode(req, source)); err != nil {
		h.logger.Warn("更新对话模式失败", zap.String("conversationId", conversationID), zap.String("source", source), zap.String("orchestration", req.Orchestration), zap.Error(err))
	}

	agentHistoryMessages, err := h.loadHistoryFromAgentTrace(conversationID)
	if err != nil {
		historyMessages, getErr := h.db.GetMessages(conversationID)
		if getErr != nil {
			agentHistoryMessages = []agent.ChatMessage{}
		} else {
			agentHistoryMessages = dbMessagesToAgentChatMessages(historyMessages)
		}
	}

	finalMessage := req.Message
	var roleTools []string
	if webshellID != "" {
		conn, errConn := h.db.GetWebshellConnection(webshellID)
		if errConn != nil || conn == nil {
			h.logger.Warn("WebShell AI 助手：未找到连接", zap.String("id", req.WebShellConnectionID), zap.Error(errConn))
			return nil, fmt.Errorf("未找到该 WebShell 连接")
		}
		webshellContext := BuildWebshellAssistantContext(conn, WebshellSkillHintMultiAgent, req.Message)
		// WebShell 模式下如果同时指定了角色，追加角色 user_prompt（工具集仍仅限 webshell 专用工具）
		if req.Role != "" && req.Role != "默认" && h.config != nil && h.config.Roles != nil {
			if role, exists := h.config.Roles[req.Role]; exists && role.Enabled && role.UserPrompt != "" {
				finalMessage = role.UserPrompt + "\n\n" + webshellContext
				h.logger.Info("WebShell + 角色: 应用角色提示词（多代理）", zap.String("role", req.Role))
			} else {
				finalMessage = webshellContext
			}
		} else {
			finalMessage = webshellContext
		}
		roleTools = []string{
			builtin.ToolWebshellExec,
			builtin.ToolWebshellFileList,
			builtin.ToolWebshellFileRead,
			builtin.ToolWebshellFileWrite,
			builtin.ToolRecordVulnerability,
			builtin.ToolListVulnerabilities,
			builtin.ToolGetVulnerability,
			builtin.ToolUpsertProjectFact,
			builtin.ToolGetProjectFact,
			builtin.ToolListProjectFacts,
			builtin.ToolSearchProjectFacts,
			builtin.ToolDeprecateProjectFact,
			builtin.ToolRestoreProjectFact,
			builtin.ToolListKnowledgeRiskTypes,
			builtin.ToolSearchKnowledgeBase,
		}
	} else if req.Role != "" && req.Role != "默认" && h.config != nil && h.config.Roles != nil {
		if role, exists := h.config.Roles[req.Role]; exists && role.Enabled {
			if role.UserPrompt != "" {
				finalMessage = role.UserPrompt + "\n\n" + req.Message
			}
			roleTools = role.Tools
		}
	}
	containerExecutionGate := h.prepareConversationContainerExecutionGate(c.Request.Context(), conv)

	var savedPaths []string
	if len(req.Attachments) > 0 {
		var aerr error
		savedPaths, aerr = saveAttachmentsToDateAndConversationDir(req.Attachments, conversationID, h.logger)
		if aerr != nil {
			return nil, fmt.Errorf("保存上传文件失败: %w", aerr)
		}
	}
	visiblePaths := savedPaths
	if conv.RuntimeMode == database.ConversationRuntimeModeContainer {
		visiblePaths, err = containerVisibleAttachmentPaths(savedPaths, conversationID)
		if err != nil {
			return nil, fmt.Errorf("规范化容器附件路径失败: %w", err)
		}
		if containerExecutionGate == nil {
			if err := h.syncConversationUploadsToWorkspace(c.Request.Context(), conv); err != nil {
				return nil, fmt.Errorf("同步附件到容器工作区失败: %w", err)
			}
		}
	}
	finalMessage = appendAttachmentsToMessage(finalMessage, req.Attachments, visiblePaths)

	userContent := userMessageContentForStorage(req.Message, req.Attachments, visiblePaths)
	userMsgRow, uerr := h.db.AddMessage(conversationID, "user", userContent, nil)
	if uerr != nil {
		h.logger.Error("保存用户消息失败", zap.Error(uerr))
		return nil, fmt.Errorf("保存用户消息失败: %w", uerr)
	}
	userMessageID := ""
	if userMsgRow != nil {
		userMessageID = userMsgRow.ID
	}

	assistantMsg, aerr := h.db.AddMessage(conversationID, "assistant", "处理中...", nil)
	var assistantMessageID string
	if aerr != nil {
		h.logger.Warn("创建助手消息占位失败", zap.Error(aerr))
	} else if assistantMsg != nil {
		assistantMessageID = assistantMsg.ID
	}

	return &multiAgentPrepared{
		ConversationID:         conversationID,
		CreatedNew:             createdNew,
		History:                agentHistoryMessages,
		FinalMessage:           finalMessage,
		RoleTools:              roleTools,
		AssistantMessageID:     assistantMessageID,
		UserMessageID:          userMessageID,
		ContainerExecutionGate: containerExecutionGate,
	}, nil
}
