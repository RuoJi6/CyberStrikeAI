package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	containerruntime "cyberstrike-ai/internal/runtime/container"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ProjectFilterUnbound 列表 API 中 project_id=__none__ 表示仅未绑定项目的对话。
const ProjectFilterUnbound = "__none__"

const (
	ConversationRuntimeModeHost      = "host"
	ConversationRuntimeModeContainer = "container"
)

// Conversation 对话
type Conversation struct {
	ID                  string                  `json:"id"`
	Title               string                  `json:"title"`
	ProjectID           string                  `json:"projectId,omitempty"`
	RoleName            string                  `json:"roleName,omitempty"`
	AgentMode           string                  `json:"agentMode,omitempty"`
	RuntimeMode         string                  `json:"runtimeMode"`
	WorkspaceMode       string                  `json:"workspaceMode,omitempty"`
	WorkspacePersistent bool                    `json:"workspacePersistent"`
	IdlePolicy          *ConversationIdlePolicy `json:"idlePolicy,omitempty"`
	Pinned              bool                    `json:"pinned"`
	CreatedAt           time.Time               `json:"createdAt"`
	UpdatedAt           time.Time               `json:"updatedAt"`
	Messages            []Message               `json:"messages,omitempty"`
}

// Message 消息
type Message struct {
	ID               string                   `json:"id"`
	ConversationID   string                   `json:"conversationId"`
	Role             string                   `json:"role"`
	Content          string                   `json:"content"`
	ReasoningContent string                   `json:"reasoningContent,omitempty"`
	MCPExecutionIDs  []string                 `json:"mcpExecutionIds,omitempty"`
	ProcessDetails   []map[string]interface{} `json:"processDetails,omitempty"`
	CreatedAt        time.Time                `json:"createdAt"`
	UpdatedAt        time.Time                `json:"updatedAt"`
}

// CreateConversation 创建新对话
func (db *DB) CreateConversation(title string, meta ConversationCreateMeta) (*Conversation, error) {
	return db.CreateConversationWithWebshell("", title, meta)
}

// CreateConversationWithWebshell 创建新对话，可选绑定 WebShell 连接 ID（为空则普通对话）
func (db *DB) CreateConversationWithWebshell(webshellConnectionID, title string, meta ConversationCreateMeta) (*Conversation, error) {
	id := uuid.New().String()
	now := time.Now().UTC()

	projectID := strings.TrimSpace(meta.ProjectID)
	if projectID != "" {
		if _, err := db.GetProject(projectID); err != nil {
			return nil, err
		}
	}
	roleName := normalizeConversationRoleName(meta.RoleName)
	agentMode := normalizeConversationAgentMode(meta.AgentMode)
	runtimeMode, err := NormalizeConversationRuntimeMode(meta.RuntimeMode)
	if err != nil {
		return nil, err
	}
	workspaceMode := strings.ToLower(strings.TrimSpace(meta.WorkspaceMode))
	requestedWorkspaceID := strings.TrimSpace(meta.WorkspaceID)
	if runtimeMode == ConversationRuntimeModeContainer {
		if workspaceMode == "" {
			switch {
			case requestedWorkspaceID != "":
				workspaceMode = ConversationWorkspaceModeShared
			case meta.WorkspacePersistent:
				workspaceMode = ConversationWorkspaceModeDedicated
			default:
				workspaceMode = ConversationWorkspaceModeDedicated
			}
		}
		if workspaceMode != ConversationWorkspaceModeEphemeral && workspaceMode != ConversationWorkspaceModeDedicated && workspaceMode != ConversationWorkspaceModeShared {
			return nil, fmt.Errorf("workspaceMode 必须为 ephemeral、dedicated 或 shared")
		}
		if workspaceMode == ConversationWorkspaceModeShared && requestedWorkspaceID == "" {
			return nil, fmt.Errorf("共享工作区必须指定 workspaceId")
		}
		if workspaceMode != ConversationWorkspaceModeShared && requestedWorkspaceID != "" {
			return nil, fmt.Errorf("只有 shared 工作区可以指定 workspaceId")
		}
	} else if workspaceMode != "" || meta.WorkspacePersistent || requestedWorkspaceID != "" {
		return nil, fmt.Errorf("容器工作区只能用于 container 对话")
	}
	idlePolicy := ConversationIdlePolicy{Action: ConversationIdleActionNone, TimeoutSeconds: ConversationIdleTimeoutDefaultSeconds}
	var idleActionValue interface{}
	var idleTimeoutValue interface{}
	if runtimeMode == ConversationRuntimeModeContainer {
		idlePolicy = DefaultNewConversationIdlePolicy()
		if meta.IdlePolicy != nil {
			idlePolicy, err = NormalizeConversationIdlePolicy(*meta.IdlePolicy)
			if err != nil {
				return nil, err
			}
		}
		idleActionValue = idlePolicy.Action
		idleTimeoutValue = idlePolicy.TimeoutSeconds
	} else if meta.IdlePolicy != nil {
		return nil, fmt.Errorf("idlePolicy 只能用于 container 对话")
	}
	runtimeControls, err := NormalizeConversationRuntimeControls(meta.RuntimeControls)
	if err != nil {
		return nil, err
	}
	if runtimeMode != ConversationRuntimeModeContainer && (runtimeControls.ScanRateEnabled || runtimeControls.CustomResourcesEnabled) {
		return nil, fmt.Errorf("容器运行控制只能用于 container 对话")
	}
	boundaryPolicyID := strings.TrimSpace(meta.BoundaryPolicyID)
	if boundaryPolicyID != "" {
		if runtimeMode != ConversationRuntimeModeContainer {
			return nil, fmt.Errorf("边界策略只能用于 container 对话")
		}
		if _, err := db.GetBoundaryPolicy(context.Background(), boundaryPolicyID); err != nil {
			return nil, fmt.Errorf("边界策略不存在: %w", err)
		}
	}
	egressMode, egressProxyID, egressProxyGroupID, egressConfigured, err := NormalizeConversationEgressSelection(
		meta.EgressMode, meta.EgressProxyID, meta.EgressProxyGroupID,
	)
	if err != nil {
		return nil, err
	}
	if egressConfigured {
		if runtimeMode != ConversationRuntimeModeContainer {
			return nil, fmt.Errorf("upstream egress can only be selected for container conversations")
		}
		if err := validateConversationEgressTarget(context.Background(), db, egressMode, egressProxyID, egressProxyGroupID); err != nil {
			return nil, fmt.Errorf("selected upstream egress does not exist: %w", err)
		}
	}
	wsID := strings.TrimSpace(webshellConnectionID)
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("开始创建对话事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	workspaceID, workspacePersistent, err := resolveNewConversationWorkspaceTx(
		context.Background(), tx, id, title, projectID, runtimeMode,
		runtimeMode == ConversationRuntimeModeContainer && workspaceMode != ConversationWorkspaceModeEphemeral, requestedWorkspaceID, now,
	)
	if err != nil {
		return nil, err
	}
	switch {
	case wsID != "" && projectID != "":
		_, err = tx.Exec(
			"INSERT INTO conversations (id, title, created_at, updated_at, webshell_connection_id, project_id, role_name, agent_mode, runtime_mode, workspace_persistent, workspace_id, idle_action, idle_timeout_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?)",
			id, title, now, now, wsID, projectID, roleName, agentMode, runtimeMode, workspacePersistent, workspaceID, idleActionValue, idleTimeoutValue,
		)
	case wsID != "":
		_, err = tx.Exec(
			"INSERT INTO conversations (id, title, created_at, updated_at, webshell_connection_id, role_name, agent_mode, runtime_mode, workspace_persistent, workspace_id, idle_action, idle_timeout_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?)",
			id, title, now, now, wsID, roleName, agentMode, runtimeMode, workspacePersistent, workspaceID, idleActionValue, idleTimeoutValue,
		)
	case projectID != "":
		_, err = tx.Exec(
			"INSERT INTO conversations (id, title, created_at, updated_at, project_id, role_name, agent_mode, runtime_mode, workspace_persistent, workspace_id, idle_action, idle_timeout_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?)",
			id, title, now, now, projectID, roleName, agentMode, runtimeMode, workspacePersistent, workspaceID, idleActionValue, idleTimeoutValue,
		)
	default:
		_, err = tx.Exec(
			"INSERT INTO conversations (id, title, created_at, updated_at, role_name, agent_mode, runtime_mode, workspace_persistent, workspace_id, idle_action, idle_timeout_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?)",
			id, title, now, now, roleName, agentMode, runtimeMode, workspacePersistent, workspaceID, idleActionValue, idleTimeoutValue,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("创建对话失败: %w", err)
	}
	if runtimeMode == ConversationRuntimeModeContainer {
		if _, err = tx.Exec(`
			UPDATE conversations SET scan_rate_enabled = ?, scan_http_rps = ?, scan_tcp_cps = ?, scan_udp_dps = ?,
				custom_resources_enabled = ?, custom_nano_cpus = ?, custom_memory_bytes = ? WHERE id = ?
		`, runtimeControls.ScanRateEnabled, runtimeControls.HTTPRequestsPerSecond, runtimeControls.TCPConnectionsPerSecond,
			runtimeControls.UDPDatagramsPerSecond, runtimeControls.CustomResourcesEnabled, runtimeControls.NanoCPUs,
			runtimeControls.MemoryBytes, id); err != nil {
			return nil, fmt.Errorf("保存对话容器运行控制失败: %w", err)
		}
		auditEnabled := true
		auditMode := EgressAuditModeCompact
		if meta.EgressAuditEnabled != nil {
			auditEnabled = *meta.EgressAuditEnabled
		}
		if meta.EgressAuditMode != "" {
			if normalized, normalizeErr := NormalizeConversationEgressAuditMode(meta.EgressAuditMode); normalizeErr == nil {
				auditEnabled = normalized != EgressAuditModeOff
				if auditEnabled {
					auditMode = normalized
				}
			}
		}
		if _, err = tx.Exec(`
			INSERT INTO conversation_egress_audit_settings (conversation_id, enabled, mode, updated_at)
			VALUES (?, ?, ?, ?)
		`, id, auditEnabled, auditMode, formatSQLiteUTC(now)); err != nil {
			return nil, fmt.Errorf("保存对话出站审计设置失败: %w", err)
		}
	}
	if boundaryPolicyID != "" {
		if _, err = tx.Exec(`
			INSERT INTO conversation_boundary_policy_selections (conversation_id, policy_id, selected_at)
			VALUES (?, ?, ?)
		`, id, boundaryPolicyID, formatSQLiteUTC(now)); err != nil {
			return nil, fmt.Errorf("选择对话边界策略失败: %w", err)
		}
	}
	if egressConfigured {
		if _, err = tx.Exec(`
			INSERT INTO conversation_egress_selections (
				conversation_id, mode, proxy_id, proxy_group_id, selected_at
			) VALUES (?, ?, NULLIF(?, ''), NULLIF(?, ''), ?)
		`, id, egressMode, egressProxyID, egressProxyGroupID, formatSQLiteUTC(now)); err != nil {
			return nil, fmt.Errorf("select conversation upstream egress: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交创建对话事务失败: %w", err)
	}

	conv := &Conversation{
		ID:                  id,
		Title:               title,
		ProjectID:           projectID,
		RoleName:            roleName,
		AgentMode:           agentMode,
		RuntimeMode:         runtimeMode,
		WorkspaceMode:       workspaceMode,
		WorkspacePersistent: workspacePersistent,
		IdlePolicy:          nil,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if wsID != "" {
		meta.WebShellConnectionID = wsID
	}
	meta.BoundaryPolicyID = boundaryPolicyID
	meta.EgressMode = egressMode
	meta.EgressProxyID = egressProxyID
	meta.EgressProxyGroupID = egressProxyGroupID
	meta.RuntimeControls = runtimeControls
	meta.WorkspacePersistent = workspacePersistent
	meta.WorkspaceMode = workspaceMode
	meta.WorkspaceID = workspaceID
	if runtimeMode == ConversationRuntimeModeContainer {
		conv.IdlePolicy = &idlePolicy
		meta.IdlePolicy = &idlePolicy
	} else {
		meta.IdlePolicy = nil
	}
	notifyConversationCreated(conv, meta)
	return conv, nil
}

// GetConversationByWebshellConnectionID 根据 WebShell 连接 ID 获取该连接下最近一条对话（用于 AI 助手持久化）
func (db *DB) GetConversationByWebshellConnectionID(connectionID string) (*Conversation, error) {
	if connectionID == "" {
		return nil, fmt.Errorf("connectionID is empty")
	}
	var conv Conversation
	var createdAt, updatedAt string
	var pinned int
	var runtimeMode sql.NullString
	err := db.QueryRow(
		"SELECT id, title, pinned, created_at, updated_at, runtime_mode, workspace_persistent FROM conversations WHERE webshell_connection_id = ? ORDER BY updated_at DESC LIMIT 1",
		connectionID,
	).Scan(&conv.ID, &conv.Title, &pinned, &createdAt, &updatedAt, &runtimeMode, &conv.WorkspacePersistent)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("查询对话失败: %w", err)
	}
	conv.RuntimeMode, _ = NormalizeConversationRuntimeMode(runtimeMode.String)
	conv.Pinned = pinned != 0
	if t, e := time.Parse("2006-01-02 15:04:05.999999999-07:00", createdAt); e == nil {
		conv.CreatedAt = t
	} else if t, e := time.Parse("2006-01-02 15:04:05", createdAt); e == nil {
		conv.CreatedAt = t
	} else {
		conv.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	}
	if t, e := time.Parse("2006-01-02 15:04:05.999999999-07:00", updatedAt); e == nil {
		conv.UpdatedAt = t
	} else if t, e := time.Parse("2006-01-02 15:04:05", updatedAt); e == nil {
		conv.UpdatedAt = t
	} else {
		conv.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	}
	messages, err := db.GetMessages(conv.ID)
	if err != nil {
		return nil, fmt.Errorf("加载消息失败: %w", err)
	}
	conv.Messages = messages

	// 加载过程详情并附加到对应消息（与 GetConversation 一致，便于刷新后仍可查看执行过程）
	processDetailsMap, err := db.GetProcessDetailsByConversation(conv.ID)
	if err != nil {
		db.logger.Warn("加载过程详情失败", zap.Error(err))
		processDetailsMap = make(map[string][]ProcessDetail)
	}
	for i := range conv.Messages {
		if details, ok := processDetailsMap[conv.Messages[i].ID]; ok {
			details = DedupeConsecutiveProcessDetails(details)
			detailsJSON := make([]map[string]interface{}, len(details))
			for j, detail := range details {
				var data interface{}
				if detail.Data != "" {
					if err := json.Unmarshal([]byte(detail.Data), &data); err != nil {
						db.logger.Warn("解析过程详情数据失败", zap.Error(err))
					}
				}
				detailsJSON[j] = map[string]interface{}{
					"id":             detail.ID,
					"messageId":      detail.MessageID,
					"conversationId": detail.ConversationID,
					"eventType":      detail.EventType,
					"message":        detail.Message,
					"data":           data,
					"createdAt":      detail.CreatedAt,
				}
			}
			conv.Messages[i].ProcessDetails = detailsJSON
		}
	}

	return &conv, nil
}

// WebShellConversationItem 用于侧边栏列表，不含消息
type WebShellConversationItem struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ListConversationsByWebshellConnectionID 列出该 WebShell 连接下的所有对话（按更新时间倒序），供侧边栏展示
func (db *DB) ListConversationsByWebshellConnectionID(connectionID string) ([]WebShellConversationItem, error) {
	if connectionID == "" {
		return nil, nil
	}
	rows, err := db.Query(
		"SELECT id, title, updated_at FROM conversations WHERE webshell_connection_id = ? ORDER BY updated_at DESC",
		connectionID,
	)
	if err != nil {
		return nil, fmt.Errorf("查询对话列表失败: %w", err)
	}
	defer rows.Close()
	var list []WebShellConversationItem
	for rows.Next() {
		var item WebShellConversationItem
		var updatedAt string
		if err := rows.Scan(&item.ID, &item.Title, &updatedAt); err != nil {
			continue
		}
		if t, e := time.Parse("2006-01-02 15:04:05.999999999-07:00", updatedAt); e == nil {
			item.UpdatedAt = t
		} else if t, e := time.Parse("2006-01-02 15:04:05", updatedAt); e == nil {
			item.UpdatedAt = t
		} else {
			item.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		}
		list = append(list, item)
	}
	return list, rows.Err()
}

// ConversationExists reports whether a conversation row exists (lightweight check for audit links).
func (db *DB) ConversationExists(id string) (bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return false, nil
	}
	var one int
	err := db.QueryRow("SELECT 1 FROM conversations WHERE id = ? LIMIT 1", id).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetConversation 获取对话
func (db *DB) GetConversation(id string) (*Conversation, error) {
	var conv Conversation
	var createdAt, updatedAt string
	var pinned int

	var projectID sql.NullString
	var roleName sql.NullString
	var agentMode sql.NullString
	var runtimeMode sql.NullString
	err := db.QueryRow(
		"SELECT id, title, pinned, created_at, updated_at, project_id, role_name, agent_mode, runtime_mode, workspace_persistent FROM conversations WHERE id = ?",
		id,
	).Scan(&conv.ID, &conv.Title, &pinned, &createdAt, &updatedAt, &projectID, &roleName, &agentMode, &runtimeMode, &conv.WorkspacePersistent)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("对话不存在")
		}
		return nil, fmt.Errorf("查询对话失败: %w", err)
	}
	if projectID.Valid {
		conv.ProjectID = strings.TrimSpace(projectID.String)
	}
	if roleName.Valid {
		conv.RoleName = normalizeConversationRoleName(roleName.String)
	}
	if agentMode.Valid {
		conv.AgentMode = normalizeConversationAgentMode(agentMode.String)
	}
	conv.RuntimeMode, _ = NormalizeConversationRuntimeMode(runtimeMode.String)

	// 尝试多种时间格式解析
	var err1, err2 error
	conv.CreatedAt, err1 = time.Parse("2006-01-02 15:04:05.999999999-07:00", createdAt)
	if err1 != nil {
		conv.CreatedAt, err1 = time.Parse("2006-01-02 15:04:05", createdAt)
	}
	if err1 != nil {
		conv.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	}

	conv.UpdatedAt, err2 = time.Parse("2006-01-02 15:04:05.999999999-07:00", updatedAt)
	if err2 != nil {
		conv.UpdatedAt, err2 = time.Parse("2006-01-02 15:04:05", updatedAt)
	}
	if err2 != nil {
		conv.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	}

	conv.Pinned = pinned != 0
	if err := db.populateConversationContainerMetadata(context.Background(), &conv); err != nil {
		return nil, fmt.Errorf("加载对话容器设置失败: %w", err)
	}

	// 加载消息
	messages, err := db.GetMessages(id)
	if err != nil {
		return nil, fmt.Errorf("加载消息失败: %w", err)
	}
	conv.Messages = messages

	// 加载过程详情（按消息ID分组）
	processDetailsMap, err := db.GetProcessDetailsByConversation(id)
	if err != nil {
		db.logger.Warn("加载过程详情失败", zap.Error(err))
		processDetailsMap = make(map[string][]ProcessDetail)
	}

	// 将过程详情附加到对应的消息上
	for i := range conv.Messages {
		if details, ok := processDetailsMap[conv.Messages[i].ID]; ok {
			details = DedupeConsecutiveProcessDetails(details)
			// 将ProcessDetail转换为JSON格式，以便前端使用
			detailsJSON := make([]map[string]interface{}, len(details))
			for j, detail := range details {
				var data interface{}
				if detail.Data != "" {
					if err := json.Unmarshal([]byte(detail.Data), &data); err != nil {
						db.logger.Warn("解析过程详情数据失败", zap.Error(err))
					}
				}
				detailsJSON[j] = map[string]interface{}{
					"id":             detail.ID,
					"messageId":      detail.MessageID,
					"conversationId": detail.ConversationID,
					"eventType":      detail.EventType,
					"message":        detail.Message,
					"data":           data,
					"createdAt":      detail.CreatedAt,
				}
			}
			conv.Messages[i].ProcessDetails = detailsJSON
		}
	}

	return &conv, nil
}

// GetConversationLite 获取对话（轻量版）：包含 messages，但不加载 process_details。
// 用于历史会话快速切换，避免一次性把大体量过程详情灌到前端导致卡顿。
func (db *DB) GetConversationLite(id string) (*Conversation, error) {
	var conv Conversation
	var createdAt, updatedAt string
	var pinned int

	var projectID sql.NullString
	var roleName sql.NullString
	var agentMode sql.NullString
	var runtimeMode sql.NullString
	err := db.QueryRow(
		"SELECT id, title, pinned, created_at, updated_at, project_id, role_name, agent_mode, runtime_mode, workspace_persistent FROM conversations WHERE id = ?",
		id,
	).Scan(&conv.ID, &conv.Title, &pinned, &createdAt, &updatedAt, &projectID, &roleName, &agentMode, &runtimeMode, &conv.WorkspacePersistent)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("对话不存在")
		}
		return nil, fmt.Errorf("查询对话失败: %w", err)
	}
	if projectID.Valid {
		conv.ProjectID = strings.TrimSpace(projectID.String)
	}
	if roleName.Valid {
		conv.RoleName = normalizeConversationRoleName(roleName.String)
	}
	if agentMode.Valid {
		conv.AgentMode = normalizeConversationAgentMode(agentMode.String)
	}
	conv.RuntimeMode, _ = NormalizeConversationRuntimeMode(runtimeMode.String)

	// 尝试多种时间格式解析
	var err1, err2 error
	conv.CreatedAt, err1 = time.Parse("2006-01-02 15:04:05.999999999-07:00", createdAt)
	if err1 != nil {
		conv.CreatedAt, err1 = time.Parse("2006-01-02 15:04:05", createdAt)
	}
	if err1 != nil {
		conv.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	}

	conv.UpdatedAt, err2 = time.Parse("2006-01-02 15:04:05.999999999-07:00", updatedAt)
	if err2 != nil {
		conv.UpdatedAt, err2 = time.Parse("2006-01-02 15:04:05", updatedAt)
	}
	if err2 != nil {
		conv.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	}

	conv.Pinned = pinned != 0
	if err := db.populateConversationContainerMetadata(context.Background(), &conv); err != nil {
		return nil, fmt.Errorf("加载对话容器设置失败: %w", err)
	}

	// 加载消息（不加载 process_details / reasoning_content，减少历史会话切换 payload）
	messages, err := db.GetMessagesLite(id)
	if err != nil {
		return nil, fmt.Errorf("加载消息失败: %w", err)
	}
	conv.Messages = messages
	return &conv, nil
}

func (db *DB) populateConversationContainerMetadata(ctx context.Context, conversation *Conversation) error {
	if conversation == nil || conversation.RuntimeMode != ConversationRuntimeModeContainer {
		return nil
	}
	binding, err := db.GetConversationWorkspaceBinding(ctx, conversation.ID)
	if err != nil {
		return err
	}
	conversation.WorkspaceMode = binding.Mode
	policy, err := db.GetConversationIdlePolicy(ctx, conversation.ID)
	if err != nil {
		return err
	}
	conversation.IdlePolicy = &policy
	return nil
}

// GetConversationRuntimeMode reads the execution location currently selected for future turns. Tool
// routing calls this for every OS command, so it must not load conversation
// messages or process details.
func (db *DB) GetConversationRuntimeMode(id string) (string, error) {
	if db == nil {
		return "", fmt.Errorf("对话数据库未配置")
	}
	var runtimeMode sql.NullString
	err := db.QueryRow("SELECT runtime_mode FROM conversations WHERE id = ?", strings.TrimSpace(id)).Scan(&runtimeMode)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("对话不存在")
		}
		return "", fmt.Errorf("查询对话执行位置失败: %w", err)
	}
	mode, err := NormalizeConversationRuntimeMode(runtimeMode.String)
	if err != nil {
		return "", fmt.Errorf("对话执行位置无效: %w", err)
	}
	return mode, nil
}

// SetConversationRuntimeMode updates the execution location for future turns.
// The handler serializes this call with task registration so a running turn
// always keeps the mode it started with.
func (db *DB) SetConversationRuntimeMode(id, runtimeMode string) error {
	if db == nil {
		return fmt.Errorf("对话数据库未配置")
	}
	mode, err := NormalizeConversationRuntimeMode(runtimeMode)
	if err != nil || strings.TrimSpace(runtimeMode) == "" {
		return fmt.Errorf("更新对话执行位置失败: runtime mode must be host or container")
	}
	id = strings.TrimSpace(id)
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("开始更新对话执行位置事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var previousMode, title string
	var projectID, workspaceID, idleAction sql.NullString
	var workspacePersistent bool
	if err := tx.QueryRow(`
		SELECT runtime_mode, title, project_id, workspace_persistent, workspace_id, idle_action
		FROM conversations WHERE id = ?
	`, id).Scan(&previousMode, &title, &projectID, &workspacePersistent, &workspaceID, &idleAction); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("对话不存在")
		}
		return fmt.Errorf("查询对话执行位置失败: %w", err)
	}
	now := time.Now().UTC()
	// A host-only conversation has never made a container workspace choice. On
	// its first switch to container execution, apply the same durable defaults
	// as a newly-created container conversation. Conversations that previously
	// chose ephemeral storage retain that explicit choice when switching back.
	initializeContainerDefaults := mode == ConversationRuntimeModeContainer &&
		previousMode != ConversationRuntimeModeContainer && !workspacePersistent &&
		strings.TrimSpace(workspaceID.String) == "" &&
		(!idleAction.Valid || strings.TrimSpace(idleAction.String) == "")
	if initializeContainerDefaults {
		workspaceIDValue := dedicatedWorkspaceID(id)
		var exists int
		if err := tx.QueryRow("SELECT COUNT(*) FROM container_workspaces WHERE id = ?", workspaceIDValue).Scan(&exists); err != nil {
			return fmt.Errorf("查询专属工作区失败: %w", err)
		}
		if exists == 0 {
			if _, err := createContainerWorkspaceTx(tx, workspaceIDValue, title+" 工作区", ContainerWorkspaceKindDedicated, projectID.String, now); err != nil {
				return fmt.Errorf("创建专属工作区失败: %w", err)
			}
		}
		workspaceID.String, workspaceID.Valid = workspaceIDValue, true
		idleAction.String, idleAction.Valid = ConversationIdleActionDelete, true
	}
	idleTimeout := ConversationIdleTimeoutDefaultSeconds
	if initializeContainerDefaults {
		_, err = tx.Exec(`
			UPDATE conversations
			SET runtime_mode = ?, workspace_persistent = 1, workspace_id = ?,
				idle_action = ?, idle_timeout_seconds = ?, updated_at = ?
			WHERE id = ?
		`, mode, workspaceID.String, idleAction.String, idleTimeout, formatSQLiteUTC(now), id)
	} else {
		_, err = tx.Exec("UPDATE conversations SET runtime_mode = ?, updated_at = ? WHERE id = ?", mode, formatSQLiteUTC(now), id)
	}
	if err != nil {
		return fmt.Errorf("更新对话执行位置失败: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交对话执行位置失败: %w", err)
	}
	return nil
}

// GetConversationWorkspacePersistent reads only the immutable workspace policy.
func (db *DB) GetConversationWorkspacePersistent(id string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("对话数据库未配置")
	}
	var persistent bool
	err := db.QueryRow("SELECT workspace_persistent FROM conversations WHERE id = ?", strings.TrimSpace(id)).Scan(&persistent)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, fmt.Errorf("对话不存在")
		}
		return false, fmt.Errorf("查询对话工作区策略失败: %w", err)
	}
	return persistent, nil
}

func normalizeConversationRoleName(roleName string) string {
	roleName = strings.TrimSpace(roleName)
	if roleName == "" {
		return "默认"
	}
	return roleName
}

func normalizeConversationAgentMode(agentMode string) string {
	agentMode = strings.ToLower(strings.TrimSpace(agentMode))
	agentMode = strings.ReplaceAll(agentMode, "-", "_")
	switch agentMode {
	case "deep", "plan_execute", "supervisor":
		return agentMode
	default:
		return "eino_single"
	}
}

// NormalizeConversationRuntimeMode validates an execution location. An empty
// value is intentionally compatible with historical creation callers.
func NormalizeConversationRuntimeMode(runtimeMode string) (string, error) {
	runtimeMode = strings.ToLower(strings.TrimSpace(runtimeMode))
	if runtimeMode == "" {
		return ConversationRuntimeModeHost, nil
	}
	switch runtimeMode {
	case ConversationRuntimeModeHost, ConversationRuntimeModeContainer:
		return runtimeMode, nil
	default:
		return "", fmt.Errorf("invalid conversation runtime mode %q: must be host or container", runtimeMode)
	}
}

func (db *DB) SetConversationRoleName(id, roleName string) error {
	roleName = normalizeConversationRoleName(roleName)
	_, err := db.Exec(
		"UPDATE conversations SET role_name = ?, updated_at = ? WHERE id = ?",
		roleName, time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("更新对话角色失败: %w", err)
	}
	return nil
}

func (db *DB) SetConversationAgentMode(id, agentMode string) error {
	agentMode = normalizeConversationAgentMode(agentMode)
	_, err := db.Exec(
		"UPDATE conversations SET agent_mode = ? WHERE id = ?",
		agentMode, id,
	)
	if err != nil {
		return fmt.Errorf("更新对话模式失败: %w", err)
	}
	return nil
}

func conversationProjectIDColumn(alias string) string {
	if alias != "" {
		return alias + ".project_id"
	}
	return "project_id"
}

func appendConversationProjectFilter(where string, args []interface{}, projectID, alias string) (string, []interface{}) {
	pid := strings.TrimSpace(projectID)
	if pid == "" {
		return where, args
	}
	col := conversationProjectIDColumn(alias)
	if pid == ProjectFilterUnbound {
		return where + fmt.Sprintf(" AND (%s IS NULL OR TRIM(COALESCE(%s, '')) = '')", col, col), args
	}
	return where + fmt.Sprintf(" AND %s = ?", col), append(args, pid)
}

func appendConversationAccessFilter(where string, args []interface{}, userID, scope, alias string) (string, []interface{}) {
	userID = strings.TrimSpace(userID)
	if userID == "" || scope == RBACScopeAll {
		return where, args
	}
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	where += fmt.Sprintf(` AND (%sowner_user_id = ? OR EXISTS (
		SELECT 1 FROM rbac_resource_assignments ra
		WHERE ra.user_id = ? AND ra.resource_type = 'conversation' AND ra.resource_id = %sid
	) OR EXISTS (
		SELECT 1 FROM projects p
		WHERE p.id = %sproject_id AND (
			p.owner_user_id = ? OR EXISTS (
				SELECT 1 FROM rbac_resource_assignments pra
				WHERE pra.user_id = ? AND pra.resource_type = 'project' AND pra.resource_id = p.id
			)
		)
	))`, prefix, prefix, prefix)
	args = append(args, userID, userID, userID, userID)
	return where, args
}

// CountConversations 统计对话数量。
func (db *DB) CountConversations(search, projectID string) (int, error) {
	var count int
	var err error
	if search != "" {
		searchPattern := "%" + search + "%"
		where := ` WHERE (c.title LIKE ?
			    OR EXISTS (SELECT 1 FROM messages m WHERE m.conversation_id = c.id AND m.content LIKE ?))`
		args := []interface{}{searchPattern, searchPattern}
		where, args = appendConversationProjectFilter(where, args, projectID, "c")
		err = db.QueryRow(`SELECT COUNT(*) FROM conversations c`+where, args...).Scan(&count)
	} else {
		where := ""
		args := []interface{}{}
		where, args = appendConversationProjectFilter(where, args, projectID, "")
		if where != "" {
			where = " WHERE" + strings.TrimPrefix(where, " AND")
		}
		err = db.QueryRow(`SELECT COUNT(*) FROM conversations`+where, args...).Scan(&count)
	}
	if err != nil {
		return 0, fmt.Errorf("统计对话失败: %w", err)
	}
	return count, nil
}

func (db *DB) CountConversationsForAccess(search, projectID, userID, scope string) (int, error) {
	var count int
	var err error
	if search != "" {
		searchPattern := "%" + search + "%"
		where := ` WHERE (c.title LIKE ?
			    OR EXISTS (SELECT 1 FROM messages m WHERE m.conversation_id = c.id AND m.content LIKE ?))`
		args := []interface{}{searchPattern, searchPattern}
		where, args = appendConversationProjectFilter(where, args, projectID, "c")
		where, args = appendConversationAccessFilter(where, args, userID, scope, "c")
		err = db.QueryRow(`SELECT COUNT(*) FROM conversations c`+where, args...).Scan(&count)
	} else {
		where := ""
		args := []interface{}{}
		where, args = appendConversationProjectFilter(where, args, projectID, "")
		where, args = appendConversationAccessFilter(where, args, userID, scope, "")
		if where != "" {
			where = " WHERE" + strings.TrimPrefix(where, " AND")
		}
		err = db.QueryRow(`SELECT COUNT(*) FROM conversations`+where, args...).Scan(&count)
	}
	if err != nil {
		return 0, fmt.Errorf("统计对话失败: %w", err)
	}
	return count, nil
}

func conversationOrderClause(sortBy, tableAlias string) string {
	col := "updated_at"
	if strings.TrimSpace(strings.ToLower(sortBy)) == "created_at" {
		col = "created_at"
	}
	prefix := tableAlias
	if prefix != "" {
		prefix += "."
	}
	return "ORDER BY " + prefix + col + " DESC"
}

// ListConversations 列出所有对话
func (db *DB) ListConversations(limit, offset int, search, sortBy, projectID string) ([]*Conversation, error) {
	var rows *sql.Rows
	var err error

	if search != "" {
		// 使用 EXISTS 子查询代替 LEFT JOIN + DISTINCT，避免大表笛卡尔积
		searchPattern := "%" + search + "%"
		orderClause := conversationOrderClause(sortBy, "c")
		where := ` WHERE (c.title LIKE ?
			    OR EXISTS (SELECT 1 FROM messages m WHERE m.conversation_id = c.id AND m.content LIKE ?))`
		args := []interface{}{searchPattern, searchPattern}
		where, args = appendConversationProjectFilter(where, args, projectID, "c")
		args = append(args, limit, offset)
		rows, err = db.Query(
			`SELECT c.id, c.title, COALESCE(c.pinned, 0), c.created_at, c.updated_at, c.project_id, c.role_name, c.agent_mode, c.runtime_mode, c.workspace_persistent
			 FROM conversations c`+where+`
			 `+orderClause+`
			 LIMIT ? OFFSET ?`,
			args...,
		)
	} else {
		orderClause := conversationOrderClause(sortBy, "")
		where := ""
		args := []interface{}{}
		where, args = appendConversationProjectFilter(where, args, projectID, "")
		if where != "" {
			where = " WHERE" + strings.TrimPrefix(where, " AND")
		}
		args = append(args, limit, offset)
		rows, err = db.Query(
			"SELECT id, title, COALESCE(pinned, 0), created_at, updated_at, project_id, role_name, agent_mode, runtime_mode, workspace_persistent FROM conversations"+where+" "+orderClause+" LIMIT ? OFFSET ?",
			args...,
		)
	}

	if err != nil {
		return nil, fmt.Errorf("查询对话列表失败: %w", err)
	}
	defer rows.Close()
	return scanConversationRows(rows)
}

func (db *DB) ListConversationsForAccess(limit, offset int, search, sortBy, projectID, userID, scope string) ([]*Conversation, error) {
	if scope == RBACScopeAll || strings.TrimSpace(userID) == "" {
		return db.ListConversations(limit, offset, search, sortBy, projectID)
	}
	var rows *sql.Rows
	var err error
	if search != "" {
		searchPattern := "%" + search + "%"
		orderClause := conversationOrderClause(sortBy, "c")
		where := ` WHERE (c.title LIKE ?
			    OR EXISTS (SELECT 1 FROM messages m WHERE m.conversation_id = c.id AND m.content LIKE ?))`
		args := []interface{}{searchPattern, searchPattern}
		where, args = appendConversationProjectFilter(where, args, projectID, "c")
		where, args = appendConversationAccessFilter(where, args, userID, scope, "c")
		args = append(args, limit, offset)
		rows, err = db.Query(
			`SELECT c.id, c.title, COALESCE(c.pinned, 0), c.created_at, c.updated_at, c.project_id, c.role_name, c.agent_mode, c.runtime_mode, c.workspace_persistent
			 FROM conversations c`+where+`
			 `+orderClause+`
			 LIMIT ? OFFSET ?`, args...)
	} else {
		orderClause := conversationOrderClause(sortBy, "")
		where := ""
		args := []interface{}{}
		where, args = appendConversationProjectFilter(where, args, projectID, "")
		where, args = appendConversationAccessFilter(where, args, userID, scope, "")
		if where != "" {
			where = " WHERE" + strings.TrimPrefix(where, " AND")
		}
		args = append(args, limit, offset)
		rows, err = db.Query(
			"SELECT id, title, COALESCE(pinned, 0), created_at, updated_at, project_id, role_name, agent_mode, runtime_mode, workspace_persistent FROM conversations"+where+" "+orderClause+" LIMIT ? OFFSET ?",
			args...)
	}
	if err != nil {
		return nil, fmt.Errorf("查询对话列表失败: %w", err)
	}
	defer rows.Close()
	return scanConversationRows(rows)
}

func scanConversationRows(rows *sql.Rows) ([]*Conversation, error) {
	var conversations []*Conversation
	for rows.Next() {
		var conv Conversation
		var createdAt, updatedAt string
		var pinned int
		var projectID sql.NullString
		var roleName sql.NullString
		var agentMode sql.NullString
		var runtimeMode sql.NullString
		if err := rows.Scan(&conv.ID, &conv.Title, &pinned, &createdAt, &updatedAt, &projectID, &roleName, &agentMode, &runtimeMode, &conv.WorkspacePersistent); err != nil {
			return nil, fmt.Errorf("扫描对话失败: %w", err)
		}
		if projectID.Valid {
			conv.ProjectID = strings.TrimSpace(projectID.String)
		}
		if roleName.Valid {
			conv.RoleName = normalizeConversationRoleName(roleName.String)
		}
		if agentMode.Valid {
			conv.AgentMode = normalizeConversationAgentMode(agentMode.String)
		}
		conv.RuntimeMode, _ = NormalizeConversationRuntimeMode(runtimeMode.String)
		var err1, err2 error
		conv.CreatedAt, err1 = time.Parse("2006-01-02 15:04:05.999999999-07:00", createdAt)
		if err1 != nil {
			conv.CreatedAt, err1 = time.Parse("2006-01-02 15:04:05", createdAt)
		}
		if err1 != nil {
			conv.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		}
		conv.UpdatedAt, err2 = time.Parse("2006-01-02 15:04:05.999999999-07:00", updatedAt)
		if err2 != nil {
			conv.UpdatedAt, err2 = time.Parse("2006-01-02 15:04:05", updatedAt)
		}
		if err2 != nil {
			conv.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		}
		conv.Pinned = pinned != 0
		conversations = append(conversations, &conv)
	}
	return conversations, rows.Err()
}

// GetConversationTitle 获取对话标题（轻量查询，不加载消息）
func (db *DB) GetConversationTitle(id string) (string, error) {
	var title string
	err := db.QueryRow("SELECT title FROM conversations WHERE id = ?", id).Scan(&title)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("对话不存在")
		}
		return "", fmt.Errorf("查询对话标题失败: %w", err)
	}
	return title, nil
}

// UpdateConversationTitle 更新对话标题
func (db *DB) UpdateConversationTitle(id, title string) error {
	// 注意：不更新 updated_at，因为重命名操作不应该改变对话的更新时间
	_, err := db.Exec(
		"UPDATE conversations SET title = ? WHERE id = ?",
		title, id,
	)
	if err != nil {
		return fmt.Errorf("更新对话标题失败: %w", err)
	}
	return nil
}

// UpdateConversationPinned 更新对话置顶状态
func (db *DB) UpdateConversationPinned(id string, pinned bool) error {
	pinnedValue := 0
	if pinned {
		pinnedValue = 1
	}
	_, err := db.Exec(
		"UPDATE conversations SET pinned = ?, updated_at = ? WHERE id = ?",
		pinnedValue, time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("更新对话置顶状态失败: %w", err)
	}
	return nil
}

// UpdateConversationTime 更新对话时间
func (db *DB) UpdateConversationTime(id string) error {
	_, err := db.Exec(
		"UPDATE conversations SET updated_at = ? WHERE id = ?",
		time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("更新对话时间失败: %w", err)
	}
	return nil
}

// DeleteConversation 删除对话及其会话相关数据。
// 由于数据库外键约束设置了 ON DELETE CASCADE，删除对话时会自动删除：
// - messages（消息）
// - process_details（过程详情）
// - attack_chain_nodes（攻击链节点）
// - attack_chain_edges（攻击链边）
// 漏洞记录会保留：vulnerabilities.conversation_id 使用 ON DELETE SET NULL，仅解除与会话的关联。
// 注意：knowledge_retrieval_logs 在删除前会被显式清理。
func (db *DB) DeleteConversation(id string) error {
	return db.DeleteConversationWithWorkspaceRetention(id, false)
}

// DeleteConversationWithWorkspaceRetention atomically preserves the managed
// named-volume claim, when requested, before the conversation row and its
// runtime record are cascade-deleted. The retained claim deliberately has no
// foreign key to conversations because it must outlive the chat history.
func (db *DB) DeleteConversationWithWorkspaceRetention(id string, retainWorkspace bool) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("对话 ID 不能为空")
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("开始删除对话事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var title, runtimeMode string
	var projectID sql.NullString
	var workspaceID sql.NullString
	var workspacePersistent bool
	if err := tx.QueryRow(`
		SELECT title, project_id, runtime_mode, workspace_persistent, workspace_id
		FROM conversations WHERE id = ?
	`, id).Scan(&title, &projectID, &runtimeMode, &workspacePersistent, &workspaceID); err != nil {
		if err == sql.ErrNoRows {
			return errors.New("对话不存在")
		}
		return fmt.Errorf("查询待删除对话失败: %w", err)
	}
	if retainWorkspace && (runtimeMode != ConversationRuntimeModeContainer || !workspacePersistent) {
		return errors.New("只有启用持久工作区的容器对话可保留工作区")
	}
	workspaceKind := ""
	if strings.TrimSpace(workspaceID.String) != "" {
		if err := tx.QueryRow("SELECT kind FROM container_workspaces WHERE id = ?", workspaceID.String).Scan(&workspaceKind); err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("查询对话工作区类型失败: %w", err)
		}
	}
	if retainWorkspace && workspaceKind == ContainerWorkspaceKindShared {
		return errors.New("共享工作区不随单个对话保留或删除")
	}

	// 删除对话前补全漏洞来源标签，便于在漏洞库中追溯已删除会话的发现。
	if _, err := tx.Exec(`
		UPDATE vulnerabilities
		SET conversation_tag = COALESCE(NULLIF(TRIM(conversation_tag), ''), ?)
		WHERE conversation_id = ?
	`, title, id); err != nil {
		db.logger.Warn("更新漏洞来源标签失败", zap.String("conversationId", id), zap.Error(err))
	}
	if _, err := tx.Exec("DELETE FROM knowledge_retrieval_logs WHERE conversation_id = ?", id); err != nil {
		db.logger.Warn("删除知识检索日志失败", zap.String("conversationId", id), zap.Error(err))
	}

	if retainWorkspace {
		runtimeID := containerruntime.RuntimeID("conversation-" + id)
		volumeName := containerruntime.WorkspaceVolumeName(runtimeID)
		if strings.TrimSpace(workspaceID.String) != "" {
			volumeName = containerruntime.WorkspaceVolumeNameForID(workspaceID.String)
		}
		if _, err := tx.Exec(`
			INSERT INTO retained_container_workspaces (
				original_conversation_id, conversation_title, runtime_id, volume_name, retained_at
			) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(original_conversation_id) DO UPDATE SET
				conversation_title = excluded.conversation_title,
				runtime_id = excluded.runtime_id,
				volume_name = excluded.volume_name,
				retained_at = excluded.retained_at
		`, id, title, string(runtimeID), volumeName, formatSQLiteUTC(time.Now())); err != nil {
			return fmt.Errorf("保留对话工作区声明失败: %w", err)
		}
	} else if _, err := tx.Exec("DELETE FROM retained_container_workspaces WHERE original_conversation_id = ?", id); err != nil {
		return fmt.Errorf("清理对话工作区声明失败: %w", err)
	}

	result, err := tx.Exec("DELETE FROM conversations WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("删除对话失败: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("对话不存在")
	}
	// Dedicated workspace resources belong to this conversation. Retained
	// volumes are represented by retained_container_workspaces after deletion;
	// shared workspace resources remain independent and attached elsewhere.
	if workspaceKind == ContainerWorkspaceKindDedicated && strings.TrimSpace(workspaceID.String) != "" {
		if _, err := tx.Exec("DELETE FROM container_workspaces WHERE id = ?", workspaceID.String); err != nil {
			return fmt.Errorf("清理专属工作区资源失败: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交删除对话事务失败: %w", err)
	}

	db.removeConversationScopedDirs(id, strings.TrimSpace(projectID.String))
	db.logger.Info("对话已删除（漏洞记录已保留）",
		zap.String("conversationId", id), zap.Bool("workspaceRetained", retainWorkspace))
	return nil
}

func sanitizeConversationPathSegment(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "default"
	}
	s = strings.ReplaceAll(s, string(filepath.Separator), "-")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, "..", "__")
	if len(s) > 180 {
		s = s[:180]
	}
	return s
}

func (db *DB) removeConversationScopedDir(base, conversationID, label string) {
	base = strings.TrimSpace(base)
	if base == "" {
		return
	}
	dir := filepath.Join(base, sanitizeConversationPathSegment(conversationID))
	if rmErr := os.RemoveAll(dir); rmErr != nil {
		if db.logger != nil {
			db.logger.Warn("删除会话目录失败",
				zap.String("conversationId", conversationID),
				zap.String("kind", label),
				zap.String("dir", dir),
				zap.Error(rmErr))
		}
	}
}

func (db *DB) einoReductionBaseDir() string {
	if db == nil {
		return ""
	}
	if base := strings.TrimSpace(db.einoReductionRootDir); base != "" {
		return base
	}
	return filepath.Join("tmp", "reduction")
}

// EinoReductionBaseDir returns the configured reduction cache root.
func (db *DB) EinoReductionBaseDir() string {
	return db.einoReductionBaseDir()
}

// ConversationArtifactsBaseDir returns the conversation-scoped artifacts root.
func (db *DB) ConversationArtifactsBaseDir() string {
	if db == nil {
		return ""
	}
	return strings.TrimSpace(db.conversationArtifactsDir)
}

// EinoWorkspaceBaseDir returns the configured agent workspace root.
func (db *DB) EinoWorkspaceBaseDir() string {
	return db.einoWorkspaceBaseDir()
}

func (db *DB) einoWorkspaceBaseDir() string {
	if db == nil {
		return ""
	}
	if base := strings.TrimSpace(db.einoWorkspaceRootDir); base != "" {
		return base
	}
	return filepath.Join("tmp", "workspace")
}

func (db *DB) removeConversationScopedDirs(conversationID, projectID string) {
	// summarization transcript, etc.
	db.removeConversationScopedDir(db.conversationArtifactsDir, conversationID, "conversation_artifacts")
	// Eino plantask JSON boards (skills_dir/.eino/plantask/<id>/).
	db.removeConversationScopedDir(db.einoPlantaskBaseDir, conversationID, "plantask")
	// Eino ADK runner checkpoints (checkpoint_dir/<id>/).
	db.removeConversationScopedDir(db.einoCheckpointBaseDir, conversationID, "eino_checkpoint")
	// Eino reduction persisted tool outputs (tmp/reduction/conversations/<id>/).
	// Project-bound sessions share projects/<id>/ — skip on single conversation delete.
	if strings.TrimSpace(projectID) == "" {
		reductionBase := filepath.Join(db.einoReductionBaseDir(), "conversations")
		db.removeConversationScopedDir(reductionBase, conversationID, "reduction")
		workspaceBase := filepath.Join(db.einoWorkspaceBaseDir(), "conversations")
		db.removeConversationScopedDir(workspaceBase, conversationID, "workspace")
	}
}

func (db *DB) removeProjectScopedDirs(projectID string) {
	// Eino reduction persisted tool outputs (tmp/reduction/projects/<id>/).
	reductionBase := filepath.Join(db.einoReductionBaseDir(), "projects")
	db.removeConversationScopedDir(reductionBase, projectID, "reduction")
	// Agent download/analysis workspace (tmp/workspace/projects/<id>/).
	workspaceBase := filepath.Join(db.einoWorkspaceBaseDir(), "projects")
	db.removeConversationScopedDir(workspaceBase, projectID, "workspace")
}

// SaveAgentTrace 保存最后一轮代理消息轨迹与助手输出摘要。
// SQLite 列名仍为 last_react_input / last_react_output，与历史库表兼容；语义上为「全模式代理轨迹」，非仅 ReAct。
func (db *DB) SaveAgentTrace(conversationID, traceInputJSON, assistantOutput string) error {
	_, err := db.Exec(
		"UPDATE conversations SET last_react_input = ?, last_react_output = ?, updated_at = ? WHERE id = ?",
		traceInputJSON, assistantOutput, time.Now(), conversationID,
	)
	if err != nil {
		return fmt.Errorf("保存代理轨迹失败: %w", err)
	}
	return nil
}

// GetAgentTrace 读取 conversations 中保存的代理轨迹（列名 last_react_*）。
func (db *DB) GetAgentTrace(conversationID string) (traceInputJSON, assistantOutput string, err error) {
	var input, output sql.NullString
	err = db.QueryRow(
		"SELECT last_react_input, last_react_output FROM conversations WHERE id = ?",
		conversationID,
	).Scan(&input, &output)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", fmt.Errorf("对话不存在")
		}
		return "", "", fmt.Errorf("获取代理轨迹失败: %w", err)
	}

	if input.Valid {
		traceInputJSON = input.String
	}
	if output.Valid {
		assistantOutput = output.String
	}

	return traceInputJSON, assistantOutput, nil
}

// ConversationHasToolProcessDetails 对话是否存在已落库的工具调用/结果（用于多代理等场景下 MCP execution id 未汇总时的攻击链判定）。
func (db *DB) ConversationHasToolProcessDetails(conversationID string) (bool, error) {
	var n int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM process_details WHERE conversation_id = ? AND event_type IN ('tool_call', 'tool_result')`,
		conversationID,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("查询过程详情失败: %w", err)
	}
	return n > 0, nil
}

// AddMessage 添加消息
func (db *DB) AddMessage(conversationID, role, content string, mcpExecutionIDs []string) (*Message, error) {
	id := uuid.New().String()
	now := time.Now()

	var mcpIDsJSON string
	if len(mcpExecutionIDs) > 0 {
		jsonData, err := json.Marshal(mcpExecutionIDs)
		if err != nil {
			db.logger.Warn("序列化MCP执行ID失败", zap.Error(err))
		} else {
			mcpIDsJSON = string(jsonData)
		}
	}

	_, err := db.Exec(
		"INSERT INTO messages (id, conversation_id, role, content, reasoning_content, mcp_execution_ids, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		id, conversationID, role, content, "", mcpIDsJSON, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("添加消息失败: %w", err)
	}

	// 更新对话时间
	if err := db.UpdateConversationTime(conversationID); err != nil {
		db.logger.Warn("更新对话时间失败", zap.Error(err))
	}

	message := &Message{
		ID:              id,
		ConversationID:  conversationID,
		Role:            role,
		Content:         content,
		MCPExecutionIDs: mcpExecutionIDs,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	return message, nil
}

// UpdateAssistantMessageFinalize 更新助手消息终态（正文、MCP id、思考链聚合文本，供无轨迹回退时回放）。
func (db *DB) UpdateAssistantMessageFinalize(messageID, content string, mcpExecutionIDs []string, reasoningContent string) error {
	var mcpIDsJSON string
	if len(mcpExecutionIDs) > 0 {
		jsonData, err := json.Marshal(mcpExecutionIDs)
		if err != nil {
			return fmt.Errorf("序列化MCP执行ID失败: %w", err)
		}
		mcpIDsJSON = string(jsonData)
	}
	_, err := db.Exec(
		"UPDATE messages SET content = ?, mcp_execution_ids = ?, reasoning_content = ?, updated_at = ? WHERE id = ?",
		content, mcpIDsJSON, strings.TrimSpace(reasoningContent), time.Now(), messageID,
	)
	if err != nil {
		return fmt.Errorf("更新助手消息失败: %w", err)
	}
	return nil
}

// GetMessages 获取对话的所有消息
func (db *DB) GetMessages(conversationID string) ([]Message, error) {
	rows, err := db.Query(
		"SELECT id, conversation_id, role, content, reasoning_content, mcp_execution_ids, created_at, updated_at FROM messages WHERE conversation_id = ? ORDER BY created_at ASC, rowid ASC",
		conversationID,
	)
	if err != nil {
		return nil, fmt.Errorf("查询消息失败: %w", err)
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var msg Message
		var reasoning sql.NullString
		var mcpIDsJSON sql.NullString
		var createdAt string
		var updatedAt sql.NullString

		if err := rows.Scan(&msg.ID, &msg.ConversationID, &msg.Role, &msg.Content, &reasoning, &mcpIDsJSON, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("扫描消息失败: %w", err)
		}
		if reasoning.Valid {
			msg.ReasoningContent = reasoning.String
		}

		// 尝试多种时间格式解析
		var err error
		msg.CreatedAt, err = time.Parse("2006-01-02 15:04:05.999999999-07:00", createdAt)
		if err != nil {
			msg.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
		}
		if err != nil {
			msg.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		}

		// updated_at 兼容老库：字段不存在/为空时回退为 created_at
		if updatedAt.Valid && strings.TrimSpace(updatedAt.String) != "" {
			msg.UpdatedAt, err = time.Parse("2006-01-02 15:04:05.999999999-07:00", updatedAt.String)
			if err != nil {
				msg.UpdatedAt, err = time.Parse("2006-01-02 15:04:05", updatedAt.String)
			}
			if err != nil {
				msg.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt.String)
			}
		}
		if msg.UpdatedAt.IsZero() {
			msg.UpdatedAt = msg.CreatedAt
		}

		// 解析MCP执行ID
		if mcpIDsJSON.Valid && mcpIDsJSON.String != "" {
			if err := json.Unmarshal([]byte(mcpIDsJSON.String), &msg.MCPExecutionIDs); err != nil {
				db.logger.Warn("解析MCP执行ID失败", zap.Error(err))
			}
		}

		messages = append(messages, msg)
	}

	return messages, nil
}

// GetMessagesLite 获取对话消息（不含 reasoning_content），用于历史会话快速切换。
func (db *DB) GetMessagesLite(conversationID string) ([]Message, error) {
	rows, err := db.Query(
		"SELECT id, conversation_id, role, content, mcp_execution_ids, created_at, updated_at FROM messages WHERE conversation_id = ? ORDER BY created_at ASC, rowid ASC",
		conversationID,
	)
	if err != nil {
		return nil, fmt.Errorf("查询消息失败: %w", err)
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var msg Message
		var mcpIDsJSON sql.NullString
		var createdAt string
		var updatedAt sql.NullString

		if err := rows.Scan(&msg.ID, &msg.ConversationID, &msg.Role, &msg.Content, &mcpIDsJSON, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("扫描消息失败: %w", err)
		}

		var err error
		msg.CreatedAt, err = time.Parse("2006-01-02 15:04:05.999999999-07:00", createdAt)
		if err != nil {
			msg.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
		}
		if err != nil {
			msg.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		}

		if updatedAt.Valid && strings.TrimSpace(updatedAt.String) != "" {
			msg.UpdatedAt, err = time.Parse("2006-01-02 15:04:05.999999999-07:00", updatedAt.String)
			if err != nil {
				msg.UpdatedAt, err = time.Parse("2006-01-02 15:04:05", updatedAt.String)
			}
			if err != nil {
				msg.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt.String)
			}
		}
		if msg.UpdatedAt.IsZero() {
			msg.UpdatedAt = msg.CreatedAt
		}

		if mcpIDsJSON.Valid && mcpIDsJSON.String != "" {
			if err := json.Unmarshal([]byte(mcpIDsJSON.String), &msg.MCPExecutionIDs); err != nil {
				db.logger.Warn("解析MCP执行ID失败", zap.Error(err))
			}
		}

		messages = append(messages, msg)
	}

	return messages, nil
}

// turnSliceRange 根据任意一条消息 ID 定位「一轮对话」在 msgs 中的 [start, end) 下标区间（msgs 须已按时间升序，与 GetMessages 一致）。
// 一轮 = 从某条 user 消息起，至下一条 user 之前（含中间所有 assistant）。
func turnSliceRange(msgs []Message, anchorID string) (start, end int, err error) {
	idx := -1
	for i := range msgs {
		if msgs[i].ID == anchorID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return 0, 0, fmt.Errorf("message not found")
	}
	start = idx
	for start > 0 && msgs[start].Role != "user" {
		start--
	}
	if start < len(msgs) && msgs[start].Role != "user" {
		start = 0
	}
	end = len(msgs)
	for i := start + 1; i < len(msgs); i++ {
		if msgs[i].Role == "user" {
			end = i
			break
		}
	}
	return start, end, nil
}

// DeleteConversationTurn 删除锚点所在轮次的全部消息（用户提问 + 该轮助手回复等），并清空 last_react_*，避免与消息表不一致。
func (db *DB) DeleteConversationTurn(conversationID, anchorMessageID string) (deletedIDs []string, err error) {
	msgs, err := db.GetMessages(conversationID)
	if err != nil {
		return nil, err
	}
	start, end, err := turnSliceRange(msgs, anchorMessageID)
	if err != nil {
		return nil, err
	}
	if start >= end {
		return nil, fmt.Errorf("empty turn range")
	}
	deletedIDs = make([]string, 0, end-start)
	for i := start; i < end; i++ {
		deletedIDs = append(deletedIDs, msgs[i].ID)
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	ph := strings.Repeat("?,", len(deletedIDs))
	ph = ph[:len(ph)-1]
	args := make([]interface{}, 0, 1+len(deletedIDs))
	args = append(args, conversationID)
	for _, id := range deletedIDs {
		args = append(args, id)
	}
	res, err := tx.Exec(
		"DELETE FROM messages WHERE conversation_id = ? AND id IN ("+ph+")",
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("delete messages: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if int(n) != len(deletedIDs) {
		return nil, fmt.Errorf("deleted count mismatch")
	}

	_, err = tx.Exec(
		`UPDATE conversations SET last_react_input = NULL, last_react_output = NULL, updated_at = ? WHERE id = ?`,
		time.Now(), conversationID,
	)
	if err != nil {
		return nil, fmt.Errorf("clear react data: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	db.logger.Info("conversation turn deleted",
		zap.String("conversationId", conversationID),
		zap.Strings("deletedMessageIds", deletedIDs),
		zap.Int("count", len(deletedIDs)),
	)
	return deletedIDs, nil
}

// ProcessDetail 过程详情事件
type ProcessDetail struct {
	ID             string    `json:"id"`
	MessageID      string    `json:"messageId"`
	ConversationID string    `json:"conversationId"`
	EventType      string    `json:"eventType"` // iteration, thinking, reasoning_chain, tool_calls_detected, tool_call, tool_result, progress, error
	Message        string    `json:"message"`
	Data           string    `json:"data"` // JSON格式的数据
	CreatedAt      time.Time `json:"createdAt"`
}

// GetTurnUserMessage 返回锚点消息所在轮次中的用户原文（最近一条 user 消息，不含完整历史）。
func (db *DB) GetTurnUserMessage(conversationID, anchorMessageID string) (string, error) {
	conversationID = strings.TrimSpace(conversationID)
	anchorMessageID = strings.TrimSpace(anchorMessageID)
	if conversationID == "" || anchorMessageID == "" {
		return "", nil
	}
	var content string
	err := db.QueryRow(`
SELECT m.content FROM messages m
WHERE m.conversation_id = ? AND m.role = 'user'
  AND m.created_at <= COALESCE((SELECT created_at FROM messages WHERE id = ? AND conversation_id = ?), m.created_at)
ORDER BY m.created_at DESC, m.rowid DESC
LIMIT 1`, conversationID, anchorMessageID, conversationID).Scan(&content)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("query turn user message: %w", err)
	}
	return content, nil
}

// AssistantCognitionTexts 单条助手消息上的思考/推理/规划文本。
type AssistantCognitionTexts struct {
	Thinking       string
	ReasoningChain string
	Planning       string
}

// GetAssistantCognitionTexts 聚合助手消息在 process_details 中的 thinking / reasoning_chain / planning。
func (db *DB) GetAssistantCognitionTexts(assistantMessageID string) (AssistantCognitionTexts, error) {
	assistantMessageID = strings.TrimSpace(assistantMessageID)
	if assistantMessageID == "" {
		return AssistantCognitionTexts{}, nil
	}
	rows, err := db.Query(`
SELECT event_type, message FROM process_details
WHERE message_id = ? AND event_type IN ('thinking', 'reasoning_chain', 'planning')
ORDER BY created_at ASC, rowid ASC`, assistantMessageID)
	if err != nil {
		return AssistantCognitionTexts{}, fmt.Errorf("query assistant cognition: %w", err)
	}
	defer rows.Close()

	var thinkingParts, reasoningParts, planningParts []string
	for rows.Next() {
		var eventType, message string
		if err := rows.Scan(&eventType, &message); err != nil {
			continue
		}
		msg := strings.TrimSpace(message)
		if msg == "" {
			continue
		}
		switch eventType {
		case "thinking":
			thinkingParts = append(thinkingParts, msg)
		case "reasoning_chain":
			reasoningParts = append(reasoningParts, msg)
		case "planning":
			planningParts = append(planningParts, msg)
		}
	}
	return AssistantCognitionTexts{
		Thinking:       strings.Join(thinkingParts, "\n\n"),
		ReasoningChain: strings.Join(reasoningParts, "\n\n"),
		Planning:       strings.Join(planningParts, "\n\n"),
	}, nil
}

// AddProcessDetail 添加过程详情事件
func (db *DB) AddProcessDetail(messageID, conversationID, eventType, message string, data interface{}) error {
	_, err := db.AddProcessDetailWithID(messageID, conversationID, eventType, message, data)
	return err
}

// AddProcessDetailWithID 添加过程详情事件并返回记录 ID。
func (db *DB) AddProcessDetailWithID(messageID, conversationID, eventType, message string, data interface{}) (string, error) {
	id := uuid.New().String()

	var dataJSON string
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			db.logger.Warn("序列化过程详情数据失败", zap.Error(err))
		} else {
			dataJSON = string(jsonData)
		}
	}

	_, err := db.Exec(
		"INSERT INTO process_details (id, message_id, conversation_id, event_type, message, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		id, messageID, conversationID, eventType, message, dataJSON, time.Now(),
	)
	if err != nil {
		return "", fmt.Errorf("添加过程详情失败: %w", err)
	}

	db.maybeRecordModelTokenUsage(messageID, conversationID, id, eventType, data)

	return id, nil
}

// UpdateProcessDetailContent 更新流式聚合详情的正文与元数据。使用固定记录 ID，
// 避免每个 token 新增一行，同时让页面刷新能读取到尚未结束的规划输出。
func (db *DB) UpdateProcessDetailContent(id, message string, data interface{}) error {
	var dataJSON string
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("序列化过程详情数据失败: %w", err)
		}
		dataJSON = string(jsonData)
	}
	result, err := db.Exec(
		"UPDATE process_details SET message = ?, data = ? WHERE id = ?",
		message, dataJSON, strings.TrimSpace(id),
	)
	if err != nil {
		return fmt.Errorf("更新过程详情失败: %w", err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr == nil && affected == 0 {
		return fmt.Errorf("过程详情不存在: %s", id)
	}
	return nil
}

// DeleteProcessDetail 删除被判定为工具结果回显的临时规划记录。
func (db *DB) DeleteProcessDetail(id string) error {
	_, err := db.Exec("DELETE FROM process_details WHERE id = ?", strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("删除过程详情失败: %w", err)
	}
	return nil
}

// GetProcessDetails 获取消息的过程详情
func (db *DB) GetProcessDetails(messageID string) ([]ProcessDetail, error) {
	rows, err := db.Query(
		"SELECT id, message_id, conversation_id, event_type, message, data, created_at FROM process_details WHERE message_id = ? ORDER BY created_at ASC, rowid ASC",
		messageID,
	)
	if err != nil {
		return nil, fmt.Errorf("查询过程详情失败: %w", err)
	}
	defer rows.Close()

	var details []ProcessDetail
	for rows.Next() {
		var detail ProcessDetail
		var createdAt string

		if err := rows.Scan(&detail.ID, &detail.MessageID, &detail.ConversationID, &detail.EventType, &detail.Message, &detail.Data, &createdAt); err != nil {
			return nil, fmt.Errorf("扫描过程详情失败: %w", err)
		}

		// 尝试多种时间格式解析
		var err error
		detail.CreatedAt, err = time.Parse("2006-01-02 15:04:05.999999999-07:00", createdAt)
		if err != nil {
			detail.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
		}
		if err != nil {
			detail.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		}

		details = append(details, detail)
	}

	return details, nil
}

// GetProcessDetailByID 获取单条过程详情。
func (db *DB) GetProcessDetailByID(id string) (*ProcessDetail, error) {
	var detail ProcessDetail
	var createdAt string
	err := db.QueryRow(
		"SELECT id, message_id, conversation_id, event_type, message, data, created_at FROM process_details WHERE id = ?",
		id,
	).Scan(&detail.ID, &detail.MessageID, &detail.ConversationID, &detail.EventType, &detail.Message, &detail.Data, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("查询过程详情失败: %w", err)
	}

	var parseErr error
	detail.CreatedAt, parseErr = time.Parse("2006-01-02 15:04:05.999999999-07:00", createdAt)
	if parseErr != nil {
		detail.CreatedAt, parseErr = time.Parse("2006-01-02 15:04:05", createdAt)
	}
	if parseErr != nil {
		detail.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	}
	return &detail, nil
}

// ProcessDetailsSummary 过程详情摘要（用于折叠态展示，避免全量加载）。
type ProcessDetailsSummary struct {
	Total                     int                           `json:"total"`
	IterationCount            int                           `json:"iterationCount"`
	MaxIteration              int                           `json:"maxIteration"`
	ToolCount                 int                           `json:"toolCount"`
	ToolExecutions            []ProcessDetailsToolExecution `json:"toolExecutions,omitempty"`
	MCPExecutionIDs           []string                      `json:"mcpExecutionIds,omitempty"`
	StartedAt                 *time.Time                    `json:"startedAt,omitempty"`
	CompletedAt               *time.Time                    `json:"completedAt,omitempty"`
	DurationMs                int64                         `json:"durationMs"`
	ElapsedMs                 *int64                        `json:"elapsedMs,omitempty"`
	ContainerInitializationMs *int64                        `json:"containerInitializationMs,omitempty"`
	ExecutionStartedAt        *time.Time                    `json:"executionStartedAt,omitempty"`
	ExecutionDurationMs       *int64                        `json:"executionDurationMs,omitempty"`
	ExecutionElapsedMs        *int64                        `json:"executionElapsedMs,omitempty"`
	Status                    string                        `json:"status,omitempty"`
}

type ProcessDetailsToolExecution struct {
	ProcessDetailID string `json:"processDetailId,omitempty"`
	ResultDetailID  string `json:"resultDetailId,omitempty"`
	ToolName        string `json:"toolName,omitempty"`
	ToolCallID      string `json:"toolCallId,omitempty"`
	ExecutionID     string `json:"executionId,omitempty"`
	Status          string `json:"status,omitempty"`
}

// GetProcessDetailsSummary 统计消息的过程详情数量与迭代轮次。
func (db *DB) GetProcessDetailsSummary(messageID string) (*ProcessDetailsSummary, error) {
	var total int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM process_details WHERE message_id = ?",
		messageID,
	).Scan(&total); err != nil {
		return nil, fmt.Errorf("统计过程详情失败: %w", err)
	}

	summary := &ProcessDetailsSummary{Total: total}
	var messageCreatedAt, messageUpdatedAt sql.NullString
	var messageContent string
	if err := db.QueryRow(
		"SELECT created_at, updated_at, content FROM messages WHERE id = ?",
		messageID,
	).Scan(&messageCreatedAt, &messageUpdatedAt, &messageContent); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("查询过程详情耗时失败: %w", err)
	}
	if messageCreatedAt.Valid {
		if startedAt := parseDBTime(messageCreatedAt.String); !startedAt.IsZero() {
			summary.StartedAt = &startedAt
		}
	}
	var terminalEvent, terminalCreatedAt string
	terminalErr := db.QueryRow(`
SELECT event_type, created_at
FROM process_details
WHERE message_id = ? AND event_type IN ('cancelled', 'timeout', 'error')
ORDER BY created_at DESC, rowid DESC
LIMIT 1`, messageID).Scan(&terminalEvent, &terminalCreatedAt)
	if terminalErr != nil && !errors.Is(terminalErr, sql.ErrNoRows) {
		return nil, fmt.Errorf("查询过程详情终态失败: %w", terminalErr)
	}
	if terminalEvent != "" {
		switch terminalEvent {
		case "cancelled":
			summary.Status = "cancelled"
		case "timeout":
			summary.Status = "timeout"
		default:
			summary.Status = "failed"
		}
		if completedAt := parseDBTime(terminalCreatedAt); !completedAt.IsZero() {
			summary.CompletedAt = &completedAt
		}
	} else if strings.TrimSpace(messageContent) == "处理中..." || strings.TrimSpace(messageContent) == "Processing..." {
		summary.Status = "running"
		if summary.StartedAt != nil {
			elapsedMs := time.Since(*summary.StartedAt).Milliseconds()
			if elapsedMs < 0 {
				elapsedMs = 0
			}
			summary.ElapsedMs = &elapsedMs
		}
	} else {
		summary.Status = "completed"
		if messageUpdatedAt.Valid {
			if completedAt := parseDBTime(messageUpdatedAt.String); !completedAt.IsZero() {
				summary.CompletedAt = &completedAt
			}
		}
	}
	if summary.StartedAt != nil && summary.CompletedAt != nil && !summary.CompletedAt.Before(*summary.StartedAt) {
		summary.DurationMs = summary.CompletedAt.Sub(*summary.StartedAt).Milliseconds()
	}
	if total == 0 {
		return summary, nil
	}

	// Container preparation is a separate user-visible phase. Keep the original
	// turn timing for compatibility, but expose an execution-only clock anchored
	// at the first durable ready event so refreshes do not fold startup time back
	// into the normal conversation duration.
	timingRows, timingErr := db.Query(`
SELECT data, created_at
FROM process_details
WHERE message_id = ? AND event_type = 'container_initialization'
ORDER BY created_at ASC, rowid ASC`, messageID)
	if timingErr != nil {
		return nil, fmt.Errorf("查询容器初始化耗时失败: %w", timingErr)
	}
	var initializationStartedAt *time.Time
	for timingRows.Next() {
		var rawData, rawCreatedAt string
		if scanErr := timingRows.Scan(&rawData, &rawCreatedAt); scanErr != nil {
			_ = timingRows.Close()
			return nil, fmt.Errorf("读取容器初始化耗时失败: %w", scanErr)
		}
		var payload struct {
			State string `json:"state"`
		}
		if json.Unmarshal([]byte(rawData), &payload) != nil {
			continue
		}
		createdAt := parseDBTime(rawCreatedAt)
		if createdAt.IsZero() {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(payload.State)) {
		case "initializing":
			if initializationStartedAt == nil {
				copy := createdAt
				initializationStartedAt = &copy
			}
		case "ready":
			if initializationStartedAt != nil && summary.ExecutionStartedAt == nil && !createdAt.Before(*initializationStartedAt) {
				copy := createdAt
				summary.ExecutionStartedAt = &copy
				duration := createdAt.Sub(*initializationStartedAt).Milliseconds()
				summary.ContainerInitializationMs = &duration
			}
		}
	}
	if closeErr := timingRows.Close(); closeErr != nil {
		return nil, fmt.Errorf("关闭容器初始化耗时结果失败: %w", closeErr)
	}
	if rowsErr := timingRows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("遍历容器初始化耗时失败: %w", rowsErr)
	}
	if summary.ExecutionStartedAt != nil {
		if summary.CompletedAt != nil && !summary.CompletedAt.Before(*summary.ExecutionStartedAt) {
			duration := summary.CompletedAt.Sub(*summary.ExecutionStartedAt).Milliseconds()
			summary.ExecutionDurationMs = &duration
		} else if summary.Status == "running" {
			elapsed := time.Since(*summary.ExecutionStartedAt).Milliseconds()
			if elapsed < 0 {
				elapsed = 0
			}
			summary.ExecutionElapsedMs = &elapsed
		}
	}

	if err := db.QueryRow(
		"SELECT COUNT(*) FROM process_details WHERE message_id = ? AND event_type = 'tool_call'",
		messageID,
	).Scan(&summary.ToolCount); err != nil {
		return nil, fmt.Errorf("统计工具调用详情失败: %w", err)
	}

	pendingToolStatus := "result_missing"
	if summary.Status == "running" {
		pendingToolStatus = "running"
	}

	execRows, err := db.Query(
		"SELECT id, event_type, data FROM process_details WHERE message_id = ? AND event_type IN ('tool_call', 'tool_result') ORDER BY created_at ASC, rowid ASC",
		messageID,
	)
	if err != nil {
		return nil, fmt.Errorf("查询工具执行摘要失败: %w", err)
	}
	seenExecIDs := make(map[string]bool)
	// A provider may reuse a fallback toolCallId across streaming rounds. Keep a
	// FIFO per ID instead of a single index so every persisted call gets at most
	// one result. ID-less results still attach to an unmatched call with the same
	// tool name (parallel nmap 1/2, 2/2 often lose one ID); different tools stay
	// unlinked so a leftover preview cannot steal another call's slot.
	toolIndexesByCallID := make(map[string][]int)
	lastMatchedToolIndexByCallID := make(map[string]int)
	matchedToolIndexes := make([]bool, 0)
	for execRows.Next() {
		var detailID string
		var eventType string
		var dataJSON string
		if err := execRows.Scan(&detailID, &eventType, &dataJSON); err != nil {
			execRows.Close()
			return nil, fmt.Errorf("扫描工具执行摘要失败: %w", err)
		}
		if dataJSON == "" {
			continue
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(dataJSON), &payload); err != nil {
			continue
		}
		toolName := processDetailString(payload, "toolName")
		toolCallID := processDetailString(payload, "toolCallId")
		execID := processDetailString(payload, "executionId")
		status := toolResultStatusFromPayload(payload, eventType)
		if eventType == "tool_call" {
			summary.ToolExecutions = append(summary.ToolExecutions, ProcessDetailsToolExecution{
				ProcessDetailID: strings.TrimSpace(detailID),
				ToolName:        toolName,
				ToolCallID:      toolCallID,
				// This summary is reconstructed from persisted history. For an
				// active assistant turn, a missing result means the call is still
				// pending; after the turn is terminal it is genuinely incomplete.
				Status: pendingToolStatus,
			})
			matchedToolIndexes = append(matchedToolIndexes, false)
			if toolCallID != "" {
				toolIndexesByCallID[toolCallID] = append(toolIndexesByCallID[toolCallID], len(summary.ToolExecutions)-1)
			}
		}
		if eventType == "tool_result" {
			idx := matchToolExecutionIndex(
				summary.ToolExecutions,
				matchedToolIndexes,
				toolCallID,
				toolName,
				toolIndexesByCallID,
				lastMatchedToolIndexByCallID,
			)
			if idx >= 0 && idx < len(summary.ToolExecutions) {
				matchedToolIndexes[idx] = true
				if toolCallID != "" {
					lastMatchedToolIndexByCallID[toolCallID] = idx
				}
				summary.ToolExecutions[idx].ResultDetailID = strings.TrimSpace(detailID)
				if summary.ToolExecutions[idx].ToolName == "" {
					summary.ToolExecutions[idx].ToolName = toolName
				}
				if summary.ToolExecutions[idx].ToolCallID == "" {
					summary.ToolExecutions[idx].ToolCallID = toolCallID
				}
				summary.ToolExecutions[idx].ExecutionID = execID
				if status != "" {
					summary.ToolExecutions[idx].Status = status
				} else {
					summary.ToolExecutions[idx].Status = "completed"
				}
			} else {
				summary.ToolExecutions = append(summary.ToolExecutions, ProcessDetailsToolExecution{
					ProcessDetailID: strings.TrimSpace(detailID),
					ToolName:        toolName,
					ToolCallID:      toolCallID,
					ExecutionID:     execID,
					Status:          status,
				})
				matchedToolIndexes = append(matchedToolIndexes, true)
			}
		}
		if execID != "" && !seenExecIDs[execID] {
			seenExecIDs[execID] = true
			summary.MCPExecutionIDs = append(summary.MCPExecutionIDs, execID)
		}
	}
	if err := execRows.Err(); err != nil {
		execRows.Close()
		return nil, fmt.Errorf("遍历工具执行摘要失败: %w", err)
	}
	execRows.Close()
	db.applyPersistedToolExecutionStatuses(summary.ToolExecutions)

	rows, err := db.Query(
		"SELECT data FROM process_details WHERE message_id = ? AND event_type = 'iteration' ORDER BY created_at ASC, rowid ASC",
		messageID,
	)
	if err != nil {
		return nil, fmt.Errorf("查询迭代详情失败: %w", err)
	}
	defer rows.Close()

	maxIter := 0
	iterCount := 0
	for rows.Next() {
		var dataJSON string
		if err := rows.Scan(&dataJSON); err != nil {
			return nil, fmt.Errorf("扫描迭代详情失败: %w", err)
		}
		iterCount++
		if dataJSON == "" {
			continue
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(dataJSON), &payload); err != nil {
			continue
		}
		if n, ok := payload["iteration"].(float64); ok && int(n) > maxIter {
			maxIter = int(n)
		}
	}
	summary.IterationCount = iterCount
	summary.MaxIteration = maxIter
	return summary, nil
}

func processDetailString(payload map[string]interface{}, key string) string {
	if payload == nil {
		return ""
	}
	v, ok := payload[key]
	if !ok || v == nil {
		return ""
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	if s == "" || s == "<nil>" {
		return ""
	}
	return s
}

func toolResultStatusFromPayload(payload map[string]interface{}, eventType string) string {
	if eventType != "tool_result" {
		return ""
	}
	if status := processDetailString(payload, "status"); strings.EqualFold(status, "background_running") {
		return "background_running"
	}
	if success, ok := payload["success"].(bool); ok {
		if success {
			return "completed"
		}
		return "failed"
	}
	if isErr, ok := payload["isError"].(bool); ok && isErr {
		return "failed"
	}
	return "completed"
}

func (db *DB) applyPersistedToolExecutionStatuses(executions []ProcessDetailsToolExecution) {
	for i := range executions {
		execID := strings.TrimSpace(executions[i].ExecutionID)
		if execID == "" {
			continue
		}
		var status string
		if err := db.QueryRow(`SELECT status FROM tool_executions WHERE id = ?`, execID).Scan(&status); err != nil {
			continue
		}
		status = strings.ToLower(strings.TrimSpace(status))
		if status == "" {
			continue
		}
		executions[i].Status = status
	}
}

func matchToolExecutionIndex(
	executions []ProcessDetailsToolExecution,
	matched []bool,
	toolCallID, toolName string,
	toolIndexesByCallID map[string][]int,
	lastMatchedToolIndexByCallID map[string]int,
) int {
	if toolCallID != "" {
		queue := toolIndexesByCallID[toolCallID]
		for len(queue) > 0 {
			candidate := queue[0]
			queue = queue[1:]
			if candidate >= 0 && candidate < len(matched) && !matched[candidate] {
				toolIndexesByCallID[toolCallID] = queue
				return candidate
			}
		}
		toolIndexesByCallID[toolCallID] = queue
		if previous, ok := lastMatchedToolIndexByCallID[toolCallID]; ok {
			return previous
		}
	}
	if toolName != "" {
		for i := range matched {
			if matched[i] {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(executions[i].ToolName), toolName) {
				return i
			}
		}
	}
	if toolCallID != "" {
		for i := range matched {
			if !matched[i] {
				return i
			}
		}
	}
	return -1
}

// GetProcessDetailsPage 分页获取消息的过程详情（按时间升序）。
func (db *DB) GetProcessDetailsPage(messageID string, limit, offset int) ([]ProcessDetail, int, error) {
	var total int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM process_details WHERE message_id = ?",
		messageID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计过程详情失败: %w", err)
	}
	if total == 0 || offset >= total {
		return nil, total, nil
	}

	rows, err := db.Query(
		"SELECT id, message_id, conversation_id, event_type, message, data, created_at FROM process_details WHERE message_id = ? ORDER BY created_at ASC, rowid ASC LIMIT ? OFFSET ?",
		messageID, limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("查询过程详情失败: %w", err)
	}
	defer rows.Close()

	var details []ProcessDetail
	for rows.Next() {
		var detail ProcessDetail
		var createdAt string

		if err := rows.Scan(&detail.ID, &detail.MessageID, &detail.ConversationID, &detail.EventType, &detail.Message, &detail.Data, &createdAt); err != nil {
			return nil, 0, fmt.Errorf("扫描过程详情失败: %w", err)
		}

		var parseErr error
		detail.CreatedAt, parseErr = time.Parse("2006-01-02 15:04:05.999999999-07:00", createdAt)
		if parseErr != nil {
			detail.CreatedAt, parseErr = time.Parse("2006-01-02 15:04:05", createdAt)
		}
		if parseErr != nil {
			detail.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		}

		details = append(details, detail)
	}

	return details, total, nil
}

// GetProcessDetailOffset 返回某条过程详情在所属消息详情流中的零基 offset。
func (db *DB) GetProcessDetailOffset(messageID, detailID string) (int, error) {
	messageID = strings.TrimSpace(messageID)
	detailID = strings.TrimSpace(detailID)
	if messageID == "" || detailID == "" {
		return 0, fmt.Errorf("messageID and detailID are required")
	}
	var createdAt string
	var rowID int64
	if err := db.QueryRow(
		"SELECT created_at, rowid FROM process_details WHERE message_id = ? AND id = ?",
		messageID, detailID,
	).Scan(&createdAt, &rowID); err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("过程详情不存在")
		}
		return 0, fmt.Errorf("查询过程详情锚点失败: %w", err)
	}
	var offset int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM process_details
		 WHERE message_id = ?
		   AND (created_at < ? OR (created_at = ? AND rowid < ?))`,
		messageID, createdAt, createdAt, rowID,
	).Scan(&offset); err != nil {
		return 0, fmt.Errorf("计算过程详情锚点位置失败: %w", err)
	}
	return offset, nil
}

// GetProcessDetailsByConversation 获取对话的所有过程详情（按消息分组）
func (db *DB) GetProcessDetailsByConversation(conversationID string) (map[string][]ProcessDetail, error) {
	rows, err := db.Query(
		"SELECT id, message_id, conversation_id, event_type, message, data, created_at FROM process_details WHERE conversation_id = ? ORDER BY created_at ASC, rowid ASC",
		conversationID,
	)
	if err != nil {
		return nil, fmt.Errorf("查询过程详情失败: %w", err)
	}
	defer rows.Close()

	detailsMap := make(map[string][]ProcessDetail)
	for rows.Next() {
		var detail ProcessDetail
		var createdAt string

		if err := rows.Scan(&detail.ID, &detail.MessageID, &detail.ConversationID, &detail.EventType, &detail.Message, &detail.Data, &createdAt); err != nil {
			return nil, fmt.Errorf("扫描过程详情失败: %w", err)
		}

		// 尝试多种时间格式解析
		var err error
		detail.CreatedAt, err = time.Parse("2006-01-02 15:04:05.999999999-07:00", createdAt)
		if err != nil {
			detail.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
		}
		if err != nil {
			detail.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		}

		detailsMap[detail.MessageID] = append(detailsMap[detail.MessageID], detail)
	}

	return detailsMap, nil
}
