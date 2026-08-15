package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const asmContinuationRecoveredMessage = "原任务已在 ASM 扫描完成后转入自动续跑。"

// ASMAgentContinuation records the durable hand-off from a completed ASM scan
// back to the Agent conversation that created it.
type ASMAgentContinuation struct {
	ID                  string     `json:"id"`
	TaskIDsJSON         string     `json:"task_ids_json"`
	ConversationID      string     `json:"conversation_id"`
	OwnerUserID         string     `json:"owner_user_id"`
	Behavior            string     `json:"behavior"`
	DeliveryMode        string     `json:"delivery_mode"`
	RunningPrompt       string     `json:"running_prompt"`
	IdlePrompt          string     `json:"idle_prompt"`
	Status              string     `json:"status"`
	AgentWasRunning     bool       `json:"agent_was_running"`
	AgentStartedAt      *time.Time `json:"agent_started_at,omitempty"`
	ConsumedTaskIDsJSON string     `json:"consumed_task_ids_json"`
	ConsumedAt          *time.Time `json:"consumed_at,omitempty"`
	ConsumedTool        string     `json:"consumed_tool,omitempty"`
	Attempts            int        `json:"attempts"`
	LastError           string     `json:"last_error,omitempty"`
	ReadyAt             *time.Time `json:"ready_at,omitempty"`
	CompletedAt         *time.Time `json:"completed_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// ASMAgentContinuationConsumption describes result reads that suppressed one
// or more queued Agent continuation notifications. A task is only consumed by
// the source conversation that originally created the continuation.
type ASMAgentContinuationConsumption struct {
	TaskID                   string   `json:"task_id"`
	MatchedContinuationIDs   []string `json:"matched_continuation_ids,omitempty"`
	CompletedContinuationIDs []string `json:"completed_continuation_ids,omitempty"`
}

// ASMAgentContinuationFilter limits durable Agent continuation diagnostics.
// Access is applied to the source conversation so non-admin users cannot read
// another user's continuation history.
type ASMAgentContinuationFilter struct {
	Statuses []string
	Query    string
	Page     int
	PageSize int
	Access   RBACListAccess
}

const asmAgentContinuationColumns = `id, task_ids_json, conversation_id, owner_user_id,
	behavior, delivery_mode, running_prompt, idle_prompt, status, agent_was_running, agent_started_at, attempts,
	consumed_task_ids_json, consumed_at, consumed_tool, last_error, ready_at, completed_at, created_at, updated_at`

func scanASMAgentContinuation(scanner interface{ Scan(...interface{}) error }) (*ASMAgentContinuation, error) {
	var item ASMAgentContinuation
	var wasRunning int
	var agentStartedAt, consumedAt, readyAt, completedAt sql.NullString
	var createdAt, updatedAt string
	if err := scanner.Scan(
		&item.ID, &item.TaskIDsJSON, &item.ConversationID, &item.OwnerUserID,
		&item.Behavior, &item.DeliveryMode, &item.RunningPrompt, &item.IdlePrompt, &item.Status,
		&wasRunning, &agentStartedAt, &item.Attempts, &item.ConsumedTaskIDsJSON, &consumedAt,
		&item.ConsumedTool, &item.LastError, &readyAt, &completedAt,
		&createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	item.AgentWasRunning = wasRunning != 0
	if agentStartedAt.Valid && strings.TrimSpace(agentStartedAt.String) != "" {
		value := parseDBTime(agentStartedAt.String)
		if !value.IsZero() {
			item.AgentStartedAt = &value
		}
	}
	if strings.TrimSpace(item.ConsumedTaskIDsJSON) == "" {
		item.ConsumedTaskIDsJSON = "[]"
	}
	if strings.TrimSpace(item.DeliveryMode) == "" {
		item.DeliveryMode = "after_turn"
	}
	if consumedAt.Valid && strings.TrimSpace(consumedAt.String) != "" {
		value := parseDBTime(consumedAt.String)
		if !value.IsZero() {
			item.ConsumedAt = &value
		}
	}
	item.CreatedAt = parseDBTime(createdAt)
	item.UpdatedAt = parseDBTime(updatedAt)
	if readyAt.Valid && strings.TrimSpace(readyAt.String) != "" {
		value := parseDBTime(readyAt.String)
		item.ReadyAt = &value
	}
	if completedAt.Valid && strings.TrimSpace(completedAt.String) != "" {
		value := parseDBTime(completedAt.String)
		item.CompletedAt = &value
	}
	return &item, nil
}

func (db *DB) CreateASMAgentContinuation(item *ASMAgentContinuation) error {
	if item == nil {
		return fmt.Errorf("ASM Agent 联动记录不能为空")
	}
	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	if strings.TrimSpace(item.ConsumedTaskIDsJSON) == "" {
		item.ConsumedTaskIDsJSON = "[]"
	}
	item.UpdatedAt = now
	_, err := db.Exec(`INSERT INTO asm_agent_continuations (
		id, task_ids_json, conversation_id, owner_user_id, behavior, delivery_mode, running_prompt,
		idle_prompt, status, agent_was_running, agent_started_at, attempts,
		consumed_task_ids_json, consumed_at, consumed_tool, last_error, ready_at,
		completed_at, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID, item.TaskIDsJSON, item.ConversationID, item.OwnerUserID, item.Behavior,
		item.DeliveryMode, item.RunningPrompt, item.IdlePrompt, item.Status, boolToInt(item.AgentWasRunning),
		item.AgentStartedAt, item.Attempts, item.ConsumedTaskIDsJSON, item.ConsumedAt, item.ConsumedTool,
		item.LastError, item.ReadyAt, item.CompletedAt, item.CreatedAt, item.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("创建 ASM Agent 联动记录失败: %w", err)
	}
	return nil
}

func decodeASMAgentContinuationTaskIDs(raw string) []string {
	var values []string
	_ = json.Unmarshal([]byte(raw), &values)
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func containsASMAgentContinuationTask(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// ConsumeASMAgentContinuationTask records a successful Agent-side result read.
// Only not-yet-delivered jobs are eligible. When every task in a continuation
// has been consumed, agent_consumed becomes a protected terminal state and the
// queued worker must not insert another completion prompt.
func (db *DB) ConsumeASMAgentContinuationTask(conversationID, taskID, toolName string) (ASMAgentContinuationConsumption, error) {
	result := ASMAgentContinuationConsumption{TaskID: strings.TrimSpace(taskID)}
	conversationID = strings.TrimSpace(conversationID)
	toolName = strings.TrimSpace(toolName)
	if conversationID == "" || result.TaskID == "" {
		return result, nil
	}
	if toolName == "" {
		toolName = "asm_list_assets"
	}

	tx, err := db.Begin()
	if err != nil {
		return result, fmt.Errorf("开始记录 ASM 结果消费失败: %w", err)
	}
	defer tx.Rollback()
	type candidate struct {
		id, taskIDsJSON, consumedJSON, status string
	}
	rows, err := tx.Query(`SELECT id, task_ids_json, consumed_task_ids_json, status
		FROM asm_agent_continuations
		WHERE conversation_id = ? AND status IN ('waiting','ready','retry','queued')
		ORDER BY created_at ASC`, conversationID)
	if err != nil {
		return result, fmt.Errorf("查询待去重 ASM 联动失败: %w", err)
	}
	candidates := make([]candidate, 0)
	for rows.Next() {
		var item candidate
		if scanErr := rows.Scan(&item.id, &item.taskIDsJSON, &item.consumedJSON, &item.status); scanErr != nil {
			rows.Close()
			return result, fmt.Errorf("读取待去重 ASM 联动失败: %w", scanErr)
		}
		candidates = append(candidates, item)
	}
	if rowsErr := rows.Close(); rowsErr != nil {
		return result, rowsErr
	}

	now := time.Now().UTC()
	for _, item := range candidates {
		taskIDs := decodeASMAgentContinuationTaskIDs(item.taskIDsJSON)
		if !containsASMAgentContinuationTask(taskIDs, result.TaskID) {
			continue
		}
		consumed := decodeASMAgentContinuationTaskIDs(item.consumedJSON)
		if !containsASMAgentContinuationTask(consumed, result.TaskID) {
			consumed = append(consumed, result.TaskID)
		}
		orderedConsumed := make([]string, 0, len(consumed))
		for _, candidateTaskID := range taskIDs {
			if containsASMAgentContinuationTask(consumed, candidateTaskID) {
				orderedConsumed = append(orderedConsumed, candidateTaskID)
			}
		}
		consumedJSON, _ := json.Marshal(orderedConsumed)
		fullyConsumed := len(taskIDs) > 0 && len(orderedConsumed) == len(taskIDs)
		nextStatus := item.status
		if fullyConsumed {
			nextStatus = "agent_consumed"
		}
		update, updateErr := tx.Exec(`UPDATE asm_agent_continuations
			SET consumed_task_ids_json = ?, consumed_at = ?, consumed_tool = ?, status = ?,
				completed_at = CASE WHEN ? = 'agent_consumed' THEN ? ELSE completed_at END,
				last_error = '', updated_at = ?
			WHERE id = ? AND status = ?`,
			string(consumedJSON), now, toolName, nextStatus, nextStatus, now, now, item.id, item.status)
		if updateErr != nil {
			return result, fmt.Errorf("记录 ASM 结果消费失败: %w", updateErr)
		}
		affected, _ := update.RowsAffected()
		if affected == 0 {
			continue
		}
		result.MatchedContinuationIDs = append(result.MatchedContinuationIDs, item.id)
		if fullyConsumed {
			result.CompletedContinuationIDs = append(result.CompletedContinuationIDs, item.id)
		}
	}
	if err = tx.Commit(); err != nil {
		return result, fmt.Errorf("提交 ASM 结果消费失败: %w", err)
	}
	return result, nil
}

// ClaimASMAgentContinuationForDelivery is the atomic boundary between an
// Agent reading results itself and the system inserting an automatic prompt.
// Whichever transition wins first suppresses the other path.
func (db *DB) ClaimASMAgentContinuationForDelivery(id string) (*ASMAgentContinuation, bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, false, fmt.Errorf("ASM Agent 联动 ID 不能为空")
	}
	now := time.Now().UTC()
	update, err := db.Exec(`UPDATE asm_agent_continuations
		SET status = 'running', attempts = attempts + 1, last_error = '', updated_at = ?
		WHERE id = ? AND status IN ('ready','retry','queued')`, now, id)
	if err != nil {
		return nil, false, fmt.Errorf("领取 ASM Agent 联动失败: %w", err)
	}
	affected, _ := update.RowsAffected()
	item, readErr := db.GetASMAgentContinuation(id)
	if readErr != nil {
		return nil, false, readErr
	}
	return item, affected > 0, nil
}

func (db *DB) GetASMAgentContinuation(id string) (*ASMAgentContinuation, error) {
	item, err := scanASMAgentContinuation(db.QueryRow(`SELECT `+asmAgentContinuationColumns+`
		FROM asm_agent_continuations WHERE id = ?`, strings.TrimSpace(id)))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("ASM Agent 联动记录不存在")
		}
		return nil, fmt.Errorf("读取 ASM Agent 联动记录失败: %w", err)
	}
	return item, nil
}

// StopASMAgentContinuationsForConversation permanently suppresses automatic
// resume when the user explicitly stops the source conversation. This state is
// persisted because an ASM scan may finish long after the Agent task vanished
// from the in-memory task manager.
func (db *DB) StopASMAgentContinuationsForConversation(conversationID, reason string) (int64, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return 0, nil
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "用户主动停止来源 Agent 对话，不再自动恢复"
	}
	now := time.Now().UTC()
	result, err := db.Exec(`UPDATE asm_agent_continuations
		SET status = 'user_stopped', last_error = ?, completed_at = ?, updated_at = ?
		WHERE conversation_id = ? AND status IN ('waiting','ready','retry','queued','running')`,
		reason, now, now, conversationID)
	if err != nil {
		return 0, fmt.Errorf("停止 ASM Agent 联动失败: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("读取停止 ASM Agent 联动数量失败: %w", err)
	}
	return affected, nil
}

func (db *DB) ListPendingASMAgentContinuations(limit int) ([]*ASMAgentContinuation, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	rows, err := db.Query(`SELECT `+asmAgentContinuationColumns+` FROM asm_agent_continuations
		WHERE status IN ('waiting','ready','retry','queued') ORDER BY created_at ASC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("查询 ASM Agent 联动记录失败: %w", err)
	}
	defer rows.Close()
	items := make([]*ASMAgentContinuation, 0)
	for rows.Next() {
		item, scanErr := scanASMAgentContinuation(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("读取 ASM Agent 联动记录失败: %w", scanErr)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListUserStoppedStartedASMAgentContinuations returns legacy rows that may
// already have delivered their notification before a later manual stop. The
// service verifies the persisted conversation message before promoting them.
func (db *DB) ListUserStoppedStartedASMAgentContinuations(limit int) ([]*ASMAgentContinuation, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := db.Query(`SELECT `+asmAgentContinuationColumns+` FROM asm_agent_continuations
		WHERE status = 'user_stopped' AND attempts > 0 ORDER BY updated_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("查询待核验 ASM Agent 联动记录失败: %w", err)
	}
	defer rows.Close()
	items := make([]*ASMAgentContinuation, 0)
	for rows.Next() {
		item, scanErr := scanASMAgentContinuation(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("读取待核验 ASM Agent 联动记录失败: %w", scanErr)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// PromoteDeliveredASMAgentContinuation repairs legacy rows only after the
// service has proved that the completion notification exists in the source
// conversation. It intentionally cannot promote a never-started stop.
func (db *DB) PromoteDeliveredASMAgentContinuation(id string, deliveredAt time.Time) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	if deliveredAt.IsZero() {
		deliveredAt = time.Now().UTC()
	}
	_, err := db.Exec(`UPDATE asm_agent_continuations
		SET status = 'completed', last_error = '', completed_at = ?, updated_at = ?
		WHERE id = ? AND status = 'user_stopped' AND attempts > 0`,
		deliveredAt.UTC(), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("修复已送达 ASM Agent 联动状态失败: %w", err)
	}
	return nil
}

// GetPendingAssistantTurnStartedAt returns the persisted start of the latest
// unfinished assistant turn. This is the process-restart fallback for ASM: the
// in-memory task registry may be empty even though the database still contains
// the foreground "处理中..." placeholder.
func (db *DB) GetPendingAssistantTurnStartedAt(conversationID string) (time.Time, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return time.Time{}, nil
	}
	var raw string
	err := db.QueryRow(`
		SELECT m.created_at
		FROM messages m
		WHERE m.rowid = (
			SELECT latest.rowid FROM messages latest
			WHERE latest.conversation_id = ? AND latest.role = 'assistant'
			ORDER BY latest.rowid DESC LIMIT 1
		)
		AND TRIM(m.content) IN ('处理中...', 'Processing...')
		AND NOT EXISTS (
			SELECT 1 FROM process_details pd
			WHERE pd.message_id = m.id AND pd.event_type IN ('cancelled', 'timeout', 'error')
		)`, conversationID).Scan(&raw)
	if err != nil {
		if err == sql.ErrNoRows {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("查询待续接 Agent 起始时间失败: %w", err)
	}
	return parseDBTime(raw), nil
}

// FinalizePendingAssistantForASMContinuation closes a stale foreground
// placeholder immediately before the ASM notification is injected. The next
// assistant turn inherits expectedStartedAt, while the old clock stops at the
// hand-off instead of continuing forever after a process restart.
func (db *DB) FinalizePendingAssistantForASMContinuation(conversationID string, expectedStartedAt, completedAt time.Time) (bool, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" || expectedStartedAt.IsZero() {
		return false, nil
	}
	if completedAt.IsZero() {
		completedAt = time.Now().UTC()
	}
	var messageID, rawCreatedAt string
	err := db.QueryRow(`
		SELECT m.id, m.created_at
		FROM messages m
		WHERE m.rowid = (
			SELECT latest.rowid FROM messages latest
			WHERE latest.conversation_id = ? AND latest.role = 'assistant'
			ORDER BY latest.rowid DESC LIMIT 1
		)
		AND TRIM(m.content) IN ('处理中...', 'Processing...')
		AND NOT EXISTS (
			SELECT 1 FROM process_details pd
			WHERE pd.message_id = m.id AND pd.event_type IN ('cancelled', 'timeout', 'error')
		)`, conversationID).Scan(&messageID, &rawCreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("查询待结束 Agent 占位消息失败: %w", err)
	}
	startedAt := parseDBTime(rawCreatedAt)
	if startedAt.IsZero() || !startedAt.Equal(expectedStartedAt) || completedAt.Before(startedAt) {
		return false, nil
	}
	result, err := db.Exec(`UPDATE messages
		SET content = ?, updated_at = ?
		WHERE id = ? AND TRIM(content) IN ('处理中...', 'Processing...')`,
		asmContinuationRecoveredMessage, completedAt.UTC(), messageID)
	if err != nil {
		return false, fmt.Errorf("结束待续接 Agent 占位消息失败: %w", err)
	}
	updated, _ := result.RowsAffected()
	return updated > 0, nil
}

// RepairMissingASMContinuationTurnTimings repairs records created before the
// persisted fallback was available. It recognizes the durable message order:
// unfinished assistant -> ASM completion notification -> resumed assistant.
func (db *DB) RepairMissingASMContinuationTurnTimings(limit int) (int, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	type notification struct {
		rowID          int64
		conversationID string
		createdAt      time.Time
	}
	rows, err := db.Query(`SELECT rowid, conversation_id, created_at FROM messages
		WHERE role = 'user' AND TRIM(content) LIKE 'ASM 扫描结果已完成。%'
		ORDER BY rowid DESC LIMIT ?`, limit)
	if err != nil {
		return 0, fmt.Errorf("查询 ASM 续跑通知失败: %w", err)
	}
	items := make([]notification, 0)
	for rows.Next() {
		var item notification
		var rawCreatedAt string
		if scanErr := rows.Scan(&item.rowID, &item.conversationID, &rawCreatedAt); scanErr != nil {
			rows.Close()
			return 0, fmt.Errorf("读取 ASM 续跑通知失败: %w", scanErr)
		}
		item.createdAt = parseDBTime(rawCreatedAt)
		items = append(items, item)
	}
	if closeErr := rows.Close(); closeErr != nil {
		return 0, closeErr
	}

	repaired := 0
	for _, item := range items {
		if item.createdAt.IsZero() {
			continue
		}
		var previousID, previousContent, rawStartedAt string
		if readErr := db.QueryRow(`SELECT id, content, created_at FROM messages
			WHERE conversation_id = ? AND role = 'assistant' AND rowid < ?
			ORDER BY rowid DESC LIMIT 1`, item.conversationID, item.rowID).
			Scan(&previousID, &previousContent, &rawStartedAt); readErr != nil {
			if readErr == sql.ErrNoRows {
				continue
			}
			return repaired, fmt.Errorf("查询 ASM 续跑前置消息失败: %w", readErr)
		}
		content := strings.TrimSpace(previousContent)
		pendingPlaceholder := content == "处理中..." || content == "Processing..."
		restartInterrupted := content == "任务因服务重启已中断。" || content == "任务因服务重启已中断，审批已取消。"
		if !pendingPlaceholder && !restartInterrupted {
			continue
		}
		if pendingPlaceholder {
			var terminalCount int
			if readErr := db.QueryRow(`SELECT COUNT(*) FROM process_details
				WHERE message_id = ? AND event_type IN ('cancelled', 'timeout', 'error')`, previousID).Scan(&terminalCount); readErr != nil {
				return repaired, fmt.Errorf("核验 ASM 续跑前置消息失败: %w", readErr)
			}
			if terminalCount > 0 {
				continue
			}
		}
		startedAt := parseDBTime(rawStartedAt)
		if startedAt.IsZero() || item.createdAt.Before(startedAt) {
			continue
		}
		var resumedID string
		if readErr := db.QueryRow(`SELECT id FROM messages
			WHERE conversation_id = ? AND role = 'assistant' AND rowid > ? AND turn_started_at IS NULL
			ORDER BY rowid ASC LIMIT 1`, item.conversationID, item.rowID).Scan(&resumedID); readErr != nil {
			if readErr == sql.ErrNoRows {
				continue
			}
			return repaired, fmt.Errorf("查询 ASM 续跑助手消息失败: %w", readErr)
		}
		tx, beginErr := db.Begin()
		if beginErr != nil {
			return repaired, beginErr
		}
		if pendingPlaceholder {
			if _, updateErr := tx.Exec(`UPDATE messages SET content = ?, updated_at = ?
				WHERE id = ? AND TRIM(content) IN ('处理中...', 'Processing...')`,
				asmContinuationRecoveredMessage, item.createdAt.UTC(), previousID); updateErr != nil {
				tx.Rollback()
				return repaired, fmt.Errorf("修复 ASM 前置消息终态失败: %w", updateErr)
			}
		}
		if _, updateErr := tx.Exec(`UPDATE messages SET turn_started_at = ?
			WHERE id = ? AND turn_started_at IS NULL`, startedAt.UTC(), resumedID); updateErr != nil {
			tx.Rollback()
			return repaired, fmt.Errorf("修复 ASM 续跑累计时间失败: %w", updateErr)
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return repaired, commitErr
		}
		repaired++
	}
	return repaired, nil
}

var validASMAgentContinuationStatuses = map[string]bool{
	"waiting": true, "ready": true, "retry": true, "queued": true, "running": true,
	"completed": true, "agent_consumed": true, "failed": true, "cancelled": true, "user_stopped": true,
}

func normalizeASMAgentContinuationPagination(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	return page, pageSize
}

func asmAgentContinuationWhere(filter ASMAgentContinuationFilter) (string, []interface{}) {
	where := []string{"1=1"}
	args := make([]interface{}, 0)
	statuses := make([]string, 0, len(filter.Statuses))
	for _, raw := range filter.Statuses {
		status := strings.ToLower(strings.TrimSpace(raw))
		if validASMAgentContinuationStatuses[status] {
			statuses = append(statuses, status)
		}
	}
	if len(statuses) > 0 {
		placeholders := make([]string, len(statuses))
		for index, status := range statuses {
			placeholders[index] = "?"
			args = append(args, status)
		}
		where = append(where, "status IN ("+strings.Join(placeholders, ",")+")")
	}
	if query := strings.ToLower(strings.TrimSpace(filter.Query)); query != "" {
		like := "%" + query + "%"
		where = append(where, `(LOWER(id) LIKE ? OR LOWER(conversation_id) LIKE ? OR LOWER(task_ids_json) LIKE ? OR LOWER(last_error) LIKE ?)`)
		args = append(args, like, like, like, like)
	}
	userID := strings.TrimSpace(filter.Access.UserID)
	switch filter.Access.Scope {
	case RBACScopeAll:
		// Administrators can inspect all continuation jobs.
	case RBACScopeAssigned:
		if userID == "" {
			where = append(where, "1=0")
		} else {
			where = append(where, `(owner_user_id = ? OR EXISTS (
				SELECT 1 FROM rbac_resource_assignments ra
				WHERE ra.user_id = ? AND ra.resource_type = 'conversation'
				AND ra.resource_id = asm_agent_continuations.conversation_id
			))`)
			args = append(args, userID, userID)
		}
	default:
		if userID == "" {
			where = append(where, "1=0")
		} else {
			where = append(where, "owner_user_id = ?")
			args = append(args, userID)
		}
	}
	return strings.Join(where, " AND "), args
}

// ListASMAgentContinuations returns historical and active continuation jobs.
func (db *DB) ListASMAgentContinuations(filter ASMAgentContinuationFilter) ([]*ASMAgentContinuation, int, error) {
	page, pageSize := normalizeASMAgentContinuationPagination(filter.Page, filter.PageSize)
	clause, args := asmAgentContinuationWhere(filter)
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM asm_agent_continuations WHERE `+clause, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计 ASM Agent 联动记录失败: %w", err)
	}
	queryArgs := append(append([]interface{}{}, args...), pageSize, (page-1)*pageSize)
	rows, err := db.Query(`SELECT `+asmAgentContinuationColumns+` FROM asm_agent_continuations
		WHERE `+clause+` ORDER BY created_at DESC LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询 ASM Agent 联动记录失败: %w", err)
	}
	defer rows.Close()
	items := make([]*ASMAgentContinuation, 0, pageSize)
	for rows.Next() {
		item, scanErr := scanASMAgentContinuation(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf("读取 ASM Agent 联动记录失败: %w", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("读取 ASM Agent 联动记录失败: %w", err)
	}
	return items, total, nil
}

// CountASMAgentContinuationsByStatus powers the diagnostics summary and uses
// the same conversation visibility boundary as the history list.
func (db *DB) CountASMAgentContinuationsByStatus(access RBACListAccess) (map[string]int, error) {
	clause, args := asmAgentContinuationWhere(ASMAgentContinuationFilter{Access: access})
	rows, err := db.Query(`SELECT status, COUNT(*) FROM asm_agent_continuations
		WHERE `+clause+` GROUP BY status`, args...)
	if err != nil {
		return nil, fmt.Errorf("统计 ASM Agent 联动状态失败: %w", err)
	}
	defer rows.Close()
	result := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("读取 ASM Agent 联动状态失败: %w", err)
		}
		result[status] = count
	}
	return result, rows.Err()
}

func (db *DB) UpdateASMAgentContinuation(item *ASMAgentContinuation) error {
	if item == nil {
		return fmt.Errorf("ASM Agent 联动记录不能为空")
	}
	item.UpdatedAt = time.Now().UTC()
	result, err := db.Exec(`UPDATE asm_agent_continuations SET status = ?, agent_was_running = ?,
		agent_started_at = ?, attempts = ?, last_error = ?, ready_at = ?, completed_at = ?, updated_at = ?
		WHERE id = ? AND status NOT IN ('user_stopped','agent_consumed')`,
		item.Status, boolToInt(item.AgentWasRunning), item.AgentStartedAt, item.Attempts, item.LastError,
		item.ReadyAt, item.CompletedAt, item.UpdatedAt, item.ID)
	if err != nil {
		return fmt.Errorf("更新 ASM Agent 联动记录失败: %w", err)
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr == nil && affected == 0 {
		var currentStatus string
		if readErr := db.QueryRow(`SELECT status FROM asm_agent_continuations WHERE id = ?`, item.ID).Scan(&currentStatus); readErr == nil && (currentStatus == "user_stopped" || currentStatus == "agent_consumed") {
			// Manual stop and Agent-side result consumption are durable terminal
			// states. Concurrent workers must never overwrite either decision.
			return nil
		}
		return fmt.Errorf("ASM Agent 联动记录不存在")
	}
	return nil
}

// RecoverStaleASMAgentContinuations makes an interrupted process retryable.
func (db *DB) RecoverStaleASMAgentContinuations(before time.Time) error {
	_, err := db.Exec(`UPDATE asm_agent_continuations SET status = 'retry',
		last_error = '服务重启后恢复续跑', updated_at = ? WHERE status = 'running' AND updated_at < ?`,
		time.Now().UTC(), before.UTC())
	if err != nil {
		return fmt.Errorf("恢复 ASM Agent 联动记录失败: %w", err)
	}
	return nil
}
