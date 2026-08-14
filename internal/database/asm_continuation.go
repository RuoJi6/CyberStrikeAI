package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ASMAgentContinuation records the durable hand-off from a completed ASM scan
// back to the Agent conversation that created it.
type ASMAgentContinuation struct {
	ID              string     `json:"id"`
	TaskIDsJSON     string     `json:"task_ids_json"`
	ConversationID  string     `json:"conversation_id"`
	OwnerUserID     string     `json:"owner_user_id"`
	Behavior        string     `json:"behavior"`
	RunningPrompt   string     `json:"running_prompt"`
	IdlePrompt      string     `json:"idle_prompt"`
	Status          string     `json:"status"`
	AgentWasRunning bool       `json:"agent_was_running"`
	Attempts        int        `json:"attempts"`
	LastError       string     `json:"last_error,omitempty"`
	ReadyAt         *time.Time `json:"ready_at,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

const asmAgentContinuationColumns = `id, task_ids_json, conversation_id, owner_user_id,
	behavior, running_prompt, idle_prompt, status, agent_was_running, attempts,
	last_error, ready_at, completed_at, created_at, updated_at`

func scanASMAgentContinuation(scanner interface{ Scan(...interface{}) error }) (*ASMAgentContinuation, error) {
	var item ASMAgentContinuation
	var wasRunning int
	var readyAt, completedAt sql.NullString
	var createdAt, updatedAt string
	if err := scanner.Scan(
		&item.ID, &item.TaskIDsJSON, &item.ConversationID, &item.OwnerUserID,
		&item.Behavior, &item.RunningPrompt, &item.IdlePrompt, &item.Status,
		&wasRunning, &item.Attempts, &item.LastError, &readyAt, &completedAt,
		&createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	item.AgentWasRunning = wasRunning != 0
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
	item.UpdatedAt = now
	_, err := db.Exec(`INSERT INTO asm_agent_continuations (
		id, task_ids_json, conversation_id, owner_user_id, behavior, running_prompt,
		idle_prompt, status, agent_was_running, attempts, last_error, ready_at,
		completed_at, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID, item.TaskIDsJSON, item.ConversationID, item.OwnerUserID, item.Behavior,
		item.RunningPrompt, item.IdlePrompt, item.Status, boolToInt(item.AgentWasRunning),
		item.Attempts, item.LastError, item.ReadyAt, item.CompletedAt, item.CreatedAt, item.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("创建 ASM Agent 联动记录失败: %w", err)
	}
	return nil
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
		WHERE conversation_id = ? AND status IN ('waiting','ready','retry','running')`,
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
		WHERE status IN ('waiting','ready','retry') ORDER BY created_at ASC LIMIT ?`, limit)
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

func (db *DB) UpdateASMAgentContinuation(item *ASMAgentContinuation) error {
	if item == nil {
		return fmt.Errorf("ASM Agent 联动记录不能为空")
	}
	item.UpdatedAt = time.Now().UTC()
	result, err := db.Exec(`UPDATE asm_agent_continuations SET status = ?, agent_was_running = ?,
		attempts = ?, last_error = ?, ready_at = ?, completed_at = ?, updated_at = ?
		WHERE id = ? AND status <> 'user_stopped'`,
		item.Status, boolToInt(item.AgentWasRunning), item.Attempts, item.LastError,
		item.ReadyAt, item.CompletedAt, item.UpdatedAt, item.ID)
	if err != nil {
		return fmt.Errorf("更新 ASM Agent 联动记录失败: %w", err)
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr == nil && affected == 0 {
		var currentStatus string
		if readErr := db.QueryRow(`SELECT status FROM asm_agent_continuations WHERE id = ?`, item.ID).Scan(&currentStatus); readErr == nil && currentStatus == "user_stopped" {
			// A manual user stop is a durable terminal state. A concurrent worker
			// completing or retrying must never overwrite that explicit choice.
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
