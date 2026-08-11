package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type ASMTask struct {
	ID           string     `json:"id"`
	ResourceID   string     `json:"resource_id"`
	ResourceName string     `json:"resource_name"`
	Provider     string     `json:"provider"`
	RemoteTaskID string     `json:"remote_task_id"`
	Name         string     `json:"name"`
	Target       string     `json:"target"`
	OptionsJSON  string     `json:"options_json"`
	Status       string     `json:"status"`
	Progress     int        `json:"progress"`
	Stage        string     `json:"stage"`
	SummaryJSON  string     `json:"summary_json"`
	DetailJSON   string     `json:"detail_json,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
	LastSyncedAt *time.Time `json:"last_synced_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type ASMTaskFilter struct {
	Provider   string
	ResourceID string
	Status     string
	Query      string
	Page       int
	PageSize   int
}

type ASMScreenshot struct {
	ID          string    `json:"id"`
	TaskID      string    `json:"task_id"`
	SourceURL   string    `json:"-"`
	Label       string    `json:"label"`
	FilePath    string    `json:"-"`
	ContentType string    `json:"content_type"`
	SizeBytes   int64     `json:"size_bytes"`
	SHA256      string    `json:"sha256"`
	URL         string    `json:"url,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

const asmTaskColumns = `id, resource_id, resource_name, provider, remote_task_id,
	name, target, options_json, status, progress, stage, summary_json, detail_json,
	last_error, last_synced_at, created_at, updated_at`

func scanASMTask(scanner interface{ Scan(...interface{}) error }) (*ASMTask, error) {
	var item ASMTask
	var syncedAt sql.NullString
	var createdAt, updatedAt string
	if err := scanner.Scan(
		&item.ID, &item.ResourceID, &item.ResourceName, &item.Provider, &item.RemoteTaskID,
		&item.Name, &item.Target, &item.OptionsJSON, &item.Status, &item.Progress, &item.Stage,
		&item.SummaryJSON, &item.DetailJSON, &item.LastError, &syncedAt, &createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	item.CreatedAt = parseDBTime(createdAt)
	item.UpdatedAt = parseDBTime(updatedAt)
	if syncedAt.Valid && strings.TrimSpace(syncedAt.String) != "" {
		parsed := parseDBTime(syncedAt.String)
		item.LastSyncedAt = &parsed
	}
	return &item, nil
}

func (db *DB) CreateASMTask(item *ASMTask) error {
	if item == nil {
		return fmt.Errorf("ASM 任务不能为空")
	}
	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	item.UpdatedAt = now
	_, err := db.Exec(`INSERT INTO asm_tasks (
		id, resource_id, resource_name, provider, remote_task_id, name, target,
		options_json, status, progress, stage, summary_json, detail_json, last_error,
		last_synced_at, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID, item.ResourceID, item.ResourceName, item.Provider, item.RemoteTaskID,
		item.Name, item.Target, item.OptionsJSON, item.Status, item.Progress, item.Stage,
		item.SummaryJSON, item.DetailJSON, item.LastError, item.LastSyncedAt,
		item.CreatedAt, item.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("创建 ASM 任务记录失败: %w", err)
	}
	return nil
}

func (db *DB) UpdateASMTask(item *ASMTask) error {
	if item == nil {
		return fmt.Errorf("ASM 任务不能为空")
	}
	item.UpdatedAt = time.Now().UTC()
	result, err := db.Exec(`UPDATE asm_tasks SET name = ?, target = ?, status = ?, progress = ?, stage = ?,
		summary_json = ?, detail_json = ?, last_error = ?, last_synced_at = ?, updated_at = ?
		WHERE id = ?`, item.Name, item.Target, item.Status, item.Progress, item.Stage, item.SummaryJSON,
		item.DetailJSON, item.LastError, item.LastSyncedAt, item.UpdatedAt, item.ID)
	if err != nil {
		return fmt.Errorf("更新 ASM 任务记录失败: %w", err)
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr == nil && rows == 0 {
		return fmt.Errorf("ASM 任务记录不存在")
	}
	return nil
}

func (db *DB) GetASMTask(id string) (*ASMTask, error) {
	item, err := scanASMTask(db.QueryRow(`SELECT `+asmTaskColumns+` FROM asm_tasks WHERE id = ?`, strings.TrimSpace(id)))
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("ASM 任务记录不存在")
	}
	if err != nil {
		return nil, fmt.Errorf("获取 ASM 任务记录失败: %w", err)
	}
	return item, nil
}

func (db *DB) FindASMTask(resourceID, remoteTaskID string) (*ASMTask, error) {
	item, err := scanASMTask(db.QueryRow(`SELECT `+asmTaskColumns+` FROM asm_tasks WHERE resource_id = ? AND remote_task_id = ?`, strings.TrimSpace(resourceID), strings.TrimSpace(remoteTaskID)))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查找 ASM 任务记录失败: %w", err)
	}
	return item, nil
}

func normalizeASMTaskPagination(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

func (db *DB) ListASMTasks(filter ASMTaskFilter) ([]*ASMTask, int, error) {
	page, pageSize := normalizeASMTaskPagination(filter.Page, filter.PageSize)
	where := []string{"1 = 1"}
	args := make([]interface{}, 0, 8)
	if value := strings.TrimSpace(filter.Provider); value != "" {
		where = append(where, "provider = ?")
		args = append(args, value)
	}
	if value := strings.TrimSpace(filter.ResourceID); value != "" {
		where = append(where, "resource_id = ?")
		args = append(args, value)
	}
	if value := strings.TrimSpace(filter.Status); value != "" {
		where = append(where, "status = ?")
		args = append(args, value)
	}
	if value := strings.TrimSpace(filter.Query); value != "" {
		where = append(where, "(name LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\' OR remote_task_id LIKE ? ESCAPE '\\')")
		escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
		like := "%" + escaped + "%"
		args = append(args, like, like, like)
	}
	clause := strings.Join(where, " AND ")
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM asm_tasks WHERE `+clause, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计 ASM 任务失败: %w", err)
	}
	queryArgs := append(append([]interface{}{}, args...), pageSize, (page-1)*pageSize)
	rows, err := db.Query(`SELECT `+asmTaskColumns+` FROM asm_tasks WHERE `+clause+` ORDER BY created_at DESC LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询 ASM 任务失败: %w", err)
	}
	defer rows.Close()
	items := make([]*ASMTask, 0)
	for rows.Next() {
		item, scanErr := scanASMTask(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf("读取 ASM 任务失败: %w", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("遍历 ASM 任务失败: %w", err)
	}
	return items, total, nil
}

func (db *DB) UpsertASMTaskResult(taskID, assetType, payloadJSON string) error {
	_, err := db.Exec(`INSERT INTO asm_task_results (task_id, asset_type, payload_json, updated_at)
		VALUES (?, ?, ?, ?) ON CONFLICT(task_id, asset_type) DO UPDATE SET
		payload_json = excluded.payload_json, updated_at = excluded.updated_at`,
		strings.TrimSpace(taskID), strings.TrimSpace(assetType), payloadJSON, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("保存 ASM 结果快照失败: %w", err)
	}
	return nil
}

func (db *DB) GetASMTaskResult(taskID, assetType string) (string, *time.Time, error) {
	var payload, updated string
	err := db.QueryRow(`SELECT payload_json, updated_at FROM asm_task_results WHERE task_id = ? AND asset_type = ?`, strings.TrimSpace(taskID), strings.TrimSpace(assetType)).Scan(&payload, &updated)
	if err == sql.ErrNoRows {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("获取 ASM 结果快照失败: %w", err)
	}
	parsed := parseDBTime(updated)
	return payload, &parsed, nil
}

func (db *DB) UpsertASMScreenshot(item *ASMScreenshot) error {
	if item == nil {
		return fmt.Errorf("ASM 截图不能为空")
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	_, err := db.Exec(`INSERT INTO asm_screenshots (
		id, task_id, source_url, label, file_path, content_type, size_bytes, sha256, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(task_id, source_url) DO UPDATE SET
		label = excluded.label, file_path = excluded.file_path, content_type = excluded.content_type,
		size_bytes = excluded.size_bytes, sha256 = excluded.sha256`,
		item.ID, item.TaskID, item.SourceURL, item.Label, item.FilePath, item.ContentType,
		item.SizeBytes, item.SHA256, item.CreatedAt)
	if err != nil {
		return fmt.Errorf("保存 ASM 截图失败: %w", err)
	}
	return nil
}

func scanASMScreenshot(scanner interface{ Scan(...interface{}) error }) (*ASMScreenshot, error) {
	var item ASMScreenshot
	var created string
	if err := scanner.Scan(&item.ID, &item.TaskID, &item.SourceURL, &item.Label,
		&item.FilePath, &item.ContentType, &item.SizeBytes, &item.SHA256, &created); err != nil {
		return nil, err
	}
	item.CreatedAt = parseDBTime(created)
	return &item, nil
}

func (db *DB) ListASMScreenshots(taskID string) ([]*ASMScreenshot, error) {
	rows, err := db.Query(`SELECT id, task_id, source_url, label, file_path, content_type,
		size_bytes, sha256, created_at FROM asm_screenshots WHERE task_id = ? ORDER BY created_at, id`, strings.TrimSpace(taskID))
	if err != nil {
		return nil, fmt.Errorf("查询 ASM 截图失败: %w", err)
	}
	defer rows.Close()
	items := make([]*ASMScreenshot, 0)
	for rows.Next() {
		item, scanErr := scanASMScreenshot(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("读取 ASM 截图失败: %w", scanErr)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) GetASMScreenshot(id string) (*ASMScreenshot, error) {
	item, err := scanASMScreenshot(db.QueryRow(`SELECT id, task_id, source_url, label, file_path,
		content_type, size_bytes, sha256, created_at FROM asm_screenshots WHERE id = ?`, strings.TrimSpace(id)))
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("ASM 截图不存在")
	}
	if err != nil {
		return nil, fmt.Errorf("获取 ASM 截图失败: %w", err)
	}
	return item, nil
}
