package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	containerruntime "cyberstrike-ai/internal/runtime/container"
	"github.com/google/uuid"
)

const (
	ContainerWorkspaceKindDedicated = "dedicated"
	ContainerWorkspaceKindShared    = "shared"

	ConversationWorkspaceModeEphemeral = "ephemeral"
	ConversationWorkspaceModeDedicated = "dedicated"
	ConversationWorkspaceModeShared    = "shared"
)

// ContainerWorkspace is a control-plane-owned Docker named volume. A shared
// workspace can be attached to multiple container conversations, while a
// dedicated workspace preserves the existing one-conversation behavior.
type ContainerWorkspace struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Kind                  string    `json:"kind"`
	ProjectID             string    `json:"projectId,omitempty"`
	VolumeName            string    `json:"-"`
	AttachedConversations int       `json:"attachedConversations"`
	CreatedAt             time.Time `json:"createdAt"`
	UpdatedAt             time.Time `json:"updatedAt"`
}

type ConversationWorkspaceBinding struct {
	ConversationID string              `json:"conversationId"`
	Mode           string              `json:"mode"`
	Workspace      *ContainerWorkspace `json:"workspace,omitempty"`
}

type ContainerWorkspaceAttachment struct {
	ConversationID    string    `json:"conversationId"`
	ConversationTitle string    `json:"conversationTitle"`
	ProjectID         string    `json:"projectId,omitempty"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

func (db *DB) initConversationWorkspaceTables() error {
	if err := db.addColumnIfMissing("conversations", "workspace_id", "ALTER TABLE conversations ADD COLUMN workspace_id TEXT"); err != nil {
		return err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS container_workspaces (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			kind TEXT NOT NULL CHECK (kind IN ('dedicated', 'shared')),
			project_id TEXT,
			volume_name TEXT NOT NULL UNIQUE,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
		);
		CREATE INDEX IF NOT EXISTS idx_container_workspaces_project ON container_workspaces(project_id);
		CREATE INDEX IF NOT EXISTS idx_container_workspaces_kind ON container_workspaces(kind);
		CREATE INDEX IF NOT EXISTS idx_conversations_workspace ON conversations(workspace_id);
	`); err != nil {
		return err
	}
	// Existing persistent workspaces already use a runtime-derived volume name.
	// Represent them as dedicated workspace resources without renaming volumes.
	if _, err := db.Exec(`
		INSERT OR IGNORE INTO container_workspaces (
			id, name, kind, project_id, volume_name, created_at, updated_at
		)
		SELECT 'conversation-' || id,
		       CASE WHEN TRIM(title) = '' THEN '专属工作区' ELSE title || ' 工作区' END,
		       'dedicated', project_id,
		       'cyberstrike-workspace-conversation-' || id,
		       created_at, updated_at
		FROM conversations
		WHERE runtime_mode = 'container' AND workspace_persistent = 1
	`); err != nil {
		return fmt.Errorf("migrate persistent container workspaces: %w", err)
	}
	if _, err := db.Exec(`
		UPDATE conversations
		SET workspace_id = 'conversation-' || id
		WHERE runtime_mode = 'container' AND workspace_persistent = 1
		  AND (workspace_id IS NULL OR TRIM(workspace_id) = '')
	`); err != nil {
		return fmt.Errorf("bind migrated persistent container workspaces: %w", err)
	}
	return nil
}

func normalizeWorkspaceName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("工作区名称不能为空")
	}
	if len([]rune(name)) > 80 {
		return "", errors.New("工作区名称不能超过 80 个字符")
	}
	return name, nil
}

func sharedWorkspaceID() string { return "shared-" + uuid.NewString() }

func dedicatedWorkspaceID(conversationID string) string {
	return "conversation-" + strings.TrimSpace(conversationID)
}

func resolveNewConversationWorkspaceTx(ctx context.Context, tx *sql.Tx, conversationID, title, projectID, runtimeMode string, persistent bool, requestedWorkspaceID string, now time.Time) (string, bool, error) {
	requestedWorkspaceID = strings.TrimSpace(requestedWorkspaceID)
	if requestedWorkspaceID != "" {
		if runtimeMode != ConversationRuntimeModeContainer {
			return "", false, errors.New("共享工作区只能用于 container 对话")
		}
		var kind string
		var workspaceProject sql.NullString
		if err := tx.QueryRowContext(ctx, "SELECT kind, project_id FROM container_workspaces WHERE id = ?", requestedWorkspaceID).Scan(&kind, &workspaceProject); err != nil {
			return "", false, errors.New("共享工作区不存在")
		}
		if kind != ContainerWorkspaceKindShared || workspaceProject.String != strings.TrimSpace(projectID) {
			return "", false, errors.New("共享工作区与对话项目不匹配")
		}
		return requestedWorkspaceID, true, nil
	}
	if !persistent {
		return "", false, nil
	}
	if runtimeMode != ConversationRuntimeModeContainer {
		return "", false, errors.New("持久化工作区只能用于 container 对话")
	}
	workspaceID := dedicatedWorkspaceID(conversationID)
	if _, err := createContainerWorkspaceTx(tx, workspaceID, title+" 工作区", ContainerWorkspaceKindDedicated, projectID, now); err != nil {
		return "", false, err
	}
	return workspaceID, true, nil
}

func createContainerWorkspaceTx(tx *sql.Tx, id, name, kind, projectID string, now time.Time) (*ContainerWorkspace, error) {
	name, err := normalizeWorkspaceName(name)
	if err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	if id == "" || (kind != ContainerWorkspaceKindDedicated && kind != ContainerWorkspaceKindShared) {
		return nil, errors.New("工作区标识或类型无效")
	}
	volumeName := containerruntime.WorkspaceVolumeNameForID(id)
	_, err = tx.Exec(`
		INSERT INTO container_workspaces (id, name, kind, project_id, volume_name, created_at, updated_at)
		VALUES (?, ?, ?, NULLIF(?, ''), ?, ?, ?)
	`, id, name, kind, strings.TrimSpace(projectID), volumeName, formatSQLiteUTC(now), formatSQLiteUTC(now))
	if err != nil {
		return nil, err
	}
	return &ContainerWorkspace{ID: id, Name: name, Kind: kind, ProjectID: strings.TrimSpace(projectID), VolumeName: volumeName, CreatedAt: now, UpdatedAt: now}, nil
}

func (db *DB) CreateSharedContainerWorkspace(ctx context.Context, name, projectID string) (*ContainerWorkspace, error) {
	now := time.Now().UTC()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if projectID = strings.TrimSpace(projectID); projectID != "" {
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM projects WHERE id = ?", projectID).Scan(&exists); err != nil || exists != 1 {
			return nil, errors.New("项目不存在")
		}
	}
	workspace, err := createContainerWorkspaceTx(tx, sharedWorkspaceID(), name, ContainerWorkspaceKindShared, projectID, now)
	if err != nil {
		return nil, fmt.Errorf("创建共享工作区失败: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return workspace, nil
}

func scanContainerWorkspace(scanner interface{ Scan(...any) error }) (*ContainerWorkspace, error) {
	var item ContainerWorkspace
	var projectID sql.NullString
	var createdAt, updatedAt string
	if err := scanner.Scan(&item.ID, &item.Name, &item.Kind, &projectID, &item.VolumeName, &createdAt, &updatedAt, &item.AttachedConversations); err != nil {
		return nil, err
	}
	item.ProjectID = projectID.String
	item.CreatedAt, _ = ParseRFC3339Time(createdAt)
	item.UpdatedAt, _ = ParseRFC3339Time(updatedAt)
	return &item, nil
}

func (db *DB) GetContainerWorkspace(ctx context.Context, id string) (*ContainerWorkspace, error) {
	return scanContainerWorkspace(db.QueryRowContext(ctx, `
		SELECT w.id, w.name, w.kind, w.project_id, w.volume_name, w.created_at, w.updated_at,
		       COUNT(c.id)
		FROM container_workspaces w
		LEFT JOIN conversations c ON c.workspace_id = w.id
		WHERE w.id = ?
		GROUP BY w.id
	`, strings.TrimSpace(id)))
}

func (db *DB) ListSharedContainerWorkspaces(ctx context.Context, projectID, query string, limit, offset int) ([]ContainerWorkspace, int, error) {
	return db.listSharedContainerWorkspaces(ctx, projectID, query, "", limit, offset)
}

// ListAssignedSharedContainerWorkspaces applies the RBAC assignment before
// LIMIT/OFFSET so a page cannot become empty merely because inaccessible
// workspaces happened to sort ahead of the caller's resources.
func (db *DB) ListAssignedSharedContainerWorkspaces(ctx context.Context, projectID, query, userID string, limit, offset int) ([]ContainerWorkspace, int, error) {
	return db.listSharedContainerWorkspaces(ctx, projectID, query, strings.TrimSpace(userID), limit, offset)
}

func (db *DB) listSharedContainerWorkspaces(ctx context.Context, projectID, query, assignedUserID string, limit, offset int) ([]ContainerWorkspace, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	projectID, query = strings.TrimSpace(projectID), strings.TrimSpace(query)
	where := "w.kind = 'shared' AND COALESCE(w.project_id, '') = ?"
	args := []any{projectID}
	if assignedUserID != "" {
		where += ` AND EXISTS (
			SELECT 1 FROM rbac_resource_assignments ra
			WHERE ra.user_id = ? AND ra.resource_type = 'container_workspace' AND ra.resource_id = w.id
		)`
		args = append(args, assignedUserID)
	}
	if query != "" {
		where += " AND (LOWER(w.name) LIKE LOWER(?) OR LOWER(w.id) LIKE LOWER(?))"
		like := "%" + query + "%"
		args = append(args, like, like)
	}
	var total int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM container_workspaces w WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT w.id, w.name, w.kind, w.project_id, w.volume_name, w.created_at, w.updated_at,
		       COUNT(c.id)
		FROM container_workspaces w
		LEFT JOIN conversations c ON c.workspace_id = w.id
		WHERE `+where+`
		GROUP BY w.id
		ORDER BY w.updated_at DESC, w.id
		LIMIT ? OFFSET ?
	`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]ContainerWorkspace, 0)
	for rows.Next() {
		item, scanErr := scanContainerWorkspace(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		items = append(items, *item)
	}
	return items, total, rows.Err()
}

func (db *DB) GetConversationWorkspaceBinding(ctx context.Context, conversationID string) (ConversationWorkspaceBinding, error) {
	var persistent bool
	var workspaceID sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT workspace_persistent, workspace_id FROM conversations WHERE id = ?`, strings.TrimSpace(conversationID)).Scan(&persistent, &workspaceID); err != nil {
		return ConversationWorkspaceBinding{}, err
	}
	binding := ConversationWorkspaceBinding{ConversationID: strings.TrimSpace(conversationID), Mode: ConversationWorkspaceModeEphemeral}
	if !persistent || strings.TrimSpace(workspaceID.String) == "" {
		return binding, nil
	}
	workspace, err := db.GetContainerWorkspace(ctx, workspaceID.String)
	if err != nil {
		return ConversationWorkspaceBinding{}, err
	}
	binding.Workspace = workspace
	binding.Mode = workspace.Kind
	return binding, nil
}

func (db *DB) ListContainerWorkspaceAttachments(ctx context.Context, workspaceID string) ([]ContainerWorkspaceAttachment, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, title, project_id, updated_at FROM conversations
		WHERE workspace_id = ? ORDER BY updated_at DESC, id
	`, strings.TrimSpace(workspaceID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ContainerWorkspaceAttachment, 0)
	for rows.Next() {
		var item ContainerWorkspaceAttachment
		var projectID sql.NullString
		var updatedAt string
		if err := rows.Scan(&item.ConversationID, &item.ConversationTitle, &projectID, &updatedAt); err != nil {
			return nil, err
		}
		item.ProjectID = projectID.String
		item.UpdatedAt, _ = ParseRFC3339Time(updatedAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) SetConversationWorkspaceBinding(ctx context.Context, conversationID, mode, workspaceID string) (ConversationWorkspaceBinding, error) {
	conversationID, mode, workspaceID = strings.TrimSpace(conversationID), strings.TrimSpace(mode), strings.TrimSpace(workspaceID)
	if mode != ConversationWorkspaceModeEphemeral && mode != ConversationWorkspaceModeDedicated && mode != ConversationWorkspaceModeShared {
		return ConversationWorkspaceBinding{}, errors.New("工作区模式无效")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ConversationWorkspaceBinding{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var runtimeMode, title string
	var projectID sql.NullString
	var previousWorkspaceID sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT runtime_mode, title, project_id, workspace_id FROM conversations WHERE id = ?", conversationID).Scan(&runtimeMode, &title, &projectID, &previousWorkspaceID); err != nil {
		return ConversationWorkspaceBinding{}, err
	}
	if runtimeMode != ConversationRuntimeModeContainer {
		return ConversationWorkspaceBinding{}, errors.New("只有容器对话可以选择工作区")
	}
	now := time.Now().UTC()
	switch mode {
	case ConversationWorkspaceModeEphemeral:
		workspaceID = ""
	case ConversationWorkspaceModeDedicated:
		workspaceID = dedicatedWorkspaceID(conversationID)
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM container_workspaces WHERE id = ?", workspaceID).Scan(&exists); err != nil {
			return ConversationWorkspaceBinding{}, err
		}
		if exists == 0 {
			if _, err := createContainerWorkspaceTx(tx, workspaceID, title+" 工作区", ContainerWorkspaceKindDedicated, projectID.String, now); err != nil {
				return ConversationWorkspaceBinding{}, err
			}
		}
	case ConversationWorkspaceModeShared:
		var kind string
		var workspaceProject sql.NullString
		if err := tx.QueryRowContext(ctx, "SELECT kind, project_id FROM container_workspaces WHERE id = ?", workspaceID).Scan(&kind, &workspaceProject); err != nil {
			return ConversationWorkspaceBinding{}, errors.New("共享工作区不存在")
		}
		if kind != ContainerWorkspaceKindShared || workspaceProject.String != projectID.String {
			return ConversationWorkspaceBinding{}, errors.New("共享工作区与对话项目不匹配")
		}
	}
	persistent := mode != ConversationWorkspaceModeEphemeral
	if _, err := tx.ExecContext(ctx, `
		UPDATE conversations SET workspace_persistent = ?, workspace_id = NULLIF(?, ''), updated_at = ? WHERE id = ?
	`, persistent, workspaceID, formatSQLiteUTC(now), conversationID); err != nil {
		return ConversationWorkspaceBinding{}, err
	}
	if workspaceID != "" {
		_, _ = tx.ExecContext(ctx, "UPDATE container_workspaces SET updated_at = ? WHERE id = ?", formatSQLiteUTC(now), workspaceID)
	}
	previousID := strings.TrimSpace(previousWorkspaceID.String)
	if previousID != "" && previousID != workspaceID {
		var previousKind string
		if err := tx.QueryRowContext(ctx, "SELECT kind FROM container_workspaces WHERE id = ?", previousID).Scan(&previousKind); err != nil && err != sql.ErrNoRows {
			return ConversationWorkspaceBinding{}, err
		}
		if previousKind == ContainerWorkspaceKindDedicated {
			if _, err := tx.ExecContext(ctx, "DELETE FROM container_workspaces WHERE id = ?", previousID); err != nil {
				return ConversationWorkspaceBinding{}, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return ConversationWorkspaceBinding{}, err
	}
	return db.GetConversationWorkspaceBinding(ctx, conversationID)
}

func (db *DB) DeleteContainerWorkspaceRecord(ctx context.Context, workspaceID string) (*ContainerWorkspace, error) {
	workspace, err := db.GetContainerWorkspace(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	if workspace.AttachedConversations != 0 {
		return nil, errors.New("工作区仍被对话使用，无法删除")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, "DELETE FROM container_workspaces WHERE id = ?", workspace.ID)
	if err != nil {
		return nil, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return nil, sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM rbac_resource_assignments WHERE resource_type = 'container_workspace' AND resource_id = ?", workspace.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return workspace, nil
}
