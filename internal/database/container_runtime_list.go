package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

const containerRuntimeListStatusExpression = `(CASE
	WHEN r.conversation_id IS NULL THEN 'not_requested'
	WHEN r.initialization_status = 'failed'
		OR r.readiness_status = 'failed'
		OR r.lifecycle_state = 'failed'
		OR r.runtime_status = 'failed'
		OR TRIM(COALESCE(r.last_error, '')) <> ''
		OR TRIM(COALESCE(r.readiness_error, '')) <> ''
		OR TRIM(COALESCE(r.lifecycle_error, '')) <> ''
		OR TRIM(COALESCE(r.runtime_drift, '')) <> '' THEN 'failed'
	WHEN r.runtime_status = 'running' THEN 'running'
	WHEN r.initialization_status IN ('queued', 'creating')
		OR r.runtime_status IN ('creating', 'starting', 'stopping')
		OR r.readiness_status IN ('pending', 'validating')
		OR r.lifecycle_state = 'in_progress' THEN 'pending'
	WHEN r.initialization_status = 'created' AND r.runtime_status = 'stopped' THEN 'stopped'
	ELSE 'pending'
END)`

var containerRuntimeListStatuses = map[string]struct{}{
	"all": {}, "not_requested": {}, "pending": {}, "running": {}, "stopped": {}, "failed": {},
}

// ContainerRuntimeListQuery is the server-side list contract used by the
// container management UI. Page-size validation remains in the HTTP layer.
type ContainerRuntimeListQuery struct {
	Limit  int
	Offset int
	Search string
	Status string
	UserID string
	Scope  string
}

// ContainerRuntimeListSummary describes the complete filtered result set, not
// merely the current page.
type ContainerRuntimeListSummary struct {
	Total      int `json:"total"`
	Running    int `json:"running"`
	Gateways   int `json:"gateways"`
	Persistent int `json:"persistent"`
	Attention  int `json:"attention"`
}

// NormalizeContainerRuntimeListStatus validates the closed status-filter set.
func NormalizeContainerRuntimeListStatus(raw string) (string, bool) {
	status := strings.ToLower(strings.TrimSpace(raw))
	if status == "" {
		status = "all"
	}
	_, ok := containerRuntimeListStatuses[status]
	return status, ok
}

func escapeContainerRuntimeSearch(raw string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(strings.TrimSpace(raw))
}

func containerRuntimeListWhere(query ContainerRuntimeListQuery) (string, []interface{}, error) {
	status, ok := NormalizeContainerRuntimeListStatus(query.Status)
	if !ok {
		return "", nil, fmt.Errorf("invalid container runtime status %q", query.Status)
	}
	where := ` WHERE c.runtime_mode = ?`
	args := []interface{}{ConversationRuntimeModeContainer}
	if search := escapeContainerRuntimeSearch(query.Search); search != "" {
		pattern := "%" + search + "%"
		where += ` AND (c.title LIKE ? ESCAPE '\' OR c.id LIKE ? ESCAPE '\')`
		args = append(args, pattern, pattern)
	}
	if status != "all" {
		where += " AND " + containerRuntimeListStatusExpression + " = ?"
		args = append(args, status)
	}
	where, args = appendConversationAccessFilter(where, args, query.UserID, query.Scope, "c")
	return where, args, nil
}

// ListContainerConversationsForAccess returns only the requested page while
// enforcing the same conversation RBAC boundary as the regular chat list.
func (db *DB) ListContainerConversationsForAccess(ctx context.Context, query ContainerRuntimeListQuery) ([]*Conversation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("container runtime list context is required")
	}
	if query.Limit <= 0 || query.Offset < 0 {
		return nil, fmt.Errorf("container runtime pagination is invalid")
	}
	where, args, err := containerRuntimeListWhere(query)
	if err != nil {
		return nil, err
	}
	args = append(args, query.Limit, query.Offset)
	rows, err := db.QueryContext(ctx, `
		SELECT c.id, c.title, COALESCE(c.pinned, 0), c.created_at, c.updated_at,
			c.project_id, c.role_name, c.agent_mode, c.runtime_mode, c.workspace_persistent
		FROM conversations c
		LEFT JOIN conversation_container_runtimes r ON r.conversation_id = c.id`+where+`
		ORDER BY c.updated_at DESC, c.id ASC
		LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("list container conversations: %w", err)
	}
	defer rows.Close()
	return scanConversationRows(rows)
}

// SummarizeContainerConversationsForAccess returns counts for the full
// filtered result set so paginated pages never present page-local totals as
// global container health.
func (db *DB) SummarizeContainerConversationsForAccess(ctx context.Context, query ContainerRuntimeListQuery) (ContainerRuntimeListSummary, error) {
	var summary ContainerRuntimeListSummary
	if ctx == nil {
		return summary, fmt.Errorf("container runtime summary context is required")
	}
	where, args, err := containerRuntimeListWhere(query)
	if err != nil {
		return summary, err
	}
	row := db.QueryRowContext(ctx, `
		SELECT COUNT(*),
			COALESCE(SUM(CASE WHEN `+containerRuntimeListStatusExpression+` = 'running' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN json_type(r.spec_json, '$.EgressGateway') IS NOT NULL
				AND json_type(r.spec_json, '$.EgressGateway') <> 'null' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN c.workspace_persistent = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN `+containerRuntimeListStatusExpression+` = 'failed' THEN 1 ELSE 0 END), 0)
		FROM conversations c
		LEFT JOIN conversation_container_runtimes r ON r.conversation_id = c.id`+where, args...)
	if err := row.Scan(&summary.Total, &summary.Running, &summary.Gateways, &summary.Persistent, &summary.Attention); err != nil {
		if err == sql.ErrNoRows {
			return summary, nil
		}
		return summary, fmt.Errorf("summarize container conversations: %w", err)
	}
	return summary, nil
}
