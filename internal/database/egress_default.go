package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const createEgressDefaultTables = `
CREATE TABLE IF NOT EXISTS user_egress_defaults (
	user_id TEXT PRIMARY KEY,
	mode TEXT NOT NULL CHECK (mode IN ('none', 'proxy', 'group')),
	proxy_id TEXT,
	proxy_group_id TEXT,
	updated_at DATETIME NOT NULL,
	FOREIGN KEY (user_id) REFERENCES rbac_users(id) ON DELETE CASCADE,
	FOREIGN KEY (proxy_id) REFERENCES egress_proxies(id) ON DELETE RESTRICT,
	FOREIGN KEY (proxy_group_id) REFERENCES egress_proxy_groups(id) ON DELETE RESTRICT,
	CHECK (
		(mode = 'none' AND proxy_id IS NULL AND proxy_group_id IS NULL)
		OR (mode = 'proxy' AND proxy_id IS NOT NULL AND length(trim(proxy_id)) > 0 AND proxy_group_id IS NULL)
		OR (mode = 'group' AND proxy_id IS NULL AND proxy_group_id IS NOT NULL AND length(trim(proxy_group_id)) > 0)
	)
);

CREATE TABLE IF NOT EXISTS project_egress_defaults (
	project_id TEXT PRIMARY KEY,
	mode TEXT NOT NULL CHECK (mode IN ('none', 'proxy', 'group')),
	proxy_id TEXT,
	proxy_group_id TEXT,
	updated_at DATETIME NOT NULL,
	FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
	FOREIGN KEY (proxy_id) REFERENCES egress_proxies(id) ON DELETE RESTRICT,
	FOREIGN KEY (proxy_group_id) REFERENCES egress_proxy_groups(id) ON DELETE RESTRICT,
	CHECK (
		(mode = 'none' AND proxy_id IS NULL AND proxy_group_id IS NULL)
		OR (mode = 'proxy' AND proxy_id IS NOT NULL AND length(trim(proxy_id)) > 0 AND proxy_group_id IS NULL)
		OR (mode = 'group' AND proxy_id IS NULL AND proxy_group_id IS NOT NULL AND length(trim(proxy_group_id)) > 0)
	)
);`

// EgressDefaultView is a credential-free projection of a configured default
// or the effective project/user inheritance preview. Configured distinguishes
// an explicit none default from the absence of a default.
type EgressDefaultView struct {
	Configured bool                     `json:"configured"`
	Mode       string                   `json:"mode"`
	Source     string                   `json:"source"`
	Proxy      *EgressProxySummary      `json:"proxy,omitempty"`
	ProxyGroup *EgressProxyGroupSummary `json:"proxyGroup,omitempty"`
	UpdatedAt  *time.Time               `json:"updatedAt,omitempty"`
}

type egressDefaultChoice struct {
	mode         string
	proxyID      string
	proxyGroupID string
	source       string
}

func (db *DB) initEgressDefaultTables() error {
	if _, err := db.Exec(createEgressDefaultTables); err != nil {
		return err
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS idx_user_egress_defaults_proxy ON user_egress_defaults(proxy_id) WHERE proxy_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_user_egress_defaults_group ON user_egress_defaults(proxy_group_id) WHERE proxy_group_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_project_egress_defaults_proxy ON project_egress_defaults(proxy_id) WHERE proxy_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_project_egress_defaults_group ON project_egress_defaults(proxy_group_id) WHERE proxy_group_id IS NOT NULL`,
	} {
		if _, err := db.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) SetUserEgressDefault(ctx context.Context, userID, mode, proxyID, proxyGroupID string) (EgressDefaultView, error) {
	return db.setEgressDefault(ctx, "user_egress_defaults", "user_id", strings.TrimSpace(userID), ConversationEgressSourceUser, mode, proxyID, proxyGroupID)
}

func (db *DB) SetProjectEgressDefault(ctx context.Context, projectID, mode, proxyID, proxyGroupID string) (EgressDefaultView, error) {
	return db.setEgressDefault(ctx, "project_egress_defaults", "project_id", strings.TrimSpace(projectID), ConversationEgressSourceProject, mode, proxyID, proxyGroupID)
}

func (db *DB) setEgressDefault(ctx context.Context, table, keyColumn, key, source, mode, proxyID, proxyGroupID string) (EgressDefaultView, error) {
	if key == "" {
		return EgressDefaultView{}, fmt.Errorf("egress default scope id is required")
	}
	mode, proxyID, proxyGroupID, configured, err := NormalizeConversationEgressSelection(mode, proxyID, proxyGroupID)
	if err != nil {
		return EgressDefaultView{}, err
	}
	if !configured {
		return EgressDefaultView{}, fmt.Errorf("explicit egress default mode is required")
	}
	if err := validateConversationEgressTarget(ctx, db, mode, proxyID, proxyGroupID); err != nil {
		return EgressDefaultView{}, err
	}
	var parentTable string
	switch table {
	case "user_egress_defaults":
		parentTable = "rbac_users"
	case "project_egress_defaults":
		parentTable = "projects"
	default:
		return EgressDefaultView{}, fmt.Errorf("unsupported egress default scope")
	}
	var exists int
	if err := db.QueryRowContext(ctx, `SELECT 1 FROM `+parentTable+` WHERE id = ?`, key).Scan(&exists); err != nil {
		return EgressDefaultView{}, err
	}
	now := time.Now().UTC()
	_, err = db.ExecContext(ctx, `
		INSERT INTO `+table+` (`+keyColumn+`, mode, proxy_id, proxy_group_id, updated_at)
		VALUES (?, ?, NULLIF(?, ''), NULLIF(?, ''), ?)
		ON CONFLICT(`+keyColumn+`) DO UPDATE SET
			mode = excluded.mode,
			proxy_id = excluded.proxy_id,
			proxy_group_id = excluded.proxy_group_id,
			updated_at = excluded.updated_at
	`, key, mode, proxyID, proxyGroupID, formatSQLiteUTC(now))
	if err != nil {
		return EgressDefaultView{}, fmt.Errorf("store %s egress default: %w", source, err)
	}
	return getEgressDefaultView(ctx, db, table, keyColumn, key, source)
}

func (db *DB) GetUserEgressDefault(ctx context.Context, userID string) (EgressDefaultView, error) {
	view, err := getEgressDefaultView(ctx, db, "user_egress_defaults", "user_id", strings.TrimSpace(userID), ConversationEgressSourceUser)
	if errors.Is(err, sql.ErrNoRows) {
		return emptyEgressDefaultView(), nil
	}
	return view, err
}

func (db *DB) GetProjectEgressDefault(ctx context.Context, projectID string) (EgressDefaultView, error) {
	view, err := getEgressDefaultView(ctx, db, "project_egress_defaults", "project_id", strings.TrimSpace(projectID), ConversationEgressSourceProject)
	if errors.Is(err, sql.ErrNoRows) {
		return emptyEgressDefaultView(), nil
	}
	return view, err
}

func emptyEgressDefaultView() EgressDefaultView {
	return EgressDefaultView{Mode: ConversationEgressModeNone, Source: ConversationEgressSourceNone}
}

func (db *DB) DeleteUserEgressDefault(ctx context.Context, userID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM user_egress_defaults WHERE user_id = ?`, strings.TrimSpace(userID))
	return err
}

func (db *DB) DeleteProjectEgressDefault(ctx context.Context, projectID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM project_egress_defaults WHERE project_id = ?`, strings.TrimSpace(projectID))
	return err
}

// GetEgressInheritancePreview resolves the effective default for a new
// container conversation without persisting a conversation selection.
func (db *DB) GetEgressInheritancePreview(ctx context.Context, userID, projectID string) (EgressDefaultView, error) {
	userID = strings.TrimSpace(userID)
	projectID = strings.TrimSpace(projectID)
	if userID == "" {
		return EgressDefaultView{}, fmt.Errorf("user id is required")
	}
	var exists int
	if err := db.QueryRowContext(ctx, `SELECT 1 FROM rbac_users WHERE id = ?`, userID).Scan(&exists); err != nil {
		return EgressDefaultView{}, err
	}
	if projectID != "" {
		if err := db.QueryRowContext(ctx, `SELECT 1 FROM projects WHERE id = ?`, projectID).Scan(&exists); err != nil {
			return EgressDefaultView{}, err
		}
	}
	return resolveEgressDefaultView(ctx, db, userID, projectID)
}

func resolveEgressDefaultView(ctx context.Context, query conversationEgressQuerier, userID, projectID string) (EgressDefaultView, error) {
	if projectID = strings.TrimSpace(projectID); projectID != "" {
		view, err := getEgressDefaultView(ctx, query, "project_egress_defaults", "project_id", projectID, ConversationEgressSourceProject)
		if err == nil {
			return view, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return EgressDefaultView{}, err
		}
	}
	if userID = strings.TrimSpace(userID); userID != "" {
		view, err := getEgressDefaultView(ctx, query, "user_egress_defaults", "user_id", userID, ConversationEgressSourceUser)
		if err == nil {
			return view, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return EgressDefaultView{}, err
		}
	}
	return emptyEgressDefaultView(), nil
}

func getEgressDefaultView(ctx context.Context, query conversationEgressQuerier, table, keyColumn, key, source string) (EgressDefaultView, error) {
	binding, err := scanConversationEgress(query.QueryRowContext(ctx, `
		SELECT '' AS conversation_id, e.mode, '`+source+`' AS source, e.updated_at,
			p.id, p.name, p.protocol, p.host, p.port, p.enabled, p.credential_ciphertext,
			g.id, g.name, g.enabled, g.failure_threshold, g.cooldown_seconds, g.fail_closed
		FROM `+table+` e
		LEFT JOIN egress_proxies p ON p.id = e.proxy_id
		LEFT JOIN egress_proxy_groups g ON g.id = e.proxy_group_id
		WHERE e.`+keyColumn+` = ?
	`, key), ConversationEgressStatePending)
	if err != nil {
		return EgressDefaultView{}, err
	}
	return EgressDefaultView{
		Configured: true,
		Mode:       binding.Mode,
		Source:     binding.Source,
		Proxy:      binding.Proxy,
		ProxyGroup: binding.ProxyGroup,
		UpdatedAt:  binding.SelectedAt,
	}, nil
}

func resolveConversationEgressDefaultChoice(ctx context.Context, query conversationEgressQuerier, conversationID string) (egressDefaultChoice, error) {
	var projectID, ownerUserID sql.NullString
	if err := query.QueryRowContext(ctx, `SELECT project_id, owner_user_id FROM conversations WHERE id = ?`, conversationID).Scan(&projectID, &ownerUserID); err != nil {
		return egressDefaultChoice{}, err
	}
	view, err := resolveEgressDefaultView(ctx, query, ownerUserID.String, projectID.String)
	if err != nil {
		return egressDefaultChoice{}, err
	}
	choice := egressDefaultChoice{mode: view.Mode, source: view.Source}
	if view.Proxy != nil {
		choice.proxyID = view.Proxy.ID
	}
	if view.ProxyGroup != nil {
		choice.proxyGroupID = view.ProxyGroup.ID
	}
	return choice, nil
}
