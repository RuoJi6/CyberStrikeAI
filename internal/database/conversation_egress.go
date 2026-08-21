package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/egress"
)

const createConversationEgressTables = `
CREATE TABLE IF NOT EXISTS conversation_egress_selections (
	conversation_id TEXT PRIMARY KEY,
	mode TEXT NOT NULL CHECK (mode IN ('none', 'proxy', 'group')),
	proxy_id TEXT,
	proxy_group_id TEXT,
	selected_at DATETIME NOT NULL,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
	FOREIGN KEY (proxy_id) REFERENCES egress_proxies(id) ON DELETE RESTRICT,
	FOREIGN KEY (proxy_group_id) REFERENCES egress_proxy_groups(id) ON DELETE RESTRICT,
	CHECK (
		(mode = 'none' AND proxy_id IS NULL AND proxy_group_id IS NULL)
		OR (mode = 'proxy' AND proxy_id IS NOT NULL AND length(trim(proxy_id)) > 0 AND proxy_group_id IS NULL)
		OR (mode = 'group' AND proxy_id IS NULL AND proxy_group_id IS NOT NULL AND length(trim(proxy_group_id)) > 0)
	)
);

CREATE TABLE IF NOT EXISTS conversation_egress_bindings (
	conversation_id TEXT PRIMARY KEY,
	mode TEXT NOT NULL CHECK (mode IN ('none', 'proxy', 'group')),
	proxy_id TEXT,
	proxy_group_id TEXT,
	source TEXT NOT NULL CHECK (source IN ('none', 'conversation', 'project', 'user')),
	bound_at DATETIME NOT NULL,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
	FOREIGN KEY (proxy_id) REFERENCES egress_proxies(id) ON DELETE RESTRICT,
	FOREIGN KEY (proxy_group_id) REFERENCES egress_proxy_groups(id) ON DELETE RESTRICT,
	CHECK (
		(mode = 'none' AND proxy_id IS NULL AND proxy_group_id IS NULL)
		OR (mode = 'proxy' AND proxy_id IS NOT NULL AND length(trim(proxy_id)) > 0 AND proxy_group_id IS NULL)
		OR (mode = 'group' AND proxy_id IS NULL AND proxy_group_id IS NOT NULL AND length(trim(proxy_group_id)) > 0)
	),
	CHECK (source <> 'none' OR mode = 'none')
);`

const (
	ConversationEgressModeNone  = "none"
	ConversationEgressModeProxy = "proxy"
	ConversationEgressModeGroup = "group"

	ConversationEgressSourceNone         = "none"
	ConversationEgressSourceConversation = "conversation"

	ConversationEgressStatePending = "pending"
	ConversationEgressStateActive  = "active"
)

var (
	ErrConversationEgressBindingNotFound = errors.New("conversation egress binding not found")
	ErrConversationEgressBindingActive   = errors.New("conversation egress binding is already active")
	ErrConversationEgressIntegrity       = errors.New("conversation egress binding integrity check failed")
)

// EgressProxyGroupSummary is the safe, routing-relevant group projection used
// by conversation bindings. Member health and internal routing weights are not
// part of a conversation's selection response.
type EgressProxyGroupSummary struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	FailureThreshold int    `json:"failureThreshold"`
	CooldownSeconds  int    `json:"cooldownSeconds"`
	FailClosed       bool   `json:"failClosed"`
}

// ConversationEgressBinding is a safe control-plane view of either the
// editable pre-start selection or the immutable binding consumed at first
// container start. It never includes encrypted credentials or group scheduler
// state.
type ConversationEgressBinding struct {
	ConversationID string                   `json:"conversationId"`
	State          string                   `json:"state"`
	Mode           string                   `json:"mode"`
	Source         string                   `json:"source"`
	Proxy          *EgressProxySummary      `json:"proxy,omitempty"`
	ProxyGroup     *EgressProxyGroupSummary `json:"proxyGroup,omitempty"`
	SelectedAt     *time.Time               `json:"selectedAt,omitempty"`
	BoundAt        *time.Time               `json:"boundAt,omitempty"`
}

func (db *DB) initConversationEgressTables() error {
	if _, err := db.Exec(createConversationEgressTables); err != nil {
		return err
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS idx_conversation_egress_selections_proxy ON conversation_egress_selections(proxy_id) WHERE proxy_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_conversation_egress_selections_group ON conversation_egress_selections(proxy_group_id) WHERE proxy_group_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_conversation_egress_bindings_proxy ON conversation_egress_bindings(proxy_id) WHERE proxy_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_conversation_egress_bindings_group ON conversation_egress_bindings(proxy_group_id) WHERE proxy_group_id IS NOT NULL`,
		`CREATE TRIGGER IF NOT EXISTS conversation_egress_bindings_no_update
		 BEFORE UPDATE ON conversation_egress_bindings
		 BEGIN SELECT RAISE(ABORT, 'conversation egress bindings are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS conversation_egress_bindings_no_live_delete
		 BEFORE DELETE ON conversation_egress_bindings
		 WHEN EXISTS (SELECT 1 FROM conversations WHERE id = OLD.conversation_id)
		 BEGIN SELECT RAISE(ABORT, 'live conversation egress bindings are immutable'); END`,
	} {
		if _, err := db.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}

// NormalizeConversationEgressSelection validates the exact three-state
// control-plane representation. configured=false means the caller omitted all
// egress fields; explicit mode=none is configured and remains distinguishable.
func NormalizeConversationEgressSelection(mode, proxyID, proxyGroupID string) (normalizedMode, normalizedProxyID, normalizedProxyGroupID string, configured bool, err error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	proxyID = strings.TrimSpace(proxyID)
	proxyGroupID = strings.TrimSpace(proxyGroupID)
	if mode == "" {
		if proxyID != "" || proxyGroupID != "" {
			return "", "", "", false, fmt.Errorf("egress mode is required when an egress resource id is provided")
		}
		return "", "", "", false, nil
	}
	switch mode {
	case ConversationEgressModeNone:
		if proxyID != "" || proxyGroupID != "" {
			return "", "", "", false, fmt.Errorf("egress mode none cannot reference a proxy or proxy group")
		}
	case ConversationEgressModeProxy:
		if proxyID == "" || proxyGroupID != "" {
			return "", "", "", false, fmt.Errorf("egress mode proxy requires only egressProxyId")
		}
	case ConversationEgressModeGroup:
		if proxyID != "" || proxyGroupID == "" {
			return "", "", "", false, fmt.Errorf("egress mode group requires only egressProxyGroupId")
		}
	default:
		return "", "", "", false, fmt.Errorf("egress mode must be none, proxy, or group")
	}
	return mode, proxyID, proxyGroupID, true, nil
}

func validateConversationEgressTarget(ctx context.Context, query conversationEgressQuerier, mode, proxyID, proxyGroupID string) error {
	var exists int
	switch mode {
	case ConversationEgressModeNone:
		return nil
	case ConversationEgressModeProxy:
		if err := query.QueryRowContext(ctx, `SELECT 1 FROM egress_proxies WHERE id = ?`, proxyID).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrEgressProxyNotFound
			}
			return err
		}
	case ConversationEgressModeGroup:
		if err := query.QueryRowContext(ctx, `SELECT 1 FROM egress_proxy_groups WHERE id = ?`, proxyGroupID).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrEgressProxyGroupNotFound
			}
			return err
		}
	default:
		return fmt.Errorf("unsupported egress mode %q", mode)
	}
	return nil
}

// SetConversationEgressSelection replaces the editable selection before first
// container start. Once a binding exists it fails closed and never mutates it.
func (db *DB) SetConversationEgressSelection(ctx context.Context, conversationID, mode, proxyID, proxyGroupID string) (ConversationEgressBinding, error) {
	conversationID = strings.TrimSpace(conversationID)
	mode, proxyID, proxyGroupID, configured, err := NormalizeConversationEgressSelection(mode, proxyID, proxyGroupID)
	if err != nil {
		return ConversationEgressBinding{}, err
	}
	if conversationID == "" || !configured {
		return ConversationEgressBinding{}, fmt.Errorf("conversation id and explicit egress mode are required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ConversationEgressBinding{}, fmt.Errorf("begin conversation egress selection: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockContainerConversationForEgress(ctx, tx, conversationID); err != nil {
		return ConversationEgressBinding{}, err
	}
	var bindingCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM conversation_egress_bindings WHERE conversation_id = ?`, conversationID).Scan(&bindingCount); err != nil {
		return ConversationEgressBinding{}, fmt.Errorf("check active conversation egress binding: %w", err)
	}
	if bindingCount != 0 {
		return ConversationEgressBinding{}, ErrConversationEgressBindingActive
	}
	if err := validateConversationEgressTarget(ctx, tx, mode, proxyID, proxyGroupID); err != nil {
		return ConversationEgressBinding{}, err
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO conversation_egress_selections (
			conversation_id, mode, proxy_id, proxy_group_id, selected_at
		) VALUES (?, ?, NULLIF(?, ''), NULLIF(?, ''), ?)
		ON CONFLICT(conversation_id) DO UPDATE SET
			mode = excluded.mode,
			proxy_id = excluded.proxy_id,
			proxy_group_id = excluded.proxy_group_id,
			selected_at = excluded.selected_at
	`, conversationID, mode, proxyID, proxyGroupID, formatSQLiteUTC(now)); err != nil {
		return ConversationEgressBinding{}, fmt.Errorf("store conversation egress selection: %w", err)
	}
	selection, err := getConversationEgressSelection(ctx, tx, conversationID)
	if err != nil {
		return ConversationEgressBinding{}, err
	}
	if err := tx.Commit(); err != nil {
		return ConversationEgressBinding{}, fmt.Errorf("commit conversation egress selection: %w", err)
	}
	return selection, nil
}

// EnsureConversationEgressBinding freezes exactly one binding before durable
// container work is queued or claimed. A no-op conversation update serializes
// concurrent first starts. Omitted selection becomes fail-closed direct mode
// none/source=none; explicit none remains source=conversation.
func (db *DB) EnsureConversationEgressBinding(ctx context.Context, conversationID string) (ConversationEgressBinding, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return ConversationEgressBinding{}, fmt.Errorf("conversation id is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ConversationEgressBinding{}, fmt.Errorf("begin conversation egress binding: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockContainerConversationForEgress(ctx, tx, conversationID); err != nil {
		return ConversationEgressBinding{}, err
	}
	if existing, getErr := getConversationEgressBinding(ctx, tx, conversationID); getErr == nil {
		if err := tx.Commit(); err != nil {
			return ConversationEgressBinding{}, fmt.Errorf("commit existing conversation egress binding: %w", err)
		}
		return existing, nil
	} else if !errors.Is(getErr, ErrConversationEgressBindingNotFound) {
		return ConversationEgressBinding{}, getErr
	}

	mode, proxyID, proxyGroupID := ConversationEgressModeNone, "", ""
	source := ConversationEgressSourceNone
	var selectionMode string
	var selectionProxyID, selectionGroupID sql.NullString
	selectionErr := tx.QueryRowContext(ctx, `
		SELECT mode, proxy_id, proxy_group_id
		FROM conversation_egress_selections WHERE conversation_id = ?
	`, conversationID).Scan(&selectionMode, &selectionProxyID, &selectionGroupID)
	if selectionErr == nil {
		mode = selectionMode
		proxyID = selectionProxyID.String
		proxyGroupID = selectionGroupID.String
		source = ConversationEgressSourceConversation
	} else if !errors.Is(selectionErr, sql.ErrNoRows) {
		return ConversationEgressBinding{}, fmt.Errorf("load conversation egress selection: %w", selectionErr)
	}
	if err := validateConversationEgressTarget(ctx, tx, mode, proxyID, proxyGroupID); err != nil {
		return ConversationEgressBinding{}, fmt.Errorf("validate conversation egress binding target: %w", err)
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO conversation_egress_bindings (
			conversation_id, mode, proxy_id, proxy_group_id, source, bound_at
		) VALUES (?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?)
	`, conversationID, mode, proxyID, proxyGroupID, source, formatSQLiteUTC(now)); err != nil {
		return ConversationEgressBinding{}, fmt.Errorf("insert conversation egress binding: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM conversation_egress_selections WHERE conversation_id = ?`, conversationID); err != nil {
		return ConversationEgressBinding{}, fmt.Errorf("consume conversation egress selection: %w", err)
	}
	binding, err := getConversationEgressBinding(ctx, tx, conversationID)
	if err != nil {
		return ConversationEgressBinding{}, err
	}
	if err := tx.Commit(); err != nil {
		return ConversationEgressBinding{}, fmt.Errorf("commit conversation egress binding: %w", err)
	}
	return binding, nil
}

func lockContainerConversationForEgress(ctx context.Context, tx *sql.Tx, conversationID string) error {
	result, err := tx.ExecContext(ctx, `UPDATE conversations SET id = id WHERE id = ?`, conversationID)
	if err != nil {
		return fmt.Errorf("lock conversation egress selection: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return sql.ErrNoRows
	}
	var runtimeMode string
	if err := tx.QueryRowContext(ctx, `SELECT runtime_mode FROM conversations WHERE id = ?`, conversationID).Scan(&runtimeMode); err != nil {
		return err
	}
	if runtimeMode != ConversationRuntimeModeContainer {
		return fmt.Errorf("conversation egress binding requires a container conversation")
	}
	return nil
}

// GetConversationEgress returns an active binding, an explicit pending
// selection, or the implicit pending none selection for an unused container
// conversation.
func (db *DB) GetConversationEgress(ctx context.Context, conversationID string) (ConversationEgressBinding, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return ConversationEgressBinding{}, fmt.Errorf("conversation id is required")
	}
	if binding, err := getConversationEgressBinding(ctx, db, conversationID); err == nil {
		return binding, nil
	} else if !errors.Is(err, ErrConversationEgressBindingNotFound) {
		return ConversationEgressBinding{}, err
	}
	if selection, err := getConversationEgressSelection(ctx, db, conversationID); err == nil {
		return selection, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return ConversationEgressBinding{}, err
	}
	var runtimeMode string
	if err := db.QueryRowContext(ctx, `SELECT runtime_mode FROM conversations WHERE id = ?`, conversationID).Scan(&runtimeMode); err != nil {
		return ConversationEgressBinding{}, err
	}
	if runtimeMode != ConversationRuntimeModeContainer {
		return ConversationEgressBinding{}, fmt.Errorf("conversation egress binding requires a container conversation")
	}
	return ConversationEgressBinding{
		ConversationID: conversationID,
		State:          ConversationEgressStatePending,
		Mode:           ConversationEgressModeNone,
		Source:         ConversationEgressSourceNone,
	}, nil
}

func (db *DB) GetConversationEgressBinding(ctx context.Context, conversationID string) (ConversationEgressBinding, error) {
	return getConversationEgressBinding(ctx, db, strings.TrimSpace(conversationID))
}

// EnsureContainerRuntimeEgressBindings upgrades only conversations with
// durable runtime rows. Unused container conversations retain editable
// selections until their first actual start.
func (db *DB) EnsureContainerRuntimeEgressBindings(ctx context.Context) error {
	rows, err := db.QueryContext(ctx, `SELECT conversation_id FROM conversation_container_runtimes ORDER BY conversation_id`)
	if err != nil {
		return fmt.Errorf("list container runtimes for egress binding migration: %w", err)
	}
	conversationIDs := make([]string, 0)
	for rows.Next() {
		var conversationID string
		if err := rows.Scan(&conversationID); err != nil {
			_ = rows.Close()
			return err
		}
		conversationIDs = append(conversationIDs, conversationID)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var bindingErrors []error
	for _, conversationID := range conversationIDs {
		if _, err := db.EnsureConversationEgressBinding(ctx, conversationID); err != nil {
			bindingErrors = append(bindingErrors, fmt.Errorf("conversation %s: %w", conversationID, err))
		}
	}
	return errors.Join(bindingErrors...)
}

type conversationEgressQuerier interface {
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func getConversationEgressSelection(ctx context.Context, query conversationEgressQuerier, conversationID string) (ConversationEgressBinding, error) {
	return scanConversationEgress(query.QueryRowContext(ctx, conversationEgressSelectSQL(`conversation_egress_selections`, `selected_at`)+` WHERE e.conversation_id = ?`, conversationID), ConversationEgressStatePending)
}

func getConversationEgressBinding(ctx context.Context, query conversationEgressQuerier, conversationID string) (ConversationEgressBinding, error) {
	binding, err := scanConversationEgress(query.QueryRowContext(ctx, conversationEgressSelectSQL(`conversation_egress_bindings`, `bound_at`)+` WHERE e.conversation_id = ?`, conversationID), ConversationEgressStateActive)
	if errors.Is(err, sql.ErrNoRows) {
		return ConversationEgressBinding{}, ErrConversationEgressBindingNotFound
	}
	return binding, err
}

func conversationEgressSelectSQL(table, timestampColumn string) string {
	source := `'conversation'`
	if table == "conversation_egress_bindings" {
		source = `e.source`
	}
	return `
		SELECT e.conversation_id, e.mode, ` + source + `, e.` + timestampColumn + `,
			p.id, p.name, p.protocol, p.host, p.port, p.enabled, p.credential_ciphertext,
			g.id, g.name, g.enabled, g.failure_threshold, g.cooldown_seconds, g.fail_closed
		FROM ` + table + ` e
		LEFT JOIN egress_proxies p ON p.id = e.proxy_id
		LEFT JOIN egress_proxy_groups g ON g.id = e.proxy_group_id`
}

func scanConversationEgress(scanner interface{ Scan(...interface{}) error }, state string) (ConversationEgressBinding, error) {
	var result ConversationEgressBinding
	var timestamp string
	var proxyID, proxyName, proxyProtocol, proxyHost, proxyCredential sql.NullString
	var proxyPort, proxyEnabled sql.NullInt64
	var groupID, groupName sql.NullString
	var groupEnabled, failureThreshold, cooldownSeconds, failClosed sql.NullInt64
	if err := scanner.Scan(
		&result.ConversationID, &result.Mode, &result.Source, &timestamp,
		&proxyID, &proxyName, &proxyProtocol, &proxyHost, &proxyPort, &proxyEnabled, &proxyCredential,
		&groupID, &groupName, &groupEnabled, &failureThreshold, &cooldownSeconds, &failClosed,
	); err != nil {
		return ConversationEgressBinding{}, err
	}
	result.State = state
	parsedAt := parseDBTime(timestamp)
	if state == ConversationEgressStateActive {
		result.BoundAt = &parsedAt
	} else {
		result.SelectedAt = &parsedAt
	}
	if proxyID.Valid {
		protocol, err := egress.ParseUpstreamProtocol(proxyProtocol.String)
		if err != nil {
			return ConversationEgressBinding{}, err
		}
		result.Proxy = &EgressProxySummary{
			ID: proxyID.String, Name: proxyName.String, Protocol: protocol,
			Host: proxyHost.String, Port: int(proxyPort.Int64), Enabled: proxyEnabled.Int64 != 0,
			CredentialsConfigured: strings.TrimSpace(proxyCredential.String) != "",
		}
	}
	if groupID.Valid {
		result.ProxyGroup = &EgressProxyGroupSummary{
			ID: groupID.String, Name: groupName.String, Enabled: groupEnabled.Int64 != 0,
			FailureThreshold: int(failureThreshold.Int64), CooldownSeconds: int(cooldownSeconds.Int64),
			FailClosed: failClosed.Int64 != 0,
		}
	}
	switch result.Mode {
	case ConversationEgressModeNone:
		if result.Proxy != nil || result.ProxyGroup != nil {
			return ConversationEgressBinding{}, ErrConversationEgressIntegrity
		}
	case ConversationEgressModeProxy:
		if result.Proxy == nil || result.ProxyGroup != nil {
			return ConversationEgressBinding{}, ErrConversationEgressIntegrity
		}
	case ConversationEgressModeGroup:
		if result.Proxy != nil || result.ProxyGroup == nil {
			return ConversationEgressBinding{}, ErrConversationEgressIntegrity
		}
	default:
		return ConversationEgressBinding{}, ErrConversationEgressIntegrity
	}
	if state == ConversationEgressStateActive && result.Source == ConversationEgressSourceNone && result.Mode != ConversationEgressModeNone {
		return ConversationEgressBinding{}, ErrConversationEgressIntegrity
	}
	return result, nil
}
