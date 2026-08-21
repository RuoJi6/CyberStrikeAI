package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"cyberstrike-ai/internal/egress"
	"github.com/google/uuid"
)

const createEgressProxyGroupsTables = `
CREATE TABLE IF NOT EXISTS egress_proxy_groups (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
	failure_threshold INTEGER NOT NULL DEFAULT 3 CHECK (failure_threshold BETWEEN 1 AND 100),
	cooldown_seconds INTEGER NOT NULL DEFAULT 60 CHECK (cooldown_seconds BETWEEN 1 AND 86400),
	fail_closed INTEGER NOT NULL DEFAULT 1 CHECK (fail_closed = 1),
	owner_user_id TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	CHECK (length(trim(name)) BETWEEN 1 AND 120),
	CHECK (length(trim(owner_user_id)) > 0)
);

CREATE TABLE IF NOT EXISTS egress_proxy_group_members (
	group_id TEXT NOT NULL,
	proxy_id TEXT NOT NULL,
	priority INTEGER NOT NULL DEFAULT 0 CHECK (priority BETWEEN 0 AND 1000000),
	weight INTEGER NOT NULL DEFAULT 1 CHECK (weight BETWEEN 1 AND 1000),
	enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
	current_weight INTEGER NOT NULL DEFAULT 0,
	consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
	circuit_open_until DATETIME,
	last_failure_at DATETIME,
	last_success_at DATETIME,
	last_selected_at DATETIME,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	PRIMARY KEY (group_id, proxy_id),
	FOREIGN KEY (group_id) REFERENCES egress_proxy_groups(id) ON DELETE CASCADE,
	FOREIGN KEY (proxy_id) REFERENCES egress_proxies(id) ON DELETE CASCADE
);`

var (
	ErrEgressProxyGroupNotFound       = errors.New("egress proxy group not found")
	ErrEgressProxyGroupMemberNotFound = errors.New("egress proxy group member not found")
	ErrNoAvailableEgressProxy         = errors.New("no available egress proxy")
)

type EgressProxySummary struct {
	ID                    string                  `json:"id"`
	Name                  string                  `json:"name"`
	Protocol              egress.UpstreamProtocol `json:"protocol"`
	Host                  string                  `json:"host"`
	Port                  int                     `json:"port"`
	Enabled               bool                    `json:"enabled"`
	CredentialsConfigured bool                    `json:"credentialsConfigured"`
}

type EgressProxyGroupMember struct {
	GroupID             string             `json:"-"`
	ProxyID             string             `json:"proxyId"`
	Priority            int                `json:"priority"`
	Weight              int                `json:"weight"`
	Enabled             bool               `json:"enabled"`
	Status              string             `json:"status"`
	ConsecutiveFailures int                `json:"consecutiveFailures"`
	CircuitOpenUntil    *time.Time         `json:"circuitOpenUntil,omitempty"`
	LastFailureAt       *time.Time         `json:"lastFailureAt,omitempty"`
	LastSuccessAt       *time.Time         `json:"lastSuccessAt,omitempty"`
	LastSelectedAt      *time.Time         `json:"lastSelectedAt,omitempty"`
	Proxy               EgressProxySummary `json:"proxy"`
	CurrentWeight       int64              `json:"-"`
	CreatedAt           time.Time          `json:"createdAt"`
	UpdatedAt           time.Time          `json:"updatedAt"`
}

type EgressProxyGroup struct {
	ID               string                   `json:"id"`
	Name             string                   `json:"name"`
	Enabled          bool                     `json:"enabled"`
	FailureThreshold int                      `json:"failureThreshold"`
	CooldownSeconds  int                      `json:"cooldownSeconds"`
	FailClosed       bool                     `json:"failClosed"`
	OwnerUserID      string                   `json:"ownerUserId,omitempty"`
	Members          []EgressProxyGroupMember `json:"members"`
	CreatedAt        time.Time                `json:"createdAt"`
	UpdatedAt        time.Time                `json:"updatedAt"`
}

type EgressProxyGroupSelection struct {
	GroupID    string             `json:"groupId"`
	ProxyID    string             `json:"proxyId"`
	Priority   int                `json:"priority"`
	Weight     int                `json:"weight"`
	Proxy      EgressProxySummary `json:"proxy"`
	SelectedAt time.Time          `json:"selectedAt"`
}

type EgressProxyGroupMemberHealth struct {
	GroupID             string     `json:"groupId"`
	ProxyID             string     `json:"proxyId"`
	ConsecutiveFailures int        `json:"consecutiveFailures"`
	CircuitOpenUntil    *time.Time `json:"circuitOpenUntil,omitempty"`
	LastFailureAt       *time.Time `json:"lastFailureAt,omitempty"`
	LastSuccessAt       *time.Time `json:"lastSuccessAt,omitempty"`
}

func (db *DB) initEgressProxyGroupTables() error {
	if _, err := db.Exec(createEgressProxyGroupsTables); err != nil {
		return err
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS idx_egress_proxy_groups_owner_updated ON egress_proxy_groups(owner_user_id, updated_at DESC, id)`,
		`CREATE INDEX IF NOT EXISTS idx_egress_proxy_group_members_routing ON egress_proxy_group_members(group_id, enabled, priority, circuit_open_until, proxy_id)`,
		`CREATE INDEX IF NOT EXISTS idx_egress_proxy_group_members_proxy ON egress_proxy_group_members(proxy_id, group_id)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}

func normalizeEgressProxyGroup(group EgressProxyGroup) (EgressProxyGroup, error) {
	name, err := egress.ValidateProxyGroupName(group.Name)
	if err != nil {
		return EgressProxyGroup{}, err
	}
	if err := egress.ValidateProxyGroupFailureThreshold(group.FailureThreshold); err != nil {
		return EgressProxyGroup{}, err
	}
	if err := egress.ValidateProxyGroupCooldownSeconds(group.CooldownSeconds); err != nil {
		return EgressProxyGroup{}, err
	}
	group.Name = name
	group.FailClosed = true
	group.OwnerUserID = strings.TrimSpace(group.OwnerUserID)
	if group.OwnerUserID == "" {
		return EgressProxyGroup{}, fmt.Errorf("egress proxy group owner is required")
	}
	if len(group.Members) < 1 || len(group.Members) > egress.MaxProxyGroupMembers {
		return EgressProxyGroup{}, fmt.Errorf("proxy group must contain between 1 and %d members", egress.MaxProxyGroupMembers)
	}
	seen := make(map[string]struct{}, len(group.Members))
	for i := range group.Members {
		member := &group.Members[i]
		member.ProxyID = strings.TrimSpace(member.ProxyID)
		if member.ProxyID == "" {
			return EgressProxyGroup{}, fmt.Errorf("proxy group member proxy id is required")
		}
		if _, exists := seen[member.ProxyID]; exists {
			return EgressProxyGroup{}, fmt.Errorf("proxy group member is duplicated")
		}
		seen[member.ProxyID] = struct{}{}
		if err := egress.ValidateProxyGroupMember(member.Priority, member.Weight); err != nil {
			return EgressProxyGroup{}, err
		}
	}
	sort.Slice(group.Members, func(i, j int) bool {
		if group.Members[i].Priority != group.Members[j].Priority {
			return group.Members[i].Priority < group.Members[j].Priority
		}
		return group.Members[i].ProxyID < group.Members[j].ProxyID
	})
	return group, nil
}

func (db *DB) CreateEgressProxyGroup(ctx context.Context, group EgressProxyGroup) (EgressProxyGroup, error) {
	group.ID = strings.TrimSpace(group.ID)
	if group.ID == "" {
		group.ID = uuid.NewString()
	}
	var err error
	group, err = normalizeEgressProxyGroup(group)
	if err != nil {
		return EgressProxyGroup{}, err
	}
	now := time.Now().UTC()
	if !group.CreatedAt.IsZero() {
		now = group.CreatedAt.UTC()
	}
	group.CreatedAt = now
	group.UpdatedAt = now
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return EgressProxyGroup{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := validateEgressProxyGroupMemberRows(ctx, tx, group.Members); err != nil {
		return EgressProxyGroup{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO egress_proxy_groups (
			id, name, enabled, failure_threshold, cooldown_seconds, fail_closed,
			owner_user_id, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
	`, group.ID, group.Name, boolToInt(group.Enabled), group.FailureThreshold, group.CooldownSeconds,
		group.OwnerUserID, formatSQLiteUTC(group.CreatedAt), formatSQLiteUTC(group.UpdatedAt)); err != nil {
		return EgressProxyGroup{}, fmt.Errorf("create egress proxy group: %w", err)
	}
	if err := insertEgressProxyGroupMembers(ctx, tx, group.ID, group.Members, now); err != nil {
		return EgressProxyGroup{}, err
	}
	if err := tx.Commit(); err != nil {
		return EgressProxyGroup{}, err
	}
	return db.GetEgressProxyGroup(ctx, group.ID)
}

func (db *DB) GetEgressProxyGroup(ctx context.Context, id string) (EgressProxyGroup, error) {
	group, err := scanEgressProxyGroup(db.QueryRowContext(ctx, `
		SELECT id, name, enabled, failure_threshold, cooldown_seconds, fail_closed,
			owner_user_id, created_at, updated_at
		FROM egress_proxy_groups WHERE id = ?
	`, strings.TrimSpace(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return EgressProxyGroup{}, ErrEgressProxyGroupNotFound
	}
	if err != nil {
		return EgressProxyGroup{}, err
	}
	group.Members, err = listEgressProxyGroupMembers(ctx, db, group.ID, time.Now().UTC())
	return group, err
}

func (db *DB) ListEgressProxyGroups(ctx context.Context, userID, scope string) ([]EgressProxyGroup, error) {
	query := `
		SELECT id, name, enabled, failure_threshold, cooldown_seconds, fail_closed,
			owner_user_id, created_at, updated_at
		FROM egress_proxy_groups`
	args := make([]interface{}, 0, 2)
	if scope != RBACScopeAll {
		query += ` WHERE owner_user_id = ? OR id IN (
			SELECT resource_id FROM rbac_resource_assignments
			WHERE user_id = ? AND resource_type = 'egress_proxy_group'
		)`
		args = append(args, strings.TrimSpace(userID), strings.TrimSpace(userID))
	}
	query += ` ORDER BY updated_at DESC, id`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list egress proxy groups: %w", err)
	}
	defer rows.Close()
	groups := make([]EgressProxyGroup, 0)
	for rows.Next() {
		group, err := scanEgressProxyGroup(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list egress proxy groups: %w", err)
	}
	now := time.Now().UTC()
	for i := range groups {
		groups[i].Members, err = listEgressProxyGroupMembers(ctx, db, groups[i].ID, now)
		if err != nil {
			return nil, err
		}
	}
	return groups, nil
}

func (db *DB) UpdateEgressProxyGroup(ctx context.Context, group EgressProxyGroup) (EgressProxyGroup, error) {
	group.ID = strings.TrimSpace(group.ID)
	if group.ID == "" {
		return EgressProxyGroup{}, fmt.Errorf("egress proxy group id is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return EgressProxyGroup{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var owner, createdAt string
	if err := tx.QueryRowContext(ctx, `SELECT owner_user_id, created_at FROM egress_proxy_groups WHERE id = ?`, group.ID).Scan(&owner, &createdAt); errors.Is(err, sql.ErrNoRows) {
		return EgressProxyGroup{}, ErrEgressProxyGroupNotFound
	} else if err != nil {
		return EgressProxyGroup{}, err
	}
	group.OwnerUserID = owner
	group.CreatedAt = parseDBTime(createdAt)
	group, err = normalizeEgressProxyGroup(group)
	if err != nil {
		return EgressProxyGroup{}, err
	}
	if err := validateEgressProxyGroupMemberRows(ctx, tx, group.Members); err != nil {
		return EgressProxyGroup{}, err
	}
	group.UpdatedAt = time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		UPDATE egress_proxy_groups
		SET name = ?, enabled = ?, failure_threshold = ?, cooldown_seconds = ?, fail_closed = 1, updated_at = ?
		WHERE id = ?
	`, group.Name, boolToInt(group.Enabled), group.FailureThreshold, group.CooldownSeconds,
		formatSQLiteUTC(group.UpdatedAt), group.ID); err != nil {
		return EgressProxyGroup{}, fmt.Errorf("update egress proxy group: %w", err)
	}
	if err := syncEgressProxyGroupMembers(ctx, tx, group.ID, group.Members, group.UpdatedAt); err != nil {
		return EgressProxyGroup{}, err
	}
	if err := tx.Commit(); err != nil {
		return EgressProxyGroup{}, err
	}
	return db.GetEgressProxyGroup(ctx, group.ID)
}

func (db *DB) DeleteEgressProxyGroup(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM egress_proxy_groups WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete egress proxy group: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return err
		}
		return ErrEgressProxyGroupNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM rbac_resource_assignments WHERE resource_type = 'egress_proxy_group' AND resource_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

type egressProxyGroupQueryer interface {
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
}

type egressProxyGroupScanner interface {
	Scan(...interface{}) error
}

func scanEgressProxyGroup(scanner egressProxyGroupScanner) (EgressProxyGroup, error) {
	var group EgressProxyGroup
	var enabled, failClosed int
	var createdAt, updatedAt string
	if err := scanner.Scan(&group.ID, &group.Name, &enabled, &group.FailureThreshold, &group.CooldownSeconds,
		&failClosed, &group.OwnerUserID, &createdAt, &updatedAt); err != nil {
		return EgressProxyGroup{}, err
	}
	group.Enabled = enabled != 0
	group.FailClosed = failClosed != 0
	group.CreatedAt = parseDBTime(createdAt)
	group.UpdatedAt = parseDBTime(updatedAt)
	return group, nil
}

func listEgressProxyGroupMembers(ctx context.Context, queryer egressProxyGroupQueryer, groupID string, now time.Time) ([]EgressProxyGroupMember, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT m.group_id, m.proxy_id, m.priority, m.weight, m.enabled, m.current_weight,
			m.consecutive_failures, m.circuit_open_until, m.last_failure_at, m.last_success_at,
			m.last_selected_at, m.created_at, m.updated_at,
			p.name, p.protocol, p.host, p.port, p.enabled,
			CASE WHEN p.credential_ciphertext = '' THEN 0 ELSE 1 END
		FROM egress_proxy_group_members m
		JOIN egress_proxies p ON p.id = m.proxy_id
		WHERE m.group_id = ?
		ORDER BY m.priority, m.proxy_id
	`, groupID)
	if err != nil {
		return nil, fmt.Errorf("list egress proxy group members: %w", err)
	}
	defer rows.Close()
	members := make([]EgressProxyGroupMember, 0)
	for rows.Next() {
		member, err := scanEgressProxyGroupMember(rows, now)
		if err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, rows.Err()
}

func scanEgressProxyGroupMember(scanner egressProxyGroupScanner, now time.Time) (EgressProxyGroupMember, error) {
	var member EgressProxyGroupMember
	var memberEnabled, proxyEnabled, credentialsConfigured int
	var protocol, createdAt, updatedAt string
	var circuitOpenUntil, lastFailureAt, lastSuccessAt, lastSelectedAt sql.NullString
	if err := scanner.Scan(
		&member.GroupID, &member.ProxyID, &member.Priority, &member.Weight, &memberEnabled, &member.CurrentWeight,
		&member.ConsecutiveFailures, &circuitOpenUntil, &lastFailureAt, &lastSuccessAt,
		&lastSelectedAt, &createdAt, &updatedAt,
		&member.Proxy.Name, &protocol, &member.Proxy.Host, &member.Proxy.Port, &proxyEnabled, &credentialsConfigured,
	); err != nil {
		return EgressProxyGroupMember{}, err
	}
	parsedProtocol, err := egress.ParseUpstreamProtocol(protocol)
	if err != nil {
		return EgressProxyGroupMember{}, err
	}
	member.Enabled = memberEnabled != 0
	member.Proxy = EgressProxySummary{
		ID: member.ProxyID, Name: member.Proxy.Name, Protocol: parsedProtocol,
		Host: member.Proxy.Host, Port: member.Proxy.Port, Enabled: proxyEnabled != 0,
		CredentialsConfigured: credentialsConfigured != 0,
	}
	member.CreatedAt = parseDBTime(createdAt)
	member.UpdatedAt = parseDBTime(updatedAt)
	member.CircuitOpenUntil = parseNullableDBTime(circuitOpenUntil)
	member.LastFailureAt = parseNullableDBTime(lastFailureAt)
	member.LastSuccessAt = parseNullableDBTime(lastSuccessAt)
	member.LastSelectedAt = parseNullableDBTime(lastSelectedAt)
	member.Status = egressProxyGroupMemberStatus(member, now)
	return member, nil
}

func parseNullableDBTime(value sql.NullString) *time.Time {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return nil
	}
	parsed := parseDBTime(value.String)
	return &parsed
}

func egressProxyGroupMemberStatus(member EgressProxyGroupMember, now time.Time) string {
	if !member.Enabled {
		return "disabled"
	}
	if !member.Proxy.Enabled {
		return "proxy_disabled"
	}
	if member.CircuitOpenUntil != nil && now.Before(*member.CircuitOpenUntil) {
		return "circuit_open"
	}
	return "available"
}

type egressProxyGroupTx interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func validateEgressProxyGroupMemberRows(ctx context.Context, tx egressProxyGroupTx, members []EgressProxyGroupMember) error {
	for _, member := range members {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM egress_proxies WHERE id = ?`, member.ProxyID).Scan(&exists); err != nil {
			return err
		}
		if exists != 1 {
			return fmt.Errorf("%w: %s", ErrEgressProxyNotFound, member.ProxyID)
		}
	}
	return nil
}

func insertEgressProxyGroupMembers(ctx context.Context, tx egressProxyGroupTx, groupID string, members []EgressProxyGroupMember, now time.Time) error {
	for _, member := range members {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO egress_proxy_group_members (
				group_id, proxy_id, priority, weight, enabled, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?)
		`, groupID, member.ProxyID, member.Priority, member.Weight, boolToInt(member.Enabled),
			formatSQLiteUTC(now), formatSQLiteUTC(now)); err != nil {
			return fmt.Errorf("create egress proxy group member: %w", err)
		}
	}
	return nil
}

func syncEgressProxyGroupMembers(ctx context.Context, tx egressProxyGroupTx, groupID string, members []EgressProxyGroupMember, now time.Time) error {
	ids := make([]string, 0, len(members))
	for _, member := range members {
		ids = append(ids, member.ProxyID)
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
	args := make([]interface{}, 0, len(ids)+1)
	args = append(args, groupID)
	for _, id := range ids {
		args = append(args, id)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM egress_proxy_group_members WHERE group_id = ? AND proxy_id NOT IN (`+placeholders+`)`, args...); err != nil {
		return err
	}
	for _, member := range members {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO egress_proxy_group_members (
				group_id, proxy_id, priority, weight, enabled, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(group_id, proxy_id) DO UPDATE SET
				current_weight = CASE
					WHEN egress_proxy_group_members.priority <> excluded.priority
						OR egress_proxy_group_members.weight <> excluded.weight
						OR egress_proxy_group_members.enabled <> excluded.enabled THEN 0
					ELSE egress_proxy_group_members.current_weight END,
				priority = excluded.priority,
				weight = excluded.weight,
				enabled = excluded.enabled,
				updated_at = excluded.updated_at
		`, groupID, member.ProxyID, member.Priority, member.Weight, boolToInt(member.Enabled),
			formatSQLiteUTC(now), formatSQLiteUTC(now)); err != nil {
			return fmt.Errorf("update egress proxy group member: %w", err)
		}
	}
	return nil
}

// SelectEgressProxyGroupMember performs priority failover and smooth weighted
// round-robin in one BEGIN IMMEDIATE transaction. It never returns a direct
// route: no eligible member is always ErrNoAvailableEgressProxy.
func (db *DB) SelectEgressProxyGroupMember(ctx context.Context, groupID string, now time.Time) (EgressProxyGroupSelection, error) {
	groupID = strings.TrimSpace(groupID)
	now = now.UTC()
	conn, err := db.Conn(ctx)
	if err != nil {
		return EgressProxyGroupSelection{}, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return EgressProxyGroupSelection{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	var groupEnabled int
	if err := conn.QueryRowContext(ctx, `SELECT enabled FROM egress_proxy_groups WHERE id = ?`, groupID).Scan(&groupEnabled); errors.Is(err, sql.ErrNoRows) {
		return EgressProxyGroupSelection{}, ErrEgressProxyGroupNotFound
	} else if err != nil {
		return EgressProxyGroupSelection{}, err
	}
	if groupEnabled == 0 {
		return EgressProxyGroupSelection{}, ErrNoAvailableEgressProxy
	}
	nowText := formatSQLiteUTC(now)
	if _, err := conn.ExecContext(ctx, `
		UPDATE egress_proxy_group_members
		SET consecutive_failures = 0, circuit_open_until = NULL, current_weight = 0
		WHERE group_id = ? AND circuit_open_until IS NOT NULL
			AND strftime('%s', circuit_open_until) <= strftime('%s', ?)
	`, groupID, nowText); err != nil {
		return EgressProxyGroupSelection{}, err
	}
	var priority sql.NullInt64
	if err := conn.QueryRowContext(ctx, `
		SELECT MIN(m.priority)
		FROM egress_proxy_group_members m
		JOIN egress_proxies p ON p.id = m.proxy_id
		WHERE m.group_id = ? AND m.enabled = 1 AND p.enabled = 1 AND m.circuit_open_until IS NULL
	`, groupID).Scan(&priority); err != nil {
		return EgressProxyGroupSelection{}, err
	}
	if !priority.Valid {
		return EgressProxyGroupSelection{}, ErrNoAvailableEgressProxy
	}
	rows, err := conn.QueryContext(ctx, `
		SELECT m.proxy_id, m.weight, m.current_weight,
			p.name, p.protocol, p.host, p.port,
			CASE WHEN p.credential_ciphertext = '' THEN 0 ELSE 1 END
		FROM egress_proxy_group_members m
		JOIN egress_proxies p ON p.id = m.proxy_id
		WHERE m.group_id = ? AND m.priority = ? AND m.enabled = 1 AND p.enabled = 1
			AND m.circuit_open_until IS NULL
		ORDER BY m.proxy_id
	`, groupID, priority.Int64)
	if err != nil {
		return EgressProxyGroupSelection{}, err
	}
	candidates := make([]egress.WeightedCandidate, 0)
	summaries := make(map[string]EgressProxySummary)
	for rows.Next() {
		var candidate egress.WeightedCandidate
		var summary EgressProxySummary
		var protocol string
		var credentialsConfigured int
		if err := rows.Scan(&candidate.ID, &candidate.Weight, &candidate.CurrentWeight,
			&summary.Name, &protocol, &summary.Host, &summary.Port, &credentialsConfigured); err != nil {
			_ = rows.Close()
			return EgressProxyGroupSelection{}, err
		}
		parsedProtocol, err := egress.ParseUpstreamProtocol(protocol)
		if err != nil {
			_ = rows.Close()
			return EgressProxyGroupSelection{}, err
		}
		summary.ID = candidate.ID
		summary.Protocol = parsedProtocol
		summary.Enabled = true
		summary.CredentialsConfigured = credentialsConfigured != 0
		candidates = append(candidates, candidate)
		summaries[candidate.ID] = summary
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return EgressProxyGroupSelection{}, err
	}
	if err := rows.Close(); err != nil {
		return EgressProxyGroupSelection{}, err
	}
	selectedID, next, err := egress.SelectSmoothWeighted(candidates)
	if errors.Is(err, egress.ErrNoWeightedCandidate) {
		return EgressProxyGroupSelection{}, ErrNoAvailableEgressProxy
	}
	if err != nil {
		return EgressProxyGroupSelection{}, err
	}
	for _, candidate := range next {
		if candidate.ID == selectedID {
			_, err = conn.ExecContext(ctx, `
				UPDATE egress_proxy_group_members
				SET current_weight = ?, last_selected_at = ?
				WHERE group_id = ? AND proxy_id = ?
			`, candidate.CurrentWeight, nowText, groupID, candidate.ID)
		} else {
			_, err = conn.ExecContext(ctx, `
				UPDATE egress_proxy_group_members SET current_weight = ?
				WHERE group_id = ? AND proxy_id = ?
			`, candidate.CurrentWeight, groupID, candidate.ID)
		}
		if err != nil {
			return EgressProxyGroupSelection{}, err
		}
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return EgressProxyGroupSelection{}, err
	}
	committed = true
	selectedWeight := 0
	for _, candidate := range candidates {
		if candidate.ID == selectedID {
			selectedWeight = candidate.Weight
			break
		}
	}
	return EgressProxyGroupSelection{
		GroupID: groupID, ProxyID: selectedID, Priority: int(priority.Int64),
		Weight: selectedWeight, Proxy: summaries[selectedID], SelectedAt: now,
	}, nil
}

// RecordEgressProxyGroupMemberResult updates a member circuit. Successful
// attempts reset the circuit. Once a failure opens a circuit, late failures do
// not extend its cooling window.
func (db *DB) RecordEgressProxyGroupMemberResult(ctx context.Context, groupID, proxyID string, success bool, now time.Time) (EgressProxyGroupMemberHealth, error) {
	groupID, proxyID = strings.TrimSpace(groupID), strings.TrimSpace(proxyID)
	now = now.UTC()
	conn, err := db.Conn(ctx)
	if err != nil {
		return EgressProxyGroupMemberHealth{}, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return EgressProxyGroupMemberHealth{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	var threshold, cooldown int
	if err := conn.QueryRowContext(ctx, `SELECT failure_threshold, cooldown_seconds FROM egress_proxy_groups WHERE id = ?`, groupID).Scan(&threshold, &cooldown); errors.Is(err, sql.ErrNoRows) {
		return EgressProxyGroupMemberHealth{}, ErrEgressProxyGroupNotFound
	} else if err != nil {
		return EgressProxyGroupMemberHealth{}, err
	}
	var failures int
	var circuitOpenUntil, lastFailureAt, lastSuccessAt sql.NullString
	if err := conn.QueryRowContext(ctx, `
		SELECT consecutive_failures, circuit_open_until, last_failure_at, last_success_at
		FROM egress_proxy_group_members WHERE group_id = ? AND proxy_id = ?
	`, groupID, proxyID).Scan(&failures, &circuitOpenUntil, &lastFailureAt, &lastSuccessAt); errors.Is(err, sql.ErrNoRows) {
		return EgressProxyGroupMemberHealth{}, ErrEgressProxyGroupMemberNotFound
	} else if err != nil {
		return EgressProxyGroupMemberHealth{}, err
	}
	nowText := formatSQLiteUTC(now)
	if success {
		failures = 0
		circuitOpenUntil = sql.NullString{}
		lastSuccessAt = sql.NullString{String: nowText, Valid: true}
		if _, err := conn.ExecContext(ctx, `
			UPDATE egress_proxy_group_members
			SET consecutive_failures = 0, circuit_open_until = NULL, last_success_at = ?
			WHERE group_id = ? AND proxy_id = ?
		`, nowText, groupID, proxyID); err != nil {
			return EgressProxyGroupMemberHealth{}, err
		}
	} else {
		existingOpen := parseNullableDBTime(circuitOpenUntil)
		if existingOpen == nil || !now.Before(*existingOpen) {
			failures++
			lastFailureAt = sql.NullString{String: nowText, Valid: true}
			if failures >= threshold {
				openUntil := now.Add(time.Duration(cooldown) * time.Second)
				circuitOpenUntil = sql.NullString{String: formatSQLiteUTC(openUntil), Valid: true}
				if _, err := conn.ExecContext(ctx, `
					UPDATE egress_proxy_group_members
					SET consecutive_failures = ?, circuit_open_until = ?, last_failure_at = ?, current_weight = 0
					WHERE group_id = ? AND proxy_id = ?
				`, failures, circuitOpenUntil.String, nowText, groupID, proxyID); err != nil {
					return EgressProxyGroupMemberHealth{}, err
				}
			} else if _, err := conn.ExecContext(ctx, `
				UPDATE egress_proxy_group_members
				SET consecutive_failures = ?, circuit_open_until = NULL, last_failure_at = ?
				WHERE group_id = ? AND proxy_id = ?
			`, failures, nowText, groupID, proxyID); err != nil {
				return EgressProxyGroupMemberHealth{}, err
			}
		}
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return EgressProxyGroupMemberHealth{}, err
	}
	committed = true
	return EgressProxyGroupMemberHealth{
		GroupID: groupID, ProxyID: proxyID, ConsecutiveFailures: failures,
		CircuitOpenUntil: parseNullableDBTime(circuitOpenUntil),
		LastFailureAt:    parseNullableDBTime(lastFailureAt), LastSuccessAt: parseNullableDBTime(lastSuccessAt),
	}, nil
}
