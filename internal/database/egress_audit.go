package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/egress"
	containerruntime "cyberstrike-ai/internal/runtime/container"
)

const createConversationEgressAuditEventsTable = `
CREATE TABLE IF NOT EXISTS egress_audit_events (
	id TEXT PRIMARY KEY,
	event_key TEXT NOT NULL UNIQUE,
	recorded_at DATETIME NOT NULL,
	occurred_at DATETIME NOT NULL,
	category TEXT NOT NULL,
	event_type TEXT NOT NULL,
	conversation_id TEXT NOT NULL,
	conversation_title TEXT NOT NULL DEFAULT '',
	container_id TEXT NOT NULL DEFAULT '',
	agent_id TEXT NOT NULL DEFAULT '',
	runtime_generation INTEGER NOT NULL DEFAULT 0,
	snapshot_id TEXT NOT NULL DEFAULT '',
	snapshot_sha256 TEXT NOT NULL DEFAULT '',
	domain TEXT NOT NULL DEFAULT '',
	resolved_ips_json TEXT NOT NULL DEFAULT '[]',
	connected_ip TEXT NOT NULL DEFAULT '',
	port INTEGER NOT NULL DEFAULT 0,
	decision TEXT NOT NULL DEFAULT '',
	result TEXT NOT NULL DEFAULT '',
	rule_id TEXT NOT NULL DEFAULT '',
	reason TEXT NOT NULL DEFAULT '',
	upstream_route_id TEXT NOT NULL DEFAULT '',
	method TEXT NOT NULL DEFAULT '',
	path TEXT NOT NULL DEFAULT '',
	http_status INTEGER NOT NULL DEFAULT 0,
	outcome TEXT NOT NULL DEFAULT '',
	latency_ms INTEGER NOT NULL DEFAULT 0,
	bytes_up INTEGER NOT NULL DEFAULT 0,
	bytes_down INTEGER NOT NULL DEFAULT 0,
	lifecycle_operation TEXT NOT NULL DEFAULT '',
	lifecycle_state TEXT NOT NULL DEFAULT '',
	message TEXT NOT NULL DEFAULT '',
	CHECK (category IN ('network', 'lifecycle')),
	CHECK (runtime_generation >= 0),
	CHECK (port >= 0 AND port <= 65535),
	CHECK (http_status >= 0 AND http_status <= 999),
	CHECK (latency_ms >= 0 AND bytes_up >= 0 AND bytes_down >= 0)
);`

const createEgressAuditRuntimeCreatedTrigger = `
CREATE TRIGGER IF NOT EXISTS trg_egress_audit_runtime_created
AFTER UPDATE OF initialization_status ON conversation_container_runtimes
WHEN NEW.initialization_status = 'created' AND OLD.initialization_status <> 'created'
BEGIN
	INSERT OR IGNORE INTO egress_audit_events (
		id, event_key, recorded_at, occurred_at, category, event_type,
		conversation_id, conversation_title, container_id, agent_id, runtime_generation,
		snapshot_id, snapshot_sha256, result, lifecycle_operation, lifecycle_state, message
	) VALUES (
		lower(hex(randomblob(16))),
		'lifecycle:' || NEW.conversation_id || ':create:' || NEW.runtime_generation || ':' || COALESCE(NEW.completed_at, NEW.updated_at),
		NEW.updated_at, COALESCE(NEW.completed_at, NEW.updated_at), 'lifecycle', 'create',
		NEW.conversation_id, COALESCE((SELECT title FROM conversations WHERE id = NEW.conversation_id), ''),
		NEW.provider_id, 'container-agent', NEW.runtime_generation,
		COALESCE(json_extract(NEW.spec_json, '$.EgressGateway.BoundarySnapshot.ID'), ''),
		COALESCE(json_extract(NEW.spec_json, '$.EgressGateway.BoundarySnapshot.SHA256'), ''),
		'success', 'create', 'idle', 'container runtime created'
	);
END;`

const createEgressAuditRuntimeCreateFailedTrigger = `
CREATE TRIGGER IF NOT EXISTS trg_egress_audit_runtime_create_failed
AFTER UPDATE OF initialization_status ON conversation_container_runtimes
WHEN NEW.initialization_status = 'failed' AND OLD.initialization_status <> 'failed'
BEGIN
	INSERT OR IGNORE INTO egress_audit_events (
		id, event_key, recorded_at, occurred_at, category, event_type,
		conversation_id, conversation_title, container_id, agent_id, runtime_generation,
		snapshot_id, snapshot_sha256, result, lifecycle_operation, lifecycle_state, message
	) VALUES (
		lower(hex(randomblob(16))),
		'lifecycle:' || NEW.conversation_id || ':create-failed:' || COALESCE(NEW.completed_at, NEW.updated_at),
		NEW.updated_at, COALESCE(NEW.completed_at, NEW.updated_at), 'lifecycle', 'create',
		NEW.conversation_id, COALESCE((SELECT title FROM conversations WHERE id = NEW.conversation_id), ''),
		NEW.provider_id, 'container-agent', NEW.runtime_generation,
		COALESCE(json_extract(NEW.spec_json, '$.EgressGateway.BoundarySnapshot.ID'), ''),
		COALESCE(json_extract(NEW.spec_json, '$.EgressGateway.BoundarySnapshot.SHA256'), ''),
		'failure', 'create', 'failed', 'container runtime creation failed'
	);
END;`

const createEgressAuditLifecycleCompletedTrigger = `
CREATE TRIGGER IF NOT EXISTS trg_egress_audit_lifecycle_completed
AFTER UPDATE OF lifecycle_state ON conversation_container_runtimes
WHEN OLD.lifecycle_state = 'in_progress' AND NEW.lifecycle_state IN ('idle', 'failed')
BEGIN
	INSERT OR IGNORE INTO egress_audit_events (
		id, event_key, recorded_at, occurred_at, category, event_type,
		conversation_id, conversation_title, container_id, agent_id, runtime_generation,
		snapshot_id, snapshot_sha256, result, lifecycle_operation, lifecycle_state, message
	) VALUES (
		lower(hex(randomblob(16))),
		'lifecycle:' || NEW.conversation_id || ':' || NEW.lifecycle_operation || ':' || NEW.runtime_generation || ':' || COALESCE(NEW.lifecycle_completed_at, NEW.updated_at),
		NEW.updated_at, COALESCE(NEW.lifecycle_completed_at, NEW.updated_at), 'lifecycle', NEW.lifecycle_operation,
		NEW.conversation_id, COALESCE((SELECT title FROM conversations WHERE id = NEW.conversation_id), ''),
		NEW.provider_id, 'container-agent', NEW.runtime_generation,
		COALESCE(json_extract(NEW.spec_json, '$.EgressGateway.BoundarySnapshot.ID'), ''),
		COALESCE(json_extract(NEW.spec_json, '$.EgressGateway.BoundarySnapshot.SHA256'), ''),
		CASE WHEN NEW.lifecycle_state = 'idle' THEN 'success' ELSE 'failure' END,
		NEW.lifecycle_operation, NEW.lifecycle_state,
		CASE WHEN NEW.lifecycle_state = 'idle' THEN 'container lifecycle completed' ELSE 'container lifecycle failed' END
	);
END;`

const createEgressAuditLifecycleDeletedTrigger = `
CREATE TRIGGER IF NOT EXISTS trg_egress_audit_lifecycle_deleted
BEFORE DELETE ON conversation_container_runtimes
WHEN OLD.initialization_status = 'created' AND OLD.lifecycle_operation = 'delete' AND OLD.lifecycle_state = 'in_progress'
BEGIN
	INSERT OR IGNORE INTO egress_audit_events (
		id, event_key, recorded_at, occurred_at, category, event_type,
		conversation_id, conversation_title, container_id, agent_id, runtime_generation,
		snapshot_id, snapshot_sha256, result, lifecycle_operation, lifecycle_state, message
	) VALUES (
		lower(hex(randomblob(16))),
		'lifecycle:' || OLD.conversation_id || ':delete:' || OLD.runtime_generation || ':' || COALESCE(OLD.lifecycle_started_at, OLD.updated_at),
		CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'lifecycle', 'delete',
		OLD.conversation_id, COALESCE((SELECT title FROM conversations WHERE id = OLD.conversation_id), ''),
		OLD.provider_id, 'container-agent', OLD.runtime_generation,
		COALESCE(json_extract(OLD.spec_json, '$.EgressGateway.BoundarySnapshot.ID'), ''),
		COALESCE(json_extract(OLD.spec_json, '$.EgressGateway.BoundarySnapshot.SHA256'), ''),
		'success', 'delete', 'idle', 'container runtime deleted'
	);
END;`

// Existing durable runtimes predate the persistent audit table. Seed one
// deterministic reconciliation event per conversation so an upgraded system
// never presents an empty lifecycle history for resources that already exist.
// The event key deliberately excludes updated_at: reopening the same database
// must not manufacture a new audit event on every application start.
const backfillEgressAuditRuntimeBaseline = `
INSERT OR IGNORE INTO egress_audit_events (
	id, event_key, recorded_at, occurred_at, category, event_type,
	conversation_id, conversation_title, container_id, agent_id, runtime_generation,
	snapshot_id, snapshot_sha256, result, lifecycle_operation, lifecycle_state, message
)
SELECT
	lower(hex(randomblob(16))),
	'lifecycle:' || r.conversation_id || ':baseline',
	r.updated_at, COALESCE(r.completed_at, r.updated_at), 'lifecycle', 'reconcile',
	r.conversation_id, COALESCE(c.title, ''), r.provider_id, 'container-agent', r.runtime_generation,
	COALESCE(json_extract(r.spec_json, '$.EgressGateway.BoundarySnapshot.ID'), ''),
	COALESCE(json_extract(r.spec_json, '$.EgressGateway.BoundarySnapshot.SHA256'), ''),
	CASE WHEN r.initialization_status = 'failed' OR r.lifecycle_state = 'failed' THEN 'failure' ELSE 'success' END,
	'reconcile',
	CASE WHEN r.initialization_status = 'failed' THEN 'failed' ELSE r.lifecycle_state END,
	'container runtime audit baseline established'
FROM conversation_container_runtimes r
LEFT JOIN conversations c ON c.id = r.conversation_id
WHERE r.initialization_status IN ('created', 'failed')
	AND NOT EXISTS (
		SELECT 1 FROM egress_audit_events existing
		WHERE existing.conversation_id = r.conversation_id AND existing.category = 'lifecycle'
	);`

// EgressAuditEvent is the credential-free persistent projection shown by the
// container audit page and export APIs. It intentionally has no raw headers,
// bodies, query strings, environment, command, mount, or provider error field.
type EgressAuditEvent struct {
	ID                 string    `json:"id"`
	RecordedAt         time.Time `json:"recordedAt"`
	OccurredAt         time.Time `json:"occurredAt"`
	Category           string    `json:"category"`
	EventType          string    `json:"eventType"`
	ConversationID     string    `json:"conversationId"`
	ConversationTitle  string    `json:"conversationTitle"`
	ContainerID        string    `json:"containerId,omitempty"`
	AgentID            string    `json:"agentId,omitempty"`
	RuntimeGeneration  int       `json:"runtimeGeneration"`
	SnapshotID         string    `json:"snapshotId,omitempty"`
	SnapshotSHA256     string    `json:"snapshotSha256,omitempty"`
	Domain             string    `json:"domain,omitempty"`
	ResolvedIPs        []string  `json:"resolvedIps,omitempty"`
	ConnectedIP        string    `json:"connectedIp,omitempty"`
	Port               int       `json:"port,omitempty"`
	Decision           string    `json:"decision,omitempty"`
	Result             string    `json:"result,omitempty"`
	RuleID             string    `json:"ruleId,omitempty"`
	Reason             string    `json:"reason,omitempty"`
	UpstreamRouteID    string    `json:"upstreamRouteId,omitempty"`
	Method             string    `json:"method,omitempty"`
	Path               string    `json:"path,omitempty"`
	HTTPStatus         int       `json:"httpStatus,omitempty"`
	Outcome            string    `json:"outcome,omitempty"`
	LatencyMS          int64     `json:"latencyMs"`
	BytesUp            int64     `json:"bytesUp,omitempty"`
	BytesDown          int64     `json:"bytesDown,omitempty"`
	LifecycleOperation string    `json:"lifecycleOperation,omitempty"`
	LifecycleState     string    `json:"lifecycleState,omitempty"`
	Message            string    `json:"message,omitempty"`
}

type EgressAuditFilter struct {
	ConversationID string
	Category       string
	EventType      string
	Decision       string
	Query          string
	Since          *time.Time
	Until          *time.Time
	Limit          int
	Offset         int
	UserID         string
	Scope          string
}

type EgressAuditSummary struct {
	Total     int `json:"total"`
	Network   int `json:"network"`
	Lifecycle int `json:"lifecycle"`
	Blocked   int `json:"blocked"`
	Failures  int `json:"failures"`
}

type EgressAuditRuntimeTarget struct {
	Record            containerruntime.InitializationRecord
	ConversationTitle string
}

var egressAuditCategories = map[string]struct{}{"all": {}, "network": {}, "lifecycle": {}}
var egressAuditEventTypes = map[string]struct{}{
	"all": {}, "dns": {}, "http": {}, "connect": {}, "create": {}, "start": {}, "stop": {}, "rebuild": {}, "delete": {}, "reconcile": {},
}
var egressAuditDecisions = map[string]struct{}{"all": {}, "allowed": {}, "blocked": {}, "success": {}, "failure": {}}

func normalizeEgressAuditFilterValue(raw string, allowed map[string]struct{}) (string, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		value = "all"
	}
	_, ok := allowed[value]
	return value, ok
}

func NormalizeEgressAuditCategory(raw string) (string, bool) {
	return normalizeEgressAuditFilterValue(raw, egressAuditCategories)
}

func NormalizeEgressAuditEventType(raw string) (string, bool) {
	return normalizeEgressAuditFilterValue(raw, egressAuditEventTypes)
}

func NormalizeEgressAuditDecision(raw string) (string, bool) {
	return normalizeEgressAuditFilterValue(raw, egressAuditDecisions)
}

func (db *DB) initEgressAuditTables() error {
	statements := []string{
		createConversationEgressAuditEventsTable,
		`CREATE INDEX IF NOT EXISTS idx_egress_audit_conversation_time ON egress_audit_events(conversation_id, occurred_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_egress_audit_category_type_time ON egress_audit_events(category, event_type, occurred_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_egress_audit_decision_time ON egress_audit_events(decision, result, occurred_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_egress_audit_domain_time ON egress_audit_events(domain, occurred_at DESC)`,
		createEgressAuditRuntimeCreatedTrigger,
		createEgressAuditRuntimeCreateFailedTrigger,
		createEgressAuditLifecycleCompletedTrigger,
		createEgressAuditLifecycleDeletedTrigger,
		backfillEgressAuditRuntimeBaseline,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("initialize egress audit schema: %w", err)
		}
	}
	return nil
}

func (db *DB) AppendEgressNetworkAuditEvent(ctx context.Context, target EgressAuditRuntimeTarget, event egress.ActivityEvent) (bool, error) {
	if ctx == nil {
		return false, errors.New("egress audit context is required")
	}
	record := target.Record
	if strings.TrimSpace(record.ConversationID) == "" || strings.TrimSpace(record.ProviderID) == "" || event.Timestamp.IsZero() ||
		event.Event != egress.ActivityEventName || (event.RequestType != egress.ActivityRequestDNS && event.RequestType != egress.ActivityRequestHTTP && event.RequestType != egress.ActivityRequestCONNECT) ||
		(event.Decision != egress.ActivityDecisionAllowed && event.Decision != egress.ActivityDecisionBlocked) {
		return false, errors.New("invalid egress network audit event")
	}
	resolvedJSON, err := json.Marshal(event.ResolvedIPs)
	if err != nil {
		return false, fmt.Errorf("encode egress audit resolved addresses: %w", err)
	}
	keyPayload := struct {
		ConversationID    string
		ContainerID       string
		RuntimeGeneration int
		Event             egress.ActivityEvent
	}{record.ConversationID, record.ProviderID, record.RuntimeGeneration, event}
	encoded, err := json.Marshal(keyPayload)
	if err != nil {
		return false, fmt.Errorf("encode egress audit event key: %w", err)
	}
	digest := sha256.Sum256(encoded)
	eventKey := "network:" + hex.EncodeToString(digest[:])
	id := "ea-" + hex.EncodeToString(digest[:16])
	now := time.Now().UTC()
	result, err := db.ExecContext(ctx, `
		INSERT OR IGNORE INTO egress_audit_events (
			id, event_key, recorded_at, occurred_at, category, event_type,
			conversation_id, conversation_title, container_id, agent_id, runtime_generation,
			snapshot_id, snapshot_sha256, domain, resolved_ips_json, connected_ip, port,
			decision, rule_id, reason, upstream_route_id, method, path, http_status,
			outcome, latency_ms, bytes_up, bytes_down, message
		) VALUES (?, ?, ?, ?, 'network', ?, ?, ?, ?, 'container-agent', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, eventKey, formatSQLiteUTC(now), formatSQLiteUTC(event.Timestamp.UTC()), event.RequestType,
		record.ConversationID, truncateEgressAuditText(target.ConversationTitle, 512), record.ProviderID, record.RuntimeGeneration,
		event.SnapshotID, event.SnapshotSHA256, event.Domain, string(resolvedJSON), event.ConnectedIP, event.Port,
		event.Decision, event.RuleID, event.Reason, event.UpstreamRouteID, event.Method, event.Path, event.HTTPStatus,
		event.Outcome, event.LatencyMS, event.BytesUp, event.BytesDown, "gateway network decision")
	if err != nil {
		return false, fmt.Errorf("append egress network audit event: %w", err)
	}
	rows, _ := result.RowsAffected()
	return rows == 1, nil
}

func truncateEgressAuditText(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len(value) > maximum {
		value = value[:maximum]
	}
	return value
}

func (db *DB) ListRunningEgressAuditRuntimeTargets(ctx context.Context) ([]EgressAuditRuntimeTarget, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT r.conversation_id, COALESCE(c.title, '')
		FROM conversation_container_runtimes r
		JOIN conversations c ON c.id = r.conversation_id
		WHERE r.initialization_status = ? AND r.runtime_status = ?
			AND json_type(r.spec_json, '$.EgressGateway') IS NOT NULL
			AND json_type(r.spec_json, '$.EgressGateway') <> 'null'
		ORDER BY r.conversation_id
	`, containerruntime.InitializationCreated, containerruntime.StatusRunning)
	if err != nil {
		return nil, fmt.Errorf("list running egress audit targets: %w", err)
	}
	defer rows.Close()
	targets := make([]EgressAuditRuntimeTarget, 0)
	for rows.Next() {
		var conversationID, title string
		if err := rows.Scan(&conversationID, &title); err != nil {
			return nil, err
		}
		record, err := db.GetContainerInitialization(ctx, conversationID)
		if err != nil {
			return nil, err
		}
		targets = append(targets, EgressAuditRuntimeTarget{Record: record, ConversationTitle: title})
	}
	return targets, rows.Err()
}

func buildEgressAuditWhere(filter EgressAuditFilter) (string, []interface{}, error) {
	category, ok := NormalizeEgressAuditCategory(filter.Category)
	if !ok {
		return "", nil, errors.New("invalid egress audit category")
	}
	eventType, ok := NormalizeEgressAuditEventType(filter.EventType)
	if !ok {
		return "", nil, errors.New("invalid egress audit event type")
	}
	decision, ok := NormalizeEgressAuditDecision(filter.Decision)
	if !ok {
		return "", nil, errors.New("invalid egress audit decision")
	}
	where := " WHERE 1=1"
	args := make([]interface{}, 0, 16)
	if conversationID := strings.TrimSpace(filter.ConversationID); conversationID != "" {
		where += " AND e.conversation_id = ?"
		args = append(args, conversationID)
	}
	if category != "all" {
		where += " AND e.category = ?"
		args = append(args, category)
	}
	if eventType != "all" {
		where += " AND e.event_type = ?"
		args = append(args, eventType)
	}
	if decision != "all" {
		where += " AND (e.decision = ? OR e.result = ?)"
		args = append(args, decision, decision)
	}
	if filter.Since != nil {
		where += " AND " + sqliteEpochGE("e.occurred_at", ">=")
		args = append(args, formatSQLiteUTC(filter.Since.UTC()))
	}
	if filter.Until != nil {
		where += " AND " + sqliteEpochGE("e.occurred_at", "<=")
		args = append(args, formatSQLiteUTC(filter.Until.UTC()))
	}
	if query := escapeContainerRuntimeSearch(filter.Query); query != "" {
		pattern := "%" + query + "%"
		where += ` AND (e.conversation_title LIKE ? ESCAPE '\' OR e.conversation_id LIKE ? ESCAPE '\'
			OR e.domain LIKE ? ESCAPE '\' OR e.connected_ip LIKE ? ESCAPE '\'
			OR e.resolved_ips_json LIKE ? ESCAPE '\' OR e.rule_id LIKE ? ESCAPE '\'
			OR e.reason LIKE ? ESCAPE '\' OR e.upstream_route_id LIKE ? ESCAPE '\'
			OR e.lifecycle_operation LIKE ? ESCAPE '\' OR e.message LIKE ? ESCAPE '\')`
		for i := 0; i < 10; i++ {
			args = append(args, pattern)
		}
	}
	where, args = appendConversationAccessFilter(where, args, filter.UserID, filter.Scope, "c")
	return where, args, nil
}

const egressAuditSelect = `
	SELECT e.id, e.recorded_at, e.occurred_at, e.category, e.event_type,
		e.conversation_id, e.conversation_title, e.container_id, e.agent_id, e.runtime_generation,
		e.snapshot_id, e.snapshot_sha256, e.domain, e.resolved_ips_json, e.connected_ip, e.port,
		e.decision, e.result, e.rule_id, e.reason, e.upstream_route_id, e.method, e.path,
		e.http_status, e.outcome, e.latency_ms, e.bytes_up, e.bytes_down,
		e.lifecycle_operation, e.lifecycle_state, e.message
	FROM egress_audit_events e
	LEFT JOIN conversations c ON c.id = e.conversation_id`

func (db *DB) ListEgressAuditEvents(ctx context.Context, filter EgressAuditFilter) ([]EgressAuditEvent, error) {
	where, args, err := buildEgressAuditWhere(filter)
	if err != nil {
		return nil, err
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 5000 {
		limit = 5000
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, egressAuditSelect+where+` ORDER BY e.occurred_at DESC, e.id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("list egress audit events: %w", err)
	}
	defer rows.Close()
	result := make([]EgressAuditEvent, 0, limit)
	for rows.Next() {
		event, err := scanEgressAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (db *DB) CountEgressAuditEvents(ctx context.Context, filter EgressAuditFilter) (int, error) {
	where, args, err := buildEgressAuditWhere(filter)
	if err != nil {
		return 0, err
	}
	var count int
	err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM egress_audit_events e LEFT JOIN conversations c ON c.id = e.conversation_id`+where, args...).Scan(&count)
	return count, err
}

func (db *DB) SummarizeEgressAuditEvents(ctx context.Context, filter EgressAuditFilter) (EgressAuditSummary, error) {
	var summary EgressAuditSummary
	where, args, err := buildEgressAuditWhere(filter)
	if err != nil {
		return summary, err
	}
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*),
			COALESCE(SUM(CASE WHEN e.category = 'network' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN e.category = 'lifecycle' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN e.decision = 'blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN e.result = 'failure' THEN 1 ELSE 0 END), 0)
		FROM egress_audit_events e
		LEFT JOIN conversations c ON c.id = e.conversation_id`+where, args...).Scan(
		&summary.Total, &summary.Network, &summary.Lifecycle, &summary.Blocked, &summary.Failures)
	return summary, err
}

type egressAuditScanner interface{ Scan(...interface{}) error }

func scanEgressAuditEvent(scanner egressAuditScanner) (EgressAuditEvent, error) {
	var event EgressAuditEvent
	var recordedAt, occurredAt, resolvedJSON string
	err := scanner.Scan(
		&event.ID, &recordedAt, &occurredAt, &event.Category, &event.EventType,
		&event.ConversationID, &event.ConversationTitle, &event.ContainerID, &event.AgentID, &event.RuntimeGeneration,
		&event.SnapshotID, &event.SnapshotSHA256, &event.Domain, &resolvedJSON, &event.ConnectedIP, &event.Port,
		&event.Decision, &event.Result, &event.RuleID, &event.Reason, &event.UpstreamRouteID, &event.Method, &event.Path,
		&event.HTTPStatus, &event.Outcome, &event.LatencyMS, &event.BytesUp, &event.BytesDown,
		&event.LifecycleOperation, &event.LifecycleState, &event.Message,
	)
	if err != nil {
		return event, err
	}
	event.RecordedAt, err = ParseRFC3339Time(recordedAt)
	if err != nil {
		return event, err
	}
	event.OccurredAt, err = ParseRFC3339Time(occurredAt)
	if err != nil {
		return event, err
	}
	if resolvedJSON != "" {
		if err := json.Unmarshal([]byte(resolvedJSON), &event.ResolvedIPs); err != nil {
			return event, fmt.Errorf("decode egress audit resolved addresses: %w", err)
		}
	}
	return event, nil
}

func (db *DB) GetEgressAuditEvent(ctx context.Context, id string, userID string, scope string) (EgressAuditEvent, error) {
	filter := EgressAuditFilter{UserID: userID, Scope: scope}
	where, args, err := buildEgressAuditWhere(filter)
	if err != nil {
		return EgressAuditEvent{}, err
	}
	where += " AND e.id = ?"
	args = append(args, strings.TrimSpace(id))
	event, err := scanEgressAuditEvent(db.QueryRowContext(ctx, egressAuditSelect+where, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return EgressAuditEvent{}, sql.ErrNoRows
	}
	return event, err
}
