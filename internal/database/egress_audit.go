package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/boundary"
	"cyberstrike-ai/internal/egress"
	containerruntime "cyberstrike-ai/internal/runtime/container"
)

const maxEgressAuditSafeInteger int64 = 1<<53 - 1

const egressAuditGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

var egressAuditCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
var egressAuditHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var ErrEgressAuditIntegrity = errors.New("egress audit integrity verification failed")

const createConversationEgressAuditEventsTable = `
CREATE TABLE IF NOT EXISTS egress_audit_events (
	id TEXT PRIMARY KEY,
	event_key TEXT NOT NULL UNIQUE,
	chain_sequence INTEGER NOT NULL DEFAULT 0,
	previous_hash TEXT NOT NULL DEFAULT '',
	event_hash TEXT NOT NULL DEFAULT '',
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
	CHECK (latency_ms >= 0 AND bytes_up >= 0 AND bytes_down >= 0),
	CHECK ((chain_sequence = 0 AND previous_hash = '' AND event_hash = '') OR
		(chain_sequence > 0 AND length(previous_hash) = 64 AND length(event_hash) = 64))
);`

const createEgressAuditChainHeadsTable = `
CREATE TABLE IF NOT EXISTS egress_audit_chain_heads (
	conversation_id TEXT PRIMARY KEY,
	last_sequence INTEGER NOT NULL,
	last_hash TEXT NOT NULL,
	event_count INTEGER NOT NULL,
	updated_at DATETIME NOT NULL,
	CHECK (last_sequence > 0),
	CHECK (event_count > 0),
	CHECK (length(last_hash) = 64)
);`

const createEgressAuditRejectPresealedInsertTrigger = `
CREATE TRIGGER IF NOT EXISTS trg_egress_audit_reject_presealed_insert
BEFORE INSERT ON egress_audit_events
WHEN NEW.chain_sequence <> 0 OR NEW.previous_hash <> '' OR NEW.event_hash <> ''
BEGIN
	SELECT RAISE(ABORT, 'egress audit chain fields are database managed');
END;`

const createEgressAuditAppendOnlyUpdateTrigger = `
CREATE TRIGGER IF NOT EXISTS trg_egress_audit_append_only_update
BEFORE UPDATE ON egress_audit_events
WHEN OLD.event_hash <> ''
BEGIN
	SELECT RAISE(ABORT, 'egress audit events are append-only');
END;`

const createEgressAuditAppendOnlyDeleteTrigger = `
CREATE TRIGGER IF NOT EXISTS trg_egress_audit_append_only_delete
BEFORE DELETE ON egress_audit_events
BEGIN
	SELECT RAISE(ABORT, 'egress audit events are append-only');
END;`

func createEgressAuditSealInsertTrigger() string {
	return fmt.Sprintf(`
CREATE TRIGGER IF NOT EXISTS trg_egress_audit_seal_insert
AFTER INSERT ON egress_audit_events
WHEN NEW.chain_sequence = 0 AND NEW.previous_hash = '' AND NEW.event_hash = ''
BEGIN
	UPDATE egress_audit_events
	SET chain_sequence = COALESCE((SELECT last_sequence FROM egress_audit_chain_heads WHERE conversation_id = NEW.conversation_id), 0) + 1,
		previous_hash = COALESCE((SELECT last_hash FROM egress_audit_chain_heads WHERE conversation_id = NEW.conversation_id), '%s'),
		event_hash = cyberstrike_egress_audit_hash(
			COALESCE((SELECT last_hash FROM egress_audit_chain_heads WHERE conversation_id = NEW.conversation_id), '%s'),
			CAST(COALESCE((SELECT last_sequence FROM egress_audit_chain_heads WHERE conversation_id = NEW.conversation_id), 0) + 1 AS TEXT),
			CAST(NEW.id AS TEXT), CAST(NEW.event_key AS TEXT), CAST(NEW.recorded_at AS TEXT), CAST(NEW.occurred_at AS TEXT),
			CAST(NEW.category AS TEXT), CAST(NEW.event_type AS TEXT), CAST(NEW.conversation_id AS TEXT), CAST(NEW.conversation_title AS TEXT),
			CAST(NEW.container_id AS TEXT), CAST(NEW.agent_id AS TEXT), CAST(NEW.runtime_generation AS TEXT), CAST(NEW.snapshot_id AS TEXT),
			CAST(NEW.snapshot_sha256 AS TEXT), CAST(NEW.domain AS TEXT), CAST(NEW.resolved_ips_json AS TEXT), CAST(NEW.connected_ip AS TEXT),
			CAST(NEW.port AS TEXT), CAST(NEW.decision AS TEXT), CAST(NEW.result AS TEXT), CAST(NEW.rule_id AS TEXT),
			CAST(NEW.reason AS TEXT), CAST(NEW.upstream_route_id AS TEXT), CAST(NEW.method AS TEXT), CAST(NEW.path AS TEXT),
			CAST(NEW.http_status AS TEXT), CAST(NEW.outcome AS TEXT), CAST(NEW.latency_ms AS TEXT), CAST(NEW.bytes_up AS TEXT),
			CAST(NEW.bytes_down AS TEXT), CAST(NEW.lifecycle_operation AS TEXT), CAST(NEW.lifecycle_state AS TEXT), CAST(NEW.message AS TEXT)
		)
	WHERE id = NEW.id;
	INSERT INTO egress_audit_chain_heads (conversation_id, last_sequence, last_hash, event_count, updated_at)
	SELECT conversation_id, chain_sequence, event_hash, chain_sequence, CURRENT_TIMESTAMP
	FROM egress_audit_events WHERE id = NEW.id
	ON CONFLICT(conversation_id) DO UPDATE SET
		last_sequence = excluded.last_sequence,
		last_hash = excluded.last_hash,
		event_count = excluded.event_count,
		updated_at = excluded.updated_at;
END;`, egressAuditGenesisHash, egressAuditGenesisHash)
}

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
	ChainSequence      int64     `json:"chainSequence"`
	PreviousHash       string    `json:"previousHash"`
	EventHash          string    `json:"eventHash"`
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

type EgressAuditIntegrity struct {
	Status        string    `json:"status"`
	Conversations int       `json:"conversations"`
	Events        int       `json:"events"`
	VerifiedAt    time.Time `json:"verifiedAt"`
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

func egressAuditHashValues(values ...interface{}) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("cyberstrike-egress-audit-chain-v1\x00"))
	for _, value := range values {
		var text string
		switch typed := value.(type) {
		case nil:
			text = ""
		case string:
			text = typed
		case []byte:
			text = string(typed)
		case int64:
			text = strconv.FormatInt(typed, 10)
		case float64:
			text = strconv.FormatFloat(typed, 'g', -1, 64)
		case bool:
			text = strconv.FormatBool(typed)
		default:
			text = fmt.Sprint(typed)
		}
		_, _ = hasher.Write([]byte(strconv.Itoa(len(text))))
		_, _ = hasher.Write([]byte{':'})
		_, _ = hasher.Write([]byte(text))
		_, _ = hasher.Write([]byte{';'})
	}
	return hex.EncodeToString(hasher.Sum(nil))
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
	if _, err := db.Exec(createConversationEgressAuditEventsTable); err != nil {
		return fmt.Errorf("initialize egress audit schema: %w", err)
	}
	for _, column := range []struct {
		name      string
		statement string
	}{
		{"chain_sequence", "ALTER TABLE egress_audit_events ADD COLUMN chain_sequence INTEGER NOT NULL DEFAULT 0"},
		{"previous_hash", "ALTER TABLE egress_audit_events ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''"},
		{"event_hash", "ALTER TABLE egress_audit_events ADD COLUMN event_hash TEXT NOT NULL DEFAULT ''"},
	} {
		if err := db.addColumnIfMissing("egress_audit_events", column.name, column.statement); err != nil {
			return fmt.Errorf("initialize egress audit chain column %s: %w", column.name, err)
		}
	}
	statements := []string{
		createEgressAuditChainHeadsTable,
		`CREATE INDEX IF NOT EXISTS idx_egress_audit_conversation_time ON egress_audit_events(conversation_id, occurred_at DESC)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_audit_conversation_sequence ON egress_audit_events(conversation_id, chain_sequence) WHERE chain_sequence > 0`,
		`CREATE INDEX IF NOT EXISTS idx_egress_audit_category_type_time ON egress_audit_events(category, event_type, occurred_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_egress_audit_decision_time ON egress_audit_events(decision, result, occurred_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_egress_audit_domain_time ON egress_audit_events(domain, occurred_at DESC)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("initialize egress audit schema: %w", err)
		}
	}
	if err := db.initializeEgressAuditChains(context.Background()); err != nil {
		return fmt.Errorf("initialize egress audit chains: %w", err)
	}
	for _, statement := range []string{
		createEgressAuditSealInsertTrigger(),
		createEgressAuditRejectPresealedInsertTrigger,
		createEgressAuditAppendOnlyUpdateTrigger,
		createEgressAuditAppendOnlyDeleteTrigger,
		createEgressAuditRuntimeCreatedTrigger,
		createEgressAuditRuntimeCreateFailedTrigger,
		createEgressAuditLifecycleCompletedTrigger,
		createEgressAuditLifecycleDeletedTrigger,
		backfillEgressAuditRuntimeBaseline,
	} {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("initialize egress audit chain trigger: %w", err)
		}
	}
	return nil
}

func (db *DB) AppendEgressNetworkAuditEvent(ctx context.Context, target EgressAuditRuntimeTarget, event egress.ActivityEvent) (bool, error) {
	if ctx == nil {
		return false, errors.New("egress audit context is required")
	}
	if err := validateEgressNetworkAuditEvent(target, event); err != nil {
		return false, err
	}
	record := target.Record
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
		record.ConversationID, sanitizeEgressAuditDisplayText(target.ConversationTitle, 512), record.ProviderID, record.RuntimeGeneration,
		event.SnapshotID, event.SnapshotSHA256, event.Domain, string(resolvedJSON), event.ConnectedIP, event.Port,
		event.Decision, event.RuleID, event.Reason, event.UpstreamRouteID, event.Method, event.Path, event.HTTPStatus,
		event.Outcome, event.LatencyMS, event.BytesUp, event.BytesDown, "gateway network decision")
	if err != nil {
		return false, fmt.Errorf("append egress network audit event: %w", err)
	}
	rows, _ := result.RowsAffected()
	return rows == 1, nil
}

func validateEgressNetworkAuditEvent(target EgressAuditRuntimeTarget, event egress.ActivityEvent) error {
	invalid := func() error { return errors.New("invalid egress network audit event") }
	record := target.Record
	if !validEgressAuditText(record.ConversationID, 128, false) ||
		!validEgressAuditText(record.ProviderID, 128, false) ||
		record.RuntimeGeneration < 0 || int64(record.RuntimeGeneration) > maxEgressAuditSafeInteger ||
		record.Spec.EgressGateway == nil || record.Spec.EgressGateway.BoundarySnapshot == nil ||
		event.Event != egress.ActivityEventName || event.Timestamp.IsZero() || event.Timestamp.After(time.Now().UTC().Add(5*time.Minute)) ||
		event.SnapshotID != record.Spec.EgressGateway.BoundarySnapshot.ID ||
		event.SnapshotSHA256 != record.Spec.EgressGateway.BoundarySnapshot.SHA256 ||
		!validEgressAuditText(event.SnapshotID, 128, false) || !validEgressAuditText(event.SnapshotSHA256, 128, false) ||
		event.LatencyMS < 0 || event.LatencyMS > maxEgressAuditSafeInteger ||
		event.BytesUp < 0 || event.BytesUp > maxEgressAuditSafeInteger ||
		event.BytesDown < 0 || event.BytesDown > maxEgressAuditSafeInteger || len(event.ResolvedIPs) > 64 ||
		!validEgressAuditCode(event.Outcome, false) || !validEgressAuditCode(event.Reason, true) ||
		!validEgressAuditText(event.RuleID, 256, true) || !validEgressAuditText(event.UpstreamRouteID, 128, true) {
		return invalid()
	}
	normalizedDomain, err := boundary.NormalizeHost(event.Domain)
	if err != nil || normalizedDomain != event.Domain {
		return invalid()
	}
	for _, raw := range event.ResolvedIPs {
		if !validEgressAuditIP(raw) {
			return invalid()
		}
	}
	if event.ConnectedIP != "" && !validEgressAuditIP(event.ConnectedIP) {
		return invalid()
	}
	expectedRouteID := ""
	if record.Spec.EgressGateway.UpstreamRoute != nil {
		expectedRouteID = record.Spec.EgressGateway.UpstreamRoute.ID
	}
	if event.UpstreamRouteID != expectedRouteID ||
		(event.Decision != egress.ActivityDecisionAllowed && event.Decision != egress.ActivityDecisionBlocked) {
		return invalid()
	}
	switch event.RequestType {
	case egress.ActivityRequestDNS:
		if event.Port != 0 || event.Method != "" || event.Path != "" || event.HTTPStatus != 0 || event.ConnectedIP != "" {
			return invalid()
		}
	case egress.ActivityRequestHTTP:
		if event.Port < 1 || event.Port > 65535 || !validEgressAuditMethod(event.Method) ||
			!validEgressAuditPath(event.Path) || event.HTTPStatus < 0 || event.HTTPStatus > 999 {
			return invalid()
		}
	case egress.ActivityRequestCONNECT:
		if event.Port < 1 || event.Port > 65535 || event.Method != "" || event.Path != "" || event.HTTPStatus != 0 {
			return invalid()
		}
	default:
		return invalid()
	}
	return nil
}

func validEgressAuditCode(value string, optional bool) bool {
	if value == "" {
		return optional
	}
	return egressAuditCodePattern.MatchString(value)
}

func validEgressAuditText(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validEgressAuditIP(raw string) bool {
	address, err := netip.ParseAddr(raw)
	return err == nil && address.IsValid() && address.Zone() == "" && address.Unmap().String() == raw
}

func validEgressAuditMethod(value string) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if !((character >= 'A' && character <= 'Z') || character == '-') {
			return false
		}
	}
	return true
}

func validEgressAuditPath(value string) bool {
	return validEgressAuditText(value, 1024, false) && strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "?#")
}

func sanitizeEgressAuditDisplayText(value string, maximum int) string {
	var builder strings.Builder
	for _, character := range strings.TrimSpace(value) {
		if character < 0x20 || character == 0x7f {
			builder.WriteByte(' ')
			continue
		}
		builder.WriteRune(character)
	}
	value = strings.Join(strings.Fields(builder.String()), " ")
	if len(value) <= maximum {
		return value
	}
	var truncated strings.Builder
	for _, character := range value {
		if truncated.Len()+utf8.RuneLen(character) > maximum {
			break
		}
		truncated.WriteRune(character)
	}
	return truncated.String()
}

type egressAuditChainRow struct {
	ID                 string
	EventKey           string
	RecordedAt         string
	OccurredAt         string
	Category           string
	EventType          string
	ConversationID     string
	ConversationTitle  string
	ContainerID        string
	AgentID            string
	RuntimeGeneration  int64
	SnapshotID         string
	SnapshotSHA256     string
	Domain             string
	ResolvedIPsJSON    string
	ConnectedIP        string
	Port               int64
	Decision           string
	Result             string
	RuleID             string
	Reason             string
	UpstreamRouteID    string
	Method             string
	Path               string
	HTTPStatus         int64
	Outcome            string
	LatencyMS          int64
	BytesUp            int64
	BytesDown          int64
	LifecycleOperation string
	LifecycleState     string
	Message            string
	ChainSequence      int64
	PreviousHash       string
	EventHash          string
}

const egressAuditChainSelect = `
	SELECT id, event_key, CAST(recorded_at AS TEXT), CAST(occurred_at AS TEXT), category, event_type,
		conversation_id, conversation_title, container_id, agent_id, runtime_generation,
		snapshot_id, snapshot_sha256, domain, resolved_ips_json, connected_ip, port,
		decision, result, rule_id, reason, upstream_route_id, method, path, http_status,
		outcome, latency_ms, bytes_up, bytes_down, lifecycle_operation, lifecycle_state, message,
		chain_sequence, previous_hash, event_hash
	FROM egress_audit_events`

func scanEgressAuditChainRow(scanner egressAuditScanner) (egressAuditChainRow, error) {
	var row egressAuditChainRow
	err := scanner.Scan(
		&row.ID, &row.EventKey, &row.RecordedAt, &row.OccurredAt, &row.Category, &row.EventType,
		&row.ConversationID, &row.ConversationTitle, &row.ContainerID, &row.AgentID, &row.RuntimeGeneration,
		&row.SnapshotID, &row.SnapshotSHA256, &row.Domain, &row.ResolvedIPsJSON, &row.ConnectedIP, &row.Port,
		&row.Decision, &row.Result, &row.RuleID, &row.Reason, &row.UpstreamRouteID, &row.Method, &row.Path, &row.HTTPStatus,
		&row.Outcome, &row.LatencyMS, &row.BytesUp, &row.BytesDown, &row.LifecycleOperation, &row.LifecycleState, &row.Message,
		&row.ChainSequence, &row.PreviousHash, &row.EventHash,
	)
	return row, err
}

func (row egressAuditChainRow) calculatedHash(previousHash string, sequence int64) string {
	return egressAuditHashValues(
		previousHash, strconv.FormatInt(sequence, 10), row.ID, row.EventKey, row.RecordedAt, row.OccurredAt,
		row.Category, row.EventType, row.ConversationID, row.ConversationTitle, row.ContainerID, row.AgentID,
		strconv.FormatInt(row.RuntimeGeneration, 10), row.SnapshotID, row.SnapshotSHA256, row.Domain,
		row.ResolvedIPsJSON, row.ConnectedIP, strconv.FormatInt(row.Port, 10), row.Decision, row.Result,
		row.RuleID, row.Reason, row.UpstreamRouteID, row.Method, row.Path, strconv.FormatInt(row.HTTPStatus, 10),
		row.Outcome, strconv.FormatInt(row.LatencyMS, 10), strconv.FormatInt(row.BytesUp, 10), strconv.FormatInt(row.BytesDown, 10),
		row.LifecycleOperation, row.LifecycleState, row.Message,
	)
}

type egressAuditChainQueryer interface {
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func loadEgressAuditChainRows(ctx context.Context, queryer egressAuditChainQueryer, conversationID, orderBy string) ([]egressAuditChainRow, error) {
	rows, err := queryer.QueryContext(ctx, egressAuditChainSelect+` WHERE conversation_id = ? ORDER BY `+orderBy, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]egressAuditChainRow, 0)
	for rows.Next() {
		row, err := scanEgressAuditChainRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (db *DB) initializeEgressAuditChains(ctx context.Context) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var total, sealed, conversations int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(CASE WHEN chain_sequence > 0 AND previous_hash <> '' AND event_hash <> '' THEN 1 ELSE 0 END), 0),
			COUNT(DISTINCT conversation_id) FROM egress_audit_events
	`).Scan(&total, &sealed, &conversations); err != nil {
		return err
	}
	var heads int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM egress_audit_chain_heads`).Scan(&heads); err != nil {
		return err
	}
	if total == 0 {
		if heads != 0 {
			return fmt.Errorf("%w: orphaned chain head", ErrEgressAuditIntegrity)
		}
		return tx.Commit()
	}
	if sealed == 0 && heads == 0 {
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT conversation_id FROM egress_audit_events ORDER BY conversation_id`)
		if err != nil {
			return err
		}
		conversationIDs := make([]string, 0, conversations)
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
		for _, conversationID := range conversationIDs {
			chainRows, err := loadEgressAuditChainRows(ctx, tx, conversationID, "occurred_at ASC, id ASC")
			if err != nil {
				return err
			}
			previousHash := egressAuditGenesisHash
			for index, row := range chainRows {
				sequence := int64(index + 1)
				eventHash := row.calculatedHash(previousHash, sequence)
				result, err := tx.ExecContext(ctx, `UPDATE egress_audit_events SET chain_sequence = ?, previous_hash = ?, event_hash = ? WHERE id = ? AND chain_sequence = 0 AND previous_hash = '' AND event_hash = ''`, sequence, previousHash, eventHash, row.ID)
				if err != nil {
					return err
				}
				if changed, _ := result.RowsAffected(); changed != 1 {
					return fmt.Errorf("%w: legacy chain row changed during migration", ErrEgressAuditIntegrity)
				}
				previousHash = eventHash
			}
			if len(chainRows) > 0 {
				if _, err := tx.ExecContext(ctx, `INSERT INTO egress_audit_chain_heads (conversation_id, last_sequence, last_hash, event_count, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`, conversationID, len(chainRows), previousHash, len(chainRows)); err != nil {
					return err
				}
			}
		}
	} else if sealed != total || heads != conversations {
		return fmt.Errorf("%w: incomplete chain migration state", ErrEgressAuditIntegrity)
	}
	if _, err := verifyEgressAuditIntegrity(ctx, tx, EgressAuditFilter{Scope: RBACScopeAll}); err != nil {
		return err
	}
	return tx.Commit()
}

func egressAuditIntegrityConversationIDs(ctx context.Context, queryer egressAuditChainQueryer, filter EgressAuditFilter) ([]string, error) {
	scopeFilter := EgressAuditFilter{ConversationID: strings.TrimSpace(filter.ConversationID), UserID: filter.UserID, Scope: filter.Scope}
	where, args, err := buildEgressAuditWhere(scopeFilter)
	if err != nil {
		return nil, err
	}
	rows, err := queryer.QueryContext(ctx, `SELECT DISTINCT e.conversation_id FROM egress_audit_events e LEFT JOIN conversations c ON c.id = e.conversation_id`+where+` ORDER BY e.conversation_id`, args...)
	if err != nil {
		return nil, err
	}
	ids := make(map[string]struct{})
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids[id] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	headWhere := " WHERE 1=1"
	headArgs := make([]interface{}, 0, 3)
	if scopeFilter.ConversationID != "" {
		headWhere += " AND h.conversation_id = ?"
		headArgs = append(headArgs, scopeFilter.ConversationID)
	}
	headWhere, headArgs = appendConversationAccessFilter(headWhere, headArgs, scopeFilter.UserID, scopeFilter.Scope, "c")
	headRows, err := queryer.QueryContext(ctx, `SELECT h.conversation_id FROM egress_audit_chain_heads h LEFT JOIN conversations c ON c.id = h.conversation_id`+headWhere+` ORDER BY h.conversation_id`, headArgs...)
	if err != nil {
		return nil, err
	}
	for headRows.Next() {
		var id string
		if err := headRows.Scan(&id); err != nil {
			_ = headRows.Close()
			return nil, err
		}
		ids[id] = struct{}{}
	}
	if err := headRows.Close(); err != nil {
		return nil, err
	}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	slices.Sort(result)
	return result, nil
}

func verifyEgressAuditIntegrity(ctx context.Context, queryer egressAuditChainQueryer, filter EgressAuditFilter) (EgressAuditIntegrity, error) {
	result := EgressAuditIntegrity{VerifiedAt: time.Now().UTC()}
	conversationIDs, err := egressAuditIntegrityConversationIDs(ctx, queryer, filter)
	if err != nil {
		return result, err
	}
	result.Conversations = len(conversationIDs)
	for _, conversationID := range conversationIDs {
		rows, err := loadEgressAuditChainRows(ctx, queryer, conversationID, "chain_sequence ASC")
		if err != nil {
			return result, err
		}
		var lastSequence, eventCount int64
		var lastHash string
		if err := queryer.QueryRowContext(ctx, `SELECT last_sequence, last_hash, event_count FROM egress_audit_chain_heads WHERE conversation_id = ?`, conversationID).Scan(&lastSequence, &lastHash, &eventCount); err != nil {
			return result, fmt.Errorf("%w: chain head missing", ErrEgressAuditIntegrity)
		}
		previousHash := egressAuditGenesisHash
		for index, row := range rows {
			sequence := int64(index + 1)
			if row.ChainSequence != sequence || row.PreviousHash != previousHash || !egressAuditHashPattern.MatchString(row.EventHash) || row.EventHash != row.calculatedHash(previousHash, sequence) {
				return result, fmt.Errorf("%w: event chain mismatch", ErrEgressAuditIntegrity)
			}
			previousHash = row.EventHash
		}
		if len(rows) == 0 || lastSequence != int64(len(rows)) || eventCount != int64(len(rows)) || lastHash != previousHash {
			return result, fmt.Errorf("%w: chain head mismatch", ErrEgressAuditIntegrity)
		}
		result.Events += len(rows)
	}
	result.Status = "verified"
	return result, nil
}

func (db *DB) VerifyEgressAuditIntegrity(ctx context.Context, filter EgressAuditFilter) (EgressAuditIntegrity, error) {
	if ctx == nil {
		return EgressAuditIntegrity{}, errors.New("egress audit context is required")
	}
	return verifyEgressAuditIntegrity(ctx, db, filter)
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
	SELECT e.id, e.chain_sequence, e.previous_hash, e.event_hash, e.recorded_at, e.occurred_at, e.category, e.event_type,
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
		&event.ID, &event.ChainSequence, &event.PreviousHash, &event.EventHash, &recordedAt, &occurredAt, &event.Category, &event.EventType,
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
