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

	"cyberstrike-ai/internal/networkprovenance"
	"cyberstrike-ai/internal/traffic"

	"github.com/google/uuid"
)

const createTrafficTransactionsTable = `
CREATE TABLE IF NOT EXISTS traffic_transactions (
	id TEXT PRIMARY KEY,
	event_id TEXT NOT NULL DEFAULT '',
	conversation_id TEXT,
	project_id TEXT,
	agent_id TEXT NOT NULL DEFAULT '',
	tool_name TEXT NOT NULL DEFAULT '',
	execution_id TEXT NOT NULL DEFAULT '',
	tool_call_id TEXT NOT NULL DEFAULT '',
	activity_scope_id TEXT NOT NULL DEFAULT '',
	runtime_generation INTEGER NOT NULL DEFAULT 0,
	runtime_instance_id TEXT NOT NULL DEFAULT '',
	attribution_status TEXT NOT NULL DEFAULT 'legacy_unattributed',
	declared_activity_kind TEXT NOT NULL DEFAULT 'unknown',
	observed_activity_kind TEXT NOT NULL DEFAULT 'single',
	runtime_mode TEXT NOT NULL DEFAULT 'unknown' CHECK (runtime_mode IN ('host', 'container', 'unknown')),
	capture_coverage TEXT NOT NULL DEFAULT 'unknown' CHECK (capture_coverage IN ('enforced', 'best_effort', 'unknown')),
	scheme TEXT NOT NULL CHECK (scheme IN ('http', 'https')),
	host TEXT NOT NULL,
	port INTEGER NOT NULL CHECK (port > 0 AND port <= 65535),
	method TEXT NOT NULL,
	path TEXT NOT NULL,
	http_status INTEGER NOT NULL DEFAULT 0 CHECK (http_status >= 0 AND http_status <= 999),
	started_at DATETIME NOT NULL,
	completed_at DATETIME,
	latency_ms INTEGER NOT NULL DEFAULT 0 CHECK (latency_ms >= 0),
	bytes_up INTEGER NOT NULL DEFAULT 0 CHECK (bytes_up >= 0),
	bytes_down INTEGER NOT NULL DEFAULT 0 CHECK (bytes_down >= 0),
	boundary_snapshot_id TEXT NOT NULL DEFAULT '',
	rule_id TEXT NOT NULL DEFAULT '',
	upstream_route_id TEXT NOT NULL DEFAULT '',
	transform_binding_id TEXT NOT NULL DEFAULT '',
	transform_revision_id TEXT NOT NULL DEFAULT '',
	transform_result TEXT NOT NULL DEFAULT '',
	aggregate_kind TEXT NOT NULL DEFAULT '',
	aggregate_count INTEGER NOT NULL DEFAULT 0 CHECK (aggregate_count >= 0),
	aggregate_first_at DATETIME,
	aggregate_last_at DATETIME,
	aggregate_summary_json TEXT NOT NULL DEFAULT '' CHECK (aggregate_summary_json = '' OR json_valid(aggregate_summary_json)),
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE SET NULL,
	FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
);`

const createTrafficMessagesTable = `
CREATE TABLE IF NOT EXISTS traffic_messages (
	id TEXT PRIMARY KEY,
	transaction_id TEXT NOT NULL,
	stage TEXT NOT NULL CHECK (stage IN ('client_request', 'decoded_request', 'upstream_request', 'upstream_response', 'decoded_response', 'client_response')),
	kind TEXT NOT NULL CHECK (kind IN ('request', 'response')),
	method TEXT NOT NULL DEFAULT '',
	path TEXT NOT NULL DEFAULT '',
	status INTEGER NOT NULL DEFAULT 0 CHECK (status >= 0 AND status <= 999),
	protocol TEXT NOT NULL DEFAULT '',
	headers_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(headers_json)),
	content_type TEXT NOT NULL DEFAULT '',
	body BLOB NOT NULL DEFAULT X'',
	body_sha256 TEXT NOT NULL,
	body_length INTEGER NOT NULL DEFAULT 0 CHECK (body_length >= 0),
	body_stored_bytes INTEGER NOT NULL DEFAULT 0 CHECK (body_stored_bytes >= 0 AND body_stored_bytes <= body_length),
	complete INTEGER NOT NULL DEFAULT 0 CHECK (complete IN (0, 1)),
	created_at DATETIME NOT NULL,
	FOREIGN KEY (transaction_id) REFERENCES traffic_transactions(id) ON DELETE CASCADE,
	UNIQUE (transaction_id, stage)
);`

const createVulnerabilityTrafficEvidenceTable = `
CREATE TABLE IF NOT EXISTS vulnerability_traffic_evidence (
	vulnerability_id TEXT NOT NULL,
	traffic_transaction_id TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'supporting' CHECK (role IN ('primary', 'supporting', 'retest')),
	note TEXT NOT NULL DEFAULT '',
	created_by_agent_id TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL,
	PRIMARY KEY (vulnerability_id, traffic_transaction_id),
	FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
	FOREIGN KEY (traffic_transaction_id) REFERENCES traffic_transactions(id) ON DELETE CASCADE
);`

func (db *DB) initTrafficTables() error {
	for _, statement := range []string{
		createTrafficTransactionsTable,
		createTrafficMessagesTable,
		createVulnerabilityTrafficEvidenceTable,
	} {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("initialize traffic evidence schema: %w", err)
		}
	}
	for _, column := range []struct{ name, statement string }{
		{"event_id", `ALTER TABLE traffic_transactions ADD COLUMN event_id TEXT NOT NULL DEFAULT ''`},
		{"tool_name", `ALTER TABLE traffic_transactions ADD COLUMN tool_name TEXT NOT NULL DEFAULT ''`},
		{"activity_scope_id", `ALTER TABLE traffic_transactions ADD COLUMN activity_scope_id TEXT NOT NULL DEFAULT ''`},
		{"runtime_generation", `ALTER TABLE traffic_transactions ADD COLUMN runtime_generation INTEGER NOT NULL DEFAULT 0`},
		{"runtime_instance_id", `ALTER TABLE traffic_transactions ADD COLUMN runtime_instance_id TEXT NOT NULL DEFAULT ''`},
		{"attribution_status", `ALTER TABLE traffic_transactions ADD COLUMN attribution_status TEXT NOT NULL DEFAULT 'legacy_unattributed'`},
		{"declared_activity_kind", `ALTER TABLE traffic_transactions ADD COLUMN declared_activity_kind TEXT NOT NULL DEFAULT 'unknown'`},
		{"observed_activity_kind", `ALTER TABLE traffic_transactions ADD COLUMN observed_activity_kind TEXT NOT NULL DEFAULT 'single'`},
	} {
		if err := db.addColumnIfMissing("traffic_transactions", column.name, column.statement); err != nil {
			return fmt.Errorf("initialize traffic provenance column %s: %w", column.name, err)
		}
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS idx_traffic_transactions_conversation_time ON traffic_transactions(conversation_id, started_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_transactions_project_time ON traffic_transactions(project_id, started_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_transactions_target_time ON traffic_transactions(host, port, started_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_transactions_execution ON traffic_transactions(execution_id, tool_call_id)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_transactions_event ON traffic_transactions(event_id) WHERE event_id <> ''`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_transactions_provenance ON traffic_transactions(runtime_mode, attribution_status, agent_id, tool_name, execution_id, activity_scope_id)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_messages_transaction_stage ON traffic_messages(transaction_id, stage)`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerability_traffic_evidence_transaction ON vulnerability_traffic_evidence(traffic_transaction_id)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("initialize traffic evidence schema: %w", err)
		}
	}
	return nil
}

type TrafficTransactionFilter struct {
	ID                string
	ConversationID    string
	ProjectID         string
	ExecutionID       string
	AgentID           string
	ToolName          string
	AttributionStatus string
	RuntimeMode       string
	Scheme            string
	Host              string
	Method            string
	Search            string
	UserID            string
	Scope             string
	Limit             int
	Offset            int
}

type trafficTransactionScanner interface {
	Scan(...interface{}) error
}

func scanTrafficTransaction(scanner trafficTransactionScanner) (traffic.Transaction, error) {
	var item traffic.Transaction
	var conversationID, projectID sql.NullString
	var completedAt, aggregateFirstAt, aggregateLastAt sql.NullTime
	err := scanner.Scan(
		&item.ID, &item.EventID, &conversationID, &projectID, &item.AgentID, &item.ToolName, &item.ExecutionID, &item.ToolCallID, &item.ActivityScopeID,
		&item.RuntimeGeneration, &item.RuntimeInstanceID, &item.AttributionStatus, &item.DeclaredActivityKind, &item.ObservedActivityKind,
		&item.RuntimeMode, &item.CaptureCoverage, &item.Scheme, &item.Host, &item.Port, &item.Method, &item.Path,
		&item.HTTPStatus, &item.StartedAt, &completedAt, &item.LatencyMS, &item.BytesUp, &item.BytesDown,
		&item.BoundarySnapshotID, &item.RuleID, &item.UpstreamRouteID,
		&item.TransformBindingID, &item.TransformRevisionID, &item.TransformResult,
		&item.AggregateKind, &item.AggregateCount, &aggregateFirstAt, &aggregateLastAt, &item.AggregateSummaryJSON,
		&item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return traffic.Transaction{}, err
	}
	item.ConversationID = conversationID.String
	item.ProjectID = projectID.String
	if completedAt.Valid {
		value := completedAt.Time
		item.CompletedAt = &value
	}
	if aggregateFirstAt.Valid {
		value := aggregateFirstAt.Time
		item.AggregateFirstAt = &value
	}
	if aggregateLastAt.Valid {
		value := aggregateLastAt.Time
		item.AggregateLastAt = &value
	}
	return item, nil
}

const trafficTransactionSelect = `
	SELECT id, event_id, conversation_id, project_id, agent_id, tool_name, execution_id, tool_call_id, activity_scope_id,
		runtime_generation, runtime_instance_id, attribution_status, declared_activity_kind, observed_activity_kind,
		runtime_mode, capture_coverage, scheme, host, port, method, path, http_status,
		started_at, completed_at, latency_ms, bytes_up, bytes_down,
		boundary_snapshot_id, rule_id, upstream_route_id,
		transform_binding_id, transform_revision_id, transform_result,
		aggregate_kind, aggregate_count, aggregate_first_at, aggregate_last_at, aggregate_summary_json,
		created_at, updated_at
	FROM traffic_transactions`

func prepareTrafficMessage(message *traffic.Message, transactionID string, now time.Time) ([]byte, error) {
	if message == nil {
		return nil, errors.New("traffic message is required")
	}
	message.TransactionID = transactionID
	if message.ID == "" {
		message.ID = uuid.NewString()
	}
	if message.CreatedAt.IsZero() {
		message.CreatedAt = now
	}
	body, err := traffic.DecodeBody(*message)
	if err != nil {
		return nil, err
	}
	// database/sql treats a nil []byte as SQL NULL. Traffic bodies are NOT
	// NULL by design, so represent an empty HTTP body as a zero-length BLOB.
	if body == nil {
		body = []byte{}
	}
	message.BodyStoredBytes = int64(len(body))
	if message.BodyLength == 0 && len(body) > 0 {
		message.BodyLength = int64(len(body))
	}
	sum := sha256.Sum256(body)
	message.BodySHA256 = hex.EncodeToString(sum[:])
	if err := traffic.ValidateMessage(*message); err != nil {
		return nil, err
	}
	return body, nil
}

func (db *DB) CreateTrafficTransaction(ctx context.Context, item *traffic.Transaction, messages []traffic.Message) (*traffic.TransactionDetail, error) {
	if db == nil || item == nil {
		return nil, errors.New("traffic transaction is required")
	}
	if id := strings.TrimSpace(item.ID); id != "" {
		var exists int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM traffic_transactions WHERE id = ?`, id).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check traffic transaction idempotency: %w", err)
		}
		if exists > 0 {
			return db.GetTrafficTransaction(ctx, id)
		}
	}
	copyItem := *item
	copyItem.EventID = strings.TrimSpace(copyItem.EventID)
	copyItem.ConversationID = strings.TrimSpace(copyItem.ConversationID)
	copyItem.ProjectID = strings.TrimSpace(copyItem.ProjectID)
	copyItem.RuntimeMode = traffic.NormalizeRuntimeMode(copyItem.RuntimeMode)
	provenance := networkprovenance.NetworkProvenanceV1{
		RuntimeMode: copyItem.RuntimeMode, RuntimeGeneration: copyItem.RuntimeGeneration,
		RuntimeInstanceID: copyItem.RuntimeInstanceID, AgentID: copyItem.AgentID, ToolName: copyItem.ToolName,
		ExecutionID: copyItem.ExecutionID, ToolCallID: copyItem.ToolCallID, ActivityScopeID: copyItem.ActivityScopeID,
		AttributionStatus: copyItem.AttributionStatus, DeclaredActivityKind: copyItem.DeclaredActivityKind,
		ObservedActivityKind: copyItem.ObservedActivityKind,
	}.Normalized()
	if copyItem.AttributionStatus == "" {
		provenance.AttributionStatus = networkprovenance.AttributionLegacyUnattributed
	}
	copyItem.AgentID, copyItem.ToolName = provenance.AgentID, provenance.ToolName
	copyItem.ExecutionID, copyItem.ToolCallID, copyItem.ActivityScopeID = provenance.ExecutionID, provenance.ToolCallID, provenance.ActivityScopeID
	copyItem.RuntimeGeneration, copyItem.RuntimeInstanceID = provenance.RuntimeGeneration, provenance.RuntimeInstanceID
	copyItem.AttributionStatus, copyItem.DeclaredActivityKind, copyItem.ObservedActivityKind = provenance.AttributionStatus, provenance.DeclaredActivityKind, provenance.ObservedActivityKind
	copyItem.CaptureCoverage = traffic.NormalizeCaptureCoverage(copyItem.CaptureCoverage)
	copyItem.Scheme = strings.ToLower(strings.TrimSpace(copyItem.Scheme))
	copyItem.Host = strings.ToLower(strings.TrimSpace(copyItem.Host))
	copyItem.Method = strings.ToUpper(strings.TrimSpace(copyItem.Method))
	if copyItem.ProjectID == "" {
		if projectID, err := db.GetConversationProjectID(copyItem.ConversationID); err == nil {
			copyItem.ProjectID = strings.TrimSpace(projectID)
		}
	}
	if err := traffic.ValidateTransaction(copyItem); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if copyItem.ID == "" {
		copyItem.ID = uuid.NewString()
	}
	copyItem.StartedAt = copyItem.StartedAt.UTC()
	if copyItem.CompletedAt != nil {
		value := copyItem.CompletedAt.UTC()
		copyItem.CompletedAt = &value
	}
	if copyItem.CreatedAt.IsZero() {
		copyItem.CreatedAt = now
	}
	copyItem.CreatedAt = copyItem.CreatedAt.UTC()
	copyItem.UpdatedAt = now

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin traffic transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO traffic_transactions (
			id, event_id, conversation_id, project_id, agent_id, tool_name, execution_id, tool_call_id, activity_scope_id,
			runtime_generation, runtime_instance_id, attribution_status, declared_activity_kind, observed_activity_kind,
			runtime_mode, capture_coverage, scheme, host, port, method, path, http_status,
			started_at, completed_at, latency_ms, bytes_up, bytes_down,
			boundary_snapshot_id, rule_id, upstream_route_id,
			transform_binding_id, transform_revision_id, transform_result,
			aggregate_kind, aggregate_count, aggregate_first_at, aggregate_last_at, aggregate_summary_json,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, copyItem.ID, copyItem.EventID, nullIfEmpty(copyItem.ConversationID), nullIfEmpty(copyItem.ProjectID), copyItem.AgentID, copyItem.ToolName, copyItem.ExecutionID, copyItem.ToolCallID, copyItem.ActivityScopeID,
		copyItem.RuntimeGeneration, copyItem.RuntimeInstanceID, copyItem.AttributionStatus, copyItem.DeclaredActivityKind, copyItem.ObservedActivityKind,
		copyItem.RuntimeMode, copyItem.CaptureCoverage, copyItem.Scheme, copyItem.Host, copyItem.Port, copyItem.Method, copyItem.Path, copyItem.HTTPStatus,
		copyItem.StartedAt, copyItem.CompletedAt, copyItem.LatencyMS, copyItem.BytesUp, copyItem.BytesDown,
		copyItem.BoundarySnapshotID, copyItem.RuleID, copyItem.UpstreamRouteID,
		copyItem.TransformBindingID, copyItem.TransformRevisionID, copyItem.TransformResult,
		copyItem.AggregateKind, copyItem.AggregateCount, copyItem.AggregateFirstAt, copyItem.AggregateLastAt, copyItem.AggregateSummaryJSON,
		copyItem.CreatedAt, copyItem.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert traffic transaction: %w", err)
	}
	prepared := make([]traffic.Message, len(messages))
	copy(prepared, messages)
	for index := range prepared {
		body, prepareErr := prepareTrafficMessage(&prepared[index], copyItem.ID, now)
		if prepareErr != nil {
			return nil, fmt.Errorf("prepare traffic message %s: %w", prepared[index].Stage, prepareErr)
		}
		headersJSON, marshalErr := json.Marshal(prepared[index].Headers)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal traffic headers: %w", marshalErr)
		}
		_, insertErr := tx.ExecContext(ctx, `
			INSERT INTO traffic_messages (
				id, transaction_id, stage, kind, method, path, status, protocol, headers_json,
				content_type, body, body_sha256, body_length, body_stored_bytes, complete, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, prepared[index].ID, copyItem.ID, prepared[index].Stage, prepared[index].Kind,
			prepared[index].Method, prepared[index].Path, prepared[index].Status, prepared[index].Protocol, string(headersJSON),
			prepared[index].ContentType, body, prepared[index].BodySHA256, prepared[index].BodyLength,
			prepared[index].BodyStoredBytes, boolToInt(prepared[index].Complete), prepared[index].CreatedAt.UTC())
		if insertErr != nil {
			return nil, fmt.Errorf("insert traffic message %s: %w", prepared[index].Stage, insertErr)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit traffic transaction: %w", err)
	}
	*item = copyItem
	return &traffic.TransactionDetail{Transaction: copyItem, Messages: prepared}, nil
}

func (db *DB) GetTrafficTransaction(ctx context.Context, id string) (*traffic.TransactionDetail, error) {
	item, err := scanTrafficTransaction(db.QueryRowContext(ctx, trafficTransactionSelect+` WHERE id = ?`, strings.TrimSpace(id)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("traffic transaction not found")
		}
		return nil, fmt.Errorf("get traffic transaction: %w", err)
	}
	messages, err := db.listTrafficMessages(ctx, item.ID)
	if err != nil {
		return nil, err
	}
	evidence, err := db.ListTrafficEvidenceForTransaction(ctx, item.ID)
	if err != nil {
		return nil, err
	}
	return &traffic.TransactionDetail{Transaction: item, Messages: messages, Evidence: evidence}, nil
}

// ApplyObservedTrafficTransform appends the first successful passive decode to
// an immutable wire transaction. The original upstream request/response rows
// are never updated or replaced.
func (db *DB) ApplyObservedTrafficTransform(ctx context.Context, transactionID, bindingID, revisionID string, messages []traffic.Message) (*traffic.TransactionDetail, error) {
	transactionID = strings.TrimSpace(transactionID)
	bindingID = strings.TrimSpace(bindingID)
	revisionID = strings.TrimSpace(revisionID)
	if transactionID == "" || bindingID == "" || revisionID == "" || len(messages) == 0 {
		return nil, errors.New("observed traffic transform identity and messages are required")
	}
	now := time.Now().UTC()
	prepared := append([]traffic.Message(nil), messages...)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE traffic_transactions
		SET transform_binding_id = ?, transform_revision_id = ?, transform_result = 'observe_passed', updated_at = ?
		WHERE id = ? AND transform_binding_id = '' AND transform_revision_id = ''
	`, bindingID, revisionID, now, transactionID)
	if err != nil {
		return nil, fmt.Errorf("claim traffic transaction observation: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		_ = tx.Rollback()
		return db.GetTrafficTransaction(ctx, transactionID)
	}
	for index := range prepared {
		if prepared[index].Stage != traffic.StageDecodedRequest && prepared[index].Stage != traffic.StageDecodedResponse {
			return nil, errors.New("observed traffic transform may only append decoded stages")
		}
		body, prepareErr := prepareTrafficMessage(&prepared[index], transactionID, now)
		if prepareErr != nil {
			return nil, prepareErr
		}
		headersJSON, marshalErr := json.Marshal(prepared[index].Headers)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if _, insertErr := tx.ExecContext(ctx, `
			INSERT INTO traffic_messages (
				id, transaction_id, stage, kind, method, path, status, protocol, headers_json,
				content_type, body, body_sha256, body_length, body_stored_bytes, complete, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, prepared[index].ID, transactionID, prepared[index].Stage, prepared[index].Kind,
			prepared[index].Method, prepared[index].Path, prepared[index].Status, prepared[index].Protocol, string(headersJSON),
			prepared[index].ContentType, body, prepared[index].BodySHA256, prepared[index].BodyLength,
			prepared[index].BodyStoredBytes, boolToInt(prepared[index].Complete), prepared[index].CreatedAt.UTC()); insertErr != nil {
			return nil, fmt.Errorf("append decoded traffic message: %w", insertErr)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetTrafficTransaction(ctx, transactionID)
}

func (db *DB) listTrafficMessages(ctx context.Context, transactionID string) ([]traffic.Message, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, transaction_id, stage, kind, method, path, status, protocol, headers_json,
			content_type, body, body_sha256, body_length, body_stored_bytes, complete, created_at
		FROM traffic_messages WHERE transaction_id = ?
		ORDER BY CASE stage
			WHEN 'client_request' THEN 1 WHEN 'decoded_request' THEN 2 WHEN 'upstream_request' THEN 3
			WHEN 'upstream_response' THEN 4 WHEN 'decoded_response' THEN 5 WHEN 'client_response' THEN 6 ELSE 99 END
	`, transactionID)
	if err != nil {
		return nil, fmt.Errorf("list traffic messages: %w", err)
	}
	defer rows.Close()
	result := make([]traffic.Message, 0, 6)
	for rows.Next() {
		var message traffic.Message
		var headersJSON string
		var body []byte
		var complete int
		if err := rows.Scan(&message.ID, &message.TransactionID, &message.Stage, &message.Kind,
			&message.Method, &message.Path, &message.Status, &message.Protocol, &headersJSON,
			&message.ContentType, &body, &message.BodySHA256, &message.BodyLength, &message.BodyStoredBytes,
			&complete, &message.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan traffic message: %w", err)
		}
		if err := json.Unmarshal([]byte(headersJSON), &message.Headers); err != nil {
			return nil, fmt.Errorf("decode traffic message headers: %w", err)
		}
		message.Body, message.BodyEncoding, _ = traffic.EncodeBody(body)
		message.Complete = complete != 0
		result = append(result, message)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list traffic messages: %w", err)
	}
	return result, nil
}

func appendTrafficAccessFilter(query string, args []interface{}, filter TrafficTransactionFilter) (string, []interface{}) {
	if strings.TrimSpace(filter.UserID) == "" || filter.Scope == RBACScopeAll {
		return query, args
	}
	query += ` AND (
		(project_id IS NOT NULL AND project_id <> '' AND (
			EXISTS (SELECT 1 FROM projects p WHERE p.id = traffic_transactions.project_id AND p.owner_user_id = ?)
			OR EXISTS (SELECT 1 FROM rbac_resource_assignments ra WHERE ra.user_id = ? AND ra.resource_type = 'project' AND ra.resource_id = traffic_transactions.project_id)
		))
		OR (conversation_id IS NOT NULL AND conversation_id <> '' AND (
			EXISTS (SELECT 1 FROM conversations c WHERE c.id = traffic_transactions.conversation_id AND c.owner_user_id = ?)
			OR EXISTS (SELECT 1 FROM rbac_resource_assignments ra WHERE ra.user_id = ? AND ra.resource_type = 'conversation' AND ra.resource_id = traffic_transactions.conversation_id)
		))
	)`
	args = append(args, filter.UserID, filter.UserID, filter.UserID, filter.UserID)
	return query, args
}

func appendTrafficTransactionFilter(query string, args []interface{}, filter TrafficTransactionFilter) (string, []interface{}) {
	for _, value := range []struct {
		column string
		value  string
	}{
		{"id", filter.ID}, {"conversation_id", filter.ConversationID}, {"project_id", filter.ProjectID},
		{"execution_id", filter.ExecutionID}, {"agent_id", filter.AgentID}, {"tool_name", filter.ToolName},
		{"attribution_status", filter.AttributionStatus}, {"runtime_mode", filter.RuntimeMode}, {"scheme", filter.Scheme},
		{"host", filter.Host}, {"method", strings.ToUpper(strings.TrimSpace(filter.Method))},
	} {
		if strings.TrimSpace(value.value) != "" {
			query += " AND " + value.column + " = ?"
			args = append(args, strings.TrimSpace(value.value))
		}
	}
	if search := strings.TrimSpace(filter.Search); search != "" {
		pattern := escapeVulnerabilityLikePattern(search)
		query += ` AND (LOWER(host) LIKE LOWER(?) ESCAPE '\' OR LOWER(path) LIKE LOWER(?) ESCAPE '\' OR LOWER(method) LIKE LOWER(?) ESCAPE '\' OR LOWER(execution_id) LIKE LOWER(?) ESCAPE '\' OR LOWER(tool_name) LIKE LOWER(?) ESCAPE '\' OR LOWER(agent_id) LIKE LOWER(?) ESCAPE '\')`
		args = append(args, pattern, pattern, pattern, pattern, pattern, pattern)
	}
	return appendTrafficAccessFilter(query, args, filter)
}

func (db *DB) ListTrafficTransactions(ctx context.Context, filter TrafficTransactionFilter) ([]traffic.Transaction, int, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	where, args := appendTrafficTransactionFilter(" WHERE 1=1", nil, filter)
	var total int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM traffic_transactions`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count traffic transactions: %w", err)
	}
	rows, err := db.QueryContext(ctx, trafficTransactionSelect+where+` ORDER BY started_at DESC, id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list traffic transactions: %w", err)
	}
	defer rows.Close()
	result := make([]traffic.Transaction, 0, limit)
	for rows.Next() {
		item, scanErr := scanTrafficTransaction(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf("scan traffic transaction: %w", scanErr)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list traffic transactions: %w", err)
	}
	return result, total, nil
}

func trafficEvidenceScopesMatch(vulnerabilityProject, vulnerabilityConversation, transactionProject, transactionConversation string) bool {
	if vulnerabilityProject != "" && transactionProject != "" && vulnerabilityProject == transactionProject {
		return true
	}
	return vulnerabilityConversation != "" && transactionConversation != "" && vulnerabilityConversation == transactionConversation
}

func (db *DB) LinkVulnerabilityTrafficEvidence(ctx context.Context, link traffic.EvidenceLink) (*traffic.EvidenceLink, error) {
	role, ok := traffic.NormalizeEvidenceRole(link.Role)
	if !ok {
		return nil, errors.New("invalid traffic evidence role")
	}
	link.VulnerabilityID = strings.TrimSpace(link.VulnerabilityID)
	link.TransactionID = strings.TrimSpace(link.TransactionID)
	link.Note = strings.TrimSpace(link.Note)
	if link.VulnerabilityID == "" || link.TransactionID == "" {
		return nil, errors.New("vulnerability and traffic transaction are required")
	}
	if len(link.Note) > 4096 {
		return nil, errors.New("traffic evidence note is too large")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var vulnerabilityProject, vulnerabilityConversation, transactionProject, transactionConversation string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(project_id,''), COALESCE(conversation_id,'') FROM vulnerabilities WHERE id = ?`, link.VulnerabilityID).Scan(&vulnerabilityProject, &vulnerabilityConversation); err != nil {
		return nil, fmt.Errorf("load vulnerability evidence scope: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(project_id,''), COALESCE(conversation_id,'') FROM traffic_transactions WHERE id = ?`, link.TransactionID).Scan(&transactionProject, &transactionConversation); err != nil {
		return nil, fmt.Errorf("load traffic evidence scope: %w", err)
	}
	if !trafficEvidenceScopesMatch(vulnerabilityProject, vulnerabilityConversation, transactionProject, transactionConversation) {
		return nil, errors.New("vulnerability and traffic transaction do not share a project or conversation")
	}
	link.Role = role
	link.CreatedAt = time.Now().UTC()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO vulnerability_traffic_evidence (
			vulnerability_id, traffic_transaction_id, role, note, created_by_agent_id, created_at
		) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(vulnerability_id, traffic_transaction_id) DO UPDATE SET
			role = excluded.role, note = excluded.note, created_by_agent_id = excluded.created_by_agent_id, created_at = excluded.created_at
	`, link.VulnerabilityID, link.TransactionID, link.Role, link.Note, link.CreatedByAgentID, link.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("link vulnerability traffic evidence: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &link, nil
}

func (db *DB) ListTrafficEvidenceForTransaction(ctx context.Context, transactionID string) ([]traffic.EvidenceLink, error) {
	return db.listTrafficEvidence(ctx, `traffic_transaction_id = ?`, strings.TrimSpace(transactionID))
}

func (db *DB) ListTrafficEvidenceForVulnerability(ctx context.Context, vulnerabilityID string) ([]traffic.EvidenceLink, error) {
	return db.listTrafficEvidence(ctx, `vulnerability_id = ?`, strings.TrimSpace(vulnerabilityID))
}

func (db *DB) listTrafficEvidence(ctx context.Context, where string, arg interface{}) ([]traffic.EvidenceLink, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT vulnerability_id, traffic_transaction_id, role, note, created_by_agent_id, created_at
		FROM vulnerability_traffic_evidence WHERE `+where+` ORDER BY created_at ASC
	`, arg)
	if err != nil {
		return nil, fmt.Errorf("list traffic evidence: %w", err)
	}
	defer rows.Close()
	result := make([]traffic.EvidenceLink, 0)
	for rows.Next() {
		var link traffic.EvidenceLink
		if err := rows.Scan(&link.VulnerabilityID, &link.TransactionID, &link.Role, &link.Note, &link.CreatedByAgentID, &link.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan traffic evidence: %w", err)
		}
		result = append(result, link)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (db *DB) UnlinkVulnerabilityTrafficEvidence(ctx context.Context, vulnerabilityID, transactionID string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM vulnerability_traffic_evidence WHERE vulnerability_id = ? AND traffic_transaction_id = ?`, strings.TrimSpace(vulnerabilityID), strings.TrimSpace(transactionID))
	if err != nil {
		return fmt.Errorf("unlink vulnerability traffic evidence: %w", err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return errors.New("traffic evidence link not found")
	}
	return nil
}
