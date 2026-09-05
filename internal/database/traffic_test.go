package database

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
	"cyberstrike-ai/internal/traffic"

	"go.uber.org/zap"
)

func TestTrafficTransactionReadsLegacyTextRuntimeGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-legacy-generation.db")
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	legacySchema := strings.Replace(createTrafficTransactionsTable,
		"runtime_generation INTEGER NOT NULL DEFAULT 0",
		"runtime_generation TEXT NOT NULL DEFAULT ''", 1)
	if _, err := raw.Exec(legacySchema); err != nil {
		_ = raw.Close()
		t.Fatalf("create legacy traffic schema: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("legacy traffic generation", ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	item := &traffic.Transaction{
		ConversationID: conversation.ID, RuntimeMode: traffic.RuntimeModeContainer,
		RuntimeGeneration: 7, CaptureCoverage: traffic.CaptureCoverageEnforced,
		Scheme: "https", Host: "example.test", Port: 443, Method: "GET", Path: "/", StartedAt: time.Now().UTC(),
	}
	if _, err := db.CreateTrafficTransaction(context.Background(), item, nil); err != nil {
		t.Fatalf("CreateTrafficTransaction: %v", err)
	}
	items, total, err := db.ListTrafficTransactions(context.Background(), TrafficTransactionFilter{Limit: 10})
	if err != nil || total != 1 || len(items) != 1 || items[0].RuntimeGeneration != 7 {
		t.Fatalf("legacy text generation list = %#v, total=%d, err=%v", items, total, err)
	}
	if _, err := db.Exec(`UPDATE traffic_transactions SET runtime_generation = '' WHERE id = ?`, item.ID); err != nil {
		t.Fatal(err)
	}
	items, total, err = db.ListTrafficTransactions(context.Background(), TrafficTransactionFilter{Limit: 10})
	if err != nil || total != 1 || len(items) != 1 || items[0].RuntimeGeneration != 0 {
		t.Fatalf("blank legacy generation list = %#v, total=%d, err=%v", items, total, err)
	}
}

func testTrafficMessage(stage, kind, method, path string, status int, raw []byte) traffic.Message {
	body, encoding, _ := traffic.EncodeBody(raw)
	return traffic.Message{
		Stage: stage, Kind: kind, Method: method, Path: path, Status: status, Protocol: "HTTP/1.1",
		Headers:     []traffic.Header{{Name: "Content-Type", Value: "application/octet-stream"}},
		ContentType: "application/octet-stream", Body: body, BodyEncoding: encoding,
		BodyLength: int64(len(raw)), BodyStoredBytes: int64(len(raw)), Complete: true,
	}
}

func TestTrafficTransactionPersistsMessagesAndVulnerabilityEvidence(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "traffic.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	conversation, err := db.CreateConversation("traffic evidence", ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	started := time.Now().UTC().Add(-25 * time.Millisecond)
	completed := time.Now().UTC()
	item := &traffic.Transaction{
		EventID: "event-traffic-1", ConversationID: conversation.ID, AgentID: "agent-1", ExecutionID: "execution-1", ToolCallID: "tool-1",
		RuntimeMode: traffic.RuntimeModeContainer, CaptureCoverage: traffic.CaptureCoverageEnforced,
		Scheme: "https", Host: "API.Example.Test", Port: 443, Method: "post", Path: "/v1/encrypted",
		HTTPStatus: 200, StartedAt: started, CompletedAt: &completed, LatencyMS: 25, BytesUp: 4, BytesDown: 5,
		Outcome: "response_interrupted", ErrorCode: "response_interrupted", ErrorSummary: "The upstream response ended before its body was complete",
		RuleID: "block-upload", BlockMatch: &boundary.BlockMatch{Source: boundary.MatchSourceRule, Type: boundary.MatchTypePathSubtree, Value: "/v1/*", RequestURL: "https://api.example.test:443/v1/encrypted", DecisionPhase: boundary.DecisionPhaseRequest,
			RuleConstraints: &boundary.RuleConstraints{Host: "api.example.test", Schemes: []string{"https"}, Ports: []int{443}, PathPrefixes: []string{"/v1/*"}, Methods: []string{"POST"}}},
	}
	detail, err := db.CreateTrafficTransaction(ctx, item, []traffic.Message{
		testTrafficMessage(traffic.StageClientRequest, traffic.MessageKindRequest, "POST", "/v1/encrypted", 0, []byte{0, 1, 2, 3}),
		testTrafficMessage(traffic.StageUpstreamResponse, traffic.MessageKindResponse, "", "", 200, []byte("reply")),
	})
	if err != nil {
		t.Fatalf("CreateTrafficTransaction: %v", err)
	}
	if detail.Transaction.EventID != "event-traffic-1" || detail.Transaction.Host != "api.example.test" || detail.Transaction.Method != "POST" || detail.Transaction.ErrorCode != "response_interrupted" || len(detail.Messages) != 2 {
		t.Fatalf("created detail = %#v", detail)
	}

	loaded, err := db.GetTrafficTransaction(ctx, item.ID)
	if err != nil {
		t.Fatalf("GetTrafficTransaction: %v", err)
	}
	if loaded.Transaction.Outcome != "response_interrupted" || loaded.Transaction.ErrorSummary == "" || loaded.Transaction.BlockMatch == nil || loaded.Transaction.BlockMatch.Value != "/v1/*" {
		t.Fatalf("loaded failure metadata = %#v", loaded.Transaction)
	}
	requestBody, err := traffic.DecodeBody(loaded.Messages[0])
	if err != nil || len(requestBody) != 4 || requestBody[2] != 2 || !loaded.Messages[0].Complete {
		t.Fatalf("loaded request body = %v, %#v, %v", requestBody, loaded.Messages[0], err)
	}
	list, total, err := db.ListTrafficTransactions(ctx, TrafficTransactionFilter{ConversationID: conversation.ID, Search: "encrypted", Limit: 10})
	if err != nil || total != 1 || len(list) != 1 || list[0].ID != item.ID {
		t.Fatalf("ListTrafficTransactions = %#v, %d, %v", list, total, err)
	}

	vulnerability, err := db.CreateVulnerability(&Vulnerability{
		ConversationID: conversation.ID, Title: "encrypted endpoint issue", Severity: "high", Status: "open",
	})
	if err != nil {
		t.Fatalf("CreateVulnerability: %v", err)
	}
	link, err := db.LinkVulnerabilityTrafficEvidence(ctx, traffic.EvidenceLink{
		VulnerabilityID: vulnerability.ID, TransactionID: item.ID, Role: traffic.EvidenceRolePrimary,
		Note: "reproduction packet", CreatedByAgentID: "agent-1",
	})
	if err != nil || link.Role != traffic.EvidenceRolePrimary {
		t.Fatalf("LinkVulnerabilityTrafficEvidence = %#v, %v", link, err)
	}
	loaded, err = db.GetTrafficTransaction(ctx, item.ID)
	if err != nil || len(loaded.Evidence) != 1 || loaded.Evidence[0].VulnerabilityID != vulnerability.ID {
		t.Fatalf("traffic evidence = %#v, %v", loaded, err)
	}

	if err := db.DeleteConversation(conversation.ID); err != nil {
		t.Fatalf("DeleteConversation: %v", err)
	}
	loaded, err = db.GetTrafficTransaction(ctx, item.ID)
	if err != nil || loaded.Transaction.ConversationID != "" || len(loaded.Evidence) != 1 {
		t.Fatalf("traffic evidence after conversation delete = %#v, %v", loaded, err)
	}
}

func TestTrafficTransactionPersistsEmptyBodyAsBlob(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "traffic-empty-body.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("empty traffic body", ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	item := &traffic.Transaction{
		ConversationID: conversation.ID, RuntimeMode: traffic.RuntimeModeContainer,
		CaptureCoverage: traffic.CaptureCoverageEnforced, Scheme: "http",
		Host: "example.test", Port: 80, Method: "GET", Path: "/", StartedAt: time.Now().UTC(),
	}
	message := testTrafficMessage(traffic.StageUpstreamRequest, traffic.MessageKindRequest, "GET", "/", 0, nil)
	detail, err := db.CreateTrafficTransaction(context.Background(), item, []traffic.Message{message})
	if err != nil {
		t.Fatalf("CreateTrafficTransaction: %v", err)
	}
	if len(detail.Messages) != 1 || detail.Messages[0].BodyLength != 0 || detail.Messages[0].Body != "" {
		t.Fatalf("empty message = %#v", detail.Messages)
	}
}

func TestTrafficEvidenceRejectsCrossConversationLink(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "traffic-scope.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	first, _ := db.CreateConversation("first", ConversationCreateMeta{})
	second, _ := db.CreateConversation("second", ConversationCreateMeta{})
	vulnerability, err := db.CreateVulnerability(&Vulnerability{ConversationID: first.ID, Title: "first vuln", Severity: "low"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	item := &traffic.Transaction{
		ConversationID: second.ID, RuntimeMode: traffic.RuntimeModeHost, CaptureCoverage: traffic.CaptureCoverageBestEffort,
		Scheme: "http", Host: "example.test", Port: 80, Method: "GET", Path: "/", StartedAt: now,
	}
	if _, err := db.CreateTrafficTransaction(ctx, item, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.LinkVulnerabilityTrafficEvidence(ctx, traffic.EvidenceLink{
		VulnerabilityID: vulnerability.ID, TransactionID: item.ID, Role: traffic.EvidenceRoleSupporting,
	}); err == nil {
		t.Fatal("expected cross-conversation evidence link to be rejected")
	}
}
