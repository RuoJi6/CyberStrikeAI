package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/traffic"

	"go.uber.org/zap"
)

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
		ConversationID: conversation.ID, AgentID: "agent-1", ExecutionID: "execution-1", ToolCallID: "tool-1",
		RuntimeMode: traffic.RuntimeModeContainer, CaptureCoverage: traffic.CaptureCoverageEnforced,
		Scheme: "https", Host: "API.Example.Test", Port: 443, Method: "post", Path: "/v1/encrypted",
		HTTPStatus: 200, StartedAt: started, CompletedAt: &completed, LatencyMS: 25, BytesUp: 4, BytesDown: 5,
	}
	detail, err := db.CreateTrafficTransaction(ctx, item, []traffic.Message{
		testTrafficMessage(traffic.StageClientRequest, traffic.MessageKindRequest, "POST", "/v1/encrypted", 0, []byte{0, 1, 2, 3}),
		testTrafficMessage(traffic.StageUpstreamResponse, traffic.MessageKindResponse, "", "", 200, []byte("reply")),
	})
	if err != nil {
		t.Fatalf("CreateTrafficTransaction: %v", err)
	}
	if detail.Transaction.Host != "api.example.test" || detail.Transaction.Method != "POST" || len(detail.Messages) != 2 {
		t.Fatalf("created detail = %#v", detail)
	}

	loaded, err := db.GetTrafficTransaction(ctx, item.ID)
	if err != nil {
		t.Fatalf("GetTrafficTransaction: %v", err)
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
