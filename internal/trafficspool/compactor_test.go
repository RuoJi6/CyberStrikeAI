package trafficspool

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"cyberstrike-ai/internal/traffic"
)

type capturedTrafficRecord struct {
	transaction traffic.Transaction
	messages    []traffic.Message
}

func compactTestTransaction(index int, startedAt time.Time) (traffic.Transaction, []traffic.Message) {
	id := fmt.Sprintf("transaction-%02d", index)
	item := traffic.Transaction{
		ID: id, ConversationID: "conversation-01", ExecutionID: "execution-01",
		RuntimeMode: traffic.RuntimeModeContainer, CaptureCoverage: traffic.CaptureCoverageEnforced,
		Scheme: "https", Host: "example.test", Port: 443, Method: "GET",
		Path: fmt.Sprintf("/FUZZ-%02d", index), HTTPStatus: 200, StartedAt: startedAt,
		BytesUp: 10, BytesDown: 20,
	}
	message := traffic.Message{TransactionID: id, Stage: traffic.StageUpstreamRequest, Kind: traffic.MessageKindRequest, Method: "GET", Path: item.Path}
	return item, []traffic.Message{message}
}

func TestCompactingSinkPreservesOrdinaryTransactions(t *testing.T) {
	var captured []capturedTrafficRecord
	sink, err := NewCompactingSink(func(_ context.Context, item traffic.Transaction, messages []traffic.Message) error {
		captured = append(captured, capturedTrafficRecord{transaction: item, messages: messages})
		return nil
	}, CompactConfig{IdleWindow: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now().UTC()
	for index := 0; index < 3; index++ {
		item, messages := compactTestTransaction(index, startedAt.Add(time.Duration(index)*time.Millisecond))
		if err := sink.Write(context.Background(), item, messages); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 3 {
		t.Fatalf("captured %d ordinary transactions, want 3", len(captured))
	}
	for index, record := range captured {
		if record.transaction.AggregateCount != 0 || len(record.messages) != 1 || record.transaction.Path != fmt.Sprintf("/FUZZ-%02d", index) {
			t.Fatalf("ordinary record %d = %#v", index, record)
		}
	}
}

func TestCompactingSinkStoresOneCompleteRepresentativeForWebFuzz(t *testing.T) {
	var captured []capturedTrafficRecord
	sink, err := NewCompactingSink(func(_ context.Context, item traffic.Transaction, messages []traffic.Message) error {
		captured = append(captured, capturedTrafficRecord{transaction: item, messages: messages})
		return nil
	}, CompactConfig{IdleWindow: time.Hour, CountThreshold: 8, DistinctThreshold: 6})
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now().UTC()
	for index := 0; index < 12; index++ {
		item, messages := compactTestTransaction(index, startedAt.Add(time.Duration(index)*time.Millisecond))
		if err := sink.Write(context.Background(), item, messages); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 1 {
		t.Fatalf("captured %d transactions, want one aggregate", len(captured))
	}
	record := captured[0]
	if record.transaction.ID != "transaction-00" || record.transaction.Path != "/FUZZ-00" || len(record.messages) != 1 {
		t.Fatalf("representative = %#v", record)
	}
	if record.transaction.AggregateKind != AggregateKindWebFuzz || record.transaction.AggregateCount != 12 ||
		record.transaction.BytesUp != 120 || record.transaction.BytesDown != 240 {
		t.Fatalf("aggregate = %#v", record.transaction)
	}
	var summary struct {
		DistinctPaths int              `json:"distinct_paths"`
		StatusCounts  map[string]int64 `json:"status_counts"`
	}
	if err := json.Unmarshal([]byte(record.transaction.AggregateSummaryJSON), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.DistinctPaths != 12 || summary.StatusCounts["200"] != 12 {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestDefaultCompactorGroupsSlowSequentialWebFuzz(t *testing.T) {
	var captured []traffic.Transaction
	sink, err := NewCompactingSink(func(_ context.Context, item traffic.Transaction, _ []traffic.Message) error {
		captured = append(captured, item)
		return nil
	}, DefaultCompactConfig())
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now().UTC()
	for index := 0; index < 12; index++ {
		item, messages := compactTestTransaction(index, startedAt.Add(time.Duration(index)*1500*time.Millisecond))
		if err := sink.Write(context.Background(), item, messages); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 1 || captured[0].AggregateKind != AggregateKindWebFuzz || captured[0].AggregateCount != 12 {
		t.Fatalf("slow sequential aggregate = %#v", captured)
	}
}

func TestCompactingSinkCompactsRepeatedRequestBurst(t *testing.T) {
	var captured []traffic.Transaction
	sink, err := NewCompactingSink(func(_ context.Context, item traffic.Transaction, _ []traffic.Message) error {
		captured = append(captured, item)
		return nil
	}, CompactConfig{IdleWindow: time.Hour, CountThreshold: 4, DistinctThreshold: 6})
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now().UTC()
	for index := 0; index < 5; index++ {
		item, messages := compactTestTransaction(index, startedAt.Add(time.Duration(index)*time.Millisecond))
		item.Path = "/login"
		messages[0].Path = item.Path
		if err := sink.Write(context.Background(), item, messages); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 1 || captured[0].AggregateKind != AggregateKindRequestBurst || captured[0].AggregateCount != 5 {
		t.Fatalf("aggregate = %#v", captured)
	}
}
