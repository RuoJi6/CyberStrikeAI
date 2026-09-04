package trafficspool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"cyberstrike-ai/internal/networkprovenance"
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
		item.DeclaredActivityKind = networkprovenance.ActivityKindFuzz
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
		item.DeclaredActivityKind = networkprovenance.ActivityKindFuzz
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

func TestCompactingSinkSeparatesConcurrentNormalAndDeclaredFuzzExecutions(t *testing.T) {
	var captured []traffic.Transaction
	sink, err := NewCompactingSink(func(_ context.Context, item traffic.Transaction, _ []traffic.Message) error {
		captured = append(captured, item)
		return nil
	}, CompactConfig{IdleWindow: time.Hour, CountThreshold: 4, DistinctThreshold: 4})
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now().UTC()
	for index := 0; index < 8; index++ {
		for _, execution := range []struct {
			id, call, kind string
		}{
			{id: "execution-normal", call: "call-normal", kind: networkprovenance.ActivityKindNormal},
			{id: "execution-fuzz", call: "call-fuzz", kind: networkprovenance.ActivityKindFuzz},
		} {
			item, messages := compactTestTransaction(index, startedAt.Add(time.Duration(index)*time.Millisecond))
			item.ID = execution.id + fmt.Sprintf("-%02d", index)
			item.ExecutionID = execution.id
			item.ToolCallID = execution.call
			item.ActivityScopeID = execution.call
			item.AttributionStatus = networkprovenance.AttributionVerified
			item.DeclaredActivityKind = execution.kind
			messages[0].TransactionID = item.ID
			if err := sink.Write(context.Background(), item, messages); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 2 {
		t.Fatalf("captured %d provenance groups, want 2: %#v", len(captured), captured)
	}
	kinds := map[string]traffic.Transaction{}
	for _, item := range captured {
		kinds[item.ExecutionID] = item
	}
	if normal := kinds["execution-normal"]; normal.AggregateKind != AggregateKindPathSweep || normal.DeclaredActivityKind != networkprovenance.ActivityKindNormal || normal.AggregateCount != 8 {
		t.Fatalf("normal execution was misclassified or merged: %#v", normal)
	}
	if fuzz := kinds["execution-fuzz"]; fuzz.AggregateKind != AggregateKindWebFuzz || fuzz.DeclaredActivityKind != networkprovenance.ActivityKindFuzz || fuzz.AggregateCount != 8 {
		t.Fatalf("declared fuzz execution = %#v", fuzz)
	}
}

func TestCompactingSinkAggregationModes(t *testing.T) {
	for _, test := range []struct {
		name, mode, kind, attribution string
		want                          int
	}{
		{name: "all normal", mode: AggregationModeAll, kind: networkprovenance.ActivityKindNormal, attribution: networkprovenance.AttributionVerified, want: 1},
		{name: "tools normal", mode: AggregationModeTools, kind: networkprovenance.ActivityKindNormal, attribution: networkprovenance.AttributionVerified, want: 20},
		{name: "tools verified fuzz", mode: AggregationModeTools, kind: networkprovenance.ActivityKindFuzz, attribution: networkprovenance.AttributionVerified, want: 1},
		{name: "tools unattributed fuzz", mode: AggregationModeTools, kind: networkprovenance.ActivityKindFuzz, attribution: networkprovenance.AttributionUnattributed, want: 20},
		{name: "none fuzz", mode: AggregationModeNone, kind: networkprovenance.ActivityKindFuzz, attribution: networkprovenance.AttributionVerified, want: 20},
	} {
		t.Run(test.name, func(t *testing.T) {
			var captured []traffic.Transaction
			sink, err := NewCompactingSink(func(_ context.Context, item traffic.Transaction, _ []traffic.Message) error {
				captured = append(captured, item)
				return nil
			}, CompactConfig{IdleWindow: time.Hour, CountThreshold: 8, DistinctThreshold: 6})
			if err != nil {
				t.Fatal(err)
			}
			if err := sink.SetAggregationMode(context.Background(), test.mode); err != nil {
				t.Fatal(err)
			}
			startedAt := time.Now().UTC()
			for index := 0; index < 20; index++ {
				item, messages := compactTestTransaction(index, startedAt.Add(time.Duration(index)*time.Millisecond))
				item.RuntimeInstanceID = "runtime-01"
				item.AgentID = "agent-01"
				item.ToolName = "scanner"
				item.ToolCallID = "call-01"
				item.ActivityScopeID = "scope-01"
				item.AttributionStatus = test.attribution
				item.DeclaredActivityKind = test.kind
				if err := sink.Write(context.Background(), item, messages); err != nil {
					t.Fatal(err)
				}
			}
			if err := sink.Close(); err != nil {
				t.Fatal(err)
			}
			if len(captured) != test.want {
				t.Fatalf("captured %d records, want %d: %#v", len(captured), test.want, captured)
			}
		})
	}
}

func TestCompactingSinkModeSwitchFlushesOldBatch(t *testing.T) {
	var captured []traffic.Transaction
	sink, err := NewCompactingSink(func(_ context.Context, item traffic.Transaction, _ []traffic.Message) error {
		captured = append(captured, item)
		return nil
	}, CompactConfig{IdleWindow: time.Hour, CountThreshold: 4, DistinctThreshold: 4})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC()
	for index := 0; index < 4; index++ {
		item, messages := compactTestTransaction(index, start.Add(time.Duration(index)*time.Millisecond))
		if err := sink.Write(context.Background(), item, messages); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.SetAggregationMode(context.Background(), AggregationModeNone); err != nil {
		t.Fatal(err)
	}
	item, messages := compactTestTransaction(9, start.Add(time.Second))
	if err := sink.Write(context.Background(), item, messages); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 2 || captured[0].AggregateCount != 4 || captured[1].AggregateCount != 0 {
		t.Fatalf("mode switch records = %#v", captured)
	}
}

func TestCompactingSinkModeSwitchFailureKeepsOldMode(t *testing.T) {
	fail := true
	sink, err := NewCompactingSink(func(_ context.Context, _ traffic.Transaction, _ []traffic.Message) error {
		if fail {
			return errors.New("synthetic persistence failure")
		}
		return nil
	}, CompactConfig{IdleWindow: time.Hour, CountThreshold: 2, DistinctThreshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	item, messages := compactTestTransaction(1, time.Now().UTC())
	if err := sink.Write(context.Background(), item, messages); err != nil {
		t.Fatal(err)
	}
	item, messages = compactTestTransaction(2, time.Now().UTC().Add(time.Millisecond))
	if err := sink.Write(context.Background(), item, messages); err != nil {
		t.Fatal(err)
	}
	if err := sink.SetAggregationMode(context.Background(), AggregationModeNone); err == nil {
		t.Fatal("mode switch unexpectedly succeeded")
	}
	if sink.mode != AggregationModeAll {
		t.Fatalf("mode after failed switch = %q", sink.mode)
	}
	fail = false
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}
