package trafficspool

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/traffic"
)

func TestAggregationPolicyAtomicWriteAndSafeFallback(t *testing.T) {
	directory, err := NewDirectory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.WriteAggregationPolicy("conversation-01", AggregationModeTools, true); err != nil {
		t.Fatal(err)
	}
	path, err := directory.ConversationPath("conversation-01")
	if err != nil {
		t.Fatal(err)
	}
	if got := loadAggregationPolicy(path); got.Mode != AggregationModeTools || !got.RecordUpstreamFailures {
		t.Fatalf("policy = %#v", got)
	}
	if err := os.WriteFile(filepath.Join(path, AggregationPolicyFilename), []byte(`{"version":"broken","mode":"all"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := loadAggregationPolicy(path); got.Mode != AggregationModeNone || got.RecordUpstreamFailures {
		t.Fatalf("invalid policy fallback = %#v", got)
	}
	if matches, _ := filepath.Glob(filepath.Join(path, ".aggregation-policy-*.tmp")); len(matches) != 0 {
		t.Fatalf("temporary policies remain: %#v", matches)
	}
}

func TestWatchAggregationPolicyHotSwitchesFutureTraffic(t *testing.T) {
	directory, err := NewDirectory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path, err := directory.ConversationPath("conversation-01")
	if err != nil {
		t.Fatal(err)
	}
	var captured []traffic.Transaction
	sink, err := NewCompactingSink(func(_ context.Context, item traffic.Transaction, _ []traffic.Message) error {
		captured = append(captured, item)
		return nil
	}, CompactConfig{IdleWindow: time.Hour, CountThreshold: 2, DistinctThreshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- WatchAggregationPolicy(ctx, path, sink) }()
	t.Cleanup(func() { cancel(); <-done; _ = sink.Close() })
	time.Sleep(20 * time.Millisecond)
	item, messages := compactTestTransaction(1, time.Now().UTC())
	if err := sink.Write(context.Background(), item, messages); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 1 {
		t.Fatalf("missing policy must preserve a complete record: %#v", captured)
	}
	if err := directory.WriteAggregationPolicy("conversation-01", AggregationModeAll, false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	for index := 2; index < 4; index++ {
		item, messages = compactTestTransaction(index, time.Now().UTC())
		if err := sink.Write(context.Background(), item, messages); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.SetAggregationMode(context.Background(), AggregationModeNone); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 2 || captured[1].AggregateCount != 2 {
		t.Fatalf("hot-switched records = %#v", captured)
	}
}
