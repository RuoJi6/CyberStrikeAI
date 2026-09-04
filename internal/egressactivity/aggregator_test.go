package egressactivity

import (
	"fmt"
	"testing"
	"time"

	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/networkprovenance"
)

func TestAggregatorReleasesOrdinaryTrafficUnchanged(t *testing.T) {
	start := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	aggregator := New(DefaultConfig())
	for index := 0; index < 3; index++ {
		if got := aggregator.Observe(activityFixture(start.Add(time.Duration(index)*100*time.Millisecond), egress.ActivityRequestHTTP, "example.com", 80, "/normal")); len(got) != 0 {
			t.Fatalf("early output = %#v", got)
		}
	}
	got := aggregator.FlushExpired(start.Add(3 * time.Second))
	if len(got) != 3 {
		t.Fatalf("ordinary output count = %d", len(got))
	}
	for _, event := range got {
		if event.AggregateCount != 0 {
			t.Fatalf("ordinary event was aggregated: %#v", event)
		}
	}
}

func TestAggregatorCompactsWebFuzzToFirstSampleAndCount(t *testing.T) {
	start := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	aggregator := New(DefaultConfig())
	for index := 0; index < 12; index++ {
		event := activityFixture(start.Add(time.Duration(index)*50*time.Millisecond), egress.ActivityRequestHTTP, "target.example", 80, fmt.Sprintf("/FUZZ-%d", index))
		event.BytesUp, event.BytesDown = 10, 20
		event.Provenance.DeclaredActivityKind = networkprovenance.ActivityKindFuzz
		if got := aggregator.Observe(event); len(got) != 0 {
			t.Fatalf("early output = %#v", got)
		}
	}
	got := aggregator.FlushExpired(start.Add(4 * time.Second))
	if len(got) != 1 || got[0].AggregateCount != 12 || got[0].AggregateKind != "web-fuzz" || got[0].Path != "/FUZZ-0" {
		t.Fatalf("aggregate = %#v", got)
	}
	if got[0].BytesUp != 120 || got[0].BytesDown != 240 || got[0].AggregateDistinctVariants != 12 {
		t.Fatalf("aggregate metrics = %#v", got[0])
	}
}

func TestAggregatorDetectsTCPPortScanAndConnectionBurstWithoutToolName(t *testing.T) {
	start := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	portScan := New(DefaultConfig())
	for index := 0; index < 6; index++ {
		event := activityFixture(start.Add(time.Duration(index)*40*time.Millisecond), egress.ActivityRequestTCP, "47.116.200.74", 20+index, "")
		portScan.Observe(event)
	}
	got := portScan.FlushAll()
	if len(got) != 1 || got[0].AggregateKind != "port-scan" || got[0].AggregateDistinctPorts != 6 {
		t.Fatalf("port scan aggregate = %#v", got)
	}

	loginBurst := New(DefaultConfig())
	for index := 0; index < 8; index++ {
		loginBurst.Observe(activityFixture(start.Add(time.Duration(index)*80*time.Millisecond), egress.ActivityRequestTCP, "mysql.internal", 3306, ""))
	}
	got = loginBurst.FlushAll()
	if len(got) != 1 || got[0].AggregateKind != "connection-burst" || got[0].AggregateCount != 8 {
		t.Fatalf("connection burst aggregate = %#v", got)
	}
}

func TestAggregatorCompactsSlowTCPFuzzByOccurrenceWindow(t *testing.T) {
	start := time.Date(2026, 8, 26, 8, 12, 36, 0, time.UTC)
	// This pattern mirrors a paced SSH/MySQL-style security check: requests
	// arrive in small clusters and no single 750ms group reaches the threshold.
	offsets := []time.Duration{
		0, 390 * time.Millisecond, 392 * time.Millisecond, 395 * time.Millisecond,
		400 * time.Millisecond, 12*time.Second + 800*time.Millisecond,
		12*time.Second + 820*time.Millisecond, 12*time.Second + 840*time.Millisecond,
		25 * time.Second, 25*time.Second + 30*time.Millisecond,
	}
	for _, replay := range []bool{false, true} {
		name := "live"
		if replay {
			name = "replay"
		}
		t.Run(name, func(t *testing.T) {
			aggregator := New(DefaultConfig())
			receivedAt := start.Add(time.Hour)
			for index, offset := range offsets {
				event := activityFixture(start.Add(offset), egress.ActivityRequestTCP, "47.116.200.74", 22, "")
				observedAt := event.Timestamp
				if replay {
					observedAt = receivedAt.Add(time.Duration(index) * 10 * time.Millisecond)
				}
				if got := aggregator.ObserveAt(event, observedAt); len(got) != 0 {
					t.Fatalf("event %d flushed before slow behaviour became idle: %#v", index, got)
				}
			}
			flushAt := offsets[len(offsets)-1] + DefaultConfig().SlowIdleWindow + time.Millisecond
			if replay {
				flushAt = time.Hour + time.Duration(len(offsets))*10*time.Millisecond + DefaultConfig().SlowIdleWindow
			}
			got := aggregator.FlushExpired(start.Add(flushAt))
			if len(got) != 1 || got[0].AggregateCount != int64(len(offsets)) || got[0].AggregateKind != "connection-burst" {
				t.Fatalf("slow TCP aggregate = %#v", got)
			}
		})
	}
}

func TestAggregatorSplitsSlowTCPBatchesByOccurrenceGapDuringReplay(t *testing.T) {
	start := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	receivedAt := start.Add(time.Hour)
	aggregator := New(DefaultConfig())
	var output []egress.ActivityEvent
	for index := 0; index < 8; index++ {
		event := activityFixture(start.Add(time.Duration(index)*time.Second), egress.ActivityRequestTCP, "47.116.200.74", 22, "")
		output = append(output, aggregator.ObserveAt(event, receivedAt.Add(time.Duration(index)*time.Millisecond))...)
	}
	for index := 0; index < 8; index++ {
		event := activityFixture(start.Add(30*time.Second+time.Duration(index)*time.Second), egress.ActivityRequestTCP, "47.116.200.74", 22, "")
		output = append(output, aggregator.ObserveAt(event, receivedAt.Add(time.Duration(8+index)*time.Millisecond))...)
	}
	output = append(output, aggregator.FlushAll()...)
	if len(output) != 2 || output[0].AggregateCount != 8 || output[1].AggregateCount != 8 {
		t.Fatalf("occurrence-separated replay batches = %#v", output)
	}
}

func TestAggregatorUsesReceiptTimeForDelayedOutOfOrderGatewayEvents(t *testing.T) {
	config := DefaultConfig()
	config.IdleWindow = 500 * time.Millisecond
	aggregator := New(config)
	occurredAt := time.Date(2026, 8, 26, 6, 52, 26, 0, time.UTC)
	receivedAt := occurredAt.Add(5 * time.Second)

	// The gateway reports the original request time only after each upstream
	// attempt times out. Delivery order differs from occurrence order, but all
	// events still belong to one observed burst.
	for index := 0; index < 8; index++ {
		event := activityFixture(
			occurredAt.Add(time.Duration(7-index)*time.Millisecond),
			egress.ActivityRequestHTTP,
			"47.116.200.74",
			80,
			fmt.Sprintf("/delayed-fuzz-%d", index),
		)
		event.Provenance.DeclaredActivityKind = networkprovenance.ActivityKindFuzz
		if got := aggregator.ObserveAt(event, receivedAt.Add(time.Duration(index)*10*time.Millisecond)); len(got) != 0 {
			t.Fatalf("event %d flushed before the observed burst was idle: %#v", index, got)
		}
	}

	got := aggregator.FlushExpired(receivedAt.Add(time.Second))
	if len(got) != 1 {
		t.Fatalf("delayed gateway burst produced %d rows, want 1", len(got))
	}
	if got[0].AggregateCount != 8 || got[0].AggregateKind != "web-fuzz" {
		t.Fatalf("unexpected aggregate: %#v", got[0])
	}
	if got[0].AggregateFirstAt == nil || !got[0].AggregateFirstAt.Equal(occurredAt) {
		t.Fatalf("aggregate first occurrence = %v, want %v", got[0].AggregateFirstAt, occurredAt)
	}
	lastOccurrence := occurredAt.Add(7 * time.Millisecond)
	if got[0].AggregateLastAt == nil || !got[0].AggregateLastAt.Equal(lastOccurrence) {
		t.Fatalf("aggregate last occurrence = %v, want %v", got[0].AggregateLastAt, lastOccurrence)
	}
}

func TestAggregatorSeparatesConcurrentNormalAndDeclaredFuzzScopes(t *testing.T) {
	start := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	aggregator := New(Config{IdleWindow: time.Second, SlowIdleWindow: time.Second, MaximumBatchAge: time.Minute, CountThreshold: 4, DistinctThreshold: 4})
	for index := 0; index < 8; index++ {
		for _, scope := range []struct {
			execution, call, kind string
		}{
			{execution: "execution-normal", call: "call-normal", kind: networkprovenance.ActivityKindNormal},
			{execution: "execution-fuzz", call: "call-fuzz", kind: networkprovenance.ActivityKindFuzz},
		} {
			event := activityFixture(start.Add(time.Duration(index)*time.Millisecond), egress.ActivityRequestHTTPS, "same.example", 443, fmt.Sprintf("/path-%d", index))
			event.Provenance = networkprovenance.NetworkProvenanceV1{
				ConversationID: "conversation", RuntimeMode: networkprovenance.RuntimeModeContainer,
				RuntimeGeneration: 2, RuntimeInstanceID: "gateway", AgentID: "agent", ToolName: "curl",
				ExecutionID: scope.execution, ToolCallID: scope.call, ActivityScopeID: scope.call,
				AttributionStatus: networkprovenance.AttributionVerified, DeclaredActivityKind: scope.kind,
			}.Normalized()
			aggregator.Observe(event)
		}
	}
	got := aggregator.FlushAll()
	if len(got) != 2 {
		t.Fatalf("got %d provenance groups, want 2: %#v", len(got), got)
	}
	byExecution := map[string]egress.ActivityEvent{}
	for _, event := range got {
		byExecution[event.Provenance.ExecutionID] = event
	}
	if normal := byExecution["execution-normal"]; normal.AggregateKind != "path-sweep" || normal.Provenance.DeclaredActivityKind != networkprovenance.ActivityKindNormal || normal.AggregateCount != 8 {
		t.Fatalf("normal execution was misclassified or merged: %#v", normal)
	}
	if fuzz := byExecution["execution-fuzz"]; fuzz.AggregateKind != "web-fuzz" || fuzz.Provenance.DeclaredActivityKind != networkprovenance.ActivityKindFuzz || fuzz.AggregateCount != 8 {
		t.Fatalf("declared fuzz execution = %#v", fuzz)
	}
}

func activityFixture(at time.Time, requestType, domain string, port int, path string) egress.ActivityEvent {
	return egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: at, RequestType: requestType, Domain: domain, Port: port,
		Decision: egress.ActivityDecisionAllowed, Outcome: "forwarded", Method: "GET", Path: path,
		SnapshotID: "11111111-1111-4111-8111-111111111111",
	}
}

func TestShouldAggregateModeMatrix(t *testing.T) {
	verifiedFuzz := activityFixture(time.Now().UTC(), egress.ActivityRequestHTTPS, "example.test", 443, "/FUZZ")
	verifiedFuzz.Provenance = networkprovenance.NetworkProvenanceV1{
		ConversationID: "conversation", RuntimeMode: networkprovenance.RuntimeModeContainer,
		RuntimeInstanceID: "runtime", AgentID: "agent", ToolName: "scanner",
		ExecutionID: "execution", ToolCallID: "call", ActivityScopeID: "scope",
		AttributionStatus: networkprovenance.AttributionVerified, DeclaredActivityKind: networkprovenance.ActivityKindFuzz,
	}.Normalized()
	normal := verifiedFuzz
	normal.Provenance.DeclaredActivityKind = networkprovenance.ActivityKindNormal
	if !ShouldAggregate(AggregationModeAll, normal) {
		t.Fatal("all must aggregate normal HTTP")
	}
	if ShouldAggregate(AggregationModeTools, normal) {
		t.Fatal("tools must not aggregate normal HTTP")
	}
	if !ShouldAggregate(AggregationModeTools, verifiedFuzz) {
		t.Fatal("tools must aggregate verified declared fuzz")
	}
	for _, requestType := range []string{
		egress.ActivityRequestTCP, egress.ActivityRequestUDP, egress.ActivityRequestDNS, egress.ActivityRequestICMP,
	} {
		event := normal
		event.RequestType = requestType
		if !ShouldAggregate(AggregationModeTools, event) {
			t.Fatalf("tools must keep behavioural aggregation for container %s", requestType)
		}
		if ShouldAggregate(AggregationModeNone, event) {
			t.Fatalf("none must not aggregate %s", requestType)
		}
	}
}
