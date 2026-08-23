package egressaudit

import (
	"context"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	containerruntime "cyberstrike-ai/internal/runtime/container"

	"go.uber.org/zap"
)

type collectorTestStore struct {
	mu      sync.Mutex
	targets []database.EgressAuditRuntimeTarget
	events  []egress.ActivityEvent
}

func (s *collectorTestStore) ApplyEgressHealthEvent(_ context.Context, _ database.EgressAuditRuntimeTarget, event egress.ActivityEvent) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return true, nil
}

func (s *collectorTestStore) ListRunningEgressAuditRuntimeTargets(context.Context) ([]database.EgressAuditRuntimeTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]database.EgressAuditRuntimeTarget(nil), s.targets...), nil
}

func (s *collectorTestStore) AppendEgressNetworkAuditEvent(_ context.Context, _ database.EgressAuditRuntimeTarget, event egress.ActivityEvent) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return true, nil
}

func (s *collectorTestStore) setTargets(targets []database.EgressAuditRuntimeTarget) {
	s.mu.Lock()
	s.targets = append([]database.EgressAuditRuntimeTarget(nil), targets...)
	s.mu.Unlock()
}

func (s *collectorTestStore) eventCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

type collectorTestStreamer struct {
	mu      sync.Mutex
	calls   int
	options []containerruntime.ActivityStreamOptions
	started chan struct{}
	stopped chan struct{}
}

func (s *collectorTestStreamer) StreamEgressActivity(ctx context.Context, _ containerruntime.RuntimeSpec, options containerruntime.ActivityStreamOptions, sink containerruntime.RuntimeActivitySink) error {
	s.mu.Lock()
	s.calls++
	s.options = append(s.options, options)
	s.mu.Unlock()
	s.started <- struct{}{}
	if err := sink(egress.ActivityEvent{Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), RequestType: egress.ActivityRequestDNS, Domain: "audit.example", Decision: egress.ActivityDecisionAllowed, Outcome: "resolved"}); err != nil {
		return err
	}
	<-ctx.Done()
	s.stopped <- struct{}{}
	return nil
}

func TestCollectorReconcilesIndependentAllLogStreams(t *testing.T) {
	target := collectorTargetFixture()
	store := &collectorTestStore{targets: []database.EgressAuditRuntimeTarget{target}}
	streamer := &collectorTestStreamer{started: make(chan struct{}, 2), stopped: make(chan struct{}, 2)}
	collector, err := NewCollector(store, streamer, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := collector.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	waitCollectorSignal(t, streamer.started, "stream start")
	waitCollectorCondition(t, func() bool { return store.eventCount() == 1 }, "persisted event")
	if collector.ActiveStreams() != 1 {
		t.Fatalf("active streams = %d", collector.ActiveStreams())
	}
	if err := collector.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	streamer.mu.Lock()
	if streamer.calls != 1 || len(streamer.options) != 1 || !streamer.options[0].All || streamer.options[0].Tail != 0 {
		t.Fatalf("stream calls/options = %d %#v", streamer.calls, streamer.options)
	}
	streamer.mu.Unlock()

	store.setTargets(nil)
	if err := collector.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	waitCollectorSignal(t, streamer.stopped, "stream stop")
	waitCollectorCondition(t, func() bool { return collector.ActiveStreams() == 0 }, "collector removal")
}

func TestCollectorPeriodicShutdownCancelsAndWaitsForStreams(t *testing.T) {
	store := &collectorTestStore{targets: []database.EgressAuditRuntimeTarget{collectorTargetFixture()}}
	streamer := &collectorTestStreamer{started: make(chan struct{}, 2), stopped: make(chan struct{}, 2)}
	collector, err := NewCollector(store, streamer, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- collector.RunPeriodic(ctx, time.Hour, nil) }()
	waitCollectorSignal(t, streamer.started, "periodic stream start")
	cancel()
	waitCollectorSignal(t, streamer.stopped, "periodic stream stop")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("collector periodic shutdown timed out")
	}
	if collector.ActiveStreams() != 0 {
		t.Fatalf("active streams after shutdown = %d", collector.ActiveStreams())
	}
}

func collectorTargetFixture() database.EgressAuditRuntimeTarget {
	return database.EgressAuditRuntimeTarget{
		ConversationTitle: "collector target",
		Record: containerruntime.InitializationRecord{
			ConversationID: "conversation-a", ProviderID: "provider-a", RuntimeGeneration: 1,
			Status: containerruntime.InitializationCreated, RuntimeStatus: containerruntime.StatusRunning,
			Spec: containerruntime.RuntimeSpec{
				ConversationID: "conversation-a",
				EgressGateway: &containerruntime.EgressGatewaySpec{BoundarySnapshot: &containerruntime.EgressBoundarySnapshotSpec{
					ID: "11111111-1111-4111-8111-111111111111", SHA256: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
				}},
			},
		},
	}
}

func waitCollectorSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitCollectorCondition(t *testing.T, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}
