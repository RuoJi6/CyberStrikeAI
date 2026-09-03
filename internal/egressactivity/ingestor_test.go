package egressactivity

import (
	"context"
	"testing"
	"time"

	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/networkprovenance"
)

func TestIngestorDeduplicatesEventIDsAndFiltersRuntimeMode(t *testing.T) {
	ingestor := NewIngestor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	containerStream := ingestor.Subscribe(ctx, "conversation", networkprovenance.RuntimeModeContainer, 0)
	hostStream := ingestor.Subscribe(ctx, "conversation", networkprovenance.RuntimeModeHostMITM, 0)
	item := IngestedActivity{ConversationID: "conversation", Event: egress.ActivityEvent{
		EventID: "event-one", Event: egress.ActivityEventName, Timestamp: time.Now().UTC(),
		Provenance: networkprovenance.NetworkProvenanceV1{RuntimeMode: networkprovenance.RuntimeModeContainer},
	}}
	if !ingestor.Publish(item) || ingestor.Publish(item) {
		t.Fatal("event ID dedupe did not accept exactly one event")
	}
	select {
	case got := <-containerStream:
		if got.Event.EventID != "event-one" || got.Event.Provenance.RuntimeMode != networkprovenance.RuntimeModeContainer {
			t.Fatalf("container event = %#v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("container subscriber did not receive event")
	}
	select {
	case got := <-hostStream:
		t.Fatalf("host subscriber received container event: %#v", got)
	case <-time.After(20 * time.Millisecond):
	}
}
