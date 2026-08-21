package egress

import (
	"context"
	"testing"
	"time"
)

func TestBootstrapGatewayRunsUntilCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx) }()
	select {
	case err := <-done:
		t.Fatalf("gateway exited before cancellation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("gateway shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway did not stop after cancellation")
	}
}

func TestBootstrapGatewayRejectsNilContext(t *testing.T) {
	if err := Run(nil); err == nil {
		t.Fatal("nil context was accepted")
	}
}
