package egress

import (
	"context"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
)

func TestZeroTrafficRatesDisableHTTPTCPAndUDPPacers(t *testing.T) {
	policy, err := boundary.NewPolicyWithDefault(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := NewProxy(policy, ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.httpPacer != nil || proxy.tcpPacer != nil || proxy.udpPacer != nil {
		t.Fatalf("zero traffic rates created proxy pacers: http=%v tcp=%v udp=%v", proxy.httpPacer, proxy.tcpPacer, proxy.udpPacer)
	}
	filter, err := newPacketFilter(policy, PacketOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if filter.tcpPacer != nil || filter.udpPacer != nil {
		t.Fatalf("zero traffic rates created packet pacers: tcp=%v udp=%v", filter.tcpPacer, filter.udpPacer)
	}
}

func TestTrafficPacerSpacesRequestsAndHonorsCancellation(t *testing.T) {
	pacer := newTrafficPacer(20)
	started := time.Now()
	if err := pacer.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := pacer.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 40*time.Millisecond {
		t.Fatalf("two reservations completed too quickly: %s", elapsed)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pacer.Wait(canceled); err == nil {
		t.Fatal("canceled wait unexpectedly succeeded")
	}
}

func TestValidateTrafficLimits(t *testing.T) {
	if err := ValidateTrafficLimits(nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTrafficLimits(&TrafficLimits{}); err == nil {
		t.Fatal("empty enabled limits were accepted")
	}
	if err := ValidateTrafficLimits(&TrafficLimits{TCPConnectionsPerSecond: 10}); err != nil {
		t.Fatal(err)
	}
}
