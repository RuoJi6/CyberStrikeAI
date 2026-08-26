package egress

import (
	"context"
	"errors"
	"sync"
	"time"
)

const MaxTrafficRatePerSecond = 100_000

type TrafficLimits struct {
	HTTPRequestsPerSecond   int
	TCPConnectionsPerSecond int
	UDPDatagramsPerSecond   int
}

func ValidateTrafficLimits(limits *TrafficLimits) error {
	if limits == nil {
		return nil
	}
	for _, rate := range []int{limits.HTTPRequestsPerSecond, limits.TCPConnectionsPerSecond, limits.UDPDatagramsPerSecond} {
		if rate < 0 || rate > MaxTrafficRatePerSecond {
			return errors.New("egress traffic rates must be between 0 and 100000 per second")
		}
	}
	if limits.HTTPRequestsPerSecond == 0 && limits.TCPConnectionsPerSecond == 0 && limits.UDPDatagramsPerSecond == 0 {
		return errors.New("egress traffic limits require at least one enabled protocol")
	}
	return nil
}

type trafficPacer struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func newTrafficPacer(rate int) *trafficPacer {
	if rate <= 0 {
		return nil
	}
	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	return &trafficPacer{interval: interval}
}

func (p *trafficPacer) Wait(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now()
	p.mu.Lock()
	reserved := now
	if p.next.After(now) {
		reserved = p.next
	}
	p.next = reserved.Add(p.interval)
	p.mu.Unlock()
	if !reserved.After(now) {
		return nil
	}
	timer := time.NewTimer(time.Until(reserved))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
