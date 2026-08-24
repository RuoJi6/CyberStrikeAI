//go:build !linux

package egress

import (
	"context"
	"sync"

	"cyberstrike-ai/internal/boundary"
)

// Unit tests for policy listeners run on developer platforms as well. Packet
// forwarding is Linux-only and is exercised in the ARM64 Docker integration
// suite, while this no-op preserves the portable HTTP/SOCKS/DNS test surface.
type packetGateway struct {
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
}

func startPacketGateway(ctx context.Context, policy *boundary.Policy, options PacketOptions) (*packetGateway, error) {
	if _, err := newPacketFilter(policy, options); err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	gateway := &packetGateway{cancel: cancel, done: make(chan error, 1)}
	go func() {
		<-runCtx.Done()
		gateway.done <- nil
		close(gateway.done)
	}()
	return gateway, nil
}

func (g *packetGateway) Close() error {
	if g == nil {
		return nil
	}
	g.once.Do(g.cancel)
	return <-g.done
}

func (g *packetGateway) Done() <-chan error {
	return g.done
}
