//go:build linux

package egress

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"cyberstrike-ai/internal/boundary"
	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
)

type packetGateway struct {
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
}

func startPacketGateway(ctx context.Context, policy *boundary.Policy, options PacketOptions) (*packetGateway, error) {
	filter, err := newPacketFilter(policy, options)
	if err != nil {
		return nil, err
	}
	queueNumber := options.QueueNumber
	if queueNumber == 0 {
		queueNumber = defaultPacketQueueNumber
	}
	queue, err := nfqueue.Open(&nfqueue.Config{
		NfQueue: queueNumber, MaxPacketLen: maxPacketCaptureBytes, MaxQueueLen: maxPacketQueueLength,
		Copymode: nfqueue.NfQnlCopyPacket, WriteTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		return nil, fmt.Errorf("open L3/L4 policy packet queue: %w", err)
	}
	if err := queue.SetOption(netlink.NoENOBUFS, true); err != nil {
		_ = queue.Close()
		return nil, fmt.Errorf("configure L3/L4 policy packet queue: %w", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	queueErrors := make(chan error, 1)
	callback := func(attribute nfqueue.Attribute) int {
		if attribute.PacketID == nil {
			return 0
		}
		verdict := nfqueue.NfDrop
		if attribute.Payload != nil {
			if allowed, _, _ := filter.evaluate(*attribute.Payload); allowed {
				verdict = nfqueue.NfAccept
			}
		}
		if verdictErr := queue.SetVerdict(*attribute.PacketID, verdict); verdictErr != nil {
			select {
			case queueErrors <- verdictErr:
			default:
			}
			return 1
		}
		return 0
	}
	if err := queue.RegisterWithErrorFunc(runCtx, callback, func(queueErr error) int {
		if runCtx.Err() == nil {
			select {
			case queueErrors <- queueErr:
			default:
			}
		}
		return 1
	}); err != nil {
		cancel()
		_ = queue.Close()
		return nil, fmt.Errorf("register L3/L4 policy packet queue: %w", err)
	}
	if err := installPacketFirewall(runCtx, queueNumber); err != nil {
		cancel()
		_ = queue.Close()
		return nil, err
	}
	gateway := &packetGateway{cancel: cancel, done: make(chan error, 1)}
	go func() {
		var result error
		select {
		case <-runCtx.Done():
		case queueErr := <-queueErrors:
			result = fmt.Errorf("L3/L4 policy packet queue stopped: %w", queueErr)
		}
		_ = removePacketFirewall()
		cancel()
		_ = queue.Close()
		gateway.done <- result
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
	if g == nil {
		closed := make(chan error)
		close(closed)
		return closed
	}
	return g.done
}

func installPacketFirewall(ctx context.Context, queueNumber uint16) error {
	_ = removePacketFirewall()
	rules := `table inet cyberstrike {
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    ct state invalid drop
    ip protocol tcp ct state new queue num ` + strconv.Itoa(int(queueNumber)) + `
    ip protocol udp ct state new queue num ` + strconv.Itoa(int(queueNumber)) + `
    ip protocol icmp ct state new queue num ` + strconv.Itoa(int(queueNumber)) + `
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname != "lo" masquerade
  }
}`
	command := exec.CommandContext(ctx, "nft", "-f", "-")
	command.Stdin = bytes.NewBufferString(rules)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("install fail-closed L3/L4 gateway rules: %w: %s", err, bytes.TrimSpace(output))
	}
	return nil
}

func removePacketFirewall() error {
	command := exec.Command("nft", "delete", "table", "inet", "cyberstrike")
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("remove L3/L4 gateway rules: %w: %s", err, bytes.TrimSpace(output))
	}
	return nil
}
