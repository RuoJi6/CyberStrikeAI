package container

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net/netip"
	"strings"

	mobynetwork "github.com/moby/moby/api/types/network"
)

const (
	// Docker's implicit address pools commonly allocate /16 or /20 networks.
	// Two isolated networks per conversation can therefore exhaust the daemon
	// after only a small number of conversations. Allocate compact, deterministic
	// subnets from the shared-address space instead. A /29 has enough addresses
	// for the agent, gateway and policy DNS while keeping 524,288 slots available.
	managedNetworkPoolPrefixBits = 10
	managedNetworkSubnetBits     = 29
	managedNetworkCreateAttempts = 64
)

var managedNetworkPool = netip.MustParsePrefix("100.64.0.0/10")

func managedNetworkIPAM(resourceKind, logicalID string, attempt int) *mobynetwork.IPAM {
	subnet := managedNetworkSubnet(resourceKind, logicalID, attempt)
	return &mobynetwork.IPAM{
		Driver: "default",
		Config: []mobynetwork.IPAMConfig{{Subnet: subnet}},
	}
}

func managedNetworkSubnet(resourceKind, logicalID string, attempt int) netip.Prefix {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.TrimSpace(resourceKind)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.TrimSpace(logicalID)))

	const slots = uint64(1 << (managedNetworkSubnetBits - managedNetworkPoolPrefixBits))
	start := h.Sum64() % slots
	// The slot count is a power of two, so an odd step visits every slot.
	step := ((h.Sum64() >> 32) | 1) % slots
	if step == 0 {
		step = 1
	}
	index := (start + uint64(max(attempt, 0))*step) % slots

	baseBytes := managedNetworkPool.Addr().As4()
	base := binary.BigEndian.Uint32(baseBytes[:])
	offset := uint32(index << (32 - managedNetworkSubnetBits))
	var subnetBytes [4]byte
	binary.BigEndian.PutUint32(subnetBytes[:], base+offset)
	return netip.PrefixFrom(netip.AddrFrom4(subnetBytes), managedNetworkSubnetBits).Masked()
}

func managedNetworkAddressConflict(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "pool overlaps") ||
		strings.Contains(message, "address pool") ||
		strings.Contains(message, "fully subnetted") ||
		strings.Contains(message, "non-overlapping ipv4")
}

func managedNetworkAllocationError(name string, err error) error {
	return fmt.Errorf("create managed network %s after %d address attempts: %w", name, managedNetworkCreateAttempts, err)
}
