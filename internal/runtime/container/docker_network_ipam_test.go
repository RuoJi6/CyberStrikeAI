package container

import (
	"errors"
	"testing"
)

func TestManagedNetworkSubnetUsesCompactDedicatedPool(t *testing.T) {
	conversation := managedNetworkSubnet(ResourceKindConversationNetwork, "conversation-runtime", 0)
	egress := managedNetworkSubnet(ResourceKindEgressNetwork, "conversation-runtime", 0)

	for name, subnet := range map[string]struct {
		prefixBits int
		contained  bool
	}{
		"conversation": {prefixBits: conversation.Bits(), contained: managedNetworkPool.Contains(conversation.Addr())},
		"egress":       {prefixBits: egress.Bits(), contained: managedNetworkPool.Contains(egress.Addr())},
	} {
		if subnet.prefixBits != managedNetworkSubnetBits || !subnet.contained {
			t.Fatalf("%s subnet is outside the managed /%d pool: %#v", name, managedNetworkSubnetBits, subnet)
		}
	}
	if conversation == egress {
		t.Fatalf("conversation and egress networks reused one subnet: %s", conversation)
	}
	if next := managedNetworkSubnet(ResourceKindConversationNetwork, "conversation-runtime", 1); next == conversation {
		t.Fatalf("collision retry did not advance from %s", conversation)
	}
	if repeat := managedNetworkSubnet(ResourceKindConversationNetwork, "conversation-runtime", 0); repeat != conversation {
		t.Fatalf("subnet allocation is not deterministic: %s != %s", repeat, conversation)
	}
}

func TestManagedNetworkAddressConflictRecognition(t *testing.T) {
	for _, message := range []string{
		"Pool overlaps with other one on this address space",
		"all predefined address pools have been fully subnetted",
		"could not find an available, non-overlapping IPv4 address pool",
	} {
		if !managedNetworkAddressConflict(errors.New(message)) {
			t.Fatalf("address conflict was not recognized: %q", message)
		}
	}
	if managedNetworkAddressConflict(errors.New("network with name already exists")) {
		t.Fatal("network name conflict was incorrectly treated as an address conflict")
	}
}
