package container

import (
	"context"
	"testing"

	mobyclient "github.com/moby/moby/client"
)

func TestDockerManagerRecoversOnlyExactOwnedRunningGatewayWithFixedSignal(t *testing.T) {
	spec, root, snapshotPath := snapshotGatewayFixture(t)
	api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01", EgressSnapshotRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.ensureOwnedConversationNetwork(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.ensureOwnedEgressNetwork(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if _, err := api.ContainerStart(context.Background(), "provider-gateway-1", mobyclient.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.ContainerStart(context.Background(), "provider-agent-1", mobyclient.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := manager.RecoverEgressHealth(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if api.killedID != "provider-gateway-1" || api.killOpts.Signal != "SIGHUP" {
		t.Fatalf("recovery signal = id %q options %#v", api.killedID, api.killOpts)
	}

	tampered := spec
	tampered.ConversationID = "other-conversation"
	api.killedID = ""
	if err := manager.RecoverEgressHealth(context.Background(), tampered); err == nil {
		t.Fatal("tampered runtime specification was accepted")
	}
	if api.killedID != "" {
		t.Fatalf("tampered runtime signaled %q", api.killedID)
	}
}
