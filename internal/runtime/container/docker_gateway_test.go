package container

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	mobycontainer "github.com/moby/moby/api/types/container"
	mobyimage "github.com/moby/moby/api/types/image"
	mobynetwork "github.com/moby/moby/api/types/network"
	mobyclient "github.com/moby/moby/client"
)

func TestRuntimeSpecGatewayOmitemptyPreservesLegacySerialization(t *testing.T) {
	spec := creationSpec()
	encoded, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "EgressGateway") {
		t.Fatalf("legacy specification gained a gateway JSON field: %s", encoded)
	}
	const legacyDigest = "sha256:0d776c118690811d8cc9ebb09e51be5de550d03873e84a27890bc978b9776574"
	if actual := RuntimeSpecDigest(spec); actual != legacyDigest {
		t.Fatalf("legacy digest = %q, want %q", actual, legacyDigest)
	}
}

func TestDockerManagerCreatesHardenedPerConversationGatewayTopology(t *testing.T) {
	spec := gatewayCreationSpec()
	api := newSuccessfulGatewayCreationAPI(spec, "instance-01")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := manager.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("create gateway topology: %v", err)
	}
	if runtime.Status != StatusStopped || len(api.createOptsByName) != 2 || api.networkCreateCalls != 2 {
		t.Fatalf("created runtime/topology = %#v / containers=%d networks=%d", runtime, len(api.createOptsByName), api.networkCreateCalls)
	}
	internalName := ConversationNetworkName(spec.ID)
	egressName := EgressNetworkName(spec.ID)
	internalOptions := api.networkCreateOptsByName[internalName]
	egressOptions := api.networkCreateOptsByName[egressName]
	if !internalOptions.Internal || egressOptions.Internal || internalOptions.Driver != "bridge" || egressOptions.Driver != "bridge" {
		t.Fatalf("network options = internal %#v, egress %#v", internalOptions, egressOptions)
	}
	agentOptions := api.createOptsByName[runtimeContainerName(spec.ID)]
	gatewayOptions := api.createOptsByName[EgressGatewayContainerName(spec.ID)]
	if len(agentOptions.NetworkingConfig.EndpointsConfig) != 1 || agentOptions.NetworkingConfig.EndpointsConfig[internalName] == nil || agentOptions.NetworkingConfig.EndpointsConfig[egressName] != nil {
		t.Fatalf("agent network endpoints = %#v", agentOptions.NetworkingConfig)
	}
	if len(gatewayOptions.NetworkingConfig.EndpointsConfig) != 2 || gatewayOptions.NetworkingConfig.EndpointsConfig[internalName] == nil || gatewayOptions.NetworkingConfig.EndpointsConfig[egressName] == nil {
		t.Fatalf("gateway network endpoints = %#v", gatewayOptions.NetworkingConfig)
	}
	if gatewayOptions.HostConfig.NetworkMode != mobycontainer.NetworkMode(internalName) || gatewayOptions.HostConfig.Privileged || !gatewayOptions.HostConfig.ReadonlyRootfs || len(gatewayOptions.HostConfig.CapDrop) != 1 || gatewayOptions.HostConfig.CapDrop[0] != "ALL" || len(gatewayOptions.HostConfig.CapAdd) != 0 || !containsString(gatewayOptions.HostConfig.SecurityOpt, "no-new-privileges") {
		t.Fatalf("gateway security baseline = %#v", gatewayOptions.HostConfig)
	}
	if len(gatewayOptions.HostConfig.Binds) != 0 || len(gatewayOptions.HostConfig.Mounts) != 0 || len(gatewayOptions.HostConfig.PortBindings) != 0 || len(gatewayOptions.HostConfig.Devices) != 0 || len(gatewayOptions.HostConfig.DeviceRequests) != 0 {
		t.Fatalf("gateway gained host or port access: %#v", gatewayOptions.HostConfig)
	}
	if gatewayOptions.Config.User != gatewayUser || gatewayOptions.Config.WorkingDir != "/" || len(gatewayOptions.Config.Entrypoint) != 1 || gatewayOptions.Config.Entrypoint[0] != gatewayBinaryPath || len(gatewayOptions.Config.Cmd) != 0 {
		t.Fatalf("gateway process options = %#v", gatewayOptions.Config)
	}
	if gatewayOptions.HostConfig.Tmpfs["/tmp"] != "rw,nosuid,nodev,mode=1777,noexec,size=16777216" || len(gatewayOptions.HostConfig.Tmpfs) != 1 {
		t.Fatalf("gateway tmpfs = %#v", gatewayOptions.HostConfig.Tmpfs)
	}
	if gatewayOptions.Config.Labels[LabelResourceKind] != ResourceKindEgressGateway || gatewayOptions.Config.Labels[LabelSpecDigest] != RuntimeSpecDigest(spec) {
		t.Fatalf("gateway labels = %#v", gatewayOptions.Config.Labels)
	}
	if len(api.networks[internalName].Containers) != 0 || len(api.networks[egressName].Containers) != 0 {
		t.Fatalf("stopped topology has active attachments: %#v / %#v", api.networks[internalName].Containers, api.networks[egressName].Containers)
	}
}

func TestDockerManagerGatewayLifecycleOrderAndCleanup(t *testing.T) {
	spec := gatewayCreationSpec()
	api := newSuccessfulGatewayCreationAPI(spec, "instance-01")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(context.Background(), spec.ID); err != nil {
		t.Fatalf("start topology: %v", err)
	}
	if len(api.startedIDs) != 2 || api.startedIDs[0] != "provider-gateway-1" || api.startedIDs[1] != "provider-agent-1" {
		t.Fatalf("start order = %#v", api.startedIDs)
	}
	if len(api.networks[ConversationNetworkName(spec.ID)].Containers) != 2 || len(api.networks[EgressNetworkName(spec.ID)].Containers) != 1 {
		t.Fatalf("running attachments = internal %#v, egress %#v", api.networks[ConversationNetworkName(spec.ID)].Containers, api.networks[EgressNetworkName(spec.ID)].Containers)
	}
	if _, err := manager.Stop(context.Background(), spec.ID, StopOptions{}); err != nil {
		t.Fatalf("stop topology: %v", err)
	}
	if len(api.stoppedIDs) != 2 || api.stoppedIDs[0] != "provider-agent-1" || api.stoppedIDs[1] != "provider-gateway-1" {
		t.Fatalf("stop order = %#v", api.stoppedIDs)
	}
	if err := manager.Delete(context.Background(), spec.ID, DeleteOptions{}); err != nil {
		t.Fatalf("delete topology: %v", err)
	}
	if len(api.containerResults) != 0 || len(api.networks) != 0 {
		t.Fatalf("topology survived delete: containers=%#v networks=%#v", api.containerResults, api.networks)
	}
}

func TestDockerManagerGatewayCreationRollbackRemovesEveryNewResource(t *testing.T) {
	spec := gatewayCreationSpec()
	api := newSuccessfulGatewayCreationAPI(spec, "instance-01")
	api.createErrs[runtimeContainerName(spec.ID)] = errors.New("agent create failed")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err == nil {
		t.Fatal("create unexpectedly succeeded")
	}
	if _, exists := api.containerResults[EgressGatewayContainerName(spec.ID)]; exists || len(api.networks) != 0 {
		t.Fatalf("rollback left gateway topology: containers=%#v networks=%#v", api.containerResults, api.networks)
	}
}

func TestDockerManagerGatewayStartFailureRollsBackToStoppedTopology(t *testing.T) {
	spec := gatewayCreationSpec()
	api := newSuccessfulGatewayCreationAPI(spec, "instance-01")
	api.startErrs = map[string]error{"provider-agent-1": errors.New("agent start failed")}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(context.Background(), spec.ID); err == nil {
		t.Fatal("start unexpectedly succeeded")
	}
	observed, err := manager.Inspect(context.Background(), spec.ID)
	if err != nil {
		t.Fatalf("inspect rolled-back topology: %v", err)
	}
	if observed.Status != StatusStopped || len(api.networks[ConversationNetworkName(spec.ID)].Containers) != 0 || len(api.networks[EgressNetworkName(spec.ID)].Containers) != 0 {
		t.Fatalf("start rollback state = %#v / %#v / %#v", observed, api.networks[ConversationNetworkName(spec.ID)].Containers, api.networks[EgressNetworkName(spec.ID)].Containers)
	}
}

func TestDockerManagerGatewayStopFailureRestoresRunningTopology(t *testing.T) {
	spec := gatewayCreationSpec()
	api := newSuccessfulGatewayCreationAPI(spec, "instance-01")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(context.Background(), spec.ID); err != nil {
		t.Fatal(err)
	}
	api.stopErrs = map[string]error{"provider-gateway-1": errors.New("gateway stop failed")}
	if _, err := manager.Stop(context.Background(), spec.ID, StopOptions{}); err == nil {
		t.Fatal("stop unexpectedly succeeded")
	}
	observed, err := manager.Inspect(context.Background(), spec.ID)
	if err != nil {
		t.Fatalf("inspect restored topology: %v", err)
	}
	if observed.Status != StatusRunning || len(api.networks[ConversationNetworkName(spec.ID)].Containers) != 2 || len(api.networks[EgressNetworkName(spec.ID)].Containers) != 1 {
		t.Fatalf("stop rollback state = %#v / %#v / %#v", observed, api.networks[ConversationNetworkName(spec.ID)].Containers, api.networks[EgressNetworkName(spec.ID)].Containers)
	}
}

func TestDockerManagerInspectRejectsGatewaySecurityDrift(t *testing.T) {
	spec := gatewayCreationSpec()
	api := newSuccessfulGatewayCreationAPI(spec, "instance-01")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	gateway := api.containerResults[EgressGatewayContainerName(spec.ID)]
	gateway.Container.HostConfig.Privileged = true
	api.containerResults[EgressGatewayContainerName(spec.ID)] = gateway
	if _, err := manager.Inspect(context.Background(), spec.ID); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("gateway drift error = %v", err)
	}
}

func gatewayCreationSpec() RuntimeSpec {
	spec := creationSpec()
	spec.Security.NetworkMode = NetworkInternal
	spec.EgressGateway = &EgressGatewaySpec{
		Image: ImageReference{
			Repository: "ghcr.io/example/cyberstrike-egress",
			Digest:     "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			Platform:   "linux/arm64",
		},
		Resources: EgressGatewayResources{
			NanoCPUs: 250_000_000, MemoryBytes: 128 << 20, PIDs: 64,
			NoFileSoft: 512, NoFileHard: 1024, TmpfsBytes: 16 << 20,
			LogMaxBytes: 2 << 20, LogMaxFiles: 2,
		},
	}
	return spec
}

func newSuccessfulGatewayCreationAPI(spec RuntimeSpec, ownerID string) *fakeDockerCreationAPI {
	agentID := "provider-agent-1"
	gatewayID := "provider-gateway-1"
	base := newSuccessfulCreationAPI(spec, ownerID, agentID, "")
	agentPinned, _ := pinnedImageReference(spec.Image)
	gatewayPinned, _ := pinnedImageReference(spec.EgressGateway.Image)
	agentImageID := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	gatewayImageID := "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	created := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	agent := base.containerResult
	agent.Container.ID = agentID
	agent.Container.Image = agentImageID
	agent.Container.Config.Image = agentPinned
	agent.Container.NetworkSettings = &mobycontainer.NetworkSettings{Networks: map[string]*mobynetwork.EndpointSettings{
		ConversationNetworkName(spec.ID): {NetworkID: "provider-network-1"},
	}}
	gateway := mobyclient.ContainerInspectResult{Container: mobycontainer.InspectResponse{
		ID: gatewayID, Created: created, Name: "/" + EgressGatewayContainerName(spec.ID), Image: gatewayImageID,
		State: &mobycontainer.State{Status: mobycontainer.StateCreated},
		Config: &mobycontainer.Config{
			Image: gatewayPinned, NetworkDisabled: false, User: gatewayUser, WorkingDir: "/",
			Entrypoint: []string{gatewayBinaryPath}, Labels: egressGatewayLabels(ownerID, spec),
		},
		HostConfig: egressGatewayHostConfig(spec),
		NetworkSettings: &mobycontainer.NetworkSettings{Networks: map[string]*mobynetwork.EndpointSettings{
			ConversationNetworkName(spec.ID): {NetworkID: "provider-network-1"},
			EgressNetworkName(spec.ID):       {NetworkID: "provider-network-2"},
		}},
	}}
	agentImage := mobyclient.ImageInspectResult{InspectResponse: mobyimage.InspectResponse{
		ID: agentImageID, RepoDigests: []string{"sandbox@" + spec.Image.Digest}, Architecture: "arm64", Os: "linux", Size: 64 << 20,
	}}
	gatewayImage := mobyclient.ImageInspectResult{InspectResponse: mobyimage.InspectResponse{
		ID: gatewayImageID, RepoDigests: []string{"cyberstrike-egress@" + spec.EgressGateway.Image.Digest}, Architecture: "arm64", Os: "linux", Size: 8 << 20,
	}}
	base.createResults = map[string]mobyclient.ContainerCreateResult{
		EgressGatewayContainerName(spec.ID): {ID: gatewayID},
		runtimeContainerName(spec.ID):       {ID: agentID},
	}
	base.createErrs = make(map[string]error)
	base.containerResults = map[string]mobyclient.ContainerInspectResult{
		EgressGatewayContainerName(spec.ID): gateway,
		runtimeContainerName(spec.ID):       agent,
	}
	base.imageResults = map[string]mobyclient.ImageInspectResult{
		agentPinned: agentImage, agentImageID: agentImage,
		gatewayPinned: gatewayImage, gatewayImageID: gatewayImage,
	}
	return base
}
