package container

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/egress"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobyimage "github.com/moby/moby/api/types/image"
	mobymount "github.com/moby/moby/api/types/mount"
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
	item2, err := json.Marshal(gatewayCreationSpec())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(item2), "BoundarySnapshot") {
		t.Fatalf("item-2 gateway specification gained a nil snapshot field: %s", item2)
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
	if len(agentOptions.HostConfig.DNS) != 0 {
		t.Fatalf("legacy snapshot-less gateway unexpectedly became policy DNS: %#v", agentOptions.HostConfig.DNS)
	}
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

func TestDockerManagerBindsExactSnapshotOnlyIntoGatewayAndStartsAfterHealthReport(t *testing.T) {
	spec, root, snapshotPath := snapshotGatewayFixture(t)
	api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	manager, err := newDockerManager(api, DockerManagerOptions{
		OwnerID: "instance-01", EgressSnapshotRoot: root, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatalf("create snapshot gateway: %v", err)
	}
	agentOptions := api.createOptsByName[runtimeContainerName(spec.ID)]
	gatewayOptions := api.createOptsByName[EgressGatewayContainerName(spec.ID)]
	if len(agentOptions.HostConfig.Binds) != 0 || len(agentOptions.HostConfig.Mounts) != 0 {
		t.Fatalf("agent received trusted snapshot mount: %#v", agentOptions.HostConfig)
	}
	if len(agentOptions.HostConfig.DNS) != 1 || agentOptions.HostConfig.DNS[0].String() != "172.30.0.2" || len(agentOptions.HostConfig.DNSOptions) != 0 || len(agentOptions.HostConfig.DNSSearch) != 0 {
		t.Fatalf("agent policy DNS = %#v", agentOptions.HostConfig)
	}
	if len(gatewayOptions.HostConfig.Binds) != 0 || len(gatewayOptions.HostConfig.Mounts) != 1 {
		t.Fatalf("gateway snapshot mounts = %#v / %#v", gatewayOptions.HostConfig.Binds, gatewayOptions.HostConfig.Mounts)
	}
	mount := gatewayOptions.HostConfig.Mounts[0]
	if mount.Type != mobymount.TypeBind || mount.Source != snapshotPath || mount.Target != egress.SnapshotContainerPath || !mount.ReadOnly || mount.BindOptions == nil || mount.BindOptions.Propagation != mobymount.PropagationRPrivate {
		t.Fatalf("gateway snapshot mount = %#v", mount)
	}
	if !equalStrings(gatewayOptions.Config.Cmd, egressGatewayCommand(spec, "run")) || !equalHealthcheck(gatewayOptions.Config.Healthcheck, egressGatewayHealthcheck(spec)) {
		t.Fatalf("gateway snapshot process config = %#v", gatewayOptions.Config)
	}
	if gatewayOptions.Config.Labels[LabelEgressSnapshotID] != spec.EgressGateway.BoundarySnapshot.ID || gatewayOptions.Config.Labels[LabelEgressSnapshotSHA256] != spec.EgressGateway.BoundarySnapshot.SHA256 {
		t.Fatalf("gateway snapshot labels = %#v", gatewayOptions.Config.Labels)
	}
	if _, err := manager.Start(context.Background(), spec.ID); err != nil {
		t.Fatalf("start snapshot gateway topology: %v", err)
	}
	if len(api.startedIDs) != 2 || api.startedIDs[0] != "provider-gateway-1" || api.startedIDs[1] != "provider-agent-1" {
		t.Fatalf("snapshot-aware start order = %#v", api.startedIDs)
	}
}

func TestDockerManagerRejectsPolicyDNSDriftAndMissingGatewayAddress(t *testing.T) {
	spec, root, snapshotPath := snapshotGatewayFixture(t)
	api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01", EgressSnapshotRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := manager.Create(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	agent := api.containerResults[runtimeContainerName(spec.ID)]
	agent.Container.HostConfig.DNS = []netip.Addr{netip.MustParseAddr("172.30.0.9")}
	api.containerResults[runtimeContainerName(spec.ID)] = agent
	if _, err := manager.Inspect(context.Background(), runtime.ID); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("policy DNS drift error = %v", err)
	}

	missingAPI := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	gatewayName := EgressGatewayContainerName(spec.ID)
	gateway := missingAPI.containerResults[gatewayName]
	gateway.Container.NetworkSettings.Networks[ConversationNetworkName(spec.ID)].IPAddress = netip.Addr{}
	missingAPI.containerResults[gatewayName] = gateway
	missingManager, err := newDockerManager(missingAPI, DockerManagerOptions{OwnerID: "instance-01", EgressSnapshotRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missingManager.Create(context.Background(), spec); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("missing gateway policy DNS address error = %v", err)
	}
}

func TestDockerManagerSnapshotGatewayFailsClosedWhenTrustedFileIsMissing(t *testing.T) {
	spec, root, snapshotPath := snapshotGatewayFixture(t)
	api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01", EgressSnapshotRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(snapshotPath); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(context.Background(), spec.ID); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("missing snapshot start error = %v", err)
	}
	if len(api.startedIDs) != 0 {
		t.Fatalf("container started without trusted snapshot: %#v", api.startedIDs)
	}
}

func TestDockerManagerSnapshotGatewayRejectsMismatchedHealthyReportBeforeAgentStart(t *testing.T) {
	spec, root, snapshotPath := snapshotGatewayFixture(t)
	api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	api.healthOutputs = map[string]string{
		"provider-gateway-1": `{"event":"boundary_snapshot_healthy","snapshotId":"00000000-0000-0000-0000-000000000000","sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
	}
	manager, err := newDockerManager(api, DockerManagerOptions{
		OwnerID: "instance-01", EgressSnapshotRoot: root, OperationTimeout: 350 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(context.Background(), spec.ID); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("mismatched snapshot health error = %v", err)
	}
	if len(api.startedIDs) != 1 || api.startedIDs[0] != "provider-gateway-1" {
		t.Fatalf("agent started before exact snapshot health: %#v", api.startedIDs)
	}
	if len(api.stoppedIDs) != 1 || api.stoppedIDs[0] != "provider-gateway-1" {
		t.Fatalf("unready gateway was not rolled back: %#v", api.stoppedIDs)
	}
}

func snapshotGatewayFixture(t *testing.T) (RuntimeSpec, string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "snapshots")
	store, err := egress.NewSnapshotStore(root)
	if err != nil {
		t.Fatal(err)
	}
	canonicalJSON := `{"schemaVersion":1,"policyId":"","rules":[]}`
	digest := sha256.Sum256([]byte(canonicalJSON))
	reference := egress.SnapshotReference{
		ID: "12345678-1234-1234-1234-123456789abc", SHA256: "sha256:" + hex.EncodeToString(digest[:]),
	}
	path, err := store.Put(reference, canonicalJSON)
	if err != nil {
		t.Fatal(err)
	}
	spec := gatewayCreationSpec()
	spec.EgressGateway.BoundarySnapshot = &EgressBoundarySnapshotSpec{ID: reference.ID, SHA256: reference.SHA256}
	return spec, store.Root(), path
}

func newSuccessfulSnapshotGatewayCreationAPI(spec RuntimeSpec, ownerID, snapshotPath string) *fakeDockerCreationAPI {
	api := newSuccessfulGatewayCreationAPI(spec, ownerID)
	name := EgressGatewayContainerName(spec.ID)
	gateway := api.containerResults[name]
	gateway.Container.Config.Cmd = egressGatewayCommand(spec, "run")
	gateway.Container.Config.Healthcheck = egressGatewayHealthcheck(spec)
	gateway.Container.HostConfig.Mounts = []mobymount.Mount{{
		Type: mobymount.TypeBind, Source: snapshotPath,
		Target: egress.SnapshotContainerPath, ReadOnly: true,
		BindOptions: &mobymount.BindOptions{Propagation: mobymount.PropagationRPrivate},
	}}
	api.containerResults[name] = gateway
	return api
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
	policyDNSAddress := netip.MustParseAddr("172.30.0.2")
	if requiresPolicyDNS(spec) {
		agent.Container.HostConfig.DNS = []netip.Addr{policyDNSAddress}
	}
	agent.Container.NetworkSettings = &mobycontainer.NetworkSettings{Networks: map[string]*mobynetwork.EndpointSettings{
		ConversationNetworkName(spec.ID): {NetworkID: "provider-network-1", IPAddress: netip.MustParseAddr("172.30.0.3")},
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
			ConversationNetworkName(spec.ID): {NetworkID: "provider-network-1", IPAddress: policyDNSAddress},
			EgressNetworkName(spec.ID):       {NetworkID: "provider-network-2", IPAddress: netip.MustParseAddr("172.31.0.2")},
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
