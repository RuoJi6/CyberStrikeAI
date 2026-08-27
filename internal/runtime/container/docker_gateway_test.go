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
	"cyberstrike-ai/internal/trafficspool"
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

func TestTrafficCaptureMountIsWritableOnlyForGateway(t *testing.T) {
	spec := gatewayCreationSpec()
	spec.EgressGateway.TrafficCapture = true
	spoolRoot := t.TempDir()
	manager, err := newDockerManager(&fakeDockerCreationAPI{fakeDockerInspectionAPI: &fakeDockerInspectionAPI{}}, DockerManagerOptions{
		OwnerID: "instance-01", TrafficSpoolRoot: spoolRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	config, hostConfig, err := manager.egressGatewayContainerConfig(spec, egressGatewayLabels("instance-01", spec))
	if err != nil {
		t.Fatal(err)
	}
	if len(hostConfig.Mounts) != 1 {
		t.Fatalf("gateway mounts = %#v", hostConfig.Mounts)
	}
	mount := hostConfig.Mounts[0]
	resolvedRoot, err := filepath.EvalSymlinks(spoolRoot)
	if err != nil {
		t.Fatal(err)
	}
	wantSource := filepath.Join(resolvedRoot, spec.ConversationID)
	if mount.Target != trafficspool.ContainerPath || mount.Source != wantSource || mount.ReadOnly {
		t.Fatalf("traffic spool mount = %#v, want source %q", mount, wantSource)
	}
	if !equalStrings(config.Env, []string{
		"CYBERSTRIKE_TRAFFIC_SPOOL_PATH=" + trafficspool.ContainerPath,
		"CYBERSTRIKE_CONVERSATION_ID=" + spec.ConversationID,
	}) {
		t.Fatalf("gateway capture environment = %#v", config.Env)
	}
	for _, agentMount := range runtimeHostConfig(spec).Mounts {
		if agentMount.Target == trafficspool.ContainerPath || agentMount.Source == wantSource {
			t.Fatalf("Agent received traffic spool mount: %#v", agentMount)
		}
	}
	reconstructed, err := egressGatewaySpecFromAgentLabels(runtimeLabels("instance-01", spec))
	if err != nil || reconstructed == nil || !reconstructed.TrafficCapture {
		t.Fatalf("reconstructed capture spec = %#v / %v", reconstructed, err)
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
	if !internalOptions.Internal || egressOptions.Internal || internalOptions.Driver != "bridge" || egressOptions.Driver != "bridge" || len(internalOptions.Options) != 1 || internalOptions.Options[conversationNetworkInhibitIPv4] != "true" {
		t.Fatalf("network options = internal %#v, egress %#v", internalOptions, egressOptions)
	}
	agentOptions := api.createOptsByName[runtimeContainerName(spec.ID)]
	gatewayOptions := api.createOptsByName[EgressGatewayContainerName(spec.ID)]
	if len(agentOptions.HostConfig.DNS) != 0 {
		t.Fatalf("legacy snapshot-less gateway unexpectedly became policy DNS: %#v", agentOptions.HostConfig.DNS)
	}
	if expected := runtimeContainerEnvironment(spec, ""); !equalStrings(agentOptions.Config.Env, expected) {
		t.Fatalf("legacy snapshot-less gateway did not neutralize inherited proxy settings: %#v", agentOptions.Config.Env)
	}
	if len(agentOptions.NetworkingConfig.EndpointsConfig) != 1 || agentOptions.NetworkingConfig.EndpointsConfig[internalName] == nil || agentOptions.NetworkingConfig.EndpointsConfig[egressName] != nil {
		t.Fatalf("agent network endpoints = %#v", agentOptions.NetworkingConfig)
	}
	if len(gatewayOptions.NetworkingConfig.EndpointsConfig) != 2 || gatewayOptions.NetworkingConfig.EndpointsConfig[internalName] == nil || gatewayOptions.NetworkingConfig.EndpointsConfig[egressName] == nil {
		t.Fatalf("gateway network endpoints = %#v", gatewayOptions.NetworkingConfig)
	}
	if gatewayOptions.HostConfig.NetworkMode != mobycontainer.NetworkMode(internalName) || gatewayOptions.HostConfig.Privileged || !gatewayOptions.HostConfig.ReadonlyRootfs || len(gatewayOptions.HostConfig.CapDrop) != 1 || gatewayOptions.HostConfig.CapDrop[0] != "ALL" || !equalCapabilitySets(gatewayOptions.HostConfig.CapAdd, gatewayCapabilities) || !containsString(gatewayOptions.HostConfig.SecurityOpt, "no-new-privileges") || gatewayOptions.HostConfig.Sysctls["net.ipv4.ip_forward"] != "1" {
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

func TestDockerManagerInspectRejectsHostGatewayOnInternalEndpoints(t *testing.T) {
	spec := gatewayCreationSpec()
	for _, endpointOwner := range []string{"agent", "gateway"} {
		t.Run(endpointOwner, func(t *testing.T) {
			api := newSuccessfulGatewayCreationAPI(spec, "instance-01")
			manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Create(context.Background(), spec); err != nil {
				t.Fatal(err)
			}
			name := runtimeContainerName(spec.ID)
			if endpointOwner == "gateway" {
				name = EgressGatewayContainerName(spec.ID)
			}
			result := api.containerResults[name]
			result.Container.NetworkSettings.Networks[ConversationNetworkName(spec.ID)].Gateway = netip.MustParseAddr("172.30.0.1")
			api.containerResults[name] = result
			if _, err := manager.Inspect(context.Background(), spec.ID); !errors.Is(err, ErrRuntimeStateConflict) {
				t.Fatalf("host gateway drift error = %v", err)
			}
		})
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
	internalEndpoint := gatewayOptions.NetworkingConfig.EndpointsConfig[ConversationNetworkName(spec.ID)]
	if internalEndpoint == nil || internalEndpoint.IPAMConfig == nil || internalEndpoint.IPAMConfig.IPv4Address.String() != "172.30.0.2" {
		t.Fatalf("gateway static policy DNS endpoint = %#v", internalEndpoint)
	}
	if expected := runtimeContainerEnvironment(spec, "172.30.0.2"); !equalStrings(agentOptions.Config.Env, expected) {
		t.Fatalf("agent proxy environment = %#v, want %#v", agentOptions.Config.Env, expected)
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
	if api.execContainerID != "provider-agent-1" || api.execCreateOpts.User != runtimeRootExecUser || api.execCreateOpts.Privileged ||
		!equalStrings(api.execCreateOpts.Cmd, []string{"/sbin/ip", "route", "replace", "default", "via", "172.30.0.2"}) ||
		!equalStrings(api.execCreateOpts.Env, runtimeExecEnvironment(nil)) {
		t.Fatalf("runtime default route helper = container %q options %#v", api.execContainerID, api.execCreateOpts)
	}
}

func TestEgressGatewayTrafficLimitsArePersistedInEnvironmentAndLabels(t *testing.T) {
	spec, root, snapshotPath := snapshotGatewayFixture(t)
	spec.EgressGateway.TrafficLimits = &EgressTrafficLimits{
		HTTPRequestsPerSecond: 7, TCPConnectionsPerSecond: 11, UDPDatagramsPerSecond: 13,
	}
	api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01", EgressSnapshotRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	labels := runtimeLabels("instance-01", spec)
	gatewayConfig, _, err := manager.egressGatewayContainerConfig(spec, expectedEgressGatewayLabels("instance-01", spec, "spec-digest"))
	if err != nil {
		t.Fatal(err)
	}
	wantTrafficEnv := []string{"CYBERSTRIKE_HTTP_RPS=7", "CYBERSTRIKE_TCP_CPS=11", "CYBERSTRIKE_UDP_DPS=13"}
	if !equalStrings(gatewayConfig.Env, wantTrafficEnv) {
		t.Fatalf("gateway traffic limit environment = %#v, want %#v", gatewayConfig.Env, wantTrafficEnv)
	}
	for key, want := range map[string]string{LabelEgressHTTPRPS: "7", LabelEgressTCPCPS: "11", LabelEgressUDPDPS: "13"} {
		if gatewayConfig.Labels[key] != want || labels[key] != want {
			t.Fatalf("traffic limit label %s = gateway %q agent %q, want %q", key, gatewayConfig.Labels[key], labels[key], want)
		}
	}
	reconstructed, err := egressGatewaySpecFromAgentLabels(labels)
	if err != nil {
		t.Fatal(err)
	}
	if reconstructed == nil || reconstructed.TrafficLimits == nil || *reconstructed.TrafficLimits != *spec.EgressGateway.TrafficLimits {
		t.Fatalf("reconstructed traffic limits = %#v", reconstructed)
	}
}

func TestEgressGatewayTrafficEnvironmentIgnoresImageDefaultsAndRejectsManagedDrift(t *testing.T) {
	withoutLimits := gatewayCreationSpec()
	if !matchesEgressGatewayTrafficEnvironment([]string{"PATH=/usr/local/bin:/usr/bin"}, egressGatewayEnvironment(withoutLimits)) {
		t.Fatal("image-defined PATH was treated as managed traffic-limit drift")
	}
	if matchesEgressGatewayTrafficEnvironment([]string{"PATH=/usr/bin", "CYBERSTRIKE_HTTP_RPS=1"}, egressGatewayEnvironment(withoutLimits)) {
		t.Fatal("disabled traffic limits accepted a managed rate variable")
	}

	withLimits := gatewayCreationSpec()
	withLimits.EgressGateway.TrafficLimits = &EgressTrafficLimits{
		HTTPRequestsPerSecond: 7, TCPConnectionsPerSecond: 11, UDPDatagramsPerSecond: 13,
	}
	expected := egressGatewayEnvironment(withLimits)
	actual := append([]string{"PATH=/usr/local/bin:/usr/bin", "LANG=C.UTF-8"}, expected...)
	if !matchesEgressGatewayTrafficEnvironment(actual, expected) {
		t.Fatal("matching managed rates with image-defined environment were rejected")
	}
	for name, mutated := range map[string][]string{
		"missing":   append([]string(nil), actual[:len(actual)-1]...),
		"changed":   replaceTestEnvironmentEntry(append([]string(nil), actual...), "CYBERSTRIKE_TCP_CPS", "12"),
		"duplicate": append(append([]string(nil), actual...), "CYBERSTRIKE_HTTP_RPS=7"),
		"malformed": append(append([]string(nil), actual[:len(actual)-3]...), "CYBERSTRIKE_HTTP_RPS"),
	} {
		t.Run(name, func(t *testing.T) {
			if matchesEgressGatewayTrafficEnvironment(mutated, expected) {
				t.Fatalf("managed traffic-limit drift was accepted: %#v", mutated)
			}
		})
	}
}

func TestDockerManagerInspectionAllowsImageDefinedGatewayEnvironment(t *testing.T) {
	spec, root, snapshotPath := snapshotGatewayFixture(t)
	api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01", EgressSnapshotRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatalf("create gateway topology: %v", err)
	}
	name := EgressGatewayContainerName(spec.ID)
	gateway := api.containerResults[name]
	gateway.Container.Config.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	api.containerResults[name] = gateway
	if _, err := manager.Inspect(context.Background(), spec.ID); err != nil {
		t.Fatalf("inspect gateway with image-defined environment: %v", err)
	}
}

func TestTLSInspectionMountsPrivateKeyOnlyIntoGatewayAndCertificateReadOnlyIntoAgent(t *testing.T) {
	spec, snapshotRoot, snapshotPath := snapshotGatewayFixture(t)
	tlsStore, err := egress.NewTLSAuthorityStore(filepath.Join(t.TempDir(), "tls-authorities"))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := egress.GenerateTLSAuthority(spec.ConversationID, time.Now().UTC(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reference, certificatePath, privateKeyPath, err := tlsStore.Put("12345678-1234-1234-1234-123456789abc", authority)
	if err != nil {
		t.Fatal(err)
	}
	spec.EgressGateway.TLSAuthority = &EgressTLSAuthoritySpec{
		ID: reference.ID, BoundarySnapshotID: spec.EgressGateway.BoundarySnapshot.ID,
		CertificateSHA256: reference.CertificateSHA256, PrivateKeySHA256: reference.PrivateKeySHA256,
	}
	api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	manager, err := newDockerManager(api, DockerManagerOptions{
		OwnerID: "instance-01", EgressSnapshotRoot: snapshotRoot, EgressTLSAuthorityRoot: tlsStore.Root(), OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, gatewayHost, err := manager.egressGatewayContainerConfig(spec, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(gatewayHost.Mounts) != 3 {
		t.Fatalf("gateway TLS mounts = %#v", gatewayHost.Mounts)
	}
	assertReadOnlyBindMount(t, gatewayHost.Mounts[1], certificatePath, egress.TLSAuthorityCertificateContainerPath)
	assertReadOnlyBindMount(t, gatewayHost.Mounts[2], privateKeyPath, egress.TLSAuthorityPrivateKeyContainerPath)

	agentHost, err := manager.runtimeContainerHostConfig(spec, "172.30.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if len(agentHost.Mounts) != 1 {
		t.Fatalf("agent TLS mounts = %#v", agentHost.Mounts)
	}
	assertReadOnlyBindMount(t, agentHost.Mounts[0], certificatePath, egress.TLSAuthorityCertificateContainerPath)
	if strings.Contains(strings.Join(runtimeProxyEnvironment(spec, "172.30.0.2"), "\n"), privateKeyPath) ||
		strings.Contains(runtimeKeepaliveScriptForSpec(spec), egress.TLSAuthorityPrivateKeyContainerPath) {
		t.Fatal("agent configuration disclosed the TLS authority private key")
	}
}

func assertReadOnlyBindMount(t *testing.T, mount mobymount.Mount, source, target string) {
	t.Helper()
	if mount.Type != mobymount.TypeBind || mount.Source != source || mount.Target != target || !mount.ReadOnly ||
		mount.BindOptions == nil || mount.BindOptions.Propagation != mobymount.PropagationRPrivate {
		t.Fatalf("read-only bind mount = %#v, want %s -> %s", mount, source, target)
	}
}

func TestDockerManagerBindsGatewayOnlyUpstreamRouteAndRejectsMissingOrWritableRoute(t *testing.T) {
	spec, snapshotRoot, snapshotPath := snapshotGatewayFixture(t)
	routeStore, err := egress.NewUpstreamRouteStore(filepath.Join(t.TempDir(), "upstream-routes"))
	if err != nil {
		t.Fatal(err)
	}
	routeReference, routePath, err := routeStore.Put(spec.ConversationID, egress.NewProxyUpstreamRoute(egress.UpstreamEndpoint{
		ID: "proxy-route", Protocol: egress.UpstreamProtocolHTTP, Host: "proxy.example", Port: 3128,
		Username: "gateway-user", Password: "gateway-secret",
	}))
	if err != nil {
		t.Fatal(err)
	}
	spec.EgressGateway.UpstreamRoute = &EgressUpstreamRouteSpec{ID: routeReference.ID, SHA256: routeReference.SHA256}
	api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	gatewayName := EgressGatewayContainerName(spec.ID)
	gateway := api.containerResults[gatewayName]
	gateway.Container.HostConfig.Mounts = append(gateway.Container.HostConfig.Mounts, mobymount.Mount{
		Type: mobymount.TypeBind, Source: routePath, Target: egress.UpstreamRouteContainerPath, ReadOnly: true,
		BindOptions: &mobymount.BindOptions{Propagation: mobymount.PropagationRPrivate},
	})
	api.containerResults[gatewayName] = gateway
	manager, err := newDockerManager(api, DockerManagerOptions{
		OwnerID: "instance-01", EgressSnapshotRoot: snapshotRoot, EgressUpstreamRoot: routeStore.Root(), OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatalf("create upstream-routed gateway: %v", err)
	}
	agentOptions := api.createOptsByName[runtimeContainerName(spec.ID)]
	gatewayOptions := api.createOptsByName[gatewayName]
	if len(agentOptions.HostConfig.Mounts) != 0 || strings.Contains(strings.Join(agentOptions.Config.Env, "\n"), "gateway-secret") {
		t.Fatalf("agent received upstream route material: %#v", agentOptions)
	}
	if len(gatewayOptions.HostConfig.Mounts) != 2 {
		t.Fatalf("gateway trusted mounts = %#v", gatewayOptions.HostConfig.Mounts)
	}
	commandText := strings.Join(gatewayOptions.Config.Cmd, " ")
	labelsJSON, _ := json.Marshal(gatewayOptions.Config.Labels)
	if strings.Contains(commandText, "gateway-user") || strings.Contains(commandText, "gateway-secret") || strings.Contains(string(labelsJSON), "gateway-user") || strings.Contains(string(labelsJSON), "gateway-secret") {
		t.Fatal("gateway command or labels exposed upstream credentials")
	}
	if gatewayOptions.Config.Labels[LabelEgressUpstreamRouteID] != routeReference.ID || gatewayOptions.Config.Labels[LabelEgressUpstreamSHA256] != routeReference.SHA256 {
		t.Fatalf("gateway upstream labels = %#v", gatewayOptions.Config.Labels)
	}

	missingManager, err := newDockerManager(newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath), DockerManagerOptions{
		OwnerID: "instance-01", EgressSnapshotRoot: snapshotRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missingManager.Create(context.Background(), spec); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("missing upstream route store error = %v", err)
	}
	if err := os.Chmod(routePath, 0o644); err != nil {
		t.Fatal(err)
	}
	writableManager, err := newDockerManager(newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath), DockerManagerOptions{
		OwnerID: "instance-01", EgressSnapshotRoot: snapshotRoot, EgressUpstreamRoot: routeStore.Root(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writableManager.Create(context.Background(), spec); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("writable upstream route error = %v", err)
	}
}

func TestDockerManagerBindsAuthProfilesOnlyIntoGatewayAndRejectsMissingOrWritableFile(t *testing.T) {
	spec, snapshotRoot, snapshotPath := snapshotGatewayFixture(t)
	authStore, err := egress.NewAuthProfilesStore(filepath.Join(t.TempDir(), "auth-profiles"))
	if err != nil {
		t.Fatal(err)
	}
	document := egress.NewAuthProfilesDocument(strings.Repeat("c", 64), []egress.GatewayAuthProfile{{
		ID: "profile-1", HeaderName: "Authorization", HeaderValue: "Bearer gateway-auth-secret",
	}})
	authReference, authPath, err := authStore.Put("auth-"+spec.EgressGateway.BoundarySnapshot.ID+"-aaaaaaaaaaaaaaaa", document)
	if err != nil {
		t.Fatal(err)
	}
	spec.EgressGateway.AuthProfiles = &EgressAuthProfilesSpec{ID: authReference.ID, SHA256: authReference.SHA256}
	api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	gatewayName := EgressGatewayContainerName(spec.ID)
	gateway := api.containerResults[gatewayName]
	gateway.Container.HostConfig.Mounts = append(gateway.Container.HostConfig.Mounts, mobymount.Mount{
		Type: mobymount.TypeBind, Source: authPath, Target: egress.AuthProfilesContainerPath, ReadOnly: true,
		BindOptions: &mobymount.BindOptions{Propagation: mobymount.PropagationRPrivate},
	})
	api.containerResults[gatewayName] = gateway
	manager, err := newDockerManager(api, DockerManagerOptions{
		OwnerID: "instance-01", EgressSnapshotRoot: snapshotRoot,
		EgressAuthProfilesRoot: authStore.Root(), OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatalf("create auth-only gateway: %v", err)
	}
	agentOptions := api.createOptsByName[runtimeContainerName(spec.ID)]
	gatewayOptions := api.createOptsByName[gatewayName]
	if len(agentOptions.HostConfig.Mounts) != 0 || strings.Contains(strings.Join(agentOptions.Config.Env, "\n"), "gateway-auth-secret") {
		t.Fatalf("agent received auth profile material: %#v", agentOptions)
	}
	if len(gatewayOptions.HostConfig.Mounts) != 2 {
		t.Fatalf("gateway auth profile mounts = %#v", gatewayOptions.HostConfig.Mounts)
	}
	commandText := strings.Join(gatewayOptions.Config.Cmd, " ")
	labelsJSON, _ := json.Marshal(gatewayOptions.Config.Labels)
	if strings.Contains(commandText, "gateway-auth-secret") || strings.Contains(string(labelsJSON), "gateway-auth-secret") {
		t.Fatal("gateway command or labels exposed injected credential")
	}
	if gatewayOptions.Config.Labels[LabelEgressAuthProfilesID] != authReference.ID || gatewayOptions.Config.Labels[LabelEgressAuthSHA256] != authReference.SHA256 {
		t.Fatalf("gateway auth profile labels = %#v", gatewayOptions.Config.Labels)
	}
	missingManager, err := newDockerManager(newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath), DockerManagerOptions{
		OwnerID: "instance-01", EgressSnapshotRoot: snapshotRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missingManager.Create(context.Background(), spec); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("missing auth profiles store error = %v", err)
	}
	if err := os.Chmod(authPath, 0o644); err != nil {
		t.Fatal(err)
	}
	writableManager, err := newDockerManager(newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath), DockerManagerOptions{
		OwnerID: "instance-01", EgressSnapshotRoot: snapshotRoot, EgressAuthProfilesRoot: authStore.Root(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writableManager.Create(context.Background(), spec); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("writable auth profiles error = %v", err)
	}
}

func TestDockerManagerRejectsCrossConversationGatewayIdentityBeforeAgentCreation(t *testing.T) {
	spec, snapshotRoot, snapshotPath := snapshotGatewayFixture(t)
	api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	gatewayName := EgressGatewayContainerName(spec.ID)
	gateway := api.containerResults[gatewayName]
	gateway.Container.Config.Labels[LabelConversationID] = "conversation-other"
	api.containerResults[gatewayName] = gateway
	manager, err := newDockerManager(api, DockerManagerOptions{
		OwnerID: "instance-01", EgressSnapshotRoot: snapshotRoot, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("cross-conversation gateway identity error = %v", err)
	}
	if _, created := api.createOptsByName[runtimeContainerName(spec.ID)]; created {
		t.Fatal("agent creation proceeded after cross-conversation gateway identity reuse")
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
	missingEndpoint := gateway.Container.NetworkSettings.Networks[ConversationNetworkName(spec.ID)]
	missingEndpoint.IPAddress = netip.Addr{}
	missingEndpoint.IPAMConfig = nil
	missingAPI.containerResults[gatewayName] = gateway
	missingManager, err := newDockerManager(missingAPI, DockerManagerOptions{OwnerID: "instance-01", EgressSnapshotRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missingManager.Create(context.Background(), spec); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("missing gateway policy DNS address error = %v", err)
	}
}

func TestDockerManagerAcceptsStoppedGatewayStaticPolicyDNSAddress(t *testing.T) {
	spec, root, snapshotPath := snapshotGatewayFixture(t)
	api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	gatewayName := EgressGatewayContainerName(spec.ID)
	gateway := api.containerResults[gatewayName]
	endpoint := gateway.Container.NetworkSettings.Networks[ConversationNetworkName(spec.ID)]
	endpoint.IPAMConfig = &mobynetwork.EndpointIPAMConfig{IPv4Address: netip.MustParseAddr("172.30.0.2")}
	endpoint.IPAddress = netip.Addr{}
	api.containerResults[gatewayName] = gateway
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01", EgressSnapshotRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatalf("create with stopped static gateway address: %v", err)
	}
}

func TestDockerManagerRejectsAgentProxyEnvironmentDrift(t *testing.T) {
	spec, root, snapshotPath := snapshotGatewayFixture(t)
	tests := []struct {
		name   string
		mutate func([]string) []string
	}{
		{name: "missing", mutate: func(values []string) []string {
			return removeTestEnvironmentKey(values, "HTTP_PROXY")
		}},
		{name: "external proxy", mutate: func(values []string) []string {
			return replaceTestEnvironmentEntry(values, "HTTP_PROXY", "http://203.0.113.10:3128")
		}},
		{name: "no proxy bypass", mutate: func(values []string) []string {
			return replaceTestEnvironmentEntry(values, "NO_PROXY", "localhost,127.0.0.1")
		}},
		{name: "duplicate", mutate: func(values []string) []string {
			for _, entry := range values {
				if strings.HasPrefix(entry, "HTTP_PROXY=") {
					return append(values, entry)
				}
			}
			return values
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
			manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01", EgressSnapshotRoot: root})
			if err != nil {
				t.Fatal(err)
			}
			runtime, err := manager.Create(context.Background(), spec)
			if err != nil {
				t.Fatal(err)
			}
			agentName := runtimeContainerName(spec.ID)
			agent := api.containerResults[agentName]
			agent.Container.Config.Env = test.mutate(append([]string(nil), agent.Container.Config.Env...))
			api.containerResults[agentName] = agent
			if _, err := manager.Inspect(context.Background(), runtime.ID); !errors.Is(err, ErrRuntimeStateConflict) {
				t.Fatalf("proxy environment drift error = %v", err)
			}
			if err := verifyReadinessIsolation(agent.Container, spec); !errors.Is(err, ErrRuntimeNotReady) {
				t.Fatalf("readiness proxy environment drift error = %v", err)
			}
		})
	}
}

func removeTestEnvironmentKey(values []string, key string) []string {
	prefix := key + "="
	result := make([]string, 0, len(values))
	for _, entry := range values {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return result
}

func replaceTestEnvironmentEntry(values []string, key, value string) []string {
	prefix := key + "="
	for index, entry := range values {
		if strings.HasPrefix(entry, prefix) {
			values[index] = prefix + value
			return values
		}
	}
	return append(values, prefix+value)
}

func TestDockerManagerRejectsProxyEnvironmentWithoutSnapshotGateway(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.Config.Env = []string{"PATH=/usr/bin", "HTTP_PROXY=http://203.0.113.10:3128"}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("unexpected proxy environment error = %v", err)
	}
}

func TestRuntimeProxyEnvironmentNeutralizesInheritedImageValues(t *testing.T) {
	spec := creationSpec()
	environment := runtimeProxyEnvironment(spec, "")
	if len(environment) != len(runtimeProxyEnvironmentKeys) {
		t.Fatalf("managed environment entries = %d, want %d: %#v", len(environment), len(runtimeProxyEnvironmentKeys), environment)
	}
	for index, key := range runtimeProxyEnvironmentKeys {
		if environment[index] != key+"=" {
			t.Fatalf("managed environment[%d] = %q, want %q", index, environment[index], key+"=")
		}
	}
	if err := verifyRuntimeProxyEnvironment(environment, spec, ""); err != nil {
		t.Fatalf("verify neutralized environment: %v", err)
	}
}

func TestRuntimeProxyEnvironmentNeutralizesInheritedCAWithoutTLSInterception(t *testing.T) {
	spec := gatewayCreationSpec()
	spec.EgressGateway.BoundarySnapshot = &EgressBoundarySnapshotSpec{
		ID:     "12345678-1234-1234-1234-123456789abc",
		SHA256: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}
	environment := runtimeProxyEnvironment(spec, "172.30.0.2")
	observed := make(map[string]string, len(environment))
	for _, entry := range environment {
		key, value, _ := strings.Cut(entry, "=")
		observed[key] = value
	}
	if observed["HTTP_PROXY"] != "http://172.30.0.2:3128" || observed["http_proxy"] != "http://172.30.0.2:3128" {
		t.Fatalf("proxy environment = %#v", observed)
	}
	if observed["ALL_PROXY"] != "socks5h://172.30.0.2:1080" || observed["all_proxy"] != "socks5h://172.30.0.2:1080" {
		t.Fatalf("SOCKS5 proxy environment = %#v", observed)
	}
	for _, key := range []string{"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "PIP_CERT", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS"} {
		if observed[key] != "" {
			t.Fatalf("inherited CA variable %s was not neutralized: %#v", key, observed)
		}
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

func TestDockerManagerInspectRejectsRunningSnapshotGatewayFailure(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*mobycontainer.State)
	}{
		{name: "crashed", mutate: func(state *mobycontainer.State) {
			state.Status = mobycontainer.StateExited
			state.Running = false
		}},
		{name: "unhealthy", mutate: func(state *mobycontainer.State) {
			state.Health.Status = mobycontainer.Unhealthy
		}},
		{name: "snapshot report mismatch", mutate: func(state *mobycontainer.State) {
			state.Health.Log[len(state.Health.Log)-1].Output = `{"event":"boundary_snapshot_healthy","snapshotId":"00000000-0000-0000-0000-000000000000","sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec, root, snapshotPath := snapshotGatewayFixture(t)
			api := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
			manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01", EgressSnapshotRoot: root})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Create(context.Background(), spec); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Start(context.Background(), spec.ID); err != nil {
				t.Fatal(err)
			}
			name := EgressGatewayContainerName(spec.ID)
			gateway := api.containerResults[name]
			test.mutate(gateway.Container.State)
			api.containerResults[name] = gateway
			if _, err := manager.Inspect(context.Background(), spec.ID); !errors.Is(err, ErrRuntimeStateConflict) {
				t.Fatalf("running snapshot gateway failure error = %v", err)
			}
		})
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
		agent.Container.Config.Env = runtimeContainerEnvironment(spec, policyDNSAddress.String())
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
			ConversationNetworkName(spec.ID): {
				NetworkID: "provider-network-1", IPAddress: policyDNSAddress,
				IPAMConfig: &mobynetwork.EndpointIPAMConfig{IPv4Address: policyDNSAddress},
			},
			EgressNetworkName(spec.ID): {NetworkID: "provider-network-2", IPAddress: netip.MustParseAddr("172.31.0.2")},
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
