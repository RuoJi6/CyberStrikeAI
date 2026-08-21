package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cyberstrike-ai/internal/egress"
	containerderrdefs "github.com/containerd/errdefs"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobymount "github.com/moby/moby/api/types/mount"
	mobynetwork "github.com/moby/moby/api/types/network"
	mobyclient "github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	gatewayNetworkModeLabel = "internal-egress"
	egressNetworkModeLabel  = "egress"
	gatewayBinaryPath       = "/cyberstrike-egress"
	gatewayUser             = "65532:65532"
)

func EgressGatewayContainerName(id RuntimeID) string {
	return "cyberstrike-egress-" + string(id)
}

func EgressNetworkName(id RuntimeID) string {
	return "cyberstrike-egress-network-" + string(id)
}

func (m *DockerManager) ensureOwnedEgressNetwork(ctx context.Context, spec RuntimeSpec) (ManagedResource, bool, error) {
	if m.networkAPI == nil {
		return ManagedResource{}, false, fmt.Errorf("%w: engine client does not support egress networks", ErrEngineUnavailable)
	}
	if spec.EgressGateway == nil {
		return ManagedResource{}, false, invalidSpec("egress gateway specification is required")
	}
	name := EgressNetworkName(spec.ID)
	result, err := m.networkAPI.NetworkInspect(ctx, name, mobyclient.NetworkInspectOptions{})
	if err == nil {
		resource, verifyErr := m.verifyEgressNetwork(spec, RuntimeSpecDigest(spec), result.Network, "", true)
		return resource, false, verifyErr
	}
	if !containerderrdefs.IsNotFound(err) {
		return ManagedResource{}, false, fmt.Errorf("inspect egress network %s: %w", name, err)
	}
	enableIPv4, enableIPv6 := true, false
	created, err := m.networkAPI.NetworkCreate(ctx, name, mobyclient.NetworkCreateOptions{
		Driver: "bridge", Scope: "local", EnableIPv4: &enableIPv4, EnableIPv6: &enableIPv6,
		Internal: false, Attachable: false, Ingress: false, Labels: egressNetworkLabels(m.ownerID, spec),
	})
	if err != nil {
		if containerderrdefs.IsConflict(err) {
			return ManagedResource{}, false, fmt.Errorf("%w: egress network %s already exists", ErrAlreadyExists, name)
		}
		return ManagedResource{}, false, fmt.Errorf("create egress network %s: %w", name, err)
	}
	if strings.TrimSpace(created.ID) == "" {
		return ManagedResource{}, true, fmt.Errorf("%w: engine returned an empty egress network id", ErrRuntimeStateConflict)
	}
	inspected, err := m.networkAPI.NetworkInspect(ctx, created.ID, mobyclient.NetworkInspectOptions{})
	if err != nil {
		return ManagedResource{}, true, fmt.Errorf("inspect created egress network %s: %w", name, err)
	}
	resource, err := m.verifyEgressNetwork(spec, RuntimeSpecDigest(spec), inspected.Network, created.ID, true)
	return resource, true, err
}

func (m *DockerManager) verifyEgressNetwork(spec RuntimeSpec, expectedSpecDigest string, actual mobynetwork.Inspect, providerID string, requireEmpty bool) (ManagedResource, error) {
	if strings.TrimSpace(providerID) != "" && actual.ID != providerID {
		return ManagedResource{}, fmt.Errorf("%w: egress network provider identity mismatch", ErrRuntimeStateConflict)
	}
	expected := egressNetworkManagedResource(spec, actual.ID)
	observed, err := m.resourceFromLabels(ResourceKindEgressNetwork, actual.ID, actual.Name, actual.Labels, actual.Created.UTC())
	if err != nil || !sameManagedResource(expected, observed) {
		return ManagedResource{}, fmt.Errorf("%w: egress network ownership mismatch", ErrRuntimeStateConflict)
	}
	if !sha256DigestPattern.MatchString(expectedSpecDigest) {
		return ManagedResource{}, fmt.Errorf("%w: egress network expected specification digest is invalid", ErrRuntimeStateConflict)
	}
	for key, value := range expectedEgressNetworkLabels(m.ownerID, spec, expectedSpecDigest) {
		if actual.Labels[key] != value {
			return ManagedResource{}, fmt.Errorf("%w: egress network label %s mismatch", ErrRuntimeStateConflict, key)
		}
	}
	if actual.Driver != "bridge" || actual.Scope != "local" || actual.Internal || !actual.EnableIPv4 || actual.EnableIPv6 || actual.Attachable || actual.Ingress || actual.ConfigOnly {
		return ManagedResource{}, fmt.Errorf("%w: egress network settings mismatch", ErrRuntimeStateConflict)
	}
	if requireEmpty && (len(actual.Containers) != 0 || len(actual.Services) != 0) {
		return ManagedResource{}, fmt.Errorf("%w: egress network already has attached workloads", ErrRuntimeStateConflict)
	}
	return observed, nil
}

func egressNetworkLabels(ownerID string, spec RuntimeSpec) map[string]string {
	return expectedEgressNetworkLabels(ownerID, spec, RuntimeSpecDigest(spec))
}

func expectedEgressNetworkLabels(ownerID string, spec RuntimeSpec, specDigest string) map[string]string {
	return map[string]string{
		LabelManaged: "true", LabelOwner: ownerID,
		LabelResourceKind: ResourceKindEgressNetwork,
		LabelResourceID:   string(spec.ID), LabelRuntimeID: string(spec.ID),
		LabelConversationID: spec.ConversationID,
		LabelSpecDigest:     specDigest, LabelNetworkMode: egressNetworkModeLabel,
	}
}

func egressNetworkManagedResource(spec RuntimeSpec, providerID string) ManagedResource {
	return ManagedResource{
		Kind: ResourceKindEgressNetwork, LogicalID: string(spec.ID), ProviderID: providerID,
		Name: EgressNetworkName(spec.ID), ConversationID: spec.ConversationID,
	}
}

func egressGatewayManagedResource(spec RuntimeSpec, providerID string) ManagedResource {
	return ManagedResource{
		Kind: ResourceKindEgressGateway, LogicalID: string(spec.ID), ProviderID: providerID,
		Name: EgressGatewayContainerName(spec.ID), ConversationID: spec.ConversationID,
	}
}

func (m *DockerManager) createEgressGateway(ctx context.Context, spec RuntimeSpec, conversationNetwork, egressNetwork ManagedResource) (string, string, error) {
	if spec.EgressGateway == nil {
		return "", "", invalidSpec("egress gateway specification is required")
	}
	gateway := *spec.EgressGateway
	platform, err := parsePlatform(gateway.Image.Platform)
	if err != nil {
		return "", "", err
	}
	pinned, _ := pinnedImageReference(gateway.Image)
	name := EgressGatewayContainerName(spec.ID)
	labels := egressGatewayLabels(m.ownerID, spec)
	config, hostConfig, err := m.egressGatewayContainerConfig(spec, labels)
	if err != nil {
		return "", "", err
	}
	result, err := m.api.ContainerCreate(ctx, mobyclient.ContainerCreateOptions{
		Name: name, Image: pinned,
		Platform:         &ocispec.Platform{OS: platform[0], Architecture: platform[1], Variant: platform[2]},
		Config:           config,
		HostConfig:       hostConfig,
		NetworkingConfig: egressGatewayNetworkingConfig(spec, conversationNetwork, egressNetwork),
	})
	if err != nil {
		if containerderrdefs.IsConflict(err) {
			return "", "", fmt.Errorf("%w: %s", ErrAlreadyExists, name)
		}
		return "", "", fmt.Errorf("create egress gateway %s: %w", spec.ID, err)
	}
	if strings.TrimSpace(result.ID) == "" {
		return "", "", fmt.Errorf("%w: engine returned an empty egress gateway id", ErrRuntimeStateConflict)
	}
	inspected, err := m.api.ContainerInspect(ctx, result.ID, mobyclient.ContainerInspectOptions{Size: false})
	if err != nil {
		return result.ID, "", fmt.Errorf("inspect created egress gateway %s: %w", result.ID, err)
	}
	if err := m.verifyEgressGatewayInspection(ctx, spec, inspected.Container, nil, StatusStopped, RuntimeSpecDigest(spec)); err != nil {
		return result.ID, "", err
	}
	if !requiresPolicyDNS(spec) {
		return result.ID, "", nil
	}
	address, err := egressGatewayPolicyDNSAddress(inspected.Container, spec)
	if err != nil {
		return result.ID, "", err
	}
	return result.ID, address, nil
}

func requiresPolicyDNS(spec RuntimeSpec) bool {
	return spec.EgressGateway != nil && spec.EgressGateway.BoundarySnapshot != nil
}

func egressGatewayPolicyDNSAddress(gateway mobycontainer.InspectResponse, spec RuntimeSpec) (string, error) {
	if gateway.NetworkSettings == nil {
		return "", fmt.Errorf("%w: egress gateway has no network settings for policy DNS", ErrRuntimeStateConflict)
	}
	endpoint := gateway.NetworkSettings.Networks[ConversationNetworkName(spec.ID)]
	if endpoint == nil || !endpoint.IPAddress.IsValid() || !endpoint.IPAddress.Is4() || endpoint.IPAddress.IsUnspecified() || endpoint.IPAddress.IsLoopback() || endpoint.IPAddress.IsMulticast() || endpoint.IPAddress.IsLinkLocalUnicast() || endpoint.IPAddress.Zone() != "" {
		return "", fmt.Errorf("%w: egress gateway policy DNS address is invalid", ErrRuntimeStateConflict)
	}
	return endpoint.IPAddress.String(), nil
}

func (m *DockerManager) inspectOwnedEgressGateway(ctx context.Context, spec RuntimeSpec, agent *mobycontainer.InspectResponse, expectedStatus Status) (mobycontainer.InspectResponse, error) {
	result, err := m.api.ContainerInspect(ctx, EgressGatewayContainerName(spec.ID), mobyclient.ContainerInspectOptions{Size: false})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return mobycontainer.InspectResponse{}, fmt.Errorf("%w: egress gateway for runtime %s", ErrNotFound, spec.ID)
		}
		return mobycontainer.InspectResponse{}, fmt.Errorf("inspect egress gateway for runtime %s: %w", spec.ID, err)
	}
	expectedSpecDigest := ""
	if agent != nil && agent.Config != nil {
		expectedSpecDigest = agent.Config.Labels[LabelSpecDigest]
	}
	if err := m.verifyEgressGatewayInspection(ctx, spec, result.Container, agent, expectedStatus, expectedSpecDigest); err != nil {
		return mobycontainer.InspectResponse{}, err
	}
	return result.Container, nil
}

func (m *DockerManager) verifyEgressGatewayInspection(ctx context.Context, spec RuntimeSpec, actual mobycontainer.InspectResponse, agent *mobycontainer.InspectResponse, expectedStatus Status, expectedSpecDigest string) error {
	if spec.EgressGateway == nil || strings.TrimSpace(actual.ID) == "" || actual.Config == nil || actual.HostConfig == nil || actual.State == nil {
		return fmt.Errorf("%w: egress gateway inspection is incomplete", ErrRuntimeStateConflict)
	}
	if strings.TrimPrefix(actual.Name, "/") != EgressGatewayContainerName(spec.ID) {
		return fmt.Errorf("%w: egress gateway name mismatch", ErrRuntimeStateConflict)
	}
	if !sha256DigestPattern.MatchString(expectedSpecDigest) {
		return fmt.Errorf("%w: egress gateway expected specification digest is invalid", ErrRuntimeStateConflict)
	}
	for key, expected := range expectedEgressGatewayLabels(m.ownerID, spec, expectedSpecDigest) {
		if actual.Config.Labels[key] != expected {
			return fmt.Errorf("%w: egress gateway label %s mismatch", ErrRuntimeStateConflict, key)
		}
	}
	status, _ := observedRuntimeStatus(actual.State)
	if status != expectedStatus {
		return fmt.Errorf("%w: egress gateway state %s does not match agent state %s", ErrRuntimeStateConflict, status, expectedStatus)
	}
	if expectedStatus == StatusRunning && requiresPolicyDNS(spec) && !healthySnapshotReport(actual.State.Health, boundarySnapshotReference(spec), upstreamRouteReference(spec)) {
		return fmt.Errorf("%w: running egress gateway does not report the exact healthy snapshot", ErrRuntimeStateConflict)
	}
	if actual.Config.NetworkDisabled || actual.Config.User != gatewayUser || actual.Config.WorkingDir != "/" || len(actual.Config.Entrypoint) != 1 || actual.Config.Entrypoint[0] != gatewayBinaryPath {
		return fmt.Errorf("%w: egress gateway process configuration mismatch", ErrRuntimeStateConflict)
	}
	expectedCommand := egressGatewayCommand(spec, "run")
	if !equalStrings(actual.Config.Cmd, expectedCommand) || !equalHealthcheck(actual.Config.Healthcheck, egressGatewayHealthcheck(spec)) {
		return fmt.Errorf("%w: egress gateway snapshot command or healthcheck mismatch", ErrRuntimeStateConflict)
	}
	if len(actual.Config.ExposedPorts) != 0 || len(actual.Config.Volumes) != 0 {
		return fmt.Errorf("%w: egress gateway image exposes ports or volumes", ErrRuntimeStateConflict)
	}
	if err := m.verifyEgressGatewayHostConfig(actual.HostConfig, spec); err != nil {
		return err
	}
	if _, err := m.VerifyRuntimeImage(ctx, actual.ID, spec.EgressGateway.Image); err != nil {
		return err
	}
	if err := m.verifyEgressGatewayNetworks(ctx, spec, actual, agent, expectedStatus); err != nil {
		return err
	}
	return nil
}

func egressGatewayHostConfig(spec RuntimeSpec) *mobycontainer.HostConfig {
	resources := spec.EgressGateway.Resources
	pidsLimit := resources.PIDs
	return &mobycontainer.HostConfig{
		NetworkMode: mobycontainer.NetworkMode(ConversationNetworkName(spec.ID)),
		LogConfig: mobycontainer.LogConfig{Type: "local", Config: map[string]string{
			"max-size": strconv.FormatInt(resources.LogMaxBytes, 10),
			"max-file": strconv.Itoa(resources.LogMaxFiles), "compress": "true",
		}},
		RestartPolicy: mobycontainer.RestartPolicy{Name: mobycontainer.RestartPolicyDisabled},
		CapDrop:       []string{"ALL"}, ReadonlyRootfs: true, SecurityOpt: []string{"no-new-privileges"},
		Tmpfs: map[string]string{"/tmp": tmpfsOptions(resources.TmpfsBytes, true)},
		Resources: mobycontainer.Resources{
			NanoCPUs: resources.NanoCPUs, Memory: resources.MemoryBytes, MemorySwap: resources.MemoryBytes,
			PidsLimit: &pidsLimit, Ulimits: []*mobycontainer.Ulimit{{
				Name: "nofile", Soft: int64(resources.NoFileSoft), Hard: int64(resources.NoFileHard),
			}},
		},
	}
}

func (m *DockerManager) egressGatewayContainerConfig(spec RuntimeSpec, labels map[string]string) (*mobycontainer.Config, *mobycontainer.HostConfig, error) {
	config := &mobycontainer.Config{
		NetworkDisabled: false, User: gatewayUser, WorkingDir: "/",
		Entrypoint: []string{gatewayBinaryPath}, Cmd: egressGatewayCommand(spec, "run"),
		Healthcheck: egressGatewayHealthcheck(spec), Labels: labels,
	}
	hostConfig := egressGatewayHostConfig(spec)
	if spec.EgressGateway.BoundarySnapshot == nil {
		return config, hostConfig, nil
	}
	path, _, err := m.loadBoundarySnapshot(spec)
	if err != nil {
		return nil, nil, err
	}
	hostConfig.Mounts = []mobymount.Mount{{
		Type: mobymount.TypeBind, Source: path,
		Target: egress.SnapshotContainerPath, ReadOnly: true,
		BindOptions: &mobymount.BindOptions{Propagation: mobymount.PropagationRPrivate},
	}}
	if spec.EgressGateway.UpstreamRoute != nil {
		routePath, _, err := m.loadUpstreamRoute(spec)
		if err != nil {
			return nil, nil, err
		}
		hostConfig.Mounts = append(hostConfig.Mounts, mobymount.Mount{
			Type: mobymount.TypeBind, Source: routePath,
			Target: egress.UpstreamRouteContainerPath, ReadOnly: true,
			BindOptions: &mobymount.BindOptions{Propagation: mobymount.PropagationRPrivate},
		})
	}
	return config, hostConfig, nil
}

func egressGatewayCommand(spec RuntimeSpec, action string) []string {
	if spec.EgressGateway == nil || spec.EgressGateway.BoundarySnapshot == nil {
		return nil
	}
	snapshot := spec.EgressGateway.BoundarySnapshot
	command := []string{
		action,
		"--snapshot-path", egress.SnapshotContainerPath,
		"--snapshot-id", snapshot.ID,
		"--snapshot-sha256", snapshot.SHA256,
	}
	if spec.EgressGateway.UpstreamRoute != nil {
		route := spec.EgressGateway.UpstreamRoute
		command = append(command,
			"--upstream-route-path", egress.UpstreamRouteContainerPath,
			"--upstream-route-id", route.ID,
			"--upstream-route-sha256", route.SHA256,
		)
	}
	return command
}

func egressGatewayHealthcheck(spec RuntimeSpec) *mobycontainer.HealthConfig {
	command := egressGatewayCommand(spec, "check")
	if command == nil {
		return nil
	}
	return &mobycontainer.HealthConfig{
		Test:     append([]string{"CMD", gatewayBinaryPath}, command...),
		Interval: time.Second, Timeout: 2 * time.Second,
		StartPeriod: 3 * time.Second, StartInterval: 250 * time.Millisecond, Retries: 3,
	}
}

func (m *DockerManager) loadBoundarySnapshot(spec RuntimeSpec) (string, egress.SnapshotReport, error) {
	if spec.EgressGateway == nil || spec.EgressGateway.BoundarySnapshot == nil {
		return "", egress.SnapshotReport{}, nil
	}
	if m.snapshotStore == nil {
		return "", egress.SnapshotReport{}, fmt.Errorf("%w: egress snapshot store is not configured", ErrRuntimeStateConflict)
	}
	reference := boundarySnapshotReference(spec)
	path, err := m.snapshotStore.Path(reference)
	if err != nil {
		return "", egress.SnapshotReport{}, fmt.Errorf("%w: resolve egress boundary snapshot: %v", ErrRuntimeStateConflict, err)
	}
	report, err := egress.LoadSnapshot(path, reference)
	if err != nil {
		return "", egress.SnapshotReport{}, fmt.Errorf("%w: verify egress boundary snapshot: %v", ErrRuntimeStateConflict, err)
	}
	return path, report, nil
}

func boundarySnapshotReference(spec RuntimeSpec) egress.SnapshotReference {
	snapshot := spec.EgressGateway.BoundarySnapshot
	return egress.SnapshotReference{ID: snapshot.ID, SHA256: snapshot.SHA256}
}

func upstreamRouteReference(spec RuntimeSpec) *egress.UpstreamRouteReference {
	if spec.EgressGateway == nil || spec.EgressGateway.UpstreamRoute == nil {
		return nil
	}
	route := spec.EgressGateway.UpstreamRoute
	return &egress.UpstreamRouteReference{ID: route.ID, SHA256: route.SHA256}
}

func (m *DockerManager) loadUpstreamRoute(spec RuntimeSpec) (string, egress.UpstreamRoute, error) {
	reference := upstreamRouteReference(spec)
	if reference == nil {
		return "", egress.UpstreamRoute{}, nil
	}
	if m.upstreamStore == nil {
		return "", egress.UpstreamRoute{}, fmt.Errorf("%w: egress upstream route store is not configured", ErrRuntimeStateConflict)
	}
	path, err := m.upstreamStore.Path(*reference)
	if err != nil {
		return "", egress.UpstreamRoute{}, fmt.Errorf("%w: resolve egress upstream route: %v", ErrRuntimeStateConflict, err)
	}
	route, err := egress.LoadUpstreamRoute(path, *reference)
	if err != nil {
		return "", egress.UpstreamRoute{}, fmt.Errorf("%w: verify egress upstream route: %v", ErrRuntimeStateConflict, err)
	}
	return path, route, nil
}

func (m *DockerManager) verifyEgressGatewayHostConfig(actual *mobycontainer.HostConfig, spec RuntimeSpec) error {
	expected := egressGatewayHostConfig(spec)
	if actual.NetworkMode != expected.NetworkMode || actual.Privileged || actual.PublishAllPorts || actual.AutoRemove || len(actual.Binds) != 0 || len(actual.Devices) != 0 || len(actual.DeviceRequests) != 0 || len(actual.PortBindings) != 0 {
		return fmt.Errorf("%w: egress gateway has host, device, privileged, or published-port access", ErrRuntimeStateConflict)
	}
	if spec.EgressGateway.BoundarySnapshot == nil {
		if len(actual.Mounts) != 0 {
			return fmt.Errorf("%w: legacy egress gateway has an unexpected mount", ErrRuntimeStateConflict)
		}
	} else {
		expectedPath, _, err := m.loadBoundarySnapshot(spec)
		if err != nil {
			return err
		}
		expectedMounts := map[string]string{egress.SnapshotContainerPath: expectedPath}
		if spec.EgressGateway.UpstreamRoute != nil {
			routePath, _, err := m.loadUpstreamRoute(spec)
			if err != nil {
				return err
			}
			expectedMounts[egress.UpstreamRouteContainerPath] = routePath
		}
		if len(actual.Mounts) != len(expectedMounts) {
			return fmt.Errorf("%w: egress gateway trusted mount count mismatch", ErrRuntimeStateConflict)
		}
		for _, mount := range actual.Mounts {
			expectedSource, ok := expectedMounts[mount.Target]
			if !ok || mount.Type != mobymount.TypeBind || mount.Source != expectedSource || !mount.ReadOnly || mount.BindOptions == nil || mount.BindOptions.Propagation != mobymount.PropagationRPrivate || mount.BindOptions.NonRecursive || mount.BindOptions.CreateMountpoint || mount.BindOptions.ReadOnlyNonRecursive || mount.BindOptions.ReadOnlyForceRecursive || mount.VolumeOptions != nil || mount.ImageOptions != nil || mount.TmpfsOptions != nil || mount.ClusterOptions != nil {
				return fmt.Errorf("%w: egress gateway trusted mount mismatch", ErrRuntimeStateConflict)
			}
			delete(expectedMounts, mount.Target)
		}
		if len(expectedMounts) != 0 {
			return fmt.Errorf("%w: egress gateway trusted mount is missing", ErrRuntimeStateConflict)
		}
	}
	if !actual.ReadonlyRootfs || len(actual.CapDrop) != 1 || !strings.EqualFold(actual.CapDrop[0], "ALL") || len(actual.CapAdd) != 0 || !containsString(actual.SecurityOpt, "no-new-privileges") {
		return fmt.Errorf("%w: egress gateway privilege restrictions mismatch", ErrRuntimeStateConflict)
	}
	if len(actual.DNS) != 0 || len(actual.DNSOptions) != 0 || len(actual.DNSSearch) != 0 || len(actual.ExtraHosts) != 0 || len(actual.Links) != 0 {
		return fmt.Errorf("%w: egress gateway declares custom DNS, hosts, or links", ErrRuntimeStateConflict)
	}
	if actual.RestartPolicy.Name != mobycontainer.RestartPolicyDisabled || actual.LogConfig.Type != expected.LogConfig.Type || len(actual.LogConfig.Config) != len(expected.LogConfig.Config) {
		return fmt.Errorf("%w: egress gateway restart or logging policy mismatch", ErrRuntimeStateConflict)
	}
	for key, value := range expected.LogConfig.Config {
		if actual.LogConfig.Config[key] != value {
			return fmt.Errorf("%w: egress gateway log option %s mismatch", ErrRuntimeStateConflict, key)
		}
	}
	if actual.NanoCPUs != expected.NanoCPUs || actual.Memory != expected.Memory || actual.MemorySwap != expected.MemorySwap || actual.PidsLimit == nil || *actual.PidsLimit != spec.EgressGateway.Resources.PIDs {
		return fmt.Errorf("%w: egress gateway CPU, memory, swap, or PIDs limits mismatch", ErrRuntimeStateConflict)
	}
	resources := spec.EgressGateway.Resources
	if len(actual.Ulimits) != 1 || actual.Ulimits[0] == nil || actual.Ulimits[0].Name != "nofile" || actual.Ulimits[0].Soft != int64(resources.NoFileSoft) || actual.Ulimits[0].Hard != int64(resources.NoFileHard) {
		return fmt.Errorf("%w: egress gateway nofile limit mismatch", ErrRuntimeStateConflict)
	}
	if len(actual.Tmpfs) != 1 || actual.Tmpfs["/tmp"] != expected.Tmpfs["/tmp"] {
		return fmt.Errorf("%w: egress gateway tmpfs mismatch", ErrRuntimeStateConflict)
	}
	return nil
}

func equalStrings(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func equalHealthcheck(actual, expected *mobycontainer.HealthConfig) bool {
	if actual == nil || expected == nil {
		return actual == nil && expected == nil
	}
	return equalStrings(actual.Test, expected.Test) && actual.Interval == expected.Interval && actual.Timeout == expected.Timeout && actual.StartPeriod == expected.StartPeriod && actual.StartInterval == expected.StartInterval && actual.Retries == expected.Retries
}

func healthySnapshotReport(health *mobycontainer.Health, reference egress.SnapshotReference, routeReference *egress.UpstreamRouteReference) bool {
	if health == nil || health.Status != mobycontainer.Healthy || len(health.Log) == 0 {
		return false
	}
	entry := health.Log[len(health.Log)-1]
	if entry == nil || entry.ExitCode != 0 {
		return false
	}
	var report egress.SnapshotReport
	if err := json.Unmarshal([]byte(strings.TrimSpace(entry.Output)), &report); err != nil {
		return false
	}
	if report.Event != "boundary_snapshot_healthy" || report.SnapshotID != reference.ID || report.SHA256 != reference.SHA256 {
		return false
	}
	if routeReference == nil {
		return report.UpstreamRouteID == "" && report.UpstreamRouteSHA256 == ""
	}
	return report.UpstreamRouteID == routeReference.ID && report.UpstreamRouteSHA256 == routeReference.SHA256
}

func egressGatewayNetworkingConfig(spec RuntimeSpec, conversationNetwork, egressNetwork ManagedResource) *mobynetwork.NetworkingConfig {
	return &mobynetwork.NetworkingConfig{EndpointsConfig: map[string]*mobynetwork.EndpointSettings{
		ConversationNetworkName(spec.ID): {NetworkID: conversationNetwork.ProviderID},
		EgressNetworkName(spec.ID):       {NetworkID: egressNetwork.ProviderID},
	}}
}

func (m *DockerManager) verifyEgressGatewayNetworks(ctx context.Context, spec RuntimeSpec, gateway mobycontainer.InspectResponse, agent *mobycontainer.InspectResponse, expectedStatus Status) error {
	if gateway.NetworkSettings == nil || len(gateway.NetworkSettings.Networks) != 2 {
		return fmt.Errorf("%w: egress gateway is not attached to exactly two networks", ErrRuntimeStateConflict)
	}
	internalEndpoint := gateway.NetworkSettings.Networks[ConversationNetworkName(spec.ID)]
	egressEndpoint := gateway.NetworkSettings.Networks[EgressNetworkName(spec.ID)]
	if internalEndpoint == nil || egressEndpoint == nil || strings.TrimSpace(internalEndpoint.NetworkID) == "" || strings.TrimSpace(egressEndpoint.NetworkID) == "" {
		return fmt.Errorf("%w: egress gateway network endpoints are incomplete", ErrRuntimeStateConflict)
	}
	if internalEndpoint.Gateway.IsValid() || internalEndpoint.IPv6Gateway.IsValid() {
		return fmt.Errorf("%w: egress gateway internal network exposes a host gateway", ErrRuntimeStateConflict)
	}
	internalResult, err := m.networkAPI.NetworkInspect(ctx, internalEndpoint.NetworkID, mobyclient.NetworkInspectOptions{})
	if err != nil {
		return fmt.Errorf("inspect egress gateway internal network: %w", err)
	}
	if _, err := m.verifyConversationNetwork(spec, gateway.Config.Labels[LabelSpecDigest], internalResult.Network, internalEndpoint.NetworkID, false); err != nil {
		return err
	}
	egressResult, err := m.networkAPI.NetworkInspect(ctx, egressEndpoint.NetworkID, mobyclient.NetworkInspectOptions{})
	if err != nil {
		return fmt.Errorf("inspect egress gateway egress network: %w", err)
	}
	if _, err := m.verifyEgressNetwork(spec, gateway.Config.Labels[LabelSpecDigest], egressResult.Network, egressEndpoint.NetworkID, false); err != nil {
		return err
	}
	if len(internalResult.Network.Services) != 0 || len(egressResult.Network.Services) != 0 {
		return fmt.Errorf("%w: gateway networks contain unexpected services", ErrRuntimeStateConflict)
	}
	if requiresPolicyDNS(spec) && agent != nil && agent.HostConfig != nil {
		expectedDNS, dnsErr := egressGatewayPolicyDNSAddress(gateway, spec)
		if dnsErr != nil {
			return dnsErr
		}
		if len(agent.HostConfig.DNS) != 1 || agent.HostConfig.DNS[0].String() != expectedDNS {
			return fmt.Errorf("%w: agent policy DNS does not match its egress gateway", ErrRuntimeStateConflict)
		}
		if agent.Config == nil {
			return fmt.Errorf("%w: agent proxy environment is unavailable", ErrRuntimeStateConflict)
		}
		if err := verifyRuntimeProxyEnvironment(agent.Config.Env, spec, expectedDNS); err != nil {
			return err
		}
	} else if agent != nil {
		if agent.Config == nil {
			return fmt.Errorf("%w: agent proxy environment is unavailable", ErrRuntimeStateConflict)
		}
		if err := verifyRuntimeProxyEnvironment(agent.Config.Env, spec, ""); err != nil {
			return err
		}
	}
	if expectedStatus == StatusRunning {
		if agent == nil || agent.State == nil || !agent.State.Running || len(internalResult.Network.Containers) != 2 || len(egressResult.Network.Containers) != 1 {
			return fmt.Errorf("%w: running gateway network attachment count mismatch", ErrRuntimeStateConflict)
		}
		if _, ok := internalResult.Network.Containers[gateway.ID]; !ok {
			return fmt.Errorf("%w: gateway internal attachment is missing", ErrRuntimeStateConflict)
		}
		if _, ok := internalResult.Network.Containers[agent.ID]; !ok {
			return fmt.Errorf("%w: agent internal attachment is missing", ErrRuntimeStateConflict)
		}
		if _, ok := egressResult.Network.Containers[gateway.ID]; !ok {
			return fmt.Errorf("%w: gateway egress attachment is missing", ErrRuntimeStateConflict)
		}
		return nil
	}
	if len(internalResult.Network.Containers) != 0 || len(egressResult.Network.Containers) != 0 {
		return fmt.Errorf("%w: stopped topology retains active network attachments", ErrRuntimeStateConflict)
	}
	return nil
}

func egressGatewayLabels(ownerID string, spec RuntimeSpec) map[string]string {
	return expectedEgressGatewayLabels(ownerID, spec, RuntimeSpecDigest(spec))
}

func expectedEgressGatewayLabels(ownerID string, spec RuntimeSpec, specDigest string) map[string]string {
	gateway := spec.EgressGateway
	resources := gateway.Resources
	labels := map[string]string{
		LabelManaged: "true", LabelOwner: ownerID,
		LabelRuntimeID: string(spec.ID), LabelResourceID: string(spec.ID),
		LabelConversationID: spec.ConversationID, LabelResourceKind: ResourceKindEgressGateway,
		LabelImageDigest: gateway.Image.Digest, LabelImagePlatform: gateway.Image.Platform,
		LabelSpecDigest: specDigest, LabelNetworkMode: gatewayNetworkModeLabel,
		LabelNanoCPUs: strconv.FormatInt(resources.NanoCPUs, 10), LabelMemoryBytes: strconv.FormatInt(resources.MemoryBytes, 10),
		LabelPIDs: strconv.FormatInt(resources.PIDs, 10), LabelNoFileSoft: strconv.FormatUint(resources.NoFileSoft, 10),
		LabelNoFileHard: strconv.FormatUint(resources.NoFileHard, 10), LabelTmpfsBytes: strconv.FormatInt(resources.TmpfsBytes, 10),
		LabelLogMaxBytes: strconv.FormatInt(resources.LogMaxBytes, 10), LabelLogMaxFiles: strconv.Itoa(resources.LogMaxFiles),
	}
	if gateway.BoundarySnapshot != nil {
		labels[LabelEgressSnapshotID] = gateway.BoundarySnapshot.ID
		labels[LabelEgressSnapshotSHA256] = gateway.BoundarySnapshot.SHA256
	}
	if gateway.UpstreamRoute != nil {
		labels[LabelEgressUpstreamRouteID] = gateway.UpstreamRoute.ID
		labels[LabelEgressUpstreamSHA256] = gateway.UpstreamRoute.SHA256
	}
	return labels
}

func egressGatewaySpecFromAgentLabels(labels map[string]string) (*EgressGatewaySpec, error) {
	enabled := strings.TrimSpace(labels[LabelEgressGateway])
	keys := []string{
		LabelEgressImageRepository, LabelEgressImageDigest, LabelEgressImagePlatform,
		LabelEgressNanoCPUs, LabelEgressMemoryBytes, LabelEgressPIDs,
		LabelEgressNoFileSoft, LabelEgressNoFileHard, LabelEgressTmpfsBytes,
		LabelEgressLogMaxBytes, LabelEgressLogMaxFiles,
		LabelEgressSnapshotID, LabelEgressSnapshotSHA256,
		LabelEgressUpstreamRouteID, LabelEgressUpstreamSHA256,
	}
	if enabled == "" {
		for _, key := range keys {
			if strings.TrimSpace(labels[key]) != "" {
				return nil, fmt.Errorf("egress gateway labels exist without the enable marker")
			}
		}
		return nil, nil
	}
	if enabled != "true" {
		return nil, fmt.Errorf("invalid egress gateway enable label")
	}
	nanoCPUs, err := positiveLabelInt64(labels, LabelEgressNanoCPUs)
	if err != nil {
		return nil, err
	}
	memoryBytes, err := positiveLabelInt64(labels, LabelEgressMemoryBytes)
	if err != nil {
		return nil, err
	}
	pids, err := positiveLabelInt64(labels, LabelEgressPIDs)
	if err != nil {
		return nil, err
	}
	nofileSoft, err := positiveLabelUint64(labels, LabelEgressNoFileSoft)
	if err != nil {
		return nil, err
	}
	nofileHard, err := positiveLabelUint64(labels, LabelEgressNoFileHard)
	if err != nil {
		return nil, err
	}
	tmpfsBytes, err := positiveLabelInt64(labels, LabelEgressTmpfsBytes)
	if err != nil {
		return nil, err
	}
	logMaxBytes, err := positiveLabelInt64(labels, LabelEgressLogMaxBytes)
	if err != nil {
		return nil, err
	}
	logMaxFiles, err := positiveLabelInt64(labels, LabelEgressLogMaxFiles)
	if err != nil || logMaxFiles > int64(^uint(0)>>1) {
		return nil, errors.New("invalid egress gateway log file label")
	}
	gateway := &EgressGatewaySpec{
		Image: ImageReference{
			Repository: strings.TrimSpace(labels[LabelEgressImageRepository]),
			Digest:     strings.TrimSpace(labels[LabelEgressImageDigest]),
			Platform:   strings.TrimSpace(labels[LabelEgressImagePlatform]),
		},
		Resources: EgressGatewayResources{
			NanoCPUs: nanoCPUs, MemoryBytes: memoryBytes, PIDs: pids,
			NoFileSoft: nofileSoft, NoFileHard: nofileHard, TmpfsBytes: tmpfsBytes,
			LogMaxBytes: logMaxBytes, LogMaxFiles: int(logMaxFiles),
		},
	}
	snapshotID := strings.TrimSpace(labels[LabelEgressSnapshotID])
	snapshotSHA256 := strings.TrimSpace(labels[LabelEgressSnapshotSHA256])
	if snapshotID != "" || snapshotSHA256 != "" {
		gateway.BoundarySnapshot = &EgressBoundarySnapshotSpec{ID: snapshotID, SHA256: snapshotSHA256}
	}
	routeID := strings.TrimSpace(labels[LabelEgressUpstreamRouteID])
	routeSHA256 := strings.TrimSpace(labels[LabelEgressUpstreamSHA256])
	if routeID != "" || routeSHA256 != "" {
		gateway.UpstreamRoute = &EgressUpstreamRouteSpec{ID: routeID, SHA256: routeSHA256}
	}
	if err := ValidateEgressGatewaySpec(*gateway); err != nil {
		return nil, err
	}
	return gateway, nil
}

func gatewayCreatedAt(actual mobycontainer.InspectResponse) time.Time {
	created, _ := time.Parse(time.RFC3339Nano, actual.Created)
	return created.UTC()
}
