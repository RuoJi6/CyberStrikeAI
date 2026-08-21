package container

import (
	"context"
	"fmt"
	"os"
	"strings"

	containerderrdefs "github.com/containerd/errdefs"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobymount "github.com/moby/moby/api/types/mount"
	mobyclient "github.com/moby/moby/client"
)

var _ RuntimeReadinessChecker = (*DockerManager)(nil)

// ValidateReadiness re-reads all critical state from Docker. It never trusts
// the Runtime returned by Create beyond using its provider ID as a lookup key.
func (m *DockerManager) ValidateReadiness(ctx context.Context, runtime Runtime, spec RuntimeSpec) (ReadinessReport, error) {
	if m == nil || m.api == nil {
		return ReadinessReport{}, fmt.Errorf("%w: engine client is not configured", ErrEngineUnavailable)
	}
	if err := ValidateSpec(spec); err != nil {
		return ReadinessReport{}, err
	}
	if !spec.Readiness.Enabled {
		return ReadinessReport{}, fmt.Errorf("%w: readiness policy is disabled", ErrRuntimeNotReady)
	}
	providerID := strings.TrimSpace(runtime.ProviderID)
	if providerID == "" {
		return ReadinessReport{}, invalidSpec("provider id is required for readiness validation")
	}
	ctx, cancel := context.WithTimeout(ctx, m.operationTimeout)
	defer cancel()
	result, err := m.api.ContainerInspect(ctx, providerID, mobyclient.ContainerInspectOptions{Size: false})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return ReadinessReport{}, fmt.Errorf("%w: provider runtime %s", ErrNotFound, providerID)
		}
		return ReadinessReport{}, fmt.Errorf("%w: inspect provider runtime %s: %v", ErrRuntimeNotReady, providerID, err)
	}
	actual := result.Container
	if actual.ID != providerID || strings.TrimPrefix(actual.Name, "/") != runtimeContainerName(spec.ID) {
		return ReadinessReport{}, fmt.Errorf("%w: runtime identity mismatch", ErrRuntimeNotReady)
	}
	if actual.State == nil || actual.State.Running || actual.State.Status != mobycontainer.StateCreated {
		return ReadinessReport{}, fmt.Errorf("%w: runtime must remain in created state during readiness validation", ErrRuntimeNotReady)
	}
	if actual.Config == nil || actual.HostConfig == nil {
		return ReadinessReport{}, fmt.Errorf("%w: runtime configuration is incomplete", ErrRuntimeNotReady)
	}
	if actual.Config.WorkingDir != spec.Workspace.MountPath {
		return ReadinessReport{}, fmt.Errorf("%w: workspace working directory mismatch", ErrRuntimeNotReady)
	}
	for key, expected := range runtimeLabels(m.ownerID, spec) {
		if actual.Config.Labels[key] != expected {
			return ReadinessReport{}, fmt.Errorf("%w: runtime label %s mismatch", ErrRuntimeNotReady, key)
		}
	}
	if err := m.verifyObservedSecurityBaseline(ctx, actual); err != nil {
		return ReadinessReport{}, fmt.Errorf("%w: %v", ErrRuntimeNotReady, err)
	}
	if spec.EgressGateway != nil {
		if _, err := m.inspectOwnedEgressGateway(ctx, spec, &actual, StatusStopped); err != nil {
			return ReadinessReport{}, fmt.Errorf("%w: %v", ErrRuntimeNotReady, err)
		}
	}
	if err := verifyReadinessIsolation(actual, spec); err != nil {
		return ReadinessReport{}, err
	}
	if _, err := m.VerifyRuntimeImage(ctx, providerID, spec.Image); err != nil {
		return ReadinessReport{}, fmt.Errorf("%w: %v", ErrRuntimeNotReady, err)
	}
	for _, tool := range spec.Readiness.Inventory.Tools {
		statResult, statErr := m.api.ContainerStatPath(ctx, providerID, mobyclient.ContainerStatPathOptions{Path: tool.Path})
		if statErr != nil {
			if containerderrdefs.IsNotFound(statErr) {
				return ReadinessReport{}, fmt.Errorf("%w: inventory tool %s is missing at %s", ErrRuntimeNotReady, tool.Name, tool.Path)
			}
			return ReadinessReport{}, fmt.Errorf("%w: inventory tool %s could not be inspected", ErrRuntimeNotReady, tool.Name)
		}
		stat := statResult.Stat
		if stat.Mode.IsDir() || stat.Mode&(os.ModeNamedPipe|os.ModeSocket|os.ModeDevice) != 0 {
			return ReadinessReport{}, fmt.Errorf("%w: inventory tool %s is not a regular executable or symlink", ErrRuntimeNotReady, tool.Name)
		}
		if stat.Mode&os.ModeSymlink == 0 && stat.Mode.Perm()&0o111 == 0 {
			return ReadinessReport{}, fmt.Errorf("%w: inventory tool %s is not executable", ErrRuntimeNotReady, tool.Name)
		}
	}
	return ReadinessReport{
		InventoryDigest: spec.Readiness.InventoryDigest,
		ToolCount:       len(spec.Readiness.Inventory.Tools),
	}, nil
}

func verifyReadinessIsolation(actual mobycontainer.InspectResponse, spec RuntimeSpec) error {
	if actual.Config == nil || actual.HostConfig == nil {
		return fmt.Errorf("%w: runtime configuration is incomplete", ErrRuntimeNotReady)
	}
	switch spec.Security.NetworkMode {
	case NetworkNone:
		if !actual.Config.NetworkDisabled || actual.HostConfig.NetworkMode != mobycontainer.NetworkMode(NetworkNone) {
			return fmt.Errorf("%w: runtime none network is not disabled", ErrRuntimeNotReady)
		}
	case NetworkInternal:
		if actual.Config.NetworkDisabled || actual.HostConfig.NetworkMode != mobycontainer.NetworkMode(ConversationNetworkName(spec.ID)) {
			return fmt.Errorf("%w: runtime internal network mode mismatch", ErrRuntimeNotReady)
		}
	default:
		return fmt.Errorf("%w: runtime network mode is invalid", ErrRuntimeNotReady)
	}
	if len(actual.HostConfig.DNS) != 0 || len(actual.HostConfig.DNSOptions) != 0 || len(actual.HostConfig.DNSSearch) != 0 || len(actual.HostConfig.ExtraHosts) != 0 || len(actual.HostConfig.Links) != 0 || len(actual.HostConfig.PortBindings) != 0 {
		return fmt.Errorf("%w: runtime declares DNS, host, link, or port egress settings", ErrRuntimeNotReady)
	}
	if actual.NetworkSettings != nil {
		if len(actual.NetworkSettings.Ports) != 0 {
			return fmt.Errorf("%w: runtime has an assigned network address or port", ErrRuntimeNotReady)
		}
		for networkName, endpoint := range actual.NetworkSettings.Networks {
			if spec.Security.NetworkMode == NetworkNone {
				if networkName != string(NetworkNone) {
					return fmt.Errorf("%w: runtime is attached to network %s", ErrRuntimeNotReady, networkName)
				}
				if endpoint != nil && (endpoint.Gateway.IsValid() || endpoint.IPAddress.IsValid() || endpoint.IPv6Gateway.IsValid() || endpoint.GlobalIPv6Address.IsValid()) {
					return fmt.Errorf("%w: runtime none network has an assigned address", ErrRuntimeNotReady)
				}
				continue
			}
			if networkName != ConversationNetworkName(spec.ID) || endpoint == nil || strings.TrimSpace(endpoint.NetworkID) == "" {
				return fmt.Errorf("%w: runtime internal network endpoint mismatch", ErrRuntimeNotReady)
			}
		}
	}
	if !spec.Workspace.Persistent && len(actual.Mounts) != 0 {
		return fmt.Errorf("%w: ephemeral runtime has an unexpected mount", ErrRuntimeNotReady)
	}
	if spec.Workspace.Persistent && len(actual.Mounts) != 1 {
		return fmt.Errorf("%w: persistent runtime does not have exactly one workspace volume", ErrRuntimeNotReady)
	}
	for _, mount := range actual.Mounts {
		if strings.EqualFold(mount.Destination, "/var/run/docker.sock") || strings.EqualFold(mount.Destination, "/run/docker.sock") || strings.Contains(strings.ToLower(mount.Source), "docker.sock") {
			return fmt.Errorf("%w: Docker Socket is mounted into the runtime", ErrRuntimeNotReady)
		}
		if !spec.Workspace.Persistent || mount.Type != mobymount.TypeVolume || mount.Name != spec.Workspace.VolumeName || mount.Destination != spec.Workspace.MountPath || !mount.RW {
			return fmt.Errorf("%w: unexpected runtime mount at %s", ErrRuntimeNotReady, mount.Destination)
		}
	}
	for path := range actual.Config.Volumes {
		if path == "/var/run/docker.sock" || path == "/run/docker.sock" {
			return fmt.Errorf("%w: image declares a Docker Socket volume", ErrRuntimeNotReady)
		}
	}
	return nil
}
