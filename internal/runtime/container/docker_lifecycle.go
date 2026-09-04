package container

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	containerderrdefs "github.com/containerd/errdefs"
	"github.com/distribution/reference"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobyclient "github.com/moby/moby/client"
)

const defaultRuntimeStopTimeout = 10 * time.Second

// Inspect resolves only the deterministic CyberStrikeAI name for id and then
// verifies all ownership and phase-1 isolation labels. A user-controlled
// Docker provider ID is never accepted by this boundary.
func (m *DockerManager) Inspect(ctx context.Context, id RuntimeID) (Runtime, error) {
	if err := validateRuntimeID(id); err != nil {
		return Runtime{}, err
	}
	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return Runtime{}, err
	}
	defer cancel()
	return m.inspectOwned(operationCtx, id)
}

func (m *DockerManager) ListOwned(ctx context.Context) ([]Runtime, error) {
	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	filters := make(mobyclient.Filters).
		Add("label", LabelManaged+"=true").
		Add("label", LabelOwner+"="+m.ownerID).
		Add("label", LabelResourceKind+"="+ResourceKindAgent)
	result, err := m.api.ContainerList(operationCtx, mobyclient.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return nil, fmt.Errorf("list owned runtimes: %w", err)
	}
	runtimes := make([]Runtime, 0, len(result.Items))
	seen := make(map[RuntimeID]string, len(result.Items))
	for _, summary := range result.Items {
		id := RuntimeID(strings.TrimSpace(summary.Labels[LabelRuntimeID]))
		if err := validateRuntimeID(id); err != nil {
			return nil, fmt.Errorf("%w: owned container %s has an invalid runtime id", ErrRuntimeStateConflict, summary.ID)
		}
		if previous, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("%w: duplicate providers %s and %s claim runtime %s", ErrRuntimeStateConflict, previous, summary.ID, id)
		}
		seen[id] = summary.ID
		inspection, inspectErr := m.api.ContainerInspect(operationCtx, summary.ID, mobyclient.ContainerInspectOptions{Size: false})
		if inspectErr != nil {
			if containerderrdefs.IsNotFound(inspectErr) {
				continue
			}
			return nil, fmt.Errorf("inspect owned runtime %s: %w", id, inspectErr)
		}
		runtime, convertErr := m.runtimeFromInspection(operationCtx, id, inspection.Container)
		if convertErr != nil {
			return nil, convertErr
		}
		runtimes = append(runtimes, runtime)
	}
	sort.Slice(runtimes, func(i, j int) bool { return runtimes[i].ID < runtimes[j].ID })
	return runtimes, nil
}

func (m *DockerManager) Start(ctx context.Context, id RuntimeID) (Runtime, error) {
	if err := validateRuntimeID(id); err != nil {
		return Runtime{}, err
	}
	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return Runtime{}, err
	}
	defer cancel()
	runtime, err := m.inspectOwned(operationCtx, id)
	if err != nil {
		return Runtime{}, err
	}
	if runtime.Status == StatusRunning {
		return runtime, nil
	}
	if runtime.Status != StatusStopped {
		return Runtime{}, fmt.Errorf("%w: cannot start runtime %s in %s", ErrRuntimeStateConflict, id, runtime.Status)
	}
	spec, gateway, err := m.inspectRuntimeTopology(operationCtx, runtime)
	if err != nil {
		return Runtime{}, err
	}
	if spec.EgressGateway != nil {
		if _, err := m.api.ContainerStart(operationCtx, gateway.ID, mobyclient.ContainerStartOptions{}); err != nil {
			if containerderrdefs.IsNotFound(err) {
				return Runtime{}, fmt.Errorf("%w: egress gateway for runtime %s", ErrNotFound, id)
			}
			return Runtime{}, fmt.Errorf("start egress gateway for runtime %s: %w", id, err)
		}
		if spec.EgressGateway.BoundarySnapshot != nil {
			if err := m.waitForEgressGatewaySnapshot(operationCtx, spec, gateway.ID); err != nil {
				seconds := int(defaultRuntimeStopTimeout / time.Second)
				rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), rollbackTimeout)
				_, rollbackErr := m.api.ContainerStop(rollbackCtx, gateway.ID, mobyclient.ContainerStopOptions{Timeout: &seconds})
				rollbackCancel()
				if rollbackErr != nil && !containerderrdefs.IsNotFound(rollbackErr) {
					err = errors.Join(err, fmt.Errorf("rollback unready egress gateway start: %w", rollbackErr))
				}
				return Runtime{}, err
			}
		}
	}
	if _, err := m.api.ContainerStart(operationCtx, runtime.ProviderID, mobyclient.ContainerStartOptions{}); err != nil {
		if spec.EgressGateway != nil {
			seconds := int(defaultRuntimeStopTimeout / time.Second)
			_, rollbackErr := m.api.ContainerStop(operationCtx, gateway.ID, mobyclient.ContainerStopOptions{Timeout: &seconds})
			if rollbackErr != nil && !containerderrdefs.IsNotFound(rollbackErr) {
				err = errors.Join(err, fmt.Errorf("rollback egress gateway start: %w", rollbackErr))
			}
		}
		if containerderrdefs.IsNotFound(err) {
			return Runtime{}, fmt.Errorf("%w: runtime %s", ErrNotFound, id)
		}
		return Runtime{}, fmt.Errorf("start runtime %s: %w", id, err)
	}
	if spec.EgressGateway != nil {
		if err := m.configureRuntimeDefaultRoute(operationCtx, spec, runtime.ProviderID, gateway); err != nil {
			seconds := int(defaultRuntimeStopTimeout / time.Second)
			_, agentStopErr := m.api.ContainerStop(operationCtx, runtime.ProviderID, mobyclient.ContainerStopOptions{Timeout: &seconds})
			_, gatewayStopErr := m.api.ContainerStop(operationCtx, gateway.ID, mobyclient.ContainerStopOptions{Timeout: &seconds})
			if agentStopErr != nil && !containerderrdefs.IsNotFound(agentStopErr) {
				err = errors.Join(err, fmt.Errorf("rollback runtime after route failure: %w", agentStopErr))
			}
			if gatewayStopErr != nil && !containerderrdefs.IsNotFound(gatewayStopErr) {
				err = errors.Join(err, fmt.Errorf("rollback egress gateway after route failure: %w", gatewayStopErr))
			}
			return Runtime{}, err
		}
	}
	if err := m.waitForRuntimeWorkspaceReady(operationCtx, spec.ID, spec.Workspace.MountPath, runtime.ProviderID); err != nil {
		seconds := int(defaultRuntimeStopTimeout / time.Second)
		_, agentStopErr := m.api.ContainerStop(operationCtx, runtime.ProviderID, mobyclient.ContainerStopOptions{Timeout: &seconds})
		if agentStopErr != nil && !containerderrdefs.IsNotFound(agentStopErr) {
			err = errors.Join(err, fmt.Errorf("rollback unready runtime start: %w", agentStopErr))
		}
		if spec.EgressGateway != nil {
			_, gatewayStopErr := m.api.ContainerStop(operationCtx, gateway.ID, mobyclient.ContainerStopOptions{Timeout: &seconds})
			if gatewayStopErr != nil && !containerderrdefs.IsNotFound(gatewayStopErr) {
				err = errors.Join(err, fmt.Errorf("rollback gateway after runtime readiness failure: %w", gatewayStopErr))
			}
		}
		return Runtime{}, err
	}
	started, err := m.inspectOwned(operationCtx, id)
	if err != nil {
		return Runtime{}, err
	}
	if started.Status != StatusRunning {
		return Runtime{}, fmt.Errorf("%w: runtime %s did not enter running state", ErrRuntimeStateConflict, id)
	}
	return started, nil
}

func (m *DockerManager) waitForRuntimeWorkspaceReady(ctx context.Context, id RuntimeID, workspacePath, providerID string) error {
	created, err := m.execAPI.ExecCreate(ctx, providerID, mobyclient.ExecCreateOptions{
		Privileged:   false,
		User:         runtimeRootExecUser,
		AttachStdin:  false,
		AttachStdout: true,
		AttachStderr: true,
		Env:          runtimeWorkspaceEnvironment(),
		WorkingDir:   workspacePath,
		Cmd:          []string{"/bin/sh", "-c", runtimeWorkspaceReadyWaitScript},
	})
	if err != nil {
		return fmt.Errorf("%w: create runtime %s workspace readiness probe: %v", ErrRuntimeNotReady, id, err)
	}
	if strings.TrimSpace(created.ID) == "" {
		return fmt.Errorf("%w: runtime %s workspace readiness probe has no exec id", ErrRuntimeNotReady, id)
	}
	attached, err := m.execAPI.ExecAttach(ctx, created.ID, mobyclient.ExecAttachOptions{})
	if err != nil {
		return fmt.Errorf("%w: attach runtime %s workspace readiness probe: %v", ErrRuntimeNotReady, id, err)
	}
	defer attached.Close()
	if _, err := io.Copy(io.Discard, attached.Reader); err != nil {
		return fmt.Errorf("%w: read runtime %s workspace readiness probe: %v", ErrRuntimeNotReady, id, err)
	}
	inspection, err := m.execAPI.ExecInspect(ctx, created.ID, mobyclient.ExecInspectOptions{})
	if err != nil {
		return fmt.Errorf("%w: inspect runtime %s workspace readiness probe: %v", ErrRuntimeNotReady, id, err)
	}
	if inspection.ID != created.ID || inspection.ContainerID != providerID || inspection.Running {
		return fmt.Errorf("%w: runtime %s workspace readiness probe identity mismatch", ErrRuntimeNotReady, id)
	}
	if inspection.ExitCode != 0 {
		return fmt.Errorf("%w: runtime %s workspace initialization probe exited with status %d", ErrRuntimeNotReady, id, inspection.ExitCode)
	}
	return nil
}

func (m *DockerManager) waitForEgressGatewaySnapshot(ctx context.Context, spec RuntimeSpec, providerID string) error {
	reference := boundarySnapshotReference(spec)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, _, err := m.loadBoundarySnapshot(spec); err != nil {
			return fmt.Errorf("%w: %v", ErrRuntimeNotReady, err)
		}
		if _, _, err := m.loadUpstreamRoute(spec); err != nil {
			return fmt.Errorf("%w: %v", ErrRuntimeNotReady, err)
		}
		if _, _, err := m.loadAuthProfiles(spec); err != nil {
			return fmt.Errorf("%w: %v", ErrRuntimeNotReady, err)
		}
		if _, _, _, err := m.loadTLSAuthority(spec); err != nil {
			return fmt.Errorf("%w: %v", ErrRuntimeNotReady, err)
		}
		result, err := m.api.ContainerInspect(ctx, providerID, mobyclient.ContainerInspectOptions{Size: false})
		if err != nil {
			if containerderrdefs.IsNotFound(err) {
				return fmt.Errorf("%w: egress gateway for runtime %s disappeared", ErrRuntimeNotReady, spec.ID)
			}
			if ctx.Err() != nil {
				return fmt.Errorf("%w: timed out waiting for egress snapshot %s: %v", ErrRuntimeNotReady, reference.ID, ctx.Err())
			}
			return fmt.Errorf("%w: inspect egress gateway health: %v", ErrRuntimeNotReady, err)
		}
		state := result.Container.State
		if state == nil {
			return fmt.Errorf("%w: egress gateway state is missing", ErrRuntimeNotReady)
		}
		if state.Running && healthySnapshotReport(state.Health, reference, upstreamRouteReference(spec), authProfilesReference(spec), tlsAuthorityReference(spec)) {
			return nil
		}
		if !state.Running || state.Status == mobycontainer.StateExited || state.Status == mobycontainer.StateDead || (state.Health != nil && state.Health.Status == mobycontainer.Unhealthy) {
			return fmt.Errorf("%w: egress gateway did not validate snapshot %s", ErrRuntimeNotReady, reference.ID)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: timed out waiting for egress snapshot %s: %v", ErrRuntimeNotReady, reference.ID, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (m *DockerManager) Stop(ctx context.Context, id RuntimeID, options StopOptions) (Runtime, error) {
	if err := validateRuntimeID(id); err != nil {
		return Runtime{}, err
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = defaultRuntimeStopTimeout
	}
	if timeout < 0 || timeout > m.operationTimeout {
		return Runtime{}, invalidSpec("stop timeout must be positive and no greater than the operation timeout")
	}
	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return Runtime{}, err
	}
	defer cancel()
	runtime, err := m.inspectOwned(operationCtx, id)
	if err != nil {
		return Runtime{}, err
	}
	if runtime.Status == StatusStopped {
		return runtime, nil
	}
	if runtime.Status != StatusRunning && runtime.Status != StatusStarting {
		return Runtime{}, fmt.Errorf("%w: cannot stop runtime %s in %s", ErrRuntimeStateConflict, id, runtime.Status)
	}
	spec, gateway, err := m.inspectRuntimeTopology(operationCtx, runtime)
	if err != nil {
		return Runtime{}, err
	}
	seconds := int((timeout + time.Second - 1) / time.Second)
	if _, err := m.api.ContainerStop(operationCtx, runtime.ProviderID, mobyclient.ContainerStopOptions{Timeout: &seconds}); err != nil {
		if containerderrdefs.IsNotFound(err) {
			return Runtime{}, fmt.Errorf("%w: runtime %s", ErrNotFound, id)
		}
		return Runtime{}, fmt.Errorf("stop runtime %s: %w", id, err)
	}
	if spec.EgressGateway != nil {
		if _, err := m.api.ContainerStop(operationCtx, gateway.ID, mobyclient.ContainerStopOptions{Timeout: &seconds}); err != nil {
			_, rollbackErr := m.api.ContainerStart(operationCtx, runtime.ProviderID, mobyclient.ContainerStartOptions{})
			if rollbackErr != nil && !containerderrdefs.IsNotFound(rollbackErr) {
				err = errors.Join(err, fmt.Errorf("rollback agent stop: %w", rollbackErr))
			}
			if containerderrdefs.IsNotFound(err) {
				return Runtime{}, fmt.Errorf("%w: egress gateway for runtime %s", ErrNotFound, id)
			}
			return Runtime{}, fmt.Errorf("stop egress gateway for runtime %s: %w", id, err)
		}
	}
	stopped, err := m.inspectOwned(operationCtx, id)
	if err != nil {
		return Runtime{}, err
	}
	if stopped.Status != StatusStopped {
		return Runtime{}, fmt.Errorf("%w: runtime %s did not enter stopped state", ErrRuntimeStateConflict, id)
	}
	return stopped, nil
}

func (m *DockerManager) inspectRuntimeTopology(ctx context.Context, runtime Runtime) (RuntimeSpec, mobycontainer.InspectResponse, error) {
	result, err := m.api.ContainerInspect(ctx, runtime.ProviderID, mobyclient.ContainerInspectOptions{Size: false})
	if err != nil {
		return RuntimeSpec{}, mobycontainer.InspectResponse{}, fmt.Errorf("inspect runtime topology %s: %w", runtime.ID, err)
	}
	if result.Container.Config == nil {
		return RuntimeSpec{}, mobycontainer.InspectResponse{}, fmt.Errorf("%w: runtime topology labels are missing", ErrRuntimeStateConflict)
	}
	spec, err := runtimeSecuritySpecFromLabels(result.Container.Config.Labels)
	if err != nil {
		return RuntimeSpec{}, mobycontainer.InspectResponse{}, fmt.Errorf("%w: runtime topology labels are invalid", ErrRuntimeStateConflict)
	}
	if spec.EgressGateway == nil {
		return spec, mobycontainer.InspectResponse{}, nil
	}
	gateway, err := m.inspectOwnedEgressGateway(ctx, spec, &result.Container, runtime.Status)
	return spec, gateway, err
}

func (m *DockerManager) Rebuild(ctx context.Context, id RuntimeID, options RebuildOptions) (Runtime, error) {
	if err := validateRuntimeID(id); err != nil {
		return Runtime{}, err
	}
	if err := ValidateSpec(options.Spec); err != nil {
		return Runtime{}, err
	}
	if options.Spec.ID != id {
		return Runtime{}, invalidSpec("rebuild runtime identity cannot change")
	}
	authorizedWorkspaceSpecDigest := options.AuthorizedWorkspaceSpecDigest
	if options.Spec.Workspace.Persistent && !options.Spec.Workspace.Shared && !options.RemoveWorkspace {
		operationCtx, cancel, contextErr := m.operationContext(ctx)
		if contextErr != nil {
			return Runtime{}, contextErr
		}
		observedDigest, authorizationErr := m.workspaceVolumeDigestForRebuild(operationCtx, options.Spec)
		cancel()
		if authorizationErr != nil {
			return Runtime{}, authorizationErr
		}
		if observedDigest != "" {
			authorizedWorkspaceSpecDigest = observedDigest
		}
	}
	current, err := m.Inspect(ctx, id)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Runtime{}, err
	}
	if err == nil {
		if current.ConversationID != options.Spec.ConversationID {
			return Runtime{}, invalidSpec("rebuild conversation identity cannot change")
		}
		if current.Status != StatusStopped {
			return Runtime{}, fmt.Errorf("%w: runtime %s must be stopped before rebuild", ErrRuntimeStateConflict, id)
		}
		operationCtx, cancel, contextErr := m.operationContext(ctx)
		if contextErr != nil {
			return Runtime{}, contextErr
		}
		inspection, inspectErr := m.api.ContainerInspect(operationCtx, current.ProviderID, mobyclient.ContainerInspectOptions{Size: false})
		if inspectErr != nil {
			cancel()
			return Runtime{}, fmt.Errorf("inspect stopped runtime %s for rebuild: %w", id, inspectErr)
		}
		if inspection.Container.Config == nil {
			cancel()
			return Runtime{}, fmt.Errorf("%w: stopped runtime %s topology labels are missing", ErrRuntimeStateConflict, id)
		}
		currentSpec, specErr := runtimeSecuritySpecFromLabels(inspection.Container.Config.Labels)
		if specErr != nil {
			cancel()
			return Runtime{}, fmt.Errorf("%w: runtime %s topology labels are invalid", ErrRuntimeStateConflict, id)
		}
		var gateway mobycontainer.InspectResponse
		if currentSpec.EgressGateway != nil {
			gateway, specErr = m.inspectOwnedEgressGateway(operationCtx, currentSpec, &inspection.Container, StatusStopped)
			if specErr != nil {
				cancel()
				return Runtime{}, specErr
			}
		}
		_, removeErr := m.api.ContainerRemove(operationCtx, current.ProviderID, mobyclient.ContainerRemoveOptions{Force: false, RemoveVolumes: false})
		if removeErr != nil && !containerderrdefs.IsNotFound(removeErr) {
			cancel()
			return Runtime{}, fmt.Errorf("remove stopped runtime %s for rebuild: %w", id, removeErr)
		}
		if currentSpec.EgressGateway != nil {
			if _, gatewayRemoveErr := m.api.ContainerRemove(operationCtx, gateway.ID, mobyclient.ContainerRemoveOptions{Force: false, RemoveVolumes: false}); gatewayRemoveErr != nil && !containerderrdefs.IsNotFound(gatewayRemoveErr) {
				cancel()
				return Runtime{}, fmt.Errorf("remove stopped egress gateway %s for rebuild: %w", id, gatewayRemoveErr)
			}
			if networkErr := m.deleteOwnedEgressNetwork(operationCtx, currentSpec, inspection.Container.Config.Labels[LabelSpecDigest]); networkErr != nil && !errors.Is(networkErr, ErrNotFound) {
				cancel()
				return Runtime{}, fmt.Errorf("remove egress network %s for rebuild: %w", id, networkErr)
			}
		}
		if currentSpec.Security.NetworkMode == NetworkInternal {
			if networkErr := m.deleteOwnedConversationNetwork(operationCtx, currentSpec, inspection.Container.Config.Labels[LabelSpecDigest]); networkErr != nil && !errors.Is(networkErr, ErrNotFound) {
				cancel()
				return Runtime{}, fmt.Errorf("remove conversation network %s for rebuild: %w", id, networkErr)
			}
		}
		cancel()
	} else {
		operationCtx, cancel, contextErr := m.operationContext(ctx)
		if contextErr != nil {
			return Runtime{}, contextErr
		}
		if _, cleanupErr := m.deleteOwnedEgressGatewayByRuntimeID(operationCtx, id); cleanupErr != nil {
			cancel()
			return Runtime{}, fmt.Errorf("recover egress gateway before rebuild %s: %w", id, cleanupErr)
		}
		if _, cleanupErr := m.deleteOwnedEgressNetworkByRuntimeID(operationCtx, id); cleanupErr != nil {
			cancel()
			return Runtime{}, fmt.Errorf("recover egress network before rebuild %s: %w", id, cleanupErr)
		}
		if _, cleanupErr := m.deleteOwnedConversationNetworkByRuntimeID(operationCtx, id); cleanupErr != nil {
			cancel()
			return Runtime{}, fmt.Errorf("recover conversation network before rebuild %s: %w", id, cleanupErr)
		}
		cancel()
	}
	if options.RemoveWorkspace && options.Spec.Workspace.Persistent && !options.Spec.Workspace.Shared {
		operationCtx, cancel, contextErr := m.operationContext(ctx)
		if contextErr != nil {
			return Runtime{}, contextErr
		}
		removeErr := m.deleteOwnedVolumeResource(operationCtx, workspaceManagedResource(options.Spec))
		cancel()
		if removeErr != nil && !errors.Is(removeErr, ErrNotFound) {
			return Runtime{}, fmt.Errorf("remove workspace volume for rebuild %s: %w", id, removeErr)
		}
	}
	rebuilt, createErr := m.create(ctx, options.Spec, authorizedWorkspaceSpecDigest)
	if createErr != nil {
		return Runtime{}, fmt.Errorf("rebuild runtime %s after removing the stopped provider: %w", id, createErr)
	}
	return rebuilt, nil
}

func (m *DockerManager) Delete(ctx context.Context, id RuntimeID, options DeleteOptions) error {
	if err := validateRuntimeID(id); err != nil {
		return err
	}
	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	runtime, err := m.inspectOwned(operationCtx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			removedGateway, gatewayErr := m.deleteOwnedEgressGatewayByRuntimeID(operationCtx, id)
			if gatewayErr != nil {
				return gatewayErr
			}
			removedEgressNetwork, egressNetworkErr := m.deleteOwnedEgressNetworkByRuntimeID(operationCtx, id)
			if egressNetworkErr != nil {
				return egressNetworkErr
			}
			removedNetwork, networkErr := m.deleteOwnedConversationNetworkByRuntimeID(operationCtx, id)
			if networkErr != nil {
				return networkErr
			}
			removedWorkspace := false
			if options.RemoveWorkspace {
				removedWorkspace, err = m.deleteOwnedWorkspaceVolumeByRuntimeID(operationCtx, id)
				if err != nil {
					return err
				}
			}
			if removedGateway || removedEgressNetwork || removedNetwork || removedWorkspace {
				return nil
			}
		}
		return err
	}
	if runtime.Status != StatusStopped && runtime.Status != StatusFailed {
		return fmt.Errorf("%w: runtime %s must be stopped before deletion", ErrRuntimeStateConflict, id)
	}
	inspection, err := m.api.ContainerInspect(operationCtx, runtime.ProviderID, mobyclient.ContainerInspectOptions{Size: false})
	if err != nil {
		return fmt.Errorf("inspect runtime %s before deletion: %w", id, err)
	}
	if inspection.Container.Config == nil {
		return fmt.Errorf("%w: runtime %s configuration disappeared before deletion", ErrRuntimeStateConflict, id)
	}
	securitySpec, err := runtimeSecuritySpecFromLabels(inspection.Container.Config.Labels)
	if err != nil {
		return fmt.Errorf("%w: runtime %s workspace labels are invalid", ErrRuntimeStateConflict, id)
	}
	_, err = m.api.ContainerRemove(operationCtx, runtime.ProviderID, mobyclient.ContainerRemoveOptions{Force: false, RemoveVolumes: false})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return fmt.Errorf("%w: runtime %s", ErrNotFound, id)
		}
		return fmt.Errorf("delete runtime %s: %w", id, err)
	}
	if securitySpec.EgressGateway != nil {
		gateway, gatewayErr := m.inspectOwnedEgressGateway(operationCtx, securitySpec, &inspection.Container, StatusStopped)
		if gatewayErr != nil {
			return fmt.Errorf("inspect runtime %s egress gateway before deletion: %w", id, gatewayErr)
		}
		if _, gatewayErr = m.api.ContainerRemove(operationCtx, gateway.ID, mobyclient.ContainerRemoveOptions{Force: false, RemoveVolumes: false}); gatewayErr != nil && !containerderrdefs.IsNotFound(gatewayErr) {
			return fmt.Errorf("delete runtime %s egress gateway: %w", id, gatewayErr)
		}
		if err := m.deleteOwnedEgressNetwork(operationCtx, securitySpec, inspection.Container.Config.Labels[LabelSpecDigest]); err != nil && !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("delete runtime %s egress network: %w", id, err)
		}
	}
	if securitySpec.Security.NetworkMode == NetworkInternal {
		if err := m.deleteOwnedConversationNetwork(operationCtx, securitySpec, inspection.Container.Config.Labels[LabelSpecDigest]); err != nil && !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("delete runtime %s conversation network: %w", id, err)
		}
	}
	if options.RemoveWorkspace && securitySpec.Workspace.Persistent && !securitySpec.Workspace.Shared {
		if err := m.deleteOwnedVolumeResource(operationCtx, workspaceManagedResource(securitySpec)); err != nil && !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("delete runtime %s workspace: %w", id, err)
		}
	}
	return nil
}

func (m *DockerManager) deleteOwnedConversationNetwork(ctx context.Context, spec RuntimeSpec, expectedSpecDigest string) error {
	if m.networkAPI == nil {
		return fmt.Errorf("%w: engine client does not support conversation networks", ErrEngineUnavailable)
	}
	name := ConversationNetworkName(spec.ID)
	result, err := m.networkAPI.NetworkInspect(ctx, name, mobyclient.NetworkInspectOptions{})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return fmt.Errorf("%w: conversation network %s", ErrNotFound, name)
		}
		return fmt.Errorf("inspect conversation network %s: %w", name, err)
	}
	resource, err := m.verifyConversationNetwork(spec, expectedSpecDigest, result.Network, result.Network.ID, true)
	if err != nil {
		return err
	}
	if _, err := m.networkAPI.NetworkRemove(ctx, resource.ProviderID, mobyclient.NetworkRemoveOptions{}); err != nil {
		if containerderrdefs.IsNotFound(err) {
			return fmt.Errorf("%w: conversation network %s", ErrNotFound, name)
		}
		return err
	}
	return nil
}

func (m *DockerManager) deleteOwnedEgressNetwork(ctx context.Context, spec RuntimeSpec, expectedSpecDigest string) error {
	if m.networkAPI == nil {
		return fmt.Errorf("%w: engine client does not support egress networks", ErrEngineUnavailable)
	}
	name := EgressNetworkName(spec.ID)
	result, err := m.networkAPI.NetworkInspect(ctx, name, mobyclient.NetworkInspectOptions{})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return fmt.Errorf("%w: egress network %s", ErrNotFound, name)
		}
		return fmt.Errorf("inspect egress network %s: %w", name, err)
	}
	resource, err := m.verifyEgressNetwork(spec, expectedSpecDigest, result.Network, result.Network.ID, true)
	if err != nil {
		return err
	}
	if _, err := m.networkAPI.NetworkRemove(ctx, resource.ProviderID, mobyclient.NetworkRemoveOptions{}); err != nil {
		if containerderrdefs.IsNotFound(err) {
			return fmt.Errorf("%w: egress network %s", ErrNotFound, name)
		}
		return err
	}
	return nil
}

func (m *DockerManager) deleteOwnedEgressGatewayByRuntimeID(ctx context.Context, id RuntimeID) (bool, error) {
	result, err := m.api.ContainerInspect(ctx, EgressGatewayContainerName(id), mobyclient.ContainerInspectOptions{Size: false})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("inspect egress gateway %s: %w", id, err)
	}
	actual := result.Container
	if actual.Config == nil || actual.State == nil || strings.TrimSpace(actual.ID) == "" {
		return false, fmt.Errorf("%w: egress gateway inspection is incomplete", ErrRuntimeStateConflict)
	}
	labels := actual.Config.Labels
	if labels[LabelRuntimeID] != string(id) || labels[LabelNetworkMode] != gatewayNetworkModeLabel || !sha256DigestPattern.MatchString(labels[LabelSpecDigest]) {
		return false, fmt.Errorf("%w: egress gateway runtime labels mismatch", ErrRuntimeStateConflict)
	}
	spec := RuntimeSpec{ID: id, ConversationID: strings.TrimSpace(labels[LabelConversationID])}
	expected := egressGatewayManagedResource(spec, actual.ID)
	observed, observeErr := m.resourceFromLabels(ResourceKindEgressGateway, actual.ID, strings.TrimPrefix(actual.Name, "/"), labels, gatewayCreatedAt(actual))
	if observeErr != nil || !sameManagedResource(expected, observed) {
		return false, fmt.Errorf("%w: egress gateway ownership mismatch", ErrRuntimeStateConflict)
	}
	if actual.State.Running {
		seconds := int(defaultRuntimeStopTimeout / time.Second)
		if _, err := m.api.ContainerStop(ctx, actual.ID, mobyclient.ContainerStopOptions{Timeout: &seconds}); err != nil && !containerderrdefs.IsNotFound(err) {
			return false, fmt.Errorf("stop egress gateway %s: %w", id, err)
		}
	}
	if _, err := m.api.ContainerRemove(ctx, actual.ID, mobyclient.ContainerRemoveOptions{Force: false, RemoveVolumes: false}); err != nil {
		if containerderrdefs.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (m *DockerManager) deleteOwnedEgressNetworkByRuntimeID(ctx context.Context, id RuntimeID) (bool, error) {
	if m.networkAPI == nil {
		return false, nil
	}
	name := EgressNetworkName(id)
	result, err := m.networkAPI.NetworkInspect(ctx, name, mobyclient.NetworkInspectOptions{})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("inspect egress network %s: %w", name, err)
	}
	labels := result.Network.Labels
	if labels[LabelRuntimeID] != string(id) || labels[LabelNetworkMode] != egressNetworkModeLabel || !sha256DigestPattern.MatchString(labels[LabelSpecDigest]) {
		return false, fmt.Errorf("%w: egress network runtime labels mismatch", ErrRuntimeStateConflict)
	}
	spec := RuntimeSpec{ID: id, ConversationID: strings.TrimSpace(labels[LabelConversationID])}
	expected := egressNetworkManagedResource(spec, result.Network.ID)
	observed, observeErr := m.resourceFromLabels(ResourceKindEgressNetwork, result.Network.ID, result.Network.Name, labels, result.Network.Created.UTC())
	if observeErr != nil || !sameManagedResource(expected, observed) {
		return false, fmt.Errorf("%w: egress network ownership mismatch", ErrRuntimeStateConflict)
	}
	if result.Network.Driver != "bridge" || result.Network.Scope != "local" || result.Network.Internal || !result.Network.EnableIPv4 || result.Network.EnableIPv6 || result.Network.Attachable || result.Network.Ingress || result.Network.ConfigOnly || len(result.Network.Containers) != 0 || len(result.Network.Services) != 0 {
		return false, fmt.Errorf("%w: egress network is unsafe to delete", ErrRuntimeStateConflict)
	}
	if _, err := m.networkAPI.NetworkRemove(ctx, result.Network.ID, mobyclient.NetworkRemoveOptions{}); err != nil {
		if containerderrdefs.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (m *DockerManager) deleteOwnedConversationNetworkByRuntimeID(ctx context.Context, id RuntimeID) (bool, error) {
	if m.networkAPI == nil {
		return false, nil
	}
	name := ConversationNetworkName(id)
	result, err := m.networkAPI.NetworkInspect(ctx, name, mobyclient.NetworkInspectOptions{})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("inspect conversation network %s: %w", name, err)
	}
	labels := result.Network.Labels
	if labels[LabelRuntimeID] != string(id) || labels[LabelNetworkMode] != string(NetworkInternal) || !sha256DigestPattern.MatchString(labels[LabelSpecDigest]) {
		return false, fmt.Errorf("%w: conversation network runtime labels mismatch", ErrRuntimeStateConflict)
	}
	spec := RuntimeSpec{
		ID: id, ConversationID: strings.TrimSpace(labels[LabelConversationID]),
		Security: SecurityProfile{NetworkMode: NetworkInternal},
	}
	expected := conversationNetworkManagedResource(spec, result.Network.ID)
	observed, observeErr := m.resourceFromLabels(ResourceKindConversationNetwork, result.Network.ID, result.Network.Name, labels, result.Network.Created.UTC())
	if observeErr != nil || !sameManagedResource(expected, observed) {
		return false, fmt.Errorf("%w: conversation network ownership mismatch", ErrRuntimeStateConflict)
	}
	if result.Network.Driver != "bridge" || result.Network.Scope != "local" || result.Network.Internal || !result.Network.EnableIPv4 || result.Network.EnableIPv6 || result.Network.Attachable || result.Network.Ingress || result.Network.ConfigOnly || !validConversationNetworkOptions(result.Network.Options) || len(result.Network.Containers) != 0 || len(result.Network.Services) != 0 {
		return false, fmt.Errorf("%w: conversation network is unsafe to delete", ErrRuntimeStateConflict)
	}
	if _, err := m.networkAPI.NetworkRemove(ctx, result.Network.ID, mobyclient.NetworkRemoveOptions{}); err != nil {
		if containerderrdefs.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (m *DockerManager) deleteOwnedWorkspaceVolumeByRuntimeID(ctx context.Context, id RuntimeID) (bool, error) {
	if m.volumeAPI == nil {
		return false, fmt.Errorf("%w: engine client does not support named volumes", ErrEngineUnavailable)
	}
	name := WorkspaceVolumeName(id)
	result, err := m.volumeAPI.VolumeInspect(ctx, name, mobyclient.VolumeInspectOptions{})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("inspect workspace volume %s: %w", name, err)
	}
	labels := result.Volume.Labels
	if labels[LabelRuntimeID] != string(id) {
		return false, fmt.Errorf("%w: workspace volume runtime identity mismatch", ErrRuntimeStateConflict)
	}
	spec := RuntimeSpec{
		ID: id, ConversationID: strings.TrimSpace(labels[LabelConversationID]),
		Workspace: WorkspaceSpec{Persistent: true, VolumeName: name, MountPath: "/workspace"},
	}
	observed, err := m.resourceFromLabels(ResourceKindWorkspaceVolume, result.Volume.Name, result.Volume.Name, result.Volume.Labels, parseVolumeCreatedAt(result.Volume))
	if err != nil || !sameManagedResource(workspaceManagedResource(spec), observed) {
		return false, fmt.Errorf("%w: workspace volume ownership mismatch", ErrRuntimeStateConflict)
	}
	if labels[LabelSpecDigest] == "" {
		return false, fmt.Errorf("%w: workspace volume specification label is missing", ErrRuntimeStateConflict)
	}
	if !sha256DigestPattern.MatchString(labels[LabelSpecDigest]) {
		return false, fmt.Errorf("%w: workspace volume specification label is invalid", ErrRuntimeStateConflict)
	}
	if err := m.deleteOwnedVolumeResource(ctx, workspaceManagedResource(spec)); err != nil {
		return false, err
	}
	return true, nil
}

// DeleteSharedWorkspace removes one control-plane-owned shared workspace
// volume. The independent workspace labels are verified before deletion; a
// caller can never supply an arbitrary Docker volume name.
func (m *DockerManager) DeleteSharedWorkspace(ctx context.Context, workspaceID string) error {
	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if m.volumeAPI == nil {
		return fmt.Errorf("%w: engine volume client is not configured", ErrEngineUnavailable)
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if !generatedNamePattern.MatchString(workspaceID) {
		return invalidSpec("workspace id is invalid")
	}
	volumeName := WorkspaceVolumeNameForID(workspaceID)
	spec := RuntimeSpec{Workspace: WorkspaceSpec{
		Persistent: true,
		ID:         workspaceID,
		Shared:     true,
		VolumeName: volumeName,
		MountPath:  "/workspace",
	}}
	result, inspectErr := m.volumeAPI.VolumeInspect(operationCtx, volumeName, mobyclient.VolumeInspectOptions{})
	if inspectErr != nil {
		if containerderrdefs.IsNotFound(inspectErr) {
			return nil
		}
		return fmt.Errorf("inspect shared workspace volume %s: %w", volumeName, inspectErr)
	}
	observed, observeErr := m.resourceFromLabels(ResourceKindWorkspaceVolume, result.Volume.Name, result.Volume.Name, result.Volume.Labels, parseVolumeCreatedAt(result.Volume))
	if observeErr != nil || !sameManagedResource(workspaceManagedResource(spec), observed) || result.Volume.Labels[LabelWorkspaceShared] != "true" {
		return fmt.Errorf("%w: shared workspace volume ownership mismatch", ErrRuntimeStateConflict)
	}
	if err := m.deleteOwnedVolumeResource(operationCtx, workspaceManagedResource(spec)); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

func (m *DockerManager) operationContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if m == nil || m.api == nil {
		return nil, nil, fmt.Errorf("%w: engine client is not configured", ErrEngineUnavailable)
	}
	if ctx == nil {
		return nil, nil, invalidSpec("context is required")
	}
	operationCtx, cancel := context.WithTimeout(ctx, m.operationTimeout)
	return operationCtx, cancel, nil
}

func (m *DockerManager) inspectOwned(ctx context.Context, id RuntimeID) (Runtime, error) {
	result, err := m.api.ContainerInspect(ctx, runtimeContainerName(id), mobyclient.ContainerInspectOptions{Size: false})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return Runtime{}, fmt.Errorf("%w: runtime %s", ErrNotFound, id)
		}
		return Runtime{}, fmt.Errorf("inspect runtime %s: %w", id, err)
	}
	return m.runtimeFromInspection(ctx, id, result.Container)
}

func (m *DockerManager) runtimeFromInspection(ctx context.Context, expectedID RuntimeID, actual mobycontainer.InspectResponse) (Runtime, error) {
	if strings.TrimSpace(actual.ID) == "" || actual.Config == nil || actual.State == nil || actual.HostConfig == nil {
		return Runtime{}, fmt.Errorf("%w: runtime %s has an incomplete engine inspection", ErrRuntimeStateConflict, expectedID)
	}
	expectedName := runtimeContainerName(expectedID)
	if strings.TrimPrefix(actual.Name, "/") != expectedName {
		return Runtime{}, fmt.Errorf("%w: runtime %s engine name mismatch", ErrRuntimeStateConflict, expectedID)
	}
	labels := actual.Config.Labels
	if labels[LabelManaged] != "true" || labels[LabelOwner] != m.ownerID || labels[LabelResourceKind] != ResourceKindAgent || labels[LabelRuntimeID] != string(expectedID) {
		return Runtime{}, fmt.Errorf("%w: runtime %s ownership labels mismatch", ErrRuntimeStateConflict, expectedID)
	}
	if !sha256DigestPattern.MatchString(strings.TrimSpace(labels[LabelSpecDigest])) {
		return Runtime{}, fmt.Errorf("%w: runtime %s immutable specification label is invalid", ErrRuntimeStateConflict, expectedID)
	}
	conversationID := strings.TrimSpace(labels[LabelConversationID])
	if !generatedNamePattern.MatchString(conversationID) {
		return Runtime{}, fmt.Errorf("%w: runtime %s conversation label is invalid", ErrRuntimeStateConflict, expectedID)
	}
	image, err := imageReferenceFromRuntime(actual.Config.Image, labels)
	if err != nil {
		return Runtime{}, fmt.Errorf("%w: runtime %s image labels mismatch", ErrRuntimeStateConflict, expectedID)
	}
	if err := m.verifyObservedSecurityBaseline(ctx, actual); err != nil {
		return Runtime{}, err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, actual.Created)
	if err != nil {
		return Runtime{}, fmt.Errorf("%w: runtime %s creation time is invalid", ErrRuntimeStateConflict, expectedID)
	}
	status, warnings := observedRuntimeStatus(actual.State)
	securitySpec, err := runtimeSecuritySpecFromLabels(labels)
	if err != nil {
		return Runtime{}, fmt.Errorf("%w: runtime %s egress labels are invalid", ErrRuntimeStateConflict, expectedID)
	}
	if !matchesRuntimeKeepalive(actual.Config, securitySpec) {
		return Runtime{}, fmt.Errorf("%w: runtime %s keepalive process drifted", ErrRuntimeStateConflict, expectedID)
	}
	if securitySpec.EgressGateway != nil {
		if _, err := m.inspectOwnedEgressGateway(ctx, securitySpec, &actual, status); err != nil {
			return Runtime{}, err
		}
	}
	updatedAt := latestRuntimeTimestamp(createdAt, actual.State.StartedAt, actual.State.FinishedAt)
	observedSpec := securitySpec
	return Runtime{
		ID:             expectedID,
		ConversationID: conversationID,
		ProviderID:     actual.ID,
		Image:          image,
		Status:         status,
		CreatedAt:      createdAt.UTC(),
		UpdatedAt:      updatedAt.UTC(),
		LastError:      strings.TrimSpace(actual.State.Error),
		Warnings:       warnings,
		SpecDigest:     labels[LabelSpecDigest],
		Spec:           &observedSpec,
	}, nil
}

func validateRuntimeID(id RuntimeID) error {
	if !generatedNamePattern.MatchString(string(id)) {
		return invalidSpec("runtime id is required and must be system-generated")
	}
	return nil
}

func imageReferenceFromRuntime(configured string, labels map[string]string) (ImageReference, error) {
	digest := strings.TrimSpace(labels[LabelImageDigest])
	platform := strings.TrimSpace(labels[LabelImagePlatform])
	if !sha256DigestPattern.MatchString(digest) {
		return ImageReference{}, errors.New("invalid digest label")
	}
	if _, err := parsePlatform(platform); err != nil {
		return ImageReference{}, err
	}
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(configured))
	if err != nil {
		return ImageReference{}, err
	}
	digested, ok := named.(reference.Digested)
	if !ok || digested.Digest().String() != digest {
		return ImageReference{}, errors.New("configured image is not pinned to the label digest")
	}
	return ImageReference{
		Repository:     reference.TrimNamed(named).Name(),
		Digest:         digest,
		Platform:       platform,
		ResolvedDigest: digest,
	}, nil
}

func (m *DockerManager) verifyObservedSecurityBaseline(ctx context.Context, actual mobycontainer.InspectResponse) error {
	host := actual.HostConfig
	config := actual.Config
	if config == nil || host == nil || actual.State == nil {
		return fmt.Errorf("%w: runtime inspection is incomplete", ErrRuntimeStateConflict)
	}
	expected, err := runtimeSecuritySpecFromLabels(config.Labels)
	if err != nil {
		return fmt.Errorf("%w: owned runtime resource labels are invalid", ErrRuntimeStateConflict)
	}
	switch expected.Security.NetworkMode {
	case NetworkNone:
		if !config.NetworkDisabled || host.NetworkMode != mobycontainer.NetworkMode(NetworkNone) || !isolatedNetworkSettings(actual.NetworkSettings) {
			return fmt.Errorf("%w: owned runtime none-network isolation drifted", ErrRuntimeStateConflict)
		}
	case NetworkInternal:
		if config.NetworkDisabled || host.NetworkMode != mobycontainer.NetworkMode(ConversationNetworkName(expected.ID)) {
			return fmt.Errorf("%w: owned runtime internal network mode drifted", ErrRuntimeStateConflict)
		}
		if err := m.verifyAttachedConversationNetwork(ctx, actual, expected); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: owned runtime network mode is invalid", ErrRuntimeStateConflict)
	}
	if err := verifyRuntimeSecurityBaseline(host, expected); err != nil {
		return err
	}
	if !requiresPolicyDNS(expected) {
		if err := verifyRuntimeProxyEnvironment(config.Env, expected, ""); err != nil {
			return err
		}
	}
	return nil
}

func (m *DockerManager) verifyAttachedConversationNetwork(ctx context.Context, actual mobycontainer.InspectResponse, spec RuntimeSpec) error {
	if m.networkAPI == nil {
		return fmt.Errorf("%w: engine client does not support conversation network inspection", ErrEngineUnavailable)
	}
	name := ConversationNetworkName(spec.ID)
	if actual.NetworkSettings == nil || len(actual.NetworkSettings.Networks) != 1 {
		return fmt.Errorf("%w: runtime is not attached to exactly one conversation network", ErrRuntimeStateConflict)
	}
	endpoint := actual.NetworkSettings.Networks[name]
	if endpoint == nil || strings.TrimSpace(endpoint.NetworkID) == "" {
		return fmt.Errorf("%w: runtime conversation network endpoint is incomplete", ErrRuntimeStateConflict)
	}
	result, err := m.networkAPI.NetworkInspect(ctx, endpoint.NetworkID, mobyclient.NetworkInspectOptions{})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return fmt.Errorf("%w: conversation network is missing", ErrRuntimeStateConflict)
		}
		return fmt.Errorf("inspect attached conversation network: %w", err)
	}
	if _, err := m.verifyConversationNetwork(spec, actual.Config.Labels[LabelSpecDigest], result.Network, endpoint.NetworkID, false); err != nil {
		return err
	}
	if !validConversationEndpointGateway(endpoint, result.Network) {
		return fmt.Errorf("%w: runtime conversation network gateway metadata mismatch", ErrRuntimeStateConflict)
	}
	expectedAttachments := 1
	if spec.EgressGateway != nil {
		expectedAttachments = 2
	}
	if len(result.Network.Services) != 0 || len(result.Network.Containers) > expectedAttachments {
		return fmt.Errorf("%w: conversation network has unexpected attached workloads", ErrRuntimeStateConflict)
	}
	if len(result.Network.Containers) == 0 {
		if actual.State == nil || actual.State.Running {
			return fmt.Errorf("%w: conversation network attachment is missing", ErrRuntimeStateConflict)
		}
		return nil
	}
	if actual.State == nil || !actual.State.Running || len(result.Network.Containers) != expectedAttachments {
		return fmt.Errorf("%w: conversation network active attachment count mismatch", ErrRuntimeStateConflict)
	}
	attached, ok := result.Network.Containers[actual.ID]
	if !ok || (strings.TrimSpace(attached.Name) != "" && strings.TrimSpace(attached.Name) != strings.TrimPrefix(actual.Name, "/")) {
		return fmt.Errorf("%w: conversation network attachment identity mismatch", ErrRuntimeStateConflict)
	}
	if spec.EgressGateway != nil {
		foundGateway := false
		for providerID, candidate := range result.Network.Containers {
			if providerID == actual.ID {
				continue
			}
			if strings.TrimSpace(candidate.Name) == EgressGatewayContainerName(spec.ID) {
				foundGateway = true
			}
		}
		if !foundGateway {
			return fmt.Errorf("%w: conversation network gateway attachment identity mismatch", ErrRuntimeStateConflict)
		}
	}
	return nil
}

func runtimeSecuritySpecFromLabels(labels map[string]string) (RuntimeSpec, error) {
	runtimeID := RuntimeID(strings.TrimSpace(labels[LabelRuntimeID]))
	if err := validateRuntimeID(runtimeID); err != nil {
		return RuntimeSpec{}, err
	}
	conversationID := strings.TrimSpace(labels[LabelConversationID])
	if !generatedNamePattern.MatchString(conversationID) {
		return RuntimeSpec{}, errors.New("invalid conversation label")
	}
	nanoCPUs, err := positiveLabelInt64(labels, LabelNanoCPUs)
	if err != nil {
		return RuntimeSpec{}, err
	}
	memory, err := positiveLabelInt64(labels, LabelMemoryBytes)
	if err != nil {
		return RuntimeSpec{}, err
	}
	pids, err := positiveLabelInt64(labels, LabelPIDs)
	if err != nil {
		return RuntimeSpec{}, err
	}
	nofileSoft, err := positiveLabelUint64(labels, LabelNoFileSoft)
	if err != nil {
		return RuntimeSpec{}, err
	}
	nofileHard, err := positiveLabelUint64(labels, LabelNoFileHard)
	if err != nil || nofileHard < nofileSoft {
		return RuntimeSpec{}, errors.New("invalid nofile labels")
	}
	workspaceBytes, err := positiveLabelInt64(labels, LabelWorkspaceBytes)
	if err != nil {
		return RuntimeSpec{}, err
	}
	tmpfsBytes, err := positiveLabelInt64(labels, LabelTmpfsBytes)
	if err != nil {
		return RuntimeSpec{}, err
	}
	logMaxBytes, err := positiveLabelInt64(labels, LabelLogMaxBytes)
	if err != nil {
		return RuntimeSpec{}, err
	}
	logMaxFiles64, err := positiveLabelInt64(labels, LabelLogMaxFiles)
	if err != nil || logMaxFiles64 > int64(^uint(0)>>1) {
		return RuntimeSpec{}, errors.New("invalid log file label")
	}
	workspacePath := strings.TrimSpace(labels[LabelWorkspacePath])
	if workspacePath != "/workspace" {
		return RuntimeSpec{}, errors.New("invalid workspace label")
	}
	persistentLabel := strings.TrimSpace(labels[LabelWorkspacePersistent])
	// Containers created before workspace persistence was introduced have no
	// persistence labels and are unambiguously ephemeral because they declare
	// no named volume and still pass the tmpfs security baseline.
	if persistentLabel == "" && strings.TrimSpace(labels[LabelWorkspaceVolume]) == "" {
		persistentLabel = "false"
	}
	if persistentLabel != "true" && persistentLabel != "false" {
		return RuntimeSpec{}, errors.New("invalid workspace persistence label")
	}
	persistent := persistentLabel == "true"
	volumeName := strings.TrimSpace(labels[LabelWorkspaceVolume])
	workspaceID := strings.TrimSpace(labels[LabelWorkspaceID])
	shared, sharedErr := strconv.ParseBool(strings.TrimSpace(labels[LabelWorkspaceShared]))
	if strings.TrimSpace(labels[LabelWorkspaceShared]) == "" {
		shared, sharedErr = false, nil
	}
	if sharedErr != nil {
		return RuntimeSpec{}, errors.New("invalid shared workspace label")
	}
	if persistent && workspaceID == "" {
		workspaceID = string(runtimeID)
	}
	if persistent && volumeName != WorkspaceVolumeNameForID(workspaceID) {
		return RuntimeSpec{}, errors.New("invalid workspace volume label")
	}
	if !persistent && volumeName != "" {
		return RuntimeSpec{}, errors.New("ephemeral workspace declares a volume label")
	}
	networkMode := NetworkMode(strings.TrimSpace(labels[LabelNetworkMode]))
	if networkMode == "" {
		// Runtimes created before stage 4 did not carry a network mode label and
		// were unconditionally created with Docker's none network.
		networkMode = NetworkNone
	}
	if networkMode != NetworkNone && networkMode != NetworkInternal {
		return RuntimeSpec{}, errors.New("invalid network mode label")
	}
	gateway, err := egressGatewaySpecFromAgentLabels(labels)
	if err != nil {
		return RuntimeSpec{}, err
	}
	return RuntimeSpec{
		ID: runtimeID, ConversationID: conversationID,
		Resources: ResourceLimits{
			NanoCPUs: nanoCPUs, MemoryBytes: memory, PIDs: pids,
			NoFileSoft: nofileSoft, NoFileHard: nofileHard,
			WorkspaceBytes: workspaceBytes, LogMaxBytes: logMaxBytes, LogMaxFiles: int(logMaxFiles64),
		},
		Security:      SecurityProfile{NetworkMode: networkMode, TmpfsBytes: tmpfsBytes},
		Workspace:     WorkspaceSpec{Persistent: persistent, ID: workspaceID, Shared: shared, VolumeName: volumeName, MountPath: workspacePath},
		EgressGateway: gateway,
	}, nil
}

func positiveLabelInt64(labels map[string]string, key string) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(labels[key]), 10, 64)
	if err != nil || value <= 0 {
		return 0, errors.New("invalid positive integer label")
	}
	return value, nil
}

func positiveLabelUint64(labels map[string]string, key string) (uint64, error) {
	value, err := strconv.ParseUint(strings.TrimSpace(labels[key]), 10, 64)
	if err != nil || value == 0 {
		return 0, errors.New("invalid positive unsigned label")
	}
	return value, nil
}

func isolatedNetworkSettings(settings *mobycontainer.NetworkSettings) bool {
	if settings == nil || len(settings.Networks) == 0 {
		return true
	}
	if len(settings.Networks) != 1 {
		return false
	}
	_, onlyNone := settings.Networks["none"]
	return onlyNone
}

func observedRuntimeStatus(state *mobycontainer.State) (Status, []string) {
	if state == nil {
		return StatusFailed, []string{"engine state is missing"}
	}
	if state.Dead {
		return StatusFailed, []string{"engine reports a dead container"}
	}
	if state.Paused {
		return StatusFailed, []string{"engine reports an unexpected paused container"}
	}
	if state.Restarting {
		return StatusStarting, []string{"engine reports an unexpected restarting container"}
	}
	if state.Running {
		return StatusRunning, nil
	}
	switch state.Status {
	case mobycontainer.StateCreated, mobycontainer.StateExited:
		return StatusStopped, nil
	case mobycontainer.StateRemoving:
		return StatusStopping, nil
	default:
		return StatusFailed, []string{"engine reports container status " + string(state.Status)}
	}
}

func latestRuntimeTimestamp(created time.Time, values ...string) time.Time {
	latest := created.UTC()
	for _, value := range values {
		parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
		if err == nil && parsed.After(latest) {
			latest = parsed.UTC()
		}
	}
	return latest
}
