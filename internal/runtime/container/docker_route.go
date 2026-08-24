package container

import (
	"context"
	"fmt"
	"io"
	"strings"

	mobystdcopy "github.com/moby/moby/api/pkg/stdcopy"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobyclient "github.com/moby/moby/client"
)

// configureRuntimeDefaultRoute makes the per-conversation gateway the only
// default route for tools that do not support HTTP/SOCKS proxy variables. The
// gateway address comes exclusively from the verified owned topology.
func (m *DockerManager) configureRuntimeDefaultRoute(ctx context.Context, spec RuntimeSpec, runtimeProviderID string, gateway mobycontainer.InspectResponse) error {
	if spec.EgressGateway == nil || spec.EgressGateway.BoundarySnapshot == nil {
		return nil
	}
	if m == nil || m.execAPI == nil {
		return fmt.Errorf("%w: container exec API is not configured", ErrEngineUnavailable)
	}
	gatewayAddress, err := egressGatewayPolicyDNSAddress(gateway, spec)
	if err != nil {
		return err
	}
	created, err := m.execAPI.ExecCreate(ctx, runtimeProviderID, mobyclient.ExecCreateOptions{
		Privileged: false, User: runtimeRootExecUser, TTY: false,
		AttachStdin: false, AttachStdout: true, AttachStderr: true,
		Env: runtimeExecEnvironment(nil), WorkingDir: spec.Workspace.MountPath,
		Cmd: []string{"/sbin/ip", "route", "replace", "default", "via", gatewayAddress},
	})
	if err != nil {
		return fmt.Errorf("create runtime gateway route helper: %w", err)
	}
	if strings.TrimSpace(created.ID) == "" {
		return fmt.Errorf("%w: engine returned an empty route helper exec id", ErrRuntimeStateConflict)
	}
	attached, err := m.execAPI.ExecAttach(ctx, created.ID, mobyclient.ExecAttachOptions{TTY: false})
	if err != nil {
		return fmt.Errorf("attach runtime gateway route helper: %w", err)
	}
	defer attached.Close()
	if _, err := mobystdcopy.StdCopy(io.Discard, io.Discard, attached.Reader); err != nil {
		return fmt.Errorf("read runtime gateway route helper: %w", err)
	}
	inspection, err := m.execAPI.ExecInspect(ctx, created.ID, mobyclient.ExecInspectOptions{})
	if err != nil {
		return fmt.Errorf("inspect runtime gateway route helper: %w", err)
	}
	if inspection.ID != created.ID || inspection.ContainerID != runtimeProviderID || inspection.Running || inspection.ExitCode != 0 {
		return fmt.Errorf("%w: runtime gateway route helper failed", ErrRuntimeStateConflict)
	}
	return nil
}
