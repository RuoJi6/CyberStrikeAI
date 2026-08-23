package container

import (
	"context"
	"fmt"
	"strings"

	mobyclient "github.com/moby/moby/client"
)

type dockerContainerSignalAPI interface {
	ContainerKill(context.Context, string, mobyclient.ContainerKillOptions) (mobyclient.ContainerKillResult, error)
}

var _ RuntimeEgressHealthController = (*DockerManager)(nil)

// RecoverEgressHealth sends the one fixed recovery signal to the exact owned
// running gateway resolved from a trusted RuntimeSpec. Provider ids, signal
// names, and arbitrary containers are never accepted from an HTTP request.
func (m *DockerManager) RecoverEgressHealth(ctx context.Context, spec RuntimeSpec) error {
	if err := ValidateSpec(spec); err != nil {
		return err
	}
	if spec.EgressGateway == nil || spec.EgressGateway.BoundarySnapshot == nil {
		return fmt.Errorf("%w: runtime has no policy egress gateway", ErrInvalidSpecification)
	}
	observation, err := m.Observe(ctx, spec)
	if err != nil {
		return err
	}
	if observation.Gateway == nil || observation.Gateway.Status != StatusRunning || strings.TrimSpace(observation.Gateway.ProviderID) == "" {
		return fmt.Errorf("%w: egress gateway is not running", ErrRuntimeNotReady)
	}
	signalAPI, ok := m.api.(dockerContainerSignalAPI)
	if !ok {
		return fmt.Errorf("%w: engine signaling is unavailable", ErrEngineUnavailable)
	}
	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if _, err := signalAPI.ContainerKill(operationCtx, observation.Gateway.ProviderID, mobyclient.ContainerKillOptions{Signal: "SIGHUP"}); err != nil {
		return fmt.Errorf("signal verified egress gateway recovery: %w", err)
	}
	return nil
}
