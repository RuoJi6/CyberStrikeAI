package container

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	containerderrdefs "github.com/containerd/errdefs"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobyclient "github.com/moby/moby/client"
)

type dockerStatsAPI interface {
	ContainerStats(context.Context, string, mobyclient.ContainerStatsOptions) (mobyclient.ContainerStatsResult, error)
}

// Observe returns a verified live projection for one trusted durable spec. It
// never accepts a user-provided Docker ID and never exposes inspect metadata.
func (m *DockerManager) Observe(ctx context.Context, spec RuntimeSpec) (RuntimeObservation, error) {
	if m == nil || m.api == nil {
		return RuntimeObservation{}, fmt.Errorf("%w: engine client is not configured", ErrEngineUnavailable)
	}
	if err := ValidateSpec(spec); err != nil {
		return RuntimeObservation{}, err
	}
	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return RuntimeObservation{}, err
	}
	defer cancel()

	agentInspection, err := m.api.ContainerInspect(operationCtx, runtimeContainerName(spec.ID), mobyclient.ContainerInspectOptions{Size: false})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return RuntimeObservation{}, fmt.Errorf("%w: runtime %s", ErrNotFound, spec.ID)
		}
		return RuntimeObservation{}, fmt.Errorf("inspect runtime %s: %w", spec.ID, err)
	}
	runtime, err := m.runtimeFromInspection(operationCtx, spec.ID, agentInspection.Container)
	if err != nil {
		return RuntimeObservation{}, err
	}
	if runtime.SpecDigest != RuntimeSpecDigest(spec) {
		return RuntimeObservation{}, fmt.Errorf("%w: runtime %s immutable specification drifted", ErrRuntimeStateConflict, spec.ID)
	}
	observation := RuntimeObservation{
		Agent: RuntimeComponentObservation{
			ProviderID:  runtime.ProviderID,
			Status:      runtime.Status,
			ImageDigest: runtime.Image.Digest,
			LastError:   runtime.LastError,
			Warnings:    append([]string(nil), runtime.Warnings...),
		},
		PolicyDNSStatus: "not_required",
		WorkspaceStatus: "ready",
		ObservedAt:      time.Now().UTC(),
	}

	if spec.EgressGateway != nil {
		gatewayInspection, inspectErr := m.inspectOwnedEgressGateway(operationCtx, spec, &agentInspection.Container, runtime.Status)
		if inspectErr != nil {
			return RuntimeObservation{}, inspectErr
		}
		gatewayStatus, warnings := observedRuntimeStatus(gatewayInspection.State)
		gateway := &RuntimeComponentObservation{
			ProviderID:  strings.TrimSpace(gatewayInspection.ID),
			Status:      gatewayStatus,
			ImageDigest: spec.EgressGateway.Image.Digest,
			Warnings:    warnings,
		}
		if gatewayInspection.State != nil {
			gateway.LastError = strings.TrimSpace(gatewayInspection.State.Error)
		}
		observation.Gateway = gateway
		if requiresPolicyDNS(spec) {
			address, addressErr := egressGatewayPolicyDNSAddress(gatewayInspection, spec)
			if addressErr != nil {
				return RuntimeObservation{}, addressErr
			}
			observation.PolicyDNSStatus = observedPolicyDNSStatus(gatewayStatus)
			observation.PolicyDNSAddress = address
		}
	}

	statsAPI, ok := m.api.(dockerStatsAPI)
	if !ok {
		return observation, nil
	}
	type usageResult struct {
		gateway bool
		usage   ResourceUsage
	}
	results := make(chan usageResult, 2)
	var workers sync.WaitGroup
	collect := func(providerID string, gateway bool) {
		defer workers.Done()
		usage, usageErr := readContainerResourceUsage(operationCtx, statsAPI, providerID)
		if usageErr == nil {
			results <- usageResult{gateway: gateway, usage: usage}
		}
	}
	if runtime.Status == StatusRunning {
		workers.Add(1)
		go collect(runtime.ProviderID, false)
	}
	if observation.Gateway != nil && observation.Gateway.Status == StatusRunning {
		workers.Add(1)
		go collect(observation.Gateway.ProviderID, true)
	}
	workers.Wait()
	close(results)
	for result := range results {
		if result.gateway && observation.Gateway != nil {
			observation.Gateway.Resources = result.usage
		} else if !result.gateway {
			observation.Agent.Resources = result.usage
		}
	}
	return observation, nil
}

func observedPolicyDNSStatus(gatewayStatus Status) string {
	if gatewayStatus == StatusRunning {
		return "ready"
	}
	return string(gatewayStatus)
}

func readContainerResourceUsage(ctx context.Context, api dockerStatsAPI, providerID string) (ResourceUsage, error) {
	result, err := api.ContainerStats(ctx, providerID, mobyclient.ContainerStatsOptions{Stream: false, IncludePreviousSample: true})
	if err != nil {
		return ResourceUsage{}, err
	}
	defer result.Body.Close()
	var stats mobycontainer.StatsResponse
	if err := json.NewDecoder(result.Body).Decode(&stats); err != nil {
		return ResourceUsage{}, fmt.Errorf("decode container stats: %w", err)
	}
	usage := ResourceUsage{
		Available:        true,
		MemoryUsageBytes: stats.MemoryStats.Usage,
		MemoryLimitBytes: stats.MemoryStats.Limit,
		PIDs:             stats.PidsStats.Current,
	}
	for _, network := range stats.Networks {
		usage.NetworkRXBytes += network.RxBytes
		usage.NetworkTXBytes += network.TxBytes
	}
	for _, entry := range stats.BlkioStats.IoServiceBytesRecursive {
		switch strings.ToLower(strings.TrimSpace(entry.Op)) {
		case "read":
			usage.BlockReadBytes += entry.Value
		case "write":
			usage.BlockWriteBytes += entry.Value
		}
	}
	currentCPU := stats.CPUStats.CPUUsage.TotalUsage
	previousCPU := stats.PreCPUStats.CPUUsage.TotalUsage
	currentSystem := stats.CPUStats.SystemUsage
	previousSystem := stats.PreCPUStats.SystemUsage
	onlineCPUs := stats.CPUStats.OnlineCPUs
	if onlineCPUs == 0 {
		onlineCPUs = uint32(len(stats.CPUStats.CPUUsage.PercpuUsage))
	}
	if currentCPU >= previousCPU && currentSystem >= previousSystem && onlineCPUs > 0 {
		cpuDelta := currentCPU - previousCPU
		systemDelta := currentSystem - previousSystem
		if cpuDelta > 0 && systemDelta > 0 {
			usage.CPUPercent = float64(cpuDelta) / float64(systemDelta) * float64(onlineCPUs) * 100
		}
	}
	return usage, nil
}
