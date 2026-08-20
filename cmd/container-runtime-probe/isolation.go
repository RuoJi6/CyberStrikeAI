package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	containerruntime "cyberstrike-ai/internal/runtime/container"
	mobyclient "github.com/moby/moby/client"
)

type isolationProbeResult struct {
	RuntimeA                containerruntime.Runtime `json:"runtime_a"`
	RuntimeB                containerruntime.Runtime `json:"runtime_b"`
	DistinctProviders       bool                     `json:"distinct_providers"`
	NetworkNoneA            bool                     `json:"network_none_a"`
	NetworkNoneB            bool                     `json:"network_none_b"`
	DockerSocketAbsentA     bool                     `json:"docker_socket_absent_a"`
	DockerSocketAbsentB     bool                     `json:"docker_socket_absent_b"`
	WorkspaceIsolated       bool                     `json:"workspace_isolated"`
	EphemeralWorkspaceReset bool                     `json:"ephemeral_workspace_reset_after_restart"`
	StoppingADidNotStopB    bool                     `json:"stopping_a_did_not_stop_b"`
	DeletedAfterCheck       bool                     `json:"deleted_after_check"`
	BothMissingAfterDelete  bool                     `json:"both_missing_after_delete"`
}

func exerciseRuntimeIsolation(ctx context.Context, manager containerruntime.RuntimeManager, base containerruntime.RuntimeSpec) (isolationProbeResult, error) {
	var result isolationProbeResult
	if manager == nil || strings.TrimSpace(string(base.ID)) == "" || strings.TrimSpace(base.ConversationID) == "" {
		return result, fmt.Errorf("%w: isolation manager, runtime id and conversation id are required", containerruntime.ErrInvalidSpecification)
	}
	api, err := mobyclient.New(mobyclient.FromEnv)
	if err != nil {
		return result, fmt.Errorf("connect Docker exec client: %w", err)
	}
	defer api.Close()

	specA := base
	specA.ID = containerruntime.RuntimeID(string(base.ID) + "-a")
	specA.ConversationID = base.ConversationID + "-a"
	specB := base
	specB.ID = containerruntime.RuntimeID(string(base.ID) + "-b")
	specB.ConversationID = base.ConversationID + "-b"

	createdA, err := manager.Create(ctx, specA)
	if err != nil {
		return result, fmt.Errorf("create isolation runtime A: %w", err)
	}
	defer deleteProbeRuntime(manager, specA.ID)
	createdB, err := manager.Create(ctx, specB)
	if err != nil {
		return result, fmt.Errorf("create isolation runtime B: %w", err)
	}
	defer deleteProbeRuntime(manager, specB.ID)
	result.DistinctProviders = createdA.ProviderID != "" && createdB.ProviderID != "" && createdA.ProviderID != createdB.ProviderID
	if !result.DistinctProviders {
		return result, fmt.Errorf("%w: isolation runtimes share a provider identity", containerruntime.ErrRuntimeStateConflict)
	}

	result.RuntimeA, err = manager.Start(ctx, specA.ID)
	if err != nil {
		return result, fmt.Errorf("start isolation runtime A: %w", err)
	}
	result.RuntimeB, err = manager.Start(ctx, specB.ID)
	if err != nil {
		return result, fmt.Errorf("start isolation runtime B: %w", err)
	}

	result.DockerSocketAbsentA = execProbeAssert(ctx, api, result.RuntimeA.ProviderID, "test ! -e /var/run/docker.sock") == nil
	result.DockerSocketAbsentB = execProbeAssert(ctx, api, result.RuntimeB.ProviderID, "test ! -e /var/run/docker.sock") == nil
	noDefaultRoute := "! grep -Eq '^[^[:space:]]+[[:space:]]+00000000[[:space:]]' /proc/net/route"
	result.NetworkNoneA = execProbeAssert(ctx, api, result.RuntimeA.ProviderID, noDefaultRoute) == nil
	result.NetworkNoneB = execProbeAssert(ctx, api, result.RuntimeB.ProviderID, noDefaultRoute) == nil
	if !result.DockerSocketAbsentA || !result.DockerSocketAbsentB || !result.NetworkNoneA || !result.NetworkNoneB {
		return result, fmt.Errorf("%w: Docker socket or default route isolation failed", containerruntime.ErrRuntimeStateConflict)
	}

	if err := execProbeAssert(ctx, api, result.RuntimeA.ProviderID, "printf conversation-a > /workspace/conversation-a"); err != nil {
		return result, fmt.Errorf("write runtime A marker: %w", err)
	}
	if err := execProbeAssert(ctx, api, result.RuntimeB.ProviderID, "test ! -e /workspace/conversation-a && printf conversation-b > /workspace/conversation-b"); err != nil {
		return result, fmt.Errorf("verify runtime B workspace isolation: %w", err)
	}
	result.WorkspaceIsolated = true

	if _, err := manager.Stop(ctx, specA.ID, containerruntime.StopOptions{}); err != nil {
		return result, fmt.Errorf("stop isolation runtime A: %w", err)
	}
	observedA, err := manager.Inspect(ctx, specA.ID)
	if err != nil {
		return result, err
	}
	observedB, err := manager.Inspect(ctx, specB.ID)
	if err != nil {
		return result, err
	}
	result.StoppingADidNotStopB = observedA.Status == containerruntime.StatusStopped && observedB.Status == containerruntime.StatusRunning
	if !result.StoppingADidNotStopB {
		return result, fmt.Errorf("%w: stopping runtime A changed runtime B", containerruntime.ErrRuntimeStateConflict)
	}

	result.RuntimeA, err = manager.Start(ctx, specA.ID)
	if err != nil {
		return result, fmt.Errorf("restart isolation runtime A: %w", err)
	}
	if err := execProbeAssert(ctx, api, result.RuntimeA.ProviderID, "test ! -e /workspace/conversation-a && test ! -e /workspace/conversation-b"); err != nil {
		return result, fmt.Errorf("verify ephemeral runtime A workspace reset after restart: %w", err)
	}
	result.EphemeralWorkspaceReset = true

	if _, err := manager.Stop(ctx, specA.ID, containerruntime.StopOptions{Timeout: time.Second}); err != nil {
		return result, fmt.Errorf("final stop isolation runtime A: %w", err)
	}
	if _, err := manager.Stop(ctx, specB.ID, containerruntime.StopOptions{Timeout: time.Second}); err != nil {
		return result, fmt.Errorf("final stop isolation runtime B: %w", err)
	}
	if err := manager.Delete(ctx, specA.ID, containerruntime.DeleteOptions{RemoveWorkspace: false}); err != nil {
		return result, fmt.Errorf("delete isolation runtime A: %w", err)
	}
	if err := manager.Delete(ctx, specB.ID, containerruntime.DeleteOptions{RemoveWorkspace: false}); err != nil {
		return result, fmt.Errorf("delete isolation runtime B: %w", err)
	}
	result.DeletedAfterCheck = true
	_, errA := manager.Inspect(ctx, specA.ID)
	_, errB := manager.Inspect(ctx, specB.ID)
	result.BothMissingAfterDelete = errors.Is(errA, containerruntime.ErrNotFound) && errors.Is(errB, containerruntime.ErrNotFound)
	if !result.BothMissingAfterDelete {
		return result, fmt.Errorf("%w: isolation runtimes remain after cleanup: %v / %v", containerruntime.ErrRuntimeStateConflict, errA, errB)
	}
	return result, nil
}

func execProbeAssert(ctx context.Context, api *mobyclient.Client, containerID, script string) error {
	execResult, err := api.ExecCreate(ctx, containerID, mobyclient.ExecCreateOptions{
		Cmd: []string{"/bin/sh", "-c", script},
	})
	if err != nil {
		return err
	}
	if _, err := api.ExecStart(ctx, execResult.ID, mobyclient.ExecStartOptions{Detach: true}); err != nil {
		return err
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		inspection, err := api.ExecInspect(ctx, execResult.ID, mobyclient.ExecInspectOptions{})
		if err != nil {
			return err
		}
		if !inspection.Running {
			if inspection.ExitCode != 0 {
				return fmt.Errorf("probe command exited with code %d", inspection.ExitCode)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func deleteProbeRuntime(manager containerruntime.RuntimeManager, runtimeID containerruntime.RuntimeID) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = manager.Stop(cleanupCtx, runtimeID, containerruntime.StopOptions{Timeout: time.Second})
	_ = manager.Delete(cleanupCtx, runtimeID, containerruntime.DeleteOptions{RemoveWorkspace: false})
}
