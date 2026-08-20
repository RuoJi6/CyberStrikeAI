package container

import (
	"context"
	"errors"
	"fmt"
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
		runtime, convertErr := m.runtimeFromInspection(id, inspection.Container)
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
	if _, err := m.api.ContainerStart(operationCtx, runtime.ProviderID, mobyclient.ContainerStartOptions{}); err != nil {
		if containerderrdefs.IsNotFound(err) {
			return Runtime{}, fmt.Errorf("%w: runtime %s", ErrNotFound, id)
		}
		return Runtime{}, fmt.Errorf("start runtime %s: %w", id, err)
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
	seconds := int((timeout + time.Second - 1) / time.Second)
	if _, err := m.api.ContainerStop(operationCtx, runtime.ProviderID, mobyclient.ContainerStopOptions{Timeout: &seconds}); err != nil {
		if containerderrdefs.IsNotFound(err) {
			return Runtime{}, fmt.Errorf("%w: runtime %s", ErrNotFound, id)
		}
		return Runtime{}, fmt.Errorf("stop runtime %s: %w", id, err)
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
		_, removeErr := m.api.ContainerRemove(operationCtx, current.ProviderID, mobyclient.ContainerRemoveOptions{Force: false, RemoveVolumes: options.RemoveWorkspace})
		cancel()
		if removeErr != nil && !containerderrdefs.IsNotFound(removeErr) {
			return Runtime{}, fmt.Errorf("remove stopped runtime %s for rebuild: %w", id, removeErr)
		}
	}
	rebuilt, createErr := m.Create(ctx, options.Spec)
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
		return err
	}
	if runtime.Status != StatusStopped && runtime.Status != StatusFailed {
		return fmt.Errorf("%w: runtime %s must be stopped before deletion", ErrRuntimeStateConflict, id)
	}
	_, err = m.api.ContainerRemove(operationCtx, runtime.ProviderID, mobyclient.ContainerRemoveOptions{Force: false, RemoveVolumes: options.RemoveWorkspace})
	if err != nil {
		if containerderrdefs.IsNotFound(err) {
			return fmt.Errorf("%w: runtime %s", ErrNotFound, id)
		}
		return fmt.Errorf("delete runtime %s: %w", id, err)
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
	return m.runtimeFromInspection(id, result.Container)
}

func (m *DockerManager) runtimeFromInspection(expectedID RuntimeID, actual mobycontainer.InspectResponse) (Runtime, error) {
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
	if err := verifyObservedSecurityBaseline(actual); err != nil {
		return Runtime{}, err
	}
	if !matchesRuntimeKeepalive(actual.Config) {
		return Runtime{}, fmt.Errorf("%w: runtime %s keepalive process drifted", ErrRuntimeStateConflict, expectedID)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, actual.Created)
	if err != nil {
		return Runtime{}, fmt.Errorf("%w: runtime %s creation time is invalid", ErrRuntimeStateConflict, expectedID)
	}
	status, warnings := observedRuntimeStatus(actual.State)
	updatedAt := latestRuntimeTimestamp(createdAt, actual.State.StartedAt, actual.State.FinishedAt)
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

func verifyObservedSecurityBaseline(actual mobycontainer.InspectResponse) error {
	host := actual.HostConfig
	config := actual.Config
	if config == nil || host == nil || actual.State == nil {
		return fmt.Errorf("%w: runtime inspection is incomplete", ErrRuntimeStateConflict)
	}
	if !config.NetworkDisabled || host.NetworkMode != mobycontainer.NetworkMode(NetworkNone) || !isolatedNetworkSettings(actual.NetworkSettings) {
		return fmt.Errorf("%w: owned runtime network isolation drifted", ErrRuntimeStateConflict)
	}
	expected, err := runtimeSecuritySpecFromLabels(config.Labels)
	if err != nil {
		return fmt.Errorf("%w: owned runtime resource labels are invalid", ErrRuntimeStateConflict)
	}
	if err := verifyRuntimeSecurityBaseline(host, expected); err != nil {
		return err
	}
	return nil
}

func runtimeSecuritySpecFromLabels(labels map[string]string) (RuntimeSpec, error) {
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
	return RuntimeSpec{
		Resources: ResourceLimits{
			NanoCPUs: nanoCPUs, MemoryBytes: memory, PIDs: pids,
			NoFileSoft: nofileSoft, NoFileHard: nofileHard,
			WorkspaceBytes: workspaceBytes, LogMaxBytes: logMaxBytes, LogMaxFiles: int(logMaxFiles64),
		},
		Security:  SecurityProfile{TmpfsBytes: tmpfsBytes},
		Workspace: WorkspaceSpec{MountPath: workspacePath},
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
