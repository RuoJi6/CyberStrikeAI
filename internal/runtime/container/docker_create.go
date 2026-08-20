package container

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	containerderrdefs "github.com/containerd/errdefs"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobyclient "github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	LabelManaged        = "com.cyberstrike.managed"
	LabelOwner          = "com.cyberstrike.owner"
	LabelRuntimeID      = "com.cyberstrike.runtime-id"
	LabelConversationID = "com.cyberstrike.conversation-id"
	LabelResourceKind   = "com.cyberstrike.resource-kind"
	LabelResourceID     = "com.cyberstrike.resource-id"
	LabelImageDigest    = "com.cyberstrike.image-digest"
	LabelImagePlatform  = "com.cyberstrike.image-platform"
	LabelSpecDigest     = "com.cyberstrike.spec-digest"
	LabelNanoCPUs       = "com.cyberstrike.limit.nano-cpus"
	LabelMemoryBytes    = "com.cyberstrike.limit.memory-bytes"
	LabelPIDs           = "com.cyberstrike.limit.pids"
	LabelNoFileSoft     = "com.cyberstrike.limit.nofile-soft"
	LabelNoFileHard     = "com.cyberstrike.limit.nofile-hard"
	LabelWorkspaceBytes = "com.cyberstrike.limit.workspace-bytes"
	LabelTmpfsBytes     = "com.cyberstrike.limit.tmpfs-bytes"
	LabelLogMaxBytes    = "com.cyberstrike.limit.log-max-bytes"
	LabelLogMaxFiles    = "com.cyberstrike.limit.log-max-files"
	LabelWorkspacePath  = "com.cyberstrike.workspace-path"
	ResourceKindAgent   = "agent-runtime"

	defaultDockerOperationTimeout = 30 * time.Second
	rollbackTimeout               = 10 * time.Second
	defaultGlobalConcurrentExec   = 32
	defaultGlobalQueuedExec       = 128
	runtimeKeepaliveScript        = "trap 'exit 0' TERM INT; while :; do sleep 3600; done"
)

var runtimeKeepaliveEntrypoint = []string{"/bin/sh", "-c"}

type dockerCreationAPI interface {
	dockerInspectionAPI
	ContainerCreate(context.Context, mobyclient.ContainerCreateOptions) (mobyclient.ContainerCreateResult, error)
	ContainerList(context.Context, mobyclient.ContainerListOptions) (mobyclient.ContainerListResult, error)
	ContainerStart(context.Context, string, mobyclient.ContainerStartOptions) (mobyclient.ContainerStartResult, error)
	ContainerStop(context.Context, string, mobyclient.ContainerStopOptions) (mobyclient.ContainerStopResult, error)
	ContainerRemove(context.Context, string, mobyclient.ContainerRemoveOptions) (mobyclient.ContainerRemoveResult, error)
	ContainerStatPath(context.Context, string, mobyclient.ContainerStatPathOptions) (mobyclient.ContainerStatPathResult, error)
}

type dockerManagedResourceAPI interface {
	NetworkList(context.Context, mobyclient.NetworkListOptions) (mobyclient.NetworkListResult, error)
	NetworkInspect(context.Context, string, mobyclient.NetworkInspectOptions) (mobyclient.NetworkInspectResult, error)
	NetworkRemove(context.Context, string, mobyclient.NetworkRemoveOptions) (mobyclient.NetworkRemoveResult, error)
	VolumeList(context.Context, mobyclient.VolumeListOptions) (mobyclient.VolumeListResult, error)
	VolumeInspect(context.Context, string, mobyclient.VolumeInspectOptions) (mobyclient.VolumeInspectResult, error)
	VolumeRemove(context.Context, string, mobyclient.VolumeRemoveOptions) (mobyclient.VolumeRemoveResult, error)
}

// DockerManagerOptions contains control-plane identity, never request data.
type DockerManagerOptions struct {
	OwnerID              string
	OperationTimeout     time.Duration
	GlobalConcurrentExec int
	GlobalQueuedExec     int
}

// DockerManager is the production RuntimeManager backed by the official Moby
// client. All lifecycle mutations resolve system-generated names and verify
// ownership labels before touching a container.
type DockerManager struct {
	*DockerInspector
	api              dockerCreationAPI
	execAPI          dockerExecAPI
	execLimiter      *ExecLimiter
	resourceAPI      dockerManagedResourceAPI
	ownerID          string
	operationTimeout time.Duration
}

var _ RuntimeManager = (*DockerManager)(nil)
var _ RuntimeExecutor = (*DockerManager)(nil)
var _ RuntimeToolOutputWriter = (*DockerManager)(nil)
var _ RuntimeWorkspaceFileWriter = (*DockerManager)(nil)

func NewDockerManagerFromEnvironment(options DockerManagerOptions) (*DockerManager, error) {
	api, err := mobyclient.New(mobyclient.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize engine client: %v", ErrEngineUnavailable, err)
	}
	manager, err := newDockerManager(api, options)
	if err != nil {
		_ = api.Close()
		return nil, err
	}
	manager.DockerInspector.closer = api
	return manager, nil
}

func newDockerManager(api dockerCreationAPI, options DockerManagerOptions) (*DockerManager, error) {
	ownerID := strings.TrimSpace(options.OwnerID)
	if !generatedNamePattern.MatchString(ownerID) {
		return nil, fmt.Errorf("%w: owner id is required and must be label-safe", ErrInvalidSpecification)
	}
	operationTimeout := options.OperationTimeout
	if operationTimeout == 0 {
		operationTimeout = defaultDockerOperationTimeout
	}
	if operationTimeout < 0 {
		return nil, fmt.Errorf("%w: operation timeout must be positive", ErrInvalidSpecification)
	}
	globalConcurrent := options.GlobalConcurrentExec
	if globalConcurrent == 0 {
		globalConcurrent = defaultGlobalConcurrentExec
	}
	globalQueued := options.GlobalQueuedExec
	if globalQueued == 0 {
		globalQueued = defaultGlobalQueuedExec
	}
	limiter, err := NewExecLimiter(ExecLimiterOptions{MaxConcurrent: globalConcurrent, MaxQueued: globalQueued})
	if err != nil {
		return nil, err
	}
	inspector := newDockerInspector(api)
	execAPI, _ := api.(dockerExecAPI)
	resourceAPI, _ := api.(dockerManagedResourceAPI)
	return &DockerManager{DockerInspector: inspector, api: api, execAPI: execAPI, execLimiter: limiter, resourceAPI: resourceAPI, ownerID: ownerID, operationTimeout: operationTimeout}, nil
}

func (m *DockerManager) Create(ctx context.Context, spec RuntimeSpec) (Runtime, error) {
	if m == nil || m.api == nil {
		return Runtime{}, fmt.Errorf("%w: engine client is not configured", ErrEngineUnavailable)
	}
	if err := ValidateSpec(spec); err != nil {
		return Runtime{}, err
	}
	if spec.Workspace.Persistent {
		return Runtime{}, invalidSpec("persistent workspace creation is not enabled in this rollout item")
	}
	ctx, cancel := context.WithTimeout(ctx, m.operationTimeout)
	defer cancel()
	engine, err := m.EngineInfo(ctx)
	if err != nil {
		return Runtime{}, err
	}
	platform, err := parsePlatform(spec.Image.Platform)
	if err != nil {
		return Runtime{}, err
	}
	if engine.OperatingSys != platform[0] || engine.Architecture != platform[1] {
		return Runtime{}, fmt.Errorf("%w: engine %s/%s cannot create %s", ErrArchitectureMismatch, engine.OperatingSys, engine.Architecture, spec.Image.Platform)
	}
	if err := verifyEngineSecurityBaseline(engine); err != nil {
		return Runtime{}, err
	}
	if _, err := m.InspectLocalImage(ctx, spec.Image); err != nil {
		return Runtime{}, err
	}

	pinned, _ := pinnedImageReference(spec.Image)
	name := runtimeContainerName(spec.ID)
	labels := runtimeLabels(m.ownerID, spec)
	createResult, err := m.api.ContainerCreate(ctx, mobyclient.ContainerCreateOptions{
		Name:  name,
		Image: pinned,
		Platform: &ocispec.Platform{
			OS:           platform[0],
			Architecture: platform[1],
			Variant:      platform[2],
		},
		Config: &mobycontainer.Config{
			NetworkDisabled: true,
			WorkingDir:      "/workspace",
			Entrypoint:      append([]string(nil), runtimeKeepaliveEntrypoint...),
			Cmd:             []string{runtimeKeepaliveScript},
			Labels:          labels,
		},
		HostConfig: runtimeHostConfig(spec),
	})
	if err != nil {
		if containerderrdefs.IsConflict(err) {
			return Runtime{}, fmt.Errorf("%w: %s", ErrAlreadyExists, name)
		}
		return Runtime{}, fmt.Errorf("create runtime %s: %w", spec.ID, err)
	}

	runtime, verifyErr := m.verifyCreatedRuntime(ctx, spec, name, labels, createResult)
	if verifyErr == nil {
		return runtime, nil
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cleanupCancel()
	_, cleanupErr := m.api.ContainerRemove(cleanupCtx, createResult.ID, mobyclient.ContainerRemoveOptions{Force: true, RemoveVolumes: false})
	if cleanupErr != nil {
		return Runtime{}, errors.Join(verifyErr, fmt.Errorf("rollback created runtime %s: %w", createResult.ID, cleanupErr))
	}
	return Runtime{}, verifyErr
}

func (m *DockerManager) verifyCreatedRuntime(ctx context.Context, spec RuntimeSpec, name string, expectedLabels map[string]string, createResult mobyclient.ContainerCreateResult) (Runtime, error) {
	if strings.TrimSpace(createResult.ID) == "" {
		return Runtime{}, fmt.Errorf("%w: engine returned an empty provider id", ErrRuntimeStateConflict)
	}
	result, err := m.api.ContainerInspect(ctx, createResult.ID, mobyclient.ContainerInspectOptions{Size: false})
	if err != nil {
		return Runtime{}, fmt.Errorf("inspect created runtime %s: %w", createResult.ID, err)
	}
	actual := result.Container
	if actual.State == nil || actual.State.Running || actual.State.Status != mobycontainer.StateCreated {
		return Runtime{}, fmt.Errorf("%w: created runtime is not in created state", ErrRuntimeStateConflict)
	}
	if strings.TrimPrefix(actual.Name, "/") != name {
		return Runtime{}, fmt.Errorf("%w: engine returned name %q, expected %q", ErrRuntimeStateConflict, actual.Name, name)
	}
	if actual.Config == nil {
		return Runtime{}, fmt.Errorf("%w: created runtime has no configuration", ErrRuntimeStateConflict)
	}
	if actual.Config.WorkingDir != spec.Workspace.MountPath {
		return Runtime{}, fmt.Errorf("%w: created runtime working directory mismatch", ErrRuntimeStateConflict)
	}
	if !matchesRuntimeKeepalive(actual.Config) {
		return Runtime{}, fmt.Errorf("%w: created runtime keepalive process mismatch", ErrRuntimeStateConflict)
	}
	for key, expected := range expectedLabels {
		if actual.Config.Labels[key] != expected {
			return Runtime{}, fmt.Errorf("%w: created runtime label %s mismatch", ErrRuntimeStateConflict, key)
		}
	}
	if actual.HostConfig == nil || actual.HostConfig.NetworkMode != mobycontainer.NetworkMode(NetworkNone) || !actual.Config.NetworkDisabled {
		return Runtime{}, fmt.Errorf("%w: created runtime network is not disabled", ErrRuntimeStateConflict)
	}
	if err := verifyRuntimeSecurityBaseline(actual.HostConfig, spec); err != nil {
		return Runtime{}, err
	}
	image, err := m.VerifyRuntimeImage(ctx, createResult.ID, spec.Image)
	if err != nil {
		return Runtime{}, err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, actual.Created)
	if err != nil {
		return Runtime{}, fmt.Errorf("%w: invalid engine creation time %q", ErrRuntimeStateConflict, actual.Created)
	}
	return Runtime{
		ID:             spec.ID,
		ConversationID: spec.ConversationID,
		ProviderID:     createResult.ID,
		Image:          image.Reference,
		Status:         StatusStopped,
		CreatedAt:      createdAt.UTC(),
		UpdatedAt:      createdAt.UTC(),
		Warnings:       append([]string(nil), createResult.Warnings...),
		SpecDigest:     expectedLabels[LabelSpecDigest],
	}, nil
}

func matchesRuntimeKeepalive(config *mobycontainer.Config) bool {
	return config != nil && len(config.Entrypoint) == 2 &&
		config.Entrypoint[0] == runtimeKeepaliveEntrypoint[0] &&
		config.Entrypoint[1] == runtimeKeepaliveEntrypoint[1] &&
		len(config.Cmd) == 1 && config.Cmd[0] == runtimeKeepaliveScript
}

func verifyEngineSecurityBaseline(engine EngineInfo) error {
	missing := make([]string, 0, 4)
	if !engine.MemoryLimit {
		missing = append(missing, "memory limits")
	}
	if !engine.CPULimit {
		missing = append(missing, "CPU quota")
	}
	if !engine.PIDsLimit {
		missing = append(missing, "PIDs limits")
	}
	if !hasSecurityOption(engine.SecurityOptions, "name=seccomp") {
		missing = append(missing, "default seccomp")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing %s", ErrEngineIncompatible, strings.Join(missing, ", "))
	}
	return nil
}

func hasSecurityOption(options []string, expected string) bool {
	for _, option := range options {
		if option == expected || strings.HasPrefix(option, expected+",") {
			return true
		}
	}
	return false
}

func runtimeHostConfig(spec RuntimeSpec) *mobycontainer.HostConfig {
	pidsLimit := spec.Resources.PIDs
	return &mobycontainer.HostConfig{
		NetworkMode: mobycontainer.NetworkMode(NetworkNone),
		LogConfig: mobycontainer.LogConfig{
			Type: "local",
			Config: map[string]string{
				"max-size": strconv.FormatInt(spec.Resources.LogMaxBytes, 10),
				"max-file": strconv.Itoa(spec.Resources.LogMaxFiles),
				"compress": "true",
			},
		},
		RestartPolicy:  mobycontainer.RestartPolicy{Name: mobycontainer.RestartPolicyDisabled},
		CapDrop:        []string{"ALL"},
		ReadonlyRootfs: true,
		SecurityOpt:    []string{"no-new-privileges"},
		Tmpfs: map[string]string{
			"/tmp":                   tmpfsOptions(spec.Security.TmpfsBytes, true),
			spec.Workspace.MountPath: tmpfsOptions(spec.Resources.WorkspaceBytes, false),
		},
		Resources: mobycontainer.Resources{
			NanoCPUs:   spec.Resources.NanoCPUs,
			Memory:     spec.Resources.MemoryBytes,
			MemorySwap: spec.Resources.MemoryBytes,
			PidsLimit:  &pidsLimit,
			Ulimits: []*mobycontainer.Ulimit{{
				Name: "nofile",
				Soft: int64(spec.Resources.NoFileSoft),
				Hard: int64(spec.Resources.NoFileHard),
			}},
		},
	}
}

func tmpfsOptions(sizeBytes int64, noexec bool) string {
	// Images may declare a non-root USER. tmpfs defaults are owned by root, so
	// both scratch locations need an explicit sticky, world-writable mode while
	// retaining nosuid/nodev (and noexec for /tmp).
	options := "rw,nosuid,nodev,mode=1777"
	if noexec {
		options += ",noexec"
	}
	return options + ",size=" + strconv.FormatInt(sizeBytes, 10)
}

func verifyRuntimeSecurityBaseline(actual *mobycontainer.HostConfig, spec RuntimeSpec) error {
	expected := runtimeHostConfig(spec)
	if actual.Privileged || actual.PublishAllPorts || actual.AutoRemove || len(actual.Binds) != 0 || len(actual.Mounts) != 0 || len(actual.Devices) != 0 || len(actual.DeviceRequests) != 0 || len(actual.PortBindings) != 0 {
		return fmt.Errorf("%w: created runtime has privileged access, host mounts, devices, or published ports", ErrRuntimeStateConflict)
	}
	if !actual.ReadonlyRootfs || len(actual.CapDrop) != 1 || !strings.EqualFold(actual.CapDrop[0], "ALL") || len(actual.CapAdd) != 0 || !containsString(actual.SecurityOpt, "no-new-privileges") {
		return fmt.Errorf("%w: created runtime privilege restrictions mismatch", ErrRuntimeStateConflict)
	}
	if actual.RestartPolicy.Name != mobycontainer.RestartPolicyDisabled {
		return fmt.Errorf("%w: created runtime restart policy mismatch", ErrRuntimeStateConflict)
	}
	if actual.LogConfig.Type != expected.LogConfig.Type || len(actual.LogConfig.Config) != len(expected.LogConfig.Config) {
		return fmt.Errorf("%w: created runtime log rotation driver mismatch", ErrRuntimeStateConflict)
	}
	for key, value := range expected.LogConfig.Config {
		if actual.LogConfig.Config[key] != value {
			return fmt.Errorf("%w: created runtime log rotation option %s mismatch", ErrRuntimeStateConflict, key)
		}
	}
	if actual.NanoCPUs != expected.NanoCPUs || actual.Memory != expected.Memory || actual.MemorySwap != expected.MemorySwap || actual.PidsLimit == nil || *actual.PidsLimit != spec.Resources.PIDs {
		return fmt.Errorf("%w: created runtime CPU, memory, swap, or PIDs limits mismatch", ErrRuntimeStateConflict)
	}
	if len(actual.Ulimits) != 1 || actual.Ulimits[0] == nil || actual.Ulimits[0].Name != "nofile" || actual.Ulimits[0].Soft != int64(spec.Resources.NoFileSoft) || actual.Ulimits[0].Hard != int64(spec.Resources.NoFileHard) {
		return fmt.Errorf("%w: created runtime nofile limit mismatch", ErrRuntimeStateConflict)
	}
	if len(actual.Tmpfs) != len(expected.Tmpfs) {
		return fmt.Errorf("%w: created runtime tmpfs mounts mismatch", ErrRuntimeStateConflict)
	}
	for path, options := range expected.Tmpfs {
		if actual.Tmpfs[path] != options {
			return fmt.Errorf("%w: created runtime tmpfs %s mismatch", ErrRuntimeStateConflict, path)
		}
	}
	return nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func runtimeContainerName(id RuntimeID) string {
	return "cyberstrike-agent-" + string(id)
}

func runtimeLabels(ownerID string, spec RuntimeSpec) map[string]string {
	return map[string]string{
		LabelManaged:        "true",
		LabelOwner:          ownerID,
		LabelRuntimeID:      string(spec.ID),
		LabelConversationID: spec.ConversationID,
		LabelResourceKind:   ResourceKindAgent,
		LabelImageDigest:    spec.Image.Digest,
		LabelImagePlatform:  spec.Image.Platform,
		LabelSpecDigest:     RuntimeSpecDigest(spec),
		LabelNanoCPUs:       strconv.FormatInt(spec.Resources.NanoCPUs, 10),
		LabelMemoryBytes:    strconv.FormatInt(spec.Resources.MemoryBytes, 10),
		LabelPIDs:           strconv.FormatInt(spec.Resources.PIDs, 10),
		LabelNoFileSoft:     strconv.FormatUint(spec.Resources.NoFileSoft, 10),
		LabelNoFileHard:     strconv.FormatUint(spec.Resources.NoFileHard, 10),
		LabelWorkspaceBytes: strconv.FormatInt(spec.Resources.WorkspaceBytes, 10),
		LabelTmpfsBytes:     strconv.FormatInt(spec.Security.TmpfsBytes, 10),
		LabelLogMaxBytes:    strconv.FormatInt(spec.Resources.LogMaxBytes, 10),
		LabelLogMaxFiles:    strconv.Itoa(spec.Resources.LogMaxFiles),
		LabelWorkspacePath:  spec.Workspace.MountPath,
	}
}
