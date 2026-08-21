package container

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"cyberstrike-ai/internal/egress"
	containerderrdefs "github.com/containerd/errdefs"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobymount "github.com/moby/moby/api/types/mount"
	mobynetwork "github.com/moby/moby/api/types/network"
	mobyvolume "github.com/moby/moby/api/types/volume"
	mobyclient "github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	LabelManaged               = "com.cyberstrike.managed"
	LabelOwner                 = "com.cyberstrike.owner"
	LabelRuntimeID             = "com.cyberstrike.runtime-id"
	LabelConversationID        = "com.cyberstrike.conversation-id"
	LabelResourceKind          = "com.cyberstrike.resource-kind"
	LabelResourceID            = "com.cyberstrike.resource-id"
	LabelImageDigest           = "com.cyberstrike.image-digest"
	LabelImagePlatform         = "com.cyberstrike.image-platform"
	LabelSpecDigest            = "com.cyberstrike.spec-digest"
	LabelNanoCPUs              = "com.cyberstrike.limit.nano-cpus"
	LabelMemoryBytes           = "com.cyberstrike.limit.memory-bytes"
	LabelPIDs                  = "com.cyberstrike.limit.pids"
	LabelNoFileSoft            = "com.cyberstrike.limit.nofile-soft"
	LabelNoFileHard            = "com.cyberstrike.limit.nofile-hard"
	LabelWorkspaceBytes        = "com.cyberstrike.limit.workspace-bytes"
	LabelTmpfsBytes            = "com.cyberstrike.limit.tmpfs-bytes"
	LabelLogMaxBytes           = "com.cyberstrike.limit.log-max-bytes"
	LabelLogMaxFiles           = "com.cyberstrike.limit.log-max-files"
	LabelWorkspacePath         = "com.cyberstrike.workspace-path"
	LabelWorkspacePersistent   = "com.cyberstrike.workspace-persistent"
	LabelWorkspaceVolume       = "com.cyberstrike.workspace-volume"
	LabelNetworkMode           = "com.cyberstrike.network-mode"
	LabelEgressGateway         = "com.cyberstrike.egress-gateway"
	LabelEgressImageRepository = "com.cyberstrike.egress.image-repository"
	LabelEgressImageDigest     = "com.cyberstrike.egress.image-digest"
	LabelEgressImagePlatform   = "com.cyberstrike.egress.image-platform"
	LabelEgressSnapshotID      = "com.cyberstrike.egress.snapshot-id"
	LabelEgressSnapshotSHA256  = "com.cyberstrike.egress.snapshot-sha256"
	LabelEgressNanoCPUs        = "com.cyberstrike.egress.limit.nano-cpus"
	LabelEgressMemoryBytes     = "com.cyberstrike.egress.limit.memory-bytes"
	LabelEgressPIDs            = "com.cyberstrike.egress.limit.pids"
	LabelEgressNoFileSoft      = "com.cyberstrike.egress.limit.nofile-soft"
	LabelEgressNoFileHard      = "com.cyberstrike.egress.limit.nofile-hard"
	LabelEgressTmpfsBytes      = "com.cyberstrike.egress.limit.tmpfs-bytes"
	LabelEgressLogMaxBytes     = "com.cyberstrike.egress.limit.log-max-bytes"
	LabelEgressLogMaxFiles     = "com.cyberstrike.egress.limit.log-max-files"
	ResourceKindAgent          = "agent-runtime"

	defaultDockerOperationTimeout  = 30 * time.Second
	rollbackTimeout                = 10 * time.Second
	defaultGlobalConcurrentExec    = 32
	defaultGlobalQueuedExec        = 128
	conversationNetworkInhibitIPv4 = "com.docker.network.bridge.inhibit_ipv4"
	runtimeKeepaliveScript         = "trap 'exit 0' TERM INT; while :; do sleep 3600; done"
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

type dockerNetworkAPI interface {
	NetworkCreate(context.Context, string, mobyclient.NetworkCreateOptions) (mobyclient.NetworkCreateResult, error)
	NetworkInspect(context.Context, string, mobyclient.NetworkInspectOptions) (mobyclient.NetworkInspectResult, error)
	NetworkRemove(context.Context, string, mobyclient.NetworkRemoveOptions) (mobyclient.NetworkRemoveResult, error)
}

type dockerVolumeAPI interface {
	VolumeCreate(context.Context, mobyclient.VolumeCreateOptions) (mobyclient.VolumeCreateResult, error)
	VolumeInspect(context.Context, string, mobyclient.VolumeInspectOptions) (mobyclient.VolumeInspectResult, error)
	VolumeRemove(context.Context, string, mobyclient.VolumeRemoveOptions) (mobyclient.VolumeRemoveResult, error)
}

// DockerManagerOptions contains control-plane identity, never request data.
type DockerManagerOptions struct {
	OwnerID              string
	OperationTimeout     time.Duration
	GlobalConcurrentExec int
	GlobalQueuedExec     int
	EgressSnapshotRoot   string
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
	networkAPI       dockerNetworkAPI
	volumeAPI        dockerVolumeAPI
	snapshotStore    *egress.SnapshotStore
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
	var snapshotStore *egress.SnapshotStore
	if strings.TrimSpace(options.EgressSnapshotRoot) != "" {
		var err error
		snapshotStore, err = egress.NewSnapshotStore(options.EgressSnapshotRoot)
		if err != nil {
			return nil, fmt.Errorf("configure egress snapshot store: %w", err)
		}
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
	networkAPI, _ := api.(dockerNetworkAPI)
	volumeAPI, _ := api.(dockerVolumeAPI)
	return &DockerManager{
		DockerInspector: inspector, api: api, execAPI: execAPI, execLimiter: limiter,
		resourceAPI: resourceAPI, networkAPI: networkAPI, volumeAPI: volumeAPI,
		snapshotStore: snapshotStore, ownerID: ownerID, operationTimeout: operationTimeout,
	}, nil
}

func (m *DockerManager) Create(ctx context.Context, spec RuntimeSpec) (Runtime, error) {
	return m.create(ctx, spec, "")
}

func (m *DockerManager) create(ctx context.Context, spec RuntimeSpec, authorizedWorkspaceSpecDigest string) (Runtime, error) {
	if m == nil || m.api == nil {
		return Runtime{}, fmt.Errorf("%w: engine client is not configured", ErrEngineUnavailable)
	}
	if err := ValidateSpec(spec); err != nil {
		return Runtime{}, err
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
	if spec.EgressGateway != nil {
		gatewayPlatform, gatewayPlatformErr := parsePlatform(spec.EgressGateway.Image.Platform)
		if gatewayPlatformErr != nil {
			return Runtime{}, gatewayPlatformErr
		}
		if engine.OperatingSys != gatewayPlatform[0] || engine.Architecture != gatewayPlatform[1] {
			return Runtime{}, fmt.Errorf("%w: engine %s/%s cannot create egress gateway %s", ErrArchitectureMismatch, engine.OperatingSys, engine.Architecture, spec.EgressGateway.Image.Platform)
		}
		if _, err := m.InspectLocalImage(ctx, spec.EgressGateway.Image); err != nil {
			return Runtime{}, err
		}
	}
	networkCreated := false
	var conversationNetwork ManagedResource
	if spec.Security.NetworkMode == NetworkInternal {
		conversationNetwork, networkCreated, err = m.ensureOwnedConversationNetwork(ctx, spec)
		if err != nil {
			return Runtime{}, m.rollbackCreatedResources(networkCreated, false, false, "", spec, err)
		}
	}
	egressNetworkCreated := false
	var egressNetwork ManagedResource
	if spec.EgressGateway != nil {
		egressNetwork, egressNetworkCreated, err = m.ensureOwnedEgressNetwork(ctx, spec)
		if err != nil {
			return Runtime{}, m.rollbackCreatedResources(networkCreated, egressNetworkCreated, false, "", spec, err)
		}
	}
	workspaceCreated := false
	if spec.Workspace.Persistent {
		workspaceCreated, err = m.ensureOwnedWorkspaceVolume(ctx, spec, authorizedWorkspaceSpecDigest)
		if err != nil {
			return Runtime{}, m.rollbackCreatedResources(networkCreated, egressNetworkCreated, workspaceCreated, "", spec, err)
		}
	}
	gatewayID := ""
	gatewayDNS := ""
	if spec.EgressGateway != nil {
		gatewayID, gatewayDNS, err = m.createEgressGateway(ctx, spec, conversationNetwork, egressNetwork)
		if err != nil {
			return Runtime{}, m.rollbackCreatedResources(networkCreated, egressNetworkCreated, workspaceCreated, gatewayID, spec, err)
		}
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
			NetworkDisabled: spec.Security.NetworkMode == NetworkNone,
			WorkingDir:      "/workspace",
			Entrypoint:      append([]string(nil), runtimeKeepaliveEntrypoint...),
			Cmd:             []string{runtimeKeepaliveScript},
			Labels:          labels,
		},
		HostConfig:       runtimeHostConfigWithPolicyDNS(spec, gatewayDNS),
		NetworkingConfig: runtimeNetworkingConfig(spec, conversationNetwork),
	})
	if err != nil {
		if containerderrdefs.IsConflict(err) {
			conflictErr := fmt.Errorf("%w: %s", ErrAlreadyExists, name)
			return Runtime{}, m.rollbackCreatedResources(networkCreated, egressNetworkCreated, workspaceCreated, gatewayID, spec, conflictErr)
		}
		createErr := fmt.Errorf("create runtime %s: %w", spec.ID, err)
		return Runtime{}, m.rollbackCreatedResources(networkCreated, egressNetworkCreated, workspaceCreated, gatewayID, spec, createErr)
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
	return Runtime{}, m.rollbackCreatedResources(networkCreated, egressNetworkCreated, workspaceCreated, gatewayID, spec, verifyErr)
}

func (m *DockerManager) ensureOwnedConversationNetwork(ctx context.Context, spec RuntimeSpec) (ManagedResource, bool, error) {
	if m.networkAPI == nil {
		return ManagedResource{}, false, fmt.Errorf("%w: engine client does not support conversation networks", ErrEngineUnavailable)
	}
	name := ConversationNetworkName(spec.ID)
	result, err := m.networkAPI.NetworkInspect(ctx, name, mobyclient.NetworkInspectOptions{})
	if err == nil {
		resource, verifyErr := m.verifyConversationNetwork(spec, RuntimeSpecDigest(spec), result.Network, "", true)
		return resource, false, verifyErr
	}
	if !containerderrdefs.IsNotFound(err) {
		return ManagedResource{}, false, fmt.Errorf("inspect conversation network %s: %w", name, err)
	}
	enableIPv4, enableIPv6 := true, false
	created, err := m.networkAPI.NetworkCreate(ctx, name, mobyclient.NetworkCreateOptions{
		Driver: "bridge", Scope: "local", EnableIPv4: &enableIPv4, EnableIPv6: &enableIPv6,
		Internal: true, Attachable: false, Ingress: false, Options: conversationNetworkOptions(),
		Labels: conversationNetworkLabels(m.ownerID, spec),
	})
	if err != nil {
		if containerderrdefs.IsConflict(err) {
			return ManagedResource{}, false, fmt.Errorf("%w: conversation network %s already exists", ErrAlreadyExists, name)
		}
		return ManagedResource{}, false, fmt.Errorf("create conversation network %s: %w", name, err)
	}
	if strings.TrimSpace(created.ID) == "" {
		return ManagedResource{}, true, fmt.Errorf("%w: engine returned an empty conversation network id", ErrRuntimeStateConflict)
	}
	inspected, err := m.networkAPI.NetworkInspect(ctx, created.ID, mobyclient.NetworkInspectOptions{})
	if err != nil {
		return ManagedResource{}, true, fmt.Errorf("inspect created conversation network %s: %w", name, err)
	}
	resource, err := m.verifyConversationNetwork(spec, RuntimeSpecDigest(spec), inspected.Network, created.ID, true)
	return resource, true, err
}

func (m *DockerManager) verifyConversationNetwork(spec RuntimeSpec, expectedSpecDigest string, actual mobynetwork.Inspect, providerID string, requireEmpty bool) (ManagedResource, error) {
	if strings.TrimSpace(providerID) != "" && actual.ID != providerID {
		return ManagedResource{}, fmt.Errorf("%w: conversation network provider identity mismatch", ErrRuntimeStateConflict)
	}
	expected := conversationNetworkManagedResource(spec, actual.ID)
	observed, err := m.resourceFromLabels(ResourceKindConversationNetwork, actual.ID, actual.Name, actual.Labels, actual.Created.UTC())
	if err != nil || !sameManagedResource(expected, observed) {
		return ManagedResource{}, fmt.Errorf("%w: conversation network ownership mismatch", ErrRuntimeStateConflict)
	}
	if !sha256DigestPattern.MatchString(expectedSpecDigest) {
		return ManagedResource{}, fmt.Errorf("%w: conversation network expected specification digest is invalid", ErrRuntimeStateConflict)
	}
	for key, value := range expectedConversationNetworkLabels(m.ownerID, spec, expectedSpecDigest) {
		if actual.Labels[key] != value {
			return ManagedResource{}, fmt.Errorf("%w: conversation network label %s mismatch", ErrRuntimeStateConflict, key)
		}
	}
	if actual.Driver != "bridge" || actual.Scope != "local" || !actual.Internal || !actual.EnableIPv4 || actual.EnableIPv6 || actual.Attachable || actual.Ingress || actual.ConfigOnly || len(actual.Options) != 1 || actual.Options[conversationNetworkInhibitIPv4] != "true" {
		return ManagedResource{}, fmt.Errorf("%w: conversation network isolation settings mismatch", ErrRuntimeStateConflict)
	}
	if requireEmpty && (len(actual.Containers) != 0 || len(actual.Services) != 0) {
		return ManagedResource{}, fmt.Errorf("%w: conversation network already has attached workloads", ErrRuntimeStateConflict)
	}
	return observed, nil
}

func conversationNetworkOptions() map[string]string {
	return map[string]string{conversationNetworkInhibitIPv4: "true"}
}

func conversationNetworkLabels(ownerID string, spec RuntimeSpec) map[string]string {
	return expectedConversationNetworkLabels(ownerID, spec, RuntimeSpecDigest(spec))
}

func expectedConversationNetworkLabels(ownerID string, spec RuntimeSpec, specDigest string) map[string]string {
	return map[string]string{
		LabelManaged: "true", LabelOwner: ownerID,
		LabelResourceKind: ResourceKindConversationNetwork,
		LabelResourceID:   string(spec.ID), LabelRuntimeID: string(spec.ID),
		LabelConversationID: spec.ConversationID,
		LabelSpecDigest:     specDigest, LabelNetworkMode: string(NetworkInternal),
	}
}

func conversationNetworkManagedResource(spec RuntimeSpec, providerID string) ManagedResource {
	return ManagedResource{
		Kind: ResourceKindConversationNetwork, LogicalID: string(spec.ID), ProviderID: providerID,
		Name: ConversationNetworkName(spec.ID), ConversationID: spec.ConversationID,
	}
}

func (m *DockerManager) ensureOwnedWorkspaceVolume(ctx context.Context, spec RuntimeSpec, authorizedSpecDigest string) (bool, error) {
	if m.volumeAPI == nil {
		return false, fmt.Errorf("%w: engine client does not support named volumes", ErrEngineUnavailable)
	}
	expected := workspaceManagedResource(spec)
	result, err := m.volumeAPI.VolumeInspect(ctx, expected.Name, mobyclient.VolumeInspectOptions{})
	if err == nil {
		return false, m.verifyWorkspaceVolume(spec, result.Volume, authorizedSpecDigest)
	}
	if !containerderrdefs.IsNotFound(err) {
		return false, fmt.Errorf("inspect workspace volume %s: %w", expected.Name, err)
	}
	created, err := m.volumeAPI.VolumeCreate(ctx, mobyclient.VolumeCreateOptions{
		Name: expected.Name, Driver: "local", Labels: workspaceVolumeLabels(m.ownerID, spec),
	})
	if err != nil {
		return false, fmt.Errorf("create workspace volume %s: %w", expected.Name, err)
	}
	if err := m.verifyWorkspaceVolume(spec, created.Volume, authorizedSpecDigest); err != nil {
		// VolumeCreate may return a concurrently-created existing volume. If its
		// immutable labels differ, ownership is ambiguous and automatic deletion
		// would be unsafe.
		return false, err
	}
	return true, nil
}

func (m *DockerManager) verifyWorkspaceVolume(spec RuntimeSpec, actual mobyvolume.Volume, authorizedSpecDigest string) error {
	expected := workspaceManagedResource(spec)
	observed, err := m.resourceFromLabels(ResourceKindWorkspaceVolume, actual.Name, actual.Name, actual.Labels, parseVolumeCreatedAt(actual))
	if err != nil || !sameManagedResource(expected, observed) {
		return fmt.Errorf("%w: workspace volume ownership mismatch", ErrRuntimeStateConflict)
	}
	for key, value := range workspaceVolumeLabels(m.ownerID, spec) {
		if key == LabelSpecDigest && workspaceVolumeSpecDigestMatches(spec, actual.Labels[key], authorizedSpecDigest) {
			continue
		}
		if actual.Labels[key] != value {
			return fmt.Errorf("%w: workspace volume label %s mismatch", ErrRuntimeStateConflict, key)
		}
	}
	return nil
}

func workspaceVolumeSpecDigestMatches(spec RuntimeSpec, actual, authorized string) bool {
	if actual == RuntimeSpecDigest(spec) {
		return true
	}
	// Rebuild receives this exact digest from the durable pre-migration
	// specification. It authorizes reuse of only that already-owned persistent
	// volume while the database independently validates the controlled topology
	// replacement. Ordinary Create calls never provide this authorization.
	if sha256DigestPattern.MatchString(strings.TrimSpace(authorized)) && actual == authorized {
		return true
	}
	// Docker volume labels are immutable. A persistent workspace created before
	// stage 4 retains the digest of an otherwise-identical pre-network or
	// pre-gateway spec after an explicit controlled topology migration.
	legacy := spec
	if legacy.EgressGateway != nil && legacy.EgressGateway.BoundarySnapshot != nil {
		gateway := *legacy.EgressGateway
		gateway.BoundarySnapshot = nil
		legacy.EgressGateway = &gateway
		if actual == RuntimeSpecDigest(legacy) {
			return true
		}
	}
	if legacy.EgressGateway != nil {
		legacy.EgressGateway = nil
		if actual == RuntimeSpecDigest(legacy) {
			return true
		}
	}
	if legacy.Security.NetworkMode == NetworkInternal {
		legacy.Security.NetworkMode = NetworkNone
		return actual == RuntimeSpecDigest(legacy)
	}
	return false
}

func (m *DockerManager) rollbackNewWorkspaceVolume(created bool, spec RuntimeSpec, cause error) error {
	if !created || !spec.Workspace.Persistent || m.volumeAPI == nil {
		return cause
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	if err := m.deleteOwnedVolumeResource(cleanupCtx, workspaceManagedResource(spec)); err != nil && !errors.Is(err, ErrNotFound) {
		return errors.Join(cause, fmt.Errorf("rollback workspace volume %s: %w", spec.Workspace.VolumeName, err))
	}
	return cause
}

func (m *DockerManager) rollbackCreatedResources(networkCreated, egressNetworkCreated, workspaceCreated bool, gatewayID string, spec RuntimeSpec, cause error) error {
	if strings.TrimSpace(gatewayID) != "" {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		_, err := m.api.ContainerRemove(cleanupCtx, gatewayID, mobyclient.ContainerRemoveOptions{Force: true, RemoveVolumes: false})
		cancel()
		if err != nil && !containerderrdefs.IsNotFound(err) {
			cause = errors.Join(cause, fmt.Errorf("rollback egress gateway %s: %w", gatewayID, err))
		}
	}
	cause = m.rollbackNewWorkspaceVolume(workspaceCreated, spec, cause)
	if egressNetworkCreated && spec.EgressGateway != nil && m.networkAPI != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		if err := m.deleteOwnedEgressNetwork(cleanupCtx, spec, RuntimeSpecDigest(spec)); err != nil && !errors.Is(err, ErrNotFound) {
			cause = errors.Join(cause, fmt.Errorf("rollback egress network %s: %w", EgressNetworkName(spec.ID), err))
		}
		cancel()
	}
	if networkCreated && spec.Security.NetworkMode == NetworkInternal && m.networkAPI != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		if err := m.deleteOwnedConversationNetwork(cleanupCtx, spec, RuntimeSpecDigest(spec)); err != nil && !errors.Is(err, ErrNotFound) {
			cause = errors.Join(cause, fmt.Errorf("rollback conversation network %s: %w", ConversationNetworkName(spec.ID), err))
		}
		cancel()
	}
	return cause
}

func workspaceVolumeLabels(ownerID string, spec RuntimeSpec) map[string]string {
	return map[string]string{
		LabelManaged: "true", LabelOwner: ownerID,
		LabelResourceKind: ResourceKindWorkspaceVolume,
		LabelResourceID:   string(spec.ID), LabelRuntimeID: string(spec.ID),
		LabelConversationID: spec.ConversationID,
		LabelSpecDigest:     RuntimeSpecDigest(spec),
	}
}

func workspaceManagedResource(spec RuntimeSpec) ManagedResource {
	return ManagedResource{
		Kind: ResourceKindWorkspaceVolume, LogicalID: string(spec.ID),
		ProviderID: spec.Workspace.VolumeName, Name: spec.Workspace.VolumeName,
		ConversationID: spec.ConversationID,
	}
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
	if err := m.verifyObservedSecurityBaseline(ctx, actual); err != nil {
		return Runtime{}, err
	}
	if spec.EgressGateway != nil {
		if _, err := m.inspectOwnedEgressGateway(ctx, spec, &actual, StatusStopped); err != nil {
			return Runtime{}, err
		}
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
	networkMode := mobycontainer.NetworkMode(NetworkNone)
	if spec.Security.NetworkMode == NetworkInternal {
		networkMode = mobycontainer.NetworkMode(ConversationNetworkName(spec.ID))
	}
	host := &mobycontainer.HostConfig{
		NetworkMode: networkMode,
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
			"/tmp": tmpfsOptions(spec.Security.TmpfsBytes, true),
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
	if spec.Workspace.Persistent {
		host.Mounts = []mobymount.Mount{{
			Type: mobymount.TypeVolume, Source: spec.Workspace.VolumeName,
			Target: spec.Workspace.MountPath, ReadOnly: false,
			VolumeOptions: &mobymount.VolumeOptions{NoCopy: false},
		}}
	} else {
		host.Tmpfs[spec.Workspace.MountPath] = tmpfsOptions(spec.Resources.WorkspaceBytes, false)
	}
	return host
}

func runtimeHostConfigWithPolicyDNS(spec RuntimeSpec, address string) *mobycontainer.HostConfig {
	host := runtimeHostConfig(spec)
	if requiresPolicyDNS(spec) {
		parsed, _ := netip.ParseAddr(address)
		host.DNS = []netip.Addr{parsed}
	}
	return host
}

func runtimeNetworkingConfig(spec RuntimeSpec, network ManagedResource) *mobynetwork.NetworkingConfig {
	if spec.Security.NetworkMode != NetworkInternal {
		return nil
	}
	return &mobynetwork.NetworkingConfig{EndpointsConfig: map[string]*mobynetwork.EndpointSettings{
		ConversationNetworkName(spec.ID): {NetworkID: network.ProviderID},
	}}
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
	if actual.NetworkMode != expected.NetworkMode {
		return fmt.Errorf("%w: created runtime network mode mismatch", ErrRuntimeStateConflict)
	}
	if actual.Privileged || actual.PublishAllPorts || actual.AutoRemove || len(actual.Binds) != 0 || len(actual.Devices) != 0 || len(actual.DeviceRequests) != 0 || len(actual.PortBindings) != 0 {
		return fmt.Errorf("%w: created runtime has privileged access, host mounts, devices, or published ports", ErrRuntimeStateConflict)
	}
	if !actual.ReadonlyRootfs || len(actual.CapDrop) != 1 || !strings.EqualFold(actual.CapDrop[0], "ALL") || len(actual.CapAdd) != 0 || !containsString(actual.SecurityOpt, "no-new-privileges") {
		return fmt.Errorf("%w: created runtime privilege restrictions mismatch", ErrRuntimeStateConflict)
	}
	if actual.RestartPolicy.Name != mobycontainer.RestartPolicyDisabled {
		return fmt.Errorf("%w: created runtime restart policy mismatch", ErrRuntimeStateConflict)
	}
	if !validRuntimePolicyDNSSettings(actual, spec) {
		return fmt.Errorf("%w: created runtime declares unsupported DNS, host, or link settings", ErrRuntimeStateConflict)
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
	if err := verifyWorkspaceHostMounts(actual.Mounts, spec); err != nil {
		return err
	}
	return nil
}

func validRuntimePolicyDNSSettings(actual *mobycontainer.HostConfig, spec RuntimeSpec) bool {
	if actual == nil || len(actual.DNSOptions) != 0 || len(actual.DNSSearch) != 0 || len(actual.ExtraHosts) != 0 || len(actual.Links) != 0 {
		return false
	}
	if !requiresPolicyDNS(spec) {
		return len(actual.DNS) == 0
	}
	if len(actual.DNS) != 1 {
		return false
	}
	address := actual.DNS[0]
	return address.IsValid() && address.Is4() && !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() && !address.IsLinkLocalUnicast() && address.Zone() == ""
}

func verifyWorkspaceHostMounts(actual []mobymount.Mount, spec RuntimeSpec) error {
	if !spec.Workspace.Persistent {
		if len(actual) != 0 {
			return fmt.Errorf("%w: ephemeral runtime declares a persistent mount", ErrRuntimeStateConflict)
		}
		return nil
	}
	if len(actual) != 1 {
		return fmt.Errorf("%w: persistent runtime must declare exactly one named volume", ErrRuntimeStateConflict)
	}
	mount := actual[0]
	if mount.Type != mobymount.TypeVolume || mount.Source != spec.Workspace.VolumeName || mount.Target != spec.Workspace.MountPath || mount.ReadOnly || (mount.VolumeOptions != nil && mount.VolumeOptions.NoCopy) {
		return fmt.Errorf("%w: persistent workspace named volume mismatch", ErrRuntimeStateConflict)
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
	labels := map[string]string{
		LabelManaged:             "true",
		LabelOwner:               ownerID,
		LabelRuntimeID:           string(spec.ID),
		LabelConversationID:      spec.ConversationID,
		LabelResourceKind:        ResourceKindAgent,
		LabelImageDigest:         spec.Image.Digest,
		LabelImagePlatform:       spec.Image.Platform,
		LabelSpecDigest:          RuntimeSpecDigest(spec),
		LabelNanoCPUs:            strconv.FormatInt(spec.Resources.NanoCPUs, 10),
		LabelMemoryBytes:         strconv.FormatInt(spec.Resources.MemoryBytes, 10),
		LabelPIDs:                strconv.FormatInt(spec.Resources.PIDs, 10),
		LabelNoFileSoft:          strconv.FormatUint(spec.Resources.NoFileSoft, 10),
		LabelNoFileHard:          strconv.FormatUint(spec.Resources.NoFileHard, 10),
		LabelWorkspaceBytes:      strconv.FormatInt(spec.Resources.WorkspaceBytes, 10),
		LabelTmpfsBytes:          strconv.FormatInt(spec.Security.TmpfsBytes, 10),
		LabelLogMaxBytes:         strconv.FormatInt(spec.Resources.LogMaxBytes, 10),
		LabelLogMaxFiles:         strconv.Itoa(spec.Resources.LogMaxFiles),
		LabelWorkspacePath:       spec.Workspace.MountPath,
		LabelWorkspacePersistent: strconv.FormatBool(spec.Workspace.Persistent),
		LabelWorkspaceVolume:     spec.Workspace.VolumeName,
		LabelNetworkMode:         string(spec.Security.NetworkMode),
	}
	if spec.EgressGateway == nil {
		return labels
	}
	gateway := spec.EgressGateway
	resources := gateway.Resources
	labels[LabelEgressGateway] = "true"
	labels[LabelEgressImageRepository] = gateway.Image.Repository
	labels[LabelEgressImageDigest] = gateway.Image.Digest
	labels[LabelEgressImagePlatform] = gateway.Image.Platform
	labels[LabelEgressNanoCPUs] = strconv.FormatInt(resources.NanoCPUs, 10)
	labels[LabelEgressMemoryBytes] = strconv.FormatInt(resources.MemoryBytes, 10)
	labels[LabelEgressPIDs] = strconv.FormatInt(resources.PIDs, 10)
	labels[LabelEgressNoFileSoft] = strconv.FormatUint(resources.NoFileSoft, 10)
	labels[LabelEgressNoFileHard] = strconv.FormatUint(resources.NoFileHard, 10)
	labels[LabelEgressTmpfsBytes] = strconv.FormatInt(resources.TmpfsBytes, 10)
	labels[LabelEgressLogMaxBytes] = strconv.FormatInt(resources.LogMaxBytes, 10)
	labels[LabelEgressLogMaxFiles] = strconv.Itoa(resources.LogMaxFiles)
	if gateway.BoundarySnapshot != nil {
		labels[LabelEgressSnapshotID] = gateway.BoundarySnapshot.ID
		labels[LabelEgressSnapshotSHA256] = gateway.BoundarySnapshot.SHA256
	}
	return labels
}
