package container

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	containerderrdefs "github.com/containerd/errdefs"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobynetwork "github.com/moby/moby/api/types/network"
	mobyvolume "github.com/moby/moby/api/types/volume"
	mobyclient "github.com/moby/moby/client"
)

var _ ManagedResourceManager = (*DockerManager)(nil)

func (m *DockerManager) ListOwnedResources(ctx context.Context) ([]ManagedResource, error) {
	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if m.resourceAPI == nil {
		return nil, fmt.Errorf("%w: engine client does not support network and volume reconciliation", ErrEngineUnavailable)
	}
	filters := make(mobyclient.Filters).
		Add("label", LabelManaged+"=true").
		Add("label", LabelOwner+"="+m.ownerID)
	resources := make([]ManagedResource, 0)
	containers, err := m.api.ContainerList(operationCtx, mobyclient.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return nil, fmt.Errorf("list owner-labelled containers: %w", err)
	}
	for _, item := range containers.Items {
		name := ""
		if len(item.Names) > 0 {
			name = strings.TrimPrefix(item.Names[0], "/")
		}
		kind := strings.TrimSpace(item.Labels[LabelResourceKind])
		if kind != ResourceKindAgent && kind != ResourceKindEgressGateway {
			return nil, fmt.Errorf("%w: unsupported owner-labelled container kind %q", ErrRuntimeStateConflict, kind)
		}
		resource, resourceErr := m.resourceFromLabels(kind, item.ID, name, item.Labels, time.Unix(item.Created, 0).UTC())
		if resourceErr != nil {
			return nil, resourceErr
		}
		resources = append(resources, resource)
	}
	networks, err := m.resourceAPI.NetworkList(operationCtx, mobyclient.NetworkListOptions{Filters: filters})
	if err != nil {
		return nil, fmt.Errorf("list owner-labelled networks: %w", err)
	}
	for _, item := range networks.Items {
		kind := strings.TrimSpace(item.Labels[LabelResourceKind])
		if kind != ResourceKindConversationNetwork && kind != ResourceKindEgressNetwork {
			return nil, fmt.Errorf("%w: unsupported owner-labelled network kind %q", ErrRuntimeStateConflict, kind)
		}
		resource, resourceErr := m.resourceFromLabels(kind, item.ID, item.Name, item.Labels, item.Created.UTC())
		if resourceErr != nil {
			return nil, resourceErr
		}
		resources = append(resources, resource)
	}
	volumes, err := m.resourceAPI.VolumeList(operationCtx, mobyclient.VolumeListOptions{Filters: filters})
	if err != nil {
		return nil, fmt.Errorf("list owner-labelled volumes: %w", err)
	}
	for _, item := range volumes.Items {
		createdAt, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(item.CreatedAt))
		resource, resourceErr := m.resourceFromLabels(ResourceKindWorkspaceVolume, item.Name, item.Name, item.Labels, createdAt.UTC())
		if resourceErr != nil {
			return nil, resourceErr
		}
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Kind == resources[j].Kind {
			return resources[i].LogicalID < resources[j].LogicalID
		}
		return resources[i].Kind < resources[j].Kind
	})
	return resources, nil
}

func (m *DockerManager) DeleteOwnedResource(ctx context.Context, resource ManagedResource) error {
	if err := validateManagedResource(resource); err != nil {
		return err
	}
	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	switch resource.Kind {
	case ResourceKindAgent, ResourceKindEgressGateway:
		return m.deleteOwnedContainerResource(operationCtx, resource)
	case ResourceKindConversationNetwork, ResourceKindEgressNetwork:
		return m.deleteOwnedNetworkResource(operationCtx, resource)
	case ResourceKindWorkspaceVolume:
		return m.deleteOwnedVolumeResource(operationCtx, resource)
	default:
		return fmt.Errorf("%w: unsupported managed resource kind", ErrInvalidSpecification)
	}
}

func (m *DockerManager) deleteOwnedContainerResource(ctx context.Context, expected ManagedResource) error {
	result, err := m.api.ContainerInspect(ctx, expected.ProviderID, mobyclient.ContainerInspectOptions{Size: false})
	if err != nil {
		return mapManagedResourceNotFound(err, expected)
	}
	actual := result.Container
	if actual.Config == nil || actual.State == nil {
		return fmt.Errorf("%w: owner-labelled container inspection is incomplete", ErrRuntimeStateConflict)
	}
	observed, err := m.resourceFromLabels(expected.Kind, actual.ID, strings.TrimPrefix(actual.Name, "/"), actual.Config.Labels, time.Time{})
	if err != nil || !sameManagedResource(expected, observed) {
		return fmt.Errorf("%w: owner-labelled container identity changed before cleanup", ErrRuntimeStateConflict)
	}
	if actual.State.Running {
		seconds := int(defaultRuntimeStopTimeout / time.Second)
		if _, err := m.api.ContainerStop(ctx, actual.ID, mobyclient.ContainerStopOptions{Timeout: &seconds}); err != nil && !containerderrdefs.IsNotFound(err) {
			return fmt.Errorf("stop orphan container %s: %w", expected.LogicalID, err)
		}
	}
	if _, err := m.api.ContainerRemove(ctx, actual.ID, mobyclient.ContainerRemoveOptions{Force: false, RemoveVolumes: false}); err != nil {
		return mapManagedResourceNotFound(err, expected)
	}
	return nil
}

func (m *DockerManager) deleteOwnedNetworkResource(ctx context.Context, expected ManagedResource) error {
	if m.resourceAPI == nil {
		return fmt.Errorf("%w: engine client does not support network reconciliation", ErrEngineUnavailable)
	}
	result, err := m.resourceAPI.NetworkInspect(ctx, expected.ProviderID, mobyclient.NetworkInspectOptions{})
	if err != nil {
		return mapManagedResourceNotFound(err, expected)
	}
	actual := result.Network
	observed, err := m.resourceFromLabels(expected.Kind, actual.ID, actual.Name, actual.Labels, actual.Created.UTC())
	if err != nil || !sameManagedResource(expected, observed) {
		return fmt.Errorf("%w: owner-labelled network identity changed before cleanup", ErrRuntimeStateConflict)
	}
	if len(actual.Containers) != 0 || len(actual.Services) != 0 {
		return fmt.Errorf("%w: orphan network %s still has attached workloads", ErrRuntimeStateConflict, expected.LogicalID)
	}
	if _, err := m.resourceAPI.NetworkRemove(ctx, actual.ID, mobyclient.NetworkRemoveOptions{}); err != nil {
		return mapManagedResourceNotFound(err, expected)
	}
	return nil
}

func (m *DockerManager) deleteOwnedVolumeResource(ctx context.Context, expected ManagedResource) error {
	if m.volumeAPI == nil {
		return fmt.Errorf("%w: engine client does not support volume reconciliation", ErrEngineUnavailable)
	}
	result, err := m.volumeAPI.VolumeInspect(ctx, expected.ProviderID, mobyclient.VolumeInspectOptions{})
	if err != nil {
		return mapManagedResourceNotFound(err, expected)
	}
	actual := result.Volume
	observed, err := m.resourceFromLabels(ResourceKindWorkspaceVolume, actual.Name, actual.Name, actual.Labels, parseVolumeCreatedAt(actual))
	if err != nil || !sameManagedResource(expected, observed) {
		return fmt.Errorf("%w: owner-labelled volume identity changed before cleanup", ErrRuntimeStateConflict)
	}
	if _, err := m.volumeAPI.VolumeRemove(ctx, actual.Name, mobyclient.VolumeRemoveOptions{Force: false}); err != nil {
		return mapManagedResourceNotFound(err, expected)
	}
	return nil
}

func (m *DockerManager) resourceFromLabels(kind, providerID, name string, labels map[string]string, createdAt time.Time) (ManagedResource, error) {
	if labels[LabelManaged] != "true" || labels[LabelOwner] != m.ownerID || labels[LabelResourceKind] != kind {
		return ManagedResource{}, fmt.Errorf("%w: managed %s ownership labels mismatch", ErrRuntimeStateConflict, kind)
	}
	logicalID := strings.TrimSpace(labels[LabelResourceID])
	if kind == ResourceKindAgent || kind == ResourceKindEgressGateway {
		logicalID = strings.TrimSpace(labels[LabelRuntimeID])
	}
	resource := ManagedResource{
		Kind:           kind,
		LogicalID:      logicalID,
		ProviderID:     strings.TrimSpace(providerID),
		Name:           strings.TrimSpace(name),
		ConversationID: strings.TrimSpace(labels[LabelConversationID]),
		CreatedAt:      createdAt.UTC(),
	}
	if kind == ResourceKindWorkspaceVolume {
		sharedLabel := strings.TrimSpace(labels[LabelWorkspaceShared])
		shared := false
		if sharedLabel != "" {
			var parseErr error
			shared, parseErr = strconv.ParseBool(sharedLabel)
			if parseErr != nil {
				return ManagedResource{}, fmt.Errorf("%w: managed workspace shared label is invalid", ErrRuntimeStateConflict)
			}
		}
		expectedShared := strings.HasPrefix(logicalID, "shared-")
		if shared != expectedShared || (shared && resource.ConversationID != "") {
			return ManagedResource{}, fmt.Errorf("%w: managed workspace sharing identity mismatch", ErrRuntimeStateConflict)
		}
	}
	if err := validateManagedResource(resource); err != nil {
		return ManagedResource{}, err
	}
	if resource.Name != managedResourceName(kind, resource.LogicalID) {
		return ManagedResource{}, fmt.Errorf("%w: managed %s name mismatch", ErrRuntimeStateConflict, kind)
	}
	return resource, nil
}

func managedResourceName(kind, logicalID string) string {
	switch kind {
	case ResourceKindAgent:
		return runtimeContainerName(RuntimeID(logicalID))
	case ResourceKindConversationNetwork:
		return "cyberstrike-network-" + logicalID
	case ResourceKindEgressGateway:
		return "cyberstrike-egress-" + logicalID
	case ResourceKindEgressNetwork:
		return "cyberstrike-egress-network-" + logicalID
	case ResourceKindWorkspaceVolume:
		return "cyberstrike-workspace-" + logicalID
	default:
		return ""
	}
}

// WorkspaceVolumeName returns the only accepted named volume for a runtime.
// It is generated by the control plane and never accepted from a user path.
func WorkspaceVolumeName(id RuntimeID) string {
	return WorkspaceVolumeNameForID(string(id))
}

// WorkspaceVolumeNameForID derives a Docker volume name from a trusted
// control-plane workspace identifier. Callers must never pass a user supplied
// Docker volume name or host path.
func WorkspaceVolumeNameForID(id string) string {
	return managedResourceName(ResourceKindWorkspaceVolume, strings.TrimSpace(id))
}

// ConversationNetworkName returns the only accepted per-conversation network
// name for a runtime. It is system-derived and never accepted from a request.
func ConversationNetworkName(id RuntimeID) string {
	return managedResourceName(ResourceKindConversationNetwork, string(id))
}

func sameManagedResource(expected, observed ManagedResource) bool {
	return expected.Kind == observed.Kind && expected.LogicalID == observed.LogicalID &&
		expected.ProviderID == observed.ProviderID && expected.Name == observed.Name &&
		expected.ConversationID == observed.ConversationID
}

func mapManagedResourceNotFound(err error, resource ManagedResource) error {
	if containerderrdefs.IsNotFound(err) {
		return fmt.Errorf("%w: managed resource %s/%s", ErrNotFound, resource.Kind, resource.LogicalID)
	}
	return err
}

func parseVolumeCreatedAt(volume mobyvolume.Volume) time.Time {
	createdAt, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(volume.CreatedAt))
	return createdAt.UTC()
}

// Compile-time field checks keep the Moby API assumptions used above visible.
var (
	_ = mobycontainer.Summary{}
	_ = mobynetwork.Summary{}
)
