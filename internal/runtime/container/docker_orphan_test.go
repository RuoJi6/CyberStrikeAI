package container

import (
	"context"
	"errors"
	"testing"
	"time"

	mobycontainer "github.com/moby/moby/api/types/container"
	mobynetwork "github.com/moby/moby/api/types/network"
	mobyvolume "github.com/moby/moby/api/types/volume"
	mobyclient "github.com/moby/moby/client"
)

type fakeDockerManagedResourceAPI struct {
	*fakeDockerCreationAPI
	networkListResult    mobyclient.NetworkListResult
	networkListErr       error
	networkInspectResult mobyclient.NetworkInspectResult
	networkInspectErr    error
	networkRemovedID     string
	networkRemoveErr     error
	volumeListResult     mobyclient.VolumeListResult
	volumeListErr        error
	volumeInspectResult  mobyclient.VolumeInspectResult
	volumeInspectErr     error
	volumeRemovedID      string
	volumeRemoveOpts     mobyclient.VolumeRemoveOptions
	volumeRemoveErr      error
}

func (f *fakeDockerManagedResourceAPI) NetworkList(context.Context, mobyclient.NetworkListOptions) (mobyclient.NetworkListResult, error) {
	return f.networkListResult, f.networkListErr
}

func (f *fakeDockerManagedResourceAPI) NetworkInspect(context.Context, string, mobyclient.NetworkInspectOptions) (mobyclient.NetworkInspectResult, error) {
	return f.networkInspectResult, f.networkInspectErr
}

func (f *fakeDockerManagedResourceAPI) NetworkRemove(_ context.Context, id string, _ mobyclient.NetworkRemoveOptions) (mobyclient.NetworkRemoveResult, error) {
	f.networkRemovedID = id
	return mobyclient.NetworkRemoveResult{}, f.networkRemoveErr
}

func (f *fakeDockerManagedResourceAPI) VolumeList(context.Context, mobyclient.VolumeListOptions) (mobyclient.VolumeListResult, error) {
	return f.volumeListResult, f.volumeListErr
}

func (f *fakeDockerManagedResourceAPI) VolumeInspect(context.Context, string, mobyclient.VolumeInspectOptions) (mobyclient.VolumeInspectResult, error) {
	return f.volumeInspectResult, f.volumeInspectErr
}

func (f *fakeDockerManagedResourceAPI) VolumeRemove(_ context.Context, id string, options mobyclient.VolumeRemoveOptions) (mobyclient.VolumeRemoveResult, error) {
	f.volumeRemovedID = id
	f.volumeRemoveOpts = options
	return mobyclient.VolumeRemoveResult{}, f.volumeRemoveErr
}

func TestDockerManagerListsAndDeletesOnlyOwnerLabelledResources(t *testing.T) {
	ownerID := "instance-01"
	spec := creationSpec()
	creationAPI := newSuccessfulCreationAPI(spec, ownerID, "provider-container-1", "")
	creationAPI.listResult = mobyclient.ContainerListResult{Items: []mobycontainer.Summary{{
		ID: "provider-container-1", Names: []string{"/" + runtimeContainerName(spec.ID)},
		Labels: runtimeLabels(ownerID, spec), Created: time.Now().Unix(),
	}}}
	networkID := "provider-network-01"
	networkLogicalID := "network-01"
	networkLabels := managedTestLabels(ownerID, ResourceKindConversationNetwork, networkLogicalID, spec.ConversationID)
	network := mobynetwork.Network{
		ID: networkID, Name: managedResourceName(ResourceKindConversationNetwork, networkLogicalID),
		Labels: networkLabels, Created: time.Now().UTC(),
	}
	volumeLogicalID := "volume-01"
	volumeName := managedResourceName(ResourceKindWorkspaceVolume, volumeLogicalID)
	volume := mobyvolume.Volume{Name: volumeName, Labels: managedTestLabels(ownerID, ResourceKindWorkspaceVolume, volumeLogicalID, spec.ConversationID), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	api := &fakeDockerManagedResourceAPI{
		fakeDockerCreationAPI: creationAPI,
		networkListResult:     mobyclient.NetworkListResult{Items: []mobynetwork.Summary{{Network: network}}},
		networkInspectResult:  mobyclient.NetworkInspectResult{Network: mobynetwork.Inspect{Network: network}},
		volumeListResult:      mobyclient.VolumeListResult{Items: []mobyvolume.Volume{volume}},
		volumeInspectResult:   mobyclient.VolumeInspectResult{Volume: volume},
	}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := manager.ListOwnedResources(context.Background())
	if err != nil || len(resources) != 3 {
		t.Fatalf("resources = %#v, %v", resources, err)
	}
	for _, resource := range resources {
		if err := manager.DeleteOwnedResource(context.Background(), resource); err != nil {
			t.Fatalf("delete %#v: %v", resource, err)
		}
	}
	if creationAPI.removedID != "provider-container-1" || creationAPI.removeOpts.Force || creationAPI.removeOpts.RemoveVolumes {
		t.Fatalf("container removal = %q / %#v", creationAPI.removedID, creationAPI.removeOpts)
	}
	if api.networkRemovedID != networkID {
		t.Fatalf("network removal = %q", api.networkRemovedID)
	}
	if api.volumeRemovedID != volumeName || api.volumeRemoveOpts.Force {
		t.Fatalf("volume removal = %q / %#v", api.volumeRemovedID, api.volumeRemoveOpts)
	}
}

func TestDockerManagerListsGatewayTopologyAsIndependentlyOwnedResources(t *testing.T) {
	ownerID := "instance-01"
	spec := gatewayCreationSpec()
	creationAPI := newSuccessfulGatewayCreationAPI(spec, ownerID)
	creationAPI.listResult = mobyclient.ContainerListResult{Items: []mobycontainer.Summary{
		{ID: "provider-agent-1", Names: []string{"/" + runtimeContainerName(spec.ID)}, Labels: runtimeLabels(ownerID, spec), Created: time.Now().Unix()},
		{ID: "provider-gateway-1", Names: []string{"/" + EgressGatewayContainerName(spec.ID)}, Labels: egressGatewayLabels(ownerID, spec), Created: time.Now().Unix()},
	}}
	internal := mobynetwork.Network{
		ID: "provider-network-1", Name: ConversationNetworkName(spec.ID), Labels: conversationNetworkLabels(ownerID, spec), Created: time.Now().UTC(),
	}
	egress := mobynetwork.Network{
		ID: "provider-network-2", Name: EgressNetworkName(spec.ID), Labels: egressNetworkLabels(ownerID, spec), Created: time.Now().UTC(),
	}
	api := &fakeDockerManagedResourceAPI{
		fakeDockerCreationAPI: creationAPI,
		networkListResult:     mobyclient.NetworkListResult{Items: []mobynetwork.Summary{{Network: internal}, {Network: egress}}},
		volumeListResult:      mobyclient.VolumeListResult{},
	}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := manager.ListOwnedResources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 4 || resources[0].Kind != ResourceKindAgent || resources[1].Kind != ResourceKindConversationNetwork || resources[2].Kind != ResourceKindEgressGateway || resources[3].Kind != ResourceKindEgressNetwork {
		t.Fatalf("gateway owned resources = %#v", resources)
	}
}

func TestDockerManagerOrphanDeletionRevalidatesLabelsAndAttachments(t *testing.T) {
	ownerID := "instance-01"
	logicalID := "network-unsafe"
	conversationID := "conversation-01"
	network := mobynetwork.Network{
		ID: "provider-network-unsafe", Name: managedResourceName(ResourceKindConversationNetwork, logicalID),
		Labels: managedTestLabels(ownerID, ResourceKindConversationNetwork, logicalID, conversationID), Created: time.Now().UTC(),
	}
	resource := ManagedResource{Kind: ResourceKindConversationNetwork, LogicalID: logicalID, ProviderID: network.ID, Name: network.Name, ConversationID: conversationID}
	tests := []struct {
		name   string
		mutate func(*mobynetwork.Inspect)
	}{
		{name: "owner changed", mutate: func(actual *mobynetwork.Inspect) { actual.Labels[LabelOwner] = "other-instance" }},
		{name: "attached container", mutate: func(actual *mobynetwork.Inspect) {
			actual.Containers = map[string]mobynetwork.EndpointResource{"container": {Name: "foreign"}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creationAPI := newSuccessfulCreationAPI(creationSpec(), ownerID, "provider-container-1", "")
			actual := mobynetwork.Inspect{Network: network}
			actual.Labels = cloneLabels(network.Labels)
			tt.mutate(&actual)
			api := &fakeDockerManagedResourceAPI{fakeDockerCreationAPI: creationAPI, networkInspectResult: mobyclient.NetworkInspectResult{Network: actual}}
			manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
			if err != nil {
				t.Fatal(err)
			}
			err = manager.DeleteOwnedResource(context.Background(), resource)
			if !errors.Is(err, ErrRuntimeStateConflict) || api.networkRemovedID != "" {
				t.Fatalf("unsafe delete = %v, removed %q", err, api.networkRemovedID)
			}
		})
	}
}

func managedTestLabels(ownerID, kind, logicalID, conversationID string) map[string]string {
	return map[string]string{
		LabelManaged:        "true",
		LabelOwner:          ownerID,
		LabelResourceKind:   kind,
		LabelResourceID:     logicalID,
		LabelConversationID: conversationID,
	}
}

func cloneLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}
