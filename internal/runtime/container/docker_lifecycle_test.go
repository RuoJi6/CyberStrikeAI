package container

import (
	"context"
	"errors"
	"testing"
	"time"

	containerderrdefs "github.com/containerd/errdefs"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobynetwork "github.com/moby/moby/api/types/network"
	mobyclient "github.com/moby/moby/client"
)

func TestDockerManagerLifecycleStartStopAndDelete(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{
		Networks: map[string]*mobynetwork.EndpointSettings{"none": {}},
	}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}

	started, err := manager.Start(context.Background(), spec.ID)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if started.Status != StatusRunning || api.startedID != "provider-container-1" {
		t.Fatalf("started runtime = %#v, provider = %q", started, api.startedID)
	}

	stopped, err := manager.Stop(context.Background(), spec.ID, StopOptions{Timeout: 2500 * time.Millisecond})
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if stopped.Status != StatusStopped || api.stoppedID != "provider-container-1" {
		t.Fatalf("stopped runtime = %#v, provider = %q", stopped, api.stoppedID)
	}
	if api.stopOpts.Timeout == nil || *api.stopOpts.Timeout != 3 {
		t.Fatalf("rounded stop timeout = %#v", api.stopOpts.Timeout)
	}

	if err := manager.Delete(context.Background(), spec.ID, DeleteOptions{}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if api.removedID != "provider-container-1" || api.removeOpts.Force || api.removeOpts.RemoveVolumes {
		t.Fatalf("delete target/options = %q / %#v", api.removedID, api.removeOpts)
	}
}

func TestDockerManagerLifecycleIsIdempotentAtTargetState(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Stop(context.Background(), spec.ID, StopOptions{}); err != nil {
		t.Fatalf("idempotent stop: %v", err)
	}
	if api.stoppedID != "" {
		t.Fatalf("engine stop was called for stopped runtime: %q", api.stoppedID)
	}
	api.containerResult.Container.State.Status = mobycontainer.StateRunning
	api.containerResult.Container.State.Running = true
	if _, err := manager.Start(context.Background(), spec.ID); err != nil {
		t.Fatalf("idempotent start: %v", err)
	}
	if api.startedID != "" {
		t.Fatalf("engine start was called for running runtime: %q", api.startedID)
	}
}

func TestDockerManagerLifecycleRejectsForeignOrDriftedRuntime(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeDockerCreationAPI)
	}{
		{
			name: "foreign owner",
			mutate: func(api *fakeDockerCreationAPI) {
				api.containerResult.Container.Config.Labels[LabelOwner] = "other-instance"
			},
		},
		{
			name: "network enabled",
			mutate: func(api *fakeDockerCreationAPI) {
				api.containerResult.Container.Config.NetworkDisabled = false
			},
		},
		{
			name: "extra network connected",
			mutate: func(api *fakeDockerCreationAPI) {
				api.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{
					Networks: map[string]*mobynetwork.EndpointSettings{"bridge": {}},
				}
			},
		},
		{
			name: "host bind added",
			mutate: func(api *fakeDockerCreationAPI) {
				api.containerResult.Container.HostConfig.Binds = []string{"/:/host"}
			},
		},
		{
			name: "memory limit changed",
			mutate: func(api *fakeDockerCreationAPI) {
				api.containerResult.Container.HostConfig.Memory *= 2
				api.containerResult.Container.HostConfig.MemorySwap *= 2
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := creationSpec()
			api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
			tt.mutate(api)
			manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = manager.Start(context.Background(), spec.ID)
			if !errors.Is(err, ErrRuntimeStateConflict) {
				t.Fatalf("start error = %v", err)
			}
			if api.startedID != "" {
				t.Fatalf("engine mutation reached foreign/drifted runtime: %q", api.startedID)
			}
		})
	}
}

func TestDockerManagerRebuildRequiresStoppedRuntime(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.State.Status = mobycontainer.StateRunning
	api.containerResult.Container.State.Running = true
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Rebuild(context.Background(), spec.ID, RebuildOptions{Spec: spec})
	if !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("rebuild running error = %v", err)
	}
	if api.removedID != "" || api.createOpts.Name != "" {
		t.Fatal("running runtime was mutated")
	}
}

func TestDockerManagerRebuildRemovesAndRecreatesStoppedRuntime(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := manager.Rebuild(context.Background(), spec.ID, RebuildOptions{Spec: spec})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if rebuilt.Status != StatusStopped || api.removedID != "provider-container-1" || api.createOpts.Name != runtimeContainerName(spec.ID) {
		t.Fatalf("rebuilt = %#v, remove=%q, create=%q", rebuilt, api.removedID, api.createOpts.Name)
	}
}

func TestDockerManagerDeleteRejectsRunningRuntime(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.State.Status = mobycontainer.StateRunning
	api.containerResult.Container.State.Running = true
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	err = manager.Delete(context.Background(), spec.ID, DeleteOptions{})
	if !errors.Is(err, ErrRuntimeStateConflict) || api.removedID != "" {
		t.Fatalf("delete running error=%v removed=%q", err, api.removedID)
	}
}

func TestDockerManagerListOwnedRejectsDuplicateRuntimeClaims(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.listResult = mobyclient.ContainerListResult{Items: []mobycontainer.Summary{
		{ID: "provider-1", Labels: runtimeLabels("instance-01", spec)},
		{ID: "provider-2", Labels: runtimeLabels("instance-01", spec)},
	}}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.ListOwned(context.Background())
	if !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("duplicate list error = %v", err)
	}
}

func TestDockerManagerLifecycleMapsNotFound(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerErr = containerderrdefs.ErrNotFound.WithMessage("missing")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Inspect(context.Background(), spec.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("inspect not found error = %v", err)
	}
}
