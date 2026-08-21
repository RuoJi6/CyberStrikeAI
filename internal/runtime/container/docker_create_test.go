package container

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	containerderrdefs "github.com/containerd/errdefs"
	mobystdcopy "github.com/moby/moby/api/pkg/stdcopy"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobyimage "github.com/moby/moby/api/types/image"
	mobynetwork "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/system"
	mobyvolume "github.com/moby/moby/api/types/volume"
	mobyclient "github.com/moby/moby/client"
)

type fakeDockerCreationAPI struct {
	*fakeDockerInspectionAPI
	createResult       mobyclient.ContainerCreateResult
	createErr          error
	createOpts         mobyclient.ContainerCreateOptions
	removeErr          error
	removedID          string
	removeOpts         mobyclient.ContainerRemoveOptions
	pathStats          map[string]mobycontainer.PathStat
	pathStatErrs       map[string]error
	listResult         mobyclient.ContainerListResult
	listErr            error
	startErr           error
	stopErr            error
	startedID          string
	stoppedID          string
	stopOpts           mobyclient.ContainerStopOptions
	execCreateOpts     mobyclient.ExecCreateOptions
	execContainerID    string
	execID             string
	execStdout         string
	execStderr         string
	execStdin          []byte
	execStdinBytes     int
	execAttachOpts     mobyclient.ExecAttachOptions
	execExitCode       int
	execRunning        bool
	volumes            map[string]mobyvolume.Volume
	volumeCreateOpts   mobyclient.VolumeCreateOptions
	volumeCreateErr    error
	volumeCreateCalls  int
	volumeInspectErr   error
	volumeRemoved      string
	volumeRemoveErr    error
	networks           map[string]mobynetwork.Inspect
	networkCreateOpts  mobyclient.NetworkCreateOptions
	networkCreateName  string
	networkCreateErr   error
	networkCreateCalls int
	networkRemoved     string
	networkRemoveErr   error
}

func (f *fakeDockerCreationAPI) ContainerCreate(_ context.Context, options mobyclient.ContainerCreateOptions) (mobyclient.ContainerCreateResult, error) {
	f.createOpts = options
	return f.createResult, f.createErr
}

func (f *fakeDockerCreationAPI) ContainerRemove(_ context.Context, id string, options mobyclient.ContainerRemoveOptions) (mobyclient.ContainerRemoveResult, error) {
	f.removedID = id
	f.removeOpts = options
	if f.removeErr == nil {
		for name, network := range f.networks {
			delete(network.Containers, id)
			f.networks[name] = network
		}
	}
	return mobyclient.ContainerRemoveResult{}, f.removeErr
}

func (f *fakeDockerCreationAPI) NetworkCreate(_ context.Context, name string, options mobyclient.NetworkCreateOptions) (mobyclient.NetworkCreateResult, error) {
	f.networkCreateName = name
	f.networkCreateOpts = options
	f.networkCreateCalls++
	if f.networkCreateErr != nil {
		return mobyclient.NetworkCreateResult{}, f.networkCreateErr
	}
	if f.networks == nil {
		f.networks = make(map[string]mobynetwork.Inspect)
	}
	if _, exists := f.networks[name]; exists {
		return mobyclient.NetworkCreateResult{}, containerderrdefs.ErrConflict.WithMessage("network exists")
	}
	id := "provider-network-1"
	enableIPv4 := options.EnableIPv4 == nil || *options.EnableIPv4
	enableIPv6 := options.EnableIPv6 != nil && *options.EnableIPv6
	f.networks[name] = mobynetwork.Inspect{Network: mobynetwork.Network{
		ID: id, Name: name, Created: time.Date(2026, 8, 21, 2, 0, 0, 0, time.UTC),
		Scope: options.Scope, Driver: options.Driver, EnableIPv4: enableIPv4, EnableIPv6: enableIPv6,
		Internal: options.Internal, Attachable: options.Attachable, Ingress: options.Ingress,
		ConfigOnly: options.ConfigOnly, Labels: cloneLabels(options.Labels),
	}}
	return mobyclient.NetworkCreateResult{ID: id}, nil
}

func (f *fakeDockerCreationAPI) NetworkInspect(_ context.Context, idOrName string, _ mobyclient.NetworkInspectOptions) (mobyclient.NetworkInspectResult, error) {
	for name, network := range f.networks {
		if name == idOrName || network.ID == idOrName {
			return mobyclient.NetworkInspectResult{Network: network}, nil
		}
	}
	return mobyclient.NetworkInspectResult{}, containerderrdefs.ErrNotFound.WithMessage("network not found")
}

func (f *fakeDockerCreationAPI) NetworkRemove(_ context.Context, id string, _ mobyclient.NetworkRemoveOptions) (mobyclient.NetworkRemoveResult, error) {
	f.networkRemoved = id
	if f.networkRemoveErr != nil {
		return mobyclient.NetworkRemoveResult{}, f.networkRemoveErr
	}
	for name, network := range f.networks {
		if network.ID == id || name == id {
			if len(network.Containers) != 0 {
				return mobyclient.NetworkRemoveResult{}, containerderrdefs.ErrConflict.WithMessage("network attached")
			}
			delete(f.networks, name)
			return mobyclient.NetworkRemoveResult{}, nil
		}
	}
	return mobyclient.NetworkRemoveResult{}, containerderrdefs.ErrNotFound.WithMessage("network not found")
}

func (f *fakeDockerCreationAPI) VolumeCreate(_ context.Context, options mobyclient.VolumeCreateOptions) (mobyclient.VolumeCreateResult, error) {
	f.volumeCreateOpts = options
	f.volumeCreateCalls++
	if f.volumeCreateErr != nil {
		return mobyclient.VolumeCreateResult{}, f.volumeCreateErr
	}
	if f.volumes == nil {
		f.volumes = make(map[string]mobyvolume.Volume)
	}
	if existing, ok := f.volumes[options.Name]; ok {
		return mobyclient.VolumeCreateResult{Volume: existing}, nil
	}
	created := mobyvolume.Volume{
		Name: options.Name, Driver: options.Driver, Labels: options.Labels,
		CreatedAt: time.Date(2026, 8, 21, 1, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	f.volumes[options.Name] = created
	return mobyclient.VolumeCreateResult{Volume: created}, nil
}

func (f *fakeDockerCreationAPI) VolumeInspect(_ context.Context, name string, _ mobyclient.VolumeInspectOptions) (mobyclient.VolumeInspectResult, error) {
	if f.volumeInspectErr != nil {
		return mobyclient.VolumeInspectResult{}, f.volumeInspectErr
	}
	if volume, ok := f.volumes[name]; ok {
		return mobyclient.VolumeInspectResult{Volume: volume}, nil
	}
	return mobyclient.VolumeInspectResult{}, containerderrdefs.ErrNotFound.WithMessage("volume not found")
}

func (f *fakeDockerCreationAPI) VolumeRemove(_ context.Context, name string, _ mobyclient.VolumeRemoveOptions) (mobyclient.VolumeRemoveResult, error) {
	f.volumeRemoved = name
	if f.volumeRemoveErr != nil {
		return mobyclient.VolumeRemoveResult{}, f.volumeRemoveErr
	}
	if _, ok := f.volumes[name]; !ok {
		return mobyclient.VolumeRemoveResult{}, containerderrdefs.ErrNotFound.WithMessage("volume not found")
	}
	delete(f.volumes, name)
	return mobyclient.VolumeRemoveResult{}, nil
}

func (f *fakeDockerCreationAPI) ContainerList(_ context.Context, _ mobyclient.ContainerListOptions) (mobyclient.ContainerListResult, error) {
	return f.listResult, f.listErr
}

func (f *fakeDockerCreationAPI) ContainerStart(_ context.Context, id string, _ mobyclient.ContainerStartOptions) (mobyclient.ContainerStartResult, error) {
	f.startedID = id
	if f.startErr == nil && f.containerResult.Container.State != nil {
		f.containerResult.Container.State.Status = mobycontainer.StateRunning
		f.containerResult.Container.State.Running = true
		if f.containerResult.Container.NetworkSettings != nil {
			for name := range f.containerResult.Container.NetworkSettings.Networks {
				if network, ok := f.networks[name]; ok {
					if network.Containers == nil {
						network.Containers = make(map[string]mobynetwork.EndpointResource)
					}
					network.Containers[id] = mobynetwork.EndpointResource{Name: strings.TrimPrefix(f.containerResult.Container.Name, "/")}
					f.networks[name] = network
				}
			}
		}
	}
	return mobyclient.ContainerStartResult{}, f.startErr
}

func (f *fakeDockerCreationAPI) ContainerStop(_ context.Context, id string, options mobyclient.ContainerStopOptions) (mobyclient.ContainerStopResult, error) {
	f.stoppedID = id
	f.stopOpts = options
	if f.stopErr == nil && f.containerResult.Container.State != nil {
		f.containerResult.Container.State.Status = mobycontainer.StateExited
		f.containerResult.Container.State.Running = false
		for name, network := range f.networks {
			delete(network.Containers, id)
			f.networks[name] = network
		}
	}
	return mobyclient.ContainerStopResult{}, f.stopErr
}

func (f *fakeDockerCreationAPI) ContainerStatPath(_ context.Context, _ string, options mobyclient.ContainerStatPathOptions) (mobyclient.ContainerStatPathResult, error) {
	if err := f.pathStatErrs[options.Path]; err != nil {
		return mobyclient.ContainerStatPathResult{}, err
	}
	if stat, ok := f.pathStats[options.Path]; ok {
		return mobyclient.ContainerStatPathResult{Stat: stat}, nil
	}
	return mobyclient.ContainerStatPathResult{Stat: mobycontainer.PathStat{Name: options.Path, Mode: 0o755}}, nil
}

func (f *fakeDockerCreationAPI) ExecCreate(_ context.Context, containerID string, options mobyclient.ExecCreateOptions) (mobyclient.ExecCreateResult, error) {
	f.execContainerID = containerID
	f.execCreateOpts = options
	if f.execID == "" {
		f.execID = "exec-1"
	}
	return mobyclient.ExecCreateResult{ID: f.execID}, nil
}

func (f *fakeDockerCreationAPI) ExecAttach(_ context.Context, _ string, options mobyclient.ExecAttachOptions) (mobyclient.ExecAttachResult, error) {
	f.execAttachOpts = options
	clientConn, serverConn := net.Pipe()
	go func() {
		if f.execCreateOpts.AttachStdin {
			f.execStdin = make([]byte, f.execStdinBytes)
			_, _ = io.ReadFull(serverConn, f.execStdin)
		}
		if options.TTY {
			_, _ = serverConn.Write([]byte(f.execStdout + f.execStderr))
		} else {
			writeFakeExecFrame(serverConn, mobystdcopy.Stdout, []byte(f.execStdout))
			writeFakeExecFrame(serverConn, mobystdcopy.Stderr, []byte(f.execStderr))
		}
		_ = serverConn.Close()
	}()
	return mobyclient.ExecAttachResult{HijackedResponse: mobyclient.NewHijackedResponse(clientConn, "application/vnd.docker.multiplexed-stream")}, nil
}

func writeFakeExecFrame(conn net.Conn, stream mobystdcopy.StdType, payload []byte) {
	if len(payload) == 0 {
		return
	}
	header := make([]byte, 8)
	header[0] = byte(stream)
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	_, _ = conn.Write(header)
	_, _ = conn.Write(payload)
}

func (f *fakeDockerCreationAPI) ExecInspect(_ context.Context, execID string, _ mobyclient.ExecInspectOptions) (mobyclient.ExecInspectResult, error) {
	return mobyclient.ExecInspectResult{ID: execID, ContainerID: f.execContainerID, ExitCode: f.execExitCode, Running: f.execRunning}, nil
}

func TestDockerManagerCreateUsesSystemNameAndOwnerLabels(t *testing.T) {
	spec := creationSpec()
	ownerID := "instance-01"
	pinned, err := pinnedImageReference(spec.Image)
	if err != nil {
		t.Fatal(err)
	}
	providerID := "provider-container-1"
	api := newSuccessfulCreationAPI(spec, ownerID, providerID, pinned)
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	runtime, err := manager.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if runtime.ID != spec.ID || runtime.ProviderID != providerID || runtime.Status != StatusStopped || runtime.Image.ResolvedDigest != spec.Image.Digest {
		t.Fatalf("runtime = %#v", runtime)
	}
	if api.createOpts.Name != "cyberstrike-agent-"+string(spec.ID) {
		t.Fatalf("container name = %q", api.createOpts.Name)
	}
	if api.createOpts.Image != pinned || api.createOpts.Config.Image != "" {
		t.Fatalf("image options = %q / %q", api.createOpts.Image, api.createOpts.Config.Image)
	}
	if !api.createOpts.Config.NetworkDisabled || api.createOpts.HostConfig.NetworkMode != mobycontainer.NetworkMode(NetworkNone) {
		t.Fatalf("network was not disabled: %#v / %#v", api.createOpts.Config, api.createOpts.HostConfig)
	}
	if !matchesRuntimeKeepalive(api.createOpts.Config) {
		t.Fatalf("fixed keepalive process was not configured: %#v", api.createOpts.Config)
	}
	if !api.createOpts.HostConfig.ReadonlyRootfs || api.createOpts.HostConfig.Privileged || len(api.createOpts.HostConfig.CapDrop) != 1 || api.createOpts.HostConfig.CapDrop[0] != "ALL" || len(api.createOpts.HostConfig.CapAdd) != 0 {
		t.Fatalf("privilege baseline = %#v", api.createOpts.HostConfig)
	}
	if !containsString(api.createOpts.HostConfig.SecurityOpt, "no-new-privileges") || api.createOpts.HostConfig.NanoCPUs != spec.Resources.NanoCPUs || api.createOpts.HostConfig.Memory != spec.Resources.MemoryBytes || api.createOpts.HostConfig.MemorySwap != spec.Resources.MemoryBytes {
		t.Fatalf("resource/security options = %#v", api.createOpts.HostConfig)
	}
	if api.createOpts.HostConfig.PidsLimit == nil || *api.createOpts.HostConfig.PidsLimit != spec.Resources.PIDs || len(api.createOpts.HostConfig.Ulimits) != 1 || api.createOpts.HostConfig.Ulimits[0].Name != "nofile" {
		t.Fatalf("pid/nofile options = %#v", api.createOpts.HostConfig.Resources)
	}
	if api.createOpts.HostConfig.Tmpfs["/tmp"] != "rw,nosuid,nodev,mode=1777,noexec,size=67108864" || api.createOpts.HostConfig.Tmpfs["/workspace"] != "rw,nosuid,nodev,mode=1777,size=1073741824" {
		t.Fatalf("tmpfs options = %#v", api.createOpts.HostConfig.Tmpfs)
	}
	if api.createOpts.HostConfig.LogConfig.Type != "local" || api.createOpts.HostConfig.LogConfig.Config["max-size"] != "10485760" || api.createOpts.HostConfig.LogConfig.Config["max-file"] != "3" || api.createOpts.HostConfig.LogConfig.Config["compress"] != "true" {
		t.Fatalf("log rotation options = %#v", api.createOpts.HostConfig.LogConfig)
	}
	labels := api.createOpts.Config.Labels
	if labels[LabelManaged] != "true" || labels[LabelOwner] != ownerID || labels[LabelRuntimeID] != string(spec.ID) || labels[LabelConversationID] != spec.ConversationID || labels[LabelImageDigest] != spec.Image.Digest {
		t.Fatalf("labels = %#v", labels)
	}
	if len(api.createOpts.HostConfig.Binds) != 0 || len(api.createOpts.HostConfig.Mounts) != 0 {
		t.Fatalf("unexpected host mounts: %#v / %#v", api.createOpts.HostConfig.Binds, api.createOpts.HostConfig.Mounts)
	}
	if api.removedID != "" {
		t.Fatalf("successful runtime was rolled back: %s", api.removedID)
	}
}

func TestDockerManagerCreateUsesOwnedInternalConversationNetwork(t *testing.T) {
	spec := creationSpec()
	spec.Security.NetworkMode = NetworkInternal
	ownerID := "instance-01"
	api := newSuccessfulCreationAPI(spec, ownerID, "provider-container-1", "")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := manager.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("create internal runtime: %v", err)
	}
	if runtime.Status != StatusStopped || api.networkCreateCalls != 1 || api.networkCreateName != ConversationNetworkName(spec.ID) {
		t.Fatalf("runtime/network create = %#v / %d / %q", runtime, api.networkCreateCalls, api.networkCreateName)
	}
	options := api.networkCreateOpts
	if options.Driver != "bridge" || options.Scope != "local" || !options.Internal || options.Attachable || options.Ingress || options.EnableIPv4 == nil || !*options.EnableIPv4 || options.EnableIPv6 == nil || *options.EnableIPv6 {
		t.Fatalf("network isolation options = %#v", options)
	}
	if options.Labels[LabelOwner] != ownerID || options.Labels[LabelResourceKind] != ResourceKindConversationNetwork || options.Labels[LabelRuntimeID] != string(spec.ID) || options.Labels[LabelConversationID] != spec.ConversationID || options.Labels[LabelNetworkMode] != string(NetworkInternal) || options.Labels[LabelSpecDigest] != RuntimeSpecDigest(spec) {
		t.Fatalf("network labels = %#v", options.Labels)
	}
	name := ConversationNetworkName(spec.ID)
	if api.createOpts.Config.NetworkDisabled || api.createOpts.HostConfig.NetworkMode != mobycontainer.NetworkMode(name) {
		t.Fatalf("container network mode = %#v / %q", api.createOpts.Config, api.createOpts.HostConfig.NetworkMode)
	}
	endpoint := api.createOpts.NetworkingConfig.EndpointsConfig[name]
	if endpoint == nil || endpoint.NetworkID != "provider-network-1" || len(api.createOpts.NetworkingConfig.EndpointsConfig) != 1 {
		t.Fatalf("container network endpoint = %#v", api.createOpts.NetworkingConfig)
	}
	network := api.networks[name]
	if len(network.Containers) != 0 {
		t.Fatalf("created-but-not-started network attachments = %#v", network.Containers)
	}
}

func TestDockerManagerCreateRejectsUnsafeExistingConversationNetwork(t *testing.T) {
	spec := creationSpec()
	spec.Security.NetworkMode = NetworkInternal
	ownerID := "instance-01"
	api := newSuccessfulCreationAPI(spec, ownerID, "provider-container-1", "")
	name := ConversationNetworkName(spec.ID)
	api.networks = map[string]mobynetwork.Inspect{name: {Network: mobynetwork.Network{
		ID: "provider-network-1", Name: name, Created: time.Now().UTC(), Scope: "local", Driver: "bridge",
		EnableIPv4: true, Internal: false, Labels: conversationNetworkLabels(ownerID, spec),
	}}}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("unsafe existing network error = %v", err)
	}
	if api.createOpts.Name != "" || api.networkCreateCalls != 0 {
		t.Fatal("container or replacement network was created after unsafe network inspection")
	}
}

func TestDockerManagerCreateReusesEmptyOwnedConversationNetwork(t *testing.T) {
	spec := creationSpec()
	spec.Security.NetworkMode = NetworkInternal
	ownerID := "instance-01"
	api := newSuccessfulCreationAPI(spec, ownerID, "provider-container-1", "")
	name := ConversationNetworkName(spec.ID)
	api.networks = map[string]mobynetwork.Inspect{name: {Network: mobynetwork.Network{
		ID: "provider-network-1", Name: name, Created: time.Now().UTC(), Scope: "local", Driver: "bridge",
		EnableIPv4: true, Internal: true, Labels: conversationNetworkLabels(ownerID, spec),
	}}}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatalf("reuse owned network: %v", err)
	}
	if api.networkCreateCalls != 0 || len(api.networks[name].Containers) != 0 {
		t.Fatalf("network reuse = create calls %d, attachments %#v", api.networkCreateCalls, api.networks[name].Containers)
	}
}

func TestDockerManagerCreateRollsBackNewConversationNetwork(t *testing.T) {
	spec := creationSpec()
	spec.Security.NetworkMode = NetworkInternal
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.createErr = errors.New("engine create failed")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err == nil {
		t.Fatal("create unexpectedly succeeded")
	}
	if api.networkRemoved != "provider-network-1" || len(api.networks) != 0 {
		t.Fatalf("rolled back network = %q / %#v", api.networkRemoved, api.networks)
	}
}

func TestDockerManagerCreateUsesOwnedConversationVolume(t *testing.T) {
	spec := creationSpec()
	spec.Workspace.Persistent = true
	spec.Workspace.VolumeName = WorkspaceVolumeName(spec.ID)
	ownerID := "instance-01"
	api := newSuccessfulCreationAPI(spec, ownerID, "provider-container-1", "")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatalf("create persistent runtime: %v", err)
	}
	if api.volumeCreateCalls != 1 || api.volumeCreateOpts.Name != spec.Workspace.VolumeName || api.volumeCreateOpts.Driver != "local" {
		t.Fatalf("volume create = %d / %#v", api.volumeCreateCalls, api.volumeCreateOpts)
	}
	if api.volumeCreateOpts.Labels[LabelOwner] != ownerID || api.volumeCreateOpts.Labels[LabelResourceKind] != ResourceKindWorkspaceVolume || api.volumeCreateOpts.Labels[LabelConversationID] != spec.ConversationID {
		t.Fatalf("volume labels = %#v", api.volumeCreateOpts.Labels)
	}
	if _, ok := api.createOpts.HostConfig.Tmpfs[spec.Workspace.MountPath]; ok {
		t.Fatal("persistent workspace was also configured as tmpfs")
	}
	if len(api.createOpts.HostConfig.Mounts) != 1 || api.createOpts.HostConfig.Mounts[0].Source != spec.Workspace.VolumeName || api.createOpts.HostConfig.Mounts[0].Target != "/workspace" {
		t.Fatalf("workspace mount = %#v", api.createOpts.HostConfig.Mounts)
	}
}

func TestDockerManagerCreateRejectsForeignWorkspaceVolume(t *testing.T) {
	spec := creationSpec()
	spec.Workspace.Persistent = true
	spec.Workspace.VolumeName = WorkspaceVolumeName(spec.ID)
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.volumes = map[string]mobyvolume.Volume{
		spec.Workspace.VolumeName: {Name: spec.Workspace.VolumeName, Driver: "local", Labels: workspaceVolumeLabels("other-owner", spec)},
	}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("foreign volume error = %v", err)
	}
	if api.createOpts.Name != "" || api.volumeCreateCalls != 0 {
		t.Fatal("container or volume mutation reached foreign workspace volume")
	}
}

func TestDockerManagerCreateReusesLegacyPersistentWorkspaceDuringNetworkMigration(t *testing.T) {
	spec := creationSpec()
	spec.Workspace.Persistent = true
	spec.Workspace.VolumeName = WorkspaceVolumeName(spec.ID)
	legacy := spec
	legacy.Security.NetworkMode = NetworkNone
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.volumes = map[string]mobyvolume.Volume{
		spec.Workspace.VolumeName: {
			Name: spec.Workspace.VolumeName, Driver: "local",
			Labels: workspaceVolumeLabels("instance-01", legacy),
		},
	}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatalf("reuse legacy workspace: %v", err)
	}
	if api.volumeCreateCalls != 0 {
		t.Fatalf("legacy workspace was recreated: %d", api.volumeCreateCalls)
	}
}

func TestDockerManagerCreateRejectsLegacyWorkspaceWithOtherSpecDrift(t *testing.T) {
	spec := creationSpec()
	spec.Workspace.Persistent = true
	spec.Workspace.VolumeName = WorkspaceVolumeName(spec.ID)
	drifted := spec
	drifted.Security.NetworkMode = NetworkNone
	drifted.Resources.MemoryBytes++
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.volumes = map[string]mobyvolume.Volume{
		spec.Workspace.VolumeName: {
			Name: spec.Workspace.VolumeName, Driver: "local",
			Labels: workspaceVolumeLabels("instance-01", drifted),
		},
	}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("drifted legacy workspace error = %v", err)
	}
	if api.createOpts.Name != "" {
		t.Fatal("container creation reached drifted legacy workspace")
	}
}

func TestDockerManagerCreateRollsBackNewWorkspaceVolumeOnFailure(t *testing.T) {
	spec := creationSpec()
	spec.Workspace.Persistent = true
	spec.Workspace.VolumeName = WorkspaceVolumeName(spec.ID)
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.createErr = errors.New("engine create failed")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err == nil {
		t.Fatal("create unexpectedly succeeded")
	}
	if api.volumeRemoved != spec.Workspace.VolumeName {
		t.Fatalf("rolled back volume = %q", api.volumeRemoved)
	}
}

func TestDockerManagerCreateRejectsMissingEngineSecurityFeature(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.infoResult.Info.PidsLimit = false
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Create(context.Background(), spec)
	if !errors.Is(err, ErrEngineIncompatible) {
		t.Fatalf("engine baseline error = %v", err)
	}
	if api.createOpts.Name != "" {
		t.Fatal("container create was called for an incompatible engine")
	}
}

func TestDockerManagerCreateRejectsEngineArchitecture(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.infoResult.Info.Architecture = "amd64"
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Create(context.Background(), spec)
	if !errors.Is(err, ErrArchitectureMismatch) {
		t.Fatalf("architecture error = %v", err)
	}
	if api.createOpts.Name != "" {
		t.Fatal("container create was called after architecture mismatch")
	}
}

func TestDockerManagerCreateRollsBackFailedVerification(t *testing.T) {
	spec := creationSpec()
	ownerID := "instance-01"
	pinned, err := pinnedImageReference(spec.Image)
	if err != nil {
		t.Fatal(err)
	}
	providerID := "provider-container-1"
	api := newSuccessfulCreationAPI(spec, ownerID, providerID, pinned)
	api.containerResult.Container.Config.Labels[LabelOwner] = "other-owner"
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Create(context.Background(), spec)
	if !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("verification error = %v", err)
	}
	if api.removedID != providerID || !api.removeOpts.Force || api.removeOpts.RemoveVolumes {
		t.Fatalf("rollback = id %q, options %#v", api.removedID, api.removeOpts)
	}
}

func TestDockerManagerCreateRollsBackSecurityMismatch(t *testing.T) {
	spec := creationSpec()
	ownerID := "instance-01"
	providerID := "provider-container-1"
	api := newSuccessfulCreationAPI(spec, ownerID, providerID, "")
	api.containerResult.Container.HostConfig.ReadonlyRootfs = false
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Create(context.Background(), spec)
	if !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("security verification error = %v", err)
	}
	if api.removedID != providerID {
		t.Fatalf("unsafe runtime was not rolled back: %q", api.removedID)
	}
}

func TestDockerManagerCreateMapsNameConflict(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.createErr = containerderrdefs.ErrConflict.WithMessage("name already in use")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Create(context.Background(), spec)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("conflict error = %v", err)
	}
}

func TestDockerManagerRequiresOwnerID(t *testing.T) {
	_, err := newDockerManager(&fakeDockerCreationAPI{fakeDockerInspectionAPI: &fakeDockerInspectionAPI{}}, DockerManagerOptions{})
	if !errors.Is(err, ErrInvalidSpecification) {
		t.Fatalf("owner error = %v", err)
	}
}

func TestDockerManagerCreateAppliesOperationTimeout(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.blockPing = true
	manager, err := newDockerManager(api, DockerManagerOptions{
		OwnerID:          "instance-01",
		OperationTimeout: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = manager.Create(context.Background(), spec)
	if !errors.Is(err, ErrEngineUnavailable) {
		t.Fatalf("timeout error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("operation timeout was not applied: %v", elapsed)
	}
}

func newSuccessfulCreationAPI(spec RuntimeSpec, ownerID, providerID, pinned string) *fakeDockerCreationAPI {
	if pinned == "" {
		pinned, _ = pinnedImageReference(spec.Image)
	}
	imageID := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	created := time.Date(2026, 8, 20, 12, 45, 0, 0, time.UTC)
	networkSettings := (*mobycontainer.NetworkSettings)(nil)
	if spec.Security.NetworkMode == NetworkInternal {
		networkSettings = &mobycontainer.NetworkSettings{Networks: map[string]*mobynetwork.EndpointSettings{
			ConversationNetworkName(spec.ID): {NetworkID: "provider-network-1"},
		}}
	}
	inspection := &fakeDockerInspectionAPI{
		pingResult: mobyclient.PingResult{APIVersion: "1.52", OSType: "linux"},
		infoResult: mobyclient.SystemInfoResult{Info: system.Info{
			ServerVersion:   "29.1.3",
			Architecture:    "arm64",
			OSType:          "linux",
			MemoryLimit:     true,
			CPUCfsQuota:     true,
			PidsLimit:       true,
			SecurityOptions: []string{"name=seccomp,profile=builtin"},
		}},
		imageResult: mobyclient.ImageInspectResult{InspectResponse: mobyimage.InspectResponse{
			ID:           imageID,
			RepoDigests:  []string{"sandbox@" + spec.Image.Digest},
			Architecture: "arm64",
			Os:           "linux",
			Size:         64 << 20,
		}},
		containerResult: mobyclient.ContainerInspectResult{Container: mobycontainer.InspectResponse{
			ID:      providerID,
			Created: created.Format(time.RFC3339Nano),
			Name:    "/" + runtimeContainerName(spec.ID),
			Image:   imageID,
			State:   &mobycontainer.State{Status: mobycontainer.StateCreated},
			Config: &mobycontainer.Config{
				Image:           pinned,
				NetworkDisabled: spec.Security.NetworkMode == NetworkNone,
				WorkingDir:      spec.Workspace.MountPath,
				Entrypoint:      append([]string(nil), runtimeKeepaliveEntrypoint...),
				Cmd:             []string{runtimeKeepaliveScript},
				Labels:          runtimeLabels(ownerID, spec),
			},
			HostConfig:      runtimeHostConfig(spec),
			NetworkSettings: networkSettings,
		}},
	}
	return &fakeDockerCreationAPI{
		fakeDockerInspectionAPI: inspection,
		createResult:            mobyclient.ContainerCreateResult{ID: providerID, Warnings: []string{"test warning"}},
	}
}

func creationSpec() RuntimeSpec {
	return RuntimeSpec{
		ID:             "runtime-01",
		ConversationID: "conversation-01",
		Image: ImageReference{
			Repository: "ghcr.io/example/sandbox",
			Digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Platform:   "linux/arm64",
		},
		Resources: ResourceLimits{
			NanoCPUs:          1_000_000_000,
			MemoryBytes:       512 << 20,
			PIDs:              128,
			NoFileSoft:        1024,
			NoFileHard:        2048,
			WorkspaceBytes:    1 << 30,
			MaxConcurrentExec: 2,
			MaxQueuedExec:     8,
			LogMaxBytes:       10 << 20,
			LogMaxFiles:       3,
		},
		Security: SecurityProfile{
			ReadOnlyRootFS:      true,
			NoNewPrivileges:     true,
			DropAllCapabilities: true,
			NetworkMode:         NetworkNone,
			SeccompProfile:      "default",
			TmpfsBytes:          64 << 20,
		},
		Workspace: WorkspaceSpec{
			MountPath: "/workspace",
		},
	}
}
