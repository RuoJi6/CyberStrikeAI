package container

import (
	"context"
	"errors"
	"strings"
	"testing"

	mobycontainer "github.com/moby/moby/api/types/container"
	mobynetwork "github.com/moby/moby/api/types/network"
)

func TestDockerManagerExecUsesOwnedRunningRuntime(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.State.Status = mobycontainer.StateRunning
	api.containerResult.Container.State.Running = true
	api.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{Networks: map[string]*mobynetwork.EndpointSettings{"none": {}}}
	api.execStdout = "stdout\n"
	api.execStderr = "stderr\n"
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr strings.Builder
	result, err := manager.Exec(context.Background(), spec, ExecRequest{
		Command:    []string{"/bin/sh", "-c", "printf ok"},
		WorkingDir: "/workspace/subdir",
		Env:        []string{"HOME=/workspace"},
	}, func(stream ExecStream, chunk []byte) error {
		switch stream {
		case ExecStreamStdout:
			stdout.Write(chunk)
		case ExecStreamStderr:
			stderr.Write(chunk)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if result.ExecID != "exec-1" || result.ExitCode != 0 || stdout.String() != api.execStdout || stderr.String() != api.execStderr {
		t.Fatalf("result=%#v stdout=%q stderr=%q", result, stdout.String(), stderr.String())
	}
	if api.execContainerID != "provider-container-1" || api.execCreateOpts.Privileged || api.execCreateOpts.TTY || api.execCreateOpts.AttachStdin || !api.execCreateOpts.AttachStdout || !api.execCreateOpts.AttachStderr {
		t.Fatalf("unsafe exec target/options: %q %#v", api.execContainerID, api.execCreateOpts)
	}
	if got := strings.Join(api.execCreateOpts.Cmd, "\x00"); got != "/bin/sh\x00-c\x00printf ok" || api.execCreateOpts.WorkingDir != "/workspace/subdir" {
		t.Fatalf("exec command/workdir = %q / %q", got, api.execCreateOpts.WorkingDir)
	}
}

func TestDockerManagerExecFailsClosedBeforeEngineMutation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*fakeDockerCreationAPI, *RuntimeSpec)
		request ExecRequest
	}{
		{
			name: "stopped runtime",
			mutate: func(api *fakeDockerCreationAPI, _ *RuntimeSpec) {
				api.containerResult.Container.State.Status = mobycontainer.StateExited
				api.containerResult.Container.State.Running = false
			},
			request: ExecRequest{Command: []string{"true"}},
		},
		{
			name: "immutable spec drift",
			mutate: func(api *fakeDockerCreationAPI, _ *RuntimeSpec) {
				api.containerResult.Container.Config.Labels[LabelSpecDigest] = "sha256:changed"
			},
			request: ExecRequest{Command: []string{"true"}},
		},
		{
			name:    "host working directory",
			mutate:  func(_ *fakeDockerCreationAPI, _ *RuntimeSpec) {},
			request: ExecRequest{Command: []string{"true"}, WorkingDir: "/etc"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := creationSpec()
			api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
			api.containerResult.Container.State.Status = mobycontainer.StateRunning
			api.containerResult.Container.State.Running = true
			api.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{Networks: map[string]*mobynetwork.EndpointSettings{"none": {}}}
			tt.mutate(api, &spec)
			manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = manager.Exec(context.Background(), spec, tt.request, nil)
			if err == nil || (!errors.Is(err, ErrRuntimeStateConflict) && !errors.Is(err, ErrInvalidSpecification)) {
				t.Fatalf("expected fail-closed validation error, got %v", err)
			}
			if api.execContainerID != "" {
				t.Fatalf("engine exec was reached: %q", api.execContainerID)
			}
		})
	}
}
