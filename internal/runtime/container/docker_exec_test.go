package container

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	mobycontainer "github.com/moby/moby/api/types/container"
	mobynetwork "github.com/moby/moby/api/types/network"
	mobyclient "github.com/moby/moby/client"
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
	if !wrappedExecEndsWith(api.execCreateOpts.Cmd, []string{"/bin/sh", "-c", "printf ok"}) || api.execCreateOpts.WorkingDir != "/workspace/subdir" {
		t.Fatalf("exec command/workdir = %q / %q", strings.Join(api.execCreateOpts.Cmd, "\x00"), api.execCreateOpts.WorkingDir)
	}
	if len(api.execCreateOpts.Cmd) < 6 || api.execCreateOpts.Cmd[0] != "/bin/sh" || api.execCreateOpts.Cmd[1] != "-c" || api.execCreateOpts.Cmd[2] != containerExecWrapperScript || api.execCreateOpts.Cmd[3] != "cyberstrike-exec" || !strings.HasPrefix(api.execCreateOpts.Cmd[4], "/tmp/.cyberstrike-exec-") {
		t.Fatalf("exec cancellation wrapper = %#v", api.execCreateOpts.Cmd)
	}
}

func TestDockerManagerExecTTYUsesRawSingleStream(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.State.Status = mobycontainer.StateRunning
	api.containerResult.Container.State.Running = true
	api.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{Networks: map[string]*mobynetwork.EndpointSettings{"none": {}}}
	api.execStdout = "tty-out\n"
	api.execStderr = "tty-err\n"
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr strings.Builder
	_, err = manager.Exec(context.Background(), spec, ExecRequest{Command: []string{"tty-check"}, TTY: true}, func(stream ExecStream, chunk []byte) error {
		if stream == ExecStreamStderr {
			stderr.Write(chunk)
		} else {
			stdout.Write(chunk)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !api.execCreateOpts.TTY || stdout.String() != "tty-out\ntty-err\n" || stderr.Len() != 0 {
		t.Fatalf("tty opts/output = %v / %q / %q", api.execCreateOpts.TTY, stdout.String(), stderr.String())
	}
}

type cancelDockerExecAPI struct {
	*fakeDockerCreationAPI
	mu           sync.Mutex
	createOpts   []mobyclient.ExecCreateOptions
	mainAttached chan struct{}
	mainPeer     net.Conn
}

func (f *cancelDockerExecAPI) ExecCreate(_ context.Context, containerID string, options mobyclient.ExecCreateOptions) (mobyclient.ExecCreateResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execContainerID = containerID
	f.createOpts = append(f.createOpts, options)
	if len(f.createOpts) == 1 {
		return mobyclient.ExecCreateResult{ID: "exec-main"}, nil
	}
	return mobyclient.ExecCreateResult{ID: "exec-cancel"}, nil
}

func (f *cancelDockerExecAPI) ExecAttach(_ context.Context, execID string, _ mobyclient.ExecAttachOptions) (mobyclient.ExecAttachResult, error) {
	clientConn, serverConn := net.Pipe()
	if execID == "exec-main" {
		f.mu.Lock()
		f.mainPeer = serverConn
		f.mu.Unlock()
		close(f.mainAttached)
	} else {
		f.mu.Lock()
		if f.mainPeer != nil {
			_ = f.mainPeer.Close()
			f.mainPeer = nil
		}
		f.mu.Unlock()
		_ = serverConn.Close()
	}
	return mobyclient.ExecAttachResult{HijackedResponse: mobyclient.NewHijackedResponse(clientConn, "application/vnd.docker.multiplexed-stream")}, nil
}

func (f *cancelDockerExecAPI) ExecInspect(_ context.Context, execID string, _ mobyclient.ExecInspectOptions) (mobyclient.ExecInspectResult, error) {
	return mobyclient.ExecInspectResult{ID: execID, ContainerID: f.execContainerID, ExitCode: 0, Running: false}, nil
}

func TestDockerManagerExecCancellationRunsOwnedTerminationHelper(t *testing.T) {
	spec := creationSpec()
	base := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	base.containerResult.Container.State.Status = mobycontainer.StateRunning
	base.containerResult.Container.State.Running = true
	base.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{Networks: map[string]*mobynetwork.EndpointSettings{"none": {}}}
	api := &cancelDockerExecAPI{fakeDockerCreationAPI: base, mainAttached: make(chan struct{})}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01", OperationTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, runErr := manager.Exec(ctx, spec, ExecRequest{Command: []string{"/bin/sh", "-c", "sleep 30"}}, nil)
		done <- runErr
	}()
	select {
	case <-api.mainAttached:
	case <-time.After(2 * time.Second):
		t.Fatal("main exec was not attached")
	}
	cancel()
	select {
	case runErr := <-done:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("cancel error = %v", runErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled exec did not return")
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.createOpts) != 2 || !wrappedExecEndsWith(api.createOpts[0].Cmd, []string{"/bin/sh", "-c", "sleep 30"}) || len(api.createOpts[1].Cmd) < 5 || api.createOpts[1].Cmd[2] != containerExecCancelScript || api.createOpts[1].Cmd[4] != api.createOpts[0].Cmd[4] {
		t.Fatalf("main/cancel exec options = %#v", api.createOpts)
	}
}

func TestJoinExecTerminationPreservesPrimaryAndTerminationErrors(t *testing.T) {
	primary := context.Canceled
	termination := errors.New("kill helper failed")
	joined := joinExecTermination(primary, termination)
	if !errors.Is(joined, primary) || !errors.Is(joined, termination) {
		t.Fatalf("joined error = %v", joined)
	}
	var terminationErr *ExecTerminationError
	if !errors.As(joined, &terminationErr) || terminationErr.Err != termination {
		t.Fatalf("termination error = %#v", terminationErr)
	}
	if got := joinExecTermination(primary, nil); got != primary {
		t.Fatalf("nil termination changed primary error: %v", got)
	}
}

func wrappedExecEndsWith(got, suffix []string) bool {
	if len(got) < len(suffix) {
		return false
	}
	start := len(got) - len(suffix)
	for i := range suffix {
		if got[start+i] != suffix[i] {
			return false
		}
	}
	return true
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
