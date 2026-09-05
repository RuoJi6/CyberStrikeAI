package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/egress"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobynetwork "github.com/moby/moby/api/types/network"
	mobyclient "github.com/moby/moby/client"
)

func TestDockerManagerExecAppendsBoundedRawBoundaryDenial(t *testing.T) {
	spec, root, snapshotPath := snapshotGatewayFixture(t)
	base := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	api := &fakeActivityDockerAPI{fakeDockerCreationAPI: base}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01", EgressSnapshotRoot: root, OperationTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(context.Background(), spec.ID); err != nil {
		t.Fatal(err)
	}
	base.execExitCode = 1
	event := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: time.Now().UTC().Add(500 * time.Millisecond), RequestType: egress.ActivityRequestTCP,
		Domain: "203.0.113.10", ConnectedIP: "203.0.113.10", Port: 22,
		Decision: egress.ActivityDecisionBlocked, Reason: "default_deny", Outcome: "policy_denied",
		SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var multiplexed bytes.Buffer
	writeActivityLogFrame(&multiplexed, append(encoded, '\n'))
	api.logs = multiplexed.Bytes()

	var stderr strings.Builder
	result, err := manager.Exec(context.Background(), spec, ExecRequest{Command: []string{"nc", "-vz", "203.0.113.10", "22"}}, func(stream ExecStream, chunk []byte) error {
		if stream == ExecStreamStderr {
			stderr.Write(chunk)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 1 || !strings.Contains(stderr.String(), "本次工具执行触发 1 次网络阻断") || !strings.Contains(stderr.String(), "请求：tcp://203.0.113.10:22（1 次）") || !strings.Contains(stderr.String(), "default_deny") {
		t.Fatalf("result/feedback = %#v / %q", result, stderr.String())
	}
	if api.logsContainerID != "provider-gateway-1" || api.logsOptions.Follow || api.logsOptions.Tail != "all" || api.logsOptions.Since == "" || api.logsOptions.Until == "" {
		t.Fatalf("bounded feedback log request = %q %#v", api.logsContainerID, api.logsOptions)
	}
}

func TestDockerManagerExecAppendsAggregatedBoundaryDenialAfterSuccessfulTool(t *testing.T) {
	spec, root, snapshotPath := snapshotGatewayFixture(t)
	base := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	api := &fakeActivityDockerAPI{fakeDockerCreationAPI: base}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01", EgressSnapshotRoot: root, OperationTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(context.Background(), spec.ID); err != nil {
		t.Fatal(err)
	}
	base.execExitCode = 0
	eventTime := time.Now().UTC().Add(500 * time.Millisecond)
	events := []egress.ActivityEvent{
		{
			Event: egress.ActivityEventName, Timestamp: eventTime, RequestType: egress.ActivityRequestTCP,
			Domain: "47.116.200.74", ConnectedIP: "47.116.200.74", Port: 22,
			Decision: egress.ActivityDecisionBlocked, RuleID: "block-ssh", Reason: "blocked-target", Outcome: "policy_denied",
			SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
		},
		{
			Event: egress.ActivityEventName, Timestamp: eventTime, RequestType: egress.ActivityRequestTCP,
			Domain: "47.116.200.74", ConnectedIP: "47.116.200.74", Port: 22,
			Decision: egress.ActivityDecisionBlocked, RuleID: "block-ssh", Reason: "blocked-target", Outcome: "policy_denied",
			SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
		},
		{
			Event: egress.ActivityEventName, Timestamp: eventTime, RequestType: egress.ActivityRequestUDP,
			Domain: "time.example", ConnectedIP: "203.0.113.123", Port: 123,
			Decision: egress.ActivityDecisionBlocked, Reason: "default-deny", Outcome: "policy_denied",
			SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
		},
		{
			Event: egress.ActivityEventName, Timestamp: eventTime, RequestType: egress.ActivityRequestDNS,
			Domain: "blocked.example", DNSQueryType: "a",
			Decision: egress.ActivityDecisionBlocked, RuleID: "block-dns", Reason: "blocked-target", Outcome: "policy_denied",
			SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
		},
		{
			Event: egress.ActivityEventName, Timestamp: eventTime, RequestType: egress.ActivityRequestHealth,
			Domain: "upstream.example", Decision: egress.ActivityDecisionBlocked, RuleID: "upstream-guard",
			Reason: "upstream_rate_limited", Outcome: "cooldown_started", RetryAfterMS: 30000,
			SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
		},
	}
	var multiplexed bytes.Buffer
	for _, event := range events {
		encoded, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		writeActivityLogFrame(&multiplexed, append(encoded, '\n'))
	}
	api.logs = multiplexed.Bytes()

	var stderr strings.Builder
	result, err := manager.Exec(context.Background(), spec, ExecRequest{Command: []string{"future-network-tool", "--probe"}}, func(stream ExecStream, chunk []byte) error {
		if stream == ExecStreamStderr {
			stderr.Write(chunk)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	feedback := stderr.String()
	if result.ExitCode != 0 || !strings.Contains(feedback, "本次工具执行触发 4 次网络阻断") ||
		!strings.Contains(feedback, "请求：tcp://47.116.200.74:22（2 次）") ||
		!strings.Contains(feedback, "原因：目标阻断（旧版记录）（blocked-target）") ||
		!strings.Contains(feedback, "请求：udp://time.example:123（1 次）") ||
		!strings.Contains(feedback, "请求：dns://blocked.example（1 次）") ||
		strings.Contains(feedback, "HEALTH") || strings.Contains(feedback, "upstream.example") ||
		!strings.Contains(feedback, "以下请求未到达目标") ||
		!strings.Contains(feedback, "当前边界或系统网络策略已明确禁止上述访问") {
		t.Fatalf("result/feedback = %#v / %q", result, feedback)
	}
}

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
	if api.execCreateOpts.User != runtimeRootExecUser || !equalStrings(api.execCreateOpts.Env, runtimeExecEnvironment(nil)) {
		t.Fatalf("exec identity/environment = %q / %#v", api.execCreateOpts.User, api.execCreateOpts.Env)
	}
	if !wrappedExecEndsWith(api.execCreateOpts.Cmd, []string{"/bin/sh", "-c", "printf ok"}) || api.execCreateOpts.WorkingDir != "/workspace" || len(api.execCreateOpts.Cmd) < 8 || api.execCreateOpts.Cmd[6] != "/workspace/subdir" {
		t.Fatalf("exec command/workdir = %q / %q", strings.Join(api.execCreateOpts.Cmd, "\x00"), api.execCreateOpts.WorkingDir)
	}
	if len(api.execCreateOpts.Cmd) < 8 || api.execCreateOpts.Cmd[0] != "/bin/sh" || api.execCreateOpts.Cmd[1] != "-c" || api.execCreateOpts.Cmd[2] != containerExecWrapperScript || api.execCreateOpts.Cmd[3] != "cyberstrike-exec" || !strings.HasPrefix(api.execCreateOpts.Cmd[4], "/tmp/.cyberstrike-exec-") || api.execCreateOpts.Cmd[5] != "/workspace" {
		t.Fatalf("exec cancellation wrapper = %#v", api.execCreateOpts.Cmd)
	}
}

func TestContainerExecWrapperRejectsSymlinkedWorkingDirectory(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(workspace, "safe")
	if err := os.Mkdir(safe, 0o755); err != nil {
		t.Fatal(err)
	}
	pidfile := filepath.Join(t.TempDir(), "exec.pid")
	run := exec.Command("/bin/sh", "-c", containerExecWrapperScript, "cyberstrike-exec", pidfile, workspace, safe, "pwd")
	output, err := run.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != safe {
		t.Fatalf("safe working directory output/error = %q / %v", output, err)
	}

	symlink := filepath.Join(workspace, "linked")
	if err := os.Symlink(t.TempDir(), symlink); err != nil {
		t.Fatal(err)
	}
	escape := exec.Command("/bin/sh", "-c", containerExecWrapperScript, "cyberstrike-exec", pidfile, workspace, symlink, "pwd")
	if output, err := escape.CombinedOutput(); err == nil {
		t.Fatalf("symlinked working directory should fail: %q", output)
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

func TestContainerExecCancelScriptTargetsGroupsAndDescendants(t *testing.T) {
	check := exec.Command("/bin/sh", "-n")
	check.Stdin = strings.NewReader(containerExecCancelScript)
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("cancellation helper is not valid POSIX shell: %v: %s", err, output)
	}
	for _, required := range []string{
		"/proc/[0-9]*/stat",
		"discover_descendants",
		"kill -STOP -\"$group\"",
		"kill -TERM -\"$group\"",
		"kill -KILL -\"$group\"",
		"kill -KILL \"$target\"",
		"[ \"$alive\" -eq 0 ]",
	} {
		if !strings.Contains(containerExecCancelScript, required) {
			t.Fatalf("cancellation helper does not contain %q", required)
		}
	}
	if strings.Contains(containerExecCancelScript, "kill -TERM -\"$pid\"") {
		t.Fatal("cancellation helper regressed to assuming child PID equals process group")
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
