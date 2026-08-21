package security

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	containerruntime "cyberstrike-ai/internal/runtime/container"
)

type executionBackendContractOutcome struct {
	result ExecutionResult
	err    error
}

func newContractContainerBackend(t *testing.T, executor containerruntime.RuntimeExecutor) ExecutionBackend {
	t.Helper()
	backend, err := NewContainerExecutionBackendWithIdentity(executor, executionBackendSpec(), "contract-container")
	if err != nil {
		t.Fatal(err)
	}
	return backend
}

func TestExecutionBackendContractSuccessAndExitFailure(t *testing.T) {
	tests := []struct {
		name        string
		hostCommand []string
		output      string
		exitCode    int
		wantError   bool
	}{
		{
			name:        "success",
			hostCommand: []string{"/bin/sh", "-c", "printf contract-success"},
			output:      "contract-success",
		},
		{
			name:        "exit_failure",
			hostCommand: []string{"/bin/sh", "-c", "printf contract-failure; exit 23"},
			output:      "contract-failure",
			exitCode:    23,
			wantError:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			containerRuntime := &fakeContainerRuntimeExecutor{
				result: containerruntime.ExecResult{ExecID: "contract-exec", ExitCode: test.exitCode},
				output: test.output,
			}
			backends := []struct {
				name    string
				backend ExecutionBackend
				command []string
			}{
				{name: "host", backend: NewHostExecutionBackend(), command: test.hostCommand},
				{name: "container", backend: newContractContainerBackend(t, containerRuntime), command: []string{"contract-command"}},
			}

			outcomes := make(map[string]executionBackendContractOutcome, len(backends))
			for _, subject := range backends {
				result, err := subject.backend.Execute(context.Background(), ExecutionRequest{Command: subject.command})
				if result.Location != subject.name {
					t.Fatalf("%s location = %q", subject.name, result.Location)
				}
				if (err != nil) != test.wantError {
					t.Fatalf("%s error = %v, wantError=%v", subject.name, err, test.wantError)
				}
				if result.Output != test.output || result.ExitCode != test.exitCode {
					t.Fatalf("%s result = %#v", subject.name, result)
				}
				if test.wantError {
					code, ok := commandExitCode(err)
					if !ok || code != test.exitCode {
						t.Fatalf("%s exit error = %T %v", subject.name, err, err)
					}
					formatted := FormatCommandFailureFromErr(err, result.Output)
					if !strings.Contains(formatted, "exit status 23") || !strings.Contains(formatted, test.output) {
						t.Fatalf("%s formatted failure = %q", subject.name, formatted)
					}
				}
				outcomes[subject.name] = executionBackendContractOutcome{result: result, err: err}
			}

			host := outcomes["host"].result
			container := outcomes["container"].result
			if host.Output != container.Output || host.ExitCode != container.ExitCode {
				t.Fatalf("normalized results differ: host=%#v container=%#v", host, container)
			}
		})
	}
}

type cancelContractContainerRuntime struct{}

func (cancelContractContainerRuntime) Exec(ctx context.Context, _ containerruntime.RuntimeSpec, _ containerruntime.ExecRequest, sink containerruntime.ExecOutputSink) (containerruntime.ExecResult, error) {
	if sink != nil {
		if err := sink(containerruntime.ExecStreamStdout, []byte("contract-started")); err != nil {
			return containerruntime.ExecResult{ExecID: "contract-cancel", ExitCode: -1}, err
		}
	}
	<-ctx.Done()
	return containerruntime.ExecResult{ExecID: "contract-cancel", ExitCode: -1}, ctx.Err()
}

func TestExecutionBackendContractCancellation(t *testing.T) {
	backends := []struct {
		name    string
		backend ExecutionBackend
		command []string
	}{
		{name: "host", backend: NewHostExecutionBackend(), command: []string{"/bin/sh", "-c", "printf contract-started; sleep 30"}},
		{name: "container", backend: newContractContainerBackend(t, cancelContractContainerRuntime{}), command: []string{"contract-cancel"}},
	}

	for _, subject := range backends {
		t.Run(subject.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			started := make(chan struct{})
			var startedOnce sync.Once
			var streamed strings.Builder
			completed := make(chan executionBackendContractOutcome, 1)
			go func() {
				result, err := subject.backend.Execute(ctx, ExecutionRequest{
					Command: subject.command,
					Output: func(chunk string) {
						streamed.WriteString(chunk)
						if strings.Contains(streamed.String(), "contract-started") {
							startedOnce.Do(func() { close(started) })
						}
					},
					NoOutputTimeoutSec: -1,
				})
				completed <- executionBackendContractOutcome{result: result, err: err}
			}()

			select {
			case <-started:
				cancel()
			case <-time.After(3 * time.Second):
				cancel()
				t.Fatal("backend did not stream its startup output")
			}

			select {
			case outcome := <-completed:
				if !errors.Is(outcome.err, context.Canceled) {
					t.Fatalf("cancel error = %T %v", outcome.err, outcome.err)
				}
				if outcome.result.Location != subject.name || outcome.result.ExitCode != -1 {
					t.Fatalf("cancel result = %#v", outcome.result)
				}
				if outcome.result.Output != "contract-started" || streamed.String() != outcome.result.Output {
					t.Fatalf("cancel output=%q streamed=%q", outcome.result.Output, streamed.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("backend did not stop promptly after cancellation")
			}
		})
	}
}

func TestExecutionBackendContractNoOutputTimeout(t *testing.T) {
	backends := []struct {
		name    string
		backend ExecutionBackend
		command []string
	}{
		{name: "host", backend: NewHostExecutionBackend(), command: []string{"/bin/sh", "-c", "sleep 30"}},
		{name: "container", backend: newContractContainerBackend(t, blockingContainerRuntimeExecutor{}), command: []string{"contract-timeout"}},
	}

	for _, subject := range backends {
		t.Run(subject.name, func(t *testing.T) {
			var streamed strings.Builder
			started := time.Now()
			result, err := subject.backend.Execute(context.Background(), ExecutionRequest{
				Command:            subject.command,
				Output:             func(chunk string) { streamed.WriteString(chunk) },
				NoOutputTimeoutSec: 1,
			})
			if err == nil || !strings.Contains(err.Error(), "shell inactivity timeout (1s)") {
				t.Fatalf("timeout error = %v", err)
			}
			if elapsed := time.Since(started); elapsed < time.Second || elapsed > 5*time.Second {
				t.Fatalf("timeout elapsed = %v", elapsed)
			}
			wantOutput := ShellNoOutputTimeoutMessage(1)
			if result.Location != subject.name || result.ExitCode != -1 || result.Output != wantOutput {
				t.Fatalf("timeout result = %#v", result)
			}
			if streamed.String() != result.Output {
				t.Fatalf("timeout streamed=%q output=%q", streamed.String(), result.Output)
			}
		})
	}
}
