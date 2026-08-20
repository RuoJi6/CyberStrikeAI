package security

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/adk/filesystem"
)

type recordingContainerFilesystemExecutionBackend struct {
	requests []ExecutionRequest
	writes   []string
	content  []string
	output   string
}

func (b *recordingContainerFilesystemExecutionBackend) ExecutionLocation() string { return "container" }

func (b *recordingContainerFilesystemExecutionBackend) Execute(_ context.Context, request ExecutionRequest) (ExecutionResult, error) {
	b.requests = append(b.requests, request)
	return ExecutionResult{Location: "container", Output: b.output}, nil
}

func (b *recordingContainerFilesystemExecutionBackend) WriteWorkspaceFile(_ context.Context, filePath string, content io.Reader, _ int64) (string, error) {
	data, err := io.ReadAll(content)
	if err != nil {
		return "", err
	}
	b.writes = append(b.writes, filePath)
	b.content = append(b.content, string(data))
	return filePath, nil
}

func TestConversationFilesystemBackendNormalizesContainerReadPath(t *testing.T) {
	container := &recordingContainerFilesystemExecutionBackend{output: "first\nsecond\n"}
	backend := NewConversationFilesystemBackend(nil, NewFixedExecutionBackendResolver(container))
	content, err := backend.Read(context.Background(), &filesystem.ReadRequest{FilePath: "uploads/./report.txt", Offset: 1, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if content.Content != "first\nsecond" || len(container.requests) != 1 {
		t.Fatalf("read content/requests = %q / %d", content.Content, len(container.requests))
	}
	request := container.requests[0]
	if request.WorkingDir != "/workspace" || !containsArgument(request.Command, "/workspace/uploads/report.txt") {
		t.Fatalf("container filesystem request = %#v", request)
	}
}

func TestConversationFilesystemBackendWritesOnlyNormalizedWorkspacePath(t *testing.T) {
	container := &recordingContainerFilesystemExecutionBackend{}
	backend := NewConversationFilesystemBackend(nil, NewFixedExecutionBackendResolver(container))
	if err := backend.Write(context.Background(), &filesystem.WriteRequest{FilePath: "results/../results/out.txt", Content: "ok"}); err != nil {
		t.Fatal(err)
	}
	if len(container.writes) != 1 || container.writes[0] != "/workspace/results/out.txt" || container.content[0] != "ok" {
		t.Fatalf("workspace writes/content = %#v / %#v", container.writes, container.content)
	}
}

func TestConversationFilesystemBackendRejectsTraversalBeforeExecution(t *testing.T) {
	container := &recordingContainerFilesystemExecutionBackend{}
	backend := NewConversationFilesystemBackend(nil, NewFixedExecutionBackendResolver(container))
	for _, filePath := range []string{"../../etc/passwd", "/etc/passwd", `uploads\..\secret`} {
		if _, err := backend.Read(context.Background(), &filesystem.ReadRequest{FilePath: filePath}); err == nil || !strings.Contains(err.Error(), "invalid container workspace path") {
			t.Fatalf("read traversal %q error = %v", filePath, err)
		}
	}
	if len(container.requests) != 0 || len(container.writes) != 0 {
		t.Fatalf("container backend reached for traversal: requests=%d writes=%d", len(container.requests), len(container.writes))
	}
}

func TestContainerFilesystemScriptsStopAfterSymlinkGuardRejection(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "passwd"), []byte("must-not-be-read\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(workspace, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(link, "passwd")

	tests := []struct {
		name   string
		script string
		args   []string
	}{
		{name: "read", script: containerReadFileScript, args: []string{workspace, target, "1", "10"}},
		{name: "read whole", script: containerReadWholeFileScript, args: []string{workspace, target}},
		{name: "list", script: containerListDirectoryScript, args: []string{workspace, link}},
		{name: "walk", script: containerWalkWorkspaceScript, args: []string{workspace, link}},
		{name: "grep", script: containerGrepWorkspaceScript, args: []string{workspace, target, "--json", "-e", "must-not-be-read"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			commandArgs := append([]string{"-c", test.script, "cyberstrike-fs-test"}, test.args...)
			cmd := exec.Command("/bin/sh", commandArgs...)
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 65 {
				t.Fatalf("guard exit error = %v, stderr = %q", err, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("guarded script leaked output: %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), "symlinked workspace path rejected") {
				t.Fatalf("guard stderr = %q", stderr.String())
			}
		})
	}
}

func containsArgument(command []string, want string) bool {
	for _, argument := range command {
		if argument == want {
			return true
		}
	}
	return false
}
