package security

import (
	"context"
	"io"
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

func containsArgument(command []string, want string) bool {
	for _, argument := range command {
		if argument == want {
			return true
		}
	}
	return false
}
