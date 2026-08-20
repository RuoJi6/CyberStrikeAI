package container

import (
	"errors"
	"testing"
)

func TestNormalizeWorkspacePathCanonicalizesRelativePaths(t *testing.T) {
	tests := map[string]string{
		"":                            "/workspace",
		".":                           "/workspace",
		"uploads/report.txt":          "/workspace/uploads/report.txt",
		"./uploads/a/../report.txt":   "/workspace/uploads/report.txt",
		"/workspace/results/out.json": "/workspace/results/out.json",
	}
	for input, expected := range tests {
		actual, err := NormalizeWorkspacePath("/workspace", input)
		if err != nil || actual != expected {
			t.Fatalf("NormalizeWorkspacePath(%q) = %q, %v; want %q", input, actual, err, expected)
		}
	}
}

func TestNormalizeWorkspacePathRejectsTraversalAndHostPaths(t *testing.T) {
	for _, input := range []string{"../etc/passwd", "/etc/passwd", "/workspace/../../etc/passwd", `uploads\..\secret`, "bad\x00path"} {
		if _, err := NormalizeWorkspacePath("/workspace", input); !errors.Is(err, ErrInvalidSpecification) {
			t.Fatalf("NormalizeWorkspacePath(%q) error = %v", input, err)
		}
	}
}
