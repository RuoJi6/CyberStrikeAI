package multiagent

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/security"

	"github.com/cloudwego/eino/adk/middlewares/skill"
)

type recordingSkillBackend struct {
	requested string
}

func (b *recordingSkillBackend) List(context.Context) ([]skill.FrontMatter, error) {
	return nil, nil
}

func (b *recordingSkillBackend) Get(_ context.Context, name string) (skill.Skill, error) {
	b.requested = name
	return skill.Skill{FrontMatter: skill.FrontMatter{Name: name}}, nil
}

func TestNormalizedEinoSkillBackendTrimsModelInput(t *testing.T) {
	inner := &recordingSkillBackend{}
	backend := &normalizedEinoSkillBackend{Backend: inner}
	got, err := backend.Get(context.Background(), "  traffic-transform-authoring\n")
	if err != nil {
		t.Fatal(err)
	}
	if inner.requested != "traffic-transform-authoring" || got.Name != inner.requested {
		t.Fatalf("skill name was not normalized: requested=%q got=%q", inner.requested, got.Name)
	}
}

type recordingContainerSkillBackend struct {
	files map[string]string
}

func (b *recordingContainerSkillBackend) ExecutionLocation() string { return "container" }

func (b *recordingContainerSkillBackend) Execute(context.Context, security.ExecutionRequest) (security.ExecutionResult, error) {
	return security.ExecutionResult{Location: "container"}, nil
}

func (b *recordingContainerSkillBackend) WriteWorkspaceFile(_ context.Context, path string, content io.Reader, _ int64) (string, error) {
	raw, err := io.ReadAll(content)
	if err != nil {
		return "", err
	}
	if b.files == nil {
		b.files = map[string]string{}
	}
	b.files[path] = string(raw)
	return path, nil
}

func TestBuildEinoSkillContentCopiesPackageIntoContainerWorkspace(t *testing.T) {
	root := t.TempDir()
	skillRoot := filepath.Join(root, "traffic-transform-authoring")
	if err := os.MkdirAll(filepath.Join(skillRoot, "references"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillRoot, "SKILL.md"), []byte("---\nname: traffic-transform-authoring\ndescription: test\n---\n\nFollow the workflow."), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillRoot, "references", "example.txt"), []byte("supporting resource"), 0o644); err != nil {
		t.Fatal(err)
	}

	containerBackend := &recordingContainerSkillBackend{}
	resolver := security.NewFixedExecutionBackendResolver(containerBackend)
	content, err := buildEinoSkillContent(root, resolver)(context.Background(), skill.Skill{
		FrontMatter:   skill.FrontMatter{Name: "traffic-transform-authoring"},
		Content:       "Follow the workflow.",
		BaseDirectory: skillRoot,
	}, "{}")
	if err != nil {
		t.Fatal(err)
	}
	wantRoot := "/workspace/.cyberstrike/skills/traffic-transform-authoring"
	if !strings.Contains(content, "此 Skill 的目录："+wantRoot) {
		t.Fatalf("tool content did not expose container skill root: %s", content)
	}
	if got := containerBackend.files[wantRoot+"/SKILL.md"]; !strings.Contains(got, "name: traffic-transform-authoring") {
		t.Fatalf("SKILL.md was not copied: %q", got)
	}
	if got := containerBackend.files[wantRoot+"/references/example.txt"]; got != "supporting resource" {
		t.Fatalf("supporting resource was not copied: %q", got)
	}
}

func TestBuildEinoSkillContentKeepsHostPathForHostExecution(t *testing.T) {
	root := t.TempDir()
	loaded := skill.Skill{
		FrontMatter:   skill.FrontMatter{Name: "host-skill"},
		Content:       "Host instructions.",
		BaseDirectory: filepath.Join(root, "host-skill"),
	}
	resolver := security.NewFixedExecutionBackendResolver(security.NewHostExecutionBackend())
	content, err := buildEinoSkillContent(root, resolver)(context.Background(), loaded, "{}")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "此 Skill 的目录："+loaded.BaseDirectory) {
		t.Fatalf("host skill root changed unexpectedly: %s", content)
	}
}
