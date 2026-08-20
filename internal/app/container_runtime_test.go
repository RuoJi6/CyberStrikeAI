package app

import (
	"testing"

	"cyberstrike-ai/internal/config"
	containerruntime "cyberstrike-ai/internal/runtime/container"
)

func TestConversationContainerSpecUsesTrustedPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.Container.Enabled = true
	cfg.Container.OwnerID = "deployment-01"
	cfg.Container.ImageRepository = "ghcr.io/usestrix/strix-sandbox"
	cfg.Container.ImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfg.Container.ImagePlatform = "linux/arm64"
	spec, err := conversationContainerSpec(cfg, "conversation-01")
	if err != nil {
		t.Fatal(err)
	}
	if spec.ID != "conversation-conversation-01" || spec.ConversationID != "conversation-01" || spec.Image.Repository != cfg.Container.ImageRepository || spec.Image.Digest != cfg.Container.ImageDigest {
		t.Fatalf("spec identity = %#v", spec)
	}
	if spec.Security.NetworkMode != containerruntime.NetworkNone || !spec.Security.ReadOnlyRootFS || !spec.Security.NoNewPrivileges || !spec.Security.DropAllCapabilities || spec.Security.SeccompProfile != "default" {
		t.Fatalf("spec security = %#v", spec.Security)
	}
	if spec.Resources.MemoryBytes != 512<<20 || spec.Resources.MaxConcurrentExec != 2 || spec.Resources.MaxQueuedExec != 8 || spec.Resources.LogMaxFiles != 3 {
		t.Fatalf("spec resources = %#v", spec.Resources)
	}
}
