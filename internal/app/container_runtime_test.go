package app

import (
	"context"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"go.uber.org/zap"
)

func TestConversationContainerSpecUsesTrustedPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.Container.Enabled = true
	cfg.Container.OwnerID = "deployment-01"
	cfg.Container.ImageRepository = "ghcr.io/usestrix/strix-sandbox"
	cfg.Container.ImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfg.Container.ImagePlatform = "linux/arm64"
	cfg.Container.ToolInventoryPath = "inventory.json"
	cfg.Container.ToolInventoryDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cfg.Container.ToolInventory = containerruntime.ToolInventory{
		SchemaVersion: containerruntime.ToolInventorySchemaVersion,
		ImageDigest:   cfg.Container.ImageDigest,
		ImagePlatform: cfg.Container.ImagePlatform,
		Tools: []containerruntime.ToolInventoryEntry{
			{Name: "sh", Path: "/bin/sh", Version: "busybox-1", Category: "runtime"},
		},
	}
	spec, err := conversationContainerSpec(cfg, "conversation-01", false)
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
	if !spec.Readiness.Enabled || spec.Readiness.InventoryDigest != cfg.Container.ToolInventoryDigest || len(spec.Readiness.Inventory.Tools) != 1 {
		t.Fatalf("spec readiness = %#v", spec.Readiness)
	}
}

func TestBoundarySnapshotInitializationStoreBindsBeforeWorkerClaim(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "initializer-boundary.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("queued", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	spec := appExecutionSpec(conversation.ID)
	if _, _, err := db.Queue(context.Background(), spec, false); err != nil {
		t.Fatal(err)
	}
	store := &boundarySnapshotInitializationStore{DB: db}
	if _, claimed, err := store.Claim(context.Background(), conversation.ID); err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	if _, err := db.GetConversationBoundarySnapshot(context.Background(), conversation.ID); err != nil {
		t.Fatalf("worker claim did not bind snapshot first: %v", err)
	}
}

func TestConversationContainerSpecUsesConversationNamedVolume(t *testing.T) {
	cfg := config.Default()
	cfg.Container.Enabled = true
	cfg.Container.ImageRepository = "ghcr.io/usestrix/strix-sandbox"
	cfg.Container.ImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfg.Container.ImagePlatform = "linux/arm64"
	cfg.Container.ToolInventoryDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cfg.Container.ToolInventory = containerruntime.ToolInventory{
		SchemaVersion: containerruntime.ToolInventorySchemaVersion,
		ImageDigest:   cfg.Container.ImageDigest, ImagePlatform: cfg.Container.ImagePlatform,
		Tools: []containerruntime.ToolInventoryEntry{{Name: "sh", Path: "/bin/sh", Version: "busybox-1", Category: "runtime"}},
	}
	spec, err := conversationContainerSpec(cfg, "conversation-01", true)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.Workspace.Persistent || spec.Workspace.VolumeName != "cyberstrike-workspace-conversation-conversation-01" {
		t.Fatalf("workspace = %#v", spec.Workspace)
	}
}
