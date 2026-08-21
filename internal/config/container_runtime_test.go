package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	containerruntime "cyberstrike-ai/internal/runtime/container"
)

func TestContainerRuntimeConfigDefaultsAndValidation(t *testing.T) {
	config := ContainerRuntimeConfig{
		Enabled:               true,
		OwnerID:               "deployment-01",
		ImageRepository:       "ghcr.io/usestrix/strix-sandbox",
		ImageDigest:           "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ImagePlatform:         "linux/arm64",
		EgressImageRepository: "ghcr.io/example/cyberstrike-egress",
		EgressImageDigest:     "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		EgressImagePlatform:   "linux/arm64",
		ToolInventoryPath:     "inventory.json",
		ToolInventoryDigest:   "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ToolInventory:         testContainerToolInventory(),
	}
	config.applyDefaults()
	if err := config.validateEnabled(); err != nil {
		t.Fatal(err)
	}
	if config.InitializerWorkers != 2 || config.QueueCapacity != 64 || config.CreateTimeoutSeconds != 120 || config.IdleStopSeconds != 1800 || config.IdleScanSeconds != 60 || config.MemoryBytes != 512<<20 || config.WorkspaceBytes != 1<<30 || config.LogMaxFiles != 3 || config.EgressMemoryBytes != 128<<20 || config.EgressLogMaxFiles != 2 {
		t.Fatalf("defaults = %#v", config)
	}
	config.IdleStopSeconds = -1
	if err := config.validateEnabled(); err != nil {
		t.Fatalf("disabled idle stop = %v", err)
	}
}

func TestContainerRuntimeConfigFailsClosedWhenEnabled(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ContainerRuntimeConfig)
		want   string
	}{
		{name: "owner", mutate: func(config *ContainerRuntimeConfig) { config.OwnerID = "" }, want: "owner_id"},
		{name: "digest", mutate: func(config *ContainerRuntimeConfig) { config.ImageDigest = "latest" }, want: "digest"},
		{name: "platform", mutate: func(config *ContainerRuntimeConfig) { config.ImagePlatform = "linux/aarch64" }, want: "canonical"},
		{name: "egress digest", mutate: func(config *ContainerRuntimeConfig) { config.EgressImageDigest = "" }, want: "egress_image_digest"},
		{name: "egress nofile", mutate: func(config *ContainerRuntimeConfig) { config.EgressNoFileSoft = 2048; config.EgressNoFileHard = 1024 }, want: "egress gateway nofile"},
		{name: "negative queue", mutate: func(config *ContainerRuntimeConfig) { config.QueueCapacity = -1 }, want: "queue_capacity"},
		{name: "invalid idle stop", mutate: func(config *ContainerRuntimeConfig) { config.IdleStopSeconds = -2 }, want: "idle_stop_seconds"},
		{name: "invalid idle scan", mutate: func(config *ContainerRuntimeConfig) { config.IdleScanSeconds = -1 }, want: "idle_scan_seconds"},
		{name: "nofile", mutate: func(config *ContainerRuntimeConfig) { config.NoFileSoft = 4096; config.NoFileHard = 1024 }, want: "nofile"},
		{name: "inventory digest", mutate: func(config *ContainerRuntimeConfig) { config.ToolInventoryDigest = "latest" }, want: "inventory digest"},
		{name: "inventory image", mutate: func(config *ContainerRuntimeConfig) {
			config.ToolInventory.ImageDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		}, want: "image identity"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := ContainerRuntimeConfig{
				Enabled: true, OwnerID: "deployment-01",
				ImageRepository:       "ghcr.io/usestrix/strix-sandbox",
				ImageDigest:           "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ImagePlatform:         "linux/arm64",
				EgressImageRepository: "ghcr.io/example/cyberstrike-egress",
				EgressImageDigest:     "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				EgressImagePlatform:   "linux/arm64",
				ToolInventoryPath:     "inventory.json",
				ToolInventoryDigest:   "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				ToolInventory:         testContainerToolInventory(),
			}
			config.applyDefaults()
			test.mutate(&config)
			err := config.validateEnabled()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestContainerRuntimeConfigLoadsPinnedInventoryRelativeToConfig(t *testing.T) {
	directory := t.TempDir()
	raw := []byte(`{"schemaVersion":1,"imageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","imagePlatform":"linux/arm64","tools":[{"name":"sh","path":"/bin/sh","version":"busybox-1","category":"runtime"}]}`)
	digest := sha256.Sum256(raw)
	expected := "sha256:" + hex.EncodeToString(digest[:])
	if err := os.WriteFile(filepath.Join(directory, "inventory.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	config := ContainerRuntimeConfig{
		Enabled: true, ToolInventoryPath: "inventory.json", ToolInventoryDigest: expected,
	}
	if err := config.loadToolInventory(filepath.Join(directory, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if config.ToolInventoryDigest != expected || config.ToolInventoryPath != filepath.Join(directory, "inventory.json") || len(config.ToolInventory.Tools) != 1 {
		t.Fatalf("loaded inventory = %#v", config)
	}
}

func testContainerToolInventory() containerruntime.ToolInventory {
	return containerruntime.ToolInventory{
		SchemaVersion: containerruntime.ToolInventorySchemaVersion,
		ImageDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ImagePlatform: "linux/arm64",
		Tools: []containerruntime.ToolInventoryEntry{
			{Name: "sh", Path: "/bin/sh", Version: "busybox-1", Category: "runtime"},
		},
	}
}
