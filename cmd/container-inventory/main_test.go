package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	containerruntime "cyberstrike-ai/internal/runtime/container"
)

func TestRunGeneratesLoadablePinnedInventory(t *testing.T) {
	directory := t.TempDir()
	entries := filepath.Join(directory, "entries.json")
	output := filepath.Join(directory, "release", "inventory.json")
	if err := os.WriteFile(entries, []byte(`{"tools":[{"name":"sh","path":"/bin/sh","version":"test-1","category":"runtime"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	imageDigest := "sha256:" + strings.Repeat("a", 64)
	var stdout bytes.Buffer
	if err := run([]string{
		"-entries", entries,
		"-image-digest", imageDigest,
		"-image-platform", "linux/arm64",
		"-output", output,
	}, &stdout); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	wantInventoryDigest := "sha256:" + hex.EncodeToString(sum[:])
	if strings.TrimSpace(stdout.String()) != wantInventoryDigest {
		t.Fatalf("reported digest = %q, want %q", strings.TrimSpace(stdout.String()), wantInventoryDigest)
	}
	inventory, actual, err := containerruntime.LoadToolInventory(output, wantInventoryDigest)
	if err != nil {
		t.Fatal(err)
	}
	if actual != wantInventoryDigest || inventory.ImageDigest != imageDigest || inventory.ImagePlatform != "linux/arm64" || len(inventory.Tools) != 1 {
		t.Fatalf("inventory = %#v, digest = %s", inventory, actual)
	}
}

func TestRunRejectsUnknownAndInvalidInput(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "inventory.json")
	for name, content := range map[string]string{
		"unknown":   `{"tools":[],"unexpected":true}`,
		"duplicate": `{"tools":[{"name":"sh","path":"/bin/sh","version":"1","category":"runtime"},{"name":"SH","path":"/usr/bin/sh","version":"1","category":"runtime"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			entries := filepath.Join(directory, name+".json")
			if err := os.WriteFile(entries, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			err := run([]string{
				"-entries", entries,
				"-image-digest", "sha256:" + strings.Repeat("a", 64),
				"-image-platform", "linux/amd64",
				"-output", output,
			}, &bytes.Buffer{})
			if err == nil {
				t.Fatal("expected invalid inventory to fail")
			}
		})
	}
}

func TestRunRejectsMissingPinnedImageMetadata(t *testing.T) {
	directory := t.TempDir()
	entries := filepath.Join(directory, "entries.json")
	if err := os.WriteFile(entries, []byte(`{"tools":[{"name":"sh","path":"/bin/sh","version":"1","category":"runtime"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"digest": {
			"-entries", entries,
			"-image-platform", "linux/arm64",
			"-output", filepath.Join(directory, "missing-digest.json"),
		},
		"platform": {
			"-entries", entries,
			"-image-digest", "sha256:" + strings.Repeat("a", 64),
			"-output", filepath.Join(directory, "missing-platform.json"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(args, &bytes.Buffer{}); err == nil {
				t.Fatal("expected missing pinned image metadata to fail")
			}
		})
	}
}
