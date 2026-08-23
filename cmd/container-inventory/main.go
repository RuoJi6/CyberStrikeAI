package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	containerruntime "cyberstrike-ai/internal/runtime/container"
)

type inventoryEntries struct {
	Tools []containerruntime.ToolInventoryEntry `json:"tools"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	set := flag.NewFlagSet("container-inventory", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	entriesPath := set.String("entries", "", "tool inventory entries JSON")
	imageDigest := set.String("image-digest", "", "platform-specific sha256 image digest")
	imagePlatform := set.String("image-platform", "", "canonical linux platform")
	outputPath := set.String("output", "", "output inventory JSON")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 ||
		strings.TrimSpace(*entriesPath) == "" ||
		strings.TrimSpace(*imageDigest) == "" ||
		strings.TrimSpace(*imagePlatform) == "" ||
		strings.TrimSpace(*outputPath) == "" {
		return errors.New("entries, image-digest and image-platform, and output are required")
	}
	raw, err := os.ReadFile(filepath.Clean(*entriesPath))
	if err != nil {
		return fmt.Errorf("read entries: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var entries inventoryEntries
	if err := decoder.Decode(&entries); err != nil {
		return fmt.Errorf("decode entries: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("entries contain trailing JSON data")
	}
	inventory := containerruntime.ToolInventory{
		SchemaVersion: containerruntime.ToolInventorySchemaVersion,
		ImageDigest:   strings.TrimSpace(*imageDigest),
		ImagePlatform: strings.TrimSpace(*imagePlatform),
		Tools:         entries.Tools,
	}
	if err := containerruntime.ValidateToolInventory(inventory); err != nil {
		return fmt.Errorf("validate inventory: %w", err)
	}
	encoded, err := json.Marshal(inventory)
	if err != nil {
		return fmt.Errorf("encode inventory: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := writeAtomic(filepath.Clean(*outputPath), encoded); err != nil {
		return err
	}
	sum := sha256.Sum256(encoded)
	_, err = fmt.Fprintln(stdout, "sha256:"+hex.EncodeToString(sum[:]))
	return err
}

func writeAtomic(path string, content []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".tool-inventory-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary inventory: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write inventory: %w", err)
	}
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set inventory permissions: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close inventory: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish inventory: %w", err)
	}
	return nil
}
