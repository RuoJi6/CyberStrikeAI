package container

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	ToolInventorySchemaVersion = 1
	maxToolInventoryBytes      = 1 << 20
	maxToolInventoryEntries    = 4096
)

var toolInventoryNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$`)

type ToolInventory struct {
	SchemaVersion int                  `json:"schemaVersion"`
	ImageDigest   string               `json:"imageDigest"`
	ImagePlatform string               `json:"imagePlatform"`
	Tools         []ToolInventoryEntry `json:"tools"`
}

type ToolInventoryEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Version  string `json:"version"`
	Category string `json:"category"`
}

// ReadinessPolicy is part of the immutable per-conversation specification.
// The inventory is loaded from a trusted release artifact by the control plane
// and persisted so a later configuration edit cannot change an in-flight job.
type ReadinessPolicy struct {
	Enabled         bool          `json:"enabled"`
	InventoryDigest string        `json:"inventoryDigest,omitempty"`
	Inventory       ToolInventory `json:"inventory,omitempty"`
}

type ReadinessReport struct {
	InventoryDigest string `json:"inventoryDigest"`
	ToolCount       int    `json:"toolCount"`
}

func LoadToolInventory(path, expectedDigest string) (ToolInventory, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return ToolInventory{}, "", invalidSpec("tool inventory path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return ToolInventory{}, "", fmt.Errorf("read tool inventory %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxToolInventoryBytes {
		return ToolInventory{}, "", invalidSpec("tool inventory must be a non-empty regular file no larger than 1 MiB")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ToolInventory{}, "", fmt.Errorf("read tool inventory %s: %w", path, err)
	}
	digest := sha256.Sum256(raw)
	actualDigest := "sha256:" + hex.EncodeToString(digest[:])
	if !sha256DigestPattern.MatchString(strings.TrimSpace(expectedDigest)) || actualDigest != strings.TrimSpace(expectedDigest) {
		return ToolInventory{}, actualDigest, fmt.Errorf("%w: tool inventory expected %s, got %s", ErrImageDigestMismatch, strings.TrimSpace(expectedDigest), actualDigest)
	}
	var inventory ToolInventory
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil {
		return ToolInventory{}, actualDigest, fmt.Errorf("decode tool inventory: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ToolInventory{}, actualDigest, invalidSpec("tool inventory contains trailing JSON data")
	}
	if err := ValidateToolInventory(inventory); err != nil {
		return ToolInventory{}, actualDigest, err
	}
	return inventory, actualDigest, nil
}

func ValidateReadinessPolicy(policy ReadinessPolicy, image ImageReference) error {
	if !policy.Enabled {
		if strings.TrimSpace(policy.InventoryDigest) != "" || policy.Inventory.SchemaVersion != 0 || len(policy.Inventory.Tools) != 0 {
			return invalidSpec("disabled readiness policy cannot include an inventory")
		}
		return nil
	}
	if !sha256DigestPattern.MatchString(strings.TrimSpace(policy.InventoryDigest)) {
		return invalidSpec("readiness inventory digest must be a lowercase sha256 digest")
	}
	if err := ValidateToolInventory(policy.Inventory); err != nil {
		return err
	}
	if policy.Inventory.ImageDigest != image.Digest || policy.Inventory.ImagePlatform != image.Platform {
		return fmt.Errorf("%w: tool inventory image identity does not match the runtime specification", ErrImageDigestMismatch)
	}
	return nil
}

func ValidateToolInventory(inventory ToolInventory) error {
	if inventory.SchemaVersion != ToolInventorySchemaVersion {
		return invalidSpec("tool inventory schemaVersion must be 1")
	}
	if !sha256DigestPattern.MatchString(strings.TrimSpace(inventory.ImageDigest)) {
		return invalidSpec("tool inventory imageDigest must be a lowercase sha256 digest")
	}
	parsedPlatform, err := parsePlatform(inventory.ImagePlatform)
	if err != nil || strings.TrimSpace(inventory.ImagePlatform) != platformFromParts(parsedPlatform) {
		return invalidSpec("tool inventory imagePlatform must be canonical")
	}
	if len(inventory.Tools) == 0 || len(inventory.Tools) > maxToolInventoryEntries {
		return invalidSpec("tool inventory must contain between 1 and 4096 tools")
	}
	names := make(map[string]struct{}, len(inventory.Tools))
	for _, tool := range inventory.Tools {
		name := strings.TrimSpace(tool.Name)
		if !toolInventoryNamePattern.MatchString(name) {
			return invalidSpec("tool inventory contains an invalid tool name")
		}
		canonicalName := strings.ToLower(name)
		if _, exists := names[canonicalName]; exists {
			return invalidSpec("tool inventory contains a duplicate tool name")
		}
		names[canonicalName] = struct{}{}
		path := strings.TrimSpace(tool.Path)
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.HasPrefix(path, "/proc/") || strings.HasPrefix(path, "/sys/") || strings.HasPrefix(path, "/dev/") || path == "/var/run/docker.sock" || path == "/run/docker.sock" {
			return invalidSpec("tool inventory contains an unsafe tool path")
		}
		if strings.TrimSpace(tool.Version) == "" || strings.TrimSpace(tool.Category) == "" {
			return invalidSpec("tool inventory entries require version and category")
		}
	}
	return nil
}

func SortedInventoryToolNames(inventory ToolInventory) []string {
	names := make([]string, 0, len(inventory.Tools))
	for _, tool := range inventory.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}
