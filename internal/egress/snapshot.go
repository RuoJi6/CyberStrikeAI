package egress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	SnapshotContainerPath = "/etc/cyberstrike/boundary.json"
	maxSnapshotBytes      = 4 << 20
)

var (
	ErrSnapshotIntegrity  = errors.New("egress boundary snapshot integrity check failed")
	snapshotIDPattern     = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	snapshotDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type SnapshotReference struct {
	ID     string
	SHA256 string
}

type SnapshotReport struct {
	Event      string `json:"event"`
	SnapshotID string `json:"snapshotId"`
	SHA256     string `json:"sha256"`
}

type snapshotEnvelope struct {
	SchemaVersion int               `json:"schemaVersion"`
	PolicyID      string            `json:"policyId"`
	Rules         []json.RawMessage `json:"rules"`
}

// SnapshotStore materializes immutable database snapshots into a trusted host
// directory. Docker mounts one exact file read-only into the corresponding
// gateway; the Agent container never receives this mount.
type SnapshotStore struct {
	root string
}

func NewSnapshotStore(root string) (*SnapshotStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("egress snapshot directory is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve egress snapshot directory: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create egress snapshot directory: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("inspect egress snapshot directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("egress snapshot directory must be a real directory")
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		return nil, fmt.Errorf("restrict egress snapshot directory permissions: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve egress snapshot directory symlinks: %w", err)
	}
	return &SnapshotStore{root: filepath.Clean(real)}, nil
}

func (s *SnapshotStore) Root() string {
	if s == nil {
		return ""
	}
	return s.root
}

func (s *SnapshotStore) Path(reference SnapshotReference) (string, error) {
	if s == nil || s.root == "" {
		return "", errors.New("egress snapshot store is not configured")
	}
	if err := validateSnapshotReference(reference); err != nil {
		return "", err
	}
	return filepath.Join(s.root, reference.ID+".json"), nil
}

func (s *SnapshotStore) Put(reference SnapshotReference, canonicalJSON string) (string, error) {
	if _, err := validateSnapshotBytes(reference, []byte(canonicalJSON)); err != nil {
		return "", err
	}
	path, err := s.Path(reference)
	if err != nil {
		return "", err
	}
	if existing, readErr := os.ReadFile(path); readErr == nil {
		if !bytes.Equal(existing, []byte(canonicalJSON)) {
			return "", fmt.Errorf("%w: immutable snapshot file content mismatch", ErrSnapshotIntegrity)
		}
		if _, err := LoadSnapshot(path, reference); err != nil {
			return "", err
		}
		return path, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", fmt.Errorf("read existing egress snapshot: %w", readErr)
	}

	temporary, err := os.CreateTemp(s.root, ".snapshot-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create egress snapshot temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if _, err := io.WriteString(temporary, canonicalJSON); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("write egress snapshot: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("sync egress snapshot: %w", err)
	}
	if err := temporary.Chmod(0o444); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("make egress snapshot read-only: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close egress snapshot: %w", err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("publish immutable egress snapshot: %w", err)
		}
		existing, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(existing, []byte(canonicalJSON)) {
			return "", fmt.Errorf("%w: concurrently published snapshot differs", ErrSnapshotIntegrity)
		}
	}
	if _, err := LoadSnapshot(path, reference); err != nil {
		return "", err
	}
	return path, nil
}

func LoadSnapshot(path string, reference SnapshotReference) (SnapshotReport, error) {
	if err := validateSnapshotReference(reference); err != nil {
		return SnapshotReport{}, err
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return SnapshotReport{}, fmt.Errorf("open egress snapshot: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return SnapshotReport{}, fmt.Errorf("stat egress snapshot: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 || info.Size() < 2 || info.Size() > maxSnapshotBytes {
		return SnapshotReport{}, fmt.Errorf("%w: snapshot file type or size is invalid", ErrSnapshotIntegrity)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil {
		return SnapshotReport{}, fmt.Errorf("read egress snapshot: %w", err)
	}
	return validateSnapshotBytes(reference, content)
}

func validateSnapshotBytes(reference SnapshotReference, content []byte) (SnapshotReport, error) {
	if err := validateSnapshotReference(reference); err != nil {
		return SnapshotReport{}, err
	}
	digestBytes := sha256.Sum256(content)
	actual := "sha256:" + hex.EncodeToString(digestBytes[:])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(reference.SHA256)) != 1 {
		return SnapshotReport{}, fmt.Errorf("%w: SHA-256 mismatch", ErrSnapshotIntegrity)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document snapshotEnvelope
	if err := decoder.Decode(&document); err != nil {
		return SnapshotReport{}, fmt.Errorf("%w: decode snapshot: %v", ErrSnapshotIntegrity, err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return SnapshotReport{}, fmt.Errorf("%w: snapshot contains trailing data", ErrSnapshotIntegrity)
	}
	if document.SchemaVersion != 1 || document.Rules == nil {
		return SnapshotReport{}, fmt.Errorf("%w: unsupported snapshot document", ErrSnapshotIntegrity)
	}
	if document.PolicyID == "" && len(document.Rules) != 0 {
		return SnapshotReport{}, fmt.Errorf("%w: default-deny snapshot contains rules", ErrSnapshotIntegrity)
	}
	return SnapshotReport{SnapshotID: reference.ID, SHA256: reference.SHA256}, nil
}

func validateSnapshotReference(reference SnapshotReference) error {
	id := strings.TrimSpace(reference.ID)
	if id != reference.ID || !snapshotIDPattern.MatchString(id) {
		return fmt.Errorf("%w: snapshot id is invalid", ErrSnapshotIntegrity)
	}
	digest := strings.TrimSpace(reference.SHA256)
	if digest != reference.SHA256 || !snapshotDigestPattern.MatchString(digest) {
		return fmt.Errorf("%w: snapshot digest is invalid", ErrSnapshotIntegrity)
	}
	return nil
}

func RunWithSnapshot(ctx context.Context, path string, reference SnapshotReference, output io.Writer) error {
	if ctx == nil {
		return errors.New("egress gateway context is required")
	}
	report, err := LoadSnapshot(path, reference)
	if err != nil {
		return err
	}
	report.Event = "boundary_snapshot_loaded"
	if output != nil {
		if err := json.NewEncoder(output).Encode(report); err != nil {
			return fmt.Errorf("report loaded boundary snapshot: %w", err)
		}
	}
	<-ctx.Done()
	return nil
}

func CheckSnapshot(path string, reference SnapshotReference, output io.Writer) error {
	report, err := LoadSnapshot(path, reference)
	if err != nil {
		return err
	}
	report.Event = "boundary_snapshot_healthy"
	if output == nil {
		return nil
	}
	return json.NewEncoder(output).Encode(report)
}
