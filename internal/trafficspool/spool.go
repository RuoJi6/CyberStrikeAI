package trafficspool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"cyberstrike-ai/internal/traffic"
)

const (
	EnvelopeVersion     = "traffic-spool/v1"
	ContainerPath       = "/var/lib/cyberstrike/traffic-spool"
	MaxEnvelopeBytes    = 32 << 20
	defaultMaximumFiles = 256
)

var spoolIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Envelope struct {
	Version     string              `json:"version"`
	Transaction traffic.Transaction `json:"transaction"`
	Messages    []traffic.Message   `json:"messages"`
}

type Writer struct {
	root           string
	conversationID string
}

// Directory owns the control-plane traffic spool root. ConversationPath is
// the only supported way for the Docker manager to derive a writable gateway
// bind mount, so request data can never select an arbitrary host path.
type Directory struct {
	root string
}

func secureDirectory(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("traffic spool directory is required")
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve traffic spool directory: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return "", fmt.Errorf("create traffic spool directory: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("inspect traffic spool directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("traffic spool directory must be a real directory")
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		return "", fmt.Errorf("restrict traffic spool directory: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve traffic spool directory symlinks: %w", err)
	}
	return filepath.Clean(real), nil
}

func NewDirectory(root string) (*Directory, error) {
	resolved, err := secureDirectory(root)
	if err != nil {
		return nil, err
	}
	return &Directory{root: resolved}, nil
}

func (d *Directory) Root() string {
	if d == nil {
		return ""
	}
	return d.root
}

func (d *Directory) ConversationPath(conversationID string) (string, error) {
	conversationID = strings.TrimSpace(conversationID)
	if d == nil || d.root == "" || !spoolIDPattern.MatchString(conversationID) {
		return "", errors.New("traffic spool conversation id is invalid")
	}
	path, err := secureDirectory(filepath.Join(d.root, conversationID))
	if err != nil {
		return "", err
	}
	// The parent spool root is 0700 and remains the host-side security
	// boundary. The gateway has no DAC override capability, so grant only
	// write+traverse (not read/list) to the bind-mounted conversation child.
	if err := os.Chmod(path, 0o703); err != nil {
		return "", fmt.Errorf("prepare traffic spool conversation directory: %w", err)
	}
	relative, err := filepath.Rel(d.root, path)
	if err != nil || relative != conversationID {
		return "", errors.New("traffic spool conversation path escapes its root")
	}
	return path, nil
}

func NewWriter(root, conversationID string) (*Writer, error) {
	conversationID = strings.TrimSpace(conversationID)
	if !spoolIDPattern.MatchString(conversationID) {
		return nil, errors.New("traffic spool conversation id is invalid")
	}
	resolved, err := writerDirectory(root)
	if err != nil {
		return nil, err
	}
	return &Writer{root: resolved, conversationID: conversationID}, nil
}

// writerDirectory accepts a control-plane-created 0703 bind mount without
// trying to chmod the mount point from inside Docker. Some engines allow file
// creation on a writable bind while rejecting chmod(2) on the mount root.
// Newly created host-mode directories are still explicitly restricted.
func writerDirectory(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("traffic spool directory is required")
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve traffic spool directory: %w", err)
	}
	created := false
	if _, err := os.Lstat(abs); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(abs, 0o700); err != nil {
			return "", fmt.Errorf("create traffic spool directory: %w", err)
		}
		created = true
	} else if err != nil {
		return "", fmt.Errorf("inspect traffic spool directory: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("inspect traffic spool directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("traffic spool directory must be a real directory")
	}
	if created {
		if err := os.Chmod(abs, 0o700); err != nil {
			return "", fmt.Errorf("restrict traffic spool directory: %w", err)
		}
		info, err = os.Lstat(abs)
		if err != nil {
			return "", fmt.Errorf("inspect traffic spool directory: %w", err)
		}
	}
	permissions := info.Mode().Perm()
	if permissions != 0o700 && permissions != 0o703 {
		return "", errors.New("traffic spool writer directory must be 0700 or write-only 0703")
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve traffic spool directory symlinks: %w", err)
	}
	return filepath.Clean(real), nil
}

func (w *Writer) Write(_ context.Context, item traffic.Transaction, messages []traffic.Message) error {
	if w == nil {
		return errors.New("traffic spool writer is unavailable")
	}
	if item.ConversationID != w.conversationID || !spoolIDPattern.MatchString(item.ID) {
		return errors.New("traffic spool transaction identity is invalid")
	}
	envelope := Envelope{Version: EnvelopeVersion, Transaction: item, Messages: messages}
	content, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode traffic spool envelope: %w", err)
	}
	if len(content) > MaxEnvelopeBytes {
		return errors.New("traffic spool envelope exceeds the hard limit")
	}
	temporary, err := os.CreateTemp(w.root, ".traffic-*.tmp")
	if err != nil {
		return fmt.Errorf("create traffic spool temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		_ = temporary.Close()
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	// The gateway commonly runs as container root while the control plane owns
	// the 0700 bind-mounted directory on the host. Keep the envelope readable by
	// that owner; the private parent directory remains the access boundary.
	if err := temporary.Chmod(0o644); err != nil {
		return fmt.Errorf("restrict traffic spool file: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write traffic spool envelope: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync traffic spool envelope: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close traffic spool envelope: %w", err)
	}
	readyPath := filepath.Join(w.root, item.ID+".ready")
	if err := os.Rename(temporaryPath, readyPath); err != nil {
		return fmt.Errorf("publish traffic spool envelope: %w", err)
	}
	cleanup = false
	return nil
}

type Store interface {
	CreateTrafficTransaction(context.Context, *traffic.Transaction, []traffic.Message) (*traffic.TransactionDetail, error)
}

type Collector struct {
	root         string
	store        Store
	maximumFiles int
	onImported   func(context.Context, *traffic.TransactionDetail)
}

// SetImportedHook installs a best-effort post-persistence observer. The spool
// file is still acknowledged if the observer fails internally; packet capture
// durability must never depend on an optional transform Runner.
func (c *Collector) SetImportedHook(hook func(context.Context, *traffic.TransactionDetail)) {
	if c != nil {
		c.onImported = hook
	}
}

type ReconcileReport struct {
	Imported    int `json:"imported"`
	Quarantined int `json:"quarantined"`
	Remaining   int `json:"remaining"`
}

func NewCollector(root string, store Store) (*Collector, error) {
	if store == nil {
		return nil, errors.New("traffic spool collector store is required")
	}
	resolved, err := secureDirectory(root)
	if err != nil {
		return nil, err
	}
	return &Collector{root: resolved, store: store, maximumFiles: defaultMaximumFiles}, nil
}

func (c *Collector) Reconcile(ctx context.Context) (ReconcileReport, error) {
	report := ReconcileReport{}
	if c == nil || c.store == nil {
		return report, errors.New("traffic spool collector is unavailable")
	}
	paths := make([]string, 0)
	err := filepath.WalkDir(c.root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".ready") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return report, fmt.Errorf("scan traffic spool: %w", err)
	}
	sort.Strings(paths)
	if len(paths) > c.maximumFiles {
		report.Remaining = len(paths) - c.maximumFiles
		paths = paths[:c.maximumFiles]
	}
	for _, path := range paths {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}
		result, importErr := c.importFile(ctx, path)
		switch result {
		case "imported":
			report.Imported++
		case "quarantined":
			report.Quarantined++
		}
		if importErr != nil {
			return report, importErr
		}
	}
	return report, nil
}

func (c *Collector) importFile(ctx context.Context, path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("open traffic spool envelope: %w", err)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, MaxEnvelopeBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return "", fmt.Errorf("read traffic spool envelope: %w", readErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close traffic spool envelope: %w", closeErr)
	}
	var envelope Envelope
	if len(content) > MaxEnvelopeBytes || json.Unmarshal(content, &envelope) != nil || !validEnvelope(path, envelope) {
		return c.quarantine(path)
	}
	detail, err := c.store.CreateTrafficTransaction(ctx, &envelope.Transaction, envelope.Messages)
	if err != nil {
		return "", fmt.Errorf("persist traffic spool envelope %s: %w", envelope.Transaction.ID, err)
	}
	if c.onImported != nil {
		c.onImported(ctx, detail)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("acknowledge traffic spool envelope: %w", err)
	}
	return "imported", nil
}

func validEnvelope(path string, envelope Envelope) bool {
	if envelope.Version != EnvelopeVersion || !spoolIDPattern.MatchString(envelope.Transaction.ID) ||
		filepath.Base(path) != envelope.Transaction.ID+".ready" ||
		filepath.Base(filepath.Dir(path)) != envelope.Transaction.ConversationID ||
		traffic.ValidateTransaction(envelope.Transaction) != nil || len(envelope.Messages) > 6 {
		return false
	}
	stages := make(map[string]struct{}, len(envelope.Messages))
	for _, message := range envelope.Messages {
		if message.TransactionID != envelope.Transaction.ID || traffic.ValidateMessage(message) != nil {
			return false
		}
		if _, duplicate := stages[message.Stage]; duplicate {
			return false
		}
		stages[message.Stage] = struct{}{}
	}
	return true
}

func (c *Collector) quarantine(path string) (string, error) {
	target := strings.TrimSuffix(path, ".ready") + ".bad"
	if err := os.Rename(path, target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("quarantine traffic spool envelope: %w", err)
	}
	return "quarantined", nil
}

func (c *Collector) RunPeriodic(ctx context.Context, interval time.Duration, callback func(ReconcileReport, error)) error {
	if ctx == nil || interval <= 0 {
		return errors.New("traffic spool collector context and interval are required")
	}
	run := func() {
		report, err := c.Reconcile(ctx)
		if callback != nil {
			callback(report, err)
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			run()
		}
	}
}
