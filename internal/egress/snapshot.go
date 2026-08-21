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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cyberstrike-ai/internal/boundary"
)

const (
	SnapshotContainerPath        = "/etc/cyberstrike/boundary.json"
	maxSnapshotBytes             = 4 << 20
	defaultSnapshotCheckInterval = time.Second
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
	Event               string `json:"event"`
	SnapshotID          string `json:"snapshotId"`
	SHA256              string `json:"sha256"`
	UpstreamRouteID     string `json:"upstreamRouteId,omitempty"`
	UpstreamRouteSHA256 string `json:"upstreamRouteSha256,omitempty"`
	AuthProfilesID      string `json:"authProfilesId,omitempty"`
	AuthProfilesSHA256  string `json:"authProfilesSha256,omitempty"`
}

type snapshotEnvelope struct {
	SchemaVersion int               `json:"schemaVersion"`
	PolicyID      string            `json:"policyId"`
	Rules         []json.RawMessage `json:"rules"`
}

type GatewayOptions struct {
	ListenAddress         string
	DNSListenAddress      string
	SnapshotCheckInterval time.Duration
	UpstreamRoutePath     string
	UpstreamRoute         *UpstreamRouteReference
	AuthProfilesPath      string
	AuthProfiles          *AuthProfilesReference
	Proxy                 ProxyOptions
	DNS                   DNSOptions
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
	report, _, err := loadPolicySnapshot(path, reference)
	return report, err
}

func LoadPolicySnapshot(path string, reference SnapshotReference) (SnapshotReport, *boundary.Policy, error) {
	return loadPolicySnapshot(path, reference)
}

func loadPolicySnapshot(path string, reference SnapshotReference) (SnapshotReport, *boundary.Policy, error) {
	if err := validateSnapshotReference(reference); err != nil {
		return SnapshotReport{}, nil, err
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return SnapshotReport{}, nil, fmt.Errorf("open egress snapshot: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return SnapshotReport{}, nil, fmt.Errorf("stat egress snapshot: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 || info.Size() < 2 || info.Size() > maxSnapshotBytes {
		return SnapshotReport{}, nil, fmt.Errorf("%w: snapshot file type or size is invalid", ErrSnapshotIntegrity)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil {
		return SnapshotReport{}, nil, fmt.Errorf("read egress snapshot: %w", err)
	}
	return validateSnapshotPolicyBytes(reference, content)
}

func validateSnapshotBytes(reference SnapshotReference, content []byte) (SnapshotReport, error) {
	report, _, err := validateSnapshotPolicyBytes(reference, content)
	return report, err
}

func validateSnapshotPolicyBytes(reference SnapshotReference, content []byte) (SnapshotReport, *boundary.Policy, error) {
	if err := validateSnapshotReference(reference); err != nil {
		return SnapshotReport{}, nil, err
	}
	digestBytes := sha256.Sum256(content)
	actual := "sha256:" + hex.EncodeToString(digestBytes[:])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(reference.SHA256)) != 1 {
		return SnapshotReport{}, nil, fmt.Errorf("%w: SHA-256 mismatch", ErrSnapshotIntegrity)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document snapshotEnvelope
	if err := decoder.Decode(&document); err != nil {
		return SnapshotReport{}, nil, fmt.Errorf("%w: decode snapshot: %v", ErrSnapshotIntegrity, err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return SnapshotReport{}, nil, fmt.Errorf("%w: snapshot contains trailing data", ErrSnapshotIntegrity)
	}
	if document.SchemaVersion != 1 || document.Rules == nil {
		return SnapshotReport{}, nil, fmt.Errorf("%w: unsupported snapshot document", ErrSnapshotIntegrity)
	}
	if document.PolicyID == "" && len(document.Rules) != 0 {
		return SnapshotReport{}, nil, fmt.Errorf("%w: default-deny snapshot contains rules", ErrSnapshotIntegrity)
	}
	policy, err := compileSnapshotPolicy(document.Rules)
	if err != nil {
		return SnapshotReport{}, nil, err
	}
	return SnapshotReport{SnapshotID: reference.ID, SHA256: reference.SHA256}, policy, nil
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

func RunWithSnapshot(ctx context.Context, path string, reference SnapshotReference, output io.Writer, configured ...GatewayOptions) error {
	if ctx == nil {
		return errors.New("egress gateway context is required")
	}
	if len(configured) > 1 {
		return errors.New("egress gateway accepts at most one options value")
	}
	options := GatewayOptions{}
	if len(configured) == 1 {
		options = configured[0]
	}
	if options.SnapshotCheckInterval < 0 {
		return errors.New("egress snapshot check interval must not be negative")
	}
	if options.SnapshotCheckInterval == 0 {
		options.SnapshotCheckInterval = defaultSnapshotCheckInterval
	}
	report, policy, err := LoadPolicySnapshot(path, reference)
	if err != nil {
		return err
	}
	if strings.TrimSpace(options.UpstreamRoutePath) != "" || options.UpstreamRoute != nil {
		if strings.TrimSpace(options.UpstreamRoutePath) == "" || options.UpstreamRoute == nil {
			return errors.New("egress upstream route path and reference must be configured together")
		}
		if options.Proxy.UpstreamRoute != nil {
			return errors.New("egress upstream route must have only one trusted source")
		}
		route, routeErr := LoadUpstreamRoute(options.UpstreamRoutePath, *options.UpstreamRoute)
		if routeErr != nil {
			return routeErr
		}
		options.Proxy.UpstreamRoute = &route
		report.UpstreamRouteID = options.UpstreamRoute.ID
		report.UpstreamRouteSHA256 = options.UpstreamRoute.SHA256
	}
	if strings.TrimSpace(options.AuthProfilesPath) != "" || options.AuthProfiles != nil {
		if strings.TrimSpace(options.AuthProfilesPath) == "" || options.AuthProfiles == nil {
			return errors.New("egress auth profiles path and reference must be configured together")
		}
		if options.Proxy.AuthProfiles != nil {
			return errors.New("egress auth profiles must have only one trusted source")
		}
		document, authErr := LoadAuthProfiles(options.AuthProfilesPath, *options.AuthProfiles)
		if authErr != nil {
			return authErr
		}
		options.Proxy.AuthProfiles = &document
		report.AuthProfilesID = options.AuthProfiles.ID
		report.AuthProfilesSHA256 = options.AuthProfiles.SHA256
	}
	proxy, err := NewProxy(policy, options.Proxy)
	if err != nil {
		return err
	}
	dnsHandler, err := NewPolicyDNS(policy, options.DNS)
	if err != nil {
		return err
	}
	listenAddress := strings.TrimSpace(options.ListenAddress)
	if listenAddress == "" {
		listenAddress = DefaultProxyListenAddress
	}
	if ctx.Err() != nil {
		return nil
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen for egress proxy: %w", err)
	}
	dnsPacket, dnsTCP, err := listenPolicyDNS(normalizedDNSListenAddress(options.DNSListenAddress))
	if err != nil {
		_ = listener.Close()
		return err
	}
	server := &http.Server{
		Handler: proxy, ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10,
	}
	report.Event = "boundary_snapshot_loaded"
	if output != nil {
		if err := json.NewEncoder(output).Encode(report); err != nil {
			closeGatewayListeners(listener, dnsPacket, dnsTCP)
			return fmt.Errorf("report loaded boundary snapshot: %w", err)
		}
	}
	type serverResult struct {
		name string
		err  error
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan serverResult, 4)
	go func() { results <- serverResult{name: "HTTP proxy", err: server.Serve(listener)} }()
	go func() {
		results <- serverResult{name: "UDP policy DNS", err: servePolicyDNSUDP(runCtx, dnsPacket, dnsHandler)}
	}()
	go func() {
		results <- serverResult{name: "TCP policy DNS", err: servePolicyDNSTCP(runCtx, dnsTCP, dnsHandler)}
	}()
	go func() {
		results <- serverResult{
			name: "snapshot integrity monitor",
			err: monitorGatewayIntegrity(runCtx, path, reference,
				options.UpstreamRoutePath, options.UpstreamRoute,
				options.AuthProfilesPath, options.AuthProfiles,
				options.SnapshotCheckInterval),
		}
	}()

	var first serverResult
	completed := 0
	select {
	case <-ctx.Done():
	case first = <-results:
		completed = 1
	}
	cancel()
	_ = server.Close()
	closeGatewayListeners(listener, dnsPacket, dnsTCP)
	for completed < 4 {
		result := <-results
		completed++
		if first.name == "" && result.err != nil && !errors.Is(result.err, http.ErrServerClosed) && !errors.Is(result.err, net.ErrClosed) {
			first = result
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if first.name == "" {
		return errors.New("egress gateway servers stopped unexpectedly")
	}
	if first.err == nil {
		return fmt.Errorf("%s stopped unexpectedly", first.name)
	}
	return fmt.Errorf("serve %s: %w", first.name, first.err)
}

func monitorGatewayIntegrity(ctx context.Context, path string, reference SnapshotReference, routePath string, routeReference *UpstreamRouteReference, authPath string, authReference *AuthProfilesReference, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := LoadSnapshot(path, reference); err != nil {
				return fmt.Errorf("revalidate immutable snapshot: %w", err)
			}
			if routeReference != nil {
				if _, err := LoadUpstreamRoute(routePath, *routeReference); err != nil {
					return fmt.Errorf("revalidate immutable upstream route: %w", err)
				}
			}
			if authReference != nil {
				if _, err := LoadAuthProfiles(authPath, *authReference); err != nil {
					return fmt.Errorf("revalidate immutable auth profiles: %w", err)
				}
			}
		}
	}
}

func CheckSnapshot(path string, reference SnapshotReference, output io.Writer) error {
	return CheckGateway(path, reference, "", nil, output)
}

func CheckGateway(path string, reference SnapshotReference, routePath string, routeReference *UpstreamRouteReference, output io.Writer) error {
	return CheckGatewayWithOptions(path, reference, GatewayOptions{
		UpstreamRoutePath: routePath, UpstreamRoute: routeReference,
	}, output)
}

func CheckGatewayWithOptions(path string, reference SnapshotReference, options GatewayOptions, output io.Writer) error {
	report, policy, err := LoadPolicySnapshot(path, reference)
	if err != nil {
		return err
	}
	if strings.TrimSpace(options.UpstreamRoutePath) != "" || options.UpstreamRoute != nil {
		if strings.TrimSpace(options.UpstreamRoutePath) == "" || options.UpstreamRoute == nil {
			return errors.New("egress upstream route path and reference must be configured together")
		}
		if _, err := LoadUpstreamRoute(options.UpstreamRoutePath, *options.UpstreamRoute); err != nil {
			return err
		}
		report.UpstreamRouteID = options.UpstreamRoute.ID
		report.UpstreamRouteSHA256 = options.UpstreamRoute.SHA256
	}
	var authDocument *AuthProfilesDocument
	if strings.TrimSpace(options.AuthProfilesPath) != "" || options.AuthProfiles != nil {
		if strings.TrimSpace(options.AuthProfilesPath) == "" || options.AuthProfiles == nil {
			return errors.New("egress auth profiles path and reference must be configured together")
		}
		document, err := LoadAuthProfiles(options.AuthProfilesPath, *options.AuthProfiles)
		if err != nil {
			return err
		}
		authDocument = &document
		report.AuthProfilesID = options.AuthProfiles.ID
		report.AuthProfilesSHA256 = options.AuthProfiles.SHA256
	}
	if _, err := authProfilesForPolicy(policy, authDocument); err != nil {
		return err
	}
	report.Event = "boundary_snapshot_healthy"
	if output == nil {
		return nil
	}
	return json.NewEncoder(output).Encode(report)
}
