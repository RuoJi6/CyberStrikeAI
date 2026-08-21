package egress

import (
	"bytes"
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
	"sort"
	"strings"
)

const (
	UpstreamRouteContainerPath = "/etc/cyberstrike/upstream.json"
	upstreamRouteSchemaVersion = 1
	maxUpstreamRouteBytes      = 1 << 20
)

var (
	ErrUpstreamRouteIntegrity = errors.New("egress upstream route integrity check failed")
	upstreamRouteIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

type UpstreamRouteReference struct {
	ID     string
	SHA256 string
}

// UpstreamEndpoint is private runtime material. Credentials are intentionally
// absent from every API projection and are written only to the trusted route
// store mounted into the egress gateway, never the Agent container.
type UpstreamEndpoint struct {
	ID       string           `json:"id"`
	Protocol UpstreamProtocol `json:"protocol"`
	Host     string           `json:"host"`
	Port     int              `json:"port"`
	Username string           `json:"username,omitempty"`
	Password string           `json:"password,omitempty"`
}

type UpstreamRouteMember struct {
	Proxy    UpstreamEndpoint `json:"proxy"`
	Priority int              `json:"priority"`
	Weight   int              `json:"weight"`
}

type UpstreamRouteGroup struct {
	ID               string                `json:"id"`
	FailureThreshold int                   `json:"failureThreshold"`
	CooldownSeconds  int                   `json:"cooldownSeconds"`
	Members          []UpstreamRouteMember `json:"members"`
}

// UpstreamRoute is the immutable gateway-only routing document. A route file
// exists only for proxy/group bindings; absence is the explicit direct mode.
type UpstreamRoute struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Mode          string              `json:"mode"`
	Proxy         *UpstreamEndpoint   `json:"proxy,omitempty"`
	Group         *UpstreamRouteGroup `json:"group,omitempty"`
}

type UpstreamRouteStore struct {
	root string
}

func NewUpstreamRouteStore(root string) (*UpstreamRouteStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("egress upstream route directory is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve egress upstream route directory: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create egress upstream route directory: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("inspect egress upstream route directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("egress upstream route directory must be a real directory")
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		return nil, fmt.Errorf("restrict egress upstream route directory permissions: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve egress upstream route directory symlinks: %w", err)
	}
	return &UpstreamRouteStore{root: filepath.Clean(real)}, nil
}

func (s *UpstreamRouteStore) Root() string {
	if s == nil {
		return ""
	}
	return s.root
}

func (s *UpstreamRouteStore) Path(reference UpstreamRouteReference) (string, error) {
	if s == nil || s.root == "" {
		return "", errors.New("egress upstream route store is not configured")
	}
	if err := validateUpstreamRouteReference(reference); err != nil {
		return "", err
	}
	return filepath.Join(s.root, reference.ID+".json"), nil
}

func (s *UpstreamRouteStore) Put(id string, route UpstreamRoute) (UpstreamRouteReference, string, error) {
	content, err := EncodeUpstreamRoute(route)
	if err != nil {
		return UpstreamRouteReference{}, "", err
	}
	digest := sha256.Sum256(content)
	reference := UpstreamRouteReference{ID: id, SHA256: "sha256:" + hex.EncodeToString(digest[:])}
	path, err := s.Path(reference)
	if err != nil {
		return UpstreamRouteReference{}, "", err
	}
	if existing, readErr := os.ReadFile(path); readErr == nil {
		if !bytes.Equal(existing, content) {
			return UpstreamRouteReference{}, "", fmt.Errorf("%w: immutable route content mismatch", ErrUpstreamRouteIntegrity)
		}
		if _, err := LoadUpstreamRoute(path, reference); err != nil {
			return UpstreamRouteReference{}, "", err
		}
		return reference, path, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return UpstreamRouteReference{}, "", fmt.Errorf("read existing egress upstream route: %w", readErr)
	}

	temporary, err := os.CreateTemp(s.root, ".upstream-*.tmp")
	if err != nil {
		return UpstreamRouteReference{}, "", fmt.Errorf("create egress upstream route temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return UpstreamRouteReference{}, "", fmt.Errorf("write egress upstream route: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return UpstreamRouteReference{}, "", fmt.Errorf("sync egress upstream route: %w", err)
	}
	// The parent directory is 0700. Read-only mode lets the non-root gateway
	// consume the bind mount without making it mutable on the host.
	if err := temporary.Chmod(0o444); err != nil {
		_ = temporary.Close()
		return UpstreamRouteReference{}, "", fmt.Errorf("make egress upstream route read-only: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return UpstreamRouteReference{}, "", fmt.Errorf("close egress upstream route: %w", err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return UpstreamRouteReference{}, "", fmt.Errorf("publish immutable egress upstream route: %w", err)
		}
		existing, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(existing, content) {
			return UpstreamRouteReference{}, "", fmt.Errorf("%w: concurrently published route differs", ErrUpstreamRouteIntegrity)
		}
	}
	if _, err := LoadUpstreamRoute(path, reference); err != nil {
		return UpstreamRouteReference{}, "", err
	}
	return reference, path, nil
}

func EncodeUpstreamRoute(route UpstreamRoute) ([]byte, error) {
	if err := validateUpstreamRoute(&route); err != nil {
		return nil, err
	}
	content, err := json.Marshal(route)
	if err != nil {
		return nil, fmt.Errorf("encode egress upstream route: %w", err)
	}
	return content, nil
}

func LoadUpstreamRoute(path string, reference UpstreamRouteReference) (UpstreamRoute, error) {
	if err := validateUpstreamRouteReference(reference); err != nil {
		return UpstreamRoute{}, err
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return UpstreamRoute{}, fmt.Errorf("open egress upstream route: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return UpstreamRoute{}, fmt.Errorf("stat egress upstream route: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 || info.Size() < 2 || info.Size() > maxUpstreamRouteBytes {
		return UpstreamRoute{}, fmt.Errorf("%w: route file type or size is invalid", ErrUpstreamRouteIntegrity)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxUpstreamRouteBytes+1))
	if err != nil {
		return UpstreamRoute{}, fmt.Errorf("read egress upstream route: %w", err)
	}
	digest := sha256.Sum256(content)
	actual := "sha256:" + hex.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(reference.SHA256)) != 1 {
		return UpstreamRoute{}, fmt.Errorf("%w: SHA-256 mismatch", ErrUpstreamRouteIntegrity)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var route UpstreamRoute
	if err := decoder.Decode(&route); err != nil {
		return UpstreamRoute{}, fmt.Errorf("%w: decode route", ErrUpstreamRouteIntegrity)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return UpstreamRoute{}, fmt.Errorf("%w: route contains trailing data", ErrUpstreamRouteIntegrity)
	}
	if err := validateUpstreamRoute(&route); err != nil {
		return UpstreamRoute{}, fmt.Errorf("%w: %v", ErrUpstreamRouteIntegrity, err)
	}
	canonical, err := json.Marshal(route)
	if err != nil || !bytes.Equal(canonical, content) {
		return UpstreamRoute{}, fmt.Errorf("%w: route JSON is not canonical", ErrUpstreamRouteIntegrity)
	}
	return route, nil
}

func validateUpstreamRouteReference(reference UpstreamRouteReference) error {
	if reference.ID != strings.TrimSpace(reference.ID) || !upstreamRouteIDPattern.MatchString(reference.ID) {
		return fmt.Errorf("%w: route id is invalid", ErrUpstreamRouteIntegrity)
	}
	if reference.SHA256 != strings.TrimSpace(reference.SHA256) || !snapshotDigestPattern.MatchString(reference.SHA256) {
		return fmt.Errorf("%w: route digest is invalid", ErrUpstreamRouteIntegrity)
	}
	return nil
}

func validateUpstreamRoute(route *UpstreamRoute) error {
	if route == nil || route.SchemaVersion != upstreamRouteSchemaVersion {
		return errors.New("egress upstream route schema version is invalid")
	}
	switch route.Mode {
	case "proxy":
		if route.Proxy == nil || route.Group != nil {
			return errors.New("proxy route requires exactly one proxy")
		}
		return validateUpstreamEndpoint(*route.Proxy)
	case "group":
		if route.Proxy != nil || route.Group == nil {
			return errors.New("group route requires exactly one proxy group")
		}
		group := route.Group
		if !upstreamRouteIDPattern.MatchString(strings.TrimSpace(group.ID)) || group.ID != strings.TrimSpace(group.ID) {
			return errors.New("upstream proxy group id is invalid")
		}
		if err := ValidateProxyGroupFailureThreshold(group.FailureThreshold); err != nil {
			return err
		}
		if err := ValidateProxyGroupCooldownSeconds(group.CooldownSeconds); err != nil {
			return err
		}
		if len(group.Members) < 1 || len(group.Members) > MaxProxyGroupMembers {
			return fmt.Errorf("upstream proxy group must contain between 1 and %d members", MaxProxyGroupMembers)
		}
		seen := make(map[string]struct{}, len(group.Members))
		for index, member := range group.Members {
			if err := validateUpstreamEndpoint(member.Proxy); err != nil {
				return err
			}
			if err := ValidateProxyGroupMember(member.Priority, member.Weight); err != nil {
				return err
			}
			if _, duplicate := seen[member.Proxy.ID]; duplicate {
				return errors.New("upstream proxy group contains a duplicate proxy")
			}
			seen[member.Proxy.ID] = struct{}{}
			if index > 0 {
				previous := group.Members[index-1]
				if previous.Priority > member.Priority || (previous.Priority == member.Priority && previous.Proxy.ID >= member.Proxy.ID) {
					return errors.New("upstream proxy group members are not canonically ordered")
				}
			}
		}
		return nil
	default:
		return errors.New("egress upstream route mode must be proxy or group")
	}
}

func validateUpstreamEndpoint(endpoint UpstreamEndpoint) error {
	if endpoint.ID != strings.TrimSpace(endpoint.ID) || !upstreamRouteIDPattern.MatchString(endpoint.ID) {
		return errors.New("upstream proxy id is invalid")
	}
	protocol, err := ParseUpstreamProtocol(string(endpoint.Protocol))
	if err != nil || protocol != endpoint.Protocol {
		return errors.New("upstream proxy protocol is invalid")
	}
	host, err := NormalizeUpstreamHost(endpoint.Host)
	if err != nil || host != endpoint.Host {
		return errors.New("upstream proxy host is not canonical")
	}
	if err := ValidateUpstreamPort(endpoint.Port); err != nil {
		return err
	}
	if endpoint.Username == "" && endpoint.Password != "" {
		return errors.New("upstream proxy password requires a username")
	}
	if protocol == UpstreamProtocolSOCKS5 && (len(endpoint.Username) > 255 || len(endpoint.Password) > 255) {
		return errors.New("SOCKS5 username and password must not exceed 255 bytes")
	}
	return nil
}

func NewProxyUpstreamRoute(proxy UpstreamEndpoint) UpstreamRoute {
	return UpstreamRoute{SchemaVersion: upstreamRouteSchemaVersion, Mode: "proxy", Proxy: &proxy}
}

func NewProxyGroupUpstreamRoute(group UpstreamRouteGroup) UpstreamRoute {
	sort.Slice(group.Members, func(i, j int) bool {
		if group.Members[i].Priority != group.Members[j].Priority {
			return group.Members[i].Priority < group.Members[j].Priority
		}
		return group.Members[i].Proxy.ID < group.Members[j].Proxy.ID
	})
	return UpstreamRoute{SchemaVersion: upstreamRouteSchemaVersion, Mode: "group", Group: &group}
}
