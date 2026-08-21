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
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	AuthProfilesContainerPath = "/etc/cyberstrike/auth-profiles.json"
	authProfilesSchemaVersion = 1
	maxAuthProfilesBytes      = 1 << 20
	MaxAuthProfileSecretBytes = 4096
	maxAuthProfiles           = 256
)

var (
	ErrAuthProfilesIntegrity = errors.New("egress auth profiles integrity check failed")
	authProfileIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	headerNamePattern        = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
)

type AuthProfilesReference struct {
	ID     string
	SHA256 string
}

// GatewayAuthProfile is secret runtime material. It is written only to the
// trusted host store and mounted into the gateway, never the Agent container.
type GatewayAuthProfile struct {
	ID          string `json:"id"`
	HeaderName  string `json:"headerName"`
	HeaderValue string `json:"headerValue"`
}

// AuthProfilesDocument contains exactly the profiles referenced by one bound
// policy. BindingSalt is derived from encrypted envelopes, preventing the
// public integrity digest from becoming a useful plaintext-secret oracle.
type AuthProfilesDocument struct {
	SchemaVersion int                  `json:"schemaVersion"`
	BindingSalt   string               `json:"bindingSalt"`
	Profiles      []GatewayAuthProfile `json:"profiles"`
}

type AuthProfilesStore struct {
	root string
}

func NewAuthProfilesStore(root string) (*AuthProfilesStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("egress auth profiles directory is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve egress auth profiles directory: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create egress auth profiles directory: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("inspect egress auth profiles directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("egress auth profiles directory must be a real directory")
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		return nil, fmt.Errorf("restrict egress auth profiles directory permissions: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve egress auth profiles directory symlinks: %w", err)
	}
	return &AuthProfilesStore{root: filepath.Clean(real)}, nil
}

func (s *AuthProfilesStore) Root() string {
	if s == nil {
		return ""
	}
	return s.root
}

func (s *AuthProfilesStore) Path(reference AuthProfilesReference) (string, error) {
	if s == nil || s.root == "" {
		return "", errors.New("egress auth profiles store is not configured")
	}
	if err := validateAuthProfilesReference(reference); err != nil {
		return "", err
	}
	return filepath.Join(s.root, reference.ID+".json"), nil
}

func (s *AuthProfilesStore) Put(id string, document AuthProfilesDocument) (AuthProfilesReference, string, error) {
	content, err := EncodeAuthProfiles(document)
	if err != nil {
		return AuthProfilesReference{}, "", err
	}
	digest := sha256.Sum256(content)
	reference := AuthProfilesReference{ID: id, SHA256: "sha256:" + hex.EncodeToString(digest[:])}
	path, err := s.Path(reference)
	if err != nil {
		return AuthProfilesReference{}, "", err
	}
	if existing, readErr := os.ReadFile(path); readErr == nil {
		if !bytes.Equal(existing, content) {
			return AuthProfilesReference{}, "", fmt.Errorf("%w: immutable auth profiles content mismatch", ErrAuthProfilesIntegrity)
		}
		if _, err := LoadAuthProfiles(path, reference); err != nil {
			return AuthProfilesReference{}, "", err
		}
		return reference, path, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return AuthProfilesReference{}, "", fmt.Errorf("read existing egress auth profiles: %w", readErr)
	}
	temporary, err := os.CreateTemp(s.root, ".auth-profiles-*.tmp")
	if err != nil {
		return AuthProfilesReference{}, "", fmt.Errorf("create egress auth profiles temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return AuthProfilesReference{}, "", fmt.Errorf("write egress auth profiles: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return AuthProfilesReference{}, "", fmt.Errorf("sync egress auth profiles: %w", err)
	}
	if err := temporary.Chmod(0o444); err != nil {
		_ = temporary.Close()
		return AuthProfilesReference{}, "", fmt.Errorf("make egress auth profiles read-only: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return AuthProfilesReference{}, "", fmt.Errorf("close egress auth profiles: %w", err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return AuthProfilesReference{}, "", fmt.Errorf("publish immutable egress auth profiles: %w", err)
		}
		existing, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(existing, content) {
			return AuthProfilesReference{}, "", fmt.Errorf("%w: concurrently published auth profiles differ", ErrAuthProfilesIntegrity)
		}
	}
	if _, err := LoadAuthProfiles(path, reference); err != nil {
		return AuthProfilesReference{}, "", err
	}
	return reference, path, nil
}

func EncodeAuthProfiles(document AuthProfilesDocument) ([]byte, error) {
	if err := validateAuthProfilesDocument(&document); err != nil {
		return nil, err
	}
	content, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode egress auth profiles: %w", err)
	}
	return content, nil
}

func LoadAuthProfiles(path string, reference AuthProfilesReference) (AuthProfilesDocument, error) {
	if err := validateAuthProfilesReference(reference); err != nil {
		return AuthProfilesDocument{}, err
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return AuthProfilesDocument{}, fmt.Errorf("open egress auth profiles: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return AuthProfilesDocument{}, fmt.Errorf("stat egress auth profiles: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 || info.Size() < 2 || info.Size() > maxAuthProfilesBytes {
		return AuthProfilesDocument{}, fmt.Errorf("%w: auth profiles file type or size is invalid", ErrAuthProfilesIntegrity)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxAuthProfilesBytes+1))
	if err != nil {
		return AuthProfilesDocument{}, fmt.Errorf("read egress auth profiles: %w", err)
	}
	digest := sha256.Sum256(content)
	actual := "sha256:" + hex.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(reference.SHA256)) != 1 {
		return AuthProfilesDocument{}, fmt.Errorf("%w: SHA-256 mismatch", ErrAuthProfilesIntegrity)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document AuthProfilesDocument
	if err := decoder.Decode(&document); err != nil {
		return AuthProfilesDocument{}, fmt.Errorf("%w: decode auth profiles", ErrAuthProfilesIntegrity)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return AuthProfilesDocument{}, fmt.Errorf("%w: auth profiles contain trailing data", ErrAuthProfilesIntegrity)
	}
	if err := validateAuthProfilesDocument(&document); err != nil {
		return AuthProfilesDocument{}, fmt.Errorf("%w: %v", ErrAuthProfilesIntegrity, err)
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, content) {
		return AuthProfilesDocument{}, fmt.Errorf("%w: auth profiles JSON is not canonical", ErrAuthProfilesIntegrity)
	}
	return document, nil
}

func validateAuthProfilesReference(reference AuthProfilesReference) error {
	if reference.ID != strings.TrimSpace(reference.ID) || !authProfileIDPattern.MatchString(reference.ID) {
		return fmt.Errorf("%w: auth profiles id is invalid", ErrAuthProfilesIntegrity)
	}
	if reference.SHA256 != strings.TrimSpace(reference.SHA256) || !snapshotDigestPattern.MatchString(reference.SHA256) {
		return fmt.Errorf("%w: auth profiles digest is invalid", ErrAuthProfilesIntegrity)
	}
	return nil
}

func validateAuthProfilesDocument(document *AuthProfilesDocument) error {
	if document == nil || document.SchemaVersion != authProfilesSchemaVersion {
		return errors.New("egress auth profiles schema version is invalid")
	}
	if len(document.BindingSalt) != 64 {
		return errors.New("egress auth profiles binding salt is invalid")
	}
	if _, err := hex.DecodeString(document.BindingSalt); err != nil || strings.ToLower(document.BindingSalt) != document.BindingSalt {
		return errors.New("egress auth profiles binding salt is invalid")
	}
	if len(document.Profiles) < 1 || len(document.Profiles) > maxAuthProfiles {
		return fmt.Errorf("egress auth profiles must contain between 1 and %d profiles", maxAuthProfiles)
	}
	for index, profile := range document.Profiles {
		if err := ValidateAuthProfileID(profile.ID); err != nil {
			return errors.New("egress auth profile id is invalid")
		}
		canonicalName, err := ValidateAuthHeaderName(profile.HeaderName)
		if err != nil || canonicalName != profile.HeaderName {
			return errors.New("egress auth profile header name is not canonical")
		}
		if err := ValidateAuthHeaderValue(profile.HeaderValue); err != nil {
			return err
		}
		if index > 0 && document.Profiles[index-1].ID >= profile.ID {
			return errors.New("egress auth profiles are not canonically ordered")
		}
	}
	return nil
}

func ValidateAuthProfileID(value string) error {
	if value != strings.TrimSpace(value) || !authProfileIDPattern.MatchString(value) {
		return errors.New("auth profile id is invalid")
	}
	return nil
}

func ValidateAuthHeaderName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || !headerNamePattern.MatchString(value) {
		return "", errors.New("auth profile header name is invalid")
	}
	canonical := textproto.CanonicalMIMEHeaderKey(value)
	lower := strings.ToLower(canonical)
	forbidden := map[string]struct{}{
		"connection": {}, "proxy-connection": {}, "keep-alive": {}, "proxy-authenticate": {},
		"proxy-authorization": {}, "te": {}, "trailer": {}, "transfer-encoding": {}, "upgrade": {},
		"host": {}, "content-length": {}, "forwarded": {}, "x-forwarded-for": {},
		"x-forwarded-host": {}, "x-forwarded-proto": {},
	}
	if _, found := forbidden[lower]; found {
		return "", errors.New("auth profile header name is not permitted")
	}
	return canonical, nil
}

func ValidateAuthHeaderValue(value string) error {
	if value == "" || len(value) > MaxAuthProfileSecretBytes || !utf8.ValidString(value) {
		return fmt.Errorf("auth profile credential must be valid UTF-8 and between 1 and %d bytes", MaxAuthProfileSecretBytes)
	}
	if strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("auth profile credential contains a control character")
	}
	return nil
}

func NewAuthProfilesDocument(bindingSalt string, profiles []GatewayAuthProfile) AuthProfilesDocument {
	copyProfiles := append([]GatewayAuthProfile(nil), profiles...)
	sort.Slice(copyProfiles, func(i, j int) bool { return copyProfiles[i].ID < copyProfiles[j].ID })
	return AuthProfilesDocument{SchemaVersion: authProfilesSchemaVersion, BindingSalt: bindingSalt, Profiles: copyProfiles}
}

func (document AuthProfilesDocument) profileMap() map[string]GatewayAuthProfile {
	profiles := make(map[string]GatewayAuthProfile, len(document.Profiles))
	for _, profile := range document.Profiles {
		profiles[profile.ID] = profile
	}
	return profiles
}

func applyAuthProfile(header http.Header, profile GatewayAuthProfile) {
	header.Del(profile.HeaderName)
	header.Set(profile.HeaderName, profile.HeaderValue)
}
