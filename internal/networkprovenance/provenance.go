package networkprovenance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	Version = 1

	RuntimeModeContainer = "container"
	RuntimeModeHostMITM  = "host_mitm"

	AttributionVerified           = "verified"
	AttributionLegacyUnattributed = "legacy_unattributed"
	AttributionUnattributed       = "unattributed"
	AttributionInvalid            = "invalid"

	ActivityKindNormal  = "normal"
	ActivityKindFuzz    = "fuzz"
	ActivityKindUnknown = "unknown"

	ObservedSingle    = "single"
	ObservedBurst     = "burst"
	ObservedPathSweep = "path_sweep"

	defaultTokenTTL = 6 * time.Hour
	maximumTokenTTL = 24 * time.Hour
	clockSkew       = 30 * time.Second
	maximumTokenLen = 4096
)

// NetworkProvenanceV1 is the canonical, bounded execution identity attached
// to HTTP/HTTPS traffic. AttributionStatus describes whether the origin was
// cryptographically verified; activity labels never upgrade that status.
type NetworkProvenanceV1 struct {
	Version              int    `json:"version"`
	ConversationID       string `json:"conversationId,omitempty"`
	RuntimeMode          string `json:"runtimeMode"`
	RuntimeGeneration    int    `json:"runtimeGeneration,omitempty"`
	RuntimeInstanceID    string `json:"runtimeInstanceId,omitempty"`
	AgentID              string `json:"agentId,omitempty"`
	ToolName             string `json:"toolName,omitempty"`
	ExecutionID          string `json:"executionId,omitempty"`
	ToolCallID           string `json:"toolCallId,omitempty"`
	ActivityScopeID      string `json:"activityScopeId,omitempty"`
	AttributionStatus    string `json:"attributionStatus"`
	DeclaredActivityKind string `json:"declaredActivityKind"`
	ObservedActivityKind string `json:"observedActivityKind"`
}

func (p NetworkProvenanceV1) Normalized() NetworkProvenanceV1 {
	p.Version = Version
	p.ConversationID = bounded(p.ConversationID, 128)
	p.RuntimeInstanceID = bounded(p.RuntimeInstanceID, 128)
	p.AgentID = bounded(p.AgentID, 128)
	p.ToolName = bounded(p.ToolName, 256)
	p.ExecutionID = bounded(p.ExecutionID, 128)
	p.ToolCallID = bounded(p.ToolCallID, 128)
	p.ActivityScopeID = bounded(p.ActivityScopeID, 128)
	if p.ActivityScopeID == "" {
		p.ActivityScopeID = p.ToolCallID
	}
	if p.ActivityScopeID == "" {
		p.ActivityScopeID = p.ExecutionID
	}
	switch strings.ToLower(strings.TrimSpace(p.RuntimeMode)) {
	case RuntimeModeContainer:
		p.RuntimeMode = RuntimeModeContainer
	case RuntimeModeHostMITM, "host":
		p.RuntimeMode = RuntimeModeHostMITM
	default:
		p.RuntimeMode = ""
	}
	switch strings.ToLower(strings.TrimSpace(p.AttributionStatus)) {
	case AttributionVerified, AttributionLegacyUnattributed, AttributionUnattributed, AttributionInvalid:
		p.AttributionStatus = strings.ToLower(strings.TrimSpace(p.AttributionStatus))
	default:
		p.AttributionStatus = AttributionUnattributed
	}
	switch strings.ToLower(strings.TrimSpace(p.DeclaredActivityKind)) {
	case ActivityKindNormal, ActivityKindFuzz:
		p.DeclaredActivityKind = strings.ToLower(strings.TrimSpace(p.DeclaredActivityKind))
	default:
		p.DeclaredActivityKind = ActivityKindUnknown
	}
	switch strings.ToLower(strings.TrimSpace(p.ObservedActivityKind)) {
	case ObservedSingle, ObservedBurst, ObservedPathSweep:
		p.ObservedActivityKind = strings.ToLower(strings.TrimSpace(p.ObservedActivityKind))
	default:
		p.ObservedActivityKind = ObservedSingle
	}
	if p.RuntimeGeneration < 0 {
		p.RuntimeGeneration = 0
	}
	return p
}

func (p NetworkProvenanceV1) ValidVerified() bool {
	p = p.Normalized()
	return p.AttributionStatus == AttributionVerified && p.ConversationID != "" && p.RuntimeMode != "" &&
		p.RuntimeInstanceID != "" && p.AgentID != "" && p.ToolName != "" && p.ExecutionID != "" && p.ActivityScopeID != ""
}

func bounded(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > limit || strings.ContainsAny(value, "\r\n\x00") {
		return ""
	}
	return value
}

type contextKey struct{}

func WithContext(ctx context.Context, provenance NetworkProvenanceV1) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, contextKey{}, provenance.Normalized())
}

func FromContext(ctx context.Context) NetworkProvenanceV1 {
	if ctx == nil {
		return NetworkProvenanceV1{}.Normalized()
	}
	value, _ := ctx.Value(contextKey{}).(NetworkProvenanceV1)
	return value.Normalized()
}

type tokenClaims struct {
	KeyID      string              `json:"kid"`
	IssuedAt   int64               `json:"iat"`
	ExpiresAt  int64               `json:"exp"`
	Nonce      string              `json:"nonce"`
	Provenance NetworkProvenanceV1 `json:"provenance"`
}

type ExpectedAudience struct {
	ConversationID    string
	RuntimeMode       string
	RuntimeGeneration int
	RuntimeInstanceID string
}

// ForAudience returns a runtime-bound provenance value without inventing an
// execution identity. It is used for gateway-originated DNS/packet/health
// observations and for rejected HTTP credentials, where the runtime is known
// but the originating execution is not verified.
func ForAudience(expected ExpectedAudience, status string) NetworkProvenanceV1 {
	return NetworkProvenanceV1{
		ConversationID:    expected.ConversationID,
		RuntimeMode:       expected.RuntimeMode,
		RuntimeGeneration: expected.RuntimeGeneration,
		RuntimeInstanceID: expected.RuntimeInstanceID,
		AttributionStatus: status,
	}.Normalized()
}

// BindAudience fills only trusted runtime fields that are absent. Existing
// execution claims are preserved so a verified HTTP request keeps its exact
// identity while non-HTTP gateway events remain explicitly unattributed.
func BindAudience(provenance NetworkProvenanceV1, expected ExpectedAudience) NetworkProvenanceV1 {
	provenance = provenance.Normalized()
	if provenance.ConversationID == "" {
		provenance.ConversationID = expected.ConversationID
	}
	if provenance.RuntimeMode == "" {
		provenance.RuntimeMode = expected.RuntimeMode
	}
	if provenance.RuntimeGeneration == 0 {
		provenance.RuntimeGeneration = expected.RuntimeGeneration
	}
	if provenance.RuntimeInstanceID == "" {
		provenance.RuntimeInstanceID = expected.RuntimeInstanceID
	}
	return provenance.Normalized()
}

type Signer struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	keyID   string
	now     func() time.Time
}

func NewSigner(private ed25519.PrivateKey) (*Signer, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("network provenance Ed25519 private key is invalid")
	}
	copyPrivate := append(ed25519.PrivateKey(nil), private...)
	public := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	digest := sha256.Sum256(public)
	return &Signer{private: copyPrivate, public: public, keyID: base64.RawURLEncoding.EncodeToString(digest[:12]), now: time.Now}, nil
}

func GenerateSigner() (*Signer, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate network provenance key: %w", err)
	}
	return NewSigner(private)
}

func (s *Signer) PublicKeyEncoded() string {
	if s == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(s.public)
}

func (s *Signer) Verifier() (*Verifier, error) {
	if s == nil {
		return nil, errors.New("network provenance signer is unavailable")
	}
	return NewVerifier(s.PublicKeyEncoded())
}

func (s *Signer) Issue(provenance NetworkProvenanceV1, deadline time.Time) (string, error) {
	if s == nil || len(s.private) != ed25519.PrivateKeySize {
		return "", errors.New("network provenance signer is unavailable")
	}
	now := s.now().UTC()
	expiresAt := deadline.UTC()
	if expiresAt.IsZero() || !expiresAt.After(now) {
		expiresAt = now.Add(defaultTokenTTL)
	}
	if maximum := now.Add(maximumTokenTTL); expiresAt.After(maximum) {
		expiresAt = maximum
	}
	provenance = provenance.Normalized()
	provenance.AttributionStatus = AttributionVerified
	if !provenance.ValidVerified() {
		return "", errors.New("network provenance is incomplete")
	}
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate network provenance nonce: %w", err)
	}
	claims := tokenClaims{
		KeyID: s.keyID, IssuedAt: now.Unix(), ExpiresAt: expiresAt.Unix(),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), Provenance: provenance,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode network provenance token: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(s.private, []byte("v1."+encoded))
	return "v1." + encoded + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

type Verifier struct {
	public ed25519.PublicKey
	keyID  string
	now    func() time.Time
}

func NewVerifier(encodedPublicKey string) (*Verifier, error) {
	public, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encodedPublicKey))
	if err != nil || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("network provenance Ed25519 public key is invalid")
	}
	digest := sha256.Sum256(public)
	return &Verifier{public: append(ed25519.PublicKey(nil), public...), keyID: base64.RawURLEncoding.EncodeToString(digest[:12]), now: time.Now}, nil
}

func (v *Verifier) Verify(token string, expected ExpectedAudience) (NetworkProvenanceV1, error) {
	invalid := NetworkProvenanceV1{AttributionStatus: AttributionInvalid}.Normalized()
	if v == nil || len(v.public) != ed25519.PublicKeySize {
		return invalid, errors.New("network provenance verifier is unavailable")
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) > maximumTokenLen {
		return invalid, errors.New("network provenance token is missing or oversized")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return invalid, errors.New("network provenance token format is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return invalid, errors.New("network provenance token payload is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(v.public, []byte("v1."+parts[1]), signature) {
		return invalid, errors.New("network provenance token signature is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var claims tokenClaims
	if err := decoder.Decode(&claims); err != nil {
		return invalid, errors.New("network provenance token claims are invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return invalid, errors.New("network provenance token has trailing data")
	}
	now := v.now().UTC()
	if claims.KeyID != v.keyID || claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt || claims.Nonce == "" ||
		time.Unix(claims.IssuedAt, 0).After(now.Add(clockSkew)) || time.Unix(claims.ExpiresAt, 0).Before(now.Add(-clockSkew)) ||
		time.Unix(claims.ExpiresAt, 0).After(time.Unix(claims.IssuedAt, 0).Add(maximumTokenTTL)) {
		return invalid, errors.New("network provenance token lifetime is invalid")
	}
	provenance := claims.Provenance.Normalized()
	provenance.AttributionStatus = AttributionVerified
	if !provenance.ValidVerified() ||
		(expected.ConversationID != "" && provenance.ConversationID != expected.ConversationID) ||
		(expected.RuntimeMode != "" && provenance.RuntimeMode != NetworkProvenanceV1{RuntimeMode: expected.RuntimeMode}.Normalized().RuntimeMode) ||
		(expected.RuntimeGeneration > 0 && provenance.RuntimeGeneration != expected.RuntimeGeneration) ||
		(expected.RuntimeInstanceID != "" && provenance.RuntimeInstanceID != expected.RuntimeInstanceID) {
		return invalid, errors.New("network provenance token audience is invalid")
	}
	return provenance, nil
}

// LoadOrCreateSigner persists a stable server-only seed. Symlinks, non-regular
// files, and group/other-readable keys are rejected.
func LoadOrCreateSigner(path string) (*Signer, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("network provenance signing key path is required")
	}
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("network provenance signing key must be a private regular file")
		}
		encoded, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("read network provenance signing key: %w", readErr)
		}
		seed, decodeErr := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		if decodeErr != nil || len(seed) != ed25519.SeedSize {
			return nil, errors.New("network provenance signing key is invalid")
		}
		return NewSigner(ed25519.NewKeyFromSeed(seed))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect network provenance signing key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create network provenance key directory: %w", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("generate network provenance signing seed: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadOrCreateSigner(path)
		}
		return nil, fmt.Errorf("create network provenance signing key: %w", err)
	}
	encoded := base64.RawStdEncoding.EncodeToString(seed) + "\n"
	if _, err := file.WriteString(encoded); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write network provenance signing key: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("sync network provenance signing key: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close network provenance signing key: %w", err)
	}
	return NewSigner(ed25519.NewKeyFromSeed(seed))
}
