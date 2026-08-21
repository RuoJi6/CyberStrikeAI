package egress

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	credentialEnvelopeVersion = "v1"
	credentialKeyBytes        = 32
	maxCredentialKeyFileBytes = 4096
)

var (
	ErrCredentialEnvelopeInvalid = errors.New("credential envelope is invalid")
	ErrCredentialKeyMismatch     = errors.New("credential envelope key does not match the configured key")
)

// ProxyCredentials is plaintext that may exist only at the control-plane and
// gateway boundaries. It must never be embedded in API response objects,
// snapshots exposed to an Agent, command lines, or container environments.
type ProxyCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// CredentialCipher seals proxy credentials with AES-256-GCM. The proxy ID is
// authenticated as AAD, so ciphertext copied between proxy records is rejected.
type CredentialCipher struct {
	aead  cipher.AEAD
	keyID string
}

func NewCredentialCipher(key []byte) (*CredentialCipher, error) {
	if len(key) != credentialKeyBytes {
		return nil, fmt.Errorf("egress credential key must be %d bytes", credentialKeyBytes)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create egress credential cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create egress credential GCM: %w", err)
	}
	digest := sha256.Sum256(key)
	return &CredentialCipher{
		aead:  aead,
		keyID: base64.RawURLEncoding.EncodeToString(digest[:12]),
	}, nil
}

func (c *CredentialCipher) Encrypt(proxyID string, plaintext []byte) (string, error) {
	if c == nil || c.aead == nil {
		return "", errors.New("egress credential cipher is not configured")
	}
	proxyID = strings.TrimSpace(proxyID)
	if proxyID == "" {
		return "", errors.New("proxy id is required for credential encryption")
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate egress credential nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, plaintext, credentialAAD(proxyID))
	return strings.Join([]string{
		credentialEnvelopeVersion,
		c.keyID,
		base64.RawURLEncoding.EncodeToString(sealed),
	}, "."), nil
}

func (c *CredentialCipher) Decrypt(proxyID, envelope string) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("egress credential cipher is not configured")
	}
	proxyID = strings.TrimSpace(proxyID)
	if proxyID == "" {
		return nil, errors.New("proxy id is required for credential decryption")
	}
	parts := strings.Split(strings.TrimSpace(envelope), ".")
	if len(parts) != 3 || parts[0] != credentialEnvelopeVersion || parts[1] == "" || parts[2] == "" {
		return nil, ErrCredentialEnvelopeInvalid
	}
	if parts[1] != c.keyID {
		return nil, ErrCredentialKeyMismatch
	}
	sealed, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sealed) < c.aead.NonceSize()+c.aead.Overhead() {
		return nil, ErrCredentialEnvelopeInvalid
	}
	nonce := sealed[:c.aead.NonceSize()]
	ciphertext := sealed[c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, credentialAAD(proxyID))
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed", ErrCredentialEnvelopeInvalid)
	}
	return plaintext, nil
}

func credentialAAD(proxyID string) []byte {
	return []byte("cyberstrike-egress-proxy:" + credentialEnvelopeVersion + ":" + proxyID)
}

// LoadOrCreateCredentialCipher loads a stable server-only key or creates one
// with mode 0600. Existing symlinks, non-regular files, or permissive modes are
// rejected instead of silently weakening the credential boundary.
func LoadOrCreateCredentialCipher(path string) (*CredentialCipher, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("egress credential key file is required")
	}
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("resolve egress credential key file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o700); err != nil {
		return nil, fmt.Errorf("create egress credential key directory: %w", err)
	}

	key, err := readCredentialKeyFile(cleanPath)
	if errors.Is(err, os.ErrNotExist) {
		key, err = createCredentialKeyFile(cleanPath)
		if errors.Is(err, os.ErrExist) {
			key, err = readCredentialKeyFile(cleanPath)
		}
	}
	if err != nil {
		return nil, err
	}
	return NewCredentialCipher(key)
}

func readCredentialKeyFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("egress credential key file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("egress credential key file must not be accessible by group or other users")
	}
	if info.Size() <= 0 || info.Size() > maxCredentialKeyFileBytes {
		return nil, errors.New("egress credential key file has an invalid size")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read egress credential key file: %w", err)
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(key) != credentialKeyBytes {
		return nil, errors.New("egress credential key file must contain one base64url-encoded 32-byte key")
	}
	return key, nil
}

func createCredentialKeyFile(path string) ([]byte, error) {
	key := make([]byte, credentialKeyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate egress credential key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(path)
		}
	}()
	encoded := base64.RawURLEncoding.EncodeToString(key) + "\n"
	if _, err := io.WriteString(f, encoded); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write egress credential key file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("sync egress credential key file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close egress credential key file: %w", err)
	}
	keep = true
	return key, nil
}
