package egress

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var tlsAuthorityIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type TLSAuthorityReference struct {
	ID                string
	CertificateSHA256 string
	PrivateKeySHA256  string
}

type TLSAuthorityStore struct{ root string }

func NewTLSAuthorityStore(root string) (*TLSAuthorityStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("TLS authority directory is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve TLS authority directory: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create TLS authority directory: %w", err)
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		return nil, fmt.Errorf("restrict TLS authority directory: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("TLS authority directory must be a real directory")
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve TLS authority directory symlinks: %w", err)
	}
	return &TLSAuthorityStore{root: filepath.Clean(real)}, nil
}

func (store *TLSAuthorityStore) Root() string {
	if store == nil {
		return ""
	}
	return store.root
}

func (store *TLSAuthorityStore) Paths(reference TLSAuthorityReference) (string, string, error) {
	if store == nil || store.root == "" {
		return "", "", errors.New("TLS authority store is not configured")
	}
	if err := validateTLSAuthorityReference(reference); err != nil {
		return "", "", err
	}
	return filepath.Join(store.root, reference.ID+".crt"), filepath.Join(store.root, reference.ID+".key"), nil
}

func (store *TLSAuthorityStore) Put(id string, authority *TLSAuthority) (TLSAuthorityReference, string, string, error) {
	if authority == nil {
		return TLSAuthorityReference{}, "", "", errors.New("TLS authority is required")
	}
	reference := TLSAuthorityReference{
		ID: strings.TrimSpace(id), CertificateSHA256: digestPEM(authority.CertificatePEM),
		PrivateKeySHA256: digestPEM(authority.PrivateKeyPEM),
	}
	certificatePath, keyPath, err := store.Paths(reference)
	if err != nil {
		return TLSAuthorityReference{}, "", "", err
	}
	if certificatePEM, certificateErr := os.ReadFile(certificatePath); certificateErr == nil {
		if privateKeyPEM, keyErr := os.ReadFile(keyPath); keyErr == nil {
			existing := TLSAuthorityReference{ID: reference.ID, CertificateSHA256: digestPEM(certificatePEM), PrivateKeySHA256: digestPEM(privateKeyPEM)}
			if _, _, loadErr := LoadTLSAuthority(certificatePath, keyPath, existing, time.Now().UTC()); loadErr != nil {
				return TLSAuthorityReference{}, "", "", loadErr
			}
			return existing, certificatePath, keyPath, nil
		}
	}
	if err := publishReadOnlyFile(store.root, keyPath, authority.PrivateKeyPEM); err != nil {
		return TLSAuthorityReference{}, "", "", fmt.Errorf("publish TLS authority key: %w", err)
	}
	if err := publishReadOnlyFile(store.root, certificatePath, authority.CertificatePEM); err != nil {
		return TLSAuthorityReference{}, "", "", fmt.Errorf("publish TLS authority certificate: %w", err)
	}
	if _, _, err := LoadTLSAuthority(certificatePath, keyPath, reference, time.Now().UTC()); err != nil {
		return TLSAuthorityReference{}, "", "", err
	}
	return reference, certificatePath, keyPath, nil
}

func LoadTLSAuthority(certificatePath, keyPath string, reference TLSAuthorityReference, now time.Time) (*TLSAuthority, []byte, error) {
	if err := validateTLSAuthorityReference(reference); err != nil {
		return nil, nil, err
	}
	certificatePEM, err := readReadOnlyFile(certificatePath, 64<<10)
	if err != nil {
		return nil, nil, fmt.Errorf("read TLS authority certificate: %w", err)
	}
	privateKeyPEM, err := readReadOnlyFile(keyPath, 64<<10)
	if err != nil {
		return nil, nil, fmt.Errorf("read TLS authority private key: %w", err)
	}
	if !digestMatches(certificatePEM, reference.CertificateSHA256) || !digestMatches(privateKeyPEM, reference.PrivateKeySHA256) {
		return nil, nil, errors.New("TLS authority digest mismatch")
	}
	authority, err := ParseTLSAuthority(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !now.UTC().Before(authority.Certificate.NotAfter) {
		return nil, nil, errors.New("TLS authority has expired")
	}
	return authority, append([]byte(nil), certificatePEM...), nil
}

func validateTLSAuthorityReference(reference TLSAuthorityReference) error {
	if !tlsAuthorityIDPattern.MatchString(reference.ID) || !snapshotDigestPattern.MatchString(reference.CertificateSHA256) || !snapshotDigestPattern.MatchString(reference.PrivateKeySHA256) {
		return errors.New("TLS authority reference is invalid")
	}
	return nil
}

func publishReadOnlyFile(root, target string, content []byte) error {
	if existing, err := os.ReadFile(target); err == nil {
		if bytes.Equal(existing, content) {
			return nil
		}
		return errors.New("immutable TLS authority file differs")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(root, ".tls-authority-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o444); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, target); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, readErr := os.ReadFile(target)
		if readErr != nil || !bytes.Equal(existing, content) {
			return errors.New("concurrently published TLS authority differs")
		}
	}
	return nil
}

func readReadOnlyFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 || info.Size() < 1 || info.Size() > maximum {
		return nil, errors.New("trusted TLS authority file type, mode or size is invalid")
	}
	return io.ReadAll(io.LimitReader(file, maximum+1))
}

func digestPEM(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func digestMatches(content []byte, expected string) bool {
	actual := digestPEM(content)
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}
