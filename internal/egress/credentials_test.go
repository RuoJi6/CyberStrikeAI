package egress

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialCipherRoundTripAndRecordBinding(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, credentialKeyBytes)
	cipher, err := NewCredentialCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"username":"alice","password":"proxy-secret"}`)
	envelope, err := cipher.Encrypt("proxy-1", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(envelope, "alice") || strings.Contains(envelope, "proxy-secret") {
		t.Fatalf("credential envelope contains plaintext: %q", envelope)
	}
	got, err := cipher.Decrypt("proxy-1", envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q, want %q", got, plaintext)
	}
	if _, err := cipher.Decrypt("proxy-2", envelope); !errors.Is(err, ErrCredentialEnvelopeInvalid) {
		t.Fatalf("cross-record decrypt error = %v", err)
	}
}

func TestCredentialCipherRejectsTamperAndWrongKey(t *testing.T) {
	cipher, err := NewCredentialCipher(bytes.Repeat([]byte{0x11}, credentialKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cipher.Encrypt("proxy-1", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(envelope, ".")
	sealed, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0x01
	parts[2] = base64.RawURLEncoding.EncodeToString(sealed)
	tampered := strings.Join(parts, ".")
	if _, err := cipher.Decrypt("proxy-1", tampered); !errors.Is(err, ErrCredentialEnvelopeInvalid) {
		t.Fatalf("tamper error = %v", err)
	}
	wrong, err := NewCredentialCipher(bytes.Repeat([]byte{0x22}, credentialKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Decrypt("proxy-1", envelope); !errors.Is(err, ErrCredentialKeyMismatch) {
		t.Fatalf("wrong-key error = %v", err)
	}
}

func TestLoadOrCreateCredentialCipherPersistsSecureKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "egress.key")
	first, err := LoadOrCreateCredentialCipher(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("key mode = %#o, want 0600", got)
	}
	envelope, err := first.Encrypt("proxy-1", []byte("persistent"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateCredentialCipher(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := second.Decrypt("proxy-1", envelope)
	if err != nil || string(got) != "persistent" {
		t.Fatalf("reload decrypt = %q / %v", got, err)
	}
}

func TestLoadCredentialCipherRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	permissive := filepath.Join(dir, "permissive.key")
	if err := os.WriteFile(permissive, []byte(strings.Repeat("A", 43)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCredentialCipher(permissive); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("permissive key error = %v", err)
	}
	target := filepath.Join(dir, "target.key")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink.key")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCredentialCipher(symlink); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink key error = %v", err)
	}
}
