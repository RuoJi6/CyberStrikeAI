package egress

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"
)

func TestConversationTLSAuthoritiesAreShortLivedIsolatedAndStoredReadOnly(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	first, err := GenerateTLSAuthority("conversation-one", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateTLSAuthority("conversation-two", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.CertificatePEM) == string(second.CertificatePEM) || first.Certificate.NotAfter.After(now.Add(time.Hour+time.Second)) {
		t.Fatal("conversation authorities are not isolated or short-lived")
	}
	leafDER, _, err := first.leafCertificate("target.example", now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	firstRoots := x509.NewCertPool()
	firstRoots.AddCert(first.Certificate)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "target.example", Roots: firstRoots, CurrentTime: now}); err != nil {
		t.Fatalf("first conversation did not trust its leaf: %v", err)
	}
	secondRoots := x509.NewCertPool()
	secondRoots.AddCert(second.Certificate)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "target.example", Roots: secondRoots, CurrentTime: now}); err == nil {
		t.Fatal("second conversation trusted the first conversation leaf")
	}

	store, err := NewTLSAuthorityStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reference, certificatePath, keyPath, err := store.Put("12345678-1234-1234-1234-123456789abc", first)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{certificatePath, keyPath} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o444 {
			t.Fatalf("trusted TLS file mode = %v err=%v", info, err)
		}
	}
	loaded, certificatePEM, err := LoadTLSAuthority(certificatePath, keyPath, reference, now)
	if err != nil || loaded.Certificate.SerialNumber.Cmp(first.Certificate.SerialNumber) != 0 || string(certificatePEM) != string(first.CertificatePEM) {
		t.Fatalf("loaded authority mismatch: %#v err=%v", loaded, err)
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("Agent certificate material is not public-certificate-only PEM")
	}
}
