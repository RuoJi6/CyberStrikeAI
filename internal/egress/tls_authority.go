package egress

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"cyberstrike-ai/internal/boundary"
)

const (
	TLSAuthorityCertificateContainerPath = "/etc/cyberstrike/tls/ca.crt"
	TLSAuthorityPrivateKeyContainerPath  = "/etc/cyberstrike/tls/ca.key"
	TLSAgentCABundlePath                 = "/tmp/cyberstrike-ca-bundle.pem"
	defaultTLSAuthorityLifetime          = 24 * time.Hour
	maximumTLSAuthorityLifetime          = 7 * 24 * time.Hour
)

// TLSAuthority is one short-lived conversation-scoped signing authority. The
// private key is mounted only into the egress gateway; Agent containers receive
// only CertificatePEM.
type TLSAuthority struct {
	Certificate    *x509.Certificate
	PrivateKey     crypto.Signer
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

func GenerateTLSAuthority(conversationID string, now time.Time, lifetime time.Duration) (*TLSAuthority, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return nil, errors.New("TLS authority conversation id is required")
	}
	if lifetime == 0 {
		lifetime = defaultTLSAuthorityLifetime
	}
	if lifetime < time.Hour || lifetime > maximumTLSAuthorityLifetime {
		return nil, errors.New("TLS authority lifetime must be between one hour and seven days")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate TLS authority key: %w", err)
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return nil, err
	}
	idHash := sha256.Sum256([]byte(conversationID))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "CyberStrikeAI conversation " + hex.EncodeToString(idHash[:8])},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(lifetime),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create TLS authority certificate: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode TLS authority private key: %w", err)
	}
	return ParseTLSAuthority(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	)
}

func ParseTLSAuthority(certificatePEM, privateKeyPEM []byte) (*TLSAuthority, error) {
	certificateBlock, rest := pem.Decode(certificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("TLS authority certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("TLS authority certificate is not a valid CA")
	}
	keyBlock, keyRest := pem.Decode(privateKeyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(keyRest))) != 0 {
		return nil, errors.New("TLS authority private key PEM is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, errors.New("TLS authority private key is invalid")
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("TLS authority private key cannot sign certificates")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !strings.EqualFold(hex.EncodeToString(publicDER), mustPublicKeyHex(certificate.PublicKey)) {
		return nil, errors.New("TLS authority certificate and private key do not match")
	}
	return &TLSAuthority{
		Certificate: certificate, PrivateKey: signer,
		CertificatePEM: append([]byte(nil), certificatePEM...), PrivateKeyPEM: append([]byte(nil), privateKeyPEM...),
	}, nil
}

func mustPublicKeyHex(publicKey any) string {
	encoded, _ := x509.MarshalPKIXPublicKey(publicKey)
	return hex.EncodeToString(encoded)
}

func (authority *TLSAuthority) leafCertificate(host string, now time.Time) (tlsCertificate []byte, privateKey crypto.Signer, err error) {
	if authority == nil || authority.Certificate == nil || authority.PrivateKey == nil {
		return nil, nil, errors.New("TLS authority is not configured")
	}
	host, err = boundary.NormalizeHost(host)
	if err != nil || strings.Contains(host, "/") {
		return nil, nil, errors.New("TLS leaf hostname is invalid")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if !now.Before(authority.Certificate.NotAfter) {
		return nil, nil, errors.New("TLS authority has expired")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate TLS leaf key: %w", err)
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return nil, nil, err
	}
	notAfter := now.Add(12 * time.Hour)
	if authority.Certificate.NotAfter.Before(notAfter) {
		notAfter = authority.Certificate.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-time.Minute), NotAfter: notAfter,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if address := net.ParseIP(host); address != nil {
		template.IPAddresses = []net.IP{address}
	} else {
		template.DNSNames = []string{host}
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, authority.Certificate, &key.PublicKey, authority.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign TLS leaf certificate: %w", err)
	}
	return encoded, key, nil
}

func randomCertificateSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}
