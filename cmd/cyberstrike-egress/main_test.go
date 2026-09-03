package main

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/networkprovenance"
)

func TestAttributionEnvironmentRequiresCompleteGenerationBoundAudience(t *testing.T) {
	signer, err := networkprovenance.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CYBERSTRIKE_ATTRIBUTION_PUBLIC_KEY", signer.PublicKeyEncoded())
	t.Setenv("CYBERSTRIKE_ATTRIBUTION_CONVERSATION_ID", "conversation-one")
	t.Setenv("CYBERSTRIKE_ATTRIBUTION_RUNTIME_GENERATION", "7")
	t.Setenv("CYBERSTRIKE_ATTRIBUTION_INSTANCE_ID", "gateway-one")
	verifier, audience, err := attributionFromEnvironment()
	if err != nil || verifier == nil || audience.ConversationID != "conversation-one" || audience.RuntimeGeneration != 7 || audience.RuntimeInstanceID != "gateway-one" {
		t.Fatalf("attribution environment = %#v verifier=%v err=%v", audience, verifier != nil, err)
	}
	t.Setenv("CYBERSTRIKE_ATTRIBUTION_RUNTIME_GENERATION", "")
	if _, _, err := attributionFromEnvironment(); err == nil {
		t.Fatal("partial attribution environment was accepted")
	}
}

func TestParseSnapshotFlagsRequiresExactConfiguredInputs(t *testing.T) {
	path, reference, err := parseSnapshotFlags("check", []string{
		"--snapshot-path", "/etc/cyberstrike/boundary.json",
		"--snapshot-id", "12345678-1234-1234-1234-123456789abc",
		"--snapshot-sha256", "sha256:" + strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/etc/cyberstrike/boundary.json" || reference.ID != "12345678-1234-1234-1234-123456789abc" || reference.SHA256 != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("parsed snapshot flags = %q, %#v", path, reference)
	}
	if _, _, err := parseSnapshotFlags("check", []string{"--snapshot-id", reference.ID, "--snapshot-sha256", reference.SHA256}); err == nil {
		t.Fatal("snapshot flags accepted a missing path")
	}
	if _, _, err := parseSnapshotFlags("check", []string{"--snapshot-path", path, "--snapshot-id", reference.ID, "--snapshot-sha256", reference.SHA256, "extra"}); err == nil {
		t.Fatal("snapshot flags accepted a positional argument")
	}
}

func TestParseGatewayFlagsRequiresCompleteOptionalTrustedDocuments(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	routeDigest := "sha256:" + strings.Repeat("b", 64)
	authDigest := "sha256:" + strings.Repeat("c", 64)
	tlsCertDigest := "sha256:" + strings.Repeat("d", 64)
	tlsKeyDigest := "sha256:" + strings.Repeat("e", 64)
	path, reference, routePath, routeReference, authPath, authReference, tlsCertPath, tlsKeyPath, tlsReference, err := parseGatewayFlags("run", []string{
		"--snapshot-path", "/etc/cyberstrike/boundary.json",
		"--snapshot-id", "12345678-1234-1234-1234-123456789abc",
		"--snapshot-sha256", digest,
		"--upstream-route-path", "/etc/cyberstrike/upstream.json",
		"--upstream-route-id", "conversation-1",
		"--upstream-route-sha256", routeDigest,
		"--auth-profiles-path", "/etc/cyberstrike/auth-profiles.json",
		"--auth-profiles-id", "auth-snapshot-1",
		"--auth-profiles-sha256", authDigest,
		"--tls-ca-cert-path", "/etc/cyberstrike/tls/ca.crt",
		"--tls-ca-key-path", "/etc/cyberstrike/tls/ca.key",
		"--tls-ca-id", "12345678-1234-1234-1234-123456789abc",
		"--tls-ca-cert-sha256", tlsCertDigest,
		"--tls-ca-key-sha256", tlsKeyDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/etc/cyberstrike/boundary.json" || reference.SHA256 != digest || routePath != "/etc/cyberstrike/upstream.json" || routeReference == nil || routeReference.ID != "conversation-1" || routeReference.SHA256 != routeDigest || authPath != "/etc/cyberstrike/auth-profiles.json" || authReference == nil || authReference.ID != "auth-snapshot-1" || authReference.SHA256 != authDigest || tlsCertPath != "/etc/cyberstrike/tls/ca.crt" || tlsKeyPath != "/etc/cyberstrike/tls/ca.key" || tlsReference == nil || tlsReference.CertificateSHA256 != tlsCertDigest || tlsReference.PrivateKeySHA256 != tlsKeyDigest {
		t.Fatalf("gateway flags = %q %#v %q %#v %q %#v %q %q %#v", path, reference, routePath, routeReference, authPath, authReference, tlsCertPath, tlsKeyPath, tlsReference)
	}
	if _, _, _, _, _, _, _, _, _, err := parseGatewayFlags("run", []string{
		"--snapshot-path", path, "--snapshot-id", reference.ID, "--snapshot-sha256", digest,
		"--upstream-route-path", routePath,
	}); err == nil {
		t.Fatal("gateway flags accepted a partial upstream route")
	}
	if _, _, _, _, _, _, _, _, _, err := parseGatewayFlags("run", []string{
		"--snapshot-path", path, "--snapshot-id", reference.ID, "--snapshot-sha256", digest,
		"--auth-profiles-id", authReference.ID,
	}); err == nil {
		t.Fatal("gateway flags accepted partial auth profiles")
	}
	if _, _, _, _, _, _, _, _, _, err := parseGatewayFlags("run", []string{
		"--snapshot-path", path, "--snapshot-id", reference.ID, "--snapshot-sha256", digest,
		"--tls-ca-id", reference.ID,
	}); err == nil {
		t.Fatal("gateway flags accepted partial TLS authority")
	}
}
