package main

import (
	"strings"
	"testing"
)

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
	path, reference, routePath, routeReference, authPath, authReference, err := parseGatewayFlags("run", []string{
		"--snapshot-path", "/etc/cyberstrike/boundary.json",
		"--snapshot-id", "12345678-1234-1234-1234-123456789abc",
		"--snapshot-sha256", digest,
		"--upstream-route-path", "/etc/cyberstrike/upstream.json",
		"--upstream-route-id", "conversation-1",
		"--upstream-route-sha256", routeDigest,
		"--auth-profiles-path", "/etc/cyberstrike/auth-profiles.json",
		"--auth-profiles-id", "auth-snapshot-1",
		"--auth-profiles-sha256", authDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/etc/cyberstrike/boundary.json" || reference.SHA256 != digest || routePath != "/etc/cyberstrike/upstream.json" || routeReference == nil || routeReference.ID != "conversation-1" || routeReference.SHA256 != routeDigest || authPath != "/etc/cyberstrike/auth-profiles.json" || authReference == nil || authReference.ID != "auth-snapshot-1" || authReference.SHA256 != authDigest {
		t.Fatalf("gateway flags = %q %#v %q %#v %q %#v", path, reference, routePath, routeReference, authPath, authReference)
	}
	if _, _, _, _, _, _, err := parseGatewayFlags("run", []string{
		"--snapshot-path", path, "--snapshot-id", reference.ID, "--snapshot-sha256", digest,
		"--upstream-route-path", routePath,
	}); err == nil {
		t.Fatal("gateway flags accepted a partial upstream route")
	}
	if _, _, _, _, _, _, err := parseGatewayFlags("run", []string{
		"--snapshot-path", path, "--snapshot-id", reference.ID, "--snapshot-sha256", digest,
		"--auth-profiles-id", authReference.ID,
	}); err == nil {
		t.Fatal("gateway flags accepted partial auth profiles")
	}
}
