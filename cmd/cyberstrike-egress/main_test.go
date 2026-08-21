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
