package egress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthProfilesStoreIsImmutableCanonicalAndSecretPrivate(t *testing.T) {
	store, err := NewAuthProfilesStore(filepath.Join(t.TempDir(), "auth-profiles"))
	if err != nil {
		t.Fatal(err)
	}
	document := NewAuthProfilesDocument(strings.Repeat("a", 64), []GatewayAuthProfile{
		{ID: "profile-b", HeaderName: "X-Api-Key", HeaderValue: "private-api-key"},
		{ID: "profile-a", HeaderName: "Authorization", HeaderValue: "Bearer private-token"},
	})
	reference, path, err := store.Put("auth-snapshot-1", document)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("auth profiles mode = %v, err=%v", info.Mode().Perm(), err)
	}
	if strings.Contains(reference.ID+reference.SHA256, "private") {
		t.Fatal("safe auth profiles reference exposed a credential")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"bindingSalt":"` + strings.Repeat("a", 64) + `","profiles":[{"id":"profile-a","headerName":"Authorization","headerValue":"Bearer private-token"},{"id":"profile-b","headerName":"X-Api-Key","headerValue":"private-api-key"}]}`
	if string(content) != want {
		t.Fatalf("auth profiles JSON is not canonical: %s", content)
	}
	loaded, err := LoadAuthProfiles(path, reference)
	if err != nil || len(loaded.Profiles) != 2 || loaded.Profiles[0].HeaderValue != "Bearer private-token" {
		t.Fatalf("loaded auth profiles = %#v, err=%v", loaded, err)
	}
	changed := NewAuthProfilesDocument(strings.Repeat("b", 64), document.Profiles)
	if _, _, err := store.Put(reference.ID, changed); !errors.Is(err, ErrAuthProfilesIntegrity) {
		t.Fatalf("immutable auth profiles replacement error = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthProfiles(path, reference); !errors.Is(err, ErrAuthProfilesIntegrity) {
		t.Fatalf("writable auth profiles error = %v", err)
	}
}

func TestAuthProfileHeaderValidationRejectsInjectionAndRoutingHeaders(t *testing.T) {
	for _, name := range []string{"", "Host", "Proxy-Authorization", "Connection", "Forwarded", "X-Forwarded-For", "Content-Length", "Bad Header", "Bad\r\nHeader"} {
		if _, err := ValidateAuthHeaderName(name); err == nil {
			t.Fatalf("forbidden auth header %q was accepted", name)
		}
	}
	for _, name := range []string{"authorization", "x-api-key", "cookie"} {
		if canonical, err := ValidateAuthHeaderName(name); err != nil || canonical == "" {
			t.Fatalf("valid auth header %q = %q, %v", name, canonical, err)
		}
	}
	for _, value := range []string{"", "secret\r\nInjected: true", "secret\x00value", strings.Repeat("x", MaxAuthProfileSecretBytes+1)} {
		if err := ValidateAuthHeaderValue(value); err == nil {
			t.Fatalf("invalid credential value of length %d was accepted", len(value))
		}
	}
}

func TestCheckGatewayRequiresExactAuthProfilesForPolicy(t *testing.T) {
	root := t.TempDir()
	snapshotStore, err := NewSnapshotStore(filepath.Join(root, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	canonical := `{"schemaVersion":1,"policyId":"policy-1","rules":[{"id":"auth-rule","effect":"auth-only","host":"auth.example","schemes":["http"],"ports":[],"pathPrefixes":[],"methods":[],"authProfileId":"profile-1","rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":0}]}`
	digest := sha256.Sum256([]byte(canonical))
	snapshotReference := SnapshotReference{ID: "22222222-2222-4222-8222-222222222222", SHA256: "sha256:" + hex.EncodeToString(digest[:])}
	snapshotPath, err := snapshotStore.Put(snapshotReference, canonical)
	if err != nil {
		t.Fatal(err)
	}
	authStore, err := NewAuthProfilesStore(filepath.Join(root, "auth"))
	if err != nil {
		t.Fatal(err)
	}
	document := NewAuthProfilesDocument(strings.Repeat("d", 64), []GatewayAuthProfile{{
		ID: "profile-1", HeaderName: "Authorization", HeaderValue: "Bearer secret",
	}})
	authReference, authPath, err := authStore.Put("auth-check-1", document)
	if err != nil {
		t.Fatal(err)
	}
	options := GatewayOptions{AuthProfilesPath: authPath, AuthProfiles: &authReference}
	if err := CheckGatewayWithOptions(snapshotPath, snapshotReference, options, nil); err != nil {
		t.Fatalf("check exact auth profiles: %v", err)
	}
	if err := CheckGateway(snapshotPath, snapshotReference, "", nil, nil); err == nil {
		t.Fatal("gateway health accepted auth-only policy without credentials")
	}
	mismatch := NewAuthProfilesDocument(strings.Repeat("e", 64), []GatewayAuthProfile{{
		ID: "profile-2", HeaderName: "Authorization", HeaderValue: "Bearer other",
	}})
	mismatchReference, mismatchPath, err := authStore.Put("auth-check-2", mismatch)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckGatewayWithOptions(snapshotPath, snapshotReference, GatewayOptions{
		AuthProfilesPath: mismatchPath, AuthProfiles: &mismatchReference,
	}, nil); err == nil {
		t.Fatal("gateway health accepted the wrong auth profile set")
	}
}

func TestGatewayIntegrityMonitorChecksAuthProfilesWithoutUpstreamRoute(t *testing.T) {
	root := t.TempDir()
	snapshotContent := `{"schemaVersion":1,"policyId":"","rules":[]}`
	snapshotPath := filepath.Join(root, "snapshot.json")
	if err := os.WriteFile(snapshotPath, []byte(snapshotContent), 0o444); err != nil {
		t.Fatal(err)
	}
	snapshotReference := testSnapshot(t, snapshotContent)
	store, err := NewAuthProfilesStore(filepath.Join(root, "auth"))
	if err != nil {
		t.Fatal(err)
	}
	document := NewAuthProfilesDocument(strings.Repeat("f", 64), []GatewayAuthProfile{{
		ID: "profile-1", HeaderName: "Authorization", HeaderValue: "Bearer monitor-secret",
	}})
	authReference, authPath, err := store.Put("auth-monitor-1", document)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- monitorGatewayIntegrity(ctx, snapshotPath, snapshotReference, "", nil, authPath, &authReference, 5*time.Millisecond)
	}()
	if err := os.Chmod(authPath, 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrAuthProfilesIntegrity) || !strings.Contains(err.Error(), "revalidate immutable auth profiles") {
			t.Fatalf("auth profile drift error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway integrity monitor ignored auth profile drift")
	}
}
