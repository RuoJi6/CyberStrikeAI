package egress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
)

const testSnapshotID = "12345678-1234-1234-1234-123456789abc"

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

type testPacketGatewayRunner struct {
	done <-chan error
}

func (runner testPacketGatewayRunner) Done() <-chan error { return runner.done }

func startTestPacketGateway(ctx context.Context, _ *boundary.Policy, _ PacketOptions) (packetGatewayRunner, error) {
	done := make(chan error, 1)
	go func() {
		<-ctx.Done()
		done <- nil
		close(done)
	}()
	return testPacketGatewayRunner{done: done}, nil
}

func (b *lockedBuffer) Write(content []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(content)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func testSnapshot(t *testing.T, content string) SnapshotReference {
	t.Helper()
	digest := sha256.Sum256([]byte(content))
	return SnapshotReference{ID: testSnapshotID, SHA256: "sha256:" + hex.EncodeToString(digest[:])}
}

func TestSnapshotStorePublishesImmutableReadOnlyFile(t *testing.T) {
	store, err := NewSnapshotStore(filepath.Join(t.TempDir(), "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Stat(store.Root())
	if err != nil {
		t.Fatal(err)
	}
	if rootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("snapshot root mode = %o, want 700", rootInfo.Mode().Perm())
	}
	content := `{"schemaVersion":1,"policyId":"","rules":[]}`
	reference := testSnapshot(t, content)
	padded := reference
	padded.ID = " " + padded.ID
	if _, err := store.Path(padded); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("padded snapshot id error = %v", err)
	}
	padded = reference
	padded.SHA256 += " "
	if _, err := store.Path(padded); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("padded snapshot digest error = %v", err)
	}
	path, err := store.Put(reference, content)
	if err != nil {
		t.Fatalf("put snapshot: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o444 || filepath.Dir(path) != store.Root() {
		t.Fatalf("snapshot path/mode = %q / %o", path, info.Mode().Perm())
	}
	if second, err := store.Put(reference, content); err != nil || second != path {
		t.Fatalf("idempotent put = %q, %v", second, err)
	}
	if _, err := store.Put(reference, strings.Replace(content, `[]`, `[{}]`, 1)); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("conflicting put error = %v", err)
	}
}

func TestLoadSnapshotRejectsDigestSchemaAndFileDrift(t *testing.T) {
	valid := `{"schemaVersion":1,"policyId":"","rules":[]}`
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte(valid), 0o444); err != nil {
		t.Fatal(err)
	}
	reference := testSnapshot(t, valid)
	if _, err := LoadSnapshot(path, reference); err != nil {
		t.Fatalf("load valid snapshot: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSnapshot(path, reference); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("writable snapshot error = %v", err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	tampered := reference
	tampered.SHA256 = "sha256:" + strings.Repeat("a", 64)
	if _, err := LoadSnapshot(path, tampered); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("digest drift error = %v", err)
	}
	unknown := `{"schemaVersion":1,"policyId":"","rules":[],"extra":true}`
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(unknown), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSnapshot(path, testSnapshot(t, unknown)); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestLoadNoBoundarySnapshotDefaultsExternalTrafficToAllow(t *testing.T) {
	content := `{"schemaVersion":3,"policyId":"","rules":[],"defaultAction":"allow"}`
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte(content), 0o444); err != nil {
		t.Fatal(err)
	}
	_, policy, err := LoadPolicySnapshot(path, testSnapshot(t, content))
	if err != nil {
		t.Fatal(err)
	}
	httpDecision, err := policy.Evaluate("http://example.com:18080/write", http.MethodDelete, []netip.Addr{netip.MustParseAddr("93.184.216.34")}, time.Now().UTC())
	if err != nil || !httpDecision.Allowed {
		t.Fatalf("HTTP default decision = %#v, %v", httpDecision, err)
	}
	tcpDecision, err := policy.EvaluateNetwork("service.example", 18080, "tcp", []netip.Addr{netip.MustParseAddr("93.184.216.34")}, time.Now().UTC())
	if err != nil || !tcpDecision.Allowed {
		t.Fatalf("TCP default decision = %#v, %v", tcpDecision, err)
	}
	privateDecision, err := policy.EvaluateNetwork("private.example", 18080, "tcp", []netip.Addr{netip.MustParseAddr("192.168.1.10")}, time.Now().UTC())
	if err != nil || privateDecision.Allowed || privateDecision.Reason != boundary.ReasonDNSRebinding {
		t.Fatalf("private baseline decision = %#v, %v", privateDecision, err)
	}
}

func TestLoadNoBoundaryTLSSnapshotDefaultsExternalTrafficToAllowAndDecryptsHTTPS(t *testing.T) {
	content := `{"schemaVersion":4,"policyId":"","rules":[],"tlsInspection":{"enabled":true,"bypassDomains":[]},"defaultAction":"allow"}`
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte(content), 0o444); err != nil {
		t.Fatal(err)
	}
	_, policy, tlsInspection, err := LoadGatewaySnapshot(path, testSnapshot(t, content))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := policy.Evaluate("https://example.com/write", http.MethodDelete, nil, time.Now().UTC())
	if err != nil || !decision.Allowed {
		t.Fatalf("HTTPS default decision = %#v, %v", decision, err)
	}
	if tlsInspection == nil || !tlsInspection.Enabled || len(tlsInspection.BypassDomains) != 0 {
		t.Fatalf("TLS inspection = %#v", tlsInspection)
	}
}

func TestLoadNetworkAccessSnapshotControlsRestrictedTargets(t *testing.T) {
	for name, allowed := range map[string]bool{"disabled": false, "enabled": true} {
		t.Run(name, func(t *testing.T) {
			content := `{"schemaVersion":5,"policyId":"","rules":[],"tlsInspection":{"enabled":true,"bypassDomains":[]},"defaultAction":"allow","networkAccess":{"allowRestrictedTargets":` + fmt.Sprintf("%t", allowed) + `}}`
			path := filepath.Join(t.TempDir(), "snapshot.json")
			if err := os.WriteFile(path, []byte(content), 0o444); err != nil {
				t.Fatal(err)
			}
			_, policy, _, err := LoadGatewaySnapshot(path, testSnapshot(t, content))
			if err != nil {
				t.Fatal(err)
			}
			decision, err := policy.EvaluateNetwork("private.example", 8443, "tcp", []netip.Addr{netip.MustParseAddr("10.2.3.4")}, time.Now().UTC())
			if err != nil || decision.Allowed != allowed {
				t.Fatalf("restricted target decision = %#v, %v", decision, err)
			}
		})
	}

	missing := `{"schemaVersion":5,"policyId":"","rules":[],"tlsInspection":{"enabled":true,"bypassDomains":[]},"defaultAction":"allow"}`
	path := filepath.Join(t.TempDir(), "missing-network-access.json")
	if err := os.WriteFile(path, []byte(missing), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadGatewaySnapshot(path, testSnapshot(t, missing)); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("missing v5 network access error = %v", err)
	}
}

func TestConfiguredGatewayReportsSnapshotAndStopsOnCancellation(t *testing.T) {
	content := `{"schemaVersion":1,"policyId":"","rules":[]}`
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte(content), 0o444); err != nil {
		t.Fatal(err)
	}
	reference := testSnapshot(t, content)
	ctx, cancel := context.WithCancel(context.Background())
	var output lockedBuffer
	done := make(chan error, 1)
	go func() {
		done <- RunWithSnapshot(ctx, path, reference, &output, GatewayOptions{ListenAddress: "127.0.0.1:0", SOCKS5ListenAddress: "127.0.0.1:0", DNSListenAddress: "127.0.0.1:0", packetGatewayStarter: startTestPacketGateway})
	}()
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(output.String(), reference.SHA256) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !strings.Contains(output.String(), `"event":"boundary_snapshot_loaded"`) {
		t.Fatalf("startup report = %q", output.String())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("gateway shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway did not stop")
	}
}

func TestConfiguredGatewayStopsWhenSnapshotIntegrityDrifts(t *testing.T) {
	content := `{"schemaVersion":1,"policyId":"","rules":[]}`
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte(content), 0o444); err != nil {
		t.Fatal(err)
	}
	reference := testSnapshot(t, content)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output lockedBuffer
	done := make(chan error, 1)
	go func() {
		done <- RunWithSnapshot(ctx, path, reference, &output, GatewayOptions{
			ListenAddress: "127.0.0.1:0", SOCKS5ListenAddress: "127.0.0.1:0", DNSListenAddress: "127.0.0.1:0", SnapshotCheckInterval: 10 * time.Millisecond,
			packetGatewayStarter: startTestPacketGateway,
		})
	}()
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(output.String(), `"event":"boundary_snapshot_loaded"`) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !strings.Contains(output.String(), `"event":"boundary_snapshot_loaded"`) {
		t.Fatalf("startup report = %q", output.String())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrSnapshotIntegrity) || !strings.Contains(err.Error(), "snapshot integrity monitor") {
			t.Fatalf("snapshot drift shutdown error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway did not stop after snapshot integrity drift")
	}
}

func TestConfiguredGatewayReportsAndMonitorsImmutableUpstreamRoute(t *testing.T) {
	content := `{"schemaVersion":1,"policyId":"","rules":[]}`
	snapshotPath := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(snapshotPath, []byte(content), 0o444); err != nil {
		t.Fatal(err)
	}
	snapshotReference := testSnapshot(t, content)
	routeStore, err := NewUpstreamRouteStore(filepath.Join(t.TempDir(), "routes"))
	if err != nil {
		t.Fatal(err)
	}
	routeReference, routePath, err := routeStore.Put("conversation-1", NewProxyUpstreamRoute(UpstreamEndpoint{
		ID: "proxy-1", Protocol: UpstreamProtocolHTTP, Host: "proxy.example", Port: 3128,
		Username: "monitor-user", Password: "monitor-secret",
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output lockedBuffer
	done := make(chan error, 1)
	go func() {
		done <- RunWithSnapshot(ctx, snapshotPath, snapshotReference, &output, GatewayOptions{
			ListenAddress: "127.0.0.1:0", SOCKS5ListenAddress: "127.0.0.1:0", DNSListenAddress: "127.0.0.1:0", SnapshotCheckInterval: 10 * time.Millisecond,
			UpstreamRoutePath: routePath, UpstreamRoute: &routeReference,
			packetGatewayStarter: startTestPacketGateway,
		})
	}()
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(output.String(), routeReference.SHA256) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	startup := output.String()
	if !strings.Contains(startup, `"upstreamRouteId":"conversation-1"`) || !strings.Contains(startup, routeReference.SHA256) || strings.Contains(startup, "monitor-user") || strings.Contains(startup, "monitor-secret") {
		t.Fatalf("gateway upstream startup report = %q", startup)
	}
	if err := os.Chmod(routePath, 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrUpstreamRouteIntegrity) || !strings.Contains(err.Error(), "snapshot integrity monitor") {
			t.Fatalf("upstream route drift shutdown error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway did not stop after upstream route integrity drift")
	}
}

func TestConfiguredGatewayRejectsNegativeSnapshotCheckInterval(t *testing.T) {
	err := RunWithSnapshot(context.Background(), "unused", SnapshotReference{}, nil, GatewayOptions{SnapshotCheckInterval: -time.Nanosecond})
	if err == nil || !strings.Contains(err.Error(), "check interval") {
		t.Fatalf("negative snapshot check interval error = %v", err)
	}
}

func TestLoadPolicySnapshotCompilesCanonicalRulesAndRejectsNonCanonicalTargets(t *testing.T) {
	valid := `{"schemaVersion":1,"policyId":"policy-1","rules":[{"id":"rule-1","effect":"allow-visit","host":"allowed.example","schemes":["http"],"ports":[80],"pathPrefixes":["/api"],"methods":["GET"],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":1}]}`
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte(valid), 0o444); err != nil {
		t.Fatal(err)
	}
	reference := testSnapshot(t, valid)
	report, policy, err := LoadPolicySnapshot(path, reference)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := policy.Evaluate("http://allowed.example/api/items", "GET", nil, time.Now())
	if err != nil || !decision.Allowed || decision.Effect != boundary.EffectAllowVisit || report.SnapshotID != reference.ID || report.SHA256 != reference.SHA256 {
		t.Fatalf("compiled policy decision/report = %#v / %#v / %v", decision, report, err)
	}
	nonCanonical := strings.Replace(valid, `"host":"allowed.example"`, `"host":"ALLOWED.EXAMPLE."`, 1)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(nonCanonical), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPolicySnapshot(path, testSnapshot(t, nonCanonical)); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("non-canonical snapshot error = %v", err)
	}
}

func TestLoadPolicySnapshotPreservesWildcardAndExactPathBlacklist(t *testing.T) {
	content := `{"schemaVersion":1,"policyId":"policy-blacklist","rules":[{"id":"rule-blacklist","effect":"blocked","host":"*","schemes":["http","https"],"ports":[],"pathPrefixes":["/api","=/health"],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":1}]}`
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte(content), 0o444); err != nil {
		t.Fatal(err)
	}
	_, policy, err := LoadPolicySnapshot(path, testSnapshot(t, content))
	if err != nil {
		t.Fatal(err)
	}
	for _, rawURL := range []string{"https://one.example/api/items", "http://two.example/health"} {
		decision, evalErr := policy.Evaluate(rawURL, http.MethodGet, nil, time.Now().UTC())
		if evalErr != nil || decision.RuleID != "rule-blacklist" || decision.Reason != boundary.ReasonBlockedPath {
			t.Fatalf("snapshot blacklist %q = %#v, %v", rawURL, decision, evalErr)
		}
	}
	child, err := policy.Evaluate("https://one.example/health/check", http.MethodGet, nil, time.Now().UTC())
	if err != nil || child.RuleID != "" || child.Reason != boundary.ReasonDefaultDeny {
		t.Fatalf("exact snapshot path matched child = %#v, %v", child, err)
	}
}

func TestLoadPolicySnapshotPreservesBoundedConcurrencyAndLegacyCanonicalJSON(t *testing.T) {
	legacy := `{"schemaVersion":1,"policyId":"policy-1","rules":[{"id":"rule-1","effect":"allow-attack","host":"allowed.example","schemes":["http"],"ports":[80],"pathPrefixes":["/"],"methods":["POST"],"authProfileId":null,"rateLimit":{"requestsPerSecond":2,"burst":5},"expiresAt":null,"position":1}]}`
	configured := strings.Replace(legacy, `"burst":5`, `"burst":5,"maxConcurrent":3`, 1)
	for name, document := range map[string]string{"legacy": legacy, "configured": configured} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "snapshot.json")
			if err := os.WriteFile(path, []byte(document), 0o444); err != nil {
				t.Fatal(err)
			}
			_, policy, err := LoadPolicySnapshot(path, testSnapshot(t, document))
			if err != nil {
				t.Fatal(err)
			}
			decision, err := policy.Evaluate("http://allowed.example/", http.MethodPost, nil, time.Now())
			if err != nil || decision.RateLimit.RequestsPerSecond != 2 || decision.RateLimit.Burst != 5 {
				t.Fatalf("rate decision = %#v, %v", decision, err)
			}
			wantConcurrent := 0
			if name == "configured" {
				wantConcurrent = 3
			}
			if decision.RateLimit.MaxConcurrent != wantConcurrent {
				t.Fatalf("max concurrent = %d, want %d", decision.RateLimit.MaxConcurrent, wantConcurrent)
			}
		})
	}
	invalid := strings.Replace(configured, `"maxConcurrent":3`, `"maxConcurrent":1025`, 1)
	path := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(path, []byte(invalid), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPolicySnapshot(path, testSnapshot(t, invalid)); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("unbounded concurrency error = %v", err)
	}
}
