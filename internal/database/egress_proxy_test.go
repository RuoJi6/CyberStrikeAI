package database

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/egress"
	"go.uber.org/zap"
)

func newEgressProxyTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "egress-proxy.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestEgressProxyCRUDStoresOnlyCiphertext(t *testing.T) {
	db := newEgressProxyTestDB(t)
	ctx := context.Background()
	created, err := db.CreateEgressProxy(ctx, EgressProxy{
		ID: "proxy-1", Name: " Primary ", Protocol: "HTTPS", Host: "Proxy.Example.COM.",
		Port: 8443, Enabled: true, OwnerUserID: "owner-1",
		CredentialCiphertext: "v1.key.ciphertext",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Name != "Primary" || created.Protocol != egress.UpstreamProtocolHTTPS || created.Host != "proxy.example.com" || !created.CredentialsConfigured || created.CredentialUpdatedAt == nil {
		t.Fatalf("created = %#v", created)
	}
	encoded, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "ciphertext") || strings.Contains(string(encoded), "CredentialCiphertext") {
		t.Fatalf("JSON exposed ciphertext: %s", encoded)
	}
	var stored string
	if err := db.QueryRow(`SELECT credential_ciphertext FROM egress_proxies WHERE id = ?`, created.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "v1.key.ciphertext" {
		t.Fatalf("stored ciphertext = %q", stored)
	}

	created.Name = "Updated"
	created.Protocol = egress.UpstreamProtocolSOCKS5
	created.Host = "127.0.0.1"
	created.Port = 1080
	created.Enabled = false
	created.CredentialCiphertext = ""
	created.CredentialUpdatedAt = nil
	updated, err := db.UpdateEgressProxy(ctx, created)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Updated" || updated.Protocol != egress.UpstreamProtocolSOCKS5 || updated.Enabled || updated.CredentialsConfigured || updated.CredentialUpdatedAt != nil {
		t.Fatalf("updated = %#v", updated)
	}
	if err := db.DeleteEgressProxy(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetEgressProxy(ctx, created.ID); err != ErrEgressProxyNotFound {
		t.Fatalf("get deleted error = %v", err)
	}
}

func TestListEgressProxiesHonorsOwnerAndAssignments(t *testing.T) {
	db := newEgressProxyTestDB(t)
	ctx := context.Background()
	for _, proxy := range []EgressProxy{
		{ID: "owned", Name: "Owned", Protocol: egress.UpstreamProtocolHTTP, Host: "one.example", Port: 8080, Enabled: true, OwnerUserID: "user-1"},
		{ID: "assigned", Name: "Assigned", Protocol: egress.UpstreamProtocolSOCKS5, Host: "two.example", Port: 1080, Enabled: true, OwnerUserID: "user-2"},
		{ID: "hidden", Name: "Hidden", Protocol: egress.UpstreamProtocolHTTPS, Host: "three.example", Port: 443, Enabled: true, OwnerUserID: "user-3"},
	} {
		if _, err := db.CreateEgressProxy(ctx, proxy); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO rbac_users (id, username, display_name, password_hash, enabled, is_builtin, created_at, updated_at) VALUES ('user-1', 'user-1', 'User 1', 'unused', 1, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if created, err := db.AssignResourcesToUser("user-1", "egress_proxy", []string{"assigned"}); err != nil || created != 1 {
		t.Fatalf("assign proxy = %d / %v", created, err)
	}
	options, err := db.ListAssignableRBACResources("egress_proxy", "two.example", 10)
	if err != nil || len(options) != 1 || options[0].ID != "assigned" || strings.Contains(strings.ToLower(options[0].Detail), "credential") {
		t.Fatalf("proxy resource options = %#v / %v", options, err)
	}
	if total, err := db.CountAssignableRBACResources("egress_proxy", "two.example"); err != nil || total != 1 {
		t.Fatalf("proxy resource count = %d / %v", total, err)
	}
	visible, err := db.ListEgressProxies(ctx, "user-1", RBACScopeOwn)
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 2 || visible[0].ID == "hidden" || visible[1].ID == "hidden" {
		t.Fatalf("visible = %#v", visible)
	}
	all, err := db.ListEgressProxies(ctx, "admin", RBACScopeAll)
	if err != nil || len(all) != 3 {
		t.Fatalf("all = %#v / %v", all, err)
	}
}

func TestEgressProxyValidationRejectsURLAndInvalidProtocol(t *testing.T) {
	db := newEgressProxyTestDB(t)
	for _, proxy := range []EgressProxy{
		{Name: "URL", Protocol: egress.UpstreamProtocolHTTP, Host: "http://proxy.example", Port: 8080, Enabled: true, OwnerUserID: "owner"},
		{Name: "FTP", Protocol: "ftp", Host: "proxy.example", Port: 21, Enabled: true, OwnerUserID: "owner"},
		{Name: "Port", Protocol: egress.UpstreamProtocolHTTP, Host: "proxy.example", Port: 0, Enabled: true, OwnerUserID: "owner"},
	} {
		if _, err := db.CreateEgressProxy(context.Background(), proxy); err == nil {
			t.Fatalf("CreateEgressProxy(%#v) succeeded", proxy)
		}
	}
}
