package database

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
	"go.uber.org/zap"
)

func TestEgressAuthProfileCRUDIsEncryptedRedactedScopedAndReferenceProtected(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "auth-profiles.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	profile, err := db.CreateEgressAuthProfile(ctx, EgressAuthProfile{
		Name: "API token", HeaderName: "authorization", Enabled: true,
		CredentialCiphertext: "v1.key.random-ciphertext", OwnerUserID: "owner-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if profile.ID == "" || profile.HeaderName != "Authorization" || !profile.CredentialsConfigured || profile.CredentialUpdatedAt == nil {
		t.Fatalf("created auth profile = %#v", profile)
	}
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"random-ciphertext", "credentialCiphertext", "credential_ciphertext"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("safe auth profile JSON exposed %q: %s", forbidden, encoded)
		}
	}
	owner, err := db.ListEgressAuthProfiles(ctx, "owner-1", RBACScopeOwn)
	if err != nil || len(owner) != 1 {
		t.Fatalf("owner profiles = %#v, %v", owner, err)
	}
	stranger, err := db.ListEgressAuthProfiles(ctx, "owner-2", RBACScopeOwn)
	if err != nil || len(stranger) != 0 {
		t.Fatalf("stranger profiles = %#v, %v", stranger, err)
	}
	profile.Name = "Updated token"
	profile.HeaderName = "x-api-key"
	updated, err := db.UpdateEgressAuthProfile(ctx, profile)
	if err != nil || updated.HeaderName != "X-Api-Key" || updated.CredentialCiphertext != profile.CredentialCiphertext {
		t.Fatalf("updated auth profile = %#v, %v", updated, err)
	}
	policy, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{Name: "Auth policy", OwnerUserID: "owner-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateBoundaryPolicyRule(ctx, BoundaryPolicyRule{
		PolicyID: policy.ID, Effect: boundary.EffectAuthOnly, Host: "api.example",
		Schemes: []string{"http"}, AuthProfileID: &profile.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteEgressAuthProfile(ctx, profile.ID); !errors.Is(err, ErrEgressAuthProfileInUse) {
		t.Fatalf("delete referenced auth profile error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM egress_auth_profiles WHERE id = ?`, profile.ID); err == nil {
		t.Fatal("SQLite deleted an auth profile referenced by a boundary rule")
	}
	var triggerCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name IN (
		'boundary_policy_rules_auth_profile_insert',
		'boundary_policy_rules_auth_profile_update',
		'egress_auth_profiles_restrict_delete'
	)`).Scan(&triggerCount); err != nil || triggerCount != 3 {
		t.Fatalf("auth profile compatibility triggers = %d, %v", triggerCount, err)
	}
}

func TestEgressAuthProfileRejectsDangerousHeaderAndUnknownBoundaryReference(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "auth-profile-validation.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := db.CreateEgressAuthProfile(ctx, EgressAuthProfile{
		Name: "Bad", HeaderName: "Proxy-Authorization", Enabled: true, OwnerUserID: "owner",
	}); err == nil {
		t.Fatal("dangerous auth header was accepted")
	}
	policy, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{Name: "Unknown auth"})
	if err != nil {
		t.Fatal(err)
	}
	missing := "missing-profile"
	if _, err := db.CreateBoundaryPolicyRule(ctx, BoundaryPolicyRule{
		PolicyID: policy.ID, Effect: boundary.EffectAuthOnly, Host: "api.example", AuthProfileID: &missing,
	}); err == nil {
		t.Fatal("unknown auth profile reference was accepted")
	}
	now := formatSQLiteUTC(time.Now().UTC())
	if _, err := db.ExecContext(ctx, `
		INSERT INTO boundary_policy_rules (
			id, policy_id, effect, host, schemes_json, ports_json, path_prefixes_json,
			methods_json, auth_profile_id, rate_limit_json, position, created_at, updated_at
		) VALUES (?, ?, 'auth-only', 'api.example', '[]', '[]', '[]', '[]', ?,
			'{"requestsPerSecond":0,"burst":0}', 0, ?, ?)
	`, "raw-missing-auth", policy.ID, missing, now, now); err == nil {
		t.Fatal("SQLite compatibility trigger accepted an unknown auth profile")
	}
}
