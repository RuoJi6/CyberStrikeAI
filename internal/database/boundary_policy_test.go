package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
	"go.uber.org/zap"
)

func TestBoundaryPolicyRuleEffectsPersistAndRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boundary-policy.db")
	db, err := NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	policy, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{
		Name:        "Stage 3 boundary",
		Description: "closed effect vocabulary",
		OwnerUserID: "owner-1",
	})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	expiresAt := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	authProfileID := "credential-profile-1"
	if _, err := db.CreateEgressAuthProfile(ctx, EgressAuthProfile{
		ID: authProfileID, Name: "Credential profile", HeaderName: "Authorization", Enabled: true, OwnerUserID: "owner-1",
	}); err != nil {
		db.Close()
		t.Fatal(err)
	}
	tests := []BoundaryPolicyRule{
		{
			PolicyID: policy.ID, Effect: boundary.EffectAllowVisit, Host: "VISIT.example.",
			Schemes: []string{"HTTPS", "https"}, Ports: []int{443, 443}, Methods: []string{"get"}, Position: 1,
		},
		{
			PolicyID: policy.ID, Effect: boundary.EffectAllowAttack, Host: "attack.example",
			Schemes: []string{"https"}, Ports: []int{443}, PathPrefixes: []string{"/v1/"},
			Methods: []string{"GET", "POST"}, RateLimit: BoundaryRateLimit{RequestsPerSecond: 2, Burst: 5, MaxConcurrent: 3},
			ExpiresAt: &expiresAt, Position: 2,
		},
		{PolicyID: policy.ID, Effect: boundary.EffectBlocked, Host: "blocked.example", Position: 3},
		{
			PolicyID: policy.ID, Effect: boundary.EffectAuthOnly, Host: "auth.example",
			AuthProfileID: &authProfileID, Position: 4,
		},
	}
	for _, rule := range tests {
		created, err := db.CreateBoundaryPolicyRule(ctx, rule)
		if err != nil {
			db.Close()
			t.Fatalf("create %s: %v", rule.Effect, err)
		}
		if created.ID == "" || created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
			db.Close()
			t.Fatalf("created %s = %#v", rule.Effect, created)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rules, err := db.ListBoundaryPolicyRules(ctx, policy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != len(tests) {
		t.Fatalf("rules = %#v", rules)
	}
	for i, want := range tests {
		got := rules[i]
		wantHost := want.Host
		if i == 0 {
			wantHost = "visit.example"
		}
		if got.Effect != want.Effect || got.Host != wantHost || got.Position != want.Position {
			t.Fatalf("rule %d = %#v", i, got)
		}
		if !got.Effect.Valid() {
			t.Fatalf("rule %d has invalid effect %q", i, got.Effect)
		}
	}
	if !reflect.DeepEqual(rules[0].Schemes, []string{"https"}) || !reflect.DeepEqual(rules[0].Ports, []int{443}) || !reflect.DeepEqual(rules[0].Methods, []string{"GET"}) {
		t.Fatalf("normalized visit rule = %#v", rules[0])
	}
	attack := rules[1]
	if attack.ExpiresAt == nil || !attack.ExpiresAt.Equal(expiresAt) || attack.RateLimit.RequestsPerSecond != 2 || attack.RateLimit.Burst != 5 || attack.RateLimit.MaxConcurrent != 3 {
		t.Fatalf("attack rule = %#v", attack)
	}
	authOnly := rules[3]
	if authOnly.AuthProfileID == nil || *authOnly.AuthProfileID != authProfileID {
		t.Fatalf("auth-only rule = %#v", authOnly)
	}
}

func TestBoundaryPolicyHTTPSInspectionIsAlwaysEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boundary-policy-tls-default.db")
	db, err := NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	created, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{
		Name: "HTTPS audit default", TLSInspectionEnabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created.TLSInspectionEnabled {
		t.Fatal("new boundary policy disabled mandatory HTTPS inspection")
	}
	updated, err := db.UpdateBoundaryPolicy(ctx, BoundaryPolicy{
		ID: created.ID, Name: created.Name, TLSInspectionEnabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.TLSInspectionEnabled {
		t.Fatal("updated boundary policy disabled mandatory HTTPS inspection")
	}
	if _, err := db.ExecContext(ctx, `UPDATE boundary_policies SET tls_inspection_enabled = 0 WHERE id = ?`, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	migrated, err := db.GetBoundaryPolicy(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !migrated.TLSInspectionEnabled {
		t.Fatal("legacy boundary policy was not migrated to mandatory HTTPS inspection")
	}
}

func TestBoundaryPolicyDefaultActionPersistsAndValidates(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "boundary-policy-default-action.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	denyPolicy, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{Name: "deny by default"})
	if err != nil || denyPolicy.DefaultAction != BoundaryDefaultActionDeny {
		t.Fatalf("default deny policy = %#v, %v", denyPolicy, err)
	}
	allowPolicy, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{Name: "blacklist", DefaultAction: " ALLOW "})
	if err != nil || allowPolicy.DefaultAction != BoundaryDefaultActionAllow {
		t.Fatalf("default allow policy = %#v, %v", allowPolicy, err)
	}
	loaded, err := db.GetBoundaryPolicy(ctx, allowPolicy.ID)
	if err != nil || loaded.DefaultAction != BoundaryDefaultActionAllow {
		t.Fatalf("loaded default action = %#v, %v", loaded, err)
	}
	updated, err := db.UpdateBoundaryPolicy(ctx, BoundaryPolicy{ID: allowPolicy.ID, Name: "renamed"})
	if err != nil || updated.DefaultAction != BoundaryDefaultActionAllow {
		t.Fatalf("omitted update changed default action = %#v, %v", updated, err)
	}
	if _, err := db.UpdateBoundaryPolicy(ctx, BoundaryPolicy{ID: allowPolicy.ID, Name: "invalid", DefaultAction: "open"}); err == nil {
		t.Fatal("invalid default action was accepted")
	}
}

func TestBoundaryPolicyDefaultActionMigrationKeepsLegacyPoliciesFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-boundary-policy.db")
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
		CREATE TABLE boundary_policies (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
			tls_inspection_enabled INTEGER NOT NULL DEFAULT 1,
			tls_bypass_domains_json TEXT NOT NULL DEFAULT '[]', owner_user_id TEXT,
			created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL
		);
		INSERT INTO boundary_policies (id, name, description, tls_inspection_enabled, tls_bypass_domains_json, created_at, updated_at)
		VALUES ('legacy-policy', 'Legacy', '', 1, '[]', '2026-09-05 00:00:00', '2026-09-05 00:00:00');
	`); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	policy, err := db.GetBoundaryPolicy(context.Background(), "legacy-policy")
	if err != nil || policy.DefaultAction != BoundaryDefaultActionDeny {
		t.Fatalf("migrated legacy policy = %#v, %v", policy, err)
	}
}

func TestBoundaryPolicyRuleEffectsFailClosedInAPIAndSQLite(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "boundary-policy-checks.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	policy, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{Name: "fail closed"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.CreateBoundaryPolicyRule(ctx, BoundaryPolicyRule{
		PolicyID: policy.ID,
		Effect:   boundary.Effect("unknown"),
	}); err == nil {
		t.Fatal("unknown effect was accepted by database API")
	}
	if _, err := db.CreateBoundaryPolicyRule(ctx, BoundaryPolicyRule{
		PolicyID: policy.ID,
		Effect:   boundary.EffectAuthOnly,
	}); err == nil {
		t.Fatal("auth-only rule without credential profile was accepted")
	}
	authProfileID := "must-use-auth-only"
	if _, err := db.CreateBoundaryPolicyRule(ctx, BoundaryPolicyRule{
		PolicyID:      policy.ID,
		Effect:        boundary.EffectAllowVisit,
		AuthProfileID: &authProfileID,
	}); err == nil {
		t.Fatal("credential profile on non-auth-only rule was accepted")
	}
	if _, err := db.CreateBoundaryPolicyRule(ctx, BoundaryPolicyRule{
		PolicyID: policy.ID,
		Effect:   boundary.EffectAllowVisit,
		Host:     "8.8.8.0/24",
	}); err == nil {
		t.Fatal("CIDR allow rule was accepted")
	}

	now := formatSQLiteUTC(time.Now())
	insert := `
		INSERT INTO boundary_policy_rules
			(id, policy_id, effect, auth_profile_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	if _, err := db.Exec(insert, "raw-unknown", policy.ID, "unknown", nil, now, now); err == nil {
		t.Fatal("SQLite accepted an unknown boundary effect")
	}
	if _, err := db.Exec(insert, "raw-auth-missing", policy.ID, "auth-only", nil, now, now); err == nil {
		t.Fatal("SQLite accepted auth-only without a credential profile")
	}
	if _, err := db.Exec(insert, "raw-auth-leak", policy.ID, "allow-visit", authProfileID, now, now); err == nil {
		t.Fatal("SQLite accepted a credential profile outside auth-only")
	}
}

func TestBoundaryPolicyBlacklistWildcardsAndPathFormsRoundTrip(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "boundary-policy-blacklist.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	policy, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{Name: "blacklist forms"})
	if err != nil {
		t.Fatal(err)
	}
	urlRule, err := db.CreateBoundaryPolicyRule(ctx, BoundaryPolicyRule{
		PolicyID: policy.ID, Effect: boundary.EffectBlocked, Host: "http://ssss.com/sdasdad/*",
	})
	if err != nil {
		t.Fatal(err)
	}
	if urlRule.Host != "ssss.com" || !reflect.DeepEqual(urlRule.Schemes, []string{"http"}) ||
		!reflect.DeepEqual(urlRule.Ports, []int{80}) || !reflect.DeepEqual(urlRule.PathPrefixes, []string{"/sdasdad"}) {
		t.Fatalf("normalized URL rule = %#v", urlRule)
	}
	wildcardRule, err := db.CreateBoundaryPolicyRule(ctx, BoundaryPolicyRule{
		PolicyID: policy.ID, Effect: boundary.EffectBlocked, Host: "*.Example.com.",
		PathPrefixes: []string{"/api/*", "=/desasdasdasd/sdadsd"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if wildcardRule.Host != "*.example.com" || !reflect.DeepEqual(wildcardRule.PathPrefixes, []string{"/api", "=/desasdasdasd/sdadsd"}) {
		t.Fatalf("normalized wildcard rule = %#v", wildcardRule)
	}
	pathOnlyRule, err := db.CreateBoundaryPolicyRule(ctx, BoundaryPolicyRule{
		PolicyID: policy.ID, Effect: boundary.EffectBlocked, PathPrefixes: []string{"/private/*"},
	})
	if err != nil || pathOnlyRule.Host != "*" || !reflect.DeepEqual(pathOnlyRule.PathPrefixes, []string{"/private"}) {
		t.Fatalf("normalized path-only rule = %#v, %v", pathOnlyRule, err)
	}
	if _, err := db.CreateBoundaryPolicyRule(ctx, BoundaryPolicyRule{
		PolicyID: policy.ID, Effect: boundary.EffectBlocked,
	}); err == nil {
		t.Fatal("hostless block without a path was accepted")
	}
	if _, err := db.CreateBoundaryPolicyRule(ctx, BoundaryPolicyRule{
		PolicyID: policy.ID, Effect: boundary.EffectAllowVisit, PathPrefixes: []string{"/private/*"},
	}); err == nil {
		t.Fatal("hostless allow rule was accepted")
	}
	if _, err := db.CreateBoundaryPolicyRule(ctx, BoundaryPolicyRule{
		PolicyID: policy.ID, Effect: boundary.EffectAllowVisit, Host: "*",
	}); err == nil {
		t.Fatal("wildcard allow rule was accepted")
	}
}

func TestBoundaryPolicyRuleCascadeDelete(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "boundary-policy-cascade.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	policy, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{Name: "cascade"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateBoundaryPolicyRule(ctx, BoundaryPolicyRule{
		PolicyID: policy.ID,
		Effect:   boundary.EffectBlocked,
		Host:     "blocked.example",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM boundary_policies WHERE id = ?`, policy.ID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM boundary_policy_rules WHERE policy_id = ?`, policy.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("boundary rules survived policy delete: %d", count)
	}
}

func TestBoundaryPolicyLookupAndOwnScopeAccess(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "boundary-policy-access.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	created, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{
		Name: "owned policy", OwnerUserID: "owner-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.GetBoundaryPolicy(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != created.ID || got.Name != created.Name || got.OwnerUserID != "owner-1" || got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatalf("policy = %#v", got)
	}
	if !db.UserCanAccessResource("owner-1", RBACScopeOwn, "boundary_policy", created.ID) {
		t.Fatal("policy owner was denied")
	}
	if db.UserCanAccessResource("other", RBACScopeOwn, "boundary_policy", created.ID) {
		t.Fatal("foreign own-scoped user was allowed")
	}
	if _, err := db.GetBoundaryPolicy(ctx, "missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing policy error = %v", err)
	}
}

func TestListBoundaryPoliciesHonorsOwnerAssignmentsAndStableOrder(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "boundary-policy-list.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	user, err := db.CreateRBACUser("boundary-list-user", "Boundary list user", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{Name: "Owned", OwnerUserID: user.ID})
	if err != nil {
		t.Fatal(err)
	}
	assigned, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{Name: "Assigned", OwnerUserID: "other-user"})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{Name: "Foreign", OwnerUserID: "other-user"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(user.ID, "boundary_policy", assigned.ID); err != nil {
		t.Fatal(err)
	}

	visible, err := db.ListBoundaryPolicies(ctx, user.ID, RBACScopeOwn)
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 2 {
		t.Fatalf("visible policies = %#v", visible)
	}
	visibleIDs := map[string]bool{visible[0].ID: true, visible[1].ID: true}
	if !visibleIDs[owned.ID] || !visibleIDs[assigned.ID] || visibleIDs[foreign.ID] {
		t.Fatalf("visible policy ids = %#v", visibleIDs)
	}
	all, err := db.ListBoundaryPolicies(ctx, "admin", RBACScopeAll)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("all policies = %#v", all)
	}
}

func TestBoundaryPolicyUsageTracksSelectionAndActiveSnapshot(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "boundary-policy-usage.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	policy, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{Name: "Used policy", OwnerUserID: "owner-1"})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := db.CreateConversation("Uses policy", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer, BoundaryPolicyID: policy.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	usage, err := db.ListBoundaryPolicyUsage(ctx, policy.ID, "admin", RBACScopeAll)
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 1 || usage[0].ConversationID != conversation.ID || usage[0].RuntimeStatus != "not_requested" || usage[0].SnapshotID != "" {
		t.Fatalf("selected usage = %#v", usage)
	}
	if err := db.DeleteBoundaryPolicy(ctx, policy.ID); !errors.Is(err, ErrBoundaryPolicyInUse) {
		t.Fatalf("delete selected policy error = %v", err)
	}

	snapshot, err := db.EnsureConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	usage, err = db.ListBoundaryPolicyUsage(ctx, policy.ID, "admin", RBACScopeAll)
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 1 || usage[0].SnapshotID != snapshot.SnapshotID || usage[0].SnapshotSHA256 != snapshot.SHA256 || usage[0].RuntimeGeneration != 1 {
		t.Fatalf("active usage = %#v", usage)
	}
	if err := db.DeleteBoundaryPolicy(ctx, policy.ID); !errors.Is(err, ErrBoundaryPolicyInUse) {
		t.Fatalf("delete active policy error = %v", err)
	}
}
