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
			Methods: []string{"GET", "POST"}, RateLimit: BoundaryRateLimit{RequestsPerSecond: 2, Burst: 5},
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
	if attack.ExpiresAt == nil || !attack.ExpiresAt.Equal(expiresAt) || attack.RateLimit.RequestsPerSecond != 2 || attack.RateLimit.Burst != 5 {
		t.Fatalf("attack rule = %#v", attack)
	}
	authOnly := rules[3]
	if authOnly.AuthProfileID == nil || *authOnly.AuthProfileID != authProfileID {
		t.Fatalf("auth-only rule = %#v", authOnly)
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
