package boundary

import (
	"net/netip"
	"testing"
	"time"
)

func TestPolicyDefaultsToDenyAndUsesFixedPriority(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		rules      []Rule
		url        string
		method     string
		wantAllow  bool
		wantRuleID string
		wantReason string
	}{
		{
			name: "default deny", url: "https://example.com/v1", method: "GET",
			wantReason: ReasonDefaultDeny,
		},
		{
			name: "allow attack outranks visit",
			rules: []Rule{
				{ID: "visit", Effect: EffectAllowVisit, Target: RuleTarget{Host: "example.com"}},
				{ID: "attack", Effect: EffectAllowAttack, Target: RuleTarget{Host: "example.com", PathPrefixes: []string{"/v1"}}},
			},
			url: "https://example.com/v1/items", method: "POST", wantAllow: true, wantRuleID: "attack", wantReason: ReasonAllowAttack,
		},
		{
			name: "blocked host outranks allow attack",
			rules: []Rule{
				{ID: "attack", Effect: EffectAllowAttack, Target: RuleTarget{Host: "example.com"}},
				{ID: "blocked-host", Effect: EffectBlocked, Target: RuleTarget{Host: "example.com"}},
			},
			url: "https://example.com/v1", method: "GET", wantRuleID: "blocked-host", wantReason: ReasonBlockedTarget,
		},
		{
			name: "blocked path outranks blocked host",
			rules: []Rule{
				{ID: "blocked-host", Effect: EffectBlocked, Target: RuleTarget{Host: "example.com"}},
				{ID: "blocked-path", Effect: EffectBlocked, Target: RuleTarget{Host: "example.com", PathPrefixes: []string{"/admin"}}},
			},
			url: "https://example.com/admin/users", method: "GET", wantRuleID: "blocked-path", wantReason: ReasonBlockedPath,
		},
		{
			name: "auth only is an explicit allow marker",
			rules: []Rule{
				{ID: "auth", Effect: EffectAuthOnly, AuthProfileID: "profile-1", Target: RuleTarget{Host: "auth.example"}},
			},
			url: "https://auth.example/", method: "GET", wantAllow: true, wantRuleID: "auth", wantReason: ReasonAuthOnly,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewPolicy(test.rules)
			if err != nil {
				t.Fatal(err)
			}
			decision, err := policy.Evaluate(test.url, test.method, nil, now)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allowed != test.wantAllow || decision.RuleID != test.wantRuleID || decision.Reason != test.wantReason {
				t.Fatalf("decision = %#v", decision)
			}
		})
	}
}

func TestPolicyMatchesAllCanonicalTargetDimensions(t *testing.T) {
	policy, err := NewPolicy([]Rule{{
		ID:     "scoped",
		Effect: EffectAllowAttack,
		Target: RuleTarget{
			Host: "BÜCHER.example.", Schemes: []string{"HTTPS"}, Ports: []int{8443},
			PathPrefixes: []string{"/v1/"}, Methods: []string{"POST"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	allowed, err := policy.Evaluate("https://bücher.example:8443/v1/items", "post", nil, now)
	if err != nil || !allowed.Allowed || allowed.RuleID != "scoped" {
		t.Fatalf("allowed = %#v, %v", allowed, err)
	}
	for _, request := range []struct{ url, method string }{
		{url: "http://bücher.example:8443/v1/items", method: "POST"},
		{url: "https://bücher.example/v1/items", method: "POST"},
		{url: "https://bücher.example:8443/v10/items", method: "POST"},
		{url: "https://bücher.example:8443/v1/items", method: "GET"},
	} {
		decision, err := policy.Evaluate(request.url, request.method, nil, now)
		if err != nil || decision.Allowed || decision.Reason != ReasonDefaultDeny {
			t.Fatalf("request %#v = %#v, %v", request, decision, err)
		}
	}
}

func TestPolicyChoosesMostSpecificRuleWithinSamePriority(t *testing.T) {
	policy, err := NewPolicy([]Rule{
		{ID: "a-broad-methods", Effect: EffectAllowVisit, Target: RuleTarget{Host: "example.com", Methods: []string{"GET", "POST"}}},
		{ID: "z-exact-method", Effect: EffectAllowVisit, Target: RuleTarget{Host: "example.com", Methods: []string{"GET"}}},
		{ID: "a-broad-path", Effect: EffectAllowAttack, Target: RuleTarget{Host: "attack.example", PathPrefixes: []string{"/api"}}},
		{ID: "z-specific-path", Effect: EffectAllowAttack, Target: RuleTarget{Host: "attack.example", PathPrefixes: []string{"/api/admin"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	visit, err := policy.Evaluate("https://example.com/", "GET", nil, now)
	if err != nil || visit.RuleID != "z-exact-method" {
		t.Fatalf("visit decision = %#v, %v", visit, err)
	}
	attack, err := policy.Evaluate("https://attack.example/api/admin/users", "GET", nil, now)
	if err != nil || attack.RuleID != "z-specific-path" {
		t.Fatalf("attack decision = %#v, %v", attack, err)
	}
}

func TestPolicyRejectsForbiddenTargetsBeforeAllowRules(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name       string
		url        string
		resolved   []netip.Addr
		wantReason string
	}{
		{name: "localhost", url: "http://localhost/", wantReason: ReasonForbiddenHostname},
		{name: "docker host", url: "http://host.docker.internal/", wantReason: ReasonForbiddenHostname},
		{name: "metadata host", url: "http://metadata.google.internal/", wantReason: ReasonForbiddenHostname},
		{name: "loopback", url: "http://127.0.0.1/", wantReason: ReasonForbiddenAddress},
		{name: "private", url: "http://10.1.2.3/", wantReason: ReasonForbiddenAddress},
		{name: "link local metadata", url: "http://169.254.169.254/", wantReason: ReasonForbiddenAddress},
		{name: "multicast", url: "http://224.0.0.1/", wantReason: ReasonForbiddenAddress},
		{name: "unspecified IPv6", url: "http://[::]/", wantReason: ReasonForbiddenAddress},
		{name: "unique local IPv6", url: "http://[fd00:ec2::254]/", wantReason: ReasonForbiddenAddress},
		{name: "carrier grade NAT", url: "http://100.64.0.1/", wantReason: ReasonForbiddenAddress},
		{name: "Docker API", url: "https://example.com:2376/", wantReason: ReasonDockerAPIPort},
		{name: "plain DNS", url: "http://example.com:53/", wantReason: ReasonDNSServicePort},
		{name: "DNS over QUIC", url: "https://example.com:784/", wantReason: ReasonDNSServicePort},
		{name: "DNS over TLS", url: "https://example.com:853/", wantReason: ReasonDNSServicePort},
		{name: "DNS over QUIC alternate", url: "https://example.com:8853/", wantReason: ReasonDNSServicePort},
		{name: "known DoH host", url: "https://dns.google/", wantReason: ReasonForbiddenDNSHost},
		{name: "known DoH subdomain", url: "https://tenant.dns.nextdns.io/", wantReason: ReasonForbiddenDNSHost},
		{name: "DNS rebinding", url: "https://allowed.example/", resolved: []netip.Addr{netip.MustParseAddr("192.168.1.5")}, wantReason: ReasonDNSRebinding},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := NormalizeRequestTarget(test.url, "GET")
			if err != nil {
				t.Fatal(err)
			}
			policy, err := NewPolicy([]Rule{{ID: "would-allow", Effect: EffectAllowVisit, Target: RuleTarget{Host: target.Host}}})
			if err != nil {
				t.Fatal(err)
			}
			decision, err := policy.Evaluate(test.url, "GET", test.resolved, now)
			if err != nil || decision.Allowed || decision.RuleID != "" || decision.Reason != test.wantReason {
				t.Fatalf("decision = %#v, %v", decision, err)
			}
		})
	}
}

func TestPolicyDNSServiceHostnameMatchingDoesNotRejectLookalikes(t *testing.T) {
	now := time.Now().UTC()
	policy, err := NewPolicy([]Rule{{ID: "lookalike", Effect: EffectAllowVisit, Target: RuleTarget{Host: "notdns.google"}}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := policy.Evaluate("https://notdns.google/", "GET", nil, now)
	if err != nil || !decision.Allowed || decision.RuleID != "lookalike" {
		t.Fatalf("lookalike decision = %#v, %v", decision, err)
	}
}

func TestPolicyAllowsExplicitPublicIPAndBlocksConfiguredNetwork(t *testing.T) {
	now := time.Now().UTC()
	allow, err := NewPolicy([]Rule{{ID: "public-ip", Effect: EffectAllowVisit, Target: RuleTarget{Host: "8.8.8.8"}}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := allow.Evaluate("https://8.8.8.8/", "GET", nil, now)
	if err != nil || !decision.Allowed || decision.RuleID != "public-ip" {
		t.Fatalf("public IP decision = %#v, %v", decision, err)
	}

	blocked, err := NewPolicy([]Rule{
		{ID: "visit", Effect: EffectAllowVisit, Target: RuleTarget{Host: "8.8.8.8"}},
		{ID: "blocked-network", Effect: EffectBlocked, Target: RuleTarget{Host: "8.8.8.0/24"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, err = blocked.Evaluate("https://8.8.8.8/", "GET", nil, now)
	if err != nil || decision.Allowed || decision.RuleID != "blocked-network" || decision.Reason != ReasonBlockedTarget {
		t.Fatalf("network decision = %#v, %v", decision, err)
	}
}

func TestPolicyDNSAllowsOnlyNamesWithActiveRulesAndRejectsUnsafeAnswers(t *testing.T) {
	now := time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Second)
	policy, err := NewPolicy([]Rule{
		{ID: "visit", Effect: EffectAllowVisit, Target: RuleTarget{Host: "allowed.example", Schemes: []string{"http"}, Methods: []string{"GET"}}},
		{ID: "attack", Effect: EffectAllowAttack, Target: RuleTarget{Host: "allowed.example", Schemes: []string{"https"}, Ports: []int{443}, PathPrefixes: []string{"/api"}}},
		{ID: "blocked-path", Effect: EffectBlocked, Target: RuleTarget{Host: "allowed.example", PathPrefixes: []string{"/admin"}}},
		{ID: "blocked-host", Effect: EffectBlocked, Target: RuleTarget{Host: "blocked.example"}},
		{ID: "expired", Effect: EffectAllowVisit, Target: RuleTarget{Host: "expired.example"}, ExpiresAt: &expired},
		{ID: "blocked-network", Effect: EffectBlocked, Target: RuleTarget{Host: "93.184.216.0/24"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := policy.EvaluateDNS("ALLOWED.EXAMPLE.", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, now)
	if err != nil || !allowed.Allowed || allowed.Host != "allowed.example" || allowed.RuleID != "attack" || allowed.Reason != ReasonAllowAttack {
		t.Fatalf("allowed DNS decision = %#v, %v", allowed, err)
	}
	for _, test := range []struct {
		name, host, reason string
		addresses          []netip.Addr
	}{
		{name: "unknown", host: "unknown.example", reason: ReasonDefaultDeny},
		{name: "blocked host", host: "blocked.example", reason: ReasonBlockedTarget},
		{name: "expired", host: "expired.example", reason: ReasonDefaultDeny},
		{name: "forbidden hostname", host: "metadata.google.internal", reason: ReasonForbiddenHostname},
		{name: "known DoH hostname", host: "cloudflare-dns.com", reason: ReasonForbiddenDNSHost},
		{name: "private rebinding", host: "allowed.example", addresses: []netip.Addr{netip.MustParseAddr("192.168.1.2")}, reason: ReasonDNSRebinding},
		{name: "mixed rebinding", host: "allowed.example", addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, reason: ReasonDNSRebinding},
		{name: "blocked public network", host: "allowed.example", addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}, reason: ReasonBlockedTarget},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision, decisionErr := policy.EvaluateDNS(test.host, test.addresses, now)
			if decisionErr != nil || decision.Allowed || decision.Reason != test.reason {
				t.Fatalf("DNS decision = %#v, %v", decision, decisionErr)
			}
		})
	}
}

func TestPolicySkipsExpiredRulesAndValidatesPolicyShape(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Second)
	policy, err := NewPolicy([]Rule{{
		ID: "expired", Effect: EffectAllowVisit, Target: RuleTarget{Host: "example.com"}, ExpiresAt: &expired,
	}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := policy.Evaluate("https://example.com/", "GET", nil, now)
	if err != nil || decision.Allowed || decision.Reason != ReasonDefaultDeny {
		t.Fatalf("expired decision = %#v, %v", decision, err)
	}

	invalid := [][]Rule{
		{{ID: "", Effect: EffectBlocked, Target: RuleTarget{Host: "example.com"}}},
		{{ID: "duplicate", Effect: EffectBlocked, Target: RuleTarget{Host: "example.com"}}, {ID: "duplicate", Effect: EffectBlocked, Target: RuleTarget{Host: "other.example"}}},
		{{ID: "cidr-allow", Effect: EffectAllowVisit, Target: RuleTarget{Host: "8.8.8.0/24"}}},
		{{ID: "auth-missing", Effect: EffectAuthOnly, Target: RuleTarget{Host: "example.com"}}},
		{{ID: "auth-leak", Effect: EffectAllowVisit, AuthProfileID: "profile", Target: RuleTarget{Host: "example.com"}}},
	}
	for _, rules := range invalid {
		if _, err := NewPolicy(rules); err == nil {
			t.Fatalf("invalid policy accepted: %#v", rules)
		}
	}
}
