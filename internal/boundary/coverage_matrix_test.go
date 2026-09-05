package boundary

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func mustCoveragePolicy(t *testing.T, rules ...Rule) *Policy {
	t.Helper()
	policy, err := NewPolicy(rules)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func requireCoverageDecision(t *testing.T, decision Decision, err error, allowed bool, ruleID, reason string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed != allowed || decision.RuleID != ruleID || decision.Reason != reason {
		t.Fatalf("decision = %#v; want allowed=%v rule=%q reason=%q", decision, allowed, ruleID, reason)
	}
}

func TestBoundaryCoverageOverlappingRulesAreStable(t *testing.T) {
	now := time.Date(2026, 8, 21, 13, 0, 0, 0, time.UTC)
	priority := mustCoveragePolicy(t,
		Rule{ID: "visit-specific", Effect: EffectAllowVisit, Target: RuleTarget{Host: "overlap.example", Schemes: []string{"https"}, Ports: []int{443}, PathPrefixes: []string{"/admin/users"}, Methods: []string{"GET"}}},
		Rule{ID: "attack-broad", Effect: EffectAllowAttack, Target: RuleTarget{Host: "overlap.example"}},
		Rule{ID: "block-admin", Effect: EffectBlocked, Target: RuleTarget{Host: "overlap.example", PathPrefixes: []string{"/admin"}}},
	)
	decision, err := priority.Evaluate("https://overlap.example/admin/users", "GET", nil, now)
	requireCoverageDecision(t, decision, err, false, "block-admin", ReasonBlockedPathSubtree)
	decision, err = priority.Evaluate("https://overlap.example/public", "GET", nil, now)
	requireCoverageDecision(t, decision, err, true, "attack-broad", ReasonAllowAttack)

	orders := [][]Rule{
		{
			{ID: "z-tie", Effect: EffectAllowVisit, Target: RuleTarget{Host: "tie.example", Methods: []string{"GET"}}},
			{ID: "a-tie", Effect: EffectAllowVisit, Target: RuleTarget{Host: "tie.example", Methods: []string{"GET"}}},
		},
		{
			{ID: "a-tie", Effect: EffectAllowVisit, Target: RuleTarget{Host: "tie.example", Methods: []string{"GET"}}},
			{ID: "z-tie", Effect: EffectAllowVisit, Target: RuleTarget{Host: "tie.example", Methods: []string{"GET"}}},
		},
	}
	for index, rules := range orders {
		policy := mustCoveragePolicy(t, rules...)
		decision, err := policy.Evaluate("https://tie.example/", "GET", nil, now)
		requireCoverageDecision(t, decision, err, true, "a-tie", ReasonAllowVisit)
		if index == 0 {
			for repeat := 0; repeat < 10; repeat++ {
				again, againErr := policy.Evaluate("https://tie.example/", "GET", nil, now)
				requireCoverageDecision(t, again, againErr, true, "a-tie", ReasonAllowVisit)
			}
		}
	}
}

func TestBoundaryCoverageWildcardAndPrefixBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 21, 13, 0, 0, 0, time.UTC)
	if _, err := NewPolicy([]Rule{{ID: "wildcard", Effect: EffectAllowVisit, Target: RuleTarget{Host: "*.example.com"}}}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("wildcard host error = %v", err)
	}

	policy := mustCoveragePolicy(t, Rule{
		ID: "exact-api", Effect: EffectAllowVisit,
		Target: RuleTarget{Host: "api.example.com", PathPrefixes: []string{"/api"}},
	})
	for _, rawURL := range []string{
		"https://api.example.com/api",
		"https://api.example.com/api/",
		"https://api.example.com/api/v1",
	} {
		decision, err := policy.Evaluate(rawURL, "GET", nil, now)
		requireCoverageDecision(t, decision, err, true, "exact-api", ReasonAllowVisit)
	}
	for _, rawURL := range []string{
		"https://sub.api.example.com/api",
		"https://api.example.com.evil.test/api",
		"https://api.example.com/apiv1",
		"https://api.example.com/apiary",
	} {
		decision, err := policy.Evaluate(rawURL, "GET", nil, now)
		requireCoverageDecision(t, decision, err, false, "", ReasonDefaultDeny)
	}
}

func TestBoundaryCoverageEncodedPathsCannotEscapeRules(t *testing.T) {
	now := time.Date(2026, 8, 21, 13, 0, 0, 0, time.UTC)
	policy := mustCoveragePolicy(t,
		Rule{ID: "visit", Effect: EffectAllowVisit, Target: RuleTarget{Host: "encoding.example"}},
		Rule{ID: "block-admin", Effect: EffectBlocked, Target: RuleTarget{Host: "encoding.example", PathPrefixes: []string{"/admin"}}},
		Rule{ID: "block-safe-admin", Effect: EffectBlocked, Target: RuleTarget{Host: "encoding.example", PathPrefixes: []string{"/safe/admin"}}},
	)

	tests := []struct {
		name     string
		rawURL   string
		wantRule string
	}{
		{name: "encoded dot segments", rawURL: "https://encoding.example/public/%2e%2e/admin/secrets", wantRule: "block-admin"},
		{name: "uppercase encoded dot segments", rawURL: "https://encoding.example/public/%2E%2E/admin", wantRule: "block-admin"},
		{name: "encoded slash", rawURL: "https://encoding.example/safe%2fadmin/secrets", wantRule: "block-safe-admin"},
		{name: "unicode path", rawURL: "https://encoding.example/caf%C3%A9", wantRule: "visit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := policy.Evaluate(test.rawURL, "GET", nil, now)
			if test.wantRule == "visit" {
				requireCoverageDecision(t, decision, err, true, "visit", ReasonAllowVisit)
				return
			}
			requireCoverageDecision(t, decision, err, false, test.wantRule, ReasonBlockedPathSubtree)
		})
	}

	for _, rawURL := range []string{
		"https://encoding.example/public/%252e%252e/admin",
		"https://encoding.example/safe%252fadmin",
		"https://encoding.example/%ff",
		"https://encoding.example/safe%5cadmin",
	} {
		decision, err := policy.Evaluate(rawURL, "GET", nil, now)
		if !errors.Is(err, ErrInvalidTarget) || decision != (Decision{}) {
			t.Fatalf("Evaluate(%q) = %#v, %v", rawURL, decision, err)
		}
	}
}

func TestBoundaryCoverageIPv6CanonicalizationAndCIDR(t *testing.T) {
	now := time.Date(2026, 8, 21, 13, 0, 0, 0, time.UTC)
	publicIPv6 := "2606:4700:4700::1111"
	policy := mustCoveragePolicy(t,
		Rule{ID: "ipv6-visit", Effect: EffectAllowVisit, Target: RuleTarget{Host: "2606:4700:4700:0:0:0:0:1111"}},
		Rule{ID: "mapped-ipv4", Effect: EffectAllowVisit, Target: RuleTarget{Host: "8.8.8.8"}},
	)
	decision, err := policy.Evaluate("https://["+publicIPv6+"]/", "GET", nil, now)
	requireCoverageDecision(t, decision, err, true, "ipv6-visit", ReasonAllowVisit)
	decision, err = policy.Evaluate("https://[::ffff:8.8.8.8]/", "GET", nil, now)
	requireCoverageDecision(t, decision, err, true, "mapped-ipv4", ReasonAllowVisit)

	blocked := mustCoveragePolicy(t,
		Rule{ID: "ipv6-visit", Effect: EffectAllowVisit, Target: RuleTarget{Host: publicIPv6}},
		Rule{ID: "ipv6-network", Effect: EffectBlocked, Target: RuleTarget{Host: "2606:4700::/32"}},
	)
	decision, err = blocked.Evaluate("https://["+publicIPv6+"]/", "GET", nil, now)
	requireCoverageDecision(t, decision, err, false, "ipv6-network", ReasonBlockedCIDR)
}

func TestBoundaryCoveragePrivateAndSpecialAddressesAlwaysWin(t *testing.T) {
	now := time.Date(2026, 8, 21, 13, 0, 0, 0, time.UTC)
	for _, rawURL := range []string{
		"http://10.255.255.254/",
		"http://172.16.0.1/",
		"http://172.31.255.254/",
		"http://192.168.255.254/",
		"http://127.0.0.1/",
		"http://[::1]/",
		"http://[fc00::1]/",
		"http://[fe80::1]/",
		"http://[::ffff:192.168.1.1]/",
	} {
		target, err := NormalizeRequestTarget(rawURL, "GET")
		if err != nil {
			t.Fatal(err)
		}
		policy := mustCoveragePolicy(t, Rule{ID: "would-allow", Effect: EffectAllowVisit, Target: RuleTarget{Host: target.Host}})
		decision, evalErr := policy.Evaluate(rawURL, "GET", nil, now)
		requireCoverageDecision(t, decision, evalErr, false, "", ReasonForbiddenAddress)
	}

	policy := mustCoveragePolicy(t, Rule{ID: "dns-name", Effect: EffectAllowVisit, Target: RuleTarget{Host: "dns.example"}})
	for _, resolved := range []netip.Addr{
		{},
		netip.MustParseAddr("192.168.10.20"),
		netip.MustParseAddr("fd00::20"),
		netip.MustParseAddr("::ffff:127.0.0.1"),
	} {
		decision, err := policy.Evaluate("https://dns.example/", "GET", []netip.Addr{netip.MustParseAddr("8.8.8.8"), resolved}, now)
		requireCoverageDecision(t, decision, err, false, "", ReasonDNSRebinding)
	}
}

func TestBoundaryCoverageExpirationUsesClosedCutoff(t *testing.T) {
	now := time.Date(2026, 8, 21, 13, 0, 0, 0, time.UTC)
	expires := now
	policy := mustCoveragePolicy(t,
		Rule{ID: "visit", Effect: EffectAllowVisit, Target: RuleTarget{Host: "expiry.example"}},
		Rule{ID: "temporary-block", Effect: EffectBlocked, Target: RuleTarget{Host: "expiry.example"}, ExpiresAt: &expires},
	)

	decision, err := policy.Evaluate("https://expiry.example/", "GET", nil, now.Add(-time.Nanosecond))
	requireCoverageDecision(t, decision, err, false, "temporary-block", ReasonBlockedDomain)
	decision, err = policy.Evaluate("https://expiry.example/", "GET", nil, now)
	requireCoverageDecision(t, decision, err, true, "visit", ReasonAllowVisit)
	decision, err = policy.Evaluate("https://expiry.example/", "GET", nil, now.Add(time.Nanosecond))
	requireCoverageDecision(t, decision, err, true, "visit", ReasonAllowVisit)

	allowExpires := now
	allow := mustCoveragePolicy(t, Rule{ID: "temporary-visit", Effect: EffectAllowVisit, Target: RuleTarget{Host: "allow-expiry.example"}, ExpiresAt: &allowExpires})
	decision, err = allow.Evaluate("https://allow-expiry.example/", "GET", nil, now)
	requireCoverageDecision(t, decision, err, false, "", ReasonDefaultDeny)
}

func TestBoundaryCoverageRedirectEveryHopIsReevaluated(t *testing.T) {
	now := time.Date(2026, 8, 21, 13, 0, 0, 0, time.UTC)
	policy := mustCoveragePolicy(t,
		Rule{ID: "origin-post", Effect: EffectAllowVisit, Target: RuleTarget{Host: "origin.example", Methods: []string{"POST"}}},
		Rule{ID: "cdn-get", Effect: EffectAllowVisit, Target: RuleTarget{Host: "cdn.example", Methods: []string{"GET"}}},
		Rule{ID: "block-cdn-admin", Effect: EffectBlocked, Target: RuleTarget{Host: "cdn.example", PathPrefixes: []string{"/admin"}}},
		Rule{ID: "would-allow-private", Effect: EffectAllowVisit, Target: RuleTarget{Host: "127.0.0.1"}},
	)

	type hop struct {
		url       string
		method    string
		resolved  []netip.Addr
		allowed   bool
		ruleID    string
		reason    string
		wantError bool
	}
	hops := []hop{
		{url: "https://origin.example/start", method: "POST", allowed: true, ruleID: "origin-post", reason: ReasonAllowVisit},
		{url: "https://cdn.example/object", method: "GET", allowed: true, ruleID: "cdn-get", reason: ReasonAllowVisit},
		{url: "https://cdn.example/public/%2e%2e/admin", method: "GET", ruleID: "block-cdn-admin", reason: ReasonBlockedPathSubtree},
		{url: "https://unlisted.example/object", method: "GET", reason: ReasonDefaultDeny},
		{url: "http://127.0.0.1/admin", method: "GET", reason: ReasonForbiddenAddress},
		{url: "https://cdn.example/object", method: "GET", resolved: []netip.Addr{netip.MustParseAddr("10.0.0.5")}, reason: ReasonDNSRebinding},
		{url: "/relative-location", method: "GET", wantError: true},
	}
	for index, hop := range hops {
		decision, err := policy.Evaluate(hop.url, hop.method, hop.resolved, now)
		if hop.wantError {
			if !errors.Is(err, ErrInvalidTarget) || decision != (Decision{}) {
				t.Fatalf("redirect hop %d = %#v, %v", index, decision, err)
			}
			continue
		}
		requireCoverageDecision(t, decision, err, hop.allowed, hop.ruleID, hop.reason)
	}
}
