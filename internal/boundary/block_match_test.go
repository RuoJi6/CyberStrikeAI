package boundary

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestBlockedRuleExplainsActualMatchedPathAndSpecificity(t *testing.T) {
	policy, err := NewPolicy([]Rule{
		{ID: "a-mixed", Effect: EffectBlocked, Target: RuleTarget{Host: "example.com", PathPrefixes: []string{"/api", "/unmatched/with/a/much/longer/path"}}},
		{ID: "b-users", Effect: EffectBlocked, Target: RuleTarget{Host: "example.com", PathPrefixes: []string{"/api/users"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := policy.Evaluate("https://example.com/api/users/42?token=secret", "GET", nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || decision.RuleID != "b-users" || decision.Reason != ReasonBlockedPathSubtree {
		t.Fatalf("decision = %#v", decision)
	}
	match := decision.BlockMatch
	if match == nil || match.Type != MatchTypePathSubtree || match.Value != "/api/users/*" || match.RequestURL != "https://example.com:443/api/users/42" || strings.Contains(match.RequestURL, "token") {
		t.Fatalf("block match = %#v", match)
	}
	if match.RuleConstraints == nil || len(match.RuleConstraints.PathPrefixes) != 1 || match.RuleConstraints.PathPrefixes[0] != "/api/users/*" {
		t.Fatalf("constraints = %#v", match.RuleConstraints)
	}
}

func TestBlockedRuleExactPathWinsAndDoesNotMatchChildren(t *testing.T) {
	policy, err := NewPolicy([]Rule{{
		ID: "exact-health", Effect: EffectBlocked,
		Target: RuleTarget{Host: "*", Schemes: []string{"https"}, PathPrefixes: []string{"=/health"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	exact, err := policy.Evaluate("https://example.com/health", "GET", nil, time.Now().UTC())
	if err != nil || exact.Allowed || exact.Reason != ReasonBlockedPathExact || exact.BlockMatch == nil || exact.BlockMatch.Value != "=/health" {
		t.Fatalf("exact = %#v, %v", exact, err)
	}
	child, err := policy.Evaluate("https://example.com/health/live", "GET", nil, time.Now().UTC())
	if err != nil || child.Allowed || child.Reason != ReasonDefaultDeny || child.RuleID != "" {
		t.Fatalf("child = %#v, %v", child, err)
	}
}

func TestBlockedRuleExactPathAlwaysOutranksMatchingSubtree(t *testing.T) {
	policy, err := NewPolicy([]Rule{{
		ID: "paths", Effect: EffectBlocked,
		Target: RuleTarget{Host: "example.com", PathPrefixes: []string{"/health", "=/health"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := policy.Evaluate("https://example.com/health", "GET", nil, time.Now().UTC())
	if err != nil || decision.RuleID != "paths" || decision.BlockMatch == nil || decision.BlockMatch.Value != "=/health" {
		t.Fatalf("decision = %#v, %v", decision, err)
	}
}

func TestBlockedRuleReasonMatrix(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name       string
		rule       Rule
		evaluate   func(*Policy) (Decision, error)
		wantReason string
		wantType   string
		wantValue  string
	}{
		{name: "method", rule: Rule{ID: "r", Effect: EffectBlocked, Target: RuleTarget{Host: "*", Methods: []string{"POST"}}}, evaluate: func(p *Policy) (Decision, error) { return p.Evaluate("https://example.com/submit", "POST", nil, now) }, wantReason: ReasonBlockedMethod, wantType: MatchTypeMethod, wantValue: "POST"},
		{name: "domain", rule: Rule{ID: "r", Effect: EffectBlocked, Target: RuleTarget{Host: "example.com"}}, evaluate: func(p *Policy) (Decision, error) { return p.Evaluate("https://example.com/", "GET", nil, now) }, wantReason: ReasonBlockedDomain, wantType: MatchTypeDomain, wantValue: "example.com"},
		{name: "wildcard domain", rule: Rule{ID: "r", Effect: EffectBlocked, Target: RuleTarget{Host: "*.example.com"}}, evaluate: func(p *Policy) (Decision, error) { return p.Evaluate("https://api.example.com/", "GET", nil, now) }, wantReason: ReasonBlockedDomainWildcard, wantType: MatchTypeDomainWildcard, wantValue: "*.example.com"},
		{name: "resolved IP", rule: Rule{ID: "r", Effect: EffectBlocked, Target: RuleTarget{Host: "93.184.216.34"}}, evaluate: func(p *Policy) (Decision, error) {
			return p.Evaluate("https://example.com/", "GET", []netip.Addr{netip.MustParseAddr("93.184.216.34")}, now)
		}, wantReason: ReasonBlockedIP, wantType: MatchTypeIP, wantValue: "93.184.216.34"},
		{name: "resolved CIDR", rule: Rule{ID: "r", Effect: EffectBlocked, Target: RuleTarget{Host: "93.184.216.0/24"}}, evaluate: func(p *Policy) (Decision, error) {
			return p.Evaluate("https://example.com/", "GET", []netip.Addr{netip.MustParseAddr("93.184.216.34")}, now)
		}, wantReason: ReasonBlockedCIDR, wantType: MatchTypeCIDR, wantValue: "93.184.216.0/24"},
		{name: "port", rule: Rule{ID: "r", Effect: EffectBlocked, Target: RuleTarget{Host: "*", Ports: []int{22}}}, evaluate: func(p *Policy) (Decision, error) { return p.EvaluateNetwork("8.8.8.8", 22, "tcp", nil, now) }, wantReason: ReasonBlockedPort, wantType: MatchTypePort, wantValue: "22"},
		{name: "protocol", rule: Rule{ID: "r", Effect: EffectBlocked, Target: RuleTarget{Host: "*", Schemes: []string{"udp"}}}, evaluate: func(p *Policy) (Decision, error) { return p.EvaluateNetwork("8.8.8.8", 53, "udp", nil, now) }, wantReason: ReasonBlockedProtocol, wantType: MatchTypeProtocol, wantValue: "udp"},
		{name: "icmp protocol", rule: Rule{ID: "r", Effect: EffectBlocked, Target: RuleTarget{Host: "*", Schemes: []string{"icmp"}}}, evaluate: func(p *Policy) (Decision, error) { return p.EvaluateNetwork("8.8.8.8", 0, "icmp", nil, now) }, wantReason: ReasonBlockedProtocol, wantType: MatchTypeProtocol, wantValue: "icmp"},
		{name: "all", rule: Rule{ID: "r", Effect: EffectBlocked, Target: RuleTarget{Host: "*"}}, evaluate: func(p *Policy) (Decision, error) { return p.Evaluate("https://example.com/", "GET", nil, now) }, wantReason: ReasonBlockedAll, wantType: MatchTypeAll, wantValue: "*"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewPolicy([]Rule{test.rule})
			if err != nil {
				t.Fatal(err)
			}
			decision, err := test.evaluate(policy)
			if err != nil || decision.Allowed || decision.Reason != test.wantReason || decision.BlockMatch == nil || decision.BlockMatch.Type != test.wantType || decision.BlockMatch.Value != test.wantValue {
				t.Fatalf("decision = %#v, %v", decision, err)
			}
			if test.wantType == MatchTypeCIDR && (decision.BlockMatch.ResolvedIP != "93.184.216.34" || decision.BlockMatch.DecisionPhase != DecisionPhaseAfterResolution) {
				t.Fatalf("resolved CIDR match = %#v", decision.BlockMatch)
			}
		})
	}
}

func TestBlockedDNSAndDefaultDenyCarryNormalizedTargets(t *testing.T) {
	policy, err := NewPolicy([]Rule{{ID: "dns", Effect: EffectBlocked, Target: RuleTarget{Host: "*.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	dnsDecision, err := policy.EvaluateDNS("api.example.com", nil, time.Now().UTC())
	if err != nil || dnsDecision.Allowed || dnsDecision.Reason != ReasonBlockedDomainWildcard || dnsDecision.BlockMatch == nil || dnsDecision.BlockMatch.RequestURL != "dns://api.example.com" {
		t.Fatalf("DNS decision = %#v, %v", dnsDecision, err)
	}
	defaultPolicy, err := NewPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := defaultPolicy.EvaluateNetwork("8.8.8.8", 443, "tcp", nil, time.Now().UTC())
	if err != nil || decision.Reason != ReasonDefaultDeny || decision.BlockMatch == nil || decision.BlockMatch.Source != MatchSourceDefault || decision.BlockMatch.RequestURL != "tcp://8.8.8.8:443" {
		t.Fatalf("default decision = %#v, %v", decision, err)
	}
}

func TestBlockedRuleChoosesLongestMatchingPathWithinRule(t *testing.T) {
	policy, err := NewPolicy([]Rule{{
		ID: "paths", Effect: EffectBlocked,
		Target: RuleTarget{Host: "example.com", PathPrefixes: []string{"/blocked", "/blocked/admin", "/not-matched/longer/value"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := policy.Evaluate("https://example.com/blocked/admin/users", "GET", nil, time.Now().UTC())
	if err != nil || decision.BlockMatch == nil || decision.BlockMatch.Value != "/blocked/admin/*" {
		t.Fatalf("decision = %#v, %v", decision, err)
	}
}
