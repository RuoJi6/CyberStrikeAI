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

func TestPolicyEmptyMethodsAllowEveryHTTPMethod(t *testing.T) {
	policy, err := NewPolicy([]Rule{{
		ID: "read-only-default", Effect: EffectAllowVisit,
		Target: RuleTarget{Host: "docs.example", Schemes: []string{"http", "https"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, method := range []string{"GET", "HEAD", "OPTIONS", "CONNECT", "POST", "PUT", "PATCH", "DELETE"} {
		decision, err := policy.Evaluate("https://docs.example/guide", method, nil, now)
		if err != nil || !decision.Allowed || decision.RuleID != "read-only-default" {
			t.Fatalf("default %s decision = %#v, %v", method, decision, err)
		}
	}
	explicit, err := NewPolicy([]Rule{{
		ID: "explicit-post", Effect: EffectAllowVisit,
		Target: RuleTarget{Host: "docs.example", Schemes: []string{"https"}, Methods: []string{"POST"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := explicit.Evaluate("https://docs.example/submit", "POST", nil, now)
	if err != nil || !decision.Allowed || decision.RuleID != "explicit-post" {
		t.Fatalf("explicit POST decision = %#v, %v", decision, err)
	}
}

func TestPolicyEvaluatesTCPAndUDPByProtocolAndPort(t *testing.T) {
	policy, err := NewPolicy([]Rule{
		{ID: "ssh", Effect: EffectAllowVisit, Target: RuleTarget{Host: "db.example", Schemes: []string{"tcp"}, Ports: []int{22}, PathPrefixes: []string{"/http-only"}, Methods: []string{"POST"}}},
		{ID: "dns", Effect: EffectAllowVisit, Target: RuleTarget{Host: "db.example", Schemes: []string{"udp"}, Ports: []int{5353}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, test := range []struct {
		protocol string
		port     int
		allow    bool
	}{
		{protocol: "tcp", port: 22, allow: true},
		{protocol: "udp", port: 5353, allow: true},
		{protocol: "tcp", port: 5353},
		{protocol: "udp", port: 22},
	} {
		decision, evalErr := policy.EvaluateNetwork("db.example", test.port, test.protocol, nil, now)
		if evalErr != nil || decision.Allowed != test.allow {
			t.Fatalf("%#v = %#v, %v", test, decision, evalErr)
		}
	}
}

func TestPolicyExplicitDefaultAllowKeepsReservedTargetsBlocked(t *testing.T) {
	policy, err := NewPolicyWithDefault(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	allowed, err := policy.Evaluate("https://example.com/write", "DELETE", []netip.Addr{netip.MustParseAddr("93.184.216.34")}, now)
	if err != nil || !allowed.Allowed {
		t.Fatalf("public default = %#v, %v", allowed, err)
	}
	blocked, err := policy.EvaluateNetwork("127.0.0.1", 3306, "tcp", nil, now)
	if err != nil || blocked.Allowed || blocked.Reason != ReasonForbiddenAddress {
		t.Fatalf("reserved default = %#v, %v", blocked, err)
	}
	blockedDNS, err := policy.EvaluateNetwork("8.8.8.8", 53, "udp", nil, now)
	if err != nil || !blockedDNS.Allowed || blockedDNS.Reason != ReasonAllowVisit || blockedDNS.RuleID != "" {
		t.Fatalf("default DNS service = %#v, %v", blockedDNS, err)
	}
}

func TestPolicyServicePortsFollowOrdinaryBoundaryRules(t *testing.T) {
	now := time.Now().UTC()
	policy, err := NewPolicy([]Rule{{
		ID: "authorized-dns-service", Effect: EffectAllowVisit,
		Target: RuleTarget{Host: "47.116.200.74"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		protocol string
		port     int
	}{
		{name: "HTTP probe", protocol: "http", port: 53},
		{name: "TCP DNS", protocol: "tcp", port: 53},
		{name: "UDP DNS", protocol: "udp", port: 53},
		{name: "DNS over TLS", protocol: "tcp", port: 853},
	} {
		t.Run(test.name, func(t *testing.T) {
			var decision Decision
			var evalErr error
			if test.protocol == "http" {
				decision, evalErr = policy.Evaluate("http://47.116.200.74:53/", "GET", nil, now)
			} else {
				decision, evalErr = policy.EvaluateNetwork("47.116.200.74", test.port, test.protocol, nil, now)
			}
			if evalErr != nil || !decision.Allowed || decision.RuleID != "authorized-dns-service" || decision.Reason != ReasonAllowVisit {
				t.Fatalf("decision = %#v, %v", decision, evalErr)
			}
		})
	}

	unmatched, err := policy.EvaluateNetwork("47.116.200.75", 53, "udp", nil, now)
	if err != nil || unmatched.Allowed || unmatched.RuleID != "" || unmatched.Reason != ReasonDefaultDeny {
		t.Fatalf("unmatched DNS service = %#v, %v", unmatched, err)
	}
}

func TestPolicyRestrictedTargetsCanBeEnabledWithoutOverridingRules(t *testing.T) {
	now := time.Now().UTC()
	open, err := NewPolicyWithNetworkAccess(nil, true, NetworkAccess{AllowRestrictedTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, rawURL := range []string{"http://127.0.0.1/", "http://10.1.2.3/", "http://169.254.169.254/", "http://host.docker.internal/"} {
		decision, evalErr := open.Evaluate(rawURL, "GET", nil, now)
		if evalErr != nil || !decision.Allowed || decision.Reason != ReasonAllowVisit {
			t.Fatalf("enabled restricted target %s = %#v, %v", rawURL, decision, evalErr)
		}
	}
	rebound, err := open.Evaluate("http://internal.example/", "GET", []netip.Addr{netip.MustParseAddr("10.1.2.3")}, now)
	if err != nil || !rebound.Allowed || rebound.Reason != ReasonAllowVisit {
		t.Fatalf("enabled DNS resolution to restricted target = %#v, %v", rebound, err)
	}
	for _, rawURL := range []string{"http://0.0.0.1/", "http://224.0.0.1/", "http://192.0.2.1/"} {
		decision, evalErr := open.Evaluate(rawURL, "GET", nil, now)
		if evalErr != nil || decision.Allowed || decision.Reason != ReasonForbiddenAddress {
			t.Fatalf("always invalid target %s = %#v, %v", rawURL, decision, evalErr)
		}
	}
	bound, err := NewPolicyWithNetworkAccess([]Rule{{
		ID: "private-service", Effect: EffectAllowVisit, Target: RuleTarget{Host: "10.1.2.3", Ports: []int{8080}},
	}}, false, NetworkAccess{AllowRestrictedTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := bound.EvaluateNetwork("10.1.2.3", 8080, "tcp", nil, now)
	if err != nil || !allowed.Allowed || allowed.RuleID != "private-service" {
		t.Fatalf("matched private target = %#v, %v", allowed, err)
	}
	denied, err := bound.EvaluateNetwork("10.1.2.3", 8081, "tcp", nil, now)
	if err != nil || denied.Allowed || denied.Reason != ReasonDefaultDeny {
		t.Fatalf("unmatched private target = %#v, %v", denied, err)
	}
	for _, port := range []int{53, 784, 853, 8853, 2375, 2376} {
		decision, evalErr := open.EvaluateNetwork("93.184.216.34", port, "tcp", nil, now)
		if evalErr != nil || !decision.Allowed || decision.RuleID != "" {
			t.Fatalf("public service port %d = %#v, %v", port, decision, evalErr)
		}
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

func TestPolicyPublicServicePortsAndResolverHostsAreNotSpecial(t *testing.T) {
	now := time.Now().UTC()
	policy, err := NewPolicyWithDefault(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, rawURL := range []string{"https://dns.google/", "https://tenant.dns.nextdns.io/", "https://example.com:2376/", "http://example.com:53/"} {
		decision, evalErr := policy.Evaluate(rawURL, "GET", nil, now)
		if evalErr != nil || !decision.Allowed || decision.Reason != ReasonAllowVisit {
			t.Fatalf("ordinary public target %s = %#v, %v", rawURL, decision, evalErr)
		}
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
		{name: "unmatched DoH hostname", host: "cloudflare-dns.com", reason: ReasonDefaultDeny},
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
		{{ID: "wildcard-allow", Effect: EffectAllowVisit, Target: RuleTarget{Host: "*.example.com"}}},
		{{ID: "auth-missing", Effect: EffectAuthOnly, Target: RuleTarget{Host: "example.com"}}},
		{{ID: "auth-leak", Effect: EffectAllowVisit, AuthProfileID: "profile", Target: RuleTarget{Host: "example.com"}}},
	}
	for _, rules := range invalid {
		if _, err := NewPolicy(rules); err == nil {
			t.Fatalf("invalid policy accepted: %#v", rules)
		}
	}
}

func TestPolicyBlockedHostWildcardsAndPorts(t *testing.T) {
	now := time.Now().UTC()
	policy, err := NewPolicyWithDefault([]Rule{
		{ID: "global-ssh-block", Effect: EffectBlocked, Target: RuleTarget{Host: "*", Schemes: []string{"tcp"}, Ports: []int{22}}},
		{ID: "example-family-block", Effect: EffectBlocked, Target: RuleTarget{Host: "*.example.com", Schemes: []string{"https"}}},
	}, true)
	if err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{"example.com", "api.example.com", "deep.api.example.com"} {
		decision, evalErr := policy.Evaluate("https://"+host+"/", "GET", nil, now)
		if evalErr != nil || decision.Allowed || decision.RuleID != "example-family-block" {
			t.Fatalf("wildcard host %q = %#v, %v", host, decision, evalErr)
		}
	}
	nonMatch, err := policy.Evaluate("https://badexample.com/", "GET", nil, now)
	if err != nil || !nonMatch.Allowed {
		t.Fatalf("wildcard boundary false positive = %#v, %v", nonMatch, err)
	}
	blockedPort, err := policy.EvaluateNetwork("service.example.net", 22, "tcp", nil, now)
	if err != nil || blockedPort.Allowed || blockedPort.RuleID != "global-ssh-block" {
		t.Fatalf("global blocked port = %#v, %v", blockedPort, err)
	}
	allowedPort, err := policy.EvaluateNetwork("service.example.net", 443, "tcp", nil, now)
	if err != nil || !allowedPort.Allowed {
		t.Fatalf("unmatched global port = %#v, %v", allowedPort, err)
	}
}

func TestPolicyBlockedPathSubtreesExactInterfacesAndURLShorthand(t *testing.T) {
	now := time.Now().UTC()
	policy, err := NewPolicyWithDefault([]Rule{
		{ID: "all-api", Effect: EffectBlocked, Target: RuleTarget{Host: "*", PathPrefixes: []string{"/api/*"}}},
		{ID: "exact-interface", Effect: EffectBlocked, Target: RuleTarget{Host: "*", PathPrefixes: []string{"=/desasdasdasd/sdadsd"}}},
		{ID: "url-subtree", Effect: EffectBlocked, Target: RuleTarget{Host: "http://ssss.com/sdasdad/*"}},
	}, true)
	if err != nil {
		t.Fatal(err)
	}

	for _, rawURL := range []string{"https://one.example/api", "https://two.example/api/users", "http://ssss.com/sdasdad", "http://ssss.com/sdasdad/child", "https://any.example/desasdasdasd/sdadsd"} {
		decision, evalErr := policy.Evaluate(rawURL, "GET", nil, now)
		if evalErr != nil || decision.Allowed || decision.Reason != ReasonBlockedPath {
			t.Fatalf("blocked path %q = %#v, %v", rawURL, decision, evalErr)
		}
	}
	for _, rawURL := range []string{
		"https://one.example/apix",
		"https://any.example/desasdasdasd/sdadsd/child",
		"https://ssss.com/sdasdad/child",
		"http://other.example/sdasdad/child",
	} {
		decision, evalErr := policy.Evaluate(rawURL, "GET", nil, now)
		if evalErr != nil || !decision.Allowed || decision.RuleID != "" {
			t.Fatalf("allowed path %q = %#v, %v", rawURL, decision, evalErr)
		}
	}
	transport, err := policy.EvaluateNetwork("one.example", 22, "tcp", nil, now)
	if err != nil || !transport.Allowed || transport.RuleID != "" {
		t.Fatalf("HTTP-only global path rule leaked into TCP = %#v, %v", transport, err)
	}
}

func TestPolicyDNSAppliesOnlyUnconditionalWildcardBlocks(t *testing.T) {
	now := time.Now().UTC()
	policy, err := NewPolicyWithDefault([]Rule{
		{ID: "blocked-domain-family", Effect: EffectBlocked, Target: RuleTarget{Host: "*.blocked.example"}},
		{ID: "http-path-only", Effect: EffectBlocked, Target: RuleTarget{Host: "*", PathPrefixes: []string{"/api/*"}}},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := policy.EvaluateDNS("api.blocked.example", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, now)
	if err != nil || blocked.Allowed || blocked.RuleID != "blocked-domain-family" {
		t.Fatalf("wildcard DNS block = %#v, %v", blocked, err)
	}
	allowed, err := policy.EvaluateDNS("allowed.example", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, now)
	if err != nil || !allowed.Allowed || allowed.RuleID != "" {
		t.Fatalf("path-scoped wildcard must not block DNS = %#v, %v", allowed, err)
	}
}
