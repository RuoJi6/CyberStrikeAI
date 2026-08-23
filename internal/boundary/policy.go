package boundary

import (
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	ReasonDefaultDeny       = "default-deny"
	ReasonBlockedPath       = "blocked-path"
	ReasonBlockedTarget     = "blocked-target"
	ReasonAllowAttack       = "allow-attack"
	ReasonAllowVisit        = "allow-visit"
	ReasonAuthOnly          = "auth-only"
	ReasonForbiddenHostname = "forbidden-hostname"
	ReasonForbiddenAddress  = "forbidden-address"
	ReasonDockerAPIPort     = "docker-api-port"
	ReasonDNSServicePort    = "dns-service-port"
	ReasonForbiddenDNSHost  = "forbidden-dns-service"
	ReasonDNSRebinding      = "dns-rebinding"
)

type Rule struct {
	ID            string     `json:"id"`
	Effect        Effect     `json:"effect"`
	Target        RuleTarget `json:"target"`
	AuthProfileID string     `json:"authProfileId,omitempty"`
	RateLimit     RateLimit  `json:"rateLimit"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
}

// RateLimit is the immutable request-governance contract attached to one
// boundary rule. MaxConcurrent is additive and omitted from legacy snapshots
// when zero, so already-bound canonical documents remain byte-for-byte valid.
type RateLimit struct {
	RequestsPerSecond float64 `json:"requestsPerSecond"`
	Burst             int     `json:"burst"`
	MaxConcurrent     int     `json:"maxConcurrent,omitempty"`
}

type Decision struct {
	Allowed       bool          `json:"allowed"`
	Effect        Effect        `json:"effect,omitempty"`
	RuleID        string        `json:"ruleId,omitempty"`
	AuthProfileID string        `json:"authProfileId,omitempty"`
	RateLimit     RateLimit     `json:"rateLimit"`
	Reason        string        `json:"reason"`
	Target        RequestTarget `json:"target"`
}

// DNSDecision is the policy result for resolving one canonical hostname. DNS
// has no request scheme, port, method, or path, so it permits a name when at
// least one active allow rule can use that name and denies it when an
// unconditional host/network block applies. The request proxy still evaluates
// every concrete HTTP request independently.
type DNSDecision struct {
	Allowed bool   `json:"allowed"`
	Effect  Effect `json:"effect,omitempty"`
	RuleID  string `json:"ruleId,omitempty"`
	Reason  string `json:"reason"`
	Host    string `json:"host"`
}

type Policy struct {
	rules []compiledRule
}

type compiledRule struct {
	Rule
	prefix *netip.Prefix
}

func NewPolicy(rules []Rule) (*Policy, error) {
	compiled := make([]compiledRule, 0, len(rules))
	seenIDs := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		rule.ID = strings.TrimSpace(rule.ID)
		if rule.ID == "" {
			return nil, fmt.Errorf("boundary rule id is required")
		}
		if _, duplicate := seenIDs[rule.ID]; duplicate {
			return nil, fmt.Errorf("duplicate boundary rule id %q", rule.ID)
		}
		seenIDs[rule.ID] = struct{}{}
		if !rule.Effect.Valid() {
			return nil, fmt.Errorf("invalid boundary rule effect %q", rule.Effect)
		}
		rule.AuthProfileID = strings.TrimSpace(rule.AuthProfileID)
		if rule.Effect == EffectAuthOnly && rule.AuthProfileID == "" {
			return nil, fmt.Errorf("boundary rule %q: auth-only requires an auth profile", rule.ID)
		}
		if rule.Effect != EffectAuthOnly && rule.AuthProfileID != "" {
			return nil, fmt.Errorf("boundary rule %q: auth profile requires auth-only effect", rule.ID)
		}
		if err := ValidateRateLimit(rule.RateLimit); err != nil {
			return nil, fmt.Errorf("boundary rule %q: %w", rule.ID, err)
		}
		target, err := NormalizeRuleTarget(rule.Target)
		if err != nil {
			return nil, fmt.Errorf("normalize boundary rule %q: %w", rule.ID, err)
		}
		rule.Target = target
		var prefix *netip.Prefix
		if strings.Contains(target.Host, "/") {
			if rule.Effect != EffectBlocked {
				return nil, fmt.Errorf("boundary rule %q: only blocked rules may use IP prefixes", rule.ID)
			}
			parsed, err := netip.ParsePrefix(target.Host)
			if err != nil {
				return nil, fmt.Errorf("boundary rule %q: %w", rule.ID, err)
			}
			prefix = &parsed
		}
		if rule.ExpiresAt != nil {
			value := rule.ExpiresAt.UTC()
			rule.ExpiresAt = &value
		}
		compiled = append(compiled, compiledRule{Rule: rule, prefix: prefix})
	}
	return &Policy{rules: compiled}, nil
}

// Evaluate normalizes every request independently, so redirects must call it
// again for each destination. resolvedIPs are checked before allow rules.
func (p *Policy) Evaluate(rawURL, method string, resolvedIPs []netip.Addr, now time.Time) (Decision, error) {
	target, err := NormalizeRequestTarget(rawURL, method)
	if err != nil {
		return Decision{}, err
	}
	decision := Decision{Target: target, Reason: ReasonDefaultDeny}
	if reason := forbiddenHostnameReason(target.Host); reason != "" {
		decision.Reason = reason
		return decision, nil
	}
	if target.Port == 2375 || target.Port == 2376 {
		decision.Reason = ReasonDockerAPIPort
		return decision, nil
	}
	if forbiddenDNSServicePort(target.Port) {
		decision.Reason = ReasonDNSServicePort
		return decision, nil
	}
	if address, err := netip.ParseAddr(target.Host); err == nil {
		if forbiddenAddress(address) {
			decision.Reason = ReasonForbiddenAddress
			return decision, nil
		}
	}
	for _, address := range resolvedIPs {
		if !address.IsValid() || forbiddenAddress(address.Unmap()) {
			decision.Reason = ReasonDNSRebinding
			return decision, nil
		}
	}

	matches := make([]compiledRule, 0)
	for _, rule := range p.rules {
		if rule.ExpiresAt != nil && !now.Before(*rule.ExpiresAt) {
			continue
		}
		if ruleMatches(rule, target) {
			matches = append(matches, rule)
		}
	}
	if len(matches) == 0 {
		return decision, nil
	}
	sort.Slice(matches, func(i, j int) bool {
		left, right := ruleRank(matches[i]), ruleRank(matches[j])
		if left != right {
			return left > right
		}
		leftSpecificity, rightSpecificity := ruleSpecificity(matches[i]), ruleSpecificity(matches[j])
		if leftSpecificity != rightSpecificity {
			return leftSpecificity > rightSpecificity
		}
		return matches[i].ID < matches[j].ID
	})
	winner := matches[0]
	decision.Effect = winner.Effect
	decision.RuleID = winner.ID
	decision.AuthProfileID = winner.AuthProfileID
	decision.RateLimit = winner.RateLimit
	switch winner.Effect {
	case EffectBlocked:
		if len(winner.Target.PathPrefixes) > 0 {
			decision.Reason = ReasonBlockedPath
		} else {
			decision.Reason = ReasonBlockedTarget
		}
	case EffectAllowAttack:
		decision.Allowed = true
		decision.Reason = ReasonAllowAttack
	case EffectAuthOnly:
		decision.Allowed = true
		decision.Reason = ReasonAuthOnly
	case EffectAllowVisit:
		decision.Allowed = true
		decision.Reason = ReasonAllowVisit
	}
	return decision, nil
}

// ValidateRateLimit rejects unbounded or non-finite attacker-controlled
// values before they can enter an immutable snapshot or allocate gateway
// state. Zero keeps the legacy "not explicitly configured" meaning.
func ValidateRateLimit(limit RateLimit) error {
	if math.IsNaN(limit.RequestsPerSecond) || math.IsInf(limit.RequestsPerSecond, 0) ||
		limit.RequestsPerSecond < 0 || limit.RequestsPerSecond > 10000 ||
		limit.Burst < 0 || limit.Burst > 100000 || limit.MaxConcurrent < 0 || limit.MaxConcurrent > 1024 ||
		(limit.RequestsPerSecond == 0) != (limit.Burst == 0) {
		return fmt.Errorf("boundary rate limit is invalid")
	}
	return nil
}

// AuthProfileIDs returns the canonical set of credential profiles referenced
// by this immutable policy. Profile contents remain gateway-only material.
func (p *Policy) AuthProfileIDs() []string {
	if p == nil {
		return nil
	}
	seen := make(map[string]struct{})
	for _, rule := range p.rules {
		if rule.Effect == EffectAuthOnly && rule.AuthProfileID != "" {
			seen[rule.AuthProfileID] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for id := range seen {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

// EvaluateDNS decides whether the policy DNS service may resolve rawHost.
// resolvedIPs must contain every address returned by the upstream resolver;
// one unsafe address denies the complete answer to prevent rebinding.
func (p *Policy) EvaluateDNS(rawHost string, resolvedIPs []netip.Addr, now time.Time) (DNSDecision, error) {
	host, err := NormalizeHost(rawHost)
	if err != nil {
		return DNSDecision{}, err
	}
	decision := DNSDecision{Host: host, Reason: ReasonDefaultDeny}
	if reason := forbiddenHostnameReason(host); reason != "" {
		decision.Reason = reason
		return decision, nil
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil && forbiddenAddress(address) {
		decision.Reason = ReasonForbiddenAddress
		return decision, nil
	}
	for _, address := range resolvedIPs {
		if !address.IsValid() || address.Zone() != "" || forbiddenAddress(address.Unmap()) {
			decision.Reason = ReasonDNSRebinding
			return decision, nil
		}
	}

	blocks := make([]compiledRule, 0)
	allows := make([]compiledRule, 0)
	for _, rule := range p.rules {
		if rule.ExpiresAt != nil && !now.Before(*rule.ExpiresAt) {
			continue
		}
		if rule.Effect == EffectBlocked && dnsRuleUnconditionallyBlocks(rule, host, resolvedIPs) {
			blocks = append(blocks, rule)
			continue
		}
		if rule.prefix == nil && rule.Target.Host == host && rule.Effect.AllowsRequest() {
			allows = append(allows, rule)
		}
	}
	if len(blocks) != 0 {
		sort.Slice(blocks, func(i, j int) bool {
			leftSpecificity, rightSpecificity := ruleSpecificity(blocks[i]), ruleSpecificity(blocks[j])
			if leftSpecificity != rightSpecificity {
				return leftSpecificity > rightSpecificity
			}
			return blocks[i].ID < blocks[j].ID
		})
		decision.Effect = EffectBlocked
		decision.RuleID = blocks[0].ID
		decision.Reason = ReasonBlockedTarget
		return decision, nil
	}
	if len(allows) == 0 {
		return decision, nil
	}
	sort.Slice(allows, func(i, j int) bool {
		left, right := ruleRank(allows[i]), ruleRank(allows[j])
		if left != right {
			return left > right
		}
		leftSpecificity, rightSpecificity := ruleSpecificity(allows[i]), ruleSpecificity(allows[j])
		if leftSpecificity != rightSpecificity {
			return leftSpecificity > rightSpecificity
		}
		return allows[i].ID < allows[j].ID
	})
	winner := allows[0]
	decision.Allowed = true
	decision.Effect = winner.Effect
	decision.RuleID = winner.ID
	switch winner.Effect {
	case EffectAllowAttack:
		decision.Reason = ReasonAllowAttack
	case EffectAuthOnly:
		decision.Reason = ReasonAuthOnly
	case EffectAllowVisit:
		decision.Reason = ReasonAllowVisit
	}
	return decision, nil
}

func dnsRuleUnconditionallyBlocks(rule compiledRule, host string, resolvedIPs []netip.Addr) bool {
	if len(rule.Target.Schemes) != 0 || len(rule.Target.Ports) != 0 || len(rule.Target.PathPrefixes) != 0 || len(rule.Target.Methods) != 0 {
		return false
	}
	if rule.prefix == nil {
		return rule.Target.Host == host
	}
	for _, address := range resolvedIPs {
		if address.IsValid() && rule.prefix.Contains(address.Unmap()) {
			return true
		}
	}
	return false
}

func ruleMatches(rule compiledRule, target RequestTarget) bool {
	if rule.prefix != nil {
		address, err := netip.ParseAddr(target.Host)
		if err != nil || !rule.prefix.Contains(address) {
			return false
		}
	} else if rule.Target.Host != target.Host {
		return false
	}
	if !containsStringOrAny(rule.Target.Schemes, target.Scheme) || !containsIntOrAny(rule.Target.Ports, target.Port) || !ruleMethodMatches(rule, target.Method) {
		return false
	}
	if len(rule.Target.PathPrefixes) == 0 {
		return true
	}
	for _, prefix := range rule.Target.PathPrefixes {
		if pathPrefixMatches(prefix, target.Path) {
			return true
		}
	}
	return false
}

// ruleMethodMatches applies the frozen allow-visit contract: omitting methods
// means ordinary read-only browsing, not every HTTP method. CONNECT is the
// transport handshake for an HTTPS visit and remains eligible for the later
// SNI and resolved-address checks; it does not authorize an application-level
// write method inside an inspected TLS session.
func ruleMethodMatches(rule compiledRule, method string) bool {
	if len(rule.Target.Methods) != 0 {
		return containsStringOrAny(rule.Target.Methods, method)
	}
	if rule.Effect != EffectAllowVisit {
		return true
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodConnect:
		return true
	default:
		return false
	}
}

func ruleRank(rule compiledRule) int {
	switch rule.Effect {
	case EffectBlocked:
		if len(rule.Target.PathPrefixes) > 0 {
			return 500
		}
		return 400
	case EffectAllowAttack:
		return 300
	case EffectAuthOnly, EffectAllowVisit:
		return 200
	default:
		return 0
	}
}

func ruleSpecificity(rule compiledRule) int {
	score := constrainedSetSpecificity(rule.Target.Schemes) + constrainedIntSetSpecificity(rule.Target.Ports) + constrainedSetSpecificity(rule.Target.Methods)
	longestPath := 0
	for _, prefix := range rule.Target.PathPrefixes {
		if len(prefix) > longestPath {
			longestPath = len(prefix)
		}
	}
	if longestPath > 0 {
		score += 1000 + longestPath*4 - len(rule.Target.PathPrefixes)
	}
	if rule.prefix == nil {
		score += 100000
	} else {
		score += rule.prefix.Bits() * 100
	}
	return score
}

func constrainedSetSpecificity(values []string) int {
	if len(values) == 0 {
		return 0
	}
	return 100 - len(values)
}

func constrainedIntSetSpecificity(values []int) int {
	if len(values) == 0 {
		return 0
	}
	return 100 - len(values)
}

func pathPrefixMatches(prefix, target string) bool {
	if prefix == "/" {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(target, prefix)
	}
	return target == prefix || strings.HasPrefix(target, prefix+"/")
}

func containsStringOrAny(values []string, target string) bool {
	if len(values) == 0 {
		return true
	}
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func containsIntOrAny(values []int, target int) bool {
	if len(values) == 0 {
		return true
	}
	index := sort.SearchInts(values, target)
	return index < len(values) && values[index] == target
}

func forbiddenHostnameReason(host string) string {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "localhost.localdomain" ||
		host == "host.docker.internal" || host == "gateway.docker.internal" || host == "docker.for.mac.host.internal" ||
		host == "metadata.google.internal" || host == "instance-data.ec2.internal" {
		return ReasonForbiddenHostname
	}
	for _, forbidden := range forbiddenDNSServiceHosts {
		if host == forbidden || strings.HasSuffix(host, "."+forbidden) {
			return ReasonForbiddenDNSHost
		}
	}
	return ""
}

func forbiddenDNSServicePort(port int) bool {
	switch port {
	case 53, 784, 853, 8853:
		return true
	default:
		return false
	}
}

var forbiddenDNSServiceHosts = []string{
	"cloudflare-dns.com",
	"security.cloudflare-dns.com",
	"family.cloudflare-dns.com",
	"one.one.one.one",
	"dns.google",
	"dns.quad9.net",
	"doh.opendns.com",
	"dns.nextdns.io",
	"dns.adguard-dns.com",
	"dns.alidns.com",
	"doh.cleanbrowsing.org",
}

var specialUsePrefixes = mustPrefixes(
	"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
	"2001:db8::/32",
)

func forbiddenAddress(address netip.Addr) bool {
	address = address.Unmap()
	if address.IsUnspecified() || address.IsLoopback() || address.IsPrivate() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return true
	}
	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}
