package boundary

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	ReasonDefaultDeny = "default-deny"
	// Legacy reason codes remain readable for existing audit rows. New blocked
	// decisions use the dimension-specific codes below.
	ReasonBlockedPath           = "blocked-path"
	ReasonBlockedTarget         = "blocked-target"
	ReasonBlockedPathExact      = "blocked-path-exact"
	ReasonBlockedPathSubtree    = "blocked-path-subtree"
	ReasonBlockedMethod         = "blocked-method"
	ReasonBlockedDomain         = "blocked-domain"
	ReasonBlockedDomainWildcard = "blocked-domain-wildcard"
	ReasonBlockedIP             = "blocked-ip"
	ReasonBlockedCIDR           = "blocked-cidr"
	ReasonBlockedPort           = "blocked-port"
	ReasonBlockedProtocol       = "blocked-protocol"
	ReasonBlockedAll            = "blocked-all"
	ReasonAllowAttack           = "allow-attack"
	ReasonAllowVisit            = "allow-visit"
	ReasonForbiddenHostname     = "forbidden-hostname"
	ReasonForbiddenAddress      = "forbidden-address"
	ReasonDNSRebinding          = "dns-rebinding"
)

// NetworkAccess controls whether a conversation may reach infrastructure and
// non-public address ranges. It is immutable for the lifetime of one boundary
// snapshot and defaults to false for every legacy caller and snapshot.
type NetworkAccess struct {
	AllowRestrictedTargets bool `json:"allowRestrictedTargets"`
}

type Rule struct {
	ID            string     `json:"id"`
	Effect        Effect     `json:"effect"`
	Target        RuleTarget `json:"target"`
	AuthProfileID string     `json:"authProfileId,omitempty"`
	RateLimit     RateLimit  `json:"rateLimit"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
}

// RateLimit is the immutable request-governance contract attached to one
// boundary rule. Zero means unlimited for that dimension. MaxConcurrent is
// omitted from legacy snapshots when zero, so already-bound canonical
// documents remain byte-for-byte valid.
type RateLimit struct {
	RequestsPerSecond float64 `json:"requestsPerSecond"`
	Burst             int     `json:"burst"`
	MaxConcurrent     int     `json:"maxConcurrent,omitempty"`
}

type Decision struct {
	Allowed    bool          `json:"allowed"`
	Effect     Effect        `json:"effect,omitempty"`
	RuleID     string        `json:"ruleId,omitempty"`
	RateLimit  RateLimit     `json:"rateLimit"`
	Reason     string        `json:"reason"`
	Target     RequestTarget `json:"target"`
	BlockMatch *BlockMatch   `json:"blockMatch,omitempty"`
}

// DNSDecision is the policy result for resolving one canonical hostname. DNS
// has no request scheme, port, method, or path, so it permits a name when at
// least one active allow rule can use that name and denies it when an
// unconditional host/network block applies. The request proxy still evaluates
// every concrete HTTP request independently.
type DNSDecision struct {
	Allowed    bool        `json:"allowed"`
	Effect     Effect      `json:"effect,omitempty"`
	RuleID     string      `json:"ruleId,omitempty"`
	Reason     string      `json:"reason"`
	Host       string      `json:"host"`
	BlockMatch *BlockMatch `json:"blockMatch,omitempty"`
}

type Policy struct {
	rules                  []compiledRule
	defaultAllow           bool
	allowRestrictedTargets bool
}

type compiledRule struct {
	Rule
	prefix *netip.Prefix
}

func NewPolicy(rules []Rule) (*Policy, error) {
	return NewPolicyWithDefault(rules, false)
}

// NewPolicyWithDefault compiles an immutable policy with an explicit fallback.
// Existing policy documents remain fail-closed; only the canonical no-boundary
// snapshot opts into defaultAllow.
func NewPolicyWithDefault(rules []Rule, defaultAllow bool) (*Policy, error) {
	return NewPolicyWithNetworkAccess(rules, defaultAllow, NetworkAccess{})
}

// NewPolicyWithNetworkAccess compiles a policy with its immutable fallback and
// conversation-scoped restricted-target gate. The gate only makes restricted
// targets eligible for normal policy evaluation; it never overrides a user
// rule or a custom policy's default deny.
func NewPolicyWithNetworkAccess(rules []Rule, defaultAllow bool, access NetworkAccess) (*Policy, error) {
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
		if strings.Contains(target.Host, "*") && rule.Effect != EffectBlocked {
			return nil, fmt.Errorf("%w: boundary rule %q: only blocked rules may use host wildcards", ErrInvalidTarget, rule.ID)
		}
		if rule.ExpiresAt != nil {
			value := rule.ExpiresAt.UTC()
			rule.ExpiresAt = &value
		}
		compiled = append(compiled, compiledRule{Rule: rule, prefix: prefix})
	}
	return &Policy{rules: compiled, defaultAllow: defaultAllow, allowRestrictedTargets: access.AllowRestrictedTargets}, nil
}

// Evaluate normalizes every request independently, so redirects must call it
// again for each destination. resolvedIPs are checked before allow rules.
func (p *Policy) Evaluate(rawURL, method string, resolvedIPs []netip.Addr, now time.Time) (Decision, error) {
	target, err := NormalizeRequestTarget(rawURL, method)
	if err != nil {
		return Decision{}, err
	}
	decision := p.defaultDecision(target)
	phase := DecisionPhaseRequest
	if len(resolvedIPs) != 0 {
		phase = DecisionPhaseAfterResolution
		if !decision.Allowed {
			decision.BlockMatch = defaultBlockMatch(target, phase)
		}
	}
	if reason := p.forbiddenHostnameReason(target.Host); reason != "" {
		decision.Allowed, decision.Reason = false, reason
		decision.BlockMatch = systemBlockMatch(target, MatchTypeHostname, target.Host, phase)
		return decision, nil
	}
	if address, err := netip.ParseAddr(target.Host); err == nil {
		if p.forbiddenAddress(address) {
			decision.Allowed, decision.Reason = false, ReasonForbiddenAddress
			decision.BlockMatch = systemBlockMatch(target, MatchTypeAddress, address.Unmap().String(), phase)
			return decision, nil
		}
	}
	for _, address := range resolvedIPs {
		if !address.IsValid() || p.forbiddenAddress(address.Unmap()) {
			decision.Allowed, decision.Reason = false, ReasonDNSRebinding
			value := "invalid-address"
			if address.IsValid() {
				value = address.Unmap().String()
			}
			decision.BlockMatch = systemBlockMatch(target, MatchTypeAddress, value, DecisionPhaseAfterResolution)
			if address.IsValid() {
				decision.BlockMatch.ResolvedIP = address.Unmap().String()
			}
			return decision, nil
		}
	}
	return p.evaluateTarget(target, decision, resolvedIPs, phase, now), nil
}

// EvaluateNetwork applies the same immutable rules to a raw TCP, UDP or ICMP target.
// HTTP-only path and method constraints do not apply to transport connections.
func (p *Policy) EvaluateNetwork(rawHost string, port int, protocol string, resolvedIPs []netip.Addr, now time.Time) (Decision, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		return Decision{}, fmt.Errorf("unsupported network protocol %q", protocol)
	}
	host, err := NormalizeHost(rawHost)
	if err != nil {
		return Decision{}, err
	}
	if protocol == "icmp" && port != 0 {
		return Decision{}, fmt.Errorf("%w: ICMP does not use a port", ErrInvalidTarget)
	}
	if protocol != "icmp" && (port < 1 || port > 65535) {
		return Decision{}, fmt.Errorf("%w: port %d is outside 1..65535", ErrInvalidTarget, port)
	}
	target := RequestTarget{Scheme: protocol, Host: host, Port: port, Path: "/"}
	decision := p.defaultDecision(target)
	decision.BlockMatch = defaultBlockMatch(target, DecisionPhaseConnect)
	if reason := p.forbiddenHostnameReason(host); reason != "" {
		decision.Allowed, decision.Reason = false, reason
		decision.BlockMatch = systemBlockMatch(target, MatchTypeHostname, host, DecisionPhaseConnect)
		return decision, nil
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil && p.forbiddenAddress(address) {
		decision.Allowed, decision.Reason = false, ReasonForbiddenAddress
		decision.BlockMatch = systemBlockMatch(target, MatchTypeAddress, address.Unmap().String(), DecisionPhaseConnect)
		return decision, nil
	}
	for _, address := range resolvedIPs {
		if !address.IsValid() || p.forbiddenAddress(address.Unmap()) {
			decision.Allowed, decision.Reason = false, ReasonDNSRebinding
			value := "invalid-address"
			if address.IsValid() {
				value = address.Unmap().String()
			}
			decision.BlockMatch = systemBlockMatch(target, MatchTypeAddress, value, DecisionPhaseConnect)
			if address.IsValid() {
				decision.BlockMatch.ResolvedIP = address.Unmap().String()
			}
			return decision, nil
		}
	}
	return p.evaluateTarget(target, decision, resolvedIPs, DecisionPhaseConnect, now), nil
}

func (p *Policy) defaultDecision(target RequestTarget) Decision {
	decision := Decision{Target: target, Reason: ReasonDefaultDeny, BlockMatch: defaultBlockMatch(target, DecisionPhaseRequest)}
	if p != nil && p.defaultAllow {
		decision.Allowed = true
		decision.Effect = EffectAllowVisit
		decision.Reason = ReasonAllowVisit
		decision.BlockMatch = nil
	}
	return decision
}

type evaluatedRuleMatch struct {
	rule        compiledRule
	matchedPath string
	matchedIP   string
}

func (p *Policy) evaluateTarget(target RequestTarget, decision Decision, resolvedIPs []netip.Addr, phase string, now time.Time) Decision {
	matches := make([]evaluatedRuleMatch, 0)
	for _, rule := range p.rules {
		if rule.ExpiresAt != nil && !now.Before(*rule.ExpiresAt) {
			continue
		}
		if matchedPath, matchedIP, ok := ruleMatches(rule, target, resolvedIPs); ok {
			matches = append(matches, evaluatedRuleMatch{rule: rule, matchedPath: matchedPath, matchedIP: matchedIP})
		}
	}
	if len(matches) == 0 {
		return decision
	}
	sort.Slice(matches, func(i, j int) bool {
		left, right := ruleRank(matches[i].rule), ruleRank(matches[j].rule)
		if left != right {
			return left > right
		}
		leftSpecificity, rightSpecificity := ruleSpecificity(matches[i].rule, matches[i].matchedPath), ruleSpecificity(matches[j].rule, matches[j].matchedPath)
		if leftSpecificity != rightSpecificity {
			return leftSpecificity > rightSpecificity
		}
		return matches[i].rule.ID < matches[j].rule.ID
	})
	winnerMatch := matches[0]
	winner := winnerMatch.rule
	decision.Allowed = false
	decision.Effect = winner.Effect
	decision.RuleID = winner.ID
	decision.RateLimit = winner.RateLimit
	switch winner.Effect {
	case EffectBlocked:
		decision.BlockMatch = ruleBlockMatch(winner, target, winnerMatch.matchedPath, winnerMatch.matchedIP, phase)
		decision.Reason = reasonForBlockedRule(decision.BlockMatch)
	case EffectAllowAttack:
		decision.Allowed, decision.Reason = true, ReasonAllowAttack
	case EffectAuthOnly:
		// Historical snapshots may still contain auth-only rules. Credential
		// injection has been removed, so these rules now fail closed.
		decision.BlockMatch = ruleBlockMatch(winner, target, winnerMatch.matchedPath, winnerMatch.matchedIP, phase)
		decision.Reason = reasonForBlockedRule(decision.BlockMatch)
	case EffectAllowVisit:
		decision.Allowed, decision.Reason = true, ReasonAllowVisit
		decision.BlockMatch = nil
	}
	if decision.Allowed {
		decision.BlockMatch = nil
	}
	return decision
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

// EvaluateDNS decides whether the policy DNS service may resolve rawHost.
// resolvedIPs must contain every address returned by the upstream resolver;
// one unsafe address denies the complete answer to prevent rebinding.
func (p *Policy) EvaluateDNS(rawHost string, resolvedIPs []netip.Addr, now time.Time) (DNSDecision, error) {
	host, err := NormalizeHost(rawHost)
	if err != nil {
		return DNSDecision{}, err
	}
	phase := DecisionPhaseRequest
	if len(resolvedIPs) != 0 {
		phase = DecisionPhaseAfterResolution
	}
	target := RequestTarget{Scheme: "dns", Host: host, Path: "/"}
	decision := DNSDecision{Host: host, Reason: ReasonDefaultDeny, BlockMatch: defaultBlockMatch(target, phase)}
	if p != nil && p.defaultAllow {
		decision.Allowed = true
		decision.Effect = EffectAllowVisit
		decision.Reason = ReasonAllowVisit
		decision.BlockMatch = nil
	}
	if reason := p.forbiddenHostnameReason(host); reason != "" {
		decision.Reason = reason
		decision.BlockMatch = systemBlockMatch(target, MatchTypeHostname, host, phase)
		return decision, nil
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil && p.forbiddenAddress(address) {
		decision.Reason = ReasonForbiddenAddress
		decision.BlockMatch = systemBlockMatch(target, MatchTypeAddress, address.Unmap().String(), phase)
		return decision, nil
	}
	for _, address := range resolvedIPs {
		if !address.IsValid() || address.Zone() != "" || p.forbiddenAddress(address.Unmap()) {
			decision.Reason = ReasonDNSRebinding
			value := "invalid-address"
			if address.IsValid() {
				value = address.Unmap().String()
			}
			decision.BlockMatch = systemBlockMatch(target, MatchTypeAddress, value, DecisionPhaseAfterResolution)
			if address.IsValid() {
				decision.BlockMatch.ResolvedIP = address.Unmap().String()
			}
			return decision, nil
		}
	}

	blocks := make([]evaluatedRuleMatch, 0)
	allows := make([]compiledRule, 0)
	for _, rule := range p.rules {
		if rule.ExpiresAt != nil && !now.Before(*rule.ExpiresAt) {
			continue
		}
		if matchedIP, blocked := dnsRuleUnconditionallyBlocks(rule, host, resolvedIPs); rule.Effect == EffectBlocked && blocked {
			blocks = append(blocks, evaluatedRuleMatch{rule: rule, matchedIP: matchedIP})
			continue
		}
		if rule.prefix == nil && rule.Target.Host == host && rule.Effect.AllowsRequest() {
			allows = append(allows, rule)
		}
	}
	if len(blocks) != 0 {
		sort.Slice(blocks, func(i, j int) bool {
			leftSpecificity, rightSpecificity := ruleSpecificity(blocks[i].rule), ruleSpecificity(blocks[j].rule)
			if leftSpecificity != rightSpecificity {
				return leftSpecificity > rightSpecificity
			}
			return blocks[i].rule.ID < blocks[j].rule.ID
		})
		winner := blocks[0]
		decision.Effect = EffectBlocked
		decision.Allowed = false
		decision.RuleID = winner.rule.ID
		decision.BlockMatch = ruleBlockMatch(winner.rule, target, "", winner.matchedIP, phase)
		decision.Reason = reasonForBlockedRule(decision.BlockMatch)
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
	decision.BlockMatch = nil
	decision.Effect = winner.Effect
	decision.RuleID = winner.ID
	switch winner.Effect {
	case EffectAllowAttack:
		decision.Reason = ReasonAllowAttack
	case EffectAllowVisit:
		decision.Reason = ReasonAllowVisit
	}
	return decision, nil
}

func dnsRuleUnconditionallyBlocks(rule compiledRule, host string, resolvedIPs []netip.Addr) (string, bool) {
	if len(rule.Target.Schemes) != 0 || len(rule.Target.Ports) != 0 || len(rule.Target.PathPrefixes) != 0 || len(rule.Target.Methods) != 0 {
		return "", false
	}
	if rule.prefix == nil {
		return ruleHostMatchesResolved(rule, host, resolvedIPs)
	}
	for _, address := range resolvedIPs {
		if address.IsValid() && rule.prefix.Contains(address.Unmap()) {
			return address.Unmap().String(), true
		}
	}
	return "", false
}

func ruleMatches(rule compiledRule, target RequestTarget, resolvedIPs []netip.Addr) (string, string, bool) {
	matchedIP, hostMatches := ruleHostMatchesResolved(rule, target.Host, resolvedIPs)
	if !hostMatches {
		return "", "", false
	}
	if !containsStringOrAny(rule.Target.Schemes, target.Scheme) || !containsIntOrAny(rule.Target.Ports, target.Port) {
		return "", "", false
	}
	if target.Scheme == "tcp" || target.Scheme == "udp" || target.Scheme == "icmp" {
		// Transport connections have no HTTP path or method. Explicitly selected
		// TCP/UDP/ICMP schemes therefore ignore those HTTP-only dimensions. A
		// path/method-only rule with no scheme is HTTP-only and must not become a
		// global transport rule merely because its host is a wildcard.
		if len(rule.Target.Schemes) == 0 && (len(rule.Target.PathPrefixes) != 0 || len(rule.Target.Methods) != 0) {
			return "", "", false
		}
		return "", matchedIP, rule.Effect != EffectAuthOnly
	}
	if !ruleMethodMatches(rule, target.Method) {
		return "", "", false
	}
	if len(rule.Target.PathPrefixes) == 0 {
		return "", matchedIP, true
	}
	matchedPath := ""
	for _, pattern := range rule.Target.PathPrefixes {
		if pathPatternMatches(pattern, target.Path) {
			if matchedPath == "" || betterMatchedPath(pattern, matchedPath) {
				matchedPath = pattern
			}
		}
	}
	return matchedPath, matchedIP, matchedPath != ""
}

func ruleMethodMatches(rule compiledRule, method string) bool {
	return containsStringOrAny(rule.Target.Methods, method)
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

func ruleSpecificity(rule compiledRule, matchedPath ...string) int {
	score := constrainedSetSpecificity(rule.Target.Schemes) + constrainedIntSetSpecificity(rule.Target.Ports) + constrainedSetSpecificity(rule.Target.Methods)
	pathScore := 0
	if len(matchedPath) != 0 && matchedPath[0] != "" {
		pathScore = pathPatternSpecificity(matchedPath[0])
	} else {
		for _, pattern := range rule.Target.PathPrefixes {
			candidate := pathPatternSpecificity(pattern)
			if candidate > pathScore {
				pathScore = candidate
			}
		}
	}
	if pathScore > 0 {
		score += pathScore - len(rule.Target.PathPrefixes)
	}
	switch {
	case rule.prefix != nil:
		score += rule.prefix.Bits() * 100
	case rule.Target.Host == "*":
		// A catch-all host is intentionally the least specific host matcher.
	case strings.HasPrefix(rule.Target.Host, "*."):
		score += 50000 + len(rule.Target.Host)
	default:
		score += 100000
	}
	return score
}

func pathPatternSpecificity(pattern string) int {
	if pattern == "" {
		return 0
	}
	score := 1000 + len(pattern)*4
	if strings.HasPrefix(pattern, "=") {
		// Exact selectors always outrank subtree selectors, even when the
		// latter contains a much longer textual prefix.
		score += 1_000_000
	}
	return score
}

func betterMatchedPath(candidate, current string) bool {
	candidateExact, currentExact := strings.HasPrefix(candidate, "="), strings.HasPrefix(current, "=")
	if candidateExact != currentExact {
		return candidateExact
	}
	return len(candidate) > len(current)
}

func ruleHostMatchesResolved(rule compiledRule, host string, resolvedIPs []netip.Addr) (string, bool) {
	if rule.prefix != nil {
		if address, err := netip.ParseAddr(host); err == nil && rule.prefix.Contains(address.Unmap()) {
			return address.Unmap().String(), true
		}
		for _, address := range resolvedIPs {
			if address.IsValid() && address.Zone() == "" && rule.prefix.Contains(address.Unmap()) {
				return address.Unmap().String(), true
			}
		}
		return "", false
	}
	if configured, err := netip.ParseAddr(rule.Target.Host); err == nil {
		configured = configured.Unmap()
		if address, parseErr := netip.ParseAddr(host); parseErr == nil && address.Unmap() == configured {
			return configured.String(), true
		}
		for _, address := range resolvedIPs {
			if address.IsValid() && address.Zone() == "" && address.Unmap() == configured {
				return configured.String(), true
			}
		}
		return "", false
	}
	return "", ruleHostMatches(rule, host)
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

func pathPatternMatches(pattern, target string) bool {
	if strings.HasPrefix(pattern, "=") {
		return target == strings.TrimPrefix(pattern, "=")
	}
	return pathPrefixMatches(pattern, target)
}

func ruleHostMatches(rule compiledRule, host string) bool {
	if rule.prefix != nil {
		address, err := netip.ParseAddr(host)
		return err == nil && rule.prefix.Contains(address)
	}
	switch {
	case rule.Target.Host == "*":
		return true
	case strings.HasPrefix(rule.Target.Host, "*."):
		base := strings.TrimPrefix(rule.Target.Host, "*.")
		return host == base || strings.HasSuffix(host, "."+base)
	default:
		return rule.Target.Host == host
	}
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

func (p *Policy) forbiddenHostnameReason(host string) string {
	if !p.allowRestrictedTargets && (host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "localhost.localdomain" ||
		host == "host.docker.internal" || host == "gateway.docker.internal" || host == "docker.for.mac.host.internal" ||
		host == "metadata.google.internal" || host == "instance-data.ec2.internal") {
		return ReasonForbiddenHostname
	}
	return ""
}

var alwaysInvalidPrefixes = mustPrefixes(
	"0.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24",
	"203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32",
)

var restrictedTargetPrefixes = mustPrefixes(
	"100.64.0.0/10", "198.18.0.0/15",
)

func (p *Policy) forbiddenAddress(address netip.Addr) bool {
	if address.Zone() != "" {
		return true
	}
	address = address.Unmap()
	if address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalMulticast() {
		return true
	}
	for _, prefix := range alwaysInvalidPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	if p.allowRestrictedTargets {
		return false
	}
	if address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() {
		return true
	}
	for _, prefix := range restrictedTargetPrefixes {
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
