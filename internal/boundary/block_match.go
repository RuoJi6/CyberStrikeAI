package boundary

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	MatchSourceRule        = "rule"
	MatchSourceDefault     = "default"
	MatchSourceSystem      = "system"
	MatchSourceGovernance  = "governance"
	MatchSourceAttribution = "attribution"

	DecisionPhaseRequest         = "request"
	DecisionPhaseAfterResolution = "after-resolution"
	DecisionPhaseConnect         = "connect"

	MatchTypePathExact      = "path-exact"
	MatchTypePathSubtree    = "path-subtree"
	MatchTypeMethod         = "method"
	MatchTypeDomain         = "domain"
	MatchTypeDomainWildcard = "domain-wildcard"
	MatchTypeIP             = "ip"
	MatchTypeCIDR           = "cidr"
	MatchTypePort           = "port"
	MatchTypeProtocol       = "protocol"
	MatchTypeAll            = "all"
	MatchTypeHostname       = "hostname"
	MatchTypeAddress        = "address"
)

// RuleConstraints is the canonical, immutable selector copied from the
// boundary snapshot that actually made a decision. Path values use the same
// presentation form as the boundary-rule UI (for example /admin/* or =/health).
type RuleConstraints struct {
	Host         string   `json:"host"`
	Schemes      []string `json:"schemes"`
	Ports        []int    `json:"ports"`
	PathPrefixes []string `json:"pathPrefixes"`
	Methods      []string `json:"methods"`
}

// BlockMatch explains a denial without consulting a mutable policy draft.
// It is intentionally bounded to target and rule metadata; headers, bodies,
// credentials and query strings are never copied into this structure.
type BlockMatch struct {
	Source          string           `json:"source"`
	Type            string           `json:"type"`
	Value           string           `json:"value,omitempty"`
	RuleConstraints *RuleConstraints `json:"ruleConstraints,omitempty"`
	RequestURL      string           `json:"requestUrl,omitempty"`
	ResolvedIP      string           `json:"resolvedIp,omitempty"`
	DecisionPhase   string           `json:"decisionPhase"`
}

func displayPathPattern(pattern string) string {
	if strings.HasPrefix(pattern, "=") {
		return pattern
	}
	if pattern == "/" {
		return "/*"
	}
	if strings.HasSuffix(pattern, "/") {
		return pattern + "*"
	}
	return pattern + "/*"
}

func ruleConstraints(target RuleTarget) *RuleConstraints {
	paths := make([]string, 0, len(target.PathPrefixes))
	for _, pattern := range target.PathPrefixes {
		paths = append(paths, displayPathPattern(pattern))
	}
	return &RuleConstraints{
		Host:         target.Host,
		Schemes:      append([]string{}, target.Schemes...),
		Ports:        append([]int{}, target.Ports...),
		PathPrefixes: paths,
		Methods:      append([]string{}, target.Methods...),
	}
}

// RequestTargetURL renders the normalized target without query strings or
// credentials. It is shared by gateway responses and audit feedback.
func RequestTargetURL(target RequestTarget) string {
	host := target.Host
	if target.Port > 0 {
		host = net.JoinHostPort(host, strconv.Itoa(target.Port))
	} else if address, err := netip.ParseAddr(host); err == nil && address.Is6() {
		host = "[" + address.String() + "]"
	}
	if target.Scheme == "http" || target.Scheme == "https" {
		path := target.Path
		if path == "" {
			path = "/"
		}
		return target.Scheme + "://" + host + path
	}
	if target.Scheme == "dns" {
		return "dns://" + target.Host
	}
	return target.Scheme + "://" + host
}

func defaultBlockMatch(target RequestTarget, phase string) *BlockMatch {
	return &BlockMatch{Source: MatchSourceDefault, Type: MatchTypeAll, Value: "default-deny", RequestURL: RequestTargetURL(target), DecisionPhase: phase}
}

func systemBlockMatch(target RequestTarget, matchType, value, phase string) *BlockMatch {
	return &BlockMatch{Source: MatchSourceSystem, Type: matchType, Value: value, RequestURL: RequestTargetURL(target), DecisionPhase: phase}
}

func ruleBlockMatch(rule compiledRule, target RequestTarget, matchedPath, matchedIP, phase string) *BlockMatch {
	matchType, value := primaryRuleMatch(rule, target, matchedPath)
	return &BlockMatch{
		Source: MatchSourceRule, Type: matchType, Value: value,
		RuleConstraints: ruleConstraints(rule.Target), RequestURL: RequestTargetURL(target),
		ResolvedIP: matchedIP, DecisionPhase: phase,
	}
}

func primaryRuleMatch(rule compiledRule, target RequestTarget, matchedPath string) (string, string) {
	if matchedPath != "" {
		if strings.HasPrefix(matchedPath, "=") {
			return MatchTypePathExact, displayPathPattern(matchedPath)
		}
		return MatchTypePathSubtree, displayPathPattern(matchedPath)
	}
	if len(rule.Target.Methods) != 0 && (target.Scheme == "http" || target.Scheme == "https") {
		return MatchTypeMethod, target.Method
	}
	if rule.Target.Host != "*" {
		if rule.prefix != nil {
			return MatchTypeCIDR, rule.Target.Host
		}
		if _, err := netip.ParseAddr(rule.Target.Host); err == nil {
			return MatchTypeIP, rule.Target.Host
		}
		if strings.HasPrefix(rule.Target.Host, "*.") {
			return MatchTypeDomainWildcard, rule.Target.Host
		}
		return MatchTypeDomain, rule.Target.Host
	}
	if len(rule.Target.Ports) != 0 {
		return MatchTypePort, strconv.Itoa(target.Port)
	}
	if len(rule.Target.Schemes) != 0 {
		return MatchTypeProtocol, target.Scheme
	}
	return MatchTypeAll, "*"
}

func reasonForBlockedRule(match *BlockMatch) string {
	if match == nil {
		return ReasonBlockedAll
	}
	switch match.Type {
	case MatchTypePathExact:
		return ReasonBlockedPathExact
	case MatchTypePathSubtree:
		return ReasonBlockedPathSubtree
	case MatchTypeMethod:
		return ReasonBlockedMethod
	case MatchTypeDomain:
		return ReasonBlockedDomain
	case MatchTypeDomainWildcard:
		return ReasonBlockedDomainWildcard
	case MatchTypeIP:
		return ReasonBlockedIP
	case MatchTypeCIDR:
		return ReasonBlockedCIDR
	case MatchTypePort:
		return ReasonBlockedPort
	case MatchTypeProtocol:
		return ReasonBlockedProtocol
	default:
		return ReasonBlockedAll
	}
}

// ValidateBlockMatch rejects unbounded or control-bearing metadata before it
// crosses the gateway audit boundary.
func ValidateBlockMatch(match *BlockMatch) error {
	if match == nil {
		return nil
	}
	if !safeMatchText(match.Source, 32, false) || !safeMatchText(match.Type, 64, false) ||
		!safeMatchText(match.Value, 2048, true) || !safeMatchText(match.RequestURL, 4096, true) ||
		!safeMatchText(match.ResolvedIP, 64, true) || !safeMatchText(match.DecisionPhase, 32, false) {
		return fmt.Errorf("invalid block match")
	}
	if !containsMatchValue([]string{MatchSourceRule, MatchSourceDefault, MatchSourceSystem, MatchSourceGovernance, MatchSourceAttribution}, match.Source) ||
		!containsMatchValue([]string{MatchTypePathExact, MatchTypePathSubtree, MatchTypeMethod, MatchTypeDomain, MatchTypeDomainWildcard, MatchTypeIP, MatchTypeCIDR, MatchTypePort, MatchTypeProtocol, MatchTypeAll, MatchTypeHostname, MatchTypeAddress}, match.Type) ||
		!containsMatchValue([]string{DecisionPhaseRequest, DecisionPhaseAfterResolution, DecisionPhaseConnect}, match.DecisionPhase) {
		return fmt.Errorf("invalid block match vocabulary")
	}
	if match.Source == MatchSourceRule && match.RuleConstraints == nil {
		return fmt.Errorf("rule block match requires constraints")
	}
	if match.ResolvedIP != "" {
		address, err := netip.ParseAddr(match.ResolvedIP)
		if err != nil || address.Zone() != "" {
			return fmt.Errorf("invalid block match resolved address")
		}
	}
	if constraints := match.RuleConstraints; constraints != nil {
		if !safeMatchText(constraints.Host, 253, false) || len(constraints.Schemes) > 32 || len(constraints.Ports) > 256 || len(constraints.PathPrefixes) > 256 || len(constraints.Methods) > 256 {
			return fmt.Errorf("invalid block match constraints")
		}
		for _, values := range [][]string{constraints.Schemes, constraints.PathPrefixes, constraints.Methods} {
			for _, value := range values {
				if !safeMatchText(value, 2048, false) {
					return fmt.Errorf("invalid block match constraint value")
				}
			}
		}
		for _, port := range constraints.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("invalid block match port")
			}
		}
	}
	return nil
}

func containsMatchValue(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func safeMatchText(value string, limit int, optional bool) bool {
	if value == "" {
		return optional
	}
	return len(value) <= limit && !strings.ContainsAny(value, "\r\n\x00")
}
