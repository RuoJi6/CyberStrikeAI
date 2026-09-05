package egress

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/boundary"
)

func TestBoundaryFeedbackExplainsActualPathAndSnapshotRule(t *testing.T) {
	match := &boundary.BlockMatch{
		Source: boundary.MatchSourceRule, Type: boundary.MatchTypePathSubtree, Value: "/blocked/*",
		RequestURL: "https://example.com:443/blocked/asdasd", DecisionPhase: boundary.DecisionPhaseRequest,
		RuleConstraints: &boundary.RuleConstraints{Host: "*", Schemes: []string{"https"}, Ports: []int{443}, PathPrefixes: []string{"/blocked/*"}, Methods: []string{"GET"}},
	}
	event := ActivityEvent{
		RequestType: ActivityRequestHTTPS, Domain: "example.com", Port: 443, Method: "GET", Path: "/blocked/asdasd",
		Decision: ActivityDecisionBlocked, Reason: boundary.ReasonBlockedPathSubtree, RuleID: "rule-path", BlockMatch: match,
	}
	feedback := FormatBoundaryBlockFeedback([]ActivityEvent{event}, 8)
	for _, wanted := range []string{
		"请求：https://example.com:443/blocked/asdasd", "原因：路径子树阻断（blocked-path-subtree）",
		"命中条件：路径 /blocked/*", "完整规则：主机 *；协议 https；端口 443；方法 GET；路径 /blocked/*",
		"判定阶段：请求阶段", "规则：rule-path；结果：请求未发送到目标",
	} {
		if !strings.Contains(feedback, wanted) {
			t.Fatalf("feedback missing %q: %q", wanted, feedback)
		}
	}
}

func TestBoundaryFeedbackDoesNotMergeDifferentMatchedPaths(t *testing.T) {
	base := ActivityEvent{RequestType: ActivityRequestHTTPS, Domain: "example.com", Port: 443, Method: "GET", Decision: ActivityDecisionBlocked, Reason: boundary.ReasonBlockedPathSubtree, RuleID: "rule-path"}
	base.BlockMatch = &boundary.BlockMatch{Source: boundary.MatchSourceRule, Type: boundary.MatchTypePathSubtree, Value: "/one/*", RequestURL: "https://example.com:443/one/a", DecisionPhase: boundary.DecisionPhaseRequest, RuleConstraints: &boundary.RuleConstraints{Host: "*", Schemes: []string{}, Ports: []int{}, PathPrefixes: []string{"/one/*", "/two/*"}, Methods: []string{}}}
	second := base
	second.BlockMatch = &boundary.BlockMatch{Source: boundary.MatchSourceRule, Type: boundary.MatchTypePathSubtree, Value: "/two/*", RequestURL: "https://example.com:443/two/b", DecisionPhase: boundary.DecisionPhaseRequest, RuleConstraints: base.BlockMatch.RuleConstraints}
	feedback := FormatBoundaryBlockFeedback([]ActivityEvent{base, second}, 8)
	if strings.Count(feedback, "- 请求：") != 2 || !strings.Contains(feedback, "/one/a") || !strings.Contains(feedback, "/two/b") {
		t.Fatalf("distinct path matches were merged: %q", feedback)
	}
}

func TestBoundaryDeniedBodyShowsResolvedCIDRAndOmitsQuery(t *testing.T) {
	decision := boundary.Decision{
		Reason: boundary.ReasonBlockedCIDR, RuleID: "rule-cidr",
		Target:     boundary.RequestTarget{Scheme: "https", Host: "service.example", Port: 443, Path: "/api", Method: "GET"},
		BlockMatch: &boundary.BlockMatch{Source: boundary.MatchSourceRule, Type: boundary.MatchTypeCIDR, Value: "93.184.216.0/24", ResolvedIP: "93.184.216.34", RequestURL: "https://service.example:443/api", DecisionPhase: boundary.DecisionPhaseAfterResolution, RuleConstraints: &boundary.RuleConstraints{Host: "93.184.216.0/24", Schemes: []string{}, Ports: []int{}, PathPrefixes: []string{}, Methods: []string{}}},
	}
	body := FormatBoundaryDeniedBody(decision)
	if !strings.Contains(body, "解析地址 93.184.216.34 ∈ CIDR 93.184.216.0/24") || !strings.Contains(body, "判定阶段：解析后阶段") || strings.Contains(body, "?") {
		t.Fatalf("CIDR body = %q", body)
	}
}

func TestValidateBlockMatchRejectsControlCharactersAndUnknownVocabulary(t *testing.T) {
	valid := &boundary.BlockMatch{Source: boundary.MatchSourceSystem, Type: boundary.MatchTypeHostname, Value: "localhost", RequestURL: "http://localhost:80/", DecisionPhase: boundary.DecisionPhaseRequest}
	if err := boundary.ValidateBlockMatch(valid); err != nil {
		t.Fatal(err)
	}
	invalid := *valid
	invalid.Value = "localhost\r\nX-Forged: true"
	if err := boundary.ValidateBlockMatch(&invalid); err == nil {
		t.Fatal("control-bearing block match accepted")
	}
	invalid = *valid
	invalid.Type = "future-untrusted-type"
	if err := boundary.ValidateBlockMatch(&invalid); err == nil {
		t.Fatal("unknown block match type accepted")
	}
}
