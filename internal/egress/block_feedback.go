package egress

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/boundary"
)

type boundaryFeedbackGroup struct {
	event ActivityEvent
	count int64
}

// BoundaryReasonLabelZH maps both current and historical reason codes.
func BoundaryReasonLabelZH(reason string) string {
	labels := map[string]string{
		boundary.ReasonBlockedPathExact:      "精确路径阻断",
		boundary.ReasonBlockedPathSubtree:    "路径子树阻断",
		boundary.ReasonBlockedMethod:         "HTTP 方法阻断",
		boundary.ReasonBlockedDomain:         "域名阻断",
		boundary.ReasonBlockedDomainWildcard: "通配域名阻断",
		boundary.ReasonBlockedIP:             "IP 地址阻断",
		boundary.ReasonBlockedCIDR:           "CIDR 网段阻断",
		boundary.ReasonBlockedPort:           "端口阻断",
		boundary.ReasonBlockedProtocol:       "协议阻断",
		boundary.ReasonBlockedAll:            "全部目标阻断",
		boundary.ReasonBlockedPath:           "路径阻断（旧版记录）",
		boundary.ReasonBlockedTarget:         "目标阻断（旧版记录）",
		boundary.ReasonDefaultDeny:           "边界默认拒绝",
		boundary.ReasonForbiddenHostname:     "系统保留主机名隔离",
		boundary.ReasonForbiddenAddress:      "系统保留地址隔离",
		boundary.ReasonDNSRebinding:          "DNS 重绑定防护",
		"encrypted-dns-denied":               "加密 DNS 阻断",
		"attribution-rejected":               "流量归因校验失败",
		"rule_rate_limit":                    "规则速率限制",
		"rule_concurrency_limit":             "规则并发限制",
		"upstream_rate_limited":              "上游限速冷却",
		"consecutive_login_failures":         "连续登录失败保护",
		"waf_challenge":                      "WAF 挑战保护",
		"captcha_challenge":                  "验证码挑战保护",
		"unsupported_opcode":                 "不支持的 DNS 操作",
		"unsupported_class":                  "不支持的 DNS 类别",
		"unsupported_query_type":             "不支持的 DNS 查询类型",
		"invalid_query_name":                 "DNS 查询名称无效",
	}
	if label := labels[strings.TrimSpace(reason)]; label != "" {
		return label
	}
	if strings.TrimSpace(reason) == "" {
		return "策略阻断"
	}
	return strings.TrimSpace(reason)
}

func boundaryMatchTypeLabelZH(matchType string) string {
	return map[string]string{
		boundary.MatchTypePathExact: "精确路径", boundary.MatchTypePathSubtree: "路径",
		boundary.MatchTypeMethod: "方法", boundary.MatchTypeDomain: "域名",
		boundary.MatchTypeDomainWildcard: "通配域名", boundary.MatchTypeIP: "IP",
		boundary.MatchTypeCIDR: "CIDR", boundary.MatchTypePort: "端口",
		boundary.MatchTypeProtocol: "协议", boundary.MatchTypeAll: "全部目标",
		boundary.MatchTypeHostname: "主机名", boundary.MatchTypeAddress: "地址",
	}[matchType]
}

func joinStrings(values []string, fallback string) string {
	if len(values) == 0 {
		return fallback
	}
	return strings.Join(values, ", ")
}

func joinPorts(values []int) string {
	if len(values) == 0 {
		return "任意"
	}
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, strconv.Itoa(value))
	}
	return strings.Join(items, ", ")
}

// BoundaryRuleConstraintsZH preserves the canonical selector values carried
// by the immutable snapshot instead of reloading a mutable policy draft.
func BoundaryRuleConstraintsZH(match *boundary.BlockMatch) string {
	if match == nil || match.RuleConstraints == nil {
		return ""
	}
	rule := match.RuleConstraints
	return fmt.Sprintf("主机 %s；协议 %s；端口 %s；方法 %s；路径 %s",
		fallback(rule.Host, "*"), joinStrings(rule.Schemes, "任意"), joinPorts(rule.Ports),
		joinStrings(rule.Methods, "任意"), joinStrings(rule.PathPrefixes, "任意"))
}

// BoundaryFeedbackRequest returns one normalized target URL/URI. HTTP query
// strings and credentials are absent from ActivityEvent by construction.
func BoundaryFeedbackRequest(event ActivityEvent) string {
	if event.BlockMatch != nil && strings.TrimSpace(event.BlockMatch.RequestURL) != "" {
		return strings.TrimSpace(event.BlockMatch.RequestURL)
	}
	scheme := strings.ToLower(strings.TrimSpace(event.RequestType))
	host := strings.TrimSpace(event.Domain)
	if host == "" {
		host = strings.TrimSpace(event.ConnectedIP)
	}
	if host == "" {
		host = "未知目标"
	}
	if scheme == ActivityRequestDNS {
		return "dns://" + host
	}
	authority := host
	if event.Port > 0 {
		authority = net.JoinHostPort(host, strconv.Itoa(event.Port))
	}
	if scheme == ActivityRequestHTTP || scheme == ActivityRequestHTTPS || scheme == ActivityRequestCONNECT {
		if scheme == ActivityRequestCONNECT {
			scheme = "https"
		}
		path := strings.TrimSpace(event.Path)
		if path == "" {
			path = "/"
		}
		return scheme + "://" + authority + path
	}
	return scheme + "://" + authority
}

func BoundaryMatchSummaryZH(match *boundary.BlockMatch) string {
	if match == nil {
		return "未提供结构化命中条件"
	}
	label := boundaryMatchTypeLabelZH(match.Type)
	if label == "" {
		label = match.Type
	}
	value := fallback(match.Value, "—")
	result := label + " " + value
	if match.ResolvedIP != "" && match.Type == boundary.MatchTypeCIDR {
		result = "解析地址 " + match.ResolvedIP + " ∈ CIDR " + value
	} else if match.ResolvedIP != "" && match.ResolvedIP != match.Value {
		result += "（解析地址 " + match.ResolvedIP + "）"
	}
	return result
}

func BoundaryDecisionPhaseLabelZH(phase string) string {
	return map[string]string{
		boundary.DecisionPhaseRequest:         "请求阶段",
		boundary.DecisionPhaseAfterResolution: "解析后阶段",
		boundary.DecisionPhaseConnect:         "连接阶段",
	}[phase]
}

// FormatBoundaryDeniedBody is the stable bilingual 403 explanation consumed
// by command-line tools and Agents.
func FormatBoundaryDeniedBody(decision boundary.Decision) string {
	reason := fallback(decision.Reason, boundary.ReasonDefaultDeny)
	ruleID := fallback(decision.RuleID, "default-deny")
	target := boundary.RequestTargetURL(decision.Target)
	match := decision.BlockMatch
	matchSummary := BoundaryMatchSummaryZH(match)
	constraints := BoundaryRuleConstraintsZH(match)
	phase := ""
	if match != nil {
		phase = BoundaryDecisionPhaseLabelZH(match.DecisionPhase)
	}
	var body strings.Builder
	fmt.Fprintf(&body, "[CyberStrikeAI 网络边界] 请求未到达目标\n请求：%s\n原因：%s（%s）\n命中条件：%s\n", target, BoundaryReasonLabelZH(reason), reason, matchSummary)
	if constraints != "" {
		fmt.Fprintf(&body, "完整规则：%s\n", constraints)
	}
	if phase != "" {
		fmt.Fprintf(&body, "判定阶段：%s\n", phase)
	}
	fmt.Fprintf(&body, "规则：%s\n结果：请求未发送到目标站点。\n", ruleID)
	fmt.Fprintf(&body, "CyberStrikeAI network boundary denied %s (reason: %s; rule: %s). The request was not sent to the destination.\n", target, reason, ruleID)
	return body.String()
}

// FormatBoundaryBlockFeedback builds the common Host/Container post-execution
// summary. maxGroups <= 0 means all groups.
func FormatBoundaryBlockFeedback(events []ActivityEvent, maxGroups int) string {
	groups := make([]boundaryFeedbackGroup, 0, len(events))
	indexes := make(map[string]int, len(events))
	total := int64(0)
	for _, event := range events {
		if event.Decision != ActivityDecisionBlocked {
			continue
		}
		weight := event.AggregateCount
		if weight < 1 {
			weight = 1
		}
		encodedMatch, _ := json.Marshal(event.BlockMatch)
		key := strings.Join([]string{BoundaryFeedbackRequest(event), event.Method, event.RuleID, event.Reason, string(encodedMatch)}, "\x00")
		if index, ok := indexes[key]; ok {
			groups[index].count += weight
		} else {
			indexes[key] = len(groups)
			groups = append(groups, boundaryFeedbackGroup{event: event, count: weight})
		}
		total += weight
	}
	if len(groups) == 0 {
		return ""
	}
	visible := len(groups)
	if maxGroups > 0 && visible > maxGroups {
		visible = maxGroups
	}
	var message strings.Builder
	fmt.Fprintf(&message, "\n[CyberStrikeAI 网络边界] 本次工具执行触发 %d 次网络阻断，以下请求未到达目标：\n", total)
	for _, group := range groups[:visible] {
		event := group.event
		fmt.Fprintf(&message, "- 请求：%s（%d 次）\n  原因：%s（%s）\n  命中条件：%s\n",
			BoundaryFeedbackRequest(event), group.count, BoundaryReasonLabelZH(event.Reason), fallback(event.Reason, "policy_denied"), BoundaryMatchSummaryZH(event.BlockMatch))
		if constraints := BoundaryRuleConstraintsZH(event.BlockMatch); constraints != "" {
			fmt.Fprintf(&message, "  完整规则：%s\n", constraints)
		}
		if event.BlockMatch != nil {
			fmt.Fprintf(&message, "  判定阶段：%s\n", fallback(BoundaryDecisionPhaseLabelZH(event.BlockMatch.DecisionPhase), event.BlockMatch.DecisionPhase))
		}
		fmt.Fprintf(&message, "  规则：%s；结果：请求未发送到目标。\n", feedbackRule(event))
	}
	if hidden := len(groups) - visible; hidden > 0 {
		fmt.Fprintf(&message, "- 其他 %d 组被阻断目标请在出站审计中查看。\n", hidden)
	}
	message.WriteString("当前边界或系统网络策略已明确禁止上述访问，请根据命中条件调整目标或联系管理员修改规则。\n")
	return message.String()
}

func feedbackRule(event ActivityEvent) string {
	if strings.TrimSpace(event.RuleID) != "" {
		return strings.TrimSpace(event.RuleID)
	}
	switch event.Reason {
	case boundary.ReasonForbiddenAddress, boundary.ReasonForbiddenHostname, boundary.ReasonDNSRebinding:
		return "系统网络隔离"
	case boundary.ReasonDefaultDeny:
		return "边界默认拒绝"
	default:
		return "系统策略"
	}
}

func fallback(value, replacement string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return replacement
	}
	return value
}
