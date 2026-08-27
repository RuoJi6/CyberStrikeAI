package egress

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/boundary"
)

const (
	defaultCooldown       = 60 * time.Second
	maximumCooldown       = time.Hour
	loginFailureThreshold = 3
)

type requestGuard struct {
	mu    sync.Mutex
	rules map[string]*requestGuardRule
}

type requestGuardRule struct {
	tokens                float64
	lastRefill            time.Time
	active                int
	cooldownUntil         time.Time
	consecutiveLoginFails int
	manualPauseReason     string
}

type requestGuardBlock struct {
	outcome      string
	reason       string
	retryAfterMS int64
}

type requestGuardTransition struct {
	outcome      string
	reason       string
	retryAfterMS int64
}

func newRequestGuard() *requestGuard {
	return &requestGuard{rules: make(map[string]*requestGuardRule)}
}

func (g *requestGuard) acquire(decision boundary.Decision, now time.Time) (func(), *requestGuardBlock, *requestGuardTransition) {
	if g == nil {
		return func() {}, nil, nil
	}
	now = now.UTC()
	g.mu.Lock()
	defer g.mu.Unlock()
	state := g.rule(decision.RuleID)
	var transition *requestGuardTransition
	if !state.cooldownUntil.IsZero() && !now.Before(state.cooldownUntil) {
		state.cooldownUntil = time.Time{}
		transition = &requestGuardTransition{outcome: "cooldown_expired", reason: "upstream_rate_limited"}
	}
	if state.manualPauseReason != "" {
		return func() {}, &requestGuardBlock{outcome: "health_paused", reason: state.manualPauseReason}, transition
	}
	if !state.cooldownUntil.IsZero() {
		retry := state.cooldownUntil.Sub(now)
		return func() {}, &requestGuardBlock{outcome: "cooldown_active", reason: "upstream_rate_limited", retryAfterMS: durationMillisecondsCeil(retry)}, transition
	}
	limit := decision.RateLimit
	if limit.MaxConcurrent > 0 && state.active >= limit.MaxConcurrent {
		return func() {}, &requestGuardBlock{outcome: "concurrency_limited", reason: "rule_concurrency_limit"}, transition
	}
	if limit.RequestsPerSecond > 0 {
		if state.lastRefill.IsZero() {
			state.tokens = float64(limit.Burst)
			state.lastRefill = now
		} else if now.After(state.lastRefill) {
			state.tokens += now.Sub(state.lastRefill).Seconds() * limit.RequestsPerSecond
			if state.tokens > float64(limit.Burst) {
				state.tokens = float64(limit.Burst)
			}
			state.lastRefill = now
		}
		if state.tokens < 1 {
			missing := 1 - state.tokens
			retry := time.Duration(missing / limit.RequestsPerSecond * float64(time.Second))
			return func() {}, &requestGuardBlock{outcome: "rate_limited", reason: "rule_rate_limit", retryAfterMS: durationMillisecondsCeil(retry)}, transition
		}
		state.tokens--
	}
	state.active++
	released := false
	return func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if released {
			return
		}
		released = true
		if state.active > 0 {
			state.active--
		}
	}, nil, transition
}

func (g *requestGuard) observeResponse(decision boundary.Decision, request *http.Request, response *http.Response, now time.Time) *requestGuardTransition {
	if g == nil || request == nil || response == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	state := g.rule(decision.RuleID)
	// A zero-valued boundary rate limit means unlimited. Do not turn a target's
	// own 429 into a platform-wide cooldown unless the user explicitly enabled
	// request governance on this rule.
	if response.StatusCode == http.StatusTooManyRequests && requestGuardConfigured(decision) {
		delay := retryAfterDuration(response.Header.Get("Retry-After"), now)
		state.cooldownUntil = now.UTC().Add(delay)
		return &requestGuardTransition{outcome: "cooldown_started", reason: "upstream_rate_limited", retryAfterMS: durationMillisecondsCeil(delay)}
	}
	if reason := responseHealthSignal(response.Header); reason != "" {
		state.manualPauseReason = reason
		return &requestGuardTransition{outcome: "health_paused", reason: reason}
	}
	if loginLikeRequest(request.Method, request.URL.Path) {
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			state.consecutiveLoginFails++
			if state.consecutiveLoginFails >= loginFailureThreshold {
				state.manualPauseReason = "consecutive_login_failures"
				return &requestGuardTransition{outcome: "health_paused", reason: state.manualPauseReason}
			}
		} else {
			state.consecutiveLoginFails = 0
		}
	}
	return nil
}

func (g *requestGuard) recover() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, state := range g.rules {
		state.cooldownUntil = time.Time{}
		state.consecutiveLoginFails = 0
		state.manualPauseReason = ""
	}
}

func (g *requestGuard) rule(id string) *requestGuardRule {
	state := g.rules[id]
	if state == nil {
		state = &requestGuardRule{}
		g.rules[id] = state
	}
	return state
}

func requestGuardConfigured(decision boundary.Decision) bool {
	return decision.RateLimit.RequestsPerSecond > 0 || decision.RateLimit.MaxConcurrent > 0
}

func retryAfterDuration(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		return boundedCooldown(time.Duration(seconds) * time.Second)
	}
	if parsed, err := http.ParseTime(value); err == nil && parsed.After(now) {
		return boundedCooldown(parsed.Sub(now))
	}
	return defaultCooldown
}

func boundedCooldown(value time.Duration) time.Duration {
	if value < time.Second {
		return time.Second
	}
	if value > maximumCooldown {
		return maximumCooldown
	}
	return value
}

func durationMillisecondsCeil(value time.Duration) int64 {
	if value <= 0 {
		return 0
	}
	return int64((value + time.Millisecond - 1) / time.Millisecond)
}

func loginLikeRequest(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	for _, segment := range strings.FieldsFunc(strings.ToLower(path), func(r rune) bool { return r == '/' || r == '-' || r == '_' || r == '.' }) {
		switch segment {
		case "login", "signin", "auth", "token", "session":
			return true
		}
	}
	return false
}

func responseHealthSignal(header http.Header) string {
	if strings.EqualFold(strings.TrimSpace(header.Get("CF-Mitigated")), "challenge") {
		return "waf_challenge"
	}
	if truthyHeader(header.Get("X-Captcha-Required")) {
		return "captcha_challenge"
	}
	switch strings.ToLower(strings.TrimSpace(header.Get("X-WAF-Action"))) {
	case "captcha":
		return "captcha_challenge"
	case "block", "blocked", "challenge":
		return "waf_challenge"
	}
	return ""
}

func truthyHeader(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "required", "challenge":
		return true
	default:
		return false
	}
}
