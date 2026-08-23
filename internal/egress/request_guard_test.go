package egress

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
)

func TestRequestGuardDeterministicRateAndConcurrencyLimits(t *testing.T) {
	now := time.Date(2026, 8, 23, 1, 0, 0, 0, time.UTC)
	guard := newRequestGuard()
	decision := boundary.Decision{RuleID: "limited", Effect: boundary.EffectAllowVisit, RateLimit: boundary.RateLimit{
		RequestsPerSecond: 2, Burst: 2, MaxConcurrent: 1,
	}}
	release, block, _ := guard.acquire(decision, now)
	if block != nil {
		t.Fatalf("first request blocked: %#v", block)
	}
	if _, block, _ := guard.acquire(decision, now); block == nil || block.outcome != "concurrency_limited" {
		t.Fatalf("concurrent request block = %#v", block)
	}
	release()
	release, block, _ = guard.acquire(decision, now)
	if block != nil {
		t.Fatalf("second token blocked: %#v", block)
	}
	release()
	if _, block, _ := guard.acquire(decision, now); block == nil || block.outcome != "rate_limited" || block.retryAfterMS != 500 {
		t.Fatalf("exhausted bucket block = %#v", block)
	}
	release, block, _ = guard.acquire(decision, now.Add(500*time.Millisecond))
	if block != nil {
		t.Fatalf("refilled token blocked: %#v", block)
	}
	release()
}

func TestRequestGuardCooldownSignalsLoginPauseAndManualRecovery(t *testing.T) {
	now := time.Date(2026, 8, 23, 1, 0, 0, 0, time.UTC)
	guard := newRequestGuard()
	decision := boundary.Decision{RuleID: "visit", Effect: boundary.EffectAllowVisit}
	request := httptest.NewRequest(http.MethodPost, "http://example.test/api/login", nil)
	response := func(status int, header http.Header) *http.Response {
		return &http.Response{StatusCode: status, Header: header}
	}
	transition := guard.observeResponse(decision, request, response(http.StatusTooManyRequests, http.Header{"Retry-After": {"99999"}}), now)
	if transition == nil || transition.outcome != "cooldown_started" || transition.retryAfterMS != int64(time.Hour/time.Millisecond) {
		t.Fatalf("cooldown transition = %#v", transition)
	}
	if _, block, _ := guard.acquire(decision, now); block == nil || block.outcome != "cooldown_active" {
		t.Fatalf("cooldown block = %#v", block)
	}
	guard.recover()
	release, block, _ := guard.acquire(decision, now)
	if block != nil {
		t.Fatalf("manual recovery did not clear cooldown: %#v", block)
	}
	release()
	for attempt := 1; attempt <= loginFailureThreshold; attempt++ {
		transition = guard.observeResponse(decision, request, response(http.StatusUnauthorized, make(http.Header)), now.Add(time.Duration(attempt)*time.Second))
	}
	if transition == nil || transition.outcome != "health_paused" || transition.reason != "consecutive_login_failures" {
		t.Fatalf("login pause transition = %#v", transition)
	}
	if _, block, _ := guard.acquire(decision, now.Add(time.Minute)); block == nil || block.outcome != "health_paused" {
		t.Fatalf("manual pause block = %#v", block)
	}
	guard.recover()
	challengeHeader := make(http.Header)
	challengeHeader.Set("CF-Mitigated", "challenge")
	challenge := response(http.StatusForbidden, challengeHeader)
	transition = guard.observeResponse(decision, httptest.NewRequest(http.MethodGet, "http://example.test/", nil), challenge, now)
	if transition == nil || transition.reason != "waf_challenge" {
		t.Fatalf("WAF transition = %#v", transition)
	}
	guard.recover()
	captcha := response(http.StatusForbidden, http.Header{"X-Captcha-Required": {"true"}})
	transition = guard.observeResponse(decision, httptest.NewRequest(http.MethodGet, "http://example.test/", nil), captcha, now)
	if transition == nil || transition.reason != "captcha_challenge" {
		t.Fatalf("CAPTCHA transition = %#v", transition)
	}
}

func TestProxyRateLimitAndUpstreamCooldownEmitCredentialFreeEvents(t *testing.T) {
	now := time.Date(2026, 8, 23, 1, 0, 0, 0, time.UTC)
	policy := testProxyPolicy(t, boundary.Rule{
		ID: "limited", Effect: boundary.EffectAllowVisit,
		Target:    boundary.RuleTarget{Host: "allowed.example", Schemes: []string{"http"}},
		RateLimit: boundary.RateLimit{RequestsPerSecond: 1, Burst: 1},
	})
	var calls atomic.Int32
	var mu sync.Mutex
	var events []ActivityEvent
	proxy, err := NewProxy(policy, ProxyOptions{
		Now: func() time.Time { return now },
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("secret-body-must-not-enter-events"))}, nil
		}),
		ActivitySink: func(event ActivityEvent) { mu.Lock(); events = append(events, event); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewRecorder()
	proxy.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "http://allowed.example/", nil))
	second := httptest.NewRecorder()
	proxy.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "http://allowed.example/", nil))
	if first.Code != http.StatusOK || second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") != "1" || calls.Load() != 1 {
		t.Fatalf("rate results = %d %d retry=%q calls=%d", first.Code, second.Code, second.Header().Get("Retry-After"), calls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 || events[1].Outcome != "rate_limited" || events[1].Reason != "rule_rate_limit" || events[1].HTTPStatus != 429 || events[1].RetryAfterMS != 1000 {
		t.Fatalf("rate events = %#v", events)
	}
	encoded := strings.Builder{}
	for _, event := range events {
		encoded.WriteString(event.Outcome)
		encoded.WriteString(event.Reason)
	}
	if strings.Contains(encoded.String(), "secret-body") {
		t.Fatal("response body entered activity events")
	}
}

func TestProxyUpstream429StartsCooldownUntilTrustedRecovery(t *testing.T) {
	now := time.Date(2026, 8, 23, 1, 0, 0, 0, time.UTC)
	policy := testProxyPolicy(t, boundary.Rule{ID: "visit", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example", Schemes: []string{"http"}}})
	var calls atomic.Int32
	var mu sync.Mutex
	var events []ActivityEvent
	proxy, err := NewProxy(policy, ProxyOptions{
		Now: func() time.Time { return now },
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			if calls.Add(1) == 1 {
				return &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": {"30"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
		ActivitySink: func(event ActivityEvent) { mu.Lock(); events = append(events, event); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	serve := func() int {
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://allowed.example/", nil))
		return recorder.Code
	}
	if status := serve(); status != http.StatusTooManyRequests {
		t.Fatalf("upstream status = %d", status)
	}
	if status := serve(); status != http.StatusTooManyRequests || calls.Load() != 1 {
		t.Fatalf("cooldown status=%d calls=%d", status, calls.Load())
	}
	proxy.RecoverHealth()
	if status := serve(); status != http.StatusNoContent || calls.Load() != 2 {
		t.Fatalf("recovered status=%d calls=%d", status, calls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	var health, blocked bool
	for _, event := range events {
		if event.RequestType == ActivityRequestHealth && event.Outcome == "cooldown_started" && event.RetryAfterMS == 30000 {
			health = true
		}
		if event.RequestType == ActivityRequestHTTP && event.Outcome == "cooldown_active" {
			blocked = true
		}
	}
	if !health || !blocked {
		t.Fatalf("cooldown events = %#v", events)
	}
}
