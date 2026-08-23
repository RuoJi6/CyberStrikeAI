package egress

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
	"golang.org/x/net/dns/dnsmessage"
)

func TestPolicyDNSActivitySeparatesPolicyDecisionFromResolutionOutcome(t *testing.T) {
	policy := testDNSPolicy(t, boundary.Rule{ID: "visit-1", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example"}})
	events := make([]ActivityEvent, 0, 2)
	handler, err := NewPolicyDNS(policy, DNSOptions{
		Now: func() time.Time { return time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC) },
		LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
		ActivitySink: func(event ActivityEvent) { events = append(events, event) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.HandleQuery(context.Background(), dnsQuery(t, 1, "allowed.example.", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.HandleQuery(context.Background(), dnsQuery(t, 2, "unknown.example.", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %#v", events)
	}
	allowed := events[0]
	if allowed.Event != ActivityEventName || allowed.RequestType != ActivityRequestDNS || allowed.Domain != "allowed.example" || allowed.Decision != ActivityDecisionAllowed || allowed.Outcome != "resolved" || allowed.RuleID != "visit-1" || len(allowed.ResolvedIPs) != 1 || allowed.ResolvedIPs[0] != "93.184.216.34" {
		t.Fatalf("allowed event = %#v", allowed)
	}
	blocked := events[1]
	if blocked.Domain != "unknown.example" || blocked.Decision != ActivityDecisionBlocked || blocked.Outcome != "policy_denied" || blocked.Reason != boundary.ReasonDefaultDeny {
		t.Fatalf("blocked event = %#v", blocked)
	}
}

func TestProxyHTTPActivityOmitsQueryHeadersBodiesAndRawErrors(t *testing.T) {
	policy := testProxyPolicy(t, boundary.Rule{ID: "visit-1", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{
		Host: "allowed.example", Schemes: []string{"http"}, Methods: []string{http.MethodPost},
	}})
	var events []ActivityEvent
	proxy, err := NewProxy(policy, ProxyOptions{
		Now:          func() time.Time { return time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC) },
		ActivitySink: func(event ActivityEvent) { events = append(events, event) },
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("safe"))}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://allowed.example/safe?token=top-secret", strings.NewReader("private-body"))
	request.Header.Set("Authorization", "Bearer private-token")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || len(events) != 1 {
		t.Fatalf("response=%d events=%#v", recorder.Code, events)
	}
	event := events[0]
	if event.Path != "/safe" || event.Method != http.MethodPost || event.HTTPStatus != http.StatusOK || event.Decision != ActivityDecisionAllowed || event.Outcome != "completed" || event.BytesDown != 4 {
		t.Fatalf("event = %#v", event)
	}
	encoded := strings.ToLower(string(mustJSON(t, event)))
	for _, secret := range []string{"top-secret", "private-body", "private-token", "authorization", "token="} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("activity event leaked %q: %s", secret, encoded)
		}
	}
}

func mustJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
