package egress

import (
	"context"
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

func TestProxyHTTPActivityCapturesCompleteBoundedPacket(t *testing.T) {
	policy := testProxyPolicy(t, boundary.Rule{ID: "visit-1", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{
		Host: "allowed.example", Schemes: []string{"http"}, Methods: []string{http.MethodPost},
	}})
	var events []ActivityEvent
	proxy, err := NewProxy(policy, ProxyOptions{
		Now:          func() time.Time { return time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC) },
		ActivitySink: func(event ActivityEvent) { events = append(events, event) },
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			body, readErr := io.ReadAll(request.Body)
			if readErr != nil || string(body) != "private-body" {
				t.Fatalf("request body = %q err=%v", body, readErr)
			}
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.1", Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("safe"))}, nil
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
	if event.HTTPPacket == nil || event.HTTPPacket.RequestLine != "POST /safe?token=top-secret HTTP/1.1" ||
		len(event.HTTPPacket.RequestHeaders["Authorization"]) != 1 || event.HTTPPacket.RequestHeaders["Authorization"][0] != "Bearer private-token" || event.HTTPPacket.RequestBody == "" ||
		event.HTTPPacket.ResponseLine != "HTTP/1.1 200 OK" || event.HTTPPacket.ResponseBody != "safe" {
		t.Fatalf("HTTP packet = %#v", event.HTTPPacket)
	}
}

func TestValidateHTTPPacketAcceptsRFCFieldNameTokens(t *testing.T) {
	packet := &HTTPPacket{
		RequestLine:    "GET / HTTP/1.1",
		RequestHeaders: map[string][]string{"X_Backend-Trace": {"safe"}, "X!#$%&'*+-.^_`|~Token": {"safe"}},
	}
	if err := ValidateHTTPPacket(packet); err != nil {
		t.Fatalf("valid RFC token header name rejected: %v", err)
	}

	for _, name := range []string{"Bad Header", "Bad:Header", "Bad\tHeader", "Bad/Header"} {
		packet.RequestHeaders = map[string][]string{name: {"safe"}}
		if err := ValidateHTTPPacket(packet); err == nil {
			t.Fatalf("invalid header name %q accepted", name)
		}
	}
	packet.RequestHeaders = map[string][]string{"Safe-Header": {"safe\r\ninjected: true"}}
	if err := ValidateHTTPPacket(packet); err == nil {
		t.Fatal("header value containing a newline was accepted")
	}
}

func TestValidateHTTPPacketAcceptsNewHexAndDecodedProjection(t *testing.T) {
	packet := &HTTPPacket{
		RequestLine: "GET / HTTP/1.1", RequestHeaders: map[string][]string{},
		ResponseLine: "HTTP/1.1 200 OK", ResponseHeaders: map[string][]string{"Content-Encoding": {"br"}},
		ResponseBody: "00ff", ResponseBodyEncoding: "hex", ResponseContentEncoding: "br", ResponseBodyDecoded: true,
	}
	if err := ValidateHTTPPacket(packet); err != nil {
		t.Fatalf("ValidateHTTPPacket: %v", err)
	}
	packet.ResponseContentEncoding = ""
	if err := ValidateHTTPPacket(packet); err == nil {
		t.Fatal("accepted decoded packet without wire content encoding")
	}
}
