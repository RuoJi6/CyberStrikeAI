package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"cyberstrike-ai/internal/boundary"
)

func TestProxyProtocolRejectsMalformedCONNECTAuthoritiesBeforeNetwork(t *testing.T) {
	policy := testProxyPolicy(t, boundary.Rule{
		ID: "connect", Effect: boundary.EffectAllowVisit,
		Target: boundary.RuleTarget{Host: "allowed.example", Schemes: []string{"https"}, Ports: []int{443}},
	})
	proxy, err := NewProxy(policy, ProxyOptions{
		LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			t.Fatal("malformed CONNECT reached DNS")
			return nil, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("malformed CONNECT reached dial")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, host, requestURI string
	}{
		{name: "missing port", host: "allowed.example", requestURI: "allowed.example"},
		{name: "nonnumeric port", host: "allowed.example:https", requestURI: "allowed.example:https"},
		{name: "overflow port", host: "allowed.example:65536", requestURI: "allowed.example:65536"},
		{name: "userinfo", host: "user@allowed.example:443", requestURI: "user@allowed.example:443"},
		{name: "path", host: "allowed.example:443/path", requestURI: "allowed.example:443/path"},
		{name: "query", host: "allowed.example:443?dns=1", requestURI: "allowed.example:443?dns=1"},
		{name: "absolute URI", host: "https://allowed.example:443", requestURI: "https://allowed.example:443"},
		{name: "authority mismatch", host: "allowed.example:443", requestURI: "other.example:443"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := &http.Request{Method: http.MethodConnect, Host: test.host, RequestURI: test.requestURI, URL: &url.URL{}}
			recorder := httptest.NewRecorder()
			proxy.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("malformed CONNECT status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestProxyBypassRegressionOnlyRejectsRestrictedTargetsBeforeNetwork(t *testing.T) {
	policy := testProxyPolicy(t,
		boundary.Rule{ID: "allowed", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example", Schemes: []string{"http", "https"}, Ports: []int{53, 784, 853, 8853, 2375, 2376}}},
		boundary.Rule{ID: "doh", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "dns.google", Schemes: []string{"https"}, Ports: []int{443}}},
		boundary.Rule{ID: "metadata", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "metadata.google.internal", Schemes: []string{"http"}, Ports: []int{80}}},
		boundary.Rule{ID: "docker-host", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "host.docker.internal", Schemes: []string{"http"}, Ports: []int{80}}},
	)
	proxy, err := NewProxy(policy, ProxyOptions{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("test dial stopped after policy authorization")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, method, target, host string
		blocked                    bool
	}{
		{name: "public service on port 53", method: http.MethodGet, target: "http://allowed.example:53/", host: "allowed.example:53"},
		{name: "public service on port 784", method: http.MethodConnect, host: "allowed.example:784"},
		{name: "public service on port 853", method: http.MethodConnect, host: "allowed.example:853"},
		{name: "public service on port 8853", method: http.MethodConnect, host: "allowed.example:8853"},
		{name: "public service on port 2375", method: http.MethodConnect, host: "allowed.example:2375"},
		{name: "public service on port 2376", method: http.MethodConnect, host: "allowed.example:2376"},
		{name: "public resolver hostname is ordinary", method: http.MethodConnect, host: "dns.google:443"},
		{name: "metadata hostname", method: http.MethodGet, target: "http://metadata.google.internal/", host: "metadata.google.internal", blocked: true},
		{name: "loopback IPv4", method: http.MethodGet, target: "http://127.0.0.1/", host: "127.0.0.1", blocked: true},
		{name: "loopback IPv6", method: http.MethodGet, target: "http://[::1]/", host: "[::1]", blocked: true},
		{name: "Docker host gateway", method: http.MethodGet, target: "http://host.docker.internal/", host: "host.docker.internal", blocked: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var request *http.Request
			if test.method == http.MethodConnect {
				request = &http.Request{Method: http.MethodConnect, Host: test.host, RequestURI: test.host, URL: &url.URL{}}
			} else {
				request = httptest.NewRequest(test.method, test.target, nil)
				request.Host = test.host
			}
			recorder := httptest.NewRecorder()
			proxy.ServeHTTP(recorder, request)
			if (recorder.Code == http.StatusForbidden) != test.blocked {
				t.Fatalf("bypass status = %d, blocked=%v", recorder.Code, test.blocked)
			}
		})
	}
}
