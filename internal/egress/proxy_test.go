package egress

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestProxyForwardsOnlyAuthorizedAbsoluteHTTPAndStripsProxyHeaders(t *testing.T) {
	policy := testProxyPolicy(t, boundary.Rule{ID: "visit", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example", Schemes: []string{"http"}, Methods: []string{"GET"}}})
	var calls atomic.Int32
	proxy, err := NewProxy(policy, ProxyOptions{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if request.RequestURI != "" || request.Host != "allowed.example:80" || request.URL.Host != "allowed.example:80" || request.URL.Path != "/path" || request.URL.RawPath != "" || request.Header.Get("Proxy-Authorization") != "" || request.Header.Get("X-Forwarded-For") != "" || request.Header.Get("X-Hop") != "" || request.Header.Get("X-Proxy-Hop") != "" {
			t.Fatalf("unsafe outbound request = %#v / %#v", request, request.Header)
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header:     http.Header{"Content-Type": {"text/plain"}, "Connection": {"X-Upstream-Hop"}, "X-Upstream-Hop": {"remove"}},
			Body:       io.NopCloser(strings.NewReader("forwarded")),
		}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://ALLOWED.EXAMPLE./safe/../path", nil)
	request.Header.Set("Proxy-Authorization", "Basic secret")
	request.Header.Set("X-Forwarded-For", "127.0.0.1")
	request.Header.Set("Connection", "X-Hop")
	request.Header.Set("X-Hop", "remove")
	request.Header.Set("Proxy-Connection", "X-Proxy-Hop")
	request.Header.Set("X-Proxy-Hop", "remove")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || recorder.Body.String() != "forwarded" || recorder.Header().Get("X-Upstream-Hop") != "" || calls.Load() != 1 {
		t.Fatalf("forward response = %d %q %#v calls=%d", recorder.Code, recorder.Body.String(), recorder.Header(), calls.Load())
	}
}

func TestProxyRejectsDeniedAmbiguousHTTPSAndAuthOnlyForwardRequests(t *testing.T) {
	allowed := testProxyPolicy(t, boundary.Rule{ID: "visit", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example"}})
	proxy, err := NewProxy(allowed, ProxyOptions{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("denied request reached transport")
		return nil, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, target, host string
		want               int
	}{
		{name: "default deny", target: "http://unknown.example/", host: "unknown.example", want: http.StatusForbidden},
		{name: "host mismatch", target: "http://allowed.example/", host: "other.example", want: http.StatusBadRequest},
		{name: "origin form", target: "/path", host: "allowed.example", want: http.StatusBadRequest},
		{name: "https absolute form", target: "https://allowed.example/", host: "allowed.example", want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			request.Host = test.host
			recorder := httptest.NewRecorder()
			proxy.ServeHTTP(recorder, request)
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d", recorder.Code, test.want)
			}
		})
	}
	authPolicy := testProxyPolicy(t, boundary.Rule{
		ID: "auth", Effect: boundary.EffectAuthOnly, AuthProfileID: "profile-1",
		Target: boundary.RuleTarget{Host: "auth.example", Schemes: []string{"http"}},
	})
	authProxy, err := NewProxy(authPolicy, ProxyOptions{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("auth-only request reached transport before credential injection exists")
		return nil, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	authProxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://auth.example/", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("auth-only status = %d", recorder.Code)
	}
}

func TestProxyCONNECTWaitsForMatchingSNIThenForwardsClientHello(t *testing.T) {
	policy := testProxyPolicy(t, boundary.Rule{ID: "connect", Effect: boundary.EffectAllowAttack, Target: boundary.RuleTarget{Host: "allowed.example", Schemes: []string{"https"}, Ports: []int{443}}})
	dialed := make(chan string, 1)
	forwarded := make(chan []byte, 1)
	hello := testClientHello("allowed.example", 9)
	proxy, err := NewProxy(policy, ProxyOptions{
		LookupNetIP: func(_ context.Context, network, host string) ([]netip.Addr, error) {
			if network != "ip" || host != "allowed.example" {
				t.Fatalf("lookup = %q %q", network, host)
			}
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			dialed <- network + ":" + address
			proxySide, upstreamSide := net.Pipe()
			go func() {
				defer upstreamSide.Close()
				content := make([]byte, len(hello))
				_, _ = io.ReadFull(upstreamSide, content)
				forwarded <- content
			}()
			return proxySide, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	client := openCONNECT(t, server.Listener.Addr().String(), "allowed.example:443", http.StatusOK)
	defer client.Close()
	select {
	case address := <-dialed:
		t.Fatalf("upstream dial occurred before ClientHello: %s", address)
	default:
	}
	if _, err := client.Write(hello); err != nil {
		t.Fatal(err)
	}
	select {
	case address := <-dialed:
		if address != "tcp:93.184.216.34:443" {
			t.Fatalf("dialed %q", address)
		}
	case <-time.After(time.Second):
		t.Fatal("matching SNI did not trigger upstream dial")
	}
	select {
	case content := <-forwarded:
		if !bytes.Equal(content, hello) {
			t.Fatal("ClientHello was not forwarded unchanged")
		}
	case <-time.After(time.Second):
		t.Fatal("ClientHello was not forwarded")
	}
}

func TestProxyManagedHTTPTransportPinsValidatedResolutionAndRejectsRebinding(t *testing.T) {
	policy := testProxyPolicy(t, boundary.Rule{ID: "visit", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example", Schemes: []string{"http"}}})
	lookup := func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" || host != "allowed.example" {
			t.Fatalf("lookup = %q %q", network, host)
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	dialed := make(chan string, 1)
	proxy, err := NewProxy(policy, ProxyOptions{
		LookupNetIP: lookup,
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			dialed <- network + ":" + address
			proxySide, upstreamSide := net.Pipe()
			go func() {
				defer upstreamSide.Close()
				request, readErr := http.ReadRequest(bufio.NewReader(upstreamSide))
				if readErr != nil {
					return
				}
				_ = request.Body.Close()
				_, _ = io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\npinned")
			}()
			return proxySide, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://allowed.example/", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "pinned" {
		t.Fatalf("pinned response = %d %q", recorder.Code, recorder.Body.String())
	}
	select {
	case address := <-dialed:
		if address != "tcp:93.184.216.34:80" {
			t.Fatalf("pinned dial = %q", address)
		}
	default:
		t.Fatal("managed transport did not dial a pinned address")
	}

	rebindingProxy, err := NewProxy(policy, ProxyOptions{
		LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("rebinding address reached network dial")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	rebindingProxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://allowed.example/", nil))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("rebinding response = %d", recorder.Code)
	}
}

func TestProxyCONNECTRejectsDeniedMissingAndMismatchedSNIWithoutDial(t *testing.T) {
	policy := testProxyPolicy(t, boundary.Rule{ID: "connect", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example", Schemes: []string{"https"}}})
	dialed := make(chan string, 1)
	proxy, err := NewProxy(policy, ProxyOptions{
		ClientHelloTimeout: 100 * time.Millisecond,
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed <- address
			left, right := net.Pipe()
			_ = right.Close()
			return left, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	denied := openCONNECT(t, server.Listener.Addr().String(), "unknown.example:443", http.StatusForbidden)
	_ = denied.Close()
	for _, hello := range [][]byte{testClientHello("other.example", 0), testClientHelloWithExtensions(nil, 0)} {
		client := openCONNECT(t, server.Listener.Addr().String(), "allowed.example:443", http.StatusOK)
		_, _ = client.Write(hello)
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = client.Read(make([]byte, 1))
		_ = client.Close()
	}
	select {
	case address := <-dialed:
		t.Fatalf("invalid CONNECT dialed %q", address)
	case <-time.After(150 * time.Millisecond):
	}
}

func testProxyPolicy(t *testing.T, rules ...boundary.Rule) *boundary.Policy {
	t.Helper()
	policy, err := boundary.NewPolicy(rules)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func openCONNECT(t *testing.T, proxyAddress, target string, wantStatus int) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", proxyAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != wantStatus {
		_ = connection.Close()
		t.Fatalf("CONNECT %s status = %d, want %d", target, response.StatusCode, wantStatus)
	}
	return connection
}
