package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
)

func TestUpstreamRouteStoreIsImmutableCanonicalAndCredentialPrivate(t *testing.T) {
	store, err := NewUpstreamRouteStore(filepath.Join(t.TempDir(), "routes"))
	if err != nil {
		t.Fatal(err)
	}
	route := NewProxyUpstreamRoute(UpstreamEndpoint{
		ID: "proxy-1", Protocol: UpstreamProtocolHTTP, Host: "proxy.example", Port: 3128,
		Username: "route-user", Password: "route-secret",
	})
	reference, path, err := store.Put("conversation-1", route)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("route mode = %v, err=%v", info.Mode().Perm(), err)
	}
	loaded, err := LoadUpstreamRoute(path, reference)
	if err != nil || loaded.Proxy == nil || loaded.Proxy.Password != "route-secret" {
		t.Fatalf("loaded route = %#v, err=%v", loaded, err)
	}
	content, _ := os.ReadFile(path)
	if strings.Contains(reference.ID+reference.SHA256, "route-user") || strings.Contains(reference.ID+reference.SHA256, "route-secret") {
		t.Fatal("safe route reference exposed credentials")
	}
	if string(content) != `{"schemaVersion":1,"mode":"proxy","proxy":{"id":"proxy-1","protocol":"http","host":"proxy.example","port":3128,"username":"route-user","password":"route-secret"}}` {
		t.Fatalf("route JSON is not canonical: %s", content)
	}

	changed := NewProxyUpstreamRoute(*route.Proxy)
	changed.Proxy.Port = 8080
	if _, _, err := store.Put("conversation-1", changed); !errors.Is(err, ErrUpstreamRouteIntegrity) {
		t.Fatalf("immutable route replacement error = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUpstreamRoute(path, reference); !errors.Is(err, ErrUpstreamRouteIntegrity) {
		t.Fatalf("writable route error = %v", err)
	}
}

func TestHTTPUpstreamRouteTunnelsPinnedTargetAndNeverFallsBackDirect(t *testing.T) {
	endpoint := UpstreamEndpoint{
		ID: "proxy-http", Protocol: UpstreamProtocolHTTP, Host: "proxy.example", Port: 3128,
		Username: "proxy-user", Password: "proxy-password",
	}
	var addresses []string
	var mu sync.Mutex
	baseDial := func(_ context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		addresses = append(addresses, network+" "+address)
		mu.Unlock()
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			request, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				return
			}
			if request.Method != http.MethodConnect || request.Host != "203.0.113.10:443" || request.Header.Get("Proxy-Authorization") == "" {
				return
			}
			_, _ = io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\n")
			payload := make([]byte, 4)
			if _, err := io.ReadFull(server, payload); err == nil && string(payload) == "ping" {
				_, _ = io.WriteString(server, "pong")
			}
		}()
		return client, nil
	}
	dialer, err := newUpstreamDialer(NewProxyUpstreamRoute(endpoint), baseDial, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialer.DialContext(context.Background(), "tcp", "203.0.113.10:443")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, "ping"); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(connection, reply); err != nil || string(reply) != "pong" {
		t.Fatalf("tunnel reply = %q, err=%v", reply, err)
	}
	if len(addresses) != 1 || addresses[0] != "tcp proxy.example:3128" {
		t.Fatalf("dial addresses = %#v", addresses)
	}

	failing, err := newUpstreamDialer(NewProxyUpstreamRoute(endpoint), func(_ context.Context, _, address string) (net.Conn, error) {
		if address == "203.0.113.10:443" {
			t.Fatal("proxy failure fell back to the requested target")
		}
		return nil, errors.New("proxy offline")
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.DialContext(context.Background(), "tcp", "203.0.113.10:443"); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("proxy failure error = %v", err)
	}
}

func TestProxyGroupOpensCircuitsAndBlocksWhenEveryUpstreamIsUnavailable(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	route := NewProxyGroupUpstreamRoute(UpstreamRouteGroup{
		ID: "group-1", FailureThreshold: 1, CooldownSeconds: 60,
		Members: []UpstreamRouteMember{
			{Proxy: UpstreamEndpoint{ID: "proxy-a", Protocol: UpstreamProtocolHTTP, Host: "a.proxy.example", Port: 3128}, Priority: 0, Weight: 1},
			{Proxy: UpstreamEndpoint{ID: "proxy-b", Protocol: UpstreamProtocolSOCKS5, Host: "b.proxy.example", Port: 1080}, Priority: 0, Weight: 1},
		},
	})
	var addresses []string
	dialer, err := newUpstreamDialer(route, func(_ context.Context, _, address string) (net.Conn, error) {
		if address == "198.51.100.20:443" {
			t.Fatal("unavailable group fell back to direct target")
		}
		addresses = append(addresses, address)
		return nil, errors.New("member offline")
	}, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := dialer.DialContext(context.Background(), "tcp", "198.51.100.20:443"); !errors.Is(err, ErrUpstreamUnavailable) {
			t.Fatalf("attempt %d error = %v", attempt, err)
		}
	}
	if len(addresses) != 2 || addresses[0] == addresses[1] {
		t.Fatalf("group attempts = %#v", addresses)
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "198.51.100.20:443"); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("all-circuits-open error = %v", err)
	}
	if len(addresses) != 2 {
		t.Fatalf("all-circuits-open performed another dial: %#v", addresses)
	}

	now = now.Add(61 * time.Second)
	if _, err := dialer.DialContext(context.Background(), "tcp", "198.51.100.20:443"); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("cooldown retry error = %v", err)
	}
	if len(addresses) != 3 {
		t.Fatalf("cooldown did not permit one proxy retry: %#v", addresses)
	}
}

func TestSOCKS5UpstreamUsesPinnedIPAndCredentials(t *testing.T) {
	endpoint := UpstreamEndpoint{
		ID: "proxy-socks", Protocol: UpstreamProtocolSOCKS5, Host: "socks.example", Port: 1080,
		Username: "user", Password: "password",
	}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(server, greeting); err != nil || string(greeting) != string([]byte{0x05, 0x01, 0x02}) {
			done <- errors.New("invalid greeting")
			return
		}
		_, _ = server.Write([]byte{0x05, 0x02})
		auth := make([]byte, 2+len(endpoint.Username)+1+len(endpoint.Password))
		if _, err := io.ReadFull(server, auth); err != nil {
			done <- err
			return
		}
		_, _ = server.Write([]byte{0x01, 0x00})
		request := make([]byte, 10)
		if _, err := io.ReadFull(server, request); err != nil || request[3] != 0x01 || request[4] != 203 || request[5] != 0 || request[6] != 113 || request[7] != 8 {
			done <- errors.New("SOCKS5 target was not the pinned IPv4 address")
			return
		}
		if _, err := server.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 1}); err != nil {
			done <- err
			return
		}
		probe := make([]byte, 1)
		if _, err := server.Read(probe); err != nil && !errors.Is(err, io.EOF) {
			done <- err
			return
		}
		done <- nil
	}()
	dialer, err := newUpstreamDialer(NewProxyUpstreamRoute(endpoint), func(context.Context, string, string) (net.Conn, error) {
		return client, nil
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialer.DialContext(context.Background(), "tcp", "203.0.113.8:443")
	if err != nil {
		t.Fatalf("%v; SOCKS5 peer: %v", err, <-done)
	}
	_ = connection.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPSUpstreamAuthenticatesTLSBeforeCONNECT(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.Host != "203.0.113.9:443" {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			return
		}
		connection, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffered.Flush()
		payload := make([]byte, 4)
		if _, err := io.ReadFull(buffered, payload); err == nil && string(payload) == "ping" {
			_, _ = io.WriteString(connection, "pong")
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	route := NewProxyUpstreamRoute(UpstreamEndpoint{ID: "proxy-https", Protocol: UpstreamProtocolHTTPS, Host: "example.com", Port: 443})
	dialer, err := newUpstreamDialer(route, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}, tlsConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialer.DialContext(context.Background(), "tcp", "203.0.113.9:443")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = io.WriteString(connection, "ping")
	reply := make([]byte, 4)
	if _, err := io.ReadFull(connection, reply); err != nil || string(reply) != "pong" {
		t.Fatalf("HTTPS upstream reply = %q, err=%v", reply, err)
	}
}

func TestPolicyProxyUsesConfiguredUpstreamAndReturnsBadGatewayWithoutDirectFallback(t *testing.T) {
	policy := testProxyPolicy(t, boundary.Rule{
		ID: "visit", Effect: boundary.EffectAllowVisit,
		Target: boundary.RuleTarget{Host: "allowed.example", Schemes: []string{"http"}, Methods: []string{"GET"}},
	})
	route := NewProxyUpstreamRoute(UpstreamEndpoint{
		ID: "proxy-fail", Protocol: UpstreamProtocolHTTP, Host: "proxy.example", Port: 3128,
	})
	proxy, err := NewProxy(policy, ProxyOptions{
		UpstreamRoute: &route,
		LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.25")}, nil
		},
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			if address == "203.0.113.25:80" {
				t.Fatal("policy proxy fell back to a direct target dial")
			}
			if address != "proxy.example:3128" {
				t.Fatalf("unexpected dial address %q", address)
			}
			return nil, errors.New("proxy offline")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://allowed.example/", nil))
	if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), "proxy.example") {
		t.Fatalf("upstream failure response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestPolicyProxyRejectsCustomTransportThatCouldBypassConfiguredUpstream(t *testing.T) {
	policy := testProxyPolicy(t, boundary.Rule{ID: "visit", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example"}})
	route := NewProxyUpstreamRoute(UpstreamEndpoint{ID: "proxy-1", Protocol: UpstreamProtocolHTTP, Host: "proxy.example", Port: 3128})
	if _, err := NewProxy(policy, ProxyOptions{
		UpstreamRoute: &route,
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("bypass transport was invoked")
			return nil, nil
		}),
	}); err == nil {
		t.Fatal("configured upstream accepted a bypass-capable custom transport")
	}
}

func TestUpstreamHandshakeStopsPromptlyWhenRequestContextIsCanceled(t *testing.T) {
	route := NewProxyUpstreamRoute(UpstreamEndpoint{ID: "proxy-hang", Protocol: UpstreamProtocolHTTP, Host: "proxy.example", Port: 3128})
	client, server := net.Pipe()
	defer server.Close()
	dialer, err := newUpstreamDialer(route, func(context.Context, string, string) (net.Conn, error) {
		return client, nil
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	started := time.Now()
	if _, err := dialer.DialContext(ctx, "tcp", "203.0.113.40:443"); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("canceled handshake error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled handshake took %s", elapsed)
	}
}
