package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/traffic"

	"go.uber.org/zap"
)

type hostTrafficRoundTripper struct{}

func (hostTrafficRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	body := "captured " + request.URL.Scheme + " " + request.URL.Path
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}, nil
}

func TestHostTrafficProxyCapturesHTTPAndHTTPSAsBestEffort(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "host-traffic.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("host traffic", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeHost})
	if err != nil {
		t.Fatal(err)
	}
	manager := newHostTrafficProxyManager(db, nil, zap.NewNop())
	manager.transport = hostTrafficRoundTripper{}
	resolver := newConversationExecutionBackendResolver(db, nil, nil, manager)
	ctx := mcp.WithMCPConversationID(context.Background(), conversation.ID)
	backend, err := resolver.ResolveExecutionBackend(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proxied, ok := backend.(*proxiedHostExecutionBackend)
	if !ok {
		t.Fatalf("backend = %T", backend)
	}
	if _, err := os.Stat(proxied.caPath); err != nil {
		t.Fatalf("temporary CA is unavailable: %v", err)
	}

	environment, err := backend.Execute(ctx, security.ExecutionRequest{
		Command: []string{"/bin/sh", "-c", `printf '%s|%s|%s' "$HTTPS_PROXY" "$CURL_CA_BUNDLE" "$NO_PROXY"`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(environment.Output, proxied.proxyURL+"|"+proxied.caPath+"|") || !strings.Contains(environment.Output, "127.0.0.1") {
		t.Fatalf("host capture environment = %q", environment.Output)
	}

	proxyURL, err := url.Parse(proxied.proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	unauthenticatedURL := *proxyURL
	unauthenticatedURL.User = nil
	unauthenticatedTransport := &http.Transport{Proxy: http.ProxyURL(&unauthenticatedURL)}
	unauthenticated := &http.Client{Transport: unauthenticatedTransport, Timeout: 3 * time.Second}
	response, err := unauthenticated.Get("http://example.com/rejected")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	unauthenticatedTransport.CloseIdleConnections()
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("unauthenticated status = %d", response.StatusCode)
	}

	caPEM, err := os.ReadFile(proxied.caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to trust conversation CA")
	}
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, target := range []string{"http://example.com/plain?q=1", "https://example.com/secure"} {
		response, requestErr := client.Get(target)
		if requestErr != nil {
			t.Fatalf("GET %s: %v", target, requestErr)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(body), "captured") {
			t.Fatalf("GET %s response=%q status=%d err=%v", target, body, response.StatusCode, readErr)
		}
	}
	transport.CloseIdleConnections()

	tempDir := manager.proxies[conversation.ID].tempDir
	closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	err = manager.Close(closeCtx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Fatalf("host capture temp directory still exists: %v", err)
	}
	items, total, err := db.ListTrafficTransactions(context.Background(), database.TrafficTransactionFilter{
		ConversationID: conversation.ID,
		RuntimeMode:    traffic.RuntimeModeHost,
		Limit:          10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("captured transactions total=%d items=%#v", total, items)
	}
	seenSchemes := map[string]bool{}
	for _, item := range items {
		if item.RuntimeMode != traffic.RuntimeModeHost || item.CaptureCoverage != traffic.CaptureCoverageBestEffort || item.HTTPStatus != http.StatusOK {
			t.Fatalf("captured transaction = %#v", item)
		}
		seenSchemes[item.Scheme] = true
		detail, getErr := db.GetTrafficTransaction(context.Background(), item.ID)
		if getErr != nil || len(detail.Messages) != 2 {
			t.Fatalf("captured detail=%#v err=%v", detail, getErr)
		}
	}
	if !seenSchemes["http"] || !seenSchemes["https"] {
		t.Fatalf("captured schemes = %#v", seenSchemes)
	}
}

func TestBuildHostTrafficCABundlePreservesSystemTrust(t *testing.T) {
	systemPath := filepath.Join(t.TempDir(), "system-ca.pem")
	if err := os.WriteFile(systemPath, []byte("SYSTEM-CA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := buildHostTrafficCABundle([]byte("CONVERSATION-CA\n"), []string{
		filepath.Join(t.TempDir(), "missing.pem"),
		systemPath,
	})
	if !bytes.Equal(bundle, []byte("SYSTEM-CA\nCONVERSATION-CA\n")) {
		t.Fatalf("combined CA bundle = %q", bundle)
	}
}
