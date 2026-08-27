package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/boundary"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/traffic"
	"cyberstrike-ai/internal/trafficspool"

	"go.uber.org/zap"
)

const (
	hostTrafficProxyUsername = "cyberstrike"
	hostTrafficCALifetime    = 7 * 24 * time.Hour
)

var hostTrafficNoProxy = strings.Join([]string{
	"localhost", "127.0.0.1", "::1",
	// Preserve direct access to the local testing ranges that host mode already
	// allowed. These requests remain outside best-effort capture by design.
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
}, ",")

var hostSystemCABundleCandidates = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Kali
	"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
	"/etc/ssl/ca-bundle.pem",             // SUSE, Alpine variants
	"/etc/ssl/cert.pem",                  // macOS, Alpine
}

// hostTrafficProxyManager owns one authenticated loopback proxy per host
// conversation. It never changes process-wide proxy or trust settings.
type hostTrafficProxyManager struct {
	db        *database.DB
	runner    trafficTransformRunner
	logger    *zap.Logger
	transport http.RoundTripper

	mu      sync.Mutex
	proxies map[string]*hostTrafficProxy
	closed  bool
}

type hostTrafficProxy struct {
	conversationID string
	proxyURL       string
	caPath         string
	tempDir        string
	expiresAt      time.Time
	server         *http.Server
	listener       net.Listener
	sink           *trafficspool.CompactingSink
	base           security.ExecutionBackend
	closeOnce      sync.Once
	closeErr       error
}

type proxiedHostExecutionBackend struct {
	base     security.ExecutionBackend
	proxyURL string
	caPath   string
}

func newHostTrafficProxyManager(db *database.DB, runner trafficTransformRunner, logger *zap.Logger) *hostTrafficProxyManager {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &hostTrafficProxyManager{
		db: db, runner: runner, logger: logger,
		proxies: make(map[string]*hostTrafficProxy),
	}
}

func (manager *hostTrafficProxyManager) ResolveHostExecutionBackend(ctx context.Context, conversationID string) (security.ExecutionBackend, error) {
	if manager == nil || manager.db == nil {
		return nil, errors.New("host traffic proxy manager is not configured")
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return nil, errors.New("host traffic proxy conversation id is required")
	}
	if mode, err := manager.db.GetConversationRuntimeMode(conversationID); err != nil {
		return nil, err
	} else if mode != database.ConversationRuntimeModeHost {
		return nil, fmt.Errorf("conversation %s is not a host conversation", conversationID)
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed {
		return nil, errors.New("host traffic proxy manager is closed")
	}
	if current := manager.proxies[conversationID]; current != nil {
		if time.Now().UTC().Before(current.expiresAt.Add(-5 * time.Minute)) {
			return current.backend(), nil
		}
		_ = current.close(ctx)
		delete(manager.proxies, conversationID)
	}
	created, err := manager.startProxy(conversationID)
	if err != nil {
		return nil, err
	}
	manager.proxies[conversationID] = created
	return created.backend(), nil
}

func (manager *hostTrafficProxyManager) startProxy(conversationID string) (_ *hostTrafficProxy, resultErr error) {
	policy, err := boundary.NewPolicyWithDefault(nil, true)
	if err != nil {
		return nil, fmt.Errorf("compile host capture policy: %w", err)
	}
	authority, err := egress.GenerateTLSAuthority(conversationID, time.Now().UTC(), hostTrafficCALifetime)
	if err != nil {
		return nil, fmt.Errorf("generate host capture authority: %w", err)
	}
	tempDir, err := os.MkdirTemp("", "cyberstrike-host-traffic-")
	if err != nil {
		return nil, fmt.Errorf("create host capture directory: %w", err)
	}
	defer func() {
		if resultErr != nil {
			_ = os.RemoveAll(tempDir)
		}
	}()
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return nil, fmt.Errorf("protect host capture directory: %w", err)
	}
	caPath := filepath.Join(tempDir, "ca-bundle.pem")
	if err := os.WriteFile(caPath, buildHostTrafficCABundle(authority.CertificatePEM, hostSystemCABundleCandidates), 0o600); err != nil {
		return nil, fmt.Errorf("write host capture authority: %w", err)
	}

	destination := func(ctx context.Context, item traffic.Transaction, messages []traffic.Message) error {
		detail, createErr := manager.db.CreateTrafficTransaction(ctx, &item, messages)
		if createErr != nil {
			return createErr
		}
		observeImportedTraffic(ctx, manager.db, manager.runner, detail, manager.logger)
		return nil
	}
	compactor, err := trafficspool.NewCompactingSink(destination, trafficspool.DefaultCompactConfig())
	if err != nil {
		return nil, err
	}
	cleanupCompactor := true
	defer func() {
		if cleanupCompactor {
			_ = compactor.Close()
		}
	}()

	proxy, err := egress.NewProxy(policy, egress.ProxyOptions{
		Transport:       manager.transport,
		TLSInspection:   &egress.TLSInspectionPolicy{Enabled: true, BypassDomains: []string{}},
		TLSAuthority:    authority,
		TrafficSink:     compactor.Write,
		ConversationID:  conversationID,
		RuntimeMode:     traffic.RuntimeModeHost,
		CaptureCoverage: traffic.CaptureCoverageBestEffort,
	})
	if err != nil {
		return nil, fmt.Errorf("create host capture proxy: %w", err)
	}
	token, err := randomHostTrafficToken()
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for host capture: %w", err)
	}
	proxyURL := (&url.URL{
		Scheme: "http", Host: listener.Addr().String(),
		User: url.UserPassword(hostTrafficProxyUsername, token),
	}).String()
	server := &http.Server{
		Handler:           hostTrafficProxyAuth(proxy, token),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	result := &hostTrafficProxy{
		conversationID: conversationID, proxyURL: proxyURL, caPath: caPath, tempDir: tempDir,
		expiresAt: authority.Certificate.NotAfter.UTC(), server: server, listener: listener,
		sink: compactor, base: security.NewHostExecutionBackend(),
	}
	cleanupCompactor = false
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			manager.logger.Warn("本机 MITM 流量代理异常退出", zap.String("conversation_id", conversationID), zap.Error(serveErr))
		}
	}()
	manager.logger.Info("本机 MITM 流量代理已启动",
		zap.String("conversation_id", conversationID),
		zap.String("listen", listener.Addr().String()),
		zap.String("capture_coverage", traffic.CaptureCoverageBestEffort),
	)
	return result, nil
}

func buildHostTrafficCABundle(conversationCA []byte, candidates []string) []byte {
	bundle := make([]byte, 0, len(conversationCA)+256<<10)
	for _, candidate := range candidates {
		content, err := os.ReadFile(candidate)
		if err != nil || len(bytes.TrimSpace(content)) == 0 {
			continue
		}
		bundle = append(bundle, content...)
		if !bytes.HasSuffix(bundle, []byte("\n")) {
			bundle = append(bundle, '\n')
		}
		break
	}
	bundle = append(bundle, conversationCA...)
	return bundle
}

func randomHostTrafficToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate host capture credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hostTrafficProxyAuth(next http.Handler, expectedToken string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := parseProxyBasicAuth(request.Header.Get("Proxy-Authorization"))
		validUser := subtle.ConstantTimeCompare([]byte(username), []byte(hostTrafficProxyUsername)) == 1
		validPassword := subtle.ConstantTimeCompare([]byte(password), []byte(expectedToken)) == 1
		if !ok || !validUser || !validPassword {
			writer.Header().Set("Proxy-Authenticate", `Basic realm="CyberStrike host traffic"`)
			http.Error(writer, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
		request.Header.Del("Proxy-Authorization")
		next.ServeHTTP(writer, request)
	})
}

func parseProxyBasicAuth(value string) (username, password string, ok bool) {
	scheme, encoded, found := strings.Cut(strings.TrimSpace(value), " ")
	if !found || !strings.EqualFold(scheme, "Basic") || strings.TrimSpace(encoded) == "" {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", "", false
	}
	username, password, ok = strings.Cut(string(decoded), ":")
	return username, password, ok
}

func (proxy *hostTrafficProxy) backend() security.ExecutionBackend {
	return &proxiedHostExecutionBackend{base: proxy.base, proxyURL: proxy.proxyURL, caPath: proxy.caPath}
}

func (*proxiedHostExecutionBackend) ExecutionLocation() string { return "host" }

func (backend *proxiedHostExecutionBackend) Execute(ctx context.Context, request security.ExecutionRequest) (security.ExecutionResult, error) {
	if backend == nil || backend.base == nil {
		return security.ExecutionResult{Location: "host", ExitCode: -1}, errors.New("proxied host execution backend is not configured")
	}
	request.Env = append(request.Env,
		"HTTP_PROXY="+backend.proxyURL,
		"HTTPS_PROXY="+backend.proxyURL,
		"http_proxy="+backend.proxyURL,
		"https_proxy="+backend.proxyURL,
		"NO_PROXY="+hostTrafficNoProxy,
		"no_proxy="+hostTrafficNoProxy,
		"CURL_CA_BUNDLE="+backend.caPath,
		"SSL_CERT_FILE="+backend.caPath,
		"REQUESTS_CA_BUNDLE="+backend.caPath,
		"NODE_EXTRA_CA_CERTS="+backend.caPath,
		"GIT_SSL_CAINFO="+backend.caPath,
		"AWS_CA_BUNDLE="+backend.caPath,
	)
	return backend.base.Execute(ctx, request)
}

func (proxy *hostTrafficProxy) close(ctx context.Context) error {
	if proxy == nil {
		return nil
	}
	proxy.closeOnce.Do(func() {
		if proxy.server != nil {
			proxy.closeErr = errors.Join(proxy.closeErr, proxy.server.Shutdown(ctx))
		}
		if proxy.sink != nil {
			proxy.closeErr = errors.Join(proxy.closeErr, proxy.sink.Close())
		}
		if proxy.tempDir != "" {
			proxy.closeErr = errors.Join(proxy.closeErr, os.RemoveAll(proxy.tempDir))
		}
	})
	return proxy.closeErr
}

func (manager *hostTrafficProxyManager) Close(ctx context.Context) error {
	if manager == nil {
		return nil
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed {
		return nil
	}
	manager.closed = true
	var result error
	for conversationID, proxy := range manager.proxies {
		if err := proxy.close(ctx); err != nil {
			result = errors.Join(result, fmt.Errorf("close host traffic proxy %s: %w", conversationID, err))
		}
		delete(manager.proxies, conversationID)
	}
	return result
}
