package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"cyberstrike-ai/internal/egressactivity"
	"cyberstrike-ai/internal/networkprovenance"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/traffic"
	"cyberstrike-ai/internal/trafficspool"

	"github.com/google/uuid"
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
	signer    *networkprovenance.Signer
	ingestor  *egressactivity.Ingestor

	mu      sync.Mutex
	proxies map[string]*hostTrafficProxy
	closed  bool
}

type hostTrafficProxy struct {
	conversationID    string
	proxyURL          string
	caPath            string
	tempDir           string
	expiresAt         time.Time
	runtimeInstanceID string
	signer            *networkprovenance.Signer
	server            *http.Server
	listener          net.Listener
	sink              *trafficspool.CompactingSink
	audit             *hostAuditQueue
	base              security.ExecutionBackend
	closeOnce         sync.Once
	closeErr          error
}

type hostAuditQueue struct {
	db        *database.DB
	target    database.EgressAuditRuntimeTarget
	logger    *zap.Logger
	events    chan egress.ActivityEvent
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	lastErr   error
}

func newHostAuditQueue(db *database.DB, target database.EgressAuditRuntimeTarget, logger *zap.Logger) *hostAuditQueue {
	queue := &hostAuditQueue{
		db: db, target: target, logger: logger,
		events: make(chan egress.ActivityEvent, 4096), stop: make(chan struct{}), done: make(chan struct{}),
	}
	go queue.run()
	return queue
}

func (queue *hostAuditQueue) run() {
	defer close(queue.done)
	for event := range queue.events {
		backoff := 25 * time.Millisecond
		for {
			_, err := queue.db.AppendEgressNetworkAuditEvent(context.Background(), queue.target, event)
			if err == nil {
				break
			}
			if !retryableHostAuditError(err) {
				queue.mu.Lock()
				queue.lastErr = errors.Join(queue.lastErr, fmt.Errorf("persist Host MITM audit event %s (%s %s:%d %s %s %s; runtime=%s/%d/%s status=%s): %w",
					event.EventID, event.RequestType, event.Domain, event.Port, event.Decision, event.Method, event.Outcome,
					event.Provenance.RuntimeMode, event.Provenance.RuntimeGeneration, event.Provenance.RuntimeInstanceID, event.Provenance.AttributionStatus, err))
				queue.mu.Unlock()
				break
			}
			queue.logger.Warn("Host MITM 出站活动持久化失败，准备重试",
				zap.String("conversation_id", queue.target.Record.ConversationID), zap.String("event_id", event.EventID), zap.Error(err))
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
				if backoff < time.Second {
					backoff *= 2
				}
			case <-queue.stop:
				timer.Stop()
				return
			}
		}
	}
}

func retryableHostAuditError(err error) bool {
	message := strings.ToLower(strings.TrimSpace(fmt.Sprint(err)))
	return strings.Contains(message, "database is locked") || strings.Contains(message, "database table is locked") ||
		strings.Contains(message, "database is busy") || strings.Contains(message, "sqlite_busy") || strings.Contains(message, "sqlite_locked")
}

func (queue *hostAuditQueue) append(event egress.ActivityEvent) {
	if queue == nil {
		return
	}
	queue.events <- event
}

func (queue *hostAuditQueue) close(ctx context.Context) error {
	if queue == nil {
		return nil
	}
	queue.closeOnce.Do(func() { close(queue.events) })
	select {
	case <-queue.done:
		queue.mu.Lock()
		defer queue.mu.Unlock()
		return queue.lastErr
	case <-ctx.Done():
		close(queue.stop)
		<-queue.done
		return ctx.Err()
	}
}

type proxiedHostExecutionBackend struct {
	base              security.ExecutionBackend
	proxyURL          string
	caPath            string
	conversationID    string
	runtimeInstanceID string
	signer            *networkprovenance.Signer
}

func newHostTrafficProxyManager(db *database.DB, runner trafficTransformRunner, logger *zap.Logger, options ...any) *hostTrafficProxyManager {
	if logger == nil {
		logger = zap.NewNop()
	}
	manager := &hostTrafficProxyManager{
		db: db, runner: runner, logger: logger,
		proxies: make(map[string]*hostTrafficProxy),
	}
	for _, option := range options {
		switch value := option.(type) {
		case *networkprovenance.Signer:
			manager.signer = value
		case *egressactivity.Ingestor:
			manager.ingestor = value
		}
	}
	return manager
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
	if manager.signer == nil {
		return nil, errors.New("host traffic provenance signer is not configured")
	}
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

	runtimeInstanceID := uuid.NewString()
	snapshotDigest := sha256.Sum256([]byte("host-mitm:" + conversationID + ":" + runtimeInstanceID))
	snapshotSHA256 := "sha256:" + hex.EncodeToString(snapshotDigest[:])
	conversationTitle := ""
	if conversation, loadErr := manager.db.GetConversationLite(conversationID); loadErr == nil {
		conversationTitle = conversation.Title
	}
	auditTarget := database.EgressAuditRuntimeTarget{
		ConversationTitle: conversationTitle, RuntimeMode: networkprovenance.RuntimeModeHostMITM,
		Record: containerruntime.InitializationRecord{
			ConversationID: conversationID, ProviderID: runtimeInstanceID, RuntimeGeneration: 1,
			Spec: containerruntime.RuntimeSpec{
				ConversationID: conversationID,
				EgressGateway: &containerruntime.EgressGatewaySpec{
					BoundarySnapshot:             &containerruntime.EgressBoundarySnapshotSpec{ID: runtimeInstanceID, SHA256: snapshotSHA256},
					AttributionPublicKey:         manager.signer.PublicKeyEncoded(),
					AttributionRuntimeGeneration: 1,
					AttributionInstanceID:        runtimeInstanceID,
				},
			},
		},
	}
	auditQueue := newHostAuditQueue(manager.db, auditTarget, manager.logger)
	cleanupAuditQueue := true
	defer func() {
		if cleanupAuditQueue {
			closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = auditQueue.close(closeCtx)
			cancel()
		}
	}()
	verifier, err := manager.signer.Verifier()
	if err != nil {
		return nil, fmt.Errorf("create host traffic provenance verifier: %w", err)
	}
	proxy, err := egress.NewProxy(policy, egress.ProxyOptions{
		Transport:           manager.transport,
		TLSInspection:       &egress.TLSInspectionPolicy{Enabled: true, BypassDomains: []string{}},
		TLSAuthority:        authority,
		TrafficSink:         compactor.Write,
		ConversationID:      conversationID,
		RuntimeMode:         traffic.RuntimeModeHost,
		CaptureCoverage:     traffic.CaptureCoverageBestEffort,
		AttributionVerifier: verifier,
		AttributionAudience: networkprovenance.ExpectedAudience{
			ConversationID: conversationID, RuntimeMode: networkprovenance.RuntimeModeHostMITM,
			RuntimeGeneration: 1, RuntimeInstanceID: runtimeInstanceID,
		},
		ActivitySink: func(event egress.ActivityEvent) {
			event.SnapshotID = runtimeInstanceID
			event.SnapshotSHA256 = snapshotSHA256
			event.Provenance = networkprovenance.BindAudience(event.Provenance, networkprovenance.ExpectedAudience{
				ConversationID: conversationID, RuntimeMode: networkprovenance.RuntimeModeHostMITM,
				RuntimeGeneration: 1, RuntimeInstanceID: runtimeInstanceID,
			})
			if manager.ingestor != nil {
				manager.ingestor.Publish(egressactivity.IngestedActivity{ConversationID: conversationID, ConversationTitle: conversationTitle, Event: event})
			}
			auditQueue.append(event)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create host capture proxy: %w", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for host capture: %w", err)
	}
	proxyURL := (&url.URL{Scheme: "http", Host: listener.Addr().String()}).String()
	server := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	result := &hostTrafficProxy{
		conversationID: conversationID, proxyURL: proxyURL, caPath: caPath, tempDir: tempDir,
		runtimeInstanceID: runtimeInstanceID, signer: manager.signer,
		expiresAt: authority.Certificate.NotAfter.UTC(), server: server, listener: listener,
		sink: compactor, base: security.NewHostExecutionBackend(),
		audit: auditQueue,
	}
	cleanupCompactor = false
	cleanupAuditQueue = false
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

func (proxy *hostTrafficProxy) backend() security.ExecutionBackend {
	return &proxiedHostExecutionBackend{
		base: proxy.base, proxyURL: proxy.proxyURL, caPath: proxy.caPath,
		conversationID: proxy.conversationID, runtimeInstanceID: proxy.runtimeInstanceID,
		signer: proxy.signer,
	}
}

func (*proxiedHostExecutionBackend) ExecutionLocation() string { return "host" }

func (backend *proxiedHostExecutionBackend) Execute(ctx context.Context, request security.ExecutionRequest) (security.ExecutionResult, error) {
	if backend == nil || backend.base == nil {
		return security.ExecutionResult{Location: "host", ExitCode: -1}, errors.New("proxied host execution backend is not configured")
	}
	var declaredKind string
	var err error
	request, declaredKind, err = security.ConsumeNetworkScope(request)
	if err != nil {
		return security.ExecutionResult{Location: "host", ExitCode: -1}, err
	}
	provenance := networkprovenance.FromContext(ctx)
	provenance.ConversationID = backend.conversationID
	provenance.RuntimeMode = networkprovenance.RuntimeModeHostMITM
	provenance.RuntimeGeneration = 1
	provenance.RuntimeInstanceID = backend.runtimeInstanceID
	if provenance.ExecutionID == "" {
		provenance.ExecutionID = uuid.NewString()
	}
	if provenance.AgentID == "" {
		provenance.AgentID = "host-agent"
	}
	if provenance.ToolName == "" {
		provenance.ToolName = "host-exec"
	}
	if declaredKind == networkprovenance.ActivityKindFuzz {
		provenance.DeclaredActivityKind = declaredKind
	} else if provenance.DeclaredActivityKind == networkprovenance.ActivityKindUnknown {
		provenance.DeclaredActivityKind = networkprovenance.ActivityKindNormal
	}
	provenance = provenance.Normalized()
	deadline, _ := ctx.Deadline()
	request, sensitiveValues, err := prepareAttributedProxyRequest(request, backend.signer, provenance, deadline, backend.proxyURL)
	if err != nil {
		return security.ExecutionResult{Location: "host", ExitCode: -1}, fmt.Errorf("issue host traffic provenance: %w", err)
	}
	request.Env = append(request.Env,
		"NO_PROXY="+hostTrafficNoProxy,
		"no_proxy="+hostTrafficNoProxy,
		"CURL_CA_BUNDLE="+backend.caPath,
		"SSL_CERT_FILE="+backend.caPath,
		"REQUESTS_CA_BUNDLE="+backend.caPath,
		"NODE_EXTRA_CA_CERTS="+backend.caPath,
		"GIT_SSL_CAINFO="+backend.caPath,
		"AWS_CA_BUNDLE="+backend.caPath,
	)
	return executeWithCredentialRedaction(ctx, backend.base, request, sensitiveValues)
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
		if proxy.audit != nil {
			proxy.closeErr = errors.Join(proxy.closeErr, proxy.audit.close(ctx))
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
