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

	"cyberstrike-ai/internal/boundary"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/networkprovenance"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/traffic"

	"go.uber.org/zap"
)

type hostTrafficRoundTripper struct{}

type hostFeedbackExecutionBackend struct{}

func (hostFeedbackExecutionBackend) Execute(_ context.Context, request security.ExecutionRequest) (security.ExecutionResult, error) {
	if request.Output != nil {
		request.Output("base-output")
	}
	return security.ExecutionResult{Output: "base-output", ExitCode: 0, Location: "host"}, nil
}

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
	signer, err := networkprovenance.LoadOrCreateSigner(filepath.Join(t.TempDir(), "provenance.key"))
	if err != nil {
		t.Fatal(err)
	}
	manager := newHostTrafficProxyManager(db, nil, zap.NewNop(), signer)
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
	environmentParts := strings.SplitN(environment.Output, "|", 3)
	if len(environmentParts) != 3 || !strings.Contains(environmentParts[0], redactedNetworkCredential) || strings.Contains(environmentParts[0], "v1.") || environmentParts[1] != proxied.caPath || !strings.Contains(environmentParts[2], "127.0.0.1") {
		t.Fatalf("host capture environment = %q", environment.Output)
	}
	provenance := networkprovenance.NetworkProvenanceV1{
		ConversationID: conversation.ID, RuntimeMode: networkprovenance.RuntimeModeHostMITM,
		RuntimeGeneration: 1, RuntimeInstanceID: proxied.runtimeInstanceID,
		AgentID: "agent-test", ToolName: "exec", ExecutionID: "execution-test",
		ToolCallID: "call-test", DeclaredActivityKind: networkprovenance.ActivityKindNormal,
	}.Normalized()
	prepared, sensitiveValues, err := prepareAttributedProxyRequest(security.ExecutionRequest{Command: []string{
		"/bin/sh", "-c", `printf normal; network-scope fuzz -- printf fuzz`,
	}}, signer, provenance, time.Time{}, proxied.proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(sensitiveValues) != 4 {
		t.Fatalf("sensitive proxy values = %d", len(sensitiveValues))
	}
	var mixedURLs []string
	for _, entry := range prepared.Env {
		name, value, found := strings.Cut(entry, "=")
		if found && (name == "HTTP_PROXY" || name == "CYBERSTRIKE_NETWORK_SCOPE_FUZZ_PROXY") {
			mixedURLs = append(mixedURLs, value)
		}
	}
	if len(mixedURLs) != 2 || mixedURLs[0] == mixedURLs[1] {
		t.Fatalf("normal/fuzz proxy scopes = %#v", mixedURLs)
	}
	verifiedScopes := make([]networkprovenance.NetworkProvenanceV1, 0, 2)
	verifier, err := signer.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range mixedURLs {
		parsed, parseErr := url.Parse(raw)
		if parseErr != nil || parsed.User == nil {
			t.Fatalf("parse scoped proxy %q: %v", raw, parseErr)
		}
		token, ok := parsed.User.Password()
		if !ok {
			t.Fatalf("scoped proxy has no token: %q", raw)
		}
		verified, verifyErr := verifier.Verify(token, networkprovenance.ExpectedAudience{
			ConversationID: conversation.ID, RuntimeMode: networkprovenance.RuntimeModeHostMITM,
			RuntimeGeneration: 1, RuntimeInstanceID: proxied.runtimeInstanceID,
		})
		if verifyErr != nil {
			t.Fatalf("verify scoped proxy: %v", verifyErr)
		}
		verifiedScopes = append(verifiedScopes, verified)
	}
	if verifiedScopes[0].ExecutionID != verifiedScopes[1].ExecutionID || verifiedScopes[0].ActivityScopeID == verifiedScopes[1].ActivityScopeID ||
		verifiedScopes[0].DeclaredActivityKind != networkprovenance.ActivityKindNormal || verifiedScopes[1].DeclaredActivityKind != networkprovenance.ActivityKindFuzz {
		t.Fatalf("normal/fuzz child scopes = %#v", verifiedScopes)
	}

	proxyURL, err := url.Parse(mixedURLs[0])
	if err != nil {
		t.Fatal(err)
	}
	unauthenticatedURL, err := url.Parse(proxied.proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	unauthenticatedTransport := &http.Transport{Proxy: http.ProxyURL(unauthenticatedURL)}
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
	auditItems, auditErr := db.ListEgressAuditEvents(context.Background(), database.EgressAuditFilter{
		ConversationID: conversation.ID, RuntimeMode: networkprovenance.RuntimeModeHostMITM,
		Scope: database.RBACScopeAll, Limit: 20,
	})
	if auditErr != nil {
		t.Fatal(auditErr)
	}
	auditEventIDs := make(map[string]struct{}, len(auditItems))
	for _, audit := range auditItems {
		auditEventIDs[audit.SourceEventID] = struct{}{}
	}
	for _, item := range items {
		if item.RuntimeMode != traffic.RuntimeModeHost || item.CaptureCoverage != traffic.CaptureCoverageBestEffort || item.HTTPStatus != http.StatusOK {
			t.Fatalf("captured transaction = %#v", item)
		}
		seenSchemes[item.Scheme] = true
		if item.EventID == "" {
			t.Fatalf("captured transaction has no shared event id: %#v", item)
		}
		if _, exists := auditEventIDs[item.EventID]; !exists {
			t.Fatalf("traffic event %q has no matching audit event: %#v", item.EventID, auditItems)
		}
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

func TestProxiedHostExecutionAppendsStructuredBoundaryFeedback(t *testing.T) {
	signer, err := networkprovenance.LoadOrCreateSigner(filepath.Join(t.TempDir(), "provenance.key"))
	if err != nil {
		t.Fatal(err)
	}
	recorder := newHostActivityRecorder()
	const executionID = "execution-host-block"
	recorder.record(egress.ActivityEvent{
		RequestType: egress.ActivityRequestHTTPS, Domain: "example.com", Port: 443, Method: http.MethodGet,
		Decision: egress.ActivityDecisionBlocked, Reason: boundary.ReasonBlockedPathSubtree, RuleID: "rule-path",
		Provenance: networkprovenance.NetworkProvenanceV1{ExecutionID: executionID}.Normalized(),
		BlockMatch: &boundary.BlockMatch{
			Source: boundary.MatchSourceRule, Type: boundary.MatchTypePathSubtree, Value: "/blocked/*",
			RequestURL: "https://example.com:443/blocked/child", DecisionPhase: boundary.DecisionPhaseRequest,
			RuleConstraints: &boundary.RuleConstraints{Host: "*", Schemes: []string{"https"}, Ports: []int{443}, PathPrefixes: []string{"/blocked/*"}, Methods: []string{"GET"}},
		},
	})
	backend := &proxiedHostExecutionBackend{
		base: hostFeedbackExecutionBackend{}, proxyURL: "http://127.0.0.1:18081", caPath: filepath.Join(t.TempDir(), "ca.pem"),
		conversationID: "conversation-host", runtimeInstanceID: "runtime-host", signer: signer, recorder: recorder,
	}
	ctx := networkprovenance.WithContext(context.Background(), networkprovenance.NetworkProvenanceV1{
		ExecutionID: executionID, AgentID: "agent-host", ToolName: "exec", ToolCallID: "call-host",
	})
	var streamed strings.Builder
	result, err := backend.Execute(ctx, security.ExecutionRequest{
		Command: []string{"printf", "ok"}, Output: func(value string) { streamed.WriteString(value) },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{result.Output, streamed.String()} {
		for _, wanted := range []string{
			"https://example.com:443/blocked/child", "路径子树阻断（blocked-path-subtree）", "命中条件：路径 /blocked/*", "请求未发送到目标",
		} {
			if !strings.Contains(output, wanted) {
				t.Fatalf("Host feedback missing %q: %q", wanted, output)
			}
		}
	}
	if items := recorder.take(executionID); len(items) != 0 {
		t.Fatalf("Host feedback recorder was not drained: %#v", items)
	}
}

func TestHostAuditQueueFailureRecordingIsOffByDefaultAndHotSwitchable(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "host-failure-toggle.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("host failure toggle", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeHost})
	if err != nil {
		t.Fatal(err)
	}
	runtimeInstanceID := "11111111-1111-4111-8111-111111111111"
	snapshotSHA256 := "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	target := database.EgressAuditRuntimeTarget{
		ConversationTitle: conversation.Title, RuntimeMode: networkprovenance.RuntimeModeHostMITM,
		Record: containerruntime.InitializationRecord{
			ConversationID: conversation.ID, ProviderID: runtimeInstanceID, RuntimeGeneration: 1,
			Spec: containerruntime.RuntimeSpec{ConversationID: conversation.ID, EgressGateway: &containerruntime.EgressGatewaySpec{
				BoundarySnapshot:      &containerruntime.EgressBoundarySnapshotSpec{ID: runtimeInstanceID, SHA256: snapshotSHA256},
				AttributionInstanceID: runtimeInstanceID,
			}},
		},
	}
	event := func(id, outcome string) egress.ActivityEvent {
		return egress.ActivityEvent{
			EventID: id, Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), RequestType: egress.ActivityRequestTCP,
			Domain: "127.0.0.1", ConnectedIP: "127.0.0.1", Port: 1, Decision: egress.ActivityDecisionAllowed, Outcome: outcome,
			SnapshotID: runtimeInstanceID, SnapshotSHA256: snapshotSHA256,
			Provenance: networkprovenance.NetworkProvenanceV1{
				ConversationID: conversation.ID, RuntimeMode: networkprovenance.RuntimeModeHostMITM,
				RuntimeGeneration: 1, RuntimeInstanceID: runtimeInstanceID,
				AttributionStatus: networkprovenance.AttributionUnattributed,
			}.Normalized(),
		}
	}
	queue := newHostAuditQueue(db, target, zap.NewNop(), nil, true, database.EgressAggregationModeNone, false)
	queue.append(event("failure-off", "dial_failed"))
	queue.append(event("success", "forwarded"))
	if err := queue.setSetting(context.Background(), true, database.EgressAggregationModeNone, true); err != nil {
		t.Fatal(err)
	}
	queue.append(event("failure-on", "dial_failed"))
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := queue.close(closeCtx); err != nil {
		t.Fatal(err)
	}
	items, err := db.ListEgressAuditEvents(context.Background(), database.EgressAuditFilter{
		ConversationID: conversation.ID, RuntimeMode: networkprovenance.RuntimeModeHostMITM, Scope: database.RBACScopeAll, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("host failure events = %#v", items)
	}
	seen := map[string]bool{}
	for _, item := range items {
		seen[item.SourceEventID] = true
	}
	if seen["failure-off"] || !seen["success"] || !seen["failure-on"] {
		t.Fatalf("host failure switch persisted IDs = %#v", seen)
	}
}
