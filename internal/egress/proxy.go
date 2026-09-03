package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/boundary"
	"cyberstrike-ai/internal/traffic"

	"github.com/google/uuid"
)

const (
	DefaultProxyListenAddress = "0.0.0.0:3128"
	defaultClientHelloTimeout = 5 * time.Second
)

type DialContextFunc func(context.Context, string, string) (net.Conn, error)
type LookupNetIPFunc func(context.Context, string, string) ([]netip.Addr, error)

type ProxyOptions struct {
	DialContext             DialContextFunc
	LookupNetIP             LookupNetIPFunc
	Transport               http.RoundTripper
	UpstreamRoute           *UpstreamRoute
	AuthProfiles            *AuthProfilesDocument
	UpstreamTLSConfig       *tls.Config
	Now                     func() time.Time
	ClientHelloTimeout      time.Duration
	MaxClientHello          int
	ActivitySink            ActivitySink
	TLSInspection           *TLSInspectionPolicy
	TLSAuthority            *TLSAuthority
	HTTPRequestsPerSecond   int
	TCPConnectionsPerSecond int
	UDPDatagramsPerSecond   int
	TrafficSink             TrafficSink
	ConversationID          string
	BoundarySnapshotID      string
	UpstreamRouteID         string
	RuntimeMode             string
	CaptureCoverage         string
}

// Proxy is the policy-enforcing HTTP forward proxy and HTTPS CONNECT tunnel.
// It never accepts policy input from a request: the immutable compiled policy
// is loaded once from the gateway's read-only snapshot.
type Proxy struct {
	policy             *boundary.Policy
	dialContext        DialContextFunc
	lookupNetIP        LookupNetIPFunc
	transport          http.RoundTripper
	authProfiles       map[string]GatewayAuthProfile
	now                func() time.Time
	clientHelloTimeout time.Duration
	maxClientHello     int
	activitySink       ActivitySink
	guard              *requestGuard
	tlsInspection      *TLSInspectionPolicy
	tlsAuthority       *TLSAuthority
	httpPacer          *trafficPacer
	tcpPacer           *trafficPacer
	udpPacer           *trafficPacer
	trafficSink        TrafficSink
	conversationID     string
	boundarySnapshotID string
	upstreamRouteID    string
	runtimeMode        string
	captureCoverage    string
}

type boundedPacketCapture struct {
	content bytes.Buffer
	total   int64
}

func (capture *boundedPacketCapture) Write(content []byte) (int, error) {
	capture.total += int64(len(content))
	remaining := MaxHTTPPacketBodyBytes - capture.content.Len()
	if remaining > 0 {
		if remaining > len(content) {
			remaining = len(content)
		}
		_, _ = capture.content.Write(content[:remaining])
	}
	return len(content), nil
}

func (capture *boundedPacketCapture) snapshot(contentType string) (body, encoding string, truncated bool) {
	content := capture.content.Bytes()
	truncated = capture.total > int64(len(content))
	if len(content) == 0 {
		return "", "", truncated
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	textual := mediaType == "" || strings.HasPrefix(mediaType, "text/") || strings.Contains(mediaType, "json") ||
		strings.Contains(mediaType, "xml") || strings.Contains(mediaType, "javascript") ||
		mediaType == "application/x-www-form-urlencoded"
	if textual && utf8.Valid(content) {
		return string(content), "utf8", truncated
	}
	return base64.StdEncoding.EncodeToString(content), "base64", truncated
}

type packetCaptureReadCloser struct {
	io.Reader
	io.Closer
}

func packetHeaders(headers http.Header) map[string][]string {
	result := make(map[string][]string, len(headers))
	for rawName, rawValues := range headers {
		name := http.CanonicalHeaderKey(rawName)
		values := make([]string, len(rawValues))
		for index, value := range rawValues {
			values[index] = value
		}
		result[name] = values
	}
	return result
}

func packetRequestTarget(request *http.Request, fallbackPath string) string {
	target := fallbackPath
	if request != nil && request.URL != nil {
		if escaped := request.URL.EscapedPath(); escaped != "" {
			target = escaped
		}
		if request.URL.RawQuery != "" {
			target += "?" + request.URL.RawQuery
		}
	}
	return target
}

func newHTTPPacket(request *http.Request, path string) HTTPPacket {
	method := http.MethodGet
	proto := "HTTP/1.1"
	headers := map[string][]string{}
	if request != nil {
		if request.Method != "" {
			method = request.Method
		}
		if request.Proto != "" {
			proto = request.Proto
		}
		headers = packetHeaders(request.Header)
		if request.Host != "" {
			headers["Host"] = []string{request.Host}
		}
	}
	return HTTPPacket{
		RequestLine:    method + " " + packetRequestTarget(request, path) + " " + proto,
		RequestHeaders: headers, SensitiveDataRedacted: false,
	}
}

func NewProxy(policy *boundary.Policy, options ProxyOptions) (*Proxy, error) {
	if policy == nil {
		return nil, errors.New("egress proxy policy is required")
	}
	if options.ClientHelloTimeout < 0 || options.MaxClientHello < 0 {
		return nil, errors.New("egress proxy limits must not be negative")
	}
	if err := ValidateTrafficLimits(&TrafficLimits{
		HTTPRequestsPerSecond:   options.HTTPRequestsPerSecond,
		TCPConnectionsPerSecond: options.TCPConnectionsPerSecond,
		UDPDatagramsPerSecond:   options.UDPDatagramsPerSecond,
	}); err != nil && (options.HTTPRequestsPerSecond != 0 || options.TCPConnectionsPerSecond != 0 || options.UDPDatagramsPerSecond != 0) {
		return nil, err
	}
	if options.UpstreamRoute != nil && options.Transport != nil {
		return nil, errors.New("egress upstream route cannot be combined with a custom HTTP transport")
	}
	authProfiles, err := authProfilesForPolicy(policy, options.AuthProfiles)
	if err != nil {
		return nil, err
	}
	if options.TLSInspection != nil {
		if err := validateTLSInspectionPolicy(options.TLSInspection); err != nil {
			return nil, err
		}
		if options.TLSAuthority == nil {
			return nil, errors.New("TLS inspection requires a conversation authority")
		}
	}
	if options.TrafficSink != nil && strings.TrimSpace(options.ConversationID) == "" {
		return nil, errors.New("traffic capture requires a conversation id")
	}
	baseDialContext := options.DialContext
	if baseDialContext == nil {
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		baseDialContext = dialer.DialContext
	}
	lookupNetIP := options.LookupNetIP
	if lookupNetIP == nil {
		lookupNetIP = net.DefaultResolver.LookupNetIP
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	dialContext := baseDialContext
	if options.UpstreamRoute != nil {
		upstream, err := newUpstreamDialer(*options.UpstreamRoute, baseDialContext, options.UpstreamTLSConfig, now)
		if err != nil {
			return nil, fmt.Errorf("configure egress upstream route: %w", err)
		}
		dialContext = upstream.DialContext
	}
	helloTimeout := options.ClientHelloTimeout
	if helloTimeout == 0 {
		helloTimeout = defaultClientHelloTimeout
	}
	maxHello := options.MaxClientHello
	if maxHello == 0 {
		maxHello = defaultMaxClientHello
	}
	proxy := &Proxy{
		policy: policy, dialContext: dialContext, lookupNetIP: lookupNetIP, transport: options.Transport, authProfiles: authProfiles, now: now,
		clientHelloTimeout: helloTimeout, maxClientHello: maxHello, activitySink: options.ActivitySink, guard: newRequestGuard(),
		tlsInspection: options.TLSInspection, tlsAuthority: options.TLSAuthority,
		httpPacer:          newTrafficPacer(options.HTTPRequestsPerSecond),
		tcpPacer:           newTrafficPacer(options.TCPConnectionsPerSecond),
		udpPacer:           newTrafficPacer(options.UDPDatagramsPerSecond),
		trafficSink:        options.TrafficSink,
		conversationID:     strings.TrimSpace(options.ConversationID),
		boundarySnapshotID: strings.TrimSpace(options.BoundarySnapshotID),
		upstreamRouteID:    strings.TrimSpace(options.UpstreamRouteID),
		runtimeMode:        traffic.NormalizeRuntimeMode(options.RuntimeMode),
		captureCoverage:    traffic.NormalizeCaptureCoverage(options.CaptureCoverage),
	}
	if proxy.transport == nil {
		proxy.transport = &http.Transport{
			Proxy: nil, DialContext: proxy.dialHTTPContext, ForceAttemptHTTP2: false,
			MaxIdleConns: 64, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second, ExpectContinueTimeout: time.Second,
		}
	}
	return proxy, nil
}

func authProfilesForPolicy(policy *boundary.Policy, document *AuthProfilesDocument) (map[string]GatewayAuthProfile, error) {
	if policy == nil {
		return nil, errors.New("egress proxy policy is required")
	}
	requiredProfiles := policy.AuthProfileIDs()
	profiles := make(map[string]GatewayAuthProfile, len(requiredProfiles))
	if len(requiredProfiles) == 0 {
		if document != nil {
			return nil, errors.New("egress auth profiles are not referenced by the boundary policy")
		}
		return profiles, nil
	}
	if document == nil {
		return nil, errors.New("egress auth profiles are required by the boundary policy")
	}
	copy := *document
	copy.Profiles = append([]GatewayAuthProfile(nil), document.Profiles...)
	if err := validateAuthProfilesDocument(&copy); err != nil {
		return nil, fmt.Errorf("configure egress auth profiles: %w", err)
	}
	profiles = copy.profileMap()
	if len(profiles) != len(requiredProfiles) {
		return nil, errors.New("egress auth profiles do not exactly match the boundary policy")
	}
	for _, id := range requiredProfiles {
		if _, ok := profiles[id]; !ok {
			return nil, fmt.Errorf("egress auth profile %q is missing", id)
		}
	}
	return profiles, nil
}

func (p *Proxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if p == nil || p.policy == nil || request == nil {
		http.Error(writer, "egress proxy unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := p.httpPacer.Wait(request.Context()); err != nil {
		http.Error(writer, "egress request canceled while waiting for the configured rate", http.StatusServiceUnavailable)
		return
	}
	if request.Method == http.MethodConnect {
		p.serveConnect(writer, request)
		return
	}
	p.serveForward(writer, request)
}

func (p *Proxy) serveForward(writer http.ResponseWriter, request *http.Request) {
	p.serveForwardRequest(writer, request, false)
}

func (p *Proxy) serveForwardRequest(writer http.ResponseWriter, request *http.Request, inspectedTLS bool) {
	if request.URL == nil || !request.URL.IsAbs() || request.URL.Scheme == "" || request.URL.Host == "" {
		http.Error(writer, "absolute HTTP proxy target required", http.StatusBadRequest)
		return
	}
	startedAt := p.now().UTC()
	attribution := consumeTrafficAttribution(request.Header)
	decision, err := p.policy.Evaluate(request.URL.String(), request.Method, nil, startedAt)
	if err != nil || (decision.Target.Scheme != "http" && (!inspectedTLS || decision.Target.Scheme != "https")) {
		http.Error(writer, "invalid HTTP proxy target", http.StatusBadRequest)
		return
	}
	requestType := ActivityRequestHTTP
	if inspectedTLS {
		requestType = ActivityRequestHTTPS
	}
	event := ActivityEvent{
		Timestamp: startedAt, RequestType: requestType,
		Domain: decision.Target.Host, Port: decision.Target.Port,
		Decision: ActivityDecisionBlocked, RuleID: decision.RuleID, Reason: decision.Reason,
		Method: request.Method, Path: activityHTTPPath(decision.Target.Path), Outcome: "rejected",
	}
	packet := newHTTPPacket(request, event.Path)
	event.HTTPPacket = &packet
	if request.ContentLength > 0 {
		event.BytesUp = request.ContentLength
	}
	dialObservation := &activityDialObservation{}
	defer func() {
		event.ResolvedIPs, event.ConnectedIP = dialObservation.snapshot()
		event.LatencyMS = activityLatencyMS(startedAt, p.now().UTC())
		emitActivity(p.activitySink, event)
	}()
	if !sameForwardAuthority(request.Host, decision.Target) {
		event.Outcome = "authority_mismatch"
		http.Error(writer, "HTTP Host does not match proxy target", http.StatusBadRequest)
		return
	}
	if isDNSOverHTTP(request, decision.Target.Path) {
		event.Outcome = "encrypted_dns_denied"
		headers, body := writeBoundaryDeniedResponse(writer, decision.Target.Host, "encrypted-dns-denied", decision.RuleID)
		captureSyntheticHTTPResponse(&packet, http.StatusForbidden, headers, body)
		event.HTTPStatus, event.BytesDown = http.StatusForbidden, int64(len(body))
		return
	}
	var authProfile *GatewayAuthProfile
	if decision.Effect == boundary.EffectAuthOnly {
		profile, ok := p.authProfiles[decision.AuthProfileID]
		if !decision.Allowed || !ok {
			event.Outcome = "auth_profile_unavailable"
			headers, body := writeBoundaryDeniedResponse(writer, decision.Target.Host, "auth-profile-unavailable", decision.RuleID)
			captureSyntheticHTTPResponse(&packet, http.StatusForbidden, headers, body)
			event.HTTPStatus, event.BytesDown = http.StatusForbidden, int64(len(body))
			return
		}
		authProfile = &profile
	} else if !proxyDecisionAllowed(decision) {
		event.Outcome = "policy_denied"
		headers, body := writeBoundaryDeniedResponse(writer, decision.Target.Host, decision.Reason, decision.RuleID)
		captureSyntheticHTTPResponse(&packet, http.StatusForbidden, headers, body)
		event.HTTPStatus, event.BytesDown = http.StatusForbidden, int64(len(body))
		return
	}
	event.Decision = ActivityDecisionAllowed
	event.Outcome = "upstream_failed"
	release, block, transition := p.guard.acquire(decision, startedAt)
	p.emitHealthTransition(decision, transition, startedAt)
	if block != nil {
		event.Decision = ActivityDecisionBlocked
		event.Reason = block.reason
		event.Outcome = block.outcome
		event.HTTPStatus = http.StatusTooManyRequests
		event.RetryAfterMS = block.retryAfterMS
		writeRateLimitResponse(writer, block.retryAfterMS)
		return
	}
	defer release()

	outbound := request.Clone(request.Context())
	outbound.RequestURI = ""
	outbound.URL = cloneURL(request.URL)
	canonicalAuthority := net.JoinHostPort(decision.Target.Host, strconv.Itoa(decision.Target.Port))
	outbound.URL.Scheme = decision.Target.Scheme
	outbound.URL.Host = canonicalAuthority
	outbound.URL.Path = decision.Target.Path
	outbound.URL.RawPath = ""
	outbound.Host = canonicalAuthority
	outbound = outbound.WithContext(context.WithValue(outbound.Context(), proxyDialContextKey{}, proxyDialAuthorization{
		rawURL: outbound.URL.String(), method: outbound.Method, target: decision.Target,
		ruleID: decision.RuleID, effect: decision.Effect, authProfileID: decision.AuthProfileID, observation: dialObservation,
	}))
	outbound.Header = request.Header.Clone()
	removeHopByHopHeaders(outbound.Header)
	outbound.Header.Del("Forwarded")
	outbound.Header.Del("X-Forwarded-For")
	outbound.Header.Del("X-Forwarded-Host")
	outbound.Header.Del("X-Forwarded-Proto")
	if authProfile != nil {
		applyAuthProfile(outbound.Header, *authProfile)
	}
	// From this point the packet projection mirrors the actual request sent to
	// the upstream, including any configured authentication profile and after
	// removing proxy-only/hop-by-hop headers.
	packet = newHTTPPacket(outbound, event.Path)
	requestCapture := &boundedPacketCapture{}
	fullRequestCapture := &fullBodyCapture{}
	if outbound.Body != nil {
		outbound.Body = &packetCaptureReadCloser{Reader: io.TeeReader(outbound.Body, io.MultiWriter(requestCapture, fullRequestCapture)), Closer: outbound.Body}
	}

	response, err := p.transport.RoundTrip(outbound)
	packet.RequestBody, packet.RequestBodyEncoding, packet.RequestBodyTruncated = requestCapture.snapshot(request.Header.Get("Content-Type"))
	if requestCapture.total > event.BytesUp {
		event.BytesUp = requestCapture.total
	}
	if err != nil {
		if denied, ok := resolvedPolicyDenial(err); ok {
			event.Decision = ActivityDecisionBlocked
			event.RuleID = denied.RuleID
			event.Reason = denied.Reason
			event.Outcome = "policy_denied_after_resolution"
			headers, body := writeBoundaryDeniedResponse(writer, decision.Target.Host, denied.Reason, denied.RuleID)
			captureSyntheticHTTPResponse(&packet, http.StatusForbidden, headers, body)
			event.HTTPStatus, event.BytesDown = http.StatusForbidden, int64(len(body))
			return
		}
		http.Error(writer, "upstream HTTP request failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	event.HTTPStatus = response.StatusCode
	event.Outcome = "completed"
	responseProtocol := response.Proto
	if responseProtocol == "" {
		responseProtocol = "HTTP/1.1"
	}
	responseStatus := strings.TrimSpace(response.Status)
	if responseStatus == "" {
		responseStatus = strconv.Itoa(response.StatusCode) + " " + http.StatusText(response.StatusCode)
	}
	packet.ResponseLine = responseProtocol + " " + responseStatus
	packet.ResponseHeaders = packetHeaders(response.Header)
	observedAt := p.now().UTC()
	p.emitHealthTransition(decision, p.guard.observeResponse(decision, outbound, response, observedAt), observedAt)
	responseHeaders := response.Header.Clone()
	removeHopByHopHeaders(responseHeaders)
	copyHeaders(writer.Header(), responseHeaders)
	writer.WriteHeader(response.StatusCode)
	responseCapture := &boundedPacketCapture{}
	fullResponseCapture := &fullBodyCapture{}
	written, copyErr := io.Copy(writer, io.TeeReader(response.Body, io.MultiWriter(responseCapture, fullResponseCapture)))
	event.BytesDown = written
	packet.ResponseBody, packet.ResponseBodyEncoding, packet.ResponseBodyTruncated = responseCapture.snapshot(response.Header.Get("Content-Type"))
	if copyErr != nil {
		event.Outcome = "response_interrupted"
	}
	completedAt := p.now().UTC()
	transactionID := uuid.NewString()
	redactHeader := ""
	if authProfile != nil {
		redactHeader = authProfile.HeaderName
	}
	requestProtocol := outbound.Proto
	if requestProtocol == "" {
		requestProtocol = "HTTP/1.1"
	}
	requestHeaders := trafficHeaders(outbound.Header, outbound.Host, redactHeader)
	responseHeadersForTraffic := trafficHeaders(response.Header, "", "")
	messages := []traffic.Message{
		fullRequestCapture.message(
			transactionID, traffic.StageUpstreamRequest, traffic.MessageKindRequest,
			outbound.Method, packetRequestTarget(outbound, event.Path), 0, requestProtocol,
			requestHeaders, startedAt,
		),
		fullResponseCapture.message(
			transactionID, traffic.StageUpstreamResponse, traffic.MessageKindResponse,
			"", "", response.StatusCode, responseProtocol,
			responseHeadersForTraffic, completedAt,
		),
	}
	transaction := traffic.Transaction{
		ID:                 transactionID,
		ConversationID:     p.conversationID,
		AgentID:            attribution.agentID,
		ExecutionID:        attribution.executionID,
		ToolCallID:         attribution.toolCallID,
		RuntimeMode:        p.runtimeMode,
		CaptureCoverage:    p.captureCoverage,
		Scheme:             decision.Target.Scheme,
		Host:               decision.Target.Host,
		Port:               decision.Target.Port,
		Method:             outbound.Method,
		Path:               packetRequestTarget(outbound, event.Path),
		HTTPStatus:         response.StatusCode,
		StartedAt:          startedAt,
		CompletedAt:        &completedAt,
		LatencyMS:          activityLatencyMS(startedAt, completedAt),
		BytesUp:            fullRequestCapture.total,
		BytesDown:          fullResponseCapture.total,
		BoundarySnapshotID: p.boundarySnapshotID,
		RuleID:             decision.RuleID,
		UpstreamRouteID:    p.upstreamRouteID,
	}
	emitTraffic(p.trafficSink, context.WithoutCancel(request.Context()), transaction, messages)
}

func (p *Proxy) serveConnect(writer http.ResponseWriter, request *http.Request) {
	startedAt := p.now().UTC()
	targetURL, targetAuthority, targetHost, targetPort, err := normalizeConnectTarget(request)
	if err != nil {
		http.Error(writer, "invalid CONNECT target", http.StatusBadRequest)
		return
	}
	attribution := consumeTrafficAttribution(request.Header)
	interceptTLS := p.shouldInterceptTLS(targetHost)
	decision := boundary.Decision{}
	if interceptTLS {
		target, normalizeErr := boundary.NormalizeRequestTarget(targetURL, http.MethodConnect)
		if normalizeErr != nil {
			writeBoundaryDeniedResponse(writer, targetHost, boundary.ReasonDefaultDeny, "")
			return
		}
		preflight, evaluateErr := p.policy.EvaluateDNS(targetHost, nil, startedAt)
		decision = boundary.Decision{Allowed: preflight.Allowed, Effect: preflight.Effect, RuleID: preflight.RuleID, Reason: preflight.Reason, Target: target}
		if evaluateErr != nil {
			writeBoundaryDeniedResponse(writer, targetHost, boundary.ReasonDefaultDeny, "")
			return
		}
	} else {
		var evaluateErr error
		decision, evaluateErr = p.policy.Evaluate(targetURL, http.MethodConnect, nil, startedAt)
		if evaluateErr != nil {
			writeBoundaryDeniedResponse(writer, targetHost, boundary.ReasonDefaultDeny, "")
			return
		}
	}
	event := ActivityEvent{
		Timestamp: startedAt, RequestType: ActivityRequestCONNECT,
		Domain: targetHost, Port: targetPort, Decision: ActivityDecisionBlocked,
		RuleID: decision.RuleID, Reason: decision.Reason, Outcome: "policy_denied",
	}
	dialObservation := &activityDialObservation{}
	defer func() {
		completedAt := p.now().UTC()
		event.ResolvedIPs, event.ConnectedIP = dialObservation.snapshot()
		event.LatencyMS = activityLatencyMS(startedAt, completedAt)
		emitActivity(p.activitySink, event)
		if !interceptTLS && event.Decision == ActivityDecisionAllowed && event.Outcome == "tunnel_closed" {
			transaction, messages := p.connectTrafficEvidence(
				request, attribution, targetAuthority, targetHost, targetPort, event, startedAt, completedAt,
			)
			emitTraffic(p.trafficSink, context.WithoutCancel(request.Context()), transaction, messages)
		}
	}()
	if !decision.Allowed || (!interceptTLS && !proxyDecisionAllowed(decision)) {
		writeBoundaryDeniedResponse(writer, targetHost, decision.Reason, decision.RuleID)
		return
	}
	event.Decision = ActivityDecisionAllowed
	event.Outcome = "tunnel_unavailable"
	if !interceptTLS {
		release, block, transition := p.guard.acquire(decision, startedAt)
		p.emitHealthTransition(decision, transition, startedAt)
		if block != nil {
			event.Decision = ActivityDecisionBlocked
			event.Reason = block.reason
			event.Outcome = block.outcome
			event.RetryAfterMS = block.retryAfterMS
			writeRateLimitResponse(writer, block.retryAfterMS)
			return
		}
		defer release()
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		event.Outcome = "hijack_unavailable"
		http.Error(writer, "CONNECT tunneling unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		event.Outcome = "hijack_failed"
		return
	}
	defer client.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		event.Outcome = "client_write_failed"
		return
	}
	if err := buffered.Flush(); err != nil {
		event.Outcome = "client_write_failed"
		return
	}
	if err := client.SetReadDeadline(time.Now().Add(p.clientHelloTimeout)); err != nil {
		event.Outcome = "client_deadline_failed"
		return
	}
	clientHello, serverName, err := readClientHelloSNI(buffered.Reader, p.maxClientHello)
	if err != nil || serverName != targetHost {
		event.Outcome = "sni_mismatch"
		return
	}
	if err := client.SetReadDeadline(time.Time{}); err != nil {
		event.Outcome = "client_deadline_failed"
		return
	}
	sniURL := (&url.URL{Scheme: "https", Host: targetAuthority, Path: "/"}).String()
	if interceptTLS {
		event.Outcome = "tls_inspection_failed"
		if err := p.serveInterceptedTLS(client, buffered.Reader, clientHello, targetAuthority, targetHost); err != nil {
			return
		}
		event.Outcome = "tls_inspection_closed"
		return
	}
	sniDecision, err := p.policy.Evaluate(sniURL, http.MethodConnect, nil, p.now().UTC())
	if err != nil || !proxyDecisionAllowed(sniDecision) || sniDecision.Target.Host != serverName || sniDecision.Target.Port != targetPort {
		event.Decision = ActivityDecisionBlocked
		event.Outcome = "sni_policy_denied"
		if err == nil {
			event.RuleID = sniDecision.RuleID
			event.Reason = sniDecision.Reason
		}
		return
	}
	event.RuleID = sniDecision.RuleID
	event.Reason = sniDecision.Reason

	upstream, err := p.dialAuthorized(request.Context(), proxyDialAuthorization{
		rawURL: sniURL, method: http.MethodConnect, target: sniDecision.Target,
		ruleID: sniDecision.RuleID, effect: sniDecision.Effect, observation: dialObservation,
	}, targetHost, targetPort)
	if err != nil {
		if denied, ok := resolvedPolicyDenial(err); ok {
			event.Decision = ActivityDecisionBlocked
			event.RuleID = denied.RuleID
			event.Reason = denied.Reason
			event.Outcome = "policy_denied_after_resolution"
		} else {
			event.Outcome = "upstream_failed"
		}
		return
	}
	defer upstream.Close()
	if err := writeAll(upstream, clientHello); err != nil {
		event.Outcome = "upstream_write_failed"
		return
	}
	event.BytesUp = int64(len(clientHello))
	uploaded, downloaded := tunnelConnections(client, buffered.Reader, upstream)
	event.BytesUp += uploaded
	event.BytesDown = downloaded
	event.Outcome = "tunnel_closed"
}

// connectTrafficEvidence records the complete CONNECT control exchange and
// encrypted tunnel byte counts. It intentionally does not represent TLS
// ciphertext as decoded HTTP. Once TLS inspection is enabled, the normal
// forward path records the decrypted HTTPS request and response instead.
func (p *Proxy) connectTrafficEvidence(
	request *http.Request,
	attribution trafficAttribution,
	authority, host string,
	port int,
	event ActivityEvent,
	startedAt, completedAt time.Time,
) (traffic.Transaction, []traffic.Message) {
	transactionID := uuid.NewString()
	protocol := strings.TrimSpace(request.Proto)
	if protocol == "" {
		protocol = "HTTP/1.1"
	}
	empty := &fullBodyCapture{}
	messages := []traffic.Message{
		empty.message(
			transactionID, traffic.StageClientRequest, traffic.MessageKindRequest,
			http.MethodConnect, "/", 0, protocol,
			trafficHeaders(request.Header, authority, ""), startedAt,
		),
		empty.message(
			transactionID, traffic.StageClientResponse, traffic.MessageKindResponse,
			"", "", http.StatusOK, "HTTP/1.1", nil, completedAt,
		),
	}
	return traffic.Transaction{
		ID:                 transactionID,
		ConversationID:     p.conversationID,
		AgentID:            attribution.agentID,
		ExecutionID:        attribution.executionID,
		ToolCallID:         attribution.toolCallID,
		RuntimeMode:        p.runtimeMode,
		CaptureCoverage:    p.captureCoverage,
		Scheme:             "https",
		Host:               host,
		Port:               port,
		Method:             http.MethodConnect,
		Path:               "/",
		HTTPStatus:         http.StatusOK,
		StartedAt:          startedAt,
		CompletedAt:        &completedAt,
		LatencyMS:          event.LatencyMS,
		BytesUp:            event.BytesUp,
		BytesDown:          event.BytesDown,
		BoundarySnapshotID: p.boundarySnapshotID,
		RuleID:             event.RuleID,
		UpstreamRouteID:    p.upstreamRouteID,
	}, messages
}

func (p *Proxy) shouldInterceptTLS(host string) bool {
	if p == nil || p.tlsInspection == nil || !p.tlsInspection.Enabled || p.tlsAuthority == nil {
		return false
	}
	for _, bypass := range p.tlsInspection.BypassDomains {
		if host == bypass || strings.HasSuffix(host, "."+bypass) {
			return false
		}
	}
	return true
}

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (connection *replayConn) Read(content []byte) (int, error) {
	return connection.reader.Read(content)
}

type interceptedResponseWriter struct {
	writer      *bufio.Writer
	header      http.Header
	wroteHeader bool
}

func (writer *interceptedResponseWriter) Header() http.Header { return writer.header }

func (writer *interceptedResponseWriter) WriteHeader(status int) {
	if writer.wroteHeader {
		return
	}
	writer.wroteHeader = true
	removeHopByHopHeaders(writer.header)
	writer.header.Set("Connection", "close")
	_, _ = fmt.Fprintf(writer.writer, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	_ = writer.header.Write(writer.writer)
	_, _ = io.WriteString(writer.writer, "\r\n")
}

func (writer *interceptedResponseWriter) Write(content []byte) (int, error) {
	if !writer.wroteHeader {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.writer.Write(content)
}

func (p *Proxy) serveInterceptedTLS(client net.Conn, buffered *bufio.Reader, clientHello []byte, authority, host string) error {
	leafDER, leafKey, err := p.tlsAuthority.leafCertificate(host, p.now().UTC())
	if err != nil {
		return err
	}
	replayed := &replayConn{Conn: client, reader: io.MultiReader(bytes.NewReader(clientHello), buffered)}
	tlsClient := tls.Server(replayed, &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafDER, p.tlsAuthority.Certificate.Raw}, PrivateKey: leafKey,
		}},
	})
	if err := tlsClient.Handshake(); err != nil {
		return fmt.Errorf("complete inspected TLS handshake: %w", err)
	}
	request, err := http.ReadRequest(bufio.NewReader(tlsClient))
	if err != nil {
		return fmt.Errorf("read inspected HTTPS request: %w", err)
	}
	defer request.Body.Close()
	request.URL.Scheme = "https"
	request.URL.Host = authority
	response := &interceptedResponseWriter{writer: bufio.NewWriter(tlsClient), header: make(http.Header)}
	p.serveForwardRequest(response, request, true)
	if !response.wroteHeader {
		response.WriteHeader(http.StatusNoContent)
	}
	if err := response.writer.Flush(); err != nil {
		return fmt.Errorf("flush inspected HTTPS response: %w", err)
	}
	if err := tlsClient.Close(); err != nil {
		return fmt.Errorf("close inspected HTTPS response: %w", err)
	}
	return nil
}

type proxyDialContextKey struct{}

type proxyDialAuthorization struct {
	rawURL        string
	method        string
	target        boundary.RequestTarget
	ruleID        string
	effect        boundary.Effect
	authProfileID string
	observation   *activityDialObservation
}

type resolvedPolicyDenialError struct {
	decision boundary.Decision
}

func (e *resolvedPolicyDenialError) Error() string {
	return "resolved egress target denied by boundary policy"
}

func resolvedPolicyDenial(err error) (boundary.Decision, bool) {
	var denied *resolvedPolicyDenialError
	if !errors.As(err, &denied) || denied == nil {
		return boundary.Decision{}, false
	}
	return denied.decision, true
}

type activityDialObservation struct {
	mu          sync.Mutex
	resolvedIPs []string
	connectedIP string
}

func (o *activityDialObservation) recordResolution(addresses []netip.Addr) {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.resolvedIPs = activityIPStrings(addresses)
	o.mu.Unlock()
}

func (o *activityDialObservation) recordConnection(address netip.Addr) {
	if o == nil || !address.IsValid() {
		return
	}
	o.mu.Lock()
	o.connectedIP = address.Unmap().String()
	o.mu.Unlock()
}

func (o *activityDialObservation) snapshot() ([]string, string) {
	if o == nil {
		return nil, ""
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.resolvedIPs...), o.connectedIP
}

func (p *Proxy) dialHTTPContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("egress proxy rejected network %q", network)
	}
	authorization, ok := ctx.Value(proxyDialContextKey{}).(proxyDialAuthorization)
	if !ok {
		return nil, errors.New("egress proxy dial authorization is missing")
	}
	host, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse authorized HTTP dial address: %w", err)
	}
	host, err = boundary.NormalizeHost(host)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || host != authorization.target.Host || port != authorization.target.Port {
		return nil, errors.New("HTTP transport dial target changed after authorization")
	}
	return p.dialAuthorized(ctx, authorization, host, port)
}

func (p *Proxy) dialAuthorized(ctx context.Context, authorization proxyDialAuthorization, host string, port int) (net.Conn, error) {
	addresses := make([]netip.Addr, 0, 4)
	if address, err := netip.ParseAddr(host); err == nil {
		addresses = append(addresses, address.Unmap())
	} else {
		resolved, lookupErr := p.lookupNetIP(ctx, "ip", host)
		if lookupErr != nil {
			return nil, fmt.Errorf("resolve authorized egress host: %w", lookupErr)
		}
		if len(resolved) == 0 || len(resolved) > 64 {
			return nil, errors.New("authorized egress host returned an invalid address count")
		}
		seen := make(map[netip.Addr]struct{}, len(resolved))
		for _, address := range resolved {
			address = address.Unmap()
			if _, duplicate := seen[address]; duplicate {
				continue
			}
			seen[address] = struct{}{}
			addresses = append(addresses, address)
		}
	}
	authorization.observation.recordResolution(addresses)
	decision, err := p.policy.Evaluate(authorization.rawURL, authorization.method, addresses, p.now().UTC())
	if err != nil {
		return nil, fmt.Errorf("re-evaluate resolved egress target: %w", err)
	}
	if !decision.Allowed {
		return nil, &resolvedPolicyDenialError{decision: decision}
	}
	if decision.RuleID != authorization.ruleID || decision.Effect != authorization.effect || decision.AuthProfileID != authorization.authProfileID ||
		(decision.Effect == boundary.EffectAuthOnly && p.authProfiles[decision.AuthProfileID].ID == "") ||
		(decision.Effect != boundary.EffectAuthOnly && !proxyDecisionAllowed(decision)) {
		return nil, errors.New("resolved egress target failed policy re-evaluation")
	}
	var lastErr error
	for _, address := range addresses {
		if !address.IsValid() || address.Zone() != "" {
			return nil, errors.New("resolver returned an invalid egress address")
		}
		connection, dialErr := p.dialContext(ctx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(port)))
		if dialErr == nil {
			authorization.observation.recordConnection(address)
			return connection, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("authorized egress host has no usable address")
	}
	return nil, fmt.Errorf("dial authorized egress address: %w", lastErr)
}

// RecoverHealth is invoked only by the trusted gateway signal listener. Agent
// traffic cannot reach this control path through the data-plane proxy.
func (p *Proxy) RecoverHealth() {
	if p != nil {
		p.guard.recover()
	}
}

func (p *Proxy) emitHealthTransition(decision boundary.Decision, transition *requestGuardTransition, now time.Time) {
	if p == nil || transition == nil {
		return
	}
	activityDecision := ActivityDecisionBlocked
	if transition.outcome == "cooldown_expired" {
		activityDecision = ActivityDecisionAllowed
	}
	emitActivity(p.activitySink, ActivityEvent{
		Timestamp: now.UTC(), RequestType: ActivityRequestHealth,
		Domain: decision.Target.Host, Decision: activityDecision,
		RuleID: decision.RuleID, Reason: transition.reason,
		Outcome: transition.outcome, RetryAfterMS: transition.retryAfterMS,
	})
}

func writeRateLimitResponse(writer http.ResponseWriter, retryAfterMS int64) {
	seconds := int64(1)
	if retryAfterMS > 0 {
		seconds = (retryAfterMS + 999) / 1000
	}
	writer.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	http.Error(writer, "egress request temporarily limited", http.StatusTooManyRequests)
}

// writeBoundaryDeniedResponse gives command-line tools and the Agent a stable,
// explicit explanation instead of an ambiguous transport failure. It only
// includes the normalized host and policy metadata; paths, queries, headers,
// request bodies and credentials are deliberately excluded.
func writeBoundaryDeniedResponse(writer http.ResponseWriter, host, reason, ruleID string) (http.Header, string) {
	host = safeBoundaryResponseValue(host, "the requested website")
	reason = safeBoundaryResponseValue(reason, boundary.ReasonDefaultDeny)
	ruleID = safeBoundaryResponseValue(ruleID, "default-deny")
	body := fmt.Sprintf(
		"CyberStrikeAI network boundary blocked access to %s (reason: %s; rule: %s). The request was not sent to the website.\nCyberStrikeAI 出站边界已禁止访问该网站（目标：%s；原因：%s；规则：%s），请求未发送到目标站点。\n",
		host, reason, ruleID, host, reason, ruleID)
	headers := http.Header{
		"Content-Type":                 {"text/plain; charset=utf-8"},
		"Content-Length":               {strconv.Itoa(len(body))},
		"Cache-Control":                {"no-store"},
		"X-CyberStrikeAI-Blocked":      {"true"},
		"X-CyberStrikeAI-Block-Reason": {reason},
		"X-CyberStrikeAI-Block-Rule":   {ruleID},
		"Proxy-Status":                 {`CyberStrikeAI; error="policy_denied"`},
	}
	copyHeaders(writer.Header(), headers)
	writer.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(writer, body)
	return headers, body
}

func captureSyntheticHTTPResponse(packet *HTTPPacket, status int, headers http.Header, body string) {
	if packet == nil {
		return
	}
	packet.ResponseLine = "HTTP/1.1 " + strconv.Itoa(status) + " " + http.StatusText(status)
	packet.ResponseHeaders = packetHeaders(headers)
	capture := &boundedPacketCapture{}
	_, _ = capture.Write([]byte(body))
	packet.ResponseBody, packet.ResponseBodyEncoding, packet.ResponseBodyTruncated = capture.snapshot(headers.Get("Content-Type"))
}

func safeBoundaryResponseValue(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\r\n\x00") {
		return fallback
	}
	return value
}

func normalizeConnectTarget(request *http.Request) (rawURL, authority, host string, port int, err error) {
	if request == nil || request.URL == nil || request.Host == "" || request.RequestURI != request.Host || strings.ContainsAny(request.Host, "/?#@") {
		return "", "", "", 0, boundary.ErrInvalidTarget
	}
	rawHost, rawPort, splitErr := net.SplitHostPort(request.Host)
	if splitErr != nil || rawPort == "" {
		return "", "", "", 0, boundary.ErrInvalidTarget
	}
	host, err = boundary.NormalizeHost(rawHost)
	if err != nil {
		return "", "", "", 0, err
	}
	port, err = strconv.Atoi(rawPort)
	if err != nil {
		return "", "", "", 0, boundary.ErrInvalidTarget
	}
	port, err = boundary.NormalizePort("https", port)
	if err != nil {
		return "", "", "", 0, err
	}
	authority = net.JoinHostPort(host, strconv.Itoa(port))
	rawURL = (&url.URL{Scheme: "https", Host: authority, Path: "/"}).String()
	return rawURL, authority, host, port, nil
}

func proxyDecisionAllowed(decision boundary.Decision) bool {
	return decision.Allowed && (decision.Effect == boundary.EffectAllowVisit || decision.Effect == boundary.EffectAllowAttack)
}

func isDNSOverHTTP(request *http.Request, canonicalPath string) bool {
	path := strings.TrimSuffix(canonicalPath, "/")
	if path == "/dns-query" || strings.HasSuffix(path, "/dns-query") {
		return true
	}
	for _, header := range []string{"Content-Type", "Accept"} {
		for _, value := range request.Header.Values(header) {
			for _, candidate := range strings.Split(value, ",") {
				mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(candidate))
				if err == nil && (strings.EqualFold(mediaType, "application/dns-message") || strings.EqualFold(mediaType, "application/dns-json")) {
					return true
				}
			}
		}
	}
	return false
}

func sameForwardAuthority(hostHeader string, target boundary.RequestTarget) bool {
	if strings.TrimSpace(hostHeader) == "" {
		return false
	}
	comparison, err := boundary.NormalizeRequestTarget(target.Scheme+"://"+hostHeader+"/", http.MethodGet)
	return err == nil && comparison.Host == target.Host && comparison.Port == target.Port
}

func cloneURL(input *url.URL) *url.URL {
	if input == nil {
		return nil
	}
	copy := *input
	return &copy
}

func removeHopByHopHeaders(header http.Header) {
	for _, connectionHeader := range []string{"Connection", "Proxy-Connection"} {
		for _, value := range header.Values(connectionHeader) {
			for _, token := range strings.Split(value, ",") {
				header.Del(strings.TrimSpace(token))
			}
		}
	}
	for _, key := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(key)
	}
}

func copyHeaders(target, source http.Header) {
	for key, values := range source {
		for _, value := range values {
			target.Add(key, value)
		}
	}
}

func writeAll(writer io.Writer, content []byte) error {
	for len(content) != 0 {
		written, err := writer.Write(content)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(content) {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

func tunnelConnections(client net.Conn, clientReader *bufio.Reader, upstream net.Conn) (uploaded, downloaded int64) {
	type copyResult struct {
		direction string
		bytes     int64
	}
	done := make(chan copyResult, 2)
	go func() {
		count, _ := io.Copy(upstream, clientReader)
		done <- copyResult{direction: "up", bytes: count}
	}()
	go func() {
		count, _ := io.Copy(client, upstream)
		done <- copyResult{direction: "down", bytes: count}
	}()
	first := <-done
	_ = client.Close()
	_ = upstream.Close()
	second := <-done
	for _, result := range []copyResult{first, second} {
		if result.direction == "up" {
			uploaded = result.bytes
		} else {
			downloaded = result.bytes
		}
	}
	return uploaded, downloaded
}
