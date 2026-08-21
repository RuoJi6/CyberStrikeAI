package egress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cyberstrike-ai/internal/boundary"
)

const (
	DefaultProxyListenAddress = "0.0.0.0:3128"
	defaultClientHelloTimeout = 5 * time.Second
)

type DialContextFunc func(context.Context, string, string) (net.Conn, error)
type LookupNetIPFunc func(context.Context, string, string) ([]netip.Addr, error)

type ProxyOptions struct {
	DialContext        DialContextFunc
	LookupNetIP        LookupNetIPFunc
	Transport          http.RoundTripper
	Now                func() time.Time
	ClientHelloTimeout time.Duration
	MaxClientHello     int
}

// Proxy is the policy-enforcing HTTP forward proxy and HTTPS CONNECT tunnel.
// It never accepts policy input from a request: the immutable compiled policy
// is loaded once from the gateway's read-only snapshot.
type Proxy struct {
	policy             *boundary.Policy
	dialContext        DialContextFunc
	lookupNetIP        LookupNetIPFunc
	transport          http.RoundTripper
	now                func() time.Time
	clientHelloTimeout time.Duration
	maxClientHello     int
}

func NewProxy(policy *boundary.Policy, options ProxyOptions) (*Proxy, error) {
	if policy == nil {
		return nil, errors.New("egress proxy policy is required")
	}
	if options.ClientHelloTimeout < 0 || options.MaxClientHello < 0 {
		return nil, errors.New("egress proxy limits must not be negative")
	}
	dialContext := options.DialContext
	if dialContext == nil {
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		dialContext = dialer.DialContext
	}
	lookupNetIP := options.LookupNetIP
	if lookupNetIP == nil {
		lookupNetIP = net.DefaultResolver.LookupNetIP
	}
	now := options.Now
	if now == nil {
		now = time.Now
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
		policy: policy, dialContext: dialContext, lookupNetIP: lookupNetIP, transport: options.Transport, now: now,
		clientHelloTimeout: helloTimeout, maxClientHello: maxHello,
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

func (p *Proxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if p == nil || p.policy == nil || request == nil {
		http.Error(writer, "egress proxy unavailable", http.StatusServiceUnavailable)
		return
	}
	if request.Method == http.MethodConnect {
		p.serveConnect(writer, request)
		return
	}
	p.serveForward(writer, request)
}

func (p *Proxy) serveForward(writer http.ResponseWriter, request *http.Request) {
	if request.URL == nil || !request.URL.IsAbs() || request.URL.Scheme == "" || request.URL.Host == "" {
		http.Error(writer, "absolute HTTP proxy target required", http.StatusBadRequest)
		return
	}
	decision, err := p.policy.Evaluate(request.URL.String(), request.Method, nil, p.now().UTC())
	if err != nil || decision.Target.Scheme != "http" {
		http.Error(writer, "invalid HTTP proxy target", http.StatusBadRequest)
		return
	}
	if !sameForwardAuthority(request.Host, decision.Target) {
		http.Error(writer, "HTTP Host does not match proxy target", http.StatusBadRequest)
		return
	}
	if !proxyDecisionAllowed(decision) {
		http.Error(writer, "egress policy denied request", http.StatusForbidden)
		return
	}

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
	}))
	outbound.Header = request.Header.Clone()
	removeHopByHopHeaders(outbound.Header)
	outbound.Header.Del("Forwarded")
	outbound.Header.Del("X-Forwarded-For")
	outbound.Header.Del("X-Forwarded-Host")
	outbound.Header.Del("X-Forwarded-Proto")

	response, err := p.transport.RoundTrip(outbound)
	if err != nil {
		http.Error(writer, "upstream HTTP request failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	responseHeaders := response.Header.Clone()
	removeHopByHopHeaders(responseHeaders)
	copyHeaders(writer.Header(), responseHeaders)
	writer.WriteHeader(response.StatusCode)
	_, _ = io.Copy(writer, response.Body)
}

func (p *Proxy) serveConnect(writer http.ResponseWriter, request *http.Request) {
	targetURL, targetAuthority, targetHost, targetPort, err := normalizeConnectTarget(request)
	if err != nil {
		http.Error(writer, "invalid CONNECT target", http.StatusBadRequest)
		return
	}
	decision, err := p.policy.Evaluate(targetURL, http.MethodConnect, nil, p.now().UTC())
	if err != nil || !proxyDecisionAllowed(decision) {
		http.Error(writer, "egress policy denied CONNECT", http.StatusForbidden)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		http.Error(writer, "CONNECT tunneling unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	if err := client.SetReadDeadline(time.Now().Add(p.clientHelloTimeout)); err != nil {
		return
	}
	clientHello, serverName, err := readClientHelloSNI(buffered.Reader, p.maxClientHello)
	if err != nil || serverName != targetHost {
		return
	}
	if err := client.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	sniURL := (&url.URL{Scheme: "https", Host: targetAuthority, Path: "/"}).String()
	sniDecision, err := p.policy.Evaluate(sniURL, http.MethodConnect, nil, p.now().UTC())
	if err != nil || !proxyDecisionAllowed(sniDecision) || sniDecision.Target.Host != serverName || sniDecision.Target.Port != targetPort {
		return
	}

	upstream, err := p.dialAuthorized(request.Context(), sniURL, http.MethodConnect, targetHost, targetPort)
	if err != nil {
		return
	}
	defer upstream.Close()
	if err := writeAll(upstream, clientHello); err != nil {
		return
	}
	tunnelConnections(client, buffered.Reader, upstream)
}

type proxyDialContextKey struct{}

type proxyDialAuthorization struct {
	rawURL string
	method string
	target boundary.RequestTarget
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
	return p.dialAuthorized(ctx, authorization.rawURL, authorization.method, host, port)
}

func (p *Proxy) dialAuthorized(ctx context.Context, rawURL, method, host string, port int) (net.Conn, error) {
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
	decision, err := p.policy.Evaluate(rawURL, method, addresses, p.now().UTC())
	if err != nil || !proxyDecisionAllowed(decision) {
		return nil, errors.New("resolved egress target failed policy re-evaluation")
	}
	var lastErr error
	for _, address := range addresses {
		if !address.IsValid() || address.Zone() != "" {
			return nil, errors.New("resolver returned an invalid egress address")
		}
		connection, dialErr := p.dialContext(ctx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(port)))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("authorized egress host has no usable address")
	}
	return nil, fmt.Errorf("dial authorized egress address: %w", lastErr)
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

func tunnelConnections(client net.Conn, clientReader *bufio.Reader, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, clientReader)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}
