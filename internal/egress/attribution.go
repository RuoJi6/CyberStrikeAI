package egress

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/networkprovenance"
)

const attributionProxyUsername = "cyberstrike"

var errAttributionRequired = errors.New("network provenance is required")

func (p *Proxy) authorizeAttribution(request *http.Request) (*http.Request, networkprovenance.NetworkProvenanceV1, error) {
	expected := p.attributionAudience
	if expected.ConversationID == "" {
		expected.ConversationID = p.conversationID
	}
	if expected.RuntimeMode == "" {
		expected.RuntimeMode = p.provenanceRuntimeMode()
	}
	legacy := networkprovenance.ForAudience(expected, networkprovenance.AttributionLegacyUnattributed)
	if request == nil {
		return request, legacy, nil
	}
	stripLegacyAttributionHeaders(request.Header)
	rawAuth := request.Header.Get("Proxy-Authorization")
	request.Header.Del("Proxy-Authorization")
	if p.attributionVerifier == nil {
		return request.WithContext(networkprovenance.WithContext(request.Context(), legacy)), legacy, nil
	}
	username, token, ok := parseAttributionBasicAuth(rawAuth)
	if !ok || username != attributionProxyUsername {
		invalid := networkprovenance.ForAudience(expected, networkprovenance.AttributionInvalid)
		return request.WithContext(networkprovenance.WithContext(request.Context(), invalid)), invalid, errAttributionRequired
	}
	provenance, err := p.attributionVerifier.Verify(token, p.attributionAudience)
	if err != nil {
		invalid := networkprovenance.ForAudience(expected, networkprovenance.AttributionInvalid)
		return request.WithContext(networkprovenance.WithContext(request.Context(), invalid)), invalid, errAttributionRequired
	}
	return request.WithContext(networkprovenance.WithContext(request.Context(), provenance)), provenance, nil
}

func (p *Proxy) provenanceRuntimeMode() string {
	if p == nil {
		return ""
	}
	if p.runtimeMode == "container" {
		return networkprovenance.RuntimeModeContainer
	}
	return networkprovenance.RuntimeModeHostMITM
}

func stripLegacyAttributionHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	for _, name := range []string{trafficAgentIDHeader, trafficExecutionIDHeader, trafficToolCallIDHeader} {
		headers.Del(name)
	}
}

func parseAttributionBasicAuth(value string) (username, token string, ok bool) {
	scheme, encoded, found := strings.Cut(strings.TrimSpace(value), " ")
	if !found || !strings.EqualFold(scheme, "Basic") || encoded == "" {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", "", false
	}
	username, token, ok = strings.Cut(string(decoded), ":")
	return strings.TrimSpace(username), strings.TrimSpace(token), ok && token != ""
}

func attributionTarget(request *http.Request) (requestType, domain string, port int) {
	requestType = ActivityRequestHTTP
	if request == nil {
		return requestType, "", 0
	}
	if request.Method == http.MethodConnect {
		requestType = ActivityRequestCONNECT
	}
	host := request.Host
	if request.URL != nil && request.URL.Host != "" {
		host = request.URL.Host
		if strings.EqualFold(request.URL.Scheme, "https") {
			requestType = ActivityRequestHTTPS
		}
	}
	parsed := &url.URL{Host: host}
	domain = strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if rawPort := parsed.Port(); rawPort != "" {
		if value, err := strconv.Atoi(rawPort); err == nil && value > 0 && value <= 65535 {
			port = value
		}
	}
	if port == 0 {
		if requestType == ActivityRequestHTTPS || requestType == ActivityRequestCONNECT {
			port = 443
		} else {
			port = 80
		}
	}
	return requestType, domain, port
}
