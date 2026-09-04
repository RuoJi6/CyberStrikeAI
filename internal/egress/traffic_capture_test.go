package egress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
	"cyberstrike-ai/internal/networkprovenance"
	"cyberstrike-ai/internal/traffic"
	"github.com/andybalholm/brotli"
)

func TestProxyCapturesCompleteTrafficAndConsumesAttributionHeaders(t *testing.T) {
	policy := testProxyPolicy(t, boundary.Rule{
		ID: "capture", Effect: boundary.EffectAllowAttack,
		Target: boundary.RuleTarget{Host: "capture.example", Schemes: []string{"http"}, Methods: []string{"POST"}},
	})
	var captured traffic.Transaction
	var messages []traffic.Message
	proxy, err := NewProxy(policy, ProxyOptions{
		ConversationID:     "conversation-1",
		BoundarySnapshotID: "snapshot-1",
		RuntimeMode:        traffic.RuntimeModeContainer,
		CaptureCoverage:    traffic.CaptureCoverageEnforced,
		TrafficSink: func(_ context.Context, item traffic.Transaction, capturedMessages []traffic.Message) error {
			captured = item
			messages = append([]traffic.Message(nil), capturedMessages...)
			return nil
		},
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Header.Get(trafficAgentIDHeader) != "" || request.Header.Get(trafficExecutionIDHeader) != "" || request.Header.Get(trafficToolCallIDHeader) != "" {
				t.Fatalf("attribution headers reached upstream: %#v", request.Header)
			}
			content, readErr := io.ReadAll(request.Body)
			if readErr != nil || !bytes.Equal(content, []byte{0, 1, 2, 3}) {
				t.Fatalf("upstream body = %v / %v", content, readErr)
			}
			return &http.Response{
				StatusCode: http.StatusCreated,
				Status:     "201 Created",
				Proto:      "HTTP/1.1",
				Header:     http.Header{"Content-Type": {"application/octet-stream"}, "X-Reply": {"one", "two"}},
				Body:       io.NopCloser(bytes.NewReader([]byte{4, 5, 0, 255})),
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://capture.example/api?item=1", bytes.NewReader([]byte{0, 1, 2, 3}))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set(trafficAgentIDHeader, "agent-1")
	request.Header.Set(trafficExecutionIDHeader, "execution-1")
	request.Header.Set(trafficToolCallIDHeader, "tool-1")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || !bytes.Equal(recorder.Body.Bytes(), []byte{4, 5, 0, 255}) {
		t.Fatalf("response = %d / %v", recorder.Code, recorder.Body.Bytes())
	}
	if captured.ID == "" || captured.ConversationID != "conversation-1" || captured.AgentID != "" || captured.ExecutionID != "" || captured.ToolCallID != "" || captured.AttributionStatus != networkprovenance.AttributionLegacyUnattributed || captured.Path != "/api?item=1" || captured.HTTPStatus != http.StatusCreated || captured.BoundarySnapshotID != "snapshot-1" || captured.RuleID != "capture" {
		t.Fatalf("captured transaction = %#v", captured)
	}
	if len(messages) != 2 || messages[0].Stage != traffic.StageUpstreamRequest || messages[1].Stage != traffic.StageUpstreamResponse {
		t.Fatalf("captured messages = %#v", messages)
	}
	requestBody, requestErr := traffic.DecodeBody(messages[0])
	responseBody, responseErr := traffic.DecodeBody(messages[1])
	if requestErr != nil || responseErr != nil || !bytes.Equal(requestBody, []byte{0, 1, 2, 3}) || !bytes.Equal(responseBody, []byte{4, 5, 0, 255}) || !messages[0].Complete || !messages[1].Complete {
		t.Fatalf("captured bodies = %v / %v / %v / %v", requestBody, responseBody, requestErr, responseErr)
	}
	for _, message := range messages {
		if err := traffic.ValidateMessage(message); err != nil {
			t.Fatalf("ValidateMessage(%s): %v", message.Stage, err)
		}
	}
}

func TestFullBodyCaptureTruncatesWithExplicitLengths(t *testing.T) {
	capture := &fullBodyCapture{}
	raw := bytes.Repeat([]byte{0xaa}, traffic.MaxStoredBodyBytes+17)
	if written, err := capture.Write(raw); err != nil || written != len(raw) {
		t.Fatalf("Write = %d / %v", written, err)
	}
	message := capture.message("transaction", traffic.StageUpstreamResponse, traffic.MessageKindResponse, "", "", 200, "HTTP/1.1", nil, time.Now().UTC())
	if message.Complete || message.BodyLength != int64(len(raw)) || message.BodyStoredBytes != traffic.MaxStoredBodyBytes {
		t.Fatalf("truncated message = %#v", message)
	}
	if err := traffic.ValidateMessage(message); err != nil {
		t.Fatalf("ValidateMessage: %v", err)
	}
}

func TestProxyKeepsCompressedWireEvidenceAndDisplaysDecodedPacket(t *testing.T) {
	var compressed bytes.Buffer
	compressor := brotli.NewWriter(&compressed)
	want := []byte("<html><body>readable complete response</body></html>")
	if _, err := compressor.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	wire := append([]byte(nil), compressed.Bytes()...)
	var messages []traffic.Message
	var events []ActivityEvent
	proxy, err := NewProxy(testProxyPolicy(t, boundary.Rule{
		ID: "capture-br", Effect: boundary.EffectAllowVisit,
		Target: boundary.RuleTarget{Host: "capture-br.example", Schemes: []string{"http"}, Methods: []string{"GET"}},
	}), ProxyOptions{
		ConversationID: "conversation-br", RuntimeMode: traffic.RuntimeModeContainer,
		CaptureCoverage: traffic.CaptureCoverageEnforced,
		ActivitySink:    func(event ActivityEvent) { events = append(events, event) },
		TrafficSink: func(_ context.Context, _ traffic.Transaction, captured []traffic.Message) error {
			messages = append([]traffic.Message(nil), captured...)
			return nil
		},
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.1",
				Header: http.Header{"Content-Type": {"text/html; charset=utf-8"}, "Content-Encoding": {"br"}},
				Body:   io.NopCloser(bytes.NewReader(wire)), Request: request,
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://capture-br.example/", nil))
	if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), wire) || recorder.Header().Get("Content-Encoding") != "br" {
		t.Fatalf("forwarded response = %d / %q / %#v", recorder.Code, recorder.Body.Bytes(), recorder.Header())
	}
	if len(events) != 1 || events[0].HTTPPacket == nil {
		t.Fatalf("events = %#v", events)
	}
	packet := events[0].HTTPPacket
	if packet.ResponseBody != string(want) || packet.ResponseBodyEncoding != "utf8" || !packet.ResponseBodyDecoded || packet.ResponseContentEncoding != "br" || packet.ResponseBodyTruncated {
		t.Fatalf("decoded packet = %#v", packet)
	}
	if len(messages) != 2 {
		t.Fatalf("messages = %#v", messages)
	}
	stored, decodeErr := traffic.DecodeBody(messages[1])
	if decodeErr != nil || !bytes.Equal(stored, wire) || messages[1].BodyEncoding != traffic.BodyEncodingBase64 {
		t.Fatalf("wire evidence = %v / %v / %s", stored, decodeErr, messages[1].BodyEncoding)
	}
}

func TestTrafficHeadersRedactOnlyInjectedAuthProfileValue(t *testing.T) {
	headers := trafficHeaders(http.Header{
		"Authorization":       {"Bearer hidden"},
		"X-Custom":            {"visible"},
		"Proxy-Authorization": {"never-store"},
	}, "example.test", "Authorization")
	values := map[string][]string{}
	for _, header := range headers {
		values[header.Name] = append(values[header.Name], header.Value)
	}
	if values["Authorization"][0] != "[REDACTED:AUTH_PROFILE]" || values["X-Custom"][0] != "visible" || len(values["Proxy-Authorization"]) != 0 || values["Host"][0] != "example.test" {
		t.Fatalf("traffic headers = %#v", values)
	}
}

func TestConnectTrafficEvidenceStoresTunnelMetadataWithoutClaimingDecodedHTTP(t *testing.T) {
	proxy := &Proxy{
		conversationID: "conversation-1", boundarySnapshotID: "snapshot-1",
		runtimeMode: traffic.RuntimeModeContainer, captureCoverage: traffic.CaptureCoverageEnforced,
	}
	request := httptest.NewRequest(http.MethodConnect, "http://proxy.invalid/", nil)
	request.Host = "example.org:443"
	request.Header.Set("X-Custom", "visible")
	startedAt := time.Now().UTC().Add(-time.Second)
	completedAt := time.Now().UTC()
	item, messages := proxy.connectTrafficEvidence(
		request, trafficAttribution{provenance: networkprovenance.NetworkProvenanceV1{AgentID: "agent-1"}.Normalized()}, "example.org:443", "example.org", 443,
		ActivityEvent{LatencyMS: 1000, BytesUp: 2048, BytesDown: 4096, RuleID: "allow"},
		http.StatusOK, nil, "", "", "",
		startedAt, completedAt,
	)
	if item.Method != http.MethodConnect || item.Scheme != "https" || item.Host != "example.org" ||
		item.Path != "/" || item.BytesUp != 2048 || item.BytesDown != 4096 || item.AgentID != "agent-1" {
		t.Fatalf("CONNECT transaction = %#v", item)
	}
	if len(messages) != 2 || messages[0].Stage != traffic.StageClientRequest ||
		messages[1].Stage != traffic.StageClientResponse || messages[0].BodyLength != 0 ||
		messages[1].BodyLength != 0 || !messages[0].Complete || !messages[1].Complete {
		t.Fatalf("CONNECT messages = %#v", messages)
	}
}

func TestProxyCapturesRequestWhenUpstreamResponseIsNotEstablished(t *testing.T) {
	var captured traffic.Transaction
	var messages []traffic.Message
	proxy, err := NewProxy(testProxyPolicy(t, boundary.Rule{
		ID: "allow-failure", Effect: boundary.EffectAllowVisit,
		Target: boundary.RuleTarget{Host: "failure.example", Schemes: []string{"http"}, Methods: []string{"GET"}},
	}), ProxyOptions{
		ConversationID: "conversation-failure", RuntimeMode: traffic.RuntimeModeContainer,
		CaptureCoverage: traffic.CaptureCoverageEnforced,
		TrafficSink: func(_ context.Context, item traffic.Transaction, capturedMessages []traffic.Message) error {
			captured, messages = item, append([]traffic.Message(nil), capturedMessages...)
			return nil
		},
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, &net.DNSError{Err: "no such host", Name: "failure.example"}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://failure.example/path?q=1", nil))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", recorder.Code)
	}
	if captured.ErrorCode != "dns_failed" || captured.Outcome != "dns_failed" || captured.HTTPStatus != http.StatusBadGateway || captured.ErrorSummary == "" {
		t.Fatalf("failed transaction = %#v", captured)
	}
	if len(messages) != 1 || messages[0].Stage != traffic.StageUpstreamRequest || messages[0].Path != "/path?q=1" {
		t.Fatalf("failed messages = %#v", messages)
	}
}

type interruptedBody struct {
	read bool
}

func (body *interruptedBody) Read(content []byte) (int, error) {
	if body.read {
		return 0, errors.New("connection reset")
	}
	body.read = true
	return copy(content, []byte("partial")), nil
}

func (*interruptedBody) Close() error { return nil }

func TestProxyMarksInterruptedUpstreamResponseIncomplete(t *testing.T) {
	var captured traffic.Transaction
	var messages []traffic.Message
	proxy, err := NewProxy(testProxyPolicy(t, boundary.Rule{
		ID: "allow-interrupted", Effect: boundary.EffectAllowVisit,
		Target: boundary.RuleTarget{Host: "interrupted.example", Schemes: []string{"http"}, Methods: []string{"GET"}},
	}), ProxyOptions{
		ConversationID: "conversation-interrupted", RuntimeMode: traffic.RuntimeModeHost,
		CaptureCoverage: traffic.CaptureCoverageBestEffort,
		TrafficSink: func(_ context.Context, item traffic.Transaction, capturedMessages []traffic.Message) error {
			captured, messages = item, append([]traffic.Message(nil), capturedMessages...)
			return nil
		},
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.1", Header: make(http.Header), Body: &interruptedBody{}, Request: request}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://interrupted.example/", nil))
	if captured.ErrorCode != "response_interrupted" || captured.Outcome != "response_interrupted" {
		t.Fatalf("interrupted transaction = %#v", captured)
	}
	if len(messages) != 2 || messages[1].Stage != traffic.StageUpstreamResponse || messages[1].Complete {
		t.Fatalf("interrupted messages = %#v", messages)
	}
}

func TestTrafficFailureClassificationIsStableAndSafe(t *testing.T) {
	deadline := fmt.Errorf("wrapped: %w", context.DeadlineExceeded)
	for _, test := range []struct {
		err  error
		code string
	}{
		{deadline, "upstream_timeout"},
		{&net.DNSError{Err: "server misbehaving", Name: "example.test"}, "dns_failed"},
		{&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("refused")}, "upstream_connect_failed"},
		{errors.New("tls: handshake failure"), "tls_handshake_failed"},
	} {
		code, summary := classifyTrafficFailure(test.err)
		if code != test.code || summary == "" || strings.Contains(summary, test.err.Error()) {
			t.Fatalf("classify %T = %q / %q", test.err, code, summary)
		}
	}
}
