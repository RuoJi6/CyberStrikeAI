package egress

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
	"cyberstrike-ai/internal/networkprovenance"
	"cyberstrike-ai/internal/traffic"
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
