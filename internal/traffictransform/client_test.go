package traffictransform

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/traffic"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestHTTPClientLoadsAndInvokesRevision(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	source := "def decode_request(ctx, wire):\n    return wire\n"
	revision, report := PrepareRevision(Revision{
		ID: "revision-1", TransformID: "transform-1", Source: source,
		Hooks: []Hook{HookDecodeRequest},
	}, DefaultRunnerInventory())
	if !report.Valid {
		t.Fatalf("revision: %#v", report)
	}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		switch request.URL.Path {
		case "/v1/revisions/load":
			return jsonResponse(`{"protocolVersion":"traffic-transform/v1","revisionId":"revision-1","sourceSha256":"` + revision.SourceSHA256 + `","valid":true,"hooks":["decode_request"],"runnerGeneration":"generation-1"}`), nil
		case "/v1/invoke":
			return jsonResponse(`{"protocolVersion":"traffic-transform/v1","invocationId":"invocation-1","action":"pass"}`), nil
		default:
			t.Fatalf("path = %s", request.URL.Path)
			return nil, nil
		}
	})
	client, err := newHTTPClient("http://transform-runner:9089", token, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.LoadRevision(context.Background(), revision); err != nil {
		t.Fatalf("LoadRevision: %v", err)
	}
	message := NewMessage(traffic.MessageKindRequest, "GET", "/", 0, nil, nil, true)
	invocation := Invocation{
		ProtocolVersion: ProtocolVersion, InvocationID: "invocation-1", RevisionID: revision.ID,
		RevisionSHA256: revision.SourceSHA256, Hook: HookDecodeRequest, Mode: ModeObserve, DeadlineMS: 250,
		Context: InvocationContext{
			TransactionID: "transaction-1", ConversationID: "conversation-1", Direction: DirectionRequest,
			Scheme: "https", Host: "example.test", Port: 443, Method: "GET", Path: "/", Timestamp: time.Now().UTC(),
		},
		Message: message,
	}
	result, err := client.Invoke(context.Background(), invocation)
	if err != nil || result.Action != ActionPass {
		t.Fatalf("Invoke = %#v / %v", result, err)
	}
}

func TestHTTPClientRejectsPublicOrCredentialedEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"https://127.0.0.1:9089",
		"http://example.com:9089",
		"http://user:pass@127.0.0.1:9089",
		"http://8.8.8.8:9089",
	} {
		if _, err := newHTTPClient(endpoint, strings.Repeat("x", 32), &http.Client{}); err == nil {
			t.Fatalf("expected endpoint %q to be rejected", endpoint)
		}
	}
}
