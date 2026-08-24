package container

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/egress"
	mobyclient "github.com/moby/moby/client"
)

type fakeActivityDockerAPI struct {
	*fakeDockerCreationAPI
	logsContainerID string
	logsOptions     mobyclient.ContainerLogsOptions
	logs            []byte
}

func (f *fakeActivityDockerAPI) ContainerLogs(_ context.Context, id string, options mobyclient.ContainerLogsOptions) (mobyclient.ContainerLogsResult, error) {
	f.logsContainerID = id
	f.logsOptions = options
	return io.NopCloser(bytes.NewReader(f.logs)), nil
}

func TestDockerManagerStreamsOnlyValidatedExactSnapshotActivity(t *testing.T) {
	spec, root, snapshotPath := snapshotGatewayFixture(t)
	base := newSuccessfulSnapshotGatewayCreationAPI(spec, "instance-01", snapshotPath)
	api := &fakeActivityDockerAPI{fakeDockerCreationAPI: base}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01", EgressSnapshotRoot: root, OperationTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(context.Background(), spec.ID); err != nil {
		t.Fatal(err)
	}
	event := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), RequestType: egress.ActivityRequestDNS,
		Domain: "allowed.example", ResolvedIPs: []string{"93.184.216.34"}, Decision: egress.ActivityDecisionAllowed,
		RuleID: "visit-1", Reason: "allow-visit", Outcome: "resolved",
		SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var multiplexed bytes.Buffer
	writeActivityLogFrame(&multiplexed, []byte(`{"event":"boundary_snapshot_loaded"}`+"\n"))
	writeActivityLogFrame(&multiplexed, append(encoded, '\n'))
	api.logs = multiplexed.Bytes()

	var received []egress.ActivityEvent
	if err := manager.StreamEgressActivity(context.Background(), spec, ActivityStreamOptions{Tail: 37}, func(event egress.ActivityEvent) error {
		received = append(received, event)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(received) != 1 || received[0].Domain != "allowed.example" {
		t.Fatalf("received = %#v", received)
	}
	if api.logsContainerID != "provider-gateway-1" || !api.logsOptions.ShowStdout || api.logsOptions.ShowStderr || !api.logsOptions.Follow || api.logsOptions.Tail != "37" {
		t.Fatalf("logs request = %q %#v", api.logsContainerID, api.logsOptions)
	}
	received = nil
	if err := manager.StreamEgressActivity(context.Background(), spec, ActivityStreamOptions{All: true}, func(event egress.ActivityEvent) error {
		received = append(received, event)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(received) != 1 || api.logsOptions.Tail != "all" || !api.logsOptions.Follow {
		t.Fatalf("complete bounded log replay = %#v, options = %#v", received, api.logsOptions)
	}
	if err := manager.StreamEgressActivity(context.Background(), spec, ActivityStreamOptions{All: true, Tail: 1}, func(egress.ActivityEvent) error { return nil }); err == nil {
		t.Fatal("combined all/tail stream options were accepted")
	}
}

func writeActivityLogFrame(target *bytes.Buffer, payload []byte) {
	header := make([]byte, 8)
	header[0] = 1
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	_, _ = target.Write(header)
	_, _ = target.Write(payload)
}

func TestGatewayActivityParserRejectsLeaksAndSnapshotDrift(t *testing.T) {
	spec, _, _ := snapshotGatewayFixture(t)
	spec.EgressGateway.UpstreamRoute = &EgressUpstreamRouteSpec{
		ID: spec.ConversationID, SHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	valid := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), RequestType: egress.ActivityRequestCONNECT,
		Domain: "allowed.example", Port: 443, Decision: egress.ActivityDecisionBlocked, RuleID: "visit-1",
		Reason: "rate_limit_exceeded", Outcome: "rate_limited", UpstreamRouteID: spec.ConversationID, SnapshotID: spec.EgressGateway.BoundarySnapshot.ID,
		SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	encoded, _ := json.Marshal(valid)
	if _, activity, err := parseGatewayActivityLine(encoded, spec); err != nil || !activity {
		t.Fatalf("valid event rejected: activity=%v err=%v", activity, err)
	}
	for _, requestType := range []string{egress.ActivityRequestTCP, egress.ActivityRequestUDP} {
		transport := valid
		transport.RequestType = requestType
		line, _ := json.Marshal(transport)
		if _, activity, err := parseGatewayActivityLine(line, spec); err != nil || !activity {
			t.Fatalf("valid %s event rejected: activity=%v err=%v", requestType, activity, err)
		}
	}
	for name, mutate := range map[string]func(*egress.ActivityEvent){
		"snapshot drift": func(event *egress.ActivityEvent) { event.SnapshotID = "00000000-0000-0000-0000-000000000000" },
		"route drift":    func(event *egress.ActivityEvent) { event.UpstreamRouteID = "other-route" },
		"connect path":   func(event *egress.ActivityEvent) { event.Path = "/must-not-exist" },
		"query-bearing HTTP path": func(event *egress.ActivityEvent) {
			event.RequestType, event.Method, event.Path, event.HTTPStatus = egress.ActivityRequestHTTP, "GET", "/safe?token=private-token", 200
		},
		"unsafe rule": func(event *egress.ActivityEvent) { event.RuleID = "secret\nheader" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			line, _ := json.Marshal(candidate)
			if _, activity, err := parseGatewayActivityLine(line, spec); err == nil || !activity {
				t.Fatalf("unsafe event accepted: %s activity=%v", line, activity)
			}
		})
	}
	for name, field := range map[string]string{
		"authorization header": "authorization",
		"request body":         "requestBody",
		"response body":        "responseBody",
		"cookie":               "cookie",
	} {
		t.Run(name, func(t *testing.T) {
			var payload map[string]interface{}
			if err := json.Unmarshal(encoded, &payload); err != nil {
				t.Fatal(err)
			}
			payload[field] = "private-secret-marker"
			line, _ := json.Marshal(payload)
			_, activity, err := parseGatewayActivityLine(line, spec)
			if err == nil || !activity || strings.Contains(err.Error(), "private-secret-marker") {
				t.Fatalf("unknown sensitive field accepted or echoed: activity=%v err=%v", activity, err)
			}
		})
	}
	line := []byte(`{"event":"boundary_snapshot_healthy","password":"secret"}`)
	if _, activity, err := parseGatewayActivityLine(line, spec); err != nil || activity {
		t.Fatalf("non-activity line = activity=%v err=%v", activity, err)
	}
	if _, activity, err := parseGatewayActivityLine([]byte(`{"event":"egress_activity","domain":`), spec); err == nil || !activity || strings.Contains(err.Error(), "domain") {
		t.Fatalf("malformed activity handling = activity=%v err=%v", activity, err)
	}
}

func TestGatewayActivityParserAcceptsOnlyClosedHealthSignals(t *testing.T) {
	spec, _, _ := snapshotGatewayFixture(t)
	valid := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), RequestType: egress.ActivityRequestHealth,
		Domain: "allowed.example", Decision: egress.ActivityDecisionBlocked, RuleID: "attack-1",
		Reason: "upstream_rate_limited", Outcome: "cooldown_started", RetryAfterMS: 30000,
		SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	encoded, _ := json.Marshal(valid)
	if _, activity, err := parseGatewayActivityLine(encoded, spec); err != nil || !activity {
		t.Fatalf("valid health event rejected: activity=%v err=%v", activity, err)
	}
	for name, mutate := range map[string]func(*egress.ActivityEvent){
		"unknown signal":     func(event *egress.ActivityEvent) { event.Reason = "provider_secret_signal" },
		"unbounded cooldown": func(event *egress.ActivityEvent) { event.RetryAfterMS = int64(time.Hour/time.Millisecond) + 1 },
		"health body bytes":  func(event *egress.ActivityEvent) { event.BytesDown = 1 },
		"health path":        func(event *egress.ActivityEvent) { event.Path = "/login" },
		"wrong verdict":      func(event *egress.ActivityEvent) { event.Decision = egress.ActivityDecisionAllowed },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			line, _ := json.Marshal(candidate)
			if _, activity, err := parseGatewayActivityLine(line, spec); err == nil || !activity {
				t.Fatalf("invalid health event accepted: %s", line)
			}
		})
	}
}
