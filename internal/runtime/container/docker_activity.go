package container

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/egress"
	"github.com/moby/moby/api/pkg/stdcopy"
	mobyclient "github.com/moby/moby/client"
)

const (
	defaultActivityTail             = 100
	maxActivityTail                 = 500
	maxActivityLine                 = 1024 << 10
	maxExecBoundaryFeedbackLogBytes = 4 << 20
)

var safeActivityCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

type dockerContainerLogsAPI interface {
	ContainerLogs(context.Context, string, mobyclient.ContainerLogsOptions) (mobyclient.ContainerLogsResult, error)
}

var _ RuntimeActivityStreamer = (*DockerManager)(nil)

// blockedEgressActivities performs a bounded, non-following read of the
// verified gateway log for one exec window. It is intentionally best-effort:
// packet enforcement remains inside the gateway, while this projection gives
// the model a clear explanation even when a tool reports success after one or
// more network operations were denied. Tool names and command arguments are
// deliberately irrelevant: every blocked network activity in the execution
// window is included, while gateway-internal health signals are excluded.
func (m *DockerManager) blockedEgressActivities(ctx context.Context, spec RuntimeSpec, since, until time.Time) ([]egress.ActivityEvent, bool) {
	if m == nil || m.api == nil || spec.EgressGateway == nil || spec.EgressGateway.BoundarySnapshot == nil {
		return nil, false
	}
	observation, err := m.Observe(ctx, spec)
	if err != nil || observation.Gateway == nil || observation.Gateway.Status != StatusRunning || strings.TrimSpace(observation.Gateway.ProviderID) == "" {
		return nil, false
	}
	logsAPI, ok := m.api.(dockerContainerLogsAPI)
	if !ok {
		return nil, false
	}
	windowStart := since.UTC()
	queryStart := windowStart.Add(-2 * time.Second)
	windowEnd := until.Add(2 * time.Second).UTC()
	logs, err := logsAPI.ContainerLogs(ctx, observation.Gateway.ProviderID, mobyclient.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: false,
		Follow:     false,
		Tail:       "all",
		Since:      queryStart.Format(time.RFC3339Nano),
		Until:      windowEnd.Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, false
	}
	defer logs.Close()

	var stdout bytes.Buffer
	limited := io.LimitReader(logs, maxExecBoundaryFeedbackLogBytes+1)
	if _, err := stdcopy.StdCopy(&stdout, io.Discard, limited); err != nil || stdout.Len() > maxExecBoundaryFeedbackLogBytes {
		return nil, false
	}
	scanner := bufio.NewScanner(&stdout)
	scanner.Buffer(make([]byte, 4096), maxActivityLine)
	blocked := make([]egress.ActivityEvent, 0, 4)
	for scanner.Scan() {
		event, isActivity, parseErr := parseGatewayActivityLine(scanner.Bytes(), spec)
		if parseErr != nil {
			return nil, false
		}
		if !isActivity || event.Timestamp.Before(windowStart) || event.Timestamp.After(windowEnd) || event.Decision != egress.ActivityDecisionBlocked {
			continue
		}
		if event.RequestType == egress.ActivityRequestHealth {
			continue
		}
		blocked = append(blocked, event)
	}
	if scanner.Err() != nil {
		return nil, false
	}
	return blocked, len(blocked) > 0
}

// StreamEgressActivity verifies the exact owned runtime topology before it
// follows the gateway's bounded local Docker log. Non-activity startup and
// health lines are ignored.
func (m *DockerManager) StreamEgressActivity(ctx context.Context, spec RuntimeSpec, options ActivityStreamOptions, sink RuntimeActivitySink) error {
	if m == nil || m.api == nil {
		return fmt.Errorf("%w: engine client is not configured", ErrEngineUnavailable)
	}
	if ctx == nil || sink == nil {
		return invalidSpec("activity stream context and sink are required")
	}
	if err := ValidateSpec(spec); err != nil {
		return err
	}
	if spec.EgressGateway == nil || spec.EgressGateway.BoundarySnapshot == nil {
		return fmt.Errorf("%w: runtime has no policy egress gateway", ErrInvalidSpecification)
	}
	tailValue := "all"
	if !options.All {
		tail := options.Tail
		if tail == 0 {
			tail = defaultActivityTail
		}
		if tail < 1 || tail > maxActivityTail {
			return invalidSpec("activity stream tail must be between 1 and 500")
		}
		tailValue = strconv.Itoa(tail)
	} else if options.Tail != 0 {
		return invalidSpec("activity stream all and tail are mutually exclusive")
	}
	observation, err := m.Observe(ctx, spec)
	if err != nil {
		return err
	}
	if observation.Gateway == nil || observation.Gateway.Status != StatusRunning || strings.TrimSpace(observation.Gateway.ProviderID) == "" {
		return fmt.Errorf("%w: egress gateway is not running", ErrRuntimeNotReady)
	}
	logsAPI, ok := m.api.(dockerContainerLogsAPI)
	if !ok {
		return fmt.Errorf("%w: engine log streaming is unavailable", ErrEngineUnavailable)
	}
	logs, err := logsAPI.ContainerLogs(ctx, observation.Gateway.ProviderID, mobyclient.ContainerLogsOptions{
		ShowStdout: true, ShowStderr: false, Follow: true, Tail: tailValue,
	})
	if err != nil {
		return fmt.Errorf("stream verified egress gateway logs: %w", err)
	}
	defer logs.Close()

	stdoutReader, stdoutWriter := io.Pipe()
	demuxDone := make(chan error, 1)
	go func() {
		_, copyErr := stdcopy.StdCopy(stdoutWriter, io.Discard, logs)
		_ = stdoutWriter.CloseWithError(copyErr)
		demuxDone <- copyErr
	}()

	scanner := bufio.NewScanner(stdoutReader)
	scanner.Buffer(make([]byte, 4096), maxActivityLine)
	for scanner.Scan() {
		event, isActivity, parseErr := parseGatewayActivityLine(scanner.Bytes(), spec)
		if parseErr != nil {
			_ = stdoutReader.CloseWithError(parseErr)
			return parseErr
		}
		if !isActivity {
			continue
		}
		if err := sink(event); err != nil {
			_ = stdoutReader.CloseWithError(err)
			return err
		}
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("read egress activity stream: %w", err)
	}
	select {
	case err := <-demuxDone:
		if err != nil && ctx.Err() == nil && !errors.Is(err, io.ErrClosedPipe) {
			return fmt.Errorf("decode egress activity stream: %w", err)
		}
	default:
	}
	return nil
}

func parseGatewayActivityLine(line []byte, spec RuntimeSpec) (egress.ActivityEvent, bool, error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return egress.ActivityEvent{}, false, nil
	}
	var header struct {
		Event string `json:"event"`
	}
	if err := json.Unmarshal(line, &header); err != nil {
		if bytes.Contains(line, []byte(egress.ActivityEventName)) {
			return egress.ActivityEvent{}, true, fmt.Errorf("%w: malformed egress activity event", ErrRuntimeStateConflict)
		}
		return egress.ActivityEvent{}, false, nil
	}
	if header.Event != egress.ActivityEventName {
		return egress.ActivityEvent{}, false, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var event egress.ActivityEvent
	if err := decoder.Decode(&event); err != nil {
		return egress.ActivityEvent{}, true, fmt.Errorf("%w: invalid egress activity event", ErrRuntimeStateConflict)
	}
	if err := validateGatewayActivityEvent(event, spec); err != nil {
		return egress.ActivityEvent{}, true, err
	}
	return event, true, nil
}

func validateGatewayActivityEvent(event egress.ActivityEvent, spec RuntimeSpec) error {
	invalid := func() error { return fmt.Errorf("%w: invalid egress activity event", ErrRuntimeStateConflict) }
	if spec.EgressGateway == nil || spec.EgressGateway.BoundarySnapshot == nil ||
		event.Event != egress.ActivityEventName || event.Timestamp.IsZero() || event.Timestamp.After(time.Now().UTC().Add(5*time.Minute)) ||
		event.SnapshotID != spec.EgressGateway.BoundarySnapshot.ID || event.SnapshotSHA256 != spec.EgressGateway.BoundarySnapshot.SHA256 ||
		len(event.Domain) > 253 || strings.TrimSpace(event.Domain) != event.Domain ||
		event.LatencyMS < 0 || event.BytesUp < 0 || event.BytesDown < 0 || event.RetryAfterMS < 0 || event.RetryAfterMS > int64(time.Hour/time.Millisecond) || len(event.ResolvedIPs) > 64 || len(event.DNSAnswers) > 128 ||
		!validActivityCode(event.Outcome, false) || !validActivityCode(event.Reason, true) || !validActivityText(event.RuleID, 256, true) {
		return invalid()
	}
	switch event.RequestType {
	case egress.ActivityRequestDNS:
		if event.Domain == "" || !validActivityCode(event.DNSQueryType, true) || event.Port != 0 || event.Method != "" || event.Path != "" || event.HTTPStatus != 0 || event.ConnectedIP != "" || event.RetryAfterMS != 0 || event.HTTPPacket != nil {
			return invalid()
		}
	case egress.ActivityRequestHTTP, egress.ActivityRequestHTTPS:
		if event.DNSQueryType != "" || len(event.DNSAnswers) != 0 || event.Domain == "" || event.Port < 1 || event.Port > 65535 || !validActivityMethod(event.Method) || !validActivityPath(event.Path) ||
			event.HTTPStatus < 0 || event.HTTPStatus > 999 || egress.ValidateHTTPPacket(event.HTTPPacket) != nil {
			return invalid()
		}
	case egress.ActivityRequestCONNECT, egress.ActivityRequestTCP, egress.ActivityRequestUDP:
		if event.DNSQueryType != "" || len(event.DNSAnswers) != 0 || event.Domain == "" || event.Port < 1 || event.Port > 65535 || event.Method != "" || event.Path != "" || event.HTTPStatus != 0 || event.HTTPPacket != nil {
			return invalid()
		}
	case egress.ActivityRequestICMP:
		if event.DNSQueryType != "" || len(event.DNSAnswers) != 0 || event.Domain == "" || event.Port != 0 || event.Method != "" || event.Path != "" || event.HTTPStatus != 0 || event.HTTPPacket != nil {
			return invalid()
		}
	case egress.ActivityRequestHealth:
		if event.DNSQueryType != "" || len(event.DNSAnswers) != 0 || event.Port != 0 || event.Method != "" || event.Path != "" || event.HTTPStatus != 0 || event.ConnectedIP != "" || len(event.ResolvedIPs) != 0 || event.BytesUp != 0 || event.BytesDown != 0 || event.LatencyMS != 0 || event.HTTPPacket != nil || !validGatewayHealthEvent(event) {
			return invalid()
		}
	default:
		return invalid()
	}
	if event.Decision != egress.ActivityDecisionAllowed && event.Decision != egress.ActivityDecisionBlocked {
		return invalid()
	}
	for _, raw := range event.ResolvedIPs {
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.IsValid() || address.Zone() != "" || address.String() != raw {
			return invalid()
		}
	}
	for _, answer := range event.DNSAnswers {
		if !validActivityText(answer, 1024, false) {
			return invalid()
		}
	}
	if event.ConnectedIP != "" {
		address, err := netip.ParseAddr(event.ConnectedIP)
		if err != nil || !address.IsValid() || address.Zone() != "" || address.String() != event.ConnectedIP {
			return invalid()
		}
	}
	expectedRouteID := ""
	if spec.EgressGateway.UpstreamRoute != nil {
		expectedRouteID = spec.EgressGateway.UpstreamRoute.ID
	}
	if event.UpstreamRouteID != expectedRouteID {
		return invalid()
	}
	return nil
}

func validGatewayHealthEvent(event egress.ActivityEvent) bool {
	switch event.Outcome {
	case "cooldown_started":
		return event.Decision == egress.ActivityDecisionBlocked && event.Reason == "upstream_rate_limited" && event.RetryAfterMS > 0
	case "cooldown_expired":
		return event.Decision == egress.ActivityDecisionAllowed && event.Reason == "upstream_rate_limited" && event.RetryAfterMS == 0
	case "health_paused":
		if event.Decision != egress.ActivityDecisionBlocked || event.RetryAfterMS != 0 {
			return false
		}
		return event.Reason == "consecutive_login_failures" || event.Reason == "waf_challenge" || event.Reason == "captcha_challenge"
	default:
		return false
	}
}

func validActivityCode(value string, optional bool) bool {
	if value == "" {
		return optional
	}
	return safeActivityCodePattern.MatchString(value)
}

func validActivityText(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validActivityMethod(value string) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if !((character >= 'A' && character <= 'Z') || character == '-') {
			return false
		}
	}
	return true
}

func validActivityPath(value string) bool {
	return validActivityText(value, 1024, false) && strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "?#")
}
