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
	defaultActivityTail = 100
	maxActivityTail     = 500
	maxActivityLine     = 64 << 10
)

var safeActivityCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

type dockerContainerLogsAPI interface {
	ContainerLogs(context.Context, string, mobyclient.ContainerLogsOptions) (mobyclient.ContainerLogsResult, error)
}

var _ RuntimeActivityStreamer = (*DockerManager)(nil)

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
		len(event.Domain) == 0 || len(event.Domain) > 253 || strings.TrimSpace(event.Domain) != event.Domain ||
		event.LatencyMS < 0 || event.BytesUp < 0 || event.BytesDown < 0 || len(event.ResolvedIPs) > 64 ||
		!validActivityCode(event.Outcome, false) || !validActivityCode(event.Reason, true) || !validActivityText(event.RuleID, 256, true) {
		return invalid()
	}
	switch event.RequestType {
	case egress.ActivityRequestDNS:
		if event.Port != 0 || event.Method != "" || event.Path != "" || event.HTTPStatus != 0 || event.ConnectedIP != "" {
			return invalid()
		}
	case egress.ActivityRequestHTTP:
		if event.Port < 1 || event.Port > 65535 || !validActivityMethod(event.Method) ||
			len(event.Path) == 0 || len(event.Path) > 1024 || !strings.HasPrefix(event.Path, "/") ||
			event.HTTPStatus < 0 || event.HTTPStatus > 999 {
			return invalid()
		}
	case egress.ActivityRequestCONNECT:
		if event.Port < 1 || event.Port > 65535 || event.Method != "" || event.Path != "" || event.HTTPStatus != 0 {
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
