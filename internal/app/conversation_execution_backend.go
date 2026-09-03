package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/networkprovenance"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"

	"github.com/google/uuid"
)

const (
	containerStartJoinPollInterval = 25 * time.Millisecond
	containerStartJoinMaxWait      = 30 * time.Second
)

// conversationExecutionBackendResolver binds command execution to durable
// conversation state. Container failures are returned to the tool caller and
// are never converted into a host backend.
type conversationExecutionBackendResolver struct {
	db        *database.DB
	host      security.ExecutionBackend
	hostProxy hostExecutionBackendProvider
	container containerruntime.RuntimeExecutor
	lifecycle *containerruntime.LifecycleController
	signer    *networkprovenance.Signer
}

type hostExecutionBackendProvider interface {
	ResolveHostExecutionBackend(context.Context, string) (security.ExecutionBackend, error)
}

func newConversationExecutionBackendResolver(db *database.DB, runtime containerruntime.RuntimeExecutor, lifecycle *containerruntime.LifecycleController, options ...any) security.ExecutionBackendResolver {
	resolver := &conversationExecutionBackendResolver{
		db:        db,
		host:      security.NewHostExecutionBackend(),
		container: runtime,
		lifecycle: lifecycle,
	}
	for _, option := range options {
		switch value := option.(type) {
		case hostExecutionBackendProvider:
			resolver.hostProxy = value
		case *networkprovenance.Signer:
			resolver.signer = value
		}
	}
	return resolver
}

func (r *conversationExecutionBackendResolver) ResolveExecutionBackend(ctx context.Context) (security.ExecutionBackend, error) {
	if r == nil || r.host == nil {
		return nil, fmt.Errorf("execution backend resolver is not configured")
	}
	conversationID := strings.TrimSpace(mcp.MCPConversationIDFromContext(ctx))
	if conversationID == "" {
		return r.host, nil
	}
	if r.db == nil {
		return nil, fmt.Errorf("conversation database is not configured")
	}
	runtimeMode, err := r.db.GetConversationRuntimeMode(conversationID)
	if err != nil {
		return nil, fmt.Errorf("resolve execution conversation %s: %w", conversationID, err)
	}
	switch runtimeMode {
	case database.ConversationRuntimeModeHost:
		if r.hostProxy != nil {
			backend, resolveErr := r.hostProxy.ResolveHostExecutionBackend(ctx, conversationID)
			if resolveErr != nil {
				return nil, fmt.Errorf("configure host traffic capture for conversation %s: %w", conversationID, resolveErr)
			}
			return backend, nil
		}
		return r.host, nil
	case database.ConversationRuntimeModeContainer:
		return r.resolveContainer(ctx, conversationID)
	default:
		return nil, fmt.Errorf("conversation %s has invalid runtime mode %q", conversationID, runtimeMode)
	}
}

func (r *conversationExecutionBackendResolver) resolveContainer(ctx context.Context, conversationID string) (security.ExecutionBackend, error) {
	if r.container == nil || r.lifecycle == nil {
		return nil, fmt.Errorf("container execution backend is unavailable for conversation %s", conversationID)
	}
	pendingBoundaryRebuild, err := r.db.HasPendingConversationBoundaryRebuild(ctx, conversationID)
	if err != nil {
		return nil, fmt.Errorf("check boundary rebuild for conversation %s: %w", conversationID, err)
	}
	if pendingBoundaryRebuild {
		return nil, fmt.Errorf("boundary rebuild for conversation %s is pending", conversationID)
	}
	snapshot, err := r.db.GetConversationBoundarySnapshot(ctx, conversationID)
	if err != nil {
		return nil, fmt.Errorf("load boundary snapshot for conversation %s: %w", conversationID, err)
	}
	record, err := r.db.GetContainerInitialization(ctx, conversationID)
	if err != nil {
		return nil, fmt.Errorf("load container runtime for conversation %s: %w", conversationID, err)
	}
	if record.Status != containerruntime.InitializationCreated ||
		(record.ReadinessStatus != containerruntime.ReadinessReady && record.ReadinessStatus != containerruntime.ReadinessNotRequired) {
		return nil, fmt.Errorf("container runtime for conversation %s is not ready", conversationID)
	}
	if snapshot.RuntimeGeneration != record.RuntimeGeneration {
		return nil, fmt.Errorf("boundary snapshot/runtime generation mismatch for conversation %s", conversationID)
	}
	if containerStartInProgress(record) {
		record, err = r.waitForContainerStart(ctx, conversationID)
		if err != nil {
			return nil, err
		}
	} else if record.RuntimeStatus == containerruntime.StatusStopped {
		started, startErr := r.lifecycle.Start(ctx, conversationID)
		if startErr != nil {
			observed, getErr := r.db.GetContainerInitialization(ctx, conversationID)
			if getErr != nil {
				return nil, fmt.Errorf("start container runtime for conversation %s: %w (reload lifecycle state: %v)", conversationID, startErr, getErr)
			}
			switch {
			case containerStartInProgress(observed):
				observed, err = r.waitForContainerStart(ctx, conversationID)
				if err != nil {
					return nil, err
				}
			case observed.RuntimeStatus == containerruntime.StatusRunning && observed.LifecycleState == containerruntime.LifecycleIdle:
				// A concurrent caller completed the same durable start before the reload.
			case observed.LifecycleOperation == containerruntime.LifecycleOperationStart && observed.LifecycleState == containerruntime.LifecycleFailed:
				return nil, containerStartFailedError(observed)
			default:
				return nil, fmt.Errorf("start container runtime for conversation %s: %w", conversationID, startErr)
			}
			record = observed
		} else {
			record = started
		}
	}
	if record.RuntimeStatus != containerruntime.StatusRunning || record.LifecycleState != containerruntime.LifecycleIdle {
		return nil, fmt.Errorf("container runtime for conversation %s is %s/%s", conversationID, record.RuntimeStatus, record.LifecycleState)
	}
	backend, err := security.NewContainerExecutionBackendWithIdentity(r.container, record.Spec, record.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("bind container execution backend for conversation %s: %w", conversationID, err)
	}
	if record.Spec.EgressGateway == nil || strings.TrimSpace(record.Spec.EgressGateway.AttributionPublicKey) == "" {
		return backend, nil
	}
	if r.signer == nil || r.signer.PublicKeyEncoded() != strings.TrimSpace(record.Spec.EgressGateway.AttributionPublicKey) {
		return nil, fmt.Errorf("container network provenance signer does not match runtime %s", conversationID)
	}
	instanceID := strings.TrimSpace(record.Spec.EgressGateway.AttributionInstanceID)
	if instanceID == "" || record.Spec.EgressGateway.AttributionRuntimeGeneration != record.RuntimeGeneration {
		return nil, fmt.Errorf("container runtime %s has no network provenance instance", conversationID)
	}
	return &proxiedContainerExecutionBackend{
		base: backend, signer: r.signer, conversationID: conversationID,
		runtimeID: record.Spec.ID, runtimeGeneration: record.Spec.EgressGateway.AttributionRuntimeGeneration, runtimeInstanceID: instanceID,
	}, nil
}

type proxiedContainerExecutionBackend struct {
	base              security.ExecutionBackend
	signer            *networkprovenance.Signer
	conversationID    string
	runtimeID         containerruntime.RuntimeID
	runtimeGeneration int
	runtimeInstanceID string
}

const networkScopeShellFunction = `network_scope() {
	if [ "$#" -lt 3 ] || [ "$1" != "fuzz" ] || [ "$2" != "--" ]; then
		return 64
	fi
	shift 2
	HTTP_PROXY="$CYBERSTRIKE_NETWORK_SCOPE_FUZZ_PROXY" HTTPS_PROXY="$CYBERSTRIKE_NETWORK_SCOPE_FUZZ_PROXY" http_proxy="$CYBERSTRIKE_NETWORK_SCOPE_FUZZ_PROXY" https_proxy="$CYBERSTRIKE_NETWORK_SCOPE_FUZZ_PROXY" "$@"
}
`

var networkScopeShellCommandPattern = regexp.MustCompile(`(^|[;\n]|&&|\|\|)[\t ]*network-scope[\t ]+fuzz[\t ]+--[\t ]+`)

func prepareAttributedProxyRequest(request security.ExecutionRequest, signer *networkprovenance.Signer, provenance networkprovenance.NetworkProvenanceV1, deadline time.Time, rawProxyURL string) (security.ExecutionRequest, []string, error) {
	if signer == nil {
		return request, nil, fmt.Errorf("network provenance signer is unavailable")
	}
	proxyURL, err := url.Parse(strings.TrimSpace(rawProxyURL))
	if err != nil || proxyURL.Scheme != "http" || proxyURL.Host == "" || proxyURL.User != nil {
		return request, nil, fmt.Errorf("network provenance proxy URL is invalid")
	}
	sensitiveValues := make([]string, 0, 4)
	signedURL := func(scope networkprovenance.NetworkProvenanceV1) (string, error) {
		token, issueErr := signer.Issue(scope, deadline)
		if issueErr != nil {
			return "", issueErr
		}
		sensitiveValues = append(sensitiveValues, token, base64.StdEncoding.EncodeToString([]byte(hostTrafficProxyUsername+":"+token)))
		copyURL := *proxyURL
		copyURL.User = url.UserPassword(hostTrafficProxyUsername, token)
		return copyURL.String(), nil
	}
	primaryURL, err := signedURL(provenance)
	if err != nil {
		return request, nil, err
	}
	request.Env = append(request.Env,
		"HTTP_PROXY="+primaryURL, "HTTPS_PROXY="+primaryURL,
		"http_proxy="+primaryURL, "https_proxy="+primaryURL,
	)
	if provenance.DeclaredActivityKind != networkprovenance.ActivityKindFuzz && len(request.Command) >= 3 &&
		(request.Command[0] == "/bin/sh" || request.Command[0] == "sh" || request.Command[0] == "/bin/bash" || request.Command[0] == "bash") && request.Command[1] == "-c" {
		rewritten := networkScopeShellCommandPattern.ReplaceAllString(request.Command[2], "$1 network_scope fuzz -- ")
		if rewritten == request.Command[2] {
			return request, sensitiveValues, nil
		}
		fuzz := provenance
		fuzz.DeclaredActivityKind = networkprovenance.ActivityKindFuzz
		fuzz.ActivityScopeID = uuid.NewString()
		fuzzURL, issueErr := signedURL(fuzz)
		if issueErr != nil {
			return request, nil, issueErr
		}
		request.Env = append(request.Env, "CYBERSTRIKE_NETWORK_SCOPE_FUZZ_PROXY="+fuzzURL)
		request.Command = append([]string(nil), request.Command...)
		request.Command[2] = networkScopeShellFunction + rewritten
	}
	return request, sensitiveValues, nil
}

const redactedNetworkCredential = "[REDACTED_NETWORK_CREDENTIAL]"

// executionOutputRedactor retains only the longest possible sensitive prefix
// between callbacks, so a credential split across stdout/stderr chunks cannot
// reach SSE, tool results, or persistent execution output.
type executionOutputRedactor struct {
	mu        sync.Mutex
	values    []string
	maxLength int
	pending   string
	output    security.ToolOutputCallback
}

func newExecutionOutputRedactor(values []string, output security.ToolOutputCallback) *executionOutputRedactor {
	redactor := &executionOutputRedactor{output: output}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		redactor.values = append(redactor.values, value)
		if len(value) > redactor.maxLength {
			redactor.maxLength = len(value)
		}
	}
	return redactor
}

func (r *executionOutputRedactor) redact(value string) string {
	for _, sensitive := range r.values {
		value = strings.ReplaceAll(value, sensitive, redactedNetworkCredential)
	}
	return value
}

func (r *executionOutputRedactor) write(chunk string) {
	if r == nil || chunk == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending += chunk
	r.pending = r.redact(r.pending)
	keep := r.maxLength - 1
	if keep < 0 {
		keep = 0
	}
	flushLength := len(r.pending) - keep
	if flushLength <= 0 {
		return
	}
	flushed := r.pending[:flushLength]
	r.pending = r.pending[flushLength:]
	if r.output != nil && flushed != "" {
		r.output(flushed)
	}
}

func (r *executionOutputRedactor) flush() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	flushed := r.redact(r.pending)
	r.pending = ""
	if r.output != nil && flushed != "" {
		r.output(flushed)
	}
}

func executeWithCredentialRedaction(ctx context.Context, backend security.ExecutionBackend, request security.ExecutionRequest, sensitiveValues []string) (security.ExecutionResult, error) {
	redactor := newExecutionOutputRedactor(sensitiveValues, request.Output)
	if request.Output != nil {
		request.Output = redactor.write
	}
	result, err := backend.Execute(ctx, request)
	redactor.flush()
	result.Output = redactor.redact(result.Output)
	return result, err
}

func (*proxiedContainerExecutionBackend) ExecutionLocation() string { return "container" }

func (backend *proxiedContainerExecutionBackend) Execute(ctx context.Context, request security.ExecutionRequest) (security.ExecutionResult, error) {
	if backend == nil || backend.base == nil || backend.signer == nil {
		return security.ExecutionResult{Location: "container", ExitCode: -1}, fmt.Errorf("container provenance backend is not configured")
	}
	var declaredKind string
	var err error
	request, declaredKind, err = security.ConsumeNetworkScope(request)
	if err != nil {
		return security.ExecutionResult{Location: "container", ExitCode: -1}, err
	}
	provenance := networkprovenance.FromContext(ctx)
	provenance.ConversationID = backend.conversationID
	provenance.RuntimeMode = networkprovenance.RuntimeModeContainer
	provenance.RuntimeGeneration = backend.runtimeGeneration
	provenance.RuntimeInstanceID = backend.runtimeInstanceID
	if provenance.ExecutionID == "" {
		provenance.ExecutionID = uuid.NewString()
	}
	if provenance.AgentID == "" {
		provenance.AgentID = "container-agent"
	}
	if provenance.ToolName == "" {
		provenance.ToolName = "container-exec"
	}
	if declaredKind == networkprovenance.ActivityKindFuzz {
		provenance.DeclaredActivityKind = declaredKind
	} else if provenance.DeclaredActivityKind == networkprovenance.ActivityKindUnknown {
		provenance.DeclaredActivityKind = networkprovenance.ActivityKindNormal
	}
	deadline, _ := ctx.Deadline()
	request, sensitiveValues, err := prepareAttributedProxyRequest(request, backend.signer, provenance, deadline,
		(&url.URL{Scheme: "http", Host: containerruntime.EgressGatewayContainerName(backend.runtimeID) + ":3128"}).String())
	if err != nil {
		return security.ExecutionResult{Location: "container", ExitCode: -1}, fmt.Errorf("issue container traffic provenance: %w", err)
	}
	return executeWithCredentialRedaction(ctx, backend.base, request, sensitiveValues)
}

func (backend *proxiedContainerExecutionBackend) WriteWorkspaceFile(ctx context.Context, path string, content io.Reader, size int64) (string, error) {
	writer, ok := backend.base.(security.WorkspaceFileWriter)
	if !ok {
		return "", fmt.Errorf("container workspace writer is unavailable")
	}
	return writer.WriteWorkspaceFile(ctx, path, content, size)
}

func containerStartInProgress(record containerruntime.InitializationRecord) bool {
	return record.LifecycleOperation == containerruntime.LifecycleOperationStart &&
		record.LifecycleState == containerruntime.LifecycleInProgress
}

func containerStartFailedError(record containerruntime.InitializationRecord) error {
	message := strings.TrimSpace(record.LifecycleError)
	if message == "" {
		message = strings.TrimSpace(record.LastError)
	}
	if message == "" {
		message = "unknown container engine error"
	}
	return fmt.Errorf("container runtime start for conversation %s failed: %s", record.ConversationID, message)
}

func (r *conversationExecutionBackendResolver) waitForContainerStart(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
	waitCtx, cancel := context.WithTimeout(ctx, containerStartJoinMaxWait)
	defer cancel()
	ticker := time.NewTicker(containerStartJoinPollInterval)
	defer ticker.Stop()

	for {
		record, err := r.db.GetContainerInitialization(waitCtx, conversationID)
		if err != nil {
			return record, fmt.Errorf("wait for container runtime start for conversation %s: %w", conversationID, err)
		}
		switch {
		case record.RuntimeStatus == containerruntime.StatusRunning && record.LifecycleState == containerruntime.LifecycleIdle:
			return record, nil
		case record.LifecycleOperation == containerruntime.LifecycleOperationStart && record.LifecycleState == containerruntime.LifecycleFailed:
			return record, containerStartFailedError(record)
		case !containerStartInProgress(record):
			return record, fmt.Errorf("container runtime start for conversation %s changed to %s/%s before completion", conversationID, record.LifecycleOperation, record.LifecycleState)
		}

		select {
		case <-waitCtx.Done():
			return record, fmt.Errorf("wait for container runtime start for conversation %s: %w", conversationID, waitCtx.Err())
		case <-ticker.C:
		}
	}
}
