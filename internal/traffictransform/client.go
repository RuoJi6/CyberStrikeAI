package traffictransform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxRunnerResponseBytes = 2 << 20

type Client interface {
	Invoke(context.Context, Invocation) (Result, error)
	Health(context.Context) (RunnerHealth, error)
}

type RevisionLoader interface {
	LoadRevision(context.Context, Revision) (LoadResult, error)
}

type RunnerHealth struct {
	Status           string            `json:"status"`
	ProtocolVersion  string            `json:"protocolVersion"`
	RunnerGeneration string            `json:"runnerGeneration"`
	LoadedRevisions  []LoadedRevision  `json:"loadedRevisions"`
	Inventory        map[string]string `json:"inventory"`
}

type LoadedRevision struct {
	RevisionID   string `json:"revisionId"`
	SourceSHA256 string `json:"sourceSha256"`
}

type LoadResult struct {
	ProtocolVersion  string `json:"protocolVersion"`
	RevisionID       string `json:"revisionId"`
	SourceSHA256     string `json:"sourceSha256"`
	Valid            bool   `json:"valid"`
	Hooks            []Hook `json:"hooks"`
	RunnerGeneration string `json:"runnerGeneration"`
}

type HTTPClient struct {
	endpoint *url.URL
	token    string
	client   *http.Client
}

func NewHTTPClient(endpoint, token string) (*HTTPClient, error) {
	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     30 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("traffic transform runner redirects are disabled")
		},
	}
	return newHTTPClient(endpoint, token, client)
}

func newHTTPClient(endpoint, token string, client *http.Client) (*HTTPClient, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("traffic transform runner endpoint must be a private HTTP URL")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("traffic transform runner endpoint must not contain a path")
	}
	if !privateRunnerHost(parsed.Hostname()) {
		return nil, errors.New("traffic transform runner endpoint must use loopback, a private IP, or a single-label sidecar name")
	}
	if len(token) < 32 {
		return nil, errors.New("traffic transform runner token must contain at least 32 characters")
	}
	if client == nil {
		return nil, errors.New("traffic transform runner HTTP client is required")
	}
	parsed.Path = ""
	return &HTTPClient{endpoint: parsed, token: token, client: client}, nil
}

func privateRunnerHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	if strings.Contains(host, ".") || strings.ContainsAny(host, "/:@?#[]\r\n\x00") {
		return false
	}
	if host == "" || len(host) > 63 || strings.HasPrefix(host, "-") || strings.HasSuffix(host, "-") {
		return false
	}
	for _, char := range host {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func (c *HTTPClient) Health(ctx context.Context) (RunnerHealth, error) {
	var health RunnerHealth
	if err := c.request(ctx, http.MethodGet, "/v1/health", nil, &health); err != nil {
		return RunnerHealth{}, err
	}
	if health.Status != "ok" || health.ProtocolVersion != ProtocolVersion || strings.TrimSpace(health.RunnerGeneration) == "" {
		return RunnerHealth{}, errors.New("traffic transform runner returned invalid health identity")
	}
	return health, nil
}

func (c *HTTPClient) LoadRevision(ctx context.Context, revision Revision) (LoadResult, error) {
	if revision.ID == "" || revision.SourceSHA256 != SourceDigest(revision.Source) {
		return LoadResult{}, errors.New("traffic transform revision identity or digest is invalid")
	}
	prepared, report := PrepareRevision(revision, DefaultRunnerInventory())
	if !report.Valid {
		return LoadResult{}, fmt.Errorf("traffic transform revision failed static validation: %s", report.Issues[0].Message)
	}
	request := struct {
		RevisionID   string   `json:"revisionId"`
		SourceSHA256 string   `json:"sourceSha256"`
		Source       string   `json:"source"`
		Manifest     Manifest `json:"manifest"`
	}{
		RevisionID: prepared.ID, SourceSHA256: prepared.SourceSHA256,
		Source: prepared.Source, Manifest: ManifestForRevision(prepared),
	}
	var result LoadResult
	if err := c.request(ctx, http.MethodPost, "/v1/revisions/load", request, &result); err != nil {
		return LoadResult{}, err
	}
	if result.ProtocolVersion != ProtocolVersion || result.RevisionID != revision.ID || result.SourceSHA256 != revision.SourceSHA256 || !result.Valid || strings.TrimSpace(result.RunnerGeneration) == "" {
		return LoadResult{}, errors.New("traffic transform runner load identity mismatch")
	}
	return result, nil
}

func (c *HTTPClient) Invoke(ctx context.Context, invocation Invocation) (Result, error) {
	if err := ValidateInvocation(invocation); err != nil {
		return Result{}, err
	}
	deadline := time.Duration(invocation.DeadlineMS) * time.Millisecond
	callCtx, cancel := context.WithTimeout(ctx, deadline+100*time.Millisecond)
	defer cancel()
	var result Result
	if err := c.request(callCtx, http.MethodPost, "/v1/invoke", invocation, &result); err != nil {
		return Result{}, err
	}
	if err := ValidateResult(invocation, result); err != nil {
		return Result{}, fmt.Errorf("validate traffic transform runner result: %w", err)
	}
	return result, nil
}

type runnerErrorEnvelope struct {
	Error *TransformError `json:"error"`
}

func (c *HTTPClient) request(ctx context.Context, method, path string, input any, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		if len(encoded) > MaxInvocationBytes {
			return errors.New("traffic transform runner request is too large")
		}
		body = bytes.NewReader(encoded)
	}
	target := *c.endpoint
	target.Path = path
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("call traffic transform runner: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxRunnerResponseBytes+1)
	encoded, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read traffic transform runner response: %w", err)
	}
	if len(encoded) > maxRunnerResponseBytes {
		return errors.New("traffic transform runner response is too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope runnerErrorEnvelope
		if json.Unmarshal(encoded, &envelope) == nil && envelope.Error != nil {
			return fmt.Errorf("traffic transform runner %s: %s", envelope.Error.Code, envelope.Error.Message)
		}
		return fmt.Errorf("traffic transform runner returned HTTP %d", response.StatusCode)
	}
	if err := json.Unmarshal(encoded, output); err != nil {
		return fmt.Errorf("decode traffic transform runner response: %w", err)
	}
	return nil
}
