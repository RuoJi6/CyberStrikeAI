package asm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/database"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	ProviderARL         = "arl"
	ProviderXingRin     = "xingrin"
	ProviderScopeSentry = "scopesentry"
)

type ProviderInfo struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Implemented  bool     `json:"implemented"`
	Capabilities []string `json:"capabilities"`
}

type ResourceView struct {
	ID                string                    `json:"id"`
	Name              string                    `json:"name"`
	Provider          string                    `json:"provider"`
	BaseURL           string                    `json:"base_url"`
	Username          string                    `json:"username,omitempty"`
	AuthType          string                    `json:"auth_type"`
	VerifyTLS         bool                      `json:"verify_tls"`
	Enabled           bool                      `json:"enabled"`
	Status            string                    `json:"status"`
	LastError         string                    `json:"last_error,omitempty"`
	LastTestAt        *time.Time                `json:"last_test_at,omitempty"`
	HasCredential     bool                      `json:"has_credential"`
	Capabilities      []string                  `json:"capabilities"`
	ProviderReady     bool                      `json:"provider_ready"`
	AgentContinuation AgentContinuationSettings `json:"agent_continuation"`
	CreatedAt         time.Time                 `json:"created_at"`
	UpdatedAt         time.Time                 `json:"updated_at"`
}

type CreateResourceInput struct {
	Name              string
	Provider          string
	BaseURL           string
	Username          string
	Credential        string
	AuthType          string
	VerifyTLS         *bool
	Enabled           *bool
	AgentContinuation *AgentContinuationSettings
}

type UpdateResourceInput struct {
	Name              *string
	Provider          *string
	BaseURL           *string
	Username          *string
	Credential        *string
	AuthType          *string
	VerifyTLS         *bool
	Enabled           *bool
	AgentContinuation *AgentContinuationSettings
}

type TaskRequest struct {
	Name           string                 `json:"name"`
	Target         string                 `json:"target"`
	Options        map[string]interface{} `json:"options,omitempty"`
	ConversationID string                 `json:"-"`
	OwnerUserID    string                 `json:"-"`
}

// TemplateRequest describes a provider-native scan template created through
// typed, audited settings. Adapters must not interpret Options as arbitrary
// upstream command lines.
type TemplateRequest struct {
	Name           string                 `json:"name"`
	PresetID       string                 `json:"preset_id,omitempty"`
	BaseTemplateID string                 `json:"base_template_id,omitempty"`
	Options        map[string]interface{} `json:"options,omitempty"`
}

type TaskFilter struct {
	TaskID   string
	Name     string
	Target   string
	Status   string
	Page     int
	PageSize int
}

type AssetFilter struct {
	TaskID   string
	Type     string
	Query    string
	Page     int
	PageSize int
}

type AssetDetailFilter struct {
	Type string
	Key  string
}

// ResultType describes one provider-native result collection. The ID is sent
// to ListAssets while Label is safe display metadata for the task center and
// Agent profile discovery.
type ResultType struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Default bool   `json:"default,omitempty"`
}

func providerResultTypes(provider string) []ResultType {
	switch normalizeProvider(provider) {
	case ProviderARL:
		return []ResultType{
			{ID: "site", Label: "站点", Default: true},
			{ID: "domain", Label: "子域名"},
			{ID: "ip", Label: "IP"},
			{ID: "cert", Label: "SSL 证书"},
			{ID: "service", Label: "服务"},
			{ID: "fileleak", Label: "文件泄露"},
			{ID: "url", Label: "URL 信息"},
			{ID: "vulnerability", Label: "风险"},
			{ID: "npoc_service", Label: "服务 (Python)"},
			{ID: "cip", Label: "C 段"},
			{ID: "nuclei_result", Label: "Nuclei"},
			{ID: "stat_finger", Label: "指纹统计"},
			{ID: "wih", Label: "WIH"},
		}
	case ProviderXingRin:
		return []ResultType{
			{ID: "site", Label: "站点", Default: true}, {ID: "domain", Label: "子域名"},
			{ID: "ip", Label: "IP"}, {ID: "url", Label: "端点 / URL"},
			{ID: "service", Label: "端口 / 服务"}, {ID: "directory", Label: "目录扫描"},
			{ID: "vulnerability", Label: "漏洞"}, {ID: "screenshot", Label: "站点截图"},
		}
	case ProviderScopeSentry:
		return []ResultType{
			{ID: "site", Label: "资产 / 站点", Default: true}, {ID: "domain", Label: "子域名"},
			{ID: "ip", Label: "IP"}, {ID: "url", Label: "URL"},
			{ID: "service", Label: "IP / 服务"}, {ID: "crawler", Label: "爬虫结果"},
			{ID: "sensitive", Label: "敏感信息"}, {ID: "directory", Label: "目录扫描"},
			{ID: "takeover", Label: "子域接管"}, {ID: "vulnerability", Label: "漏洞"},
		}
	default:
		return []ResultType{{ID: "site", Label: "站点", Default: true}}
	}
}

func providerSupportsResultType(provider, resultType string) bool {
	resultType = strings.ToLower(strings.TrimSpace(resultType))
	for _, item := range providerResultTypes(provider) {
		if item.ID == resultType {
			return true
		}
	}
	return false
}

type TaskOptionFilter struct {
	Kind     string
	Query    string
	ID       string
	Page     int
	PageSize int
}

type TaskOptionSkip struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

type AllTaskOptionsResult struct {
	Provider       string                 `json:"provider"`
	ResourceID     string                 `json:"resource_id"`
	Kind           string                 `json:"kind"`
	Query          string                 `json:"query,omitempty"`
	Page           int                    `json:"page"`
	PageSize       int                    `json:"page_size"`
	SupportedKinds []string               `json:"supported_kinds"`
	QueriedKinds   []string               `json:"queried_kinds"`
	SkippedKinds   []TaskOptionSkip       `json:"skipped_kinds,omitempty"`
	Options        map[string]interface{} `json:"options"`
	Errors         map[string]string      `json:"errors,omitempty"`
	Partial        bool                   `json:"partial"`
}

type TaskManageRequest struct {
	Action         string
	TaskID         string
	Options        map[string]interface{}
	ConversationID string `json:"-"`
	OwnerUserID    string `json:"-"`
}

type Connection struct {
	Resource *database.ASMResource
	Secret   string
}

type Adapter interface {
	Provider() string
	Capabilities() []string
	Test(context.Context, *Connection) (interface{}, error)
	CreateTask(context.Context, *Connection, TaskRequest) (interface{}, error)
	ListTasks(context.Context, *Connection, TaskFilter) (interface{}, error)
	GetTask(context.Context, *Connection, string) (interface{}, error)
	ListAssets(context.Context, *Connection, AssetFilter) (interface{}, error)
	StopTask(context.Context, *Connection, string) (interface{}, error)
}

// TaskProfileAdapter exposes provider-specific task creation metadata and
// dynamic upstream choices without forcing every adapter to implement it.
type TaskProfileAdapter interface {
	GetTaskProfile(context.Context, *Connection) (interface{}, error)
	ListTaskOptions(context.Context, *Connection, TaskOptionFilter) (interface{}, error)
}

// TaskManagerAdapter exposes provider-specific lifecycle actions beyond stop.
type TaskManagerAdapter interface {
	ManageTask(context.Context, *Connection, TaskManageRequest) (interface{}, error)
}

// TemplateCreatorAdapter is implemented only by providers that expose a safe
// template-save API. The service keeps this separate from generic task
// creation so callers can inspect and explicitly select the created template.
type TemplateCreatorAdapter interface {
	CreateTemplate(context.Context, *Connection, TemplateRequest) (interface{}, error)
}

// AssetDetailAdapter exposes result details that the upstream stores outside
// the paginated list payload (for example vulnerability request/response).
type AssetDetailAdapter interface {
	GetAssetDetail(context.Context, *Connection, AssetDetailFilter) (interface{}, error)
}

type Service struct {
	db                 *database.DB
	cipher             *credentialCipher
	logger             *zap.Logger
	adapters           map[string]Adapter
	screenshotDir      string
	screenshotMu       sync.Mutex
	screenshotJobs     map[string]bool
	screenshotErrors   map[string]string
	resultSyncMu       sync.Mutex
	resultSyncJobs     map[string]bool
	resultSyncSem      chan struct{}
	continuationMu     sync.Mutex
	continuationJobs   map[string]bool
	agentRunning       func(string) bool
	continuationRunner func(context.Context, *database.ASMAgentContinuation, string) error
	workerCtx          context.Context
}

func NewService(db *database.DB, databasePath string, logger *zap.Logger) (*Service, error) {
	if db == nil {
		return nil, fmt.Errorf("ASM 服务需要数据库")
	}
	cipher, err := newCredentialCipher(databasePath)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	service := &Service{
		db: db, cipher: cipher, logger: logger, adapters: make(map[string]Adapter),
		screenshotDir:  filepath.Join(filepath.Dir(databasePath), "asm_screenshots"),
		screenshotJobs: make(map[string]bool), screenshotErrors: make(map[string]string),
		resultSyncJobs: make(map[string]bool), resultSyncSem: make(chan struct{}, 1),
		continuationJobs: make(map[string]bool),
		workerCtx:        context.Background(),
	}
	service.RegisterAdapter(NewARLAdapter())
	service.RegisterAdapter(NewXingRinAdapter())
	service.RegisterAdapter(NewScopeSentryAdapter())
	return service, nil
}

func (s *Service) RegisterAdapter(adapter Adapter) {
	if adapter == nil {
		return
	}
	provider := normalizeProvider(adapter.Provider())
	if provider != "" {
		s.adapters[provider] = adapter
	}
}

func normalizeProvider(value string) string {
	provider := strings.ToLower(strings.TrimSpace(value))
	switch provider {
	case "lighthouse", "arl-lighthouse", "灯塔":
		return ProviderARL
	case "xingrin", "xinghuan", "星环":
		return ProviderXingRin
	case "scope-sentry", "scope_sentry":
		return ProviderScopeSentry
	default:
		return provider
	}
}

func providerDisplayName(provider string) string {
	switch provider {
	case ProviderARL:
		return "ARL / 灯塔"
	case ProviderXingRin:
		return "XingRin / 星环"
	case ProviderScopeSentry:
		return "ScopeSentry"
	default:
		return provider
	}
}

func (s *Service) Providers() []ProviderInfo {
	providers := []string{ProviderARL, ProviderXingRin, ProviderScopeSentry}
	result := make([]ProviderInfo, 0, len(providers))
	for _, provider := range providers {
		adapter, ok := s.adapters[provider]
		info := ProviderInfo{ID: provider, Name: providerDisplayName(provider), Implemented: ok, Capabilities: []string{}}
		if ok {
			info.Capabilities = append(info.Capabilities, adapter.Capabilities()...)
		}
		result = append(result, info)
	}
	return result
}

func (s *Service) ListResources(enabledOnly bool) ([]ResourceView, error) {
	items, err := s.db.ListASMResources(enabledOnly)
	if err != nil {
		return nil, err
	}
	views := make([]ResourceView, 0, len(items))
	for _, item := range items {
		views = append(views, s.resourceView(item))
	}
	return views, nil
}

func (s *Service) GetResource(id string) (ResourceView, error) {
	item, err := s.db.GetASMResource(id)
	if err != nil {
		return ResourceView{}, err
	}
	return s.resourceView(item), nil
}

func (s *Service) resourceView(item *database.ASMResource) ResourceView {
	adapter, ready := s.adapters[normalizeProvider(item.Provider)]
	capabilities := []string{}
	if ready {
		capabilities = append(capabilities, adapter.Capabilities()...)
	}
	sort.Strings(capabilities)
	return ResourceView{
		ID: item.ID, Name: item.Name, Provider: item.Provider, BaseURL: item.BaseURL,
		Username: item.Username, AuthType: item.AuthType, VerifyTLS: item.VerifyTLS,
		Enabled: item.Enabled, Status: item.Status, LastError: item.LastError,
		LastTestAt: item.LastTestAt, HasCredential: item.SecretCiphertext != "",
		Capabilities: capabilities, ProviderReady: ready,
		AgentContinuation: resourceAgentContinuation(item),
		CreatedAt:         item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

func validateResourceFields(name, provider, baseURL, username, authType string) (string, string, string, string, string, error) {
	name = strings.TrimSpace(name)
	provider = normalizeProvider(provider)
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	username = strings.TrimSpace(username)
	authType = strings.ToLower(strings.TrimSpace(authType))
	if authType == "" {
		authType = "password"
	}
	if name == "" || len(name) > 100 {
		return "", "", "", "", "", fmt.Errorf("名称不能为空且不能超过 100 字符")
	}
	if provider != ProviderARL && provider != ProviderXingRin && provider != ProviderScopeSentry {
		return "", "", "", "", "", fmt.Errorf("不支持的 ASM 类型: %s", provider)
	}
	if len(baseURL) > 2048 {
		return "", "", "", "", "", fmt.Errorf("ASM 地址过长")
	}
	parsed, err := url.ParseRequestURI(baseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", "", "", "", "", fmt.Errorf("ASM 地址必须是有效的 http 或 https URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", "", "", "", fmt.Errorf("ASM 地址不能包含凭据、查询参数或片段")
	}
	if len(username) > 200 {
		return "", "", "", "", "", fmt.Errorf("用户名过长")
	}
	if authType != "password" && authType != "api_key" {
		return "", "", "", "", "", fmt.Errorf("认证类型仅支持 password 或 api_key")
	}
	return name, provider, baseURL, username, authType, nil
}

func (s *Service) CreateResource(input CreateResourceInput) (ResourceView, error) {
	name, provider, baseURL, username, authType, err := validateResourceFields(input.Name, input.Provider, input.BaseURL, input.Username, input.AuthType)
	if err != nil {
		return ResourceView{}, err
	}
	if _, ready := s.adapters[provider]; !ready {
		return ResourceView{}, fmt.Errorf("%s 适配器尚未完成", providerDisplayName(provider))
	}
	if len(input.Credential) > 8192 {
		return ResourceView{}, fmt.Errorf("凭据过长")
	}
	if strings.TrimSpace(input.Credential) == "" {
		return ResourceView{}, fmt.Errorf("凭据不能为空")
	}
	verifyTLS, enabled := true, true
	if input.VerifyTLS != nil {
		verifyTLS = *input.VerifyTLS
	}
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	id := "asm_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	ciphertext, err := s.cipher.encrypt(id, input.Credential)
	if err != nil {
		return ResourceView{}, err
	}
	item := &database.ASMResource{
		ID: id, Name: name, Provider: provider, BaseURL: baseURL, Username: username,
		SecretCiphertext: ciphertext, AuthType: authType, VerifyTLS: verifyTLS,
		Enabled: enabled, Status: "unknown", MetadataJSON: encodeResourceAgentContinuation(input.AgentContinuation, "{}"),
	}
	if err := s.db.CreateASMResource(item); err != nil {
		return ResourceView{}, err
	}
	return s.resourceView(item), nil
}

func (s *Service) UpdateResource(id string, input UpdateResourceInput) (ResourceView, error) {
	item, err := s.db.GetASMResource(id)
	if err != nil {
		return ResourceView{}, err
	}
	name, provider, baseURL, username, authType := item.Name, item.Provider, item.BaseURL, item.Username, item.AuthType
	if input.Name != nil {
		name = *input.Name
	}
	if input.Provider != nil {
		provider = *input.Provider
	}
	if input.BaseURL != nil {
		baseURL = *input.BaseURL
	}
	if input.Username != nil {
		username = *input.Username
	}
	if input.AuthType != nil {
		authType = *input.AuthType
	}
	name, provider, baseURL, username, authType, err = validateResourceFields(name, provider, baseURL, username, authType)
	if err != nil {
		return ResourceView{}, err
	}
	if _, ready := s.adapters[provider]; !ready {
		return ResourceView{}, fmt.Errorf("%s 适配器尚未完成", providerDisplayName(provider))
	}
	item.Name, item.Provider, item.BaseURL, item.Username, item.AuthType = name, provider, baseURL, username, authType
	if input.VerifyTLS != nil {
		item.VerifyTLS = *input.VerifyTLS
	}
	if input.Enabled != nil {
		item.Enabled = *input.Enabled
	}
	if input.AgentContinuation != nil {
		item.MetadataJSON = encodeResourceAgentContinuation(input.AgentContinuation, item.MetadataJSON)
	}
	if input.Credential != nil && *input.Credential != "" {
		if len(*input.Credential) > 8192 {
			return ResourceView{}, fmt.Errorf("凭据过长")
		}
		item.SecretCiphertext, err = s.cipher.encrypt(item.ID, *input.Credential)
		if err != nil {
			return ResourceView{}, err
		}
	}
	item.Status, item.LastError = "unknown", ""
	if err := s.db.UpdateASMResource(item); err != nil {
		return ResourceView{}, err
	}
	return s.resourceView(item), nil
}

func (s *Service) DeleteResource(id string) error {
	return s.db.DeleteASMResource(id)
}

func (s *Service) connection(id string, requireEnabled bool) (*Connection, Adapter, error) {
	item, err := s.db.GetASMResource(strings.TrimSpace(id))
	if err != nil {
		return nil, nil, err
	}
	if requireEnabled && !item.Enabled {
		return nil, nil, fmt.Errorf("ASM 资源已禁用")
	}
	adapter, ok := s.adapters[normalizeProvider(item.Provider)]
	if !ok {
		return nil, nil, fmt.Errorf("%s 适配器尚未完成", providerDisplayName(item.Provider))
	}
	secret, err := s.cipher.decrypt(item.ID, item.SecretCiphertext)
	if err != nil {
		return nil, nil, err
	}
	return &Connection{Resource: item, Secret: secret}, adapter, nil
}

func truncateError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > 1000 {
		value = value[:1000]
	}
	return value
}

func (s *Service) TestConnection(ctx context.Context, id string) (interface{}, error) {
	conn, adapter, err := s.connection(id, false)
	if err != nil {
		return nil, err
	}
	result, testErr := adapter.Test(ctx, conn)
	now := time.Now().UTC()
	conn.Resource.LastTestAt = &now
	if testErr != nil {
		conn.Resource.Status = "error"
		conn.Resource.LastError = truncateError(testErr)
	} else {
		conn.Resource.Status = "connected"
		conn.Resource.LastError = ""
	}
	if updateErr := s.db.UpdateASMResource(conn.Resource); updateErr != nil {
		s.logger.Warn("更新 ASM 连接状态失败", zap.String("resource_id", id), zap.Error(updateErr))
	}
	return result, testErr
}

func (s *Service) GetTaskProfile(ctx context.Context, resourceID string) (interface{}, error) {
	conn, adapter, err := s.connection(resourceID, true)
	if err != nil {
		return nil, err
	}
	profiler, ok := adapter.(TaskProfileAdapter)
	if !ok {
		return nil, fmt.Errorf("%s 暂未提供任务创建配置发现能力", providerDisplayName(conn.Resource.Provider))
	}
	profile, err := profiler.GetTaskProfile(ctx, conn)
	if err != nil {
		return nil, err
	}
	if object := valueMap(profile); object != nil {
		presets := templatePresetsForProvider(conn.Resource.Provider)
		if len(presets) > 0 {
			object["template_presets"] = presets
			object["template_preset_query"] = "asm_list_task_options(kind=template_presets)"
			templateKind := "task_template"
			if normalizeProvider(conn.Resource.Provider) == ProviderARL {
				templateKind = "policy"
			}
			object["template_creation"] = map[string]interface{}{
				"tool": "asm_create_template", "provider_kind": templateKind,
				"recommended_mode": "preset_id", "idempotent_presets": true,
			}
			kinds := taskOptionKinds(object)
			found := false
			for _, kind := range kinds {
				if kind == "template_presets" {
					found = true
					break
				}
			}
			if !found {
				object["dynamic_option_kinds"] = append(kinds, "template_presets")
			}
		}
		object["task_option_query_modes"] = []string{"single", "all"}
		object["task_option_all_note"] = "kind=all 会按当前分页批量读取所有列表型动态选项；*_detail 类型需要 id，必须单独查询"
		return object, nil
	}
	return profile, nil
}

func taskOptionKinds(profile interface{}) []string {
	object := valueMap(profile)
	if object == nil {
		return nil
	}
	raw, exists := object["dynamic_option_kinds"]
	if !exists {
		return nil
	}
	result := make([]string, 0)
	seen := make(map[string]struct{})
	appendKind := func(value interface{}) {
		kind := strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
		if kind == "" || kind == "all" {
			return
		}
		if _, exists := seen[kind]; exists {
			return
		}
		seen[kind] = struct{}{}
		result = append(result, kind)
	}
	switch values := raw.(type) {
	case []string:
		for _, value := range values {
			appendKind(value)
		}
	case []interface{}:
		for _, value := range values {
			appendKind(value)
		}
	default:
		appendKind(values)
	}
	return result
}

func taskOptionPayload(value interface{}) interface{} {
	if object := valueMap(value); object != nil {
		if options, exists := object["options"]; exists {
			return options
		}
	}
	return value
}

func (s *Service) listAllTaskOptions(ctx context.Context, conn *Connection, profiler TaskProfileAdapter, filter TaskOptionFilter) (AllTaskOptionsResult, error) {
	profile, err := profiler.GetTaskProfile(ctx, conn)
	if err != nil {
		return AllTaskOptionsResult{}, err
	}
	kinds := taskOptionKinds(profile)
	if len(templatePresetsForProvider(conn.Resource.Provider)) > 0 {
		found := false
		for _, kind := range kinds {
			if kind == "template_presets" {
				found = true
				break
			}
		}
		if !found {
			kinds = append(kinds, "template_presets")
		}
	}
	if len(kinds) == 0 {
		return AllTaskOptionsResult{}, fmt.Errorf("%s 未声明可查询的动态选项类别", providerDisplayName(conn.Resource.Provider))
	}
	result := AllTaskOptionsResult{
		Provider: normalizeProvider(conn.Resource.Provider), ResourceID: conn.Resource.ID, Kind: "all",
		Query: filter.Query, Page: filter.Page, PageSize: filter.PageSize,
		SupportedKinds: kinds, QueriedKinds: []string{}, SkippedKinds: []TaskOptionSkip{},
		Options: map[string]interface{}{}, Errors: map[string]string{},
	}
	for _, kind := range kinds {
		if strings.HasSuffix(kind, "_detail") {
			result.SkippedKinds = append(result.SkippedKinds, TaskOptionSkip{
				Kind: kind, Reason: "该类型需要 id，请使用具体 kind 和 id 单独查询",
			})
			continue
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		child := filter
		child.Kind = kind
		child.ID = ""
		result.QueriedKinds = append(result.QueriedKinds, kind)
		var value interface{}
		var optionErr error
		if kind == "template_presets" {
			presets := templatePresetsForProvider(conn.Resource.Provider)
			value = map[string]interface{}{
				"provider": normalizeProvider(conn.Resource.Provider), "resource_id": conn.Resource.ID,
				"kind": kind, "options": map[string]interface{}{"items": presets, "total": len(presets)},
			}
		} else {
			value, optionErr = profiler.ListTaskOptions(ctx, conn, child)
		}
		if optionErr != nil {
			result.Errors[kind] = truncateError(optionErr)
			continue
		}
		result.Options[kind] = taskOptionPayload(value)
	}
	result.Partial = len(result.Errors) > 0
	if !result.Partial {
		result.Errors = nil
	}
	return result, nil
}

func (s *Service) ListTaskOptions(ctx context.Context, resourceID string, filter TaskOptionFilter) (interface{}, error) {
	conn, adapter, err := s.connection(resourceID, true)
	if err != nil {
		return nil, err
	}
	profiler, ok := adapter.(TaskProfileAdapter)
	if !ok {
		return nil, fmt.Errorf("%s 暂未提供任务动态选项查询能力", providerDisplayName(conn.Resource.Provider))
	}
	filter.Kind = strings.ToLower(strings.TrimSpace(filter.Kind))
	filter.Query = strings.TrimSpace(filter.Query)
	filter.ID = strings.TrimSpace(filter.ID)
	filter.Page, filter.PageSize = normalizePagination(filter.Page, filter.PageSize)
	if filter.Kind == "template_presets" {
		presets := templatePresetsForProvider(conn.Resource.Provider)
		if len(presets) == 0 {
			return nil, fmt.Errorf("%s 暂未提供内置扫描模板", providerDisplayName(conn.Resource.Provider))
		}
		return map[string]interface{}{
			"provider": normalizeProvider(conn.Resource.Provider), "resource_id": conn.Resource.ID,
			"kind": filter.Kind, "options": map[string]interface{}{"items": presets, "total": len(presets)},
		}, nil
	}
	if filter.Kind == "all" {
		return s.listAllTaskOptions(ctx, conn, profiler, filter)
	}
	return profiler.ListTaskOptions(ctx, conn, filter)
}

func (s *Service) ManageTask(ctx context.Context, resourceID string, req TaskManageRequest) (interface{}, error) {
	conn, adapter, err := s.connection(resourceID, true)
	if err != nil {
		return nil, err
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	req.TaskID = strings.TrimSpace(req.TaskID)
	if req.Action == "" {
		return nil, fmt.Errorf("任务管理 action 不能为空")
	}
	if req.Options == nil {
		req.Options = map[string]interface{}{}
	}
	if req.Action == "sync_results" {
		item, findErr := s.db.FindASMTask(resourceID, req.TaskID)
		if findErr != nil {
			return nil, findErr
		}
		if item == nil {
			return nil, fmt.Errorf("ASM 本地任务记录不存在，请先调用 asm_list_tasks 导入任务")
		}
		return s.SyncTaskResults(ctx, item.ID)
	}
	manager, ok := adapter.(TaskManagerAdapter)
	if !ok {
		return nil, fmt.Errorf("%s 暂未提供扩展任务管理能力", providerDisplayName(conn.Resource.Provider))
	}
	result, err := manager.ManageTask(ctx, conn, req)
	if err != nil {
		return nil, err
	}
	updated := false
	var managedTask *database.ASMTask
	switch req.Action {
	case "restart", "resume":
		updated = s.recordTaskLifecycle(conn.Resource.ID, req.TaskID, "running", req.Action, true)
		if updated {
			managedTask, _ = s.db.FindASMTask(conn.Resource.ID, req.TaskID)
		}
	case "delete":
		updated = s.recordTaskLifecycle(conn.Resource.ID, req.TaskID, "stopped", "deleted", false)
	}
	object := valueMap(result)
	if object == nil && (req.Action == "restart" || req.Action == "resume") {
		object = map[string]interface{}{"provider_response": result}
	}
	if object != nil {
		object["local_history_updated"] = updated
		if req.Action == "restart" || req.Action == "resume" {
			if managedTask != nil {
				object["local_task_id"] = managedTask.ID
				object["local_task_ids"] = []string{managedTask.ID}
			}
			s.attachAgentContinuation(conn, TaskRequest{
				ConversationID: req.ConversationID,
				OwnerUserID:    req.OwnerUserID,
			}, object)
		}
		return object, nil
	}
	return result, nil
}

func (s *Service) CreateTask(ctx context.Context, resourceID string, req TaskRequest) (interface{}, error) {
	conn, adapter, err := s.connection(resourceID, true)
	if err != nil {
		return nil, err
	}
	result, err := adapter.CreateTask(ctx, conn, req)
	if err != nil {
		return nil, err
	}
	recorded := s.recordCreatedTask(conn, req, result)
	s.attachAgentContinuation(conn, req, recorded)
	return recorded, nil
}

func (s *Service) CreateTemplate(ctx context.Context, resourceID string, req TemplateRequest) (interface{}, error) {
	conn, adapter, err := s.connection(resourceID, true)
	if err != nil {
		return nil, err
	}
	creator, ok := adapter.(TemplateCreatorAdapter)
	if !ok {
		return nil, fmt.Errorf("%s 暂未提供扫描模板创建能力", providerDisplayName(conn.Resource.Provider))
	}
	if req.Options == nil {
		req.Options = map[string]interface{}{}
	}
	req, err = applyTemplatePreset(conn.Resource.Provider, req)
	if err != nil {
		return nil, err
	}
	return creator.CreateTemplate(ctx, conn, req)
}

func (s *Service) ListTasks(ctx context.Context, resourceID string, filter TaskFilter) (interface{}, error) {
	conn, adapter, err := s.connection(resourceID, true)
	if err != nil {
		return nil, err
	}
	result, err := adapter.ListTasks(ctx, conn, filter)
	if err != nil {
		return nil, err
	}
	s.recordListedTasks(conn, result)
	return result, nil
}

func (s *Service) GetTask(ctx context.Context, resourceID, taskID string) (interface{}, error) {
	conn, adapter, err := s.connection(resourceID, true)
	if err != nil {
		return nil, err
	}
	taskID = strings.TrimSpace(taskID)
	result, err := adapter.GetTask(ctx, conn, taskID)
	if err != nil {
		return nil, err
	}
	s.recordTaskDetail(conn, taskID, result)
	return result, nil
}

func (s *Service) ListAssets(ctx context.Context, resourceID string, filter AssetFilter) (interface{}, error) {
	conn, _, err := s.connection(resourceID, true)
	if err != nil {
		return nil, err
	}
	if filter.Type != "" && !providerSupportsResultType(conn.Resource.Provider, filter.Type) {
		return nil, fmt.Errorf("%s 不支持结果类型: %s；请先读取 asm_get_task_profile.result_types", providerDisplayName(conn.Resource.Provider), filter.Type)
	}
	if strings.TrimSpace(filter.TaskID) == "" {
		return nil, fmt.Errorf("本地结果查询必须提供 task_id")
	}
	task, err := s.db.FindASMTask(resourceID, filter.TaskID)
	if err != nil {
		return nil, err
	}
	if task == nil {
		return nil, fmt.Errorf("ASM 本地任务记录不存在，请先调用 asm_list_tasks 导入任务")
	}
	resultType := normalizeAssetType(filter.Type)
	state := s.resultSyncView(task)
	if task.Status == "completed" && !state.typeCompleted(resultType) && state.typeStatus(resultType) != "syncing" {
		if _, syncErr := s.syncTaskResultType(ctx, task, resultType); syncErr != nil {
			s.logger.Warn("MCP 首次读取 ASM 本地结果同步失败", zap.String("task_id", task.ID), zap.String("asset_type", resultType), zap.Error(syncErr))
		}
	}
	return s.ListTaskHistoryResults(ctx, task.ID, filter)
}

func (s *Service) StopTask(ctx context.Context, resourceID, taskID string) (interface{}, error) {
	conn, adapter, err := s.connection(resourceID, true)
	if err != nil {
		return nil, err
	}
	taskID = strings.TrimSpace(taskID)
	result, err := adapter.StopTask(ctx, conn, taskID)
	if err != nil {
		return nil, err
	}
	updated := s.recordTaskLifecycle(conn.Resource.ID, taskID, "stopped", "stopped", false)
	if object := valueMap(result); object != nil {
		object["local_history_updated"] = updated
		return object, nil
	}
	return result, nil
}

func MarshalResult(value interface{}) string {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(raw)
}
