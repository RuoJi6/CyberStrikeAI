package app

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/traffic"
	"cyberstrike-ai/internal/traffictransform"

	"go.uber.org/zap"
)

type trafficTransformRunner interface {
	traffictransform.Client
	traffictransform.RevisionLoader
}

func registerTrafficTransformTools(server *mcp.Server, db *database.DB, runner trafficTransformRunner, logger *zap.Logger) {
	if server == nil || db == nil {
		return
	}
	registerListTrafficTransactionsTool(server, db)
	registerGetTrafficTransactionTool(server, db)
	registerLinkTrafficEvidenceTool(server, db)
	registerConfigureTrafficDecoderTool(server, db, runner)
	registerManageTrafficTransformTool(server, db)
	registerCreateTrafficTransformTool(server, db)
	registerValidateTrafficTransformTool(server, db, runner)
	registerTestTrafficTransformTool(server, db, runner)
	registerActivateTrafficTransformTool(server, db)
	registerDeactivateTrafficTransformTool(server, db)
	if logger != nil {
		logger.Info("MITM 流量证据与 Traffic Transform MCP 工具已注册", zap.Bool("runner_available", runner != nil))
	}
}

func registerConfigureTrafficDecoderTool(server *mcp.Server, db *database.DB, runner trafficTransformRunner) {
	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolConfigureTrafficDecoder,
		Description:      "配置一个网站的 MITM 旁路解密脚本。普通加解密任务优先使用本工具，并先加载 traffic-transform-authoring Skill。只需提供历史事务、方向和 Python 源码；工具会自动确定 decode Hook 和依赖，并一次完成创建、Runner 校验、历史包试跑，以及用户明确要求时的按站点启用。不要为探测 SDK 创建 probe/diag 脚本；失败后最多在返回的 transformId 下修正一次。当前只生成抓包后的明文证据，不修改真实发包。",
		ShortDescription: "一次完成网站流量解密脚本的创建、校验、试跑与可选启用",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"transaction_id": map[string]interface{}{"type": "string", "description": "当前对话中的一条完整历史事务 ID"},
				"direction": map[string]interface{}{
					"type": "string", "enum": []string{"request", "response", "both"},
					"description": "解密请求、响应或两者；默认 request",
				},
				"source": map[string]interface{}{
					"type":        "string",
					"description": "完整 transform.py。优先使用 @body_decoder：函数体只接收 body: bytes 并返回 bytes/str/None",
				},
				"transform_id": map[string]interface{}{"type": "string", "description": "仅修正已有脚本时填写；不要为每次修正创建新 Transform"},
				"name":         map[string]interface{}{"type": "string", "description": "新脚本名称；transform_id 为空时必填"},
				"description":  map[string]interface{}{"type": "string", "description": "算法、密钥来源和适用接口的简短说明"},
				"config":       map[string]interface{}{"type": "object", "description": "可选的 Agent 已知脚本配置"},
				"activate":     map[string]interface{}{"type": "boolean", "description": "只有用户明确要求启用时设为 true；默认 false"},
				"path_prefix":  map[string]interface{}{"type": "string", "description": "启用时可选的路径前缀，例如 /api/；站点固定取历史事务的精确 host"},
				"method":       map[string]interface{}{"type": "string", "description": "启用时可选的 HTTP 方法限制"},
			},
			"required":             []string{"transaction_id", "source"},
			"additionalProperties": false,
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if runner == nil {
			return textResult("错误: Traffic Transform Runner 未配置或不可用", true), nil
		}
		conversationID := conversationIDFromToolCtx(ctx)
		if conversationID == "" {
			return textResult("错误: 无法确定当前对话", true), nil
		}
		detail, err := db.GetTrafficTransaction(ctx, strings.TrimSpace(strArg(args, "transaction_id")))
		if err != nil || !trafficDetailBelongsToConversation(db, detail, conversationID) {
			return textResult("错误: 流量事务不存在或不属于当前项目/对话", true), nil
		}
		directions, hooks, err := decoderDirections(strArg(args, "direction"))
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		messages := make(map[string]traffic.Message, len(directions))
		for _, direction := range directions {
			message, selectErr := selectTrafficMessage(detail.Messages, direction)
			if selectErr != nil {
				return textResult("错误: "+selectErr.Error(), true), nil
			}
			messages[direction] = message
		}

		principal, _ := authctx.PrincipalFromContext(ctx)
		transformID := strings.TrimSpace(strArg(args, "transform_id"))
		var transform *traffictransform.Transform
		if transformID == "" {
			name := strings.TrimSpace(strArg(args, "name"))
			if name == "" {
				return textResult("错误: 新建解密脚本时 name 必填", true), nil
			}
			projectID, _ := db.GetConversationProjectID(conversationID)
			transform, err = db.CreateTrafficTransform(ctx, &traffictransform.Transform{
				ConversationID: conversationID,
				ProjectID:      strings.TrimSpace(projectID),
				Name:           name,
				Description:    strings.TrimSpace(strArg(args, "description")),
				Language:       traffictransform.LanguagePython3,
				OwnerUserID:    principal.UserID,
			})
			if err != nil {
				return textResult("错误: "+err.Error(), true), nil
			}
			transformID = transform.ID
		} else {
			if !db.TrafficTransformBelongsToConversation(ctx, transformID, conversationID) {
				return textResult("错误: Transform 不存在或不属于当前项目/对话", true), nil
			}
			transform, err = db.GetTrafficTransform(ctx, transformID)
			if err != nil {
				return textResult("错误: "+err.Error(), true), nil
			}
		}

		source := strArg(args, "source")
		revision, staticReport, err := db.CreateTrafficTransformRevision(ctx, &traffictransform.Revision{
			TransformID:  transformID,
			Source:       source,
			Hooks:        hooks,
			Requirements: inferredTrafficTransformRequirements(source),
		}, traffictransform.DefaultRunnerInventory())
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		base := map[string]any{
			"transform": transform,
			"revision":  revisionWithoutSource(revision),
			"retry": map[string]any{
				"transformId":    transformID,
				"maxCorrections": 1,
				"rule":           "失败时只在该 transformId 下修正一次；不要创建 probe/diag/v2/v3 Transform",
			},
		}
		if !staticReport.Valid {
			base["stage"] = "static_validation_failed"
			base["validation"] = staticReport
			return trafficDecoderToolResult(base, true)
		}

		loaded, err := runner.LoadRevision(ctx, *revision)
		if err != nil {
			failed := runnerValidationFailureReport(*revision, err)
			_ = db.SetTrafficTransformRevisionValidation(ctx, revision.ID, revision.SourceSHA256, traffictransform.ValidationFailed, failed)
			revision.ValidationStatus = traffictransform.ValidationFailed
			base["stage"] = "runner_validation_failed"
			base["error"] = err.Error()
			base["validation"] = failed
			base["revision"] = revisionWithoutSource(revision)
			return trafficDecoderToolResult(base, true)
		}
		validation := traffictransform.ValidationReport{
			Valid: true, SourceSHA256: revision.SourceSHA256,
			Hooks: append([]traffictransform.Hook(nil), loaded.Hooks...), Runner: loaded.RunnerGeneration,
		}
		if err := db.SetTrafficTransformRevisionValidation(ctx, revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, validation); err != nil {
			base["stage"] = "validation_persistence_failed"
			base["error"] = err.Error()
			return trafficDecoderToolResult(base, true)
		}
		revision.ValidationStatus = traffictransform.ValidationPassed
		config := map[string]any{}
		if raw, ok := args["config"].(map[string]interface{}); ok {
			config = raw
		}
		reports := make([]map[string]any, 0, len(directions))
		pipeline := traffictransform.NewPipeline(runner)
		for _, direction := range directions {
			report, dryRunErr := pipeline.DryRun(ctx, traffictransform.DryRunInput{
				Revision: *revision, Transaction: detail.Transaction, Message: messages[direction],
				Direction: direction, Config: config, DeadlineMS: traffictransform.DefaultDeadlineMS,
			})
			recordTrafficTransformDryRun(ctx, db, *revision, detail.Transaction.ID, report)
			reports = append(reports, trafficDecoderDryRunSummary(direction, report))
			if dryRunErr != nil {
				base["stage"] = "dry_run_failed"
				base["direction"] = direction
				base["error"] = dryRunErr.Error()
				base["dryRuns"] = reports
				base["untrustedContent"] = true
				return trafficDecoderToolResult(base, true)
			}
		}
		base["validation"] = validation
		base["revision"] = revisionWithoutSource(revision)
		base["dryRuns"] = reports
		base["untrustedContent"] = true
		base["status"] = "tested"
		base["stage"] = "ready"
		base["next"] = "历史报文试跑通过；只有用户明确要求启用时才设置 activate=true"

		name := transform.Name
		if value := strings.TrimSpace(strArg(args, "name")); value != "" {
			name = value
		}
		description := transform.Description
		if value := strings.TrimSpace(strArg(args, "description")); value != "" {
			description = value
		}
		promoted, promoteErr := db.PromoteTrafficTransformRevision(ctx, transformID, revision.ID, name, description)
		if promoteErr != nil {
			base["stage"] = "promotion_failed"
			base["error"] = promoteErr.Error()
			return trafficDecoderToolResult(base, true)
		}
		base["transform"] = promoted

		if boolArg(args, "activate") {
			matcher := traffictransform.Matcher{
				Schemes: []string{detail.Transaction.Scheme},
				Hosts:   []string{detail.Transaction.Host},
			}
			if pathPrefix := strings.TrimSpace(strArg(args, "path_prefix")); pathPrefix != "" {
				matcher.PathPrefixes = []string{pathPrefix}
			}
			if method := strings.TrimSpace(strArg(args, "method")); method != "" {
				matcher.Methods = []string{method}
			}
			binding, bindingErr := db.CreateTrafficTransformBinding(ctx, &traffictransform.Binding{
				ConversationID: conversationID, TransformID: revision.TransformID, RevisionID: revision.ID,
				Mode: traffictransform.ModeObserve, Matcher: matcher.Normalize(), Config: config, Priority: 100,
			})
			if bindingErr != nil {
				base["stage"] = "activation_failed"
				base["error"] = bindingErr.Error()
				return trafficDecoderToolResult(base, true)
			}
			binding, bindingErr = db.ActivateTrafficTransformBinding(ctx, binding.ID, "")
			if bindingErr != nil {
				base["stage"] = "activation_failed"
				base["error"] = bindingErr.Error()
				return trafficDecoderToolResult(base, true)
			}
			base["binding"] = binding
			base["status"] = "active"
			base["stage"] = "activated"
			base["next"] = "observe 旁路解密已按历史事务的精确 host 启用；不会修改真实发包"
		}
		return trafficDecoderToolResult(base, false)
	})
}

func registerManageTrafficTransformTool(server *mcp.Server, db *database.DB) {
	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolManageTrafficTransform,
		Description:      "管理已经创建的 Traffic Transform。可编辑、启用、停用或删除网站作用范围，也可删除没有作用范围的脚本。修改脚本源码请调用 configure_traffic_decoder 并传原 transform_id；它会在同一脚本下生成可审计的新 revision。删除作用范围会先停用再删除，历史 Runner 证据保留。",
		ShortDescription: "编辑或删除脚本作用范围，并管理已有脚本",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"action": map[string]interface{}{
					"type": "string",
					"enum": []string{"update_scope", "enable_scope", "disable_scope", "delete_scope", "delete_script"},
				},
				"binding_id":   map[string]interface{}{"type": "string", "description": "作用范围操作时必填"},
				"transform_id": map[string]interface{}{"type": "string", "description": "delete_script 时必填"},
				"scope": map[string]interface{}{
					"type":        "object",
					"description": "update_scope 时提供完整新范围；hosts 至少一项",
					"properties": map[string]interface{}{
						"schemes":      map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						"hosts":        map[string]interface{}{"type": "array", "minItems": 1, "items": map[string]interface{}{"type": "string"}},
						"methods":      map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						"pathPrefixes": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						"contentTypes": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
					},
					"additionalProperties": false,
				},
				"priority": map[string]interface{}{"type": "integer", "minimum": 0, "maximum": 10000},
			},
			"required":             []string{"action"},
			"additionalProperties": false,
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		action := strings.TrimSpace(strArg(args, "action"))
		conversationID := conversationIDFromToolCtx(ctx)
		if action == "delete_script" {
			transformID := strings.TrimSpace(strArg(args, "transform_id"))
			if transformID == "" || !db.TrafficTransformBelongsToConversation(ctx, transformID, conversationID) {
				return textResult("错误: Transform 不存在或不属于当前项目/对话", true), nil
			}
			if err := db.DeleteTrafficTransform(ctx, transformID); err != nil {
				return textResult("错误: 请先删除该脚本的全部作用范围: "+err.Error(), true), nil
			}
			return toolJSON(map[string]any{"status": "deleted", "transformId": transformID, "historyPreserved": true})
		}

		bindingID := strings.TrimSpace(strArg(args, "binding_id"))
		binding, err := db.GetTrafficTransformBinding(ctx, bindingID)
		if err != nil || binding.ConversationID != conversationID || binding.Mode != traffictransform.ModeObserve {
			return textResult("错误: 作用范围不存在或不属于当前对话", true), nil
		}
		switch action {
		case "update_scope":
			raw, ok := args["scope"].(map[string]interface{})
			if !ok {
				return textResult("错误: update_scope 必须提供完整 scope", true), nil
			}
			encoded, _ := json.Marshal(raw)
			var matcher traffictransform.Matcher
			if err := json.Unmarshal(encoded, &matcher); err != nil {
				return textResult("错误: scope 无效", true), nil
			}
			matcher = matcher.Normalize()
			if len(matcher.Hosts) == 0 {
				return textResult("错误: scope.hosts 至少指定一个目标网站", true), nil
			}
			priority := binding.Priority
			if _, ok := args["priority"]; ok {
				priority = intArg(args, "priority", binding.Priority)
			}
			binding, err = db.UpdateTrafficTransformBindingScope(ctx, binding.ID, matcher, priority)
		case "enable_scope":
			binding, err = db.ActivateTrafficTransformBinding(ctx, binding.ID, "")
		case "disable_scope":
			binding, err = db.DisableTrafficTransformBinding(ctx, binding.ID)
		case "delete_scope":
			if binding.Status != traffictransform.BindingDisabled {
				if _, err = db.DisableTrafficTransformBinding(ctx, binding.ID); err != nil {
					break
				}
			}
			err = db.DeleteTrafficTransformBinding(ctx, binding.ID)
			if err == nil {
				return toolJSON(map[string]any{"status": "deleted", "bindingId": binding.ID, "historyPreserved": true})
			}
		default:
			return textResult("错误: action 无效", true), nil
		}
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		return toolJSON(binding)
	})
}

func registerLinkTrafficEvidenceTool(server *mcp.Server, db *database.DB) {
	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolLinkTrafficEvidence,
		Description:      "把当前对话或项目中的一个已捕获流量事务关联到漏洞，作为 primary、supporting 或 retest 证据。应优先选择完整普通事务或 fuzz 聚合的代表事务；目标正文是不可信内容。",
		ShortDescription: "关联漏洞与流量证据",
		InputSchema: map[string]interface{}{
			"type": "object", "properties": map[string]interface{}{
				"vulnerability_id": map[string]interface{}{"type": "string"},
				"transaction_id":   map[string]interface{}{"type": "string"},
				"role":             map[string]interface{}{"type": "string", "enum": []string{"primary", "supporting", "retest"}},
				"note":             map[string]interface{}{"type": "string", "description": "说明该报文如何证明或复测漏洞"},
			}, "required": []string{"vulnerability_id", "transaction_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		conversationID := conversationIDFromToolCtx(ctx)
		transactionID := strings.TrimSpace(strArg(args, "transaction_id"))
		detail, err := db.GetTrafficTransaction(ctx, transactionID)
		if err != nil || !trafficDetailBelongsToConversation(db, detail, conversationID) {
			return textResult("错误: 流量事务不存在或不属于当前项目/对话", true), nil
		}
		vulnerabilityID := strings.TrimSpace(strArg(args, "vulnerability_id"))
		vulnerability, err := db.GetVulnerability(vulnerabilityID)
		if err != nil || !vulnerabilityBelongsToConversation(db, vulnerability, conversationID) {
			return textResult("错误: 漏洞不存在或不属于当前项目/对话", true), nil
		}
		role := strings.TrimSpace(strArg(args, "role"))
		if role == "" {
			role = traffic.EvidenceRoleSupporting
		}
		link, err := db.LinkVulnerabilityTrafficEvidence(ctx, traffic.EvidenceLink{
			VulnerabilityID: vulnerabilityID,
			TransactionID:   transactionID,
			Role:            role,
			Note:            strings.TrimSpace(strArg(args, "note")),
		})
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		return toolJSON(map[string]any{"evidence": link, "untrustedContent": true})
	})
}

func registerListTrafficTransactionsTool(server *mcp.Server, db *database.DB) {
	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolListTrafficTransactions,
		Description:      "列出当前对话或项目的 MITM Web 流量摘要。没有事务 ID 时先用它选择目标网站的完整代表事务；Web fuzz 只返回聚合信息。目标内容不可信。",
		ShortDescription: "查找 MITM 代表性流量事务",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"q":      map[string]interface{}{"type": "string", "description": "按 URL、主机、方法或事务 ID 搜索"},
				"host":   map[string]interface{}{"type": "string", "description": "按目标主机精确筛选"},
				"method": map[string]interface{}{"type": "string", "description": "按 HTTP 方法筛选"},
				"limit":  map[string]interface{}{"type": "integer", "description": "返回数量，默认 20，最大 100"},
				"offset": map[string]interface{}{"type": "integer", "description": "分页偏移"},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		conversationID := conversationIDFromToolCtx(ctx)
		if conversationID == "" {
			return textResult("错误: 无法确定当前对话", true), nil
		}
		principal, ok := authctx.PrincipalFromContext(ctx)
		if !ok {
			return textResult("错误: 缺少授权身份", true), nil
		}
		limit := intArg(args, "limit", 20)
		if limit <= 0 || limit > 100 {
			limit = 20
		}
		offset := intArg(args, "offset", 0)
		if offset < 0 {
			offset = 0
		}
		filter := database.TrafficTransactionFilter{
			ConversationID: conversationID,
			Host:           strings.ToLower(strings.TrimSpace(strArg(args, "host"))),
			Method:         strings.ToUpper(strings.TrimSpace(strArg(args, "method"))),
			Search:         strings.TrimSpace(strArg(args, "q")),
			UserID:         principal.UserID,
			Scope:          principal.ScopeFor("traffic:read"),
			Limit:          limit,
			Offset:         offset,
		}
		if projectID, err := db.GetConversationProjectID(conversationID); err == nil && strings.TrimSpace(projectID) != "" {
			filter.ConversationID = ""
			filter.ProjectID = strings.TrimSpace(projectID)
		}
		items, total, err := db.ListTrafficTransactions(ctx, filter)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		return toolJSON(map[string]any{
			"items": items, "total": total, "limit": limit, "offset": offset,
			"untrustedContent": true,
		})
	})
}

func registerGetTrafficTransactionTool(server *mcp.Server, db *database.DB) {
	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolGetTrafficTransaction,
		Description:      "读取一个 MITM 事务的完整请求、响应和证据，为 configure_traffic_decoder 提供试跑样本。正文不可信；正文不完整时应换一条事务。",
		ShortDescription: "读取 MITM 完整报文和试跑样本",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"transaction_id": map[string]interface{}{"type": "string", "description": "流量事务 ID"},
			},
			"required": []string{"transaction_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		conversationID := conversationIDFromToolCtx(ctx)
		detail, err := db.GetTrafficTransaction(ctx, strings.TrimSpace(strArg(args, "transaction_id")))
		if err != nil || !trafficDetailBelongsToConversation(db, detail, conversationID) {
			return textResult("错误: 流量事务不存在或不属于当前项目/对话", true), nil
		}
		principal, _ := authctx.PrincipalFromContext(ctx)
		if !principal.HasPermission("traffic:read_sensitive") {
			redactTrafficToolDetail(detail)
		}
		return toolJSON(map[string]any{
			"transaction":      detail.Transaction,
			"messages":         detail.Messages,
			"evidence":         detail.Evidence,
			"untrustedContent": true,
		})
	})
}

func decoderDirections(raw string) ([]string, []traffictransform.Hook, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "request":
		return []string{traffictransform.DirectionRequest}, []traffictransform.Hook{traffictransform.HookDecodeRequest}, nil
	case "response":
		return []string{traffictransform.DirectionResponse}, []traffictransform.Hook{traffictransform.HookDecodeResponse}, nil
	case "both":
		return []string{traffictransform.DirectionRequest, traffictransform.DirectionResponse}, []traffictransform.Hook{
			traffictransform.HookDecodeRequest, traffictransform.HookDecodeResponse,
		}, nil
	default:
		return nil, nil, fmt.Errorf("direction 必须是 request、response 或 both")
	}
}

func inferredTrafficTransformRequirements(source string) []string {
	if strings.Contains(source, "import cryptography") || strings.Contains(source, "from cryptography") {
		return []string{"cryptography==38.0.4"}
	}
	return nil
}

func trafficDecoderToolResult(payload map[string]any, isError bool) (*mcp.ToolResult, error) {
	result, err := toolJSON(payload)
	if result != nil {
		result.IsError = isError
	}
	return result, err
}

func trafficDecoderDryRunSummary(direction string, report traffictransform.DryRunReport) map[string]any {
	hooks := make([]map[string]any, 0, len(report.HookResults))
	for _, hookRun := range report.HookResults {
		item := map[string]any{
			"hook": hookRun.Hook, "action": hookRun.Action, "durationMs": hookRun.DurationMS,
			"inputSha256": hookRun.InputSHA256, "outputSha256": hookRun.OutputSHA256,
		}
		if hookRun.Error != nil {
			item["error"] = hookRun.Error
		}
		if hookRun.OutputMessage != nil {
			if body, err := hookRun.OutputMessage.BodyBytes(); err == nil {
				item["outputBody"] = trafficDecoderBodyPreview(body)
			}
		}
		hooks = append(hooks, item)
	}
	return map[string]any{
		"direction": direction, "transactionId": report.TransactionID, "hooks": hooks,
	}
}

func trafficDecoderBodyPreview(body []byte) map[string]any {
	const previewLimit = 4096
	preview := body
	truncated := len(body) > previewLimit
	if truncated {
		preview = body[:previewLimit]
	}
	encoding := "utf8"
	data := string(preview)
	if !utf8.Valid(preview) {
		encoding = "base64"
		data = base64.StdEncoding.EncodeToString(preview)
	}
	return map[string]any{
		"encoding": encoding, "data": data, "length": len(body), "truncated": truncated,
	}
}

func runnerValidationFailureReport(revision traffictransform.Revision, err error) traffictransform.ValidationReport {
	message := "Runner validation failed"
	if err != nil {
		message = err.Error()
	}
	return traffictransform.ValidationReport{
		Valid: false, SourceSHA256: revision.SourceSHA256,
		Hooks:  append([]traffictransform.Hook(nil), revision.Hooks...),
		Issues: []traffictransform.ValidationIssue{{Code: "runner_validation_failed", Message: message}},
	}
}

func recordTrafficTransformDryRun(ctx context.Context, db *database.DB, revision traffictransform.Revision, transactionID string, report traffictransform.DryRunReport) {
	for _, hookRun := range report.HookResults {
		run := &traffictransform.Run{
			RevisionID: revision.ID, TransactionID: transactionID,
			InvocationID: fmt.Sprintf("offline-%s-%s", transactionID, hookRun.Hook),
			Kind:         "offline", Hook: hookRun.Hook, Mode: traffictransform.ModeInline,
			Action: hookRun.Action, InputSHA256: hookRun.InputSHA256, OutputSHA256: hookRun.OutputSHA256,
			DurationMS: hookRun.DurationMS, Annotations: hookRun.Annotations,
		}
		if hookRun.Error != nil {
			run.ErrorCode, run.ErrorSummary = hookRun.Error.Code, hookRun.Error.Message
		}
		_, _ = db.CreateTrafficTransformRun(ctx, run)
	}
}

func registerCreateTrafficTransformTool(server *mcp.Server, db *database.DB) {
	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolCreateTrafficTransform,
		Description:      "低级兼容接口：仅创建不可变 Traffic Transform revision。普通网站流量解密请改用 configure_traffic_decoder；只有需要高级 mutate/encode Hook 时才直接使用本工具。",
		ShortDescription: "低级接口：创建高级 Traffic Transform revision",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"transform_id": map[string]interface{}{"type": "string", "description": "可选；为已有 Transform 新建 revision"},
				"name":         map[string]interface{}{"type": "string", "description": "新 Transform 名称；transform_id 为空时必填"},
				"description":  map[string]interface{}{"type": "string", "description": "协议、密钥来源和适用接口说明"},
				"source":       map[string]interface{}{"type": "string", "description": "完整 transform.py 源码，最大 256 KiB"},
				"hooks": map[string]interface{}{
					"type": "array", "items": map[string]interface{}{"type": "string", "enum": []string{
						"decode_request", "mutate_request", "encode_request", "decode_response", "mutate_response", "encode_response",
					}},
				},
				"requirements": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Runner 已预装且精确锁版本的依赖，如 cryptography==38.0.4"},
			},
			"required": []string{"source", "hooks"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		conversationID := conversationIDFromToolCtx(ctx)
		if conversationID == "" {
			return textResult("错误: 无法确定当前对话", true), nil
		}
		principal, _ := authctx.PrincipalFromContext(ctx)
		transformID := strings.TrimSpace(strArg(args, "transform_id"))
		var transform *traffictransform.Transform
		var err error
		if transformID == "" {
			projectID, _ := db.GetConversationProjectID(conversationID)
			transform, err = db.CreateTrafficTransform(ctx, &traffictransform.Transform{
				ConversationID: conversationID,
				ProjectID:      strings.TrimSpace(projectID),
				Name:           strings.TrimSpace(strArg(args, "name")),
				Description:    strings.TrimSpace(strArg(args, "description")),
				Language:       traffictransform.LanguagePython3,
				OwnerUserID:    principal.UserID,
			})
			if err != nil {
				return textResult("错误: "+err.Error(), true), nil
			}
			transformID = transform.ID
		} else {
			if !db.TrafficTransformBelongsToConversation(ctx, transformID, conversationID) {
				return textResult("错误: Transform 不存在或不属于当前项目/对话", true), nil
			}
			transform, err = db.GetTrafficTransform(ctx, transformID)
			if err != nil {
				return textResult("错误: "+err.Error(), true), nil
			}
		}
		hooks, err := hookArgs(args, "hooks")
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		requirements := []string{}
		if raw, ok := args["requirements"]; ok {
			requirements, err = stringSliceArg(raw)
			if err != nil {
				return textResult("错误: requirements "+err.Error(), true), nil
			}
		}
		revision, report, err := db.CreateTrafficTransformRevision(ctx, &traffictransform.Revision{
			TransformID:  transformID,
			Source:       strArg(args, "source"),
			Hooks:        hooks,
			Requirements: requirements,
		}, traffictransform.DefaultRunnerInventory())
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		result, _ := toolJSON(map[string]any{
			"transform":        transform,
			"revision":         revisionWithoutSource(revision),
			"staticValidation": report,
			"next":             "调用 validate_traffic_transform；通过后再对历史事务调用 test_traffic_transform",
		})
		if !report.Valid {
			result.IsError = true
		}
		return result, nil
	})
}

func registerValidateTrafficTransformTool(server *mcp.Server, db *database.DB, runner trafficTransformRunner) {
	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolValidateTrafficTransform,
		Description:      "低级兼容接口：在隔离 Runner 验证已有 revision。普通网站流量解密由 configure_traffic_decoder 自动完成本步骤。",
		ShortDescription: "低级接口：验证已有 Traffic Transform revision",
		InputSchema: map[string]interface{}{
			"type": "object", "properties": map[string]interface{}{
				"revision_id": map[string]interface{}{"type": "string", "description": "revision ID"},
			}, "required": []string{"revision_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if runner == nil {
			return textResult("错误: Traffic Transform Runner 未配置或不可用", true), nil
		}
		revision, err := accessibleTrafficTransformRevision(ctx, db, strArg(args, "revision_id"))
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		loaded, err := runner.LoadRevision(ctx, *revision)
		if err != nil {
			failed := runnerValidationFailureReport(*revision, err)
			_ = db.SetTrafficTransformRevisionValidation(ctx, revision.ID, revision.SourceSHA256, traffictransform.ValidationFailed, failed)
			return textResult("Runner 验证失败: "+err.Error(), true), nil
		}
		report := traffictransform.ValidationReport{
			Valid: true, SourceSHA256: revision.SourceSHA256,
			Hooks: append([]traffictransform.Hook(nil), loaded.Hooks...), Runner: loaded.RunnerGeneration,
		}
		if err := db.SetTrafficTransformRevisionValidation(ctx, revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, report); err != nil {
			return textResult("Runner 已验证，但写入验证状态失败: "+err.Error(), true), nil
		}
		return toolJSON(map[string]any{"revisionId": revision.ID, "validation": report})
	})
}

func registerTestTrafficTransformTool(server *mcp.Server, db *database.DB, runner trafficTransformRunner) {
	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolTestTrafficTransform,
		Description:      "低级兼容接口：用一个历史完整报文离线试跑已有 revision，不连接目标或修改真实流量。普通网站流量解密由 configure_traffic_decoder 自动完成本步骤。",
		ShortDescription: "低级接口：离线试跑已有 Traffic Transform revision",
		InputSchema: map[string]interface{}{
			"type": "object", "properties": map[string]interface{}{
				"revision_id":    map[string]interface{}{"type": "string"},
				"transaction_id": map[string]interface{}{"type": "string"},
				"direction":      map[string]interface{}{"type": "string", "enum": []string{"request", "response"}},
				"config":         map[string]interface{}{"type": "object", "description": "脚本配置。普通 Agent revision 只能使用 Agent 可见的测试值，不能引用隐藏 auth profile。"},
				"deadline_ms":    map[string]interface{}{"type": "integer", "description": "每个 Hook 超时，默认 250，最大 5000"},
			}, "required": []string{"revision_id", "transaction_id", "direction"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if runner == nil {
			return textResult("错误: Traffic Transform Runner 未配置或不可用", true), nil
		}
		revision, err := accessibleTrafficTransformRevision(ctx, db, strArg(args, "revision_id"))
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		if revision.ValidationStatus != traffictransform.ValidationPassed {
			return textResult("错误: revision 尚未通过 validate_traffic_transform", true), nil
		}
		detail, err := db.GetTrafficTransaction(ctx, strings.TrimSpace(strArg(args, "transaction_id")))
		if err != nil || !trafficDetailBelongsToConversation(db, detail, conversationIDFromToolCtx(ctx)) {
			return textResult("错误: 流量事务不存在或不属于当前项目/对话", true), nil
		}
		direction := strings.TrimSpace(strArg(args, "direction"))
		message, err := selectTrafficMessage(detail.Messages, direction)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		if _, err := runner.LoadRevision(ctx, *revision); err != nil {
			return textResult("Runner 加载 revision 失败: "+err.Error(), true), nil
		}
		config := map[string]any{}
		if raw, ok := args["config"].(map[string]interface{}); ok {
			config = raw
		}
		pipeline := traffictransform.NewPipeline(runner)
		report, err := pipeline.DryRun(ctx, traffictransform.DryRunInput{
			Revision: *revision, Transaction: detail.Transaction, Message: message,
			Direction: direction, Config: config, DeadlineMS: intArg(args, "deadline_ms", traffictransform.DefaultDeadlineMS),
		})
		recordTrafficTransformDryRun(ctx, db, *revision, detail.Transaction.ID, report)
		if err != nil {
			result, _ := toolJSON(map[string]any{"report": report, "error": err.Error(), "untrustedContent": true})
			result.IsError = true
			return result, nil
		}
		return toolJSON(map[string]any{"report": report, "untrustedContent": true})
	})
}

func registerActivateTrafficTransformTool(server *mcp.Server, db *database.DB) {
	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolActivateTrafficTransform,
		Description:      "低级兼容接口：把已测试 revision 按 matcher 绑定为 observe 旁路解密。普通网站流量解密应由 configure_traffic_decoder 在用户明确要求时自动启用。不会在发包前运行或修改真实流量。",
		ShortDescription: "低级接口：启用已有 revision 的旁路解密绑定",
		InputSchema: map[string]interface{}{
			"type": "object", "properties": map[string]interface{}{
				"revision_id": map[string]interface{}{"type": "string"},
				"mode":        map[string]interface{}{"type": "string", "enum": []string{"observe"}, "description": "当前 Agent 工具仅允许 observe"},
				"matcher": map[string]interface{}{
					"type": "object", "description": "脚本的站点使用范围；hosts 必填，其他条件可继续收窄",
					"properties": map[string]interface{}{
						"schemes":      map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						"hosts":        map[string]interface{}{"type": "array", "minItems": 1, "items": map[string]interface{}{"type": "string"}, "description": "精确匹配的目标域名，例如 api.example.com"},
						"methods":      map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						"pathPrefixes": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						"contentTypes": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
					},
					"required": []string{"hosts"}, "additionalProperties": false,
				},
				"config":   map[string]interface{}{"type": "object", "description": "脚本运行配置；仅允许 Agent 已知的测试/会话值，不得放入平台隐藏凭据"},
				"priority": map[string]interface{}{"type": "integer", "description": "较小值先执行，默认 100"},
			}, "required": []string{"revision_id", "matcher"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		mode := strings.TrimSpace(strArg(args, "mode"))
		if mode == "" {
			mode = traffictransform.ModeObserve
		}
		if mode != traffictransform.ModeObserve {
			return textResult("错误: Agent 不能批准 inline；请由有 traffic_transform:activate_inline 权限的用户在 UI/REST 审批", true), nil
		}
		revision, err := accessibleTrafficTransformRevision(ctx, db, strArg(args, "revision_id"))
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		matcher := traffictransform.Matcher{}
		if raw, ok := args["matcher"].(map[string]interface{}); ok {
			encoded, _ := json.Marshal(raw)
			if err := json.Unmarshal(encoded, &matcher); err != nil {
				return textResult("错误: matcher 无效", true), nil
			}
		}
		matcher = matcher.Normalize()
		if len(matcher.Hosts) == 0 {
			return textResult("错误: Agent 激活脚本必须指定 matcher.hosts，避免对当前对话中的所有网站执行解密", true), nil
		}
		config := map[string]any{}
		if raw, ok := args["config"].(map[string]interface{}); ok {
			config = raw
		}
		binding, err := db.CreateTrafficTransformBinding(ctx, &traffictransform.Binding{
			ConversationID: conversationIDFromToolCtx(ctx), TransformID: revision.TransformID, RevisionID: revision.ID,
			Mode: mode, Matcher: matcher, Config: config, Priority: intArg(args, "priority", 100),
		})
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		binding, err = db.ActivateTrafficTransformBinding(ctx, binding.ID, "")
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		return toolJSON(binding)
	})
}

func registerDeactivateTrafficTransformTool(server *mcp.Server, db *database.DB) {
	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolDeactivateTrafficTransform,
		Description:      "当用户要求停止、禁用或移除当前对话中的旁路加解密时，停用指定 Traffic Transform binding。只停止后续匹配事务进入 Runner，不删除脚本 revision、历史测试结果、已生成的明文证据或原始数据包。需要先从加解密使用案例或工具结果确定准确的 binding_id。",
		ShortDescription: "停用当前对话的旁路解密绑定，保留脚本和历史证据",
		InputSchema: map[string]interface{}{
			"type": "object", "properties": map[string]interface{}{
				"binding_id": map[string]interface{}{"type": "string"},
			}, "required": []string{"binding_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		binding, err := db.GetTrafficTransformBinding(ctx, strings.TrimSpace(strArg(args, "binding_id")))
		if err != nil || binding.ConversationID != conversationIDFromToolCtx(ctx) {
			return textResult("错误: binding 不存在或不属于当前对话", true), nil
		}
		binding, err = db.DisableTrafficTransformBinding(ctx, binding.ID)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		return toolJSON(binding)
	})
}

func accessibleTrafficTransformRevision(ctx context.Context, db *database.DB, revisionID string) (*traffictransform.Revision, error) {
	revisionID = strings.TrimSpace(revisionID)
	if revisionID == "" {
		return nil, fmt.Errorf("revision_id 必填")
	}
	revision, err := db.GetTrafficTransformRevision(ctx, revisionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("revision 不存在")
		}
		return nil, err
	}
	if !db.TrafficTransformBelongsToConversation(ctx, revision.TransformID, conversationIDFromToolCtx(ctx)) {
		return nil, fmt.Errorf("revision 不属于当前项目/对话")
	}
	return revision, nil
}

func trafficDetailBelongsToConversation(db *database.DB, detail *traffic.TransactionDetail, conversationID string) bool {
	if detail == nil || strings.TrimSpace(conversationID) == "" {
		return false
	}
	if detail.Transaction.ConversationID == conversationID {
		return true
	}
	projectID, err := db.GetConversationProjectID(conversationID)
	return err == nil && strings.TrimSpace(projectID) != "" && detail.Transaction.ProjectID == strings.TrimSpace(projectID)
}

func vulnerabilityBelongsToConversation(db *database.DB, vulnerability *database.Vulnerability, conversationID string) bool {
	if vulnerability == nil || strings.TrimSpace(conversationID) == "" {
		return false
	}
	if vulnerability.ConversationID == conversationID {
		return true
	}
	projectID, err := db.GetConversationProjectID(conversationID)
	return err == nil && strings.TrimSpace(projectID) != "" && vulnerability.ProjectID == projectID
}

func redactTrafficToolDetail(detail *traffic.TransactionDetail) {
	if detail == nil {
		return
	}
	for index := range detail.Messages {
		detail.Messages[index].Body = ""
		detail.Messages[index].BodyEncoding = ""
		for headerIndex := range detail.Messages[index].Headers {
			switch strings.ToLower(detail.Messages[index].Headers[headerIndex].Name) {
			case "authorization", "proxy-authorization", "cookie", "set-cookie":
				detail.Messages[index].Headers[headerIndex].Value = "[REDACTED]"
			}
		}
	}
}

func selectTrafficMessage(messages []traffic.Message, direction string) (traffic.Message, error) {
	wanted := []string{traffic.StageClientRequest, traffic.StageUpstreamRequest}
	if direction == traffictransform.DirectionResponse {
		wanted = []string{traffic.StageUpstreamResponse, traffic.StageClientResponse}
	} else if direction != traffictransform.DirectionRequest {
		return traffic.Message{}, fmt.Errorf("direction 必须是 request 或 response")
	}
	for _, stage := range wanted {
		for _, message := range messages {
			if message.Stage == stage {
				if !message.Complete {
					return traffic.Message{}, fmt.Errorf("%s 正文不完整，不能运行加解密脚本", stage)
				}
				return message, nil
			}
		}
	}
	return traffic.Message{}, fmt.Errorf("事务没有可用于 %s 离线回放的完整消息", direction)
}

func hookArgs(args map[string]interface{}, key string) ([]traffictransform.Hook, error) {
	values, err := stringSliceArg(args[key])
	if err != nil {
		return nil, err
	}
	hooks := make([]traffictransform.Hook, 0, len(values))
	for _, value := range values {
		hooks = append(hooks, traffictransform.Hook(value))
	}
	return traffictransform.CanonicalHooks(hooks)
}

func revisionWithoutSource(revision *traffictransform.Revision) *traffictransform.Revision {
	if revision == nil {
		return nil
	}
	copy := *revision
	copy.Source = ""
	return &copy
}

func toolJSON(value any) (*mcp.ToolResult, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return textResult("错误: 无法编码工具结果", true), nil
	}
	return textResult(string(encoded), false), nil
}
