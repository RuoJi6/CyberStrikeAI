package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/traffic"
	"cyberstrike-ai/internal/traffictransform"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	trafficReplayMaxBodyBytes               = 2 << 20
	trafficReplayMaxOutputBytes             = 2 << 20
	trafficReplayTransformAttributionPrefix = "replay-transform:"
)

var trafficReplayHeaderName = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)

type trafficReplayRequest struct {
	Method  string           `json:"method"`
	URL     string           `json:"url"`
	Headers []traffic.Header `json:"headers"`
	Body    string           `json:"body"`
}

type trafficReplayTransformResult struct {
	Matched       bool                               `json:"matched"`
	Applied       bool                               `json:"applied"`
	Strategy      string                             `json:"strategy,omitempty"`
	BindingID     string                             `json:"bindingId,omitempty"`
	RevisionID    string                             `json:"revisionId,omitempty"`
	TransformID   string                             `json:"transformId,omitempty"`
	TransformName string                             `json:"transformName,omitempty"`
	Hooks         []trafficReplayTransformHookResult `json:"hooks,omitempty"`
}

type trafficReplayTransformHookResult struct {
	Hook       traffictransform.Hook `json:"hook"`
	Action     string                `json:"action"`
	DurationMS int64                 `json:"durationMs"`
	ErrorCode  string                `json:"errorCode,omitempty"`
}

func replayOriginalRequest(messages []traffic.Message) (traffic.Message, error) {
	for _, stage := range []string{traffic.StageClientRequest, traffic.StageUpstreamRequest} {
		for _, message := range messages {
			if message.Stage == stage {
				if !message.Complete {
					return traffic.Message{}, fmt.Errorf("原始请求正文不完整，不能安全重发")
				}
				if message.BodyEncoding == traffic.BodyEncodingBase64 {
					return traffic.Message{}, fmt.Errorf("当前重发包仅支持文本正文，二进制正文请等待文件载荷模式")
				}
				return message, nil
			}
		}
	}
	return traffic.Message{}, fmt.Errorf("事务没有可重发的完整请求")
}

func defaultTrafficPort(scheme string) int {
	if strings.EqualFold(scheme, "https") {
		return 443
	}
	return 80
}

func parsedTrafficPort(target *url.URL) (int, error) {
	if target.Port() == "" {
		return defaultTrafficPort(target.Scheme), nil
	}
	port, err := strconv.Atoi(target.Port())
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("目标端口无效")
	}
	return port, nil
}

func validateTrafficReplayTarget(transaction traffic.Transaction, raw string) (*url.URL, error) {
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || target == nil || target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("请输入完整的 http 或 https URL")
	}
	if target.User != nil || target.Fragment != "" || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, fmt.Errorf("URL 不允许凭据、片段或非 HTTP 协议")
	}
	port, err := parsedTrafficPort(target)
	if err != nil {
		return nil, err
	}
	expectedPort := transaction.Port
	if expectedPort == 0 {
		expectedPort = defaultTrafficPort(transaction.Scheme)
	}
	if !strings.EqualFold(target.Scheme, transaction.Scheme) || !strings.EqualFold(target.Hostname(), transaction.Host) || port != expectedPort {
		return nil, fmt.Errorf("重发只允许修改原站点内的路径和参数，协议、主机与端口必须保持不变")
	}
	if target.Path == "" {
		target.Path = "/"
	}
	return target, nil
}

func validateTrafficReplayHeaders(headers []traffic.Header) error {
	if len(headers) > 128 {
		return fmt.Errorf("请求头不能超过 128 项")
	}
	total := 0
	blocked := map[string]bool{
		"host": true, "content-length": true, "transfer-encoding": true,
		"connection": true, "proxy-connection": true, "proxy-authorization": true,
	}
	for _, header := range headers {
		name := strings.TrimSpace(header.Name)
		if !trafficReplayHeaderName.MatchString(name) || strings.ContainsAny(header.Value, "\r\n\x00") {
			return fmt.Errorf("请求头 %q 无效", header.Name)
		}
		if blocked[strings.ToLower(name)] {
			return fmt.Errorf("请求头 %s 由重发器管理，不能手动设置", name)
		}
		if strings.HasPrefix(strings.ToLower(name), "x-cyberstrike-") {
			return fmt.Errorf("请求头 %s 属于平台内部归因字段，不能手动设置", name)
		}
		total += len(name) + len(header.Value)
	}
	if total > 128<<10 {
		return fmt.Errorf("请求头总大小不能超过 128 KiB")
	}
	return nil
}

func parseTrafficReplayOutput(output string) (string, int) {
	const marker = "\n__CYBERSTRIKE_REPLAY_STATUS__:"
	index := strings.LastIndex(output, marker)
	if index < 0 {
		return output, 0
	}
	statusText := strings.TrimSpace(output[index+len(marker):])
	status, _ := strconv.Atoi(statusText)
	return output[:index], status
}

func trafficReplayHasHook(revision traffictransform.Revision, wanted traffictransform.Hook) bool {
	for _, hook := range revision.Hooks {
		if hook == wanted {
			return true
		}
	}
	return false
}

func trafficReplayMessage(transactionID string, request trafficReplayRequest, target *url.URL) traffic.Message {
	body, encoding, digest := traffic.EncodeBody([]byte(request.Body))
	return traffic.Message{
		TransactionID: transactionID, Stage: traffic.StageClientRequest, Kind: traffic.MessageKindRequest,
		Method: request.Method, Path: target.RequestURI(), Protocol: "HTTP/1.1",
		Headers: append([]traffic.Header(nil), request.Headers...), ContentType: traffictransform.ContentType(request.Headers),
		Body: body, BodyEncoding: encoding, BodySHA256: digest, BodyLength: int64(len(request.Body)),
		BodyStoredBytes: int64(len(request.Body)), Complete: true, CreatedAt: time.Now().UTC(),
	}
}

func trafficReplayTargetWithPath(target *url.URL, rawPath string) (*url.URL, error) {
	reference, err := url.Parse(strings.TrimSpace(rawPath))
	if err != nil || reference == nil || reference.IsAbs() || reference.Host != "" || reference.Fragment != "" || !strings.HasPrefix(reference.Path, "/") {
		return nil, fmt.Errorf("脚本返回了无效的请求路径")
	}
	result := *target
	result.Path, result.RawPath, result.RawQuery = reference.Path, reference.RawPath, reference.RawQuery
	return &result, nil
}

func (h *TrafficHandler) storeTrafficReplayRun(ctx context.Context, detail *traffic.TransactionDetail, binding *traffictransform.Binding, revision *traffictransform.Revision, run *traffictransform.Run) {
	if _, err := h.db.CreateTrafficTransformRun(ctx, run); err != nil {
		h.logger.Warn("保存重发包脚本运行记录失败", zap.String("transaction_id", detail.Transaction.ID), zap.Error(err))
	}
}

// observeTrafficReplayDecode lets a decoder-only script inspect the edited raw
// request without replacing the bytes sent on the wire. This is the safe replay
// path for passive/observe transforms: the editor already contains ciphertext,
// so an encoder is not required unless a mutate hook needs to write changes back.
func (h *TrafficHandler) observeTrafficReplayDecode(ctx context.Context, detail *traffic.TransactionDetail, binding *traffictransform.Binding, revision *traffictransform.Revision, message traffic.Message, matchContext traffictransform.InvocationContext, info *trafficReplayTransformResult) error {
	decoded, err := traffictransform.MessageFromTraffic(message)
	if err != nil {
		return fmt.Errorf("准备旁路解密请求失败: %w", err)
	}
	matchContext.Config = binding.Config
	invocation := traffictransform.Invocation{
		ProtocolVersion:  traffictransform.ProtocolVersion,
		InvocationID:     uuid.NewString(),
		RevisionID:       revision.ID,
		RevisionSHA256:   revision.SourceSHA256,
		BindingID:        binding.ID,
		Hook:             traffictransform.HookDecodeRequest,
		Mode:             traffictransform.ModeObserve,
		DeadlineMS:       traffictransform.DefaultDeadlineMS,
		Context:          matchContext,
		Message:          decoded,
		TransactionState: map[string]any{},
	}
	started := time.Now()
	result, invokeErr := h.transformRunner.Invoke(ctx, invocation)
	duration := max(time.Since(started).Milliseconds(), int64(0))
	resultErr := invokeErr
	if resultErr == nil {
		resultErr = traffictransform.ValidateResult(invocation, result)
	}
	action := result.Action
	errorCode := ""
	if resultErr != nil {
		action = traffictransform.ActionError
		errorCode = "runner_unavailable"
	} else if result.Error != nil {
		errorCode = result.Error.Code
	}
	info.Hooks = append(info.Hooks, trafficReplayTransformHookResult{
		Hook: traffictransform.HookDecodeRequest, Action: action, DurationMS: duration, ErrorCode: errorCode,
	})
	run := &traffictransform.Run{
		BindingID: binding.ID, RevisionID: revision.ID, TransactionID: detail.Transaction.ID,
		InvocationID: invocation.InvocationID, Kind: "online", Hook: traffictransform.HookDecodeRequest,
		Mode: traffictransform.ModeObserve, Action: action, InputSHA256: decoded.Body.SHA256,
		DurationMS: duration, Annotations: result.Annotations,
	}
	if result.Message != nil {
		run.OutputSHA256 = result.Message.Body.SHA256
	}
	if resultErr != nil {
		run.ErrorCode, run.ErrorSummary = errorCode, resultErr.Error()
	} else if result.Error != nil {
		run.ErrorCode, run.ErrorSummary = result.Error.Code, result.Error.Message
	}
	h.storeTrafficReplayRun(ctx, detail, binding, revision, run)
	if resultErr != nil {
		return resultErr
	}
	if result.Action == traffictransform.ActionError {
		return fmt.Errorf("%s: %s", result.Error.Code, result.Error.Message)
	}
	if result.Action != traffictransform.ActionPass && result.Action != traffictransform.ActionReplace {
		return fmt.Errorf("旁路解密返回了不支持的动作 %s", result.Action)
	}
	return nil
}

func (h *TrafficHandler) applyTrafficReplayTransform(ctx context.Context, detail *traffic.TransactionDetail, request trafficReplayRequest, target *url.URL) (trafficReplayRequest, *url.URL, trafficReplayTransformResult, error) {
	info := trafficReplayTransformResult{}
	bindings, err := h.db.ListActiveTrafficTransformBindings(ctx, detail.Transaction.ConversationID)
	if err != nil {
		return request, target, info, fmt.Errorf("读取加解密规则失败: %w", err)
	}
	message := trafficReplayMessage(detail.Transaction.ID, request, target)
	matchContext := traffictransform.InvocationContext{
		TransactionID: detail.Transaction.ID, ConversationID: detail.Transaction.ConversationID,
		Direction: traffictransform.DirectionRequest, Scheme: detail.Transaction.Scheme, Host: detail.Transaction.Host,
		Port: detail.Transaction.Port, Method: request.Method, Path: target.RequestURI(),
		ContentType: message.ContentType, Timestamp: time.Now().UTC(),
	}
	if matchContext.Port == 0 {
		matchContext.Port = defaultTrafficPort(matchContext.Scheme)
	}
	var binding *traffictransform.Binding
	for index := range bindings {
		if bindings[index].Matcher.Matches(matchContext) {
			binding = &bindings[index]
			break
		}
	}
	if binding == nil {
		return request, target, info, nil
	}
	info.Matched = true
	info.BindingID, info.RevisionID, info.TransformID = binding.ID, binding.RevisionID, binding.TransformID
	revision, err := h.db.GetTrafficTransformRevision(ctx, binding.RevisionID)
	if err != nil {
		return request, target, info, fmt.Errorf("读取匹配脚本版本失败: %w", err)
	}
	if transform, getErr := h.db.GetTrafficTransform(ctx, binding.TransformID); getErr == nil {
		info.TransformName = transform.Name
	}
	hasDecode := trafficReplayHasHook(*revision, traffictransform.HookDecodeRequest)
	hasMutate := trafficReplayHasHook(*revision, traffictransform.HookMutateRequest)
	hasEncode := trafficReplayHasHook(*revision, traffictransform.HookEncodeRequest)
	if !hasEncode && hasMutate {
		return request, target, info, fmt.Errorf("请求匹配加解密规则，但脚本包含 mutate_request 且缺少 encode_request，不能把修改安全写回密文")
	}
	if hasEncode {
		info.Strategy = "inline"
	} else if hasDecode {
		info.Strategy = "observe"
	} else {
		info.Strategy = "passthrough"
		return request, target, info, nil
	}
	if h.transformRunner == nil {
		if info.Strategy == "observe" && binding.FailurePolicy == traffictransform.FailurePolicyContinue {
			info.Hooks = append(info.Hooks, trafficReplayTransformHookResult{Hook: traffictransform.HookDecodeRequest, Action: traffictransform.ActionError, ErrorCode: "runner_unavailable"})
			return request, target, info, nil
		}
		return request, target, info, fmt.Errorf("请求匹配加解密规则，但隔离 Runner 当前不可用，已阻止发送")
	}
	loaded, err := h.transformRunner.LoadRevision(ctx, *revision)
	if err != nil || !loaded.Valid {
		if err == nil {
			err = fmt.Errorf("Runner 拒绝加载脚本版本")
		}
		if info.Strategy == "observe" && binding.FailurePolicy == traffictransform.FailurePolicyContinue {
			info.Hooks = append(info.Hooks, trafficReplayTransformHookResult{Hook: traffictransform.HookDecodeRequest, Action: traffictransform.ActionError, ErrorCode: "load_failed"})
			return request, target, info, nil
		}
		return request, target, info, fmt.Errorf("加载匹配脚本失败: %w", err)
	}
	if info.Strategy == "observe" {
		if err := h.observeTrafficReplayDecode(ctx, detail, binding, revision, message, matchContext, &info); err != nil {
			if binding.FailurePolicy == traffictransform.FailurePolicyContinue {
				return request, target, info, nil
			}
			return request, target, info, fmt.Errorf("旁路解密脚本执行失败，已阻止发送: %w", err)
		}
		info.Applied = true
		return request, target, info, nil
	}
	transaction := detail.Transaction
	transaction.Method, transaction.Path = request.Method, target.RequestURI()
	if transaction.Port == 0 {
		transaction.Port = defaultTrafficPort(transaction.Scheme)
	}
	report, runErr := traffictransform.NewPipeline(h.transformRunner).DryRun(ctx, traffictransform.DryRunInput{
		Revision: *revision, BindingID: binding.ID, Transaction: transaction, Message: message,
		Config: binding.Config, Direction: traffictransform.DirectionRequest,
	})
	for _, hookRun := range report.HookResults {
		hookResult := trafficReplayTransformHookResult{Hook: hookRun.Hook, Action: hookRun.Action, DurationMS: hookRun.DurationMS}
		if hookRun.Error != nil {
			hookResult.ErrorCode = hookRun.Error.Code
		}
		info.Hooks = append(info.Hooks, hookResult)
		run := &traffictransform.Run{
			BindingID: binding.ID, RevisionID: revision.ID, TransactionID: detail.Transaction.ID,
			InvocationID: hookRun.InvocationID, Kind: "online", Hook: hookRun.Hook, Mode: traffictransform.ModeInline,
			Action: hookRun.Action, InputSHA256: hookRun.InputSHA256, OutputSHA256: hookRun.OutputSHA256,
			DurationMS: hookRun.DurationMS, Annotations: hookRun.Annotations,
		}
		if hookRun.Error != nil {
			run.ErrorCode, run.ErrorSummary = hookRun.Error.Code, hookRun.Error.Message
		}
		h.storeTrafficReplayRun(ctx, detail, binding, revision, run)
	}
	if runErr != nil || report.FinalMessage == nil {
		if runErr == nil {
			runErr = fmt.Errorf("脚本没有返回最终请求")
		}
		return request, target, info, fmt.Errorf("匹配脚本执行失败，已阻止发送: %w", runErr)
	}
	finalMessage := report.FinalMessage
	finalTarget, err := trafficReplayTargetWithPath(target, finalMessage.Path)
	if err != nil {
		return request, target, info, err
	}
	body, err := finalMessage.BodyBytes()
	if err != nil || !utf8.Valid(body) {
		return request, target, info, fmt.Errorf("脚本返回了当前重发器不支持的二进制正文")
	}
	if len(body) > trafficReplayMaxBodyBytes {
		return request, target, info, fmt.Errorf("脚本返回的正文超过重发上限 2 MiB")
	}
	request.Method = strings.ToUpper(strings.TrimSpace(finalMessage.Method))
	request.Headers = append([]traffic.Header(nil), finalMessage.Headers...)
	request.Body = string(body)
	if err := validateTrafficReplayHeaders(request.Headers); err != nil {
		return request, target, info, fmt.Errorf("脚本返回的请求头无效: %w", err)
	}
	info.Applied = true
	return request, finalTarget, info, nil
}

func (h *TrafficHandler) Replay(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	if !session.Permissions["traffic:read_sensitive"] {
		c.JSON(http.StatusForbidden, gin.H{"error": "重发完整数据包需要 traffic:read_sensitive 权限"})
		return
	}
	if h.replayExecutor == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "重发执行器未配置"})
		return
	}
	detail, err := h.db.GetTrafficTransaction(c.Request.Context(), strings.TrimSpace(c.Param("id")))
	if err != nil || !h.canAccess(session, detail, "traffic:replay") {
		c.JSON(http.StatusNotFound, gin.H{"error": "流量事务不存在"})
		return
	}
	if strings.TrimSpace(detail.Transaction.ConversationID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该事务没有对话边界，不能决定本机或容器执行位置"})
		return
	}
	if _, err := replayOriginalRequest(detail.Messages); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var request trafficReplayRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "重发请求无效"})
		return
	}
	request.Method = strings.ToUpper(strings.TrimSpace(request.Method))
	allowedMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true}
	if !allowedMethods[request.Method] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "仅支持 GET、POST、PUT、PATCH、DELETE、HEAD 和 OPTIONS"})
		return
	}
	target, err := validateTrafficReplayTarget(detail.Transaction, request.URL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(request.Body) > trafficReplayMaxBodyBytes {
		c.JSON(http.StatusBadRequest, gin.H{"error": "重发正文不能超过 2 MiB"})
		return
	}
	if err := validateTrafficReplayHeaders(request.Headers); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	request, target, transformResult, err := h.applyTrafficReplayTransform(c.Request.Context(), detail, request, target)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error(), "transform": transformResult})
		return
	}
	if !allowedMethods[request.Method] {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "脚本返回了重发器不支持的 HTTP 方法", "transform": transformResult})
		return
	}
	command := []string{"curl", "--disable", "--silent", "--show-error", "--include", "--max-time", "30", "--max-redirs", "0", "--request", request.Method}
	if transformResult.Applied {
		attribution := trafficReplayTransformAttributionPrefix + transformResult.BindingID + ":" + transformResult.RevisionID
		command = append(command, "--header", "X-Cyberstrike-Execution-Id: "+attribution)
	}
	for _, header := range request.Headers {
		command = append(command, "--header", strings.TrimSpace(header.Name)+": "+header.Value)
	}
	if request.Body != "" {
		command = append(command, "--data-raw", request.Body)
	}
	command = append(command, "--write-out", "\n__CYBERSTRIKE_REPLAY_STATUS__:%{http_code}\n", "--url", target.String())
	ctx, cancel := context.WithTimeout(c.Request.Context(), 35*time.Second)
	defer cancel()
	result, execErr := h.replayExecutor(ctx, detail.Transaction.ConversationID, security.ExecutionRequest{
		Command: command, MaxOutputBytes: trafficReplayMaxOutputBytes,
	})
	rawResponse, status := parseTrafficReplayOutput(result.Output)
	if execErr != nil {
		h.logger.Warn("重发流量事务失败", zap.String("transaction_id", detail.Transaction.ID), zap.Error(execErr))
		c.JSON(http.StatusBadGateway, gin.H{"error": "重发失败: " + execErr.Error(), "rawResponse": rawResponse, "executionLocation": result.Location})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"transactionId": detail.Transaction.ID, "httpStatus": status, "rawResponse": rawResponse,
		"executionLocation": result.Location, "runtimeId": result.RuntimeID, "containerId": result.ContainerID,
		"transform": transformResult,
	})
}
