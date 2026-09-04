# Traffic Transform v1 协议与实现契约

> 状态：v1 revision、隔离 Runner、dry-run 与异步 observe 已实现；inline 尚未实现  
> 上层设计：[Agent 可编程 MITM 与流量证据设计](programmable-mitm-traffic-design.md)

本文冻结 Gateway、Transform Runner、Agent 脚本和控制面之间的首版契约，避免实现阶段各自定义不兼容的数据结构。

## Agent 常用入口

普通网站流量解密不需要手工编排多个 MCP 工具。Agent 应加载
`traffic-transform-authoring` Skill，然后调用 `configure_traffic_decoder`：

1. 指定一条完整历史事务、`request`/`response`/`both` 方向和源码。
2. 服务端自动推导 decode Hook 与已锁定依赖。
3. 在一次调用内创建不可变 revision、Runner 校验并离线试跑。
4. 只有用户明确要求时，才按该事务的精确 host 创建 observe 绑定。

修改源码时传原 `transform_id`，新源码会成为同一脚本的新 revision，并把
observe 作用范围切换到已验证版本。作用范围的编辑、启停和删除，以及无作用
范围脚本的删除，统一使用 `manage_traffic_transform`。下文的六 Hook 和独立
create/validate/test/activate 工具属于高级或兼容接口。

最小正文解密 SDK：

```python
from cyberstrike_transform import body_decoder

@body_decoder(content_type="application/json")
def decode_request(body: bytes) -> bytes:
    return decrypt(body)
```

## 1. 协议原则

- Gateway 负责授权、TLS、HTTP 规范化、目标校验、正文上限和持久化。
- Runner 只执行一个已加载 revision 的指定 Hook，不作边界或 RBAC 决策。
- Agent 脚本只能返回结构化结果，不能通过 stdout 控制代理行为。
- 所有长度、超时、并发和版本由 Gateway 与 Runner 双重校验。
- v1 处理 HTTP 语义消息，不承诺保留 chunk framing、Header 原始大小写或 TCP 分段。
- 请求和响应正文对脚本统一表示为 bytes；JSON 传输时使用 base64。

## 2. Gateway 内部接口

建议在 `internal/traffictransform` 定义与传输方式无关的 Go 接口：

```go
type Client interface {
    Invoke(context.Context, Invocation) (Result, error)
    Health(context.Context) (RunnerHealth, error)
}

type Invocation struct {
    ProtocolVersion string
    InvocationID    string
    RevisionID      string
    RevisionSHA256  string
    BindingID       string
    Hook            Hook
    Mode            Mode
    DeadlineMS      int
    Context         InvocationContext
    Message         Message
    OriginalWire    *Message
    TransactionState map[string]any
}

type Result struct {
    Action           Action
    Message          *Message
    Annotations      []Annotation
    StatePatch       map[string]any
    Error            *TransformError
}
```

`egress.Proxy` 只依赖该接口，不知道 Python、进程或 Docker。测试使用 fake Client 验证 Hook 顺序、失败策略和二次边界校验。

## 3. Hook 和动作

Hook 枚举：

- `decode_request`
- `mutate_request`
- `encode_request`
- `decode_response`
- `mutate_response`
- `encode_response`

Action 枚举：

- `pass`：不产生新消息。decode 的 pass 表示没有可解码内容；mutate/encode 的 pass 表示沿用输入。
- `replace`：使用结果中的 `message` 进入下一阶段。
- `block`：终止事务；只允许已批准的 inline binding 使用。
- `error`：Hook 执行失败，必须包含稳定错误码。

observe 模式只允许调用 `decode_request` 和 `decode_response`，并拒绝 `block`。inline 模式按方向依次调用 decode、mutate、encode；不存在的 Hook 等价于 `pass`。

## 4. Invocation 信封

Gateway 调用 Runner 的 JSON 示例：

```json
{
  "protocolVersion": "traffic-transform/v1",
  "invocationId": "tti_01...",
  "revisionId": "ttr_01...",
  "revisionSha256": "<64 hex>",
  "bindingId": "ttb_01...",
  "hook": "decode_request",
  "mode": "observe",
  "deadlineMs": 250,
  "context": {
    "transactionId": "txn_01...",
    "conversationId": "conv_01...",
    "direction": "request",
    "scheme": "https",
    "host": "api.example.test",
    "port": 443,
    "method": "POST",
    "path": "/api/order",
    "contentType": "application/octet-stream",
    "timestamp": "2026-08-27T12:00:00Z",
    "config": {}
  },
  "message": {
    "kind": "request",
    "method": "POST",
    "path": "/api/order",
    "status": 0,
    "headers": [
      {"name": "Content-Type", "value": "application/octet-stream"}
    ],
    "body": {
      "encoding": "base64",
      "data": "AAECAw==",
      "length": 4,
      "sha256": "<64 hex>",
      "complete": true
    }
  },
  "transactionState": {}
}
```

Runner 不接收 `execution_id`、`tool_call_id`、边界规则、上游代理、控制面 Secret 或数据库主键集合。脚本完成编解码不需要这些信息。

## 5. Message

### 5.1 Header

Header 使用数组：

```json
{"name": "Set-Cookie", "value": "a=1; Path=/"}
```

限制：

- 名称只允许 RFC token 字符。
- 名称和值不能包含 CR、LF 或 NUL。
- 单 Header、Header 总数和总字节数都有硬上限。
- Gateway 在发出前删除 hop-by-hop、代理认证和内部追踪 Header。
- `Host`、`:authority`、`Connection`、`Transfer-Encoding` 和 `Content-Length` 由 Gateway 管理，脚本不能直接控制。

### 5.2 Body

RPC 中正文只使用 base64：

```json
{
  "encoding": "base64",
  "data": "eyJvayI6dHJ1ZX0=",
  "length": 11,
  "sha256": "<64 hex>",
  "complete": true
}
```

- `length` 是原始 bytes 长度，不是 base64 字符数。
- `complete=false` 的正文不能进入 inline Hook。
- observe 可以选择跳过过大正文，并记录 `body_too_large`；不能把片段交给普通非流式解密脚本并声称解密成功。
- 首版不允许 Runner 自己读取 blob ID，避免赋予存储访问能力。

### 5.3 HTTP 规范化

Gateway 捕获的是 Go HTTP 栈解析后的语义消息：

- chunked framing 已被解析，不保存原 chunk 边界。
- 发往目标前重新计算 `Content-Length` 或安全的 transfer encoding。
- Transport 必须禁用自动响应解压缩，避免保存正文与 `Content-Encoding` 不一致。
- TLS MITM 首版只协商 HTTP/1.1；HTTP/2、WebSocket Upgrade 和 HTTP/3 单独设计。

## 6. Result 信封

成功替换示例：

```json
{
  "protocolVersion": "traffic-transform/v1",
  "invocationId": "tti_01...",
  "action": "replace",
  "message": {
    "kind": "request",
    "method": "POST",
    "path": "/api/order",
    "status": 0,
    "headers": [
      {"name": "Content-Type", "value": "application/json"}
    ],
    "body": {
      "encoding": "base64",
      "data": "eyJvayI6dHJ1ZX0=",
      "length": 11,
      "sha256": "<64 hex>",
      "complete": true
    }
  },
  "annotations": [
    {"key": "codec", "value": "example-v1"}
  ],
  "statePatch": {}
}
```

Gateway 必须验证：

- protocol/invocation/revision 与调用一致。
- `replace` 必须有 message，`pass` 不能偷偷带超限正文。
- method/path 修改仍在 binding 与边界范围内。
- scheme/host/port 不能由脚本返回或修改。
- Header、状态码、正文长度、hash 和总输出满足上限。
- observe 结果只能存为 decoded view，不能替换线上消息。

## 7. 错误码

稳定错误码至少包括：

- `revision_not_loaded`
- `revision_hash_mismatch`
- `unsupported_protocol`
- `hook_not_implemented`
- `invalid_input`
- `invalid_output`
- `body_too_large`
- `deadline_exceeded`
- `cpu_limit_exceeded`
- `memory_limit_exceeded`
- `worker_crashed`
- `dependency_unavailable`
- `script_exception`
- `circuit_open`
- `runner_unavailable`

原始 Python traceback 只进入受限诊断日志；API 和 Agent 工具返回清理后的摘要、错误码和 revision ID，不能泄露宿主路径或控制面环境变量。

## 8. Python SDK 契约

Agent 编写普通模块，不实现网络服务。固定 runner 负责加载模块、调用 Hook 和序列化：

```python
from cyberstrike_transform import Message

def decode_request(ctx, wire: Message) -> Message:
    plaintext = decode_application_payload(wire.body)
    return wire.with_body(
        plaintext,
        content_type="application/json",
    )

def mutate_request(ctx, logical: Message) -> Message:
    return logical

def encode_request(ctx, logical: Message, original_wire: Message) -> Message:
    ciphertext = encode_application_payload(logical.body)
    return original_wire.with_body(
        ciphertext,
        content_type="application/octet-stream",
    )
```

SDK 提供：

- bytes 与 Header 的安全访问器。
- `with_body`、`set_header`、`remove_header` 等不可变更新方法。
- JSON、base64、hex、URL 编码和压缩辅助函数。
- 受控密码学库适配，但不提供网络、文件系统或命令执行封装。
- 输出 schema 与大小的本地预校验。

脚本 manifest：

```json
{
  "protocolVersion": "traffic-transform/v1",
  "language": "python3",
  "entrypoint": "transform.py",
  "sdkVersion": "1",
  "hooks": ["decode_request", "encode_request"],
  "requirements": ["cryptography==<runner-provided-version>"]
}
```

Runner 无网络安装依赖。`requirements` 只能引用 runner inventory 中预装且版本锁定的包；缺失依赖在 activate 前失败。

## 9. 事务内状态

部分协议需要在请求阶段生成 nonce 或派生 key，并在响应阶段继续使用。v1 支持有界的事务内 JSON state：

- Hook 通过 `statePatch` 写入，后续 Hook 通过 `transactionState` 读取。
- Gateway 持有 state，Runner 不维护跨请求全局状态。
- state 大小、层级、key 数和 value 类型都有上限。
- state 只活到事务完成或超时，默认不进入普通 decoded view。
- 为漏洞复现需要保存时，只保存加密后的 state artifact 或 hash，并明确标注敏感级别。
- v1 不支持跨事务可变 session state；需要时另行设计带并发和恢复语义的 store。

## 10. 流式、缓冲和性能

Gateway 为每个语义 HTTP 请求生成独立 transaction ID。TLS MITM 连接可以承载多个顺序 HTTP/1.1 事务；连接级错误与事务级错误分开记录。首版不在一个 HTTP/1.1 连接上并行处理多个请求。

### 10.1 无 Transform

请求和响应保持流式转发，同时 tee 到有界 spool/blob writer。正文不整体进入内存。

### 10.2 Observe

- 线上流量继续流式传输和捕获。
- 完整正文落盘后，异步调用 decode Hook。
- decoded view 稍后补充到事务，不增加目标响应关键路径延迟。
- 如果正文超过 transform 上限，保存原始证据并记录解码跳过原因。

### 10.3 Inline

- 请求在发往目标前必须完整缓冲到 `transform_max_body_bytes`。
- 响应在返回 Agent 前必须完整缓冲到相同或独立上限。
- 超限默认失败关闭，不能把部分加密正文送入脚本。
- 使用磁盘 spool + 有界内存窗口，避免大正文全部驻留 Go heap。
- 每对话、每 binding 和全局都有并发 semaphore 与最大排队时间。
- fuzz 场景的正文存储可以聚合，但 inline Hook 仍逐条执行。

后续若需要处理超大文件，新增独立的 streaming transform 协议，不在 v1 中用隐式分块模拟。

## 11. Runner 传输与生命周期

首版 Runner 在私有端点提供：

- `GET /v1/health`
- `POST /v1/invoke`

使用 HTTP/1.1 + JSON 是实现细节，Go 内部接口保持独立，后续可以替换 Unix socket、MessagePack 或 gRPC。端点要求：

- 仅监听 sidecar 私有网络或 host loopback。
- 每代 runner 使用随机能力令牌；令牌不进入 Agent 环境和日志。
- 请求设置 body 上限、deadline 和 invocation nonce。
- health 返回 runner generation、protocol version、已加载 revision hash 和 worker pool 状态，不返回源码。

容器 Runner 启动流程：

1. 控制面创建专用配置 volume，并用无网络 init 容器写入 revision bundle。
2. Runner 以只读方式挂载 bundle，校验 manifest 和源码 SHA-256。
3. Runner 启动预热 worker pool，health 报告准确 hash。
4. Gateway 只有在 hash 与已批准 binding snapshot 一致后才切换流量。
5. 旧 runner 等待在途 invocation 完成后销毁；失败则保留旧 binding，不半激活新 revision。

## 12. 失败矩阵

| 场景 | Observe | Inline |
| --- | --- | --- |
| Runner 不可用 | 原流量继续，记录错误 | 默认 502/受控失败，禁止发送未处理正文 |
| Hook 超时/崩溃 | 原流量继续，计入熔断 | 失败关闭，计入熔断 |
| 正文超过脚本上限 | 跳过 decode，原流量继续 | 失败关闭并标明 `body_too_large` |
| 脚本输出非法 Header | 丢弃 decoded view | 失败关闭 |
| 脚本尝试改 host/port | 忽略并记录违规 | 拒绝事务并熔断候选 |
| 证据存储不可用 | 转发继续，发出审计告警 | 转发策略不变；不能伪称证据已保存 |
| 审计 collector 不可用 | Gateway 本地有界缓冲 | 同左；缓冲满后告警但不绕过边界 |
| 连续失败达到阈值 | 打开熔断，停止调用 | 打开熔断并失败关闭 |

## 13. 控制面接口

当前已实现的 REST 流量接口：

- `GET /api/traffic-transactions`
- `GET /api/traffic-transactions/:id`
- `GET /api/vulnerabilities/:id/traffic-evidence`
- `POST /api/vulnerabilities/:id/traffic-evidence`
- `DELETE /api/vulnerabilities/:id/traffic-evidence/:transactionId`
- `GET /api/traffic-transforms`（脚本、限定站点的使用案例和注入对话；不含源码与 binding config）
- `GET /api/traffic-transform-revisions/:id/source`（需要独立的 `traffic_transform:read_source` 权限）

Transform 当前通过 Agent MCP 的 `create_traffic_transform`、`validate_traffic_transform`、`test_traffic_transform`、`activate_traffic_transform` 和 `deactivate_traffic_transform` 使用。Agent 激活时必须指定 `matcher.hosts`；抓包仍覆盖完整对话，但只有命中 host（以及可选 path、method、content-type）的事务才进入 Runner。管理端已提供 observe binding 的作用范围与启停接口；inline 仍不能通过这些接口自行审批：

- `POST /api/traffic-transforms`
- `POST /api/traffic-transforms/:id/revisions`
- `POST /api/traffic-transform-revisions/:id/validate`
- `POST /api/traffic-transform-revisions/:id/test`
- `POST /api/conversations/:id/traffic-transform-bindings`
- `PUT /api/traffic-transform-bindings/:id/scope`（只更新 matcher 与优先级，不读写 binding config）
- `POST /api/traffic-transform-bindings/:id/activate`
- `POST /api/traffic-transform-bindings/:id/disable`
- `DELETE /api/traffic-transform-bindings/:id`（只允许删除已停用的 observe 使用案例；保留 revision 与历史运行证据）
- `GET /api/traffic-transform-bindings/:id/runs`

列表 API 不返回源码和正文；详情仍按权限返回摘要。源码、敏感正文和导出使用独立权限并记录读取审计。

所有正文响应都带 `untrustedContent=true`、内容 hash、长度、完整性和来源阶段。Agent MCP 适配器不得把目标正文拼接成系统级提示，也不得根据正文中的自然语言自动调用 activate/approve 工具。

## 14. 验收测试

协议实现至少覆盖：

- 重复 Header、二进制正文、空正文、压缩正文和多字节文本。
- decode→encode round-trip hash 一致和允许的非确定性差异。
- method/path 合法修改与 host/port 非法修改。
- observe 异步不阻塞转发。
- inline 超时、OOM、worker kill、非法 JSON 和超大输出失败关闭。
- request state 正确传递到 response，且不同并发事务不串值。
- revision 热切换不把同一事务分配给两个 revision。
- Gateway/Runner 重启、熔断和半激活恢复。
- fuzz 高并发下内存、磁盘、队列和正文保留符合上限。
- 代理认证和追踪令牌不进入脚本或上游。
