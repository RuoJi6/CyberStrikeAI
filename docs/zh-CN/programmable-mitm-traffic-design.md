# Agent 可编程 MITM 与流量证据设计

> 状态：阶段 1、Host 尽力捕获、阶段 3 与 observe 数据面已实现；inline 仍在设计中
> 最后更新：2026-08-27  
> 工作分支：`codex/mitm-traffic-evidence`  
> 基线分支：`codex/docker-agent-runtime`

## 1. 目标与范围

本功能不是只增加一个被动 MITM 代理，而是提供“Agent 可编程流量工作台”：

1. 捕获 Agent 产生的 HTTP/HTTPS 请求与响应，并关联对话、Agent、工具执行和漏洞。
2. Agent 可以编写脚本，对 HTTPS 解密后的应用层密文进行解码、修改和重新编码。
3. 脚本先用历史报文离线验证，再由用户或策略批准后挂到实时流量。
4. 漏洞详情直接展示关联的完整 HTTP 事务，不再只依赖 `evidence` 文本。
5. Web fuzz 等高流量行为只持久化代表样本、数量和关键差异，不保存每个完整报文。
6. 本机执行和容器执行共享数据模型、脚本协议和 Agent 工具，只替换流量入口与脚本运行后端。

需要区分两层“加解密”：

- **TLS MITM**：网关使用对话级 CA 终止客户端 TLS，再与目标建立新的 TLS 连接。Docker 分支已有基础能力。
- **应用层编解码**：例如正文使用 AES、RSA、SM2/SM4、自定义 XOR、压缩、签名或动态字段。Agent 编写的 Traffic Transform 处理这一层。

首版“完整数据包”指完整 HTTP 请求/响应消息，不等同于 Ethernet/TCP 层 PCAP。TCP/UDP 首版仍只记录连接和统计信息。

### 1.1 当前分支已经实现

- Docker Agent 的 HTTP 请求/响应正文通过每对话私有 spool 捕获并导入数据库，单方向最多保存 10 MiB；截断时保留真实长度和完整性标志。
- 未解密 HTTPS 保存 CONNECT 控制报文、目标和隧道上下行字节数，不把 TLS 密文伪装成已解密 HTTP。
- Web fuzz/请求突发按 30 秒行为窗口识别，连续空闲 3 秒后结束，只保存一个完整代表事务、总数、状态码分布和最多 32 个代表路径。
- 独立“流量证据”页面、事务详情、敏感正文 RBAC，以及漏洞详情内的证据列表和关联 API。
- Agent MCP 已提供流量检索、详情读取、漏洞证据关联，以及 Transform 的创建、隔离验证、历史报文 dry-run、observe 激活和停用。
- Python Transform Runner 使用私有 Docker internal network、随机 token、非 root、只读 rootfs、无 capabilities、无公网和 CPU/内存/PID 限制。
- active observe binding 在证据导入后异步执行 decode，原始 wire message 不被修改；失败时原流量继续。
- Host 对话通过带随机认证凭据的 loopback Gateway 和临时对话 CA 尽力捕获遵循代理环境的 HTTP/HTTPS 子进程流量，记录为 `best_effort`。

当前没有实现 Host 每次执行的细粒度追踪令牌、实时 inline 改包/重新编码、管理员 inline 审批页面、每对话 Runner sidecar 和 blob/配额层。下文相应章节描述的是目标架构，不代表当前已交付能力。当前部署与验证方法见[流量证据与 Transform Runner 运维](traffic-evidence-operations.md)。

## 2. 已冻结的核心决策

### 2.1 可信边界

- Egress Gateway 是唯一可信的网络执行点，边界策略判定永远早于脚本。
- Agent 生成的脚本是不可信代码，不能载入网关 Go 进程。
- 脚本不能修改边界快照、上游出口、目标 host/port、审计记录或 auth profile。
- 容器模式使用独立 `transform-runner` sidecar；不把脚本 runner 放入 Agent 容器或网关容器。
- 本机模式使用受管理的本地 worker 子进程；生产配置可以完全禁止本机 inline 脚本。
- 已激活脚本使用不可变 revision，历史流量始终能追溯到准确源码 SHA-256。

### 2.2 运行模式

- `observe`：只产生解码视图，不改变线上流量；脚本失败时原流量继续。
- `inline`：允许在明文阶段修改并重新编码；超时、崩溃或非法输出默认失败关闭。
- 创建、校验和离线测试脚本不改变网络行为。
- 激活 `inline` 必须具有独立 RBAC 权限，并经过 HITL/用户批准。

### 2.3 证据与审计

- 现有 `egress_audit_events` 继续承担摘要、查询和不可变哈希链职责。
- 完整正文进入独立 traffic/blob 存储，审计事件只引用 `traffic_transaction_id`。
- 原始消息、解码视图、实际转发消息和脚本 revision 分开保存。
- 任何截断都必须显示真实长度、已保存长度和截断原因，不能标记为“完整”。

## 3. 总体架构

```text
Agent 命令/工具
    │
    │ HTTP(S)_PROXY + 对话 CA + 执行追踪令牌
    ▼
可信 Egress Gateway
    ├─ 原始目标边界校验
    ├─ TLS MITM
    ├─ client/upstream 消息捕获
    ├─ Transform 调度
    ├─ 输出 schema、大小和 Header 校验
    ├─ 变换后再次执行边界校验
    └─ 审计与证据持久化
             │
             │ 有界 RPC
             ▼
不可信 Transform Runner
    ├─ 加载不可变脚本 revision
    ├─ decode / mutate / encode
    ├─ 无数据库、无 Docker Socket
    ├─ 默认无外网
    └─ CPU、内存、时间、并发、输入和输出硬限制
```

控制面负责 revision、绑定、批准、runner 生命周期和流量索引。网关在控制面不可用时仍按已激活的不可变快照运行，不能回退到直连或绕过边界。

## 4. HTTP 事务与证据模型

现有 `egress.ActivityEvent.HTTPPacket` 每方向最多保存 32 KiB，适合作为审计投影，不应扩展为完整流量仓库。

### 4.1 `traffic_transactions`

一个事务表示一次完整 HTTP 请求/响应，保存：

- `id`、`conversation_id`、`project_id`
- `agent_id`、`execution_id`、`tool_call_id`
- `runtime_mode`：`host`、`container`
- `capture_coverage`：`enforced`、`best_effort`、`unknown`
- `scheme`、`host`、`port`、`method`、`path`、`http_status`
- `started_at`、`completed_at`、延迟和上下行字节数
- `boundary_snapshot_id`、`rule_id`、`upstream_route_id`
- `transform_binding_id`、`transform_revision_id`、变换结果
- `aggregate_kind`、`aggregate_count`、首次/末次时间和差异摘要
- `request_message_id`、`response_message_id` 等阶段引用

### 4.2 `traffic_messages`

一个事务可以保存六个阶段：

1. `client_request`：客户端送入代理的消息。
2. `decoded_request`：脚本生成的可读逻辑消息。
3. `upstream_request`：实际发往目标的消息。
4. `upstream_response`：目标返回的消息。
5. `decoded_response`：脚本生成的可读逻辑消息。
6. `client_response`：实际返回 Agent 的消息。

Header 使用有序多值列表，而不是 `map[string][]string`，避免丢失重复 Header 和顺序。每个阶段保存 start-line、Header、正文引用、内容类型、编码、完整性状态和 SHA-256。

### 4.3 `traffic_blobs`

- 小文本正文可内联；较大或二进制正文写入 blob/artifact 存储。
- 数据库保存 blob ID、SHA-256、原始长度、保存长度、MIME、编码、压缩和加密元数据。
- 默认正文配额按用户、项目和对话三级限制。
- 到达软上限时停止保存普通流量正文，但继续保存摘要和显式漏洞证据。
- 到达硬上限时明确记录 `quota_exceeded`，不阻塞网关转发。
- 敏感正文应支持静态加密、保留周期和单独读取权限。

### 4.4 漏洞关联

新增 `vulnerability_traffic_evidence`：

- `vulnerability_id`
- `traffic_transaction_id`
- `role`：`primary`、`supporting`、`retest`
- `note`
- `created_by_agent_id`、`created_at`

`record_vulnerability` 增加可选 `traffic_evidence_ids`。原 `evidence` 文本继续保存结论、观察点和非 HTTP 证据；原始请求/响应无需再次复制。

## 5. Traffic Transform 领域模型

### 5.1 表与对象

- `traffic_transforms`：逻辑脚本、名称、说明、语言、所有者和状态。
- `traffic_transform_revisions`：不可变源码、入口点、依赖清单、协议版本、SHA-256 和校验结果。
- `traffic_transform_bindings`：revision、对话、匹配器、模式、优先级、失败策略和批准信息。
- `traffic_transform_runs`：离线/在线执行、Hook、输入/输出 hash、耗时、错误和 runner 身份。
- `traffic_transform_runner_states`：runner generation、健康、熔断、最后错误和恢复时间。

修改脚本必须创建新 revision。切换绑定是原子操作；旧 revision 不删除，除非没有证据引用且用户执行受审计的清理。

### 5.2 匹配器

绑定最少支持：

- scheme、host、port
- path 前缀或受限正则
- HTTP method
- request/response Content-Type
- Header 存在或固定前缀
- request、response 或双向

匹配器只能缩小当前边界授权，不能扩大目标范围。若多个绑定命中，按显式优先级排序；首版限制为每方向至多一个 inline binding，但可以有多个 observe binding，避免不可预测的多重加密。

### 5.3 Hook

首版协议定义六个可选 Hook：

```python
def decode_request(ctx, wire_message): ...
def mutate_request(ctx, logical_message): ...
def encode_request(ctx, logical_message, original_wire_message): ...

def decode_response(ctx, wire_message): ...
def mutate_response(ctx, logical_message): ...
def encode_response(ctx, logical_message, original_wire_message): ...
```

- `decode_*`：把应用层密文转换成逻辑消息。
- `mutate_*`：可选修改逻辑消息；observe 模式不会调用。
- `encode_*`：把逻辑消息重新编码为线上消息。

这样未来的手工改包/重放页面可以插入 decode 与 encode 之间，不需要重写脚本协议。

### 5.4 请求执行顺序

```text
接收请求
  → 校验原始目标
  → 捕获 client_request
  → decode_request
  → [inline] mutate_request
  → [inline] encode_request
  → 校验脚本输出与 Content-Length
  → 再次校验 method/path；禁止改变 scheme/host/port
  → 注入受控 auth profile
  → 捕获 upstream_request
  → 发往目标
```

### 5.5 响应执行顺序

```text
接收目标响应
  → 捕获 upstream_response
  → decode_response
  → [inline] mutate_response
  → [inline] encode_response
  → 校验脚本输出与 Content-Length
  → 捕获 client_response
  → 返回 Agent
```

`Proxy-Authorization`、hop-by-hop Header、内部追踪 Header 和 auth profile 凭据不提供给脚本，也不转发到目标。

## 6. Agent 使用方式

新增 MCP 工具，全部根据当前上下文确定项目、对话和授权范围，不允许 Agent 自报其他对话 ID：

| 工具 | 作用 |
| --- | --- |
| `list_traffic_transactions` | 检索事务摘要；fuzz 默认只返回聚合项 |
| `get_traffic_transaction` | 按需读取原始、解码和实际转发视图 |
| `create_traffic_transform` | 以源码创建逻辑脚本或新 revision |
| `validate_traffic_transform` | 检查语法、协议、依赖、Hook 和输出约束 |
| `test_traffic_transform` | 对历史事务离线运行，返回 decoded view、diff 和 round-trip 结果 |
| `activate_traffic_transform` | 绑定 revision；inline 触发批准 |
| `deactivate_traffic_transform` | 停止实时绑定，不删除历史版本 |
| `link_traffic_evidence` | 把事务关联到漏洞 |

推荐 Agent 流程：

1. 产生或选择代表请求，读取事务并确定密文位于 Header、query 还是 body。
2. 编写 Python 脚本，调用 `create_traffic_transform` 固化 revision。
3. 对历史事务离线测试，验证 decode 结果和 decode→encode round-trip。
4. 先以 observe 模式激活，确认实时解码稳定且没有超时。
5. 需要自动改包时申请 inline；用户看到脚本 hash、作用域、失败策略和样例 diff 后批准。
6. 验证漏洞后把事务 ID 传给 `record_vulnerability` 或调用 `link_traffic_evidence`。

工具只把按需片段返回模型。大正文通过分页、byte range 或 artifact 引用读取，避免模型上下文爆炸和无意泄露。

### 6.1 脚本来源

首版 `create_traffic_transform` 直接接收有大小上限的源码，不接受任意宿主机路径。以后可以增加受控的 `workspace_artifact_id` 导入，但必须通过标准化工作区接口读取，不能让控制面按 Agent 提供的路径读取文件系统。

### 6.2 Secret 边界

Agent-authored 脚本只能使用 Agent 已知的值和绑定配置，不能读取 auth profile 或控制面 Secret。因为脚本本身由 Agent 编写，把隐藏 Secret 交给脚本等价于交给 Agent。

如果以后需要使用对 Agent 隐藏的业务密钥，必须增加 `trusted-admin` transform：由管理员审核源码、运行在独立信任级别、禁止向 decoded view 输出 Secret，并与 Agent-authored transform 分开管理。

### 6.3 来自目标的数据不是指令

HTTP Header、正文、解码结果和目标 JavaScript 都属于不可信目标数据。Agent 工具返回时必须使用结构化字段和明确的 untrusted-content 标记，系统提示词要求模型把它们作为分析材料而不是指令执行。目标响应中出现“调用工具”“关闭审计”“激活脚本”等文本不能改变工具授权或批准流程。

## 7. 容器执行目标拓扑

```text
                         ┌─ egress network ─→ Internet
                         │
Agent internal network   │       transform internal network
┌──────────────┐    ┌────┴─────────┐    ┌──────────────────┐
│ Agent 容器   │ →  │ Egress       │ →  │ Transform Runner │
│ 无公网路由   │    │ Gateway      │    │ Sidecar          │
└──────────────┘    └──────────────┘    └──────────────────┘
       ▲                     ▲                    ▲
       │                     │                    │
  不连接 transform 网   同时连接三条网      不连接 Agent/公网
```

- 继续复用 Docker 分支现有的每对话 internal network、Gateway、TLS Authority 和不可变边界快照。
- 新增每对话 transform internal network，只连接 Gateway 和 Runner。
- Runner 使用独立只读镜像、非 root、`cap-drop=ALL`、`no-new-privileges`、只读 rootfs、tmpfs、PID/CPU/内存限制。
- 脚本 revision 由控制面写入专用 named volume，再以只读方式挂给 Runner；Agent 容器不挂载该 volume。
- Runner 没有公网路由、数据库、Docker Socket、工作区或上游代理凭据。
- Gateway 用短期能力令牌调用 Runner，并校验每个返回值；Runner 不是授权判定点。
- Agent 容器重建后，已激活 revision 从控制面恢复；工作区不是唯一副本。
- HTTP/HTTPS 无直连路径时，捕获覆盖级别标记为 `enforced`。证书固定的客户端会失败并记录 TLS 错误，而不是绕过网关。

当前阶段的抓包 spool 已按对话隔离；observe Runner 是控制面通过独立 private internal network 调用的共享无状态实例，且不与 Agent/Gateway 网络相连。目标版本再演进为上图所示的每对话 sidecar，并让 Gateway 直接调用 inline Hook。

## 8. 本机执行拓扑（尽力捕获已实现）

```text
Host ExecutionBackend 启动的 Agent 命令
  │ 每次执行注入 HTTP(S)_PROXY、CA
  ▼
127.0.0.1 随机端口上的对话 Gateway
  │ loopback 有界 RPC
  ▼
控制面 SQLite 与受管理的 Transform Runner
```

- 不修改操作系统全局代理、系统信任库或防火墙。
- `ProxiedExecutionBackend` 已包装现有 Host backend，为每次命令注入带认证的代理 URL、对话 CA 和常见客户端信任变量。
- 系统根证书与对话 CA 组成的 CA bundle 放在权限为 `0700` 的临时目录，文件为 `0600`；代理只监听 `127.0.0.1` 随机端口，按对话隔离，应用关闭后清理。
- HTTP/HTTPS 完整消息直接经过相同的高流量压缩后写入数据库，再异步触发已绑定的 observe Transform。
- 当前共享 Transform Runner 仍使用固定程序和协议，不由网关拼接任意 shell 命令；后续再演进为受管理的每对话 Worker。
- 本机程序可以忽略代理变量、证书固定或直接建立 socket，因此覆盖级别只能标记为 `best_effort`。
- 后续管理员可配置 `host_transform_mode=disabled|observe|inline`，生产默认建议 `observe`。

若以后要强制接管本机所有流量，需要单独设计具有管理员权限的 TUN/透明代理。首版不能静默修改系统全局网络配置，也不能宣称本机流量已被完全强制捕获。

## 9. 执行关联

每次 `ExecutionBackend.Execute` 创建短期签名令牌，令牌只包含随机 ID 或不可伪造的最小 claims。网关校验后关联：

- `conversation_id`
- `agent_id`
- `execution_id`
- `tool_call_id`
- 过期时间与 nonce

令牌通过代理认证通道传递，网关消费后删除，绝不转发上游或写入普通 Header 视图。无法携带令牌的流量仍按对话级 Gateway 关联，但执行和工具标记为未知。

## 10. Runner 稳定性与失败策略

- 每个 Hook 有 wall time、CPU、内存、输入正文、输出正文、日志和并发硬上限。
- stdout/stderr 只保存有界诊断日志；RPC 使用独立 socket/协议。
- 输出必须通过版本化 schema 校验，拒绝 CRLF Header 注入、非法状态行和不一致正文长度。
- 连续超时/崩溃触发 binding 熔断，进入 `open_circuit`。
- observe 熔断后保留原始流量并停止调用脚本，同时告警。
- inline 熔断后默认失败关闭；只有管理员显式配置的非敏感测试场景允许 fail-open。
- 网关重启时从已批准 binding snapshot 恢复；控制面不可用不能自动启用新 revision。
- 每次运行保存 revision hash、输入/输出 hash、耗时、runner generation、结果和错误码。

推荐状态机：

```text
draft → validated → tested → observe_active
                              │
                              ├─ disable → inactive
                              └─ approve_inline → inline_active

observe_active / inline_active
  ├─ repeated_failure → open_circuit
  ├─ new_revision → pending_switch
  └─ deactivate → inactive

open_circuit → successful_probe → previous_active_state
```

## 11. Web fuzz 与高流量

继续复用 `internal/egressactivity.Aggregator` 的行为检测，不依赖 ffuf、gobuster 等工具名：

- 未达到阈值前暂存少量事件。
- 达到阈值后只保留首个完整代表事务。
- 聚合保存总请求数、成功/失败/状态码分布、字节数、首次/末次时间、目标/端口/路径或 payload 差异摘要。
- 后续正文不持久化为完整证据；Agent 显式标记保留的个别事务除外，并受配额约束。
- inline 脚本仍处理每个实际请求；聚合只影响存储和 UI，不能跳过协议必需的重新编码。
- runner 并发耗尽时对 inline 请求施加反压，不允许无界排队。

## 12. 页面设计

新增独立一级页面“流量工作台”：

```text
流量工作台
  ├─ 实时流量：筛选、聚合标识、捕获覆盖级别
  ├─ 事务详情：Client / Decoded / Upstream 三视图与 Diff
  ├─ Transform：源码版本、校验、离线测试、绑定和熔断状态
  └─ 证据关联：漏洞、证据角色、备注和导出
```

漏洞详情增加“数据包证据”，按事务展示请求、响应、脚本版本、原始/解码视图和截断状态。Authorization、Cookie、Token 和正文读取需要 `traffic:read_sensitive`；页面默认遮罩敏感 Header，临时显示行为写审计。

## 13. RBAC 与批准

建议新增权限：

- `traffic:read`、`traffic:read_sensitive`、`traffic:export`、`traffic:delete`
- `traffic_transform:read`、`traffic_transform:write`
- `traffic_transform:activate_observe`
- `traffic_transform:activate_inline`
- `traffic_evidence:link`

inline 批准记录必须包含 revision SHA-256、匹配范围、方向、失败策略、批准人、批准时间和过期时间。revision 或匹配范围变化后原批准自动失效。

## 14. 代码落点

- `internal/traffic/`：事务、消息、blob、聚合和证据领域模型。
- `internal/traffictransform/`：协议、revision、校验、runner client、supervisor 和状态机。
- `internal/egress/`：在 `serveForwardRequest` 增加受控 Hook 点，不把脚本实现耦合进 Proxy。
- `internal/security/`：Host 的 `ProxiedExecutionBackend` 和执行追踪令牌。
- `internal/runtime/container/`：Runner sidecar、第二内部网络、专用 volume 和恢复。
- `internal/database/traffic.go`：流量、脚本、绑定、run 和漏洞关联迁移。
- `internal/handler/traffic.go`：工作台 API、正文分片读取和敏感权限。
- `internal/app/traffic_tools.go`：Agent MCP 工具。
- `cmd/traffic-transform-runner/`：固定 runner 入口。
- `web/`：流量工作台、事务详情、脚本测试和漏洞证据区。

### 14.1 与现有代码的具体衔接

- `internal/egress/proxy.go` 的 `serveForwardRequest` 是 HTTP/HTTPS 统一 Hook 点；`serveConnect` 仍只负责 CONNECT、SNI 和 TLS 终止。
- 现有 `boundedPacketCapture` 与 `MaxHTTPPacketBodyBytes` 保留为 32 KiB 审计预览。新增 spool recorder，不能简单提高常量后继续把正文写进 Docker 日志。
- 现有 `serveInterceptedTLS` 每个 CONNECT 只读取一个 HTTP 请求，并由 `interceptedResponseWriter` 强制 `Connection: close`。实现流量工作台前必须先支持一个 TLS 会话内的多请求循环、正确 body drain、每请求独立事务 ID 和连接关闭语义，否则 fuzz 会重复 TLS 握手并产生严重开销。
- 当前 `egressaudit.Collector` 通过 `RuntimeActivityStreamer` 读取 Gateway Docker stdout，只适合有界摘要。完整正文使用独立 `TrafficEvidenceCollector`，不能复用日志通道。
- 当前 `RuntimeSpec` 把 Agent 与 Egress Gateway 作为一个生命周期拓扑。Transform Runner 应有独立 generation 和 reconcile controller；激活脚本只滚动 Runner/Gateway，不得重建 Agent 容器或工作区。
- 当前 Host `ExecutionBackend` 使用去重后的请求级环境覆盖；包装器只对本次子进程追加代理/CA 变量，不修改 `os.Environ` 或系统配置。

### 14.2 Evidence spool

Host Gateway 和 Docker Gateway 统一写版本化 spool envelope：

1. Gateway 把 metadata、Header 和正文 blob 写入系统生成的对话目录，先写 `.tmp`。
2. 完成 hash 和 fsync 后原子改名为 `.ready`。
3. `TrafficEvidenceCollector` 校验 conversation/generation、schema、大小和 SHA-256，再写数据库/blob store。
4. 成功后删除 `.ready`；失败进入有界重试和 quarantine，不把损坏记录显示成完整证据。

Docker 本地引擎首版可以把应用私有、按对话隔离的 spool 目录 bind mount 到 Gateway，只允许该精确目录读写；Agent 和 Transform Runner均不挂载。远程 Docker Engine 需要另加流式 ingestion transport，不能假设应用主机能直接读取远端 bind path。

spool 具有磁盘配额、文件数上限、单事务上限和启动恢复扫描。spool 满时继续执行边界策略与网络转发，产生明确的 `evidence_dropped` 审计告警；不能回退到把正文写入 stdout。

## 15. 实施阶段

当前完成情况：阶段 1 的事务/页面/漏洞关联与高流量聚合已完成（blob 配额和 intercepted TLS keep-alive 除外）；阶段 2 已完成 Host 对话级尽力捕获，尚缺每次执行的细粒度追踪令牌；阶段 3 已完成；阶段 4 已完成导入后的异步 observe 主路径。阶段 5 尚未开始。

### 阶段 1：事务与证据底座

- 重构 intercepted TLS keep-alive，使一个 CONNECT 可以安全处理多个 HTTP/1.1 事务。
- 新增统一事务/blob 模型、配额、保留策略和 RBAC。
- 实现 Gateway evidence spool 与独立 collector，完整正文不走 Docker stdout。
- 将现有 32 KiB `HTTPPacket` 投影关联到 transaction ID。
- 完成工作台只读页面和漏洞证据关联。
- 保持 fuzz 聚合并补充状态码/差异摘要。

### 阶段 2：本机入口与执行追踪

- [x] 实现 Host loopback Gateway 和 `ProxiedExecutionBackend`。
- [ ] 为 host/container 命令注入短期执行追踪令牌。
- [x] UI 明确显示 `enforced` 与 `best_effort`。

### 阶段 3：脚本 revision 与离线测试

- 实现 runner 协议、源码版本化、静态校验和历史报文 dry-run。
- 增加 create/validate/test MCP 工具。
- 验证 decode→encode round-trip，不接入实时网关。

### 阶段 4：Observe 模式

- 接入请求/响应 decode Hook。
- 实现 runner 生命周期、超时、熔断、恢复和诊断。
- 页面显示原始/解码 diff 与 revision。

### 阶段 5：Inline 模式

- 增加激活批准、失败关闭、二次边界校验和 Header 规范化。
- 支持修改后重新编码和请求/响应回放。
- 完成漏洞证据一键关联与导出。

### 阶段 6：完整验收

- 容器：无直连绕过、CA 隔离、sidecar 隔离、容器重建恢复、高流量聚合。
- 本机：curl、Python requests、Node、Git 等常见客户端，并正确标注不可捕获场景。
- 故障：死循环、OOM、超大正文、非法 Header、runner 崩溃、网关重启、配额耗尽。
- 安全：跨对话读取、目标改写绕过、凭据泄露、SSRF、审计篡改和脚本供应链。

## 16. 首版明确不做

- 不安装系统根证书，不修改全局代理或防火墙。
- 不承诺捕获本机模式下忽略代理的所有 socket 流量。
- 不允许脚本改变授权目标或替代边界策略。
- 不把所有 fuzz 请求全文落库。
- 不把 PCAP、HTTP/2 多路复用、QUIC/HTTP/3 或透明代理伪装成已支持。
- 不允许 Agent 未经批准激活会改变线上请求的 inline revision。
- 不向 Agent-authored 脚本提供对 Agent 隐藏的业务 Secret。
