# Agent 容器、边界规则与出站代理实施计划

> 状态：执行中  
> 当前阶段：阶段 8 已提前完成；阶段 7 正在进行 ARM64 最终回归、内置浏览器验收与精确版部署
> 最后更新：2026-08-23
> 工作分支：`codex/docker-agent-runtime`

本文档是 Agent 容器化的唯一执行清单。以后每完成一个阶段，必须先通过本地测试和测试机验收，再将该阶段勾选为完成，然后进入下一阶段。

## 1. 已确认的产品决策

- [x] 一个对话对应一个 Agent 容器，同一对话的主 Agent 和子 Agent 共享该容器。
- [x] 创建对话时，用户可以选择“容器执行”或“本机执行”。
- [x] 容器模式使用 `ghcr.io/usestrix/strix-sandbox:1.3.0` 作为首选基础环境；生产配置使用镜像 digest 锁定，不依赖浮动 tag。
- [x] 当前发布只在受控 ARM64 测试机上构建并验证 `linux/arm64`；不在 GitHub 或 AMD64 环境构建，后续增加其他架构时须单独设计、生成 SBOM 并验收。
- [x] 文件持久化是用户可选项。启用时使用每对话独立 Docker named volume 挂载到 `/workspace`，不允许用户任意绑定宿主机路径。
- [x] 对话完成或长时间空闲可停止容器；对话再次执行时恢复。删除容器和删除工作区是两个独立操作。
- [x] 边界规则默认拒绝，对话开始时生成不可变快照；Agent 不能在运行中扩大授权范围。
- [x] Agent 容器不能直接出网，所有受控 HTTP/HTTPS 出站请求必须经过 CyberStrikeAI 出站网关。
- [x] 上游单代理或代理组只决定“从哪个出口访问”，不能覆盖边界规则的允许/拒绝结果。
- [x] 首版只做 HTTP 及 HTTPS CONNECT/SNI 域名级强制和审计，不解密 HTTPS 正文。完整 TLS 解密是后续可选阶段。
- [x] 当前系统没有 Agent 浏览器功能，本计划不实现浏览器会话、浏览器配置文件或每 Agent 浏览器命名空间。临时文件和工具输出仅按对话工作区隔离。
- [x] 工具以“构建时进入受控派生镜像”为主，对话首次启动只校验工具清单和版本，不在后台下载全部工具。镜像发布必须生成工具 inventory 和 SBOM。
- [x] Agent 状态、对话、审计和运行时期望状态存在容器外；容器是可重建计算资源，不作为唯一状态源。

## 2. 安全架构基线

```text
CyberStrikeAI 控制面
  ├─ 对话/容器生命周期
  ├─ 边界策略与不可变快照
  ├─ 代理条目/代理组/路由规则
  └─ 审计、健康监控与管理 API
                  │
                  │ 创建资源/下发已锁定快照
                  ▼
      每对话独立 internal Docker 网络
      ┌──────────────────────────────────┐
      │ Agent 容器                     │
      │ - 无公网默认路由              │
      │ - 可选 /workspace named volume │
      │ - 不挂载 Docker socket         │
      └───────────────┬──────────────────┘
                      │ HTTP/HTTPS/DNS
                      ▼
      ┌──────────────────────────────────┐
      │ 对话级出站网关 + 策略 DNS       │
      │ - 执行快照，默认拒绝          │
      │ - 唯一连接公网的容器          │
      │ - 可选上游单代理/代理组       │
      └───────────────┬──────────────────┘
                      ▼
                   Internet
```

强制要求：

1. Agent 容器只连接对话级 `--internal` 网络，不连接 Docker 默认 `bridge`。
2. 只有出站网关同时连接对话内部网络和出口网络。
3. 不依赖 `HTTP_PROXY`/`HTTPS_PROXY` 环境变量实现安全边界；环境变量只是客户端兼容性配置，Docker 网络路由才是强制边界。
4. 不挂载 `/var/run/docker.sock`，不使用 `--privileged`、`--network host` 或任意宿主机 bind mount。
5. 默认 `cap-drop=ALL`、`no-new-privileges`、只读 rootfs 和 tmpfs 临时目录。需要原始套接字的明确工具配置可单独增加 `NET_RAW`，永不默认授予 `NET_ADMIN`/`SYS_ADMIN`。
6. 出站网关、策略或代理路由不可用时必须失败关闭，不能回退到直连。

## 3. 执行范围

“容器模式”不能只改 `exec`。需要先对现有工具按执行位置分类：

| 类别 | 例子 | 容器模式行为 |
| --- | --- | --- |
| OS 命令/脚本 | `exec`、`execute`、Python/Shell 脚本 | 必须在对话容器内执行 |
| 命令型 YAML 工具 | `nmap`、`ffuf`、`nuclei` 等本地二进制 | 必须在对话容器内执行 |
| 内部业务工具 | 记录漏洞、项目事实、查询资产 | 仍在 CyberStrikeAI 控制面执行 |
| 远程 API 工具 | FOFA/Quake 等 | 控制面或独立服务执行，必须单独标注出站边界 |
| 外部 MCP | 远程或本地 MCP Server | 不会因 Agent 容器化自动进入容器，需单独隔离和审计 |
| WebShell/C2 | 平台管理的远程会话 | 属于独立高风险边界，不伪装为已被 Agent 容器隔离 |

页面和审计中必须显示每个工具的实际执行位置：`container`、`control-plane`、`external`。

## 4. 边界规则模型

### 4.1 规则类型

- `allow-visit`：普通访问，默认只允许 `GET`/`HEAD`/`OPTIONS`，可明确增加方法。
- `allow-attack`：主动测试，必须限定域名或 IP、端口、路径、并发和速率。
- `blocked`：显式拒绝，优先级最高。
- `auth-only`：作为允许规则的访问标记，只允许网关为匹配请求注入指定凭据配置；原始凭据不进入 Agent 环境变量和工具参数。

最小规则字段：

```json
{
  "effect": "allow-attack",
  "host": "api.example.com",
  "schemes": ["https"],
  "ports": [443],
  "pathPrefixes": ["/v1/"],
  "methods": ["GET", "POST"],
  "authProfileId": null,
  "rateLimit": {"requestsPerSecond": 2, "burst": 5},
  "expiresAt": null
}
```

### 4.2 `allow-attack` 的强制方式

`allow-attack` 不是给 Agent 的一句提示词，也不等于“该对话可以攻击任意目标”。它是快照中针对一个规范化目标的授权等级，需要同时通过两道门：

```text
工具调用
  │
  ├─ 动作门：工具权限 + HITL/确定性高风险规则
  │             判断是否允许主动测试行为
  │
  └─ 目标门：出站网关匹配 allow-attack 快照
                校验 host/IP + scheme + port + 可见的 path/method + 限速
```

任何一道门拒绝，请求都不能发出。边界快照只能由用户/管理员在控制面生成，Agent 传入的 URL、Host header、SNI 或工具参数不能修改授权等级。

首版不解密 HTTPS，因此对 HTTPS 的 `allow-visit`/`allow-attack` 只能硬性区分到域名/SNI 和端口；无法硬性区分加密隧道内的 method/path/payload。这部分先由工具权限和 HITL 收窄，只有启用阶段 8 TLS 完整审计后才能在网络层对 HTTPS method/path 强制。界面必须显示当前强制精度，不得将“目标级”标记为“完整请求级”。

### 4.3 固定优先级

```text
精确 blocked 路径
  > blocked 主机/网段
  > 精确 allow-attack
  > 精确 allow-visit
  > 默认拒绝
```

规则匹配前必须统一规范化小写域名、IDNA、末尾点、默认端口、IPv4/IPv6 和 URL 路径。重定向后的每一跳都必须重新评估。

### 4.4 默认禁止目标

除非管理员在专用安全策略中显式授权，始终禁止：

- loopback、link-local、multicast、unspecified 地址。
- RFC1918 私网、Docker 网关、宿主机服务地址。
- 云元数据地址，包括 `169.254.169.254` 及 IPv6 对应范围。
- Docker API、Unix Socket 和未授权的直接 IP 请求。

DNS 和出站网关必须各自检查解析结果，避免只依赖 DNS 名称导致 DNS Rebinding 绕过。

## 5. 数据与 API 边界

计划新增的主要数据对象：

| 对象 | 用途 |
| --- | --- |
| `container_runtime_profiles` | 镜像、平台、资源限制、默认能力、工作区策略 |
| `conversation_runtimes` | 对话与容器/网络/卷/网关的生命周期绑定 |
| `boundary_policies` | 可编辑的边界策略草案 |
| `boundary_policy_rules` | 域名/IP/端口/路径/方法/限速规则 |
| `boundary_policy_snapshots` | 对话启动时生成的不可变 JSON 及 SHA-256 |
| `conversation_boundary_bindings` | 对话与快照的绑定 |
| `egress_proxies` | 加密保存的单代理条目 |
| `egress_proxy_groups` | 代理组和失败关闭策略 |
| `egress_proxy_group_members` | 优先级、权重、启用状态 |
| `conversation_egress_bindings` | 不使用上游/单代理/代理组的对话级绑定 |
| `egress_audit_events` | DNS、CONNECT、HTTP、限速、健康和拒绝事件 |

凭据不得出现在列表 API、前端 DOM、容器环境变量、日志或预览结果中。对话列表只返回脱敏后的代理摘要。

计划提供的 API 路由组：

- `/api/container-runtimes`：运行时列表、详情、启动、停止、重建、删除。
- `/api/container-runtime-profiles`：镜像和资源配置。
- `/api/boundary-policies`：边界策略与规则管理、模拟匹配。
- `/api/conversations/{id}/boundary`：对话快照、摘要和重建影响。
- `/api/egress-proxies` 与 `/api/egress-proxy-groups`：代理资源库、组成员和检测。
- `/api/conversations/{id}/egress`：对话出口绑定和影响预览。
- `/api/egress-audit-events`：可搜索、分页和导出的出站审计。

## 6. 界面信息架构

左侧“容器管理”使用可折叠子页，不把所有内容放在一个长页面滚动：

```text
容器管理
  ├─ 容器概览
  ├─ 对话容器
  ├─ 运行环境
  ├─ 边界规则
  ├─ 出站代理
  ├─ 网络活动
  └─ 出站审计
```

交互要求：

- 页面标题和副标题显示当前子页信息，不固定显示“容器管理”。
- 代理条目在“出站代理”中可折叠；代理组和单代理为同一资源域的不同子区块。
- “绑定单个代理”时只显示单代理选择器；“绑定代理组”时只显示代理组选择器。
- 选择器使用统一组件，支持搜索、多选、键盘操作和空状态；不直接使用浏览器原生多选 `select`。
- 表格支持 10/20/50/100 条每页，翻页和筛选保持在 URL 状态中。
- 所有破坏性操作说明容器、文件卷、快照和日志的实际影响。
- 对话页必须显示当前执行位置、容器状态、边界快照摘要和出口摘要，但容器后台初始化不得阻塞对话页面。
- “网络活动”显示正在发生的域名访问与允许/阻断决策；“出站审计”显示已持久化、可搜索和可导出的历史记录。
- 实时活动至少显示：时间、对话/Agent/工具、请求类型（DNS/HTTP/CONNECT）、域名、解析 IP、端口、判定、命中规则、上游代理、延迟和字节数。
- 纯 HTTP 可额外显示 method、path 和目标响应状态；首版 HTTPS CONNECT 只显示域名/SNI、端口、隧道结果和上下行字节，不伪造 URL path、HTTP status 或正文可见性。
- 网络活动支持按对话、Agent、工具、域名、允许/阻断和代理出口筛选，并通过 SSE 或 WebSocket 增量刷新，不对整页轮询。

## 7. 分阶段执行清单

### 阶段 0：设计冻结、执行面盘点与测试基线

目标：在写 Docker 调用代码前，确认所有会执行本机命令的路径，避免只隔离一部分工具。

阶段交付物：[Agent 容器执行面盘点](container-execution-surface-inventory.md)。

- [x] 确认当前工作分支与 `main` 基线一致，无旧 Docker 实现残留。
- [x] 固化容器、文件、边界和出口决策。
- [x] 创建本分阶段实施文档和验收门槛。
- [x] 盘点 `internal/security/executor.go`、Eino 文件/命令工具、YAML 命令工具、MCP、工作流、批量任务、终端与 WebShell/C2 的执行边界。
- [x] 为工具生成 `container`/`control-plane`/`external` 执行位置清单。
- [x] 固化第三方 API 工具、本地 stdio MCP、管理终端、WebShell 和 C2 的例外原则，不让它们被“对话容器化”错误覆盖。
- [x] 记录当前本地 Go/静态前端测试与测试机部署/启动基线。

验收门槛：执行路径清单经代码搜索与测试交叉验证，每一类都有明确归属，无“容器模式下不确定在哪执行”的路径。

### 阶段 1：容器运行时最小安全闭环

目标：建立一个对话一个容器的生命周期，但默认使用 `network=none`，本阶段不开放任何出网。

计划代码落点：

- `internal/runtime/container/`：Engine 探测、镜像检查、创建/启动/停止/重建/删除、资源状态对账。
- `internal/database/container_runtime.go`：运行时和资源绑定持久化。
- `internal/handler/container_runtime.go`：RBAC 受控的管理 API。
- `internal/config/config.go` 与 `config.example.yaml`：功能开关、镜像 digest、资源上限、空闲停止策略。

任务：

- [x] 引入可替换的 `RuntimeManager` 接口，不在 handler 中拼接 Docker CLI 命令。
- [x] 检查 Docker Engine 可用性、服务端架构、镜像 manifest/digest 和容器实际镜像。
- [x] 创建对话级容器，容器名只使用系统生成 ID，资源添加 CyberStrikeAI 所有者标签。
- [x] 实施 CPU、内存、PIDs、超时、只读 rootfs、tmpfs、capabilities 和 seccomp 基线。
- [x] 实施 `nofile`、工作区磁盘、容器日志轮转、每对话/全局并发 exec 和排队反压限制。
- [x] 实现可供首次执行调用的持久化后台容器初始化协调器：有界 worker/队列、并发去重、显式失败重试、重启恢复和 RBAC 受控状态 API；请求线程不等待 Docker。
- [x] 启动就绪前校验工作区、镜像 digest、工具 inventory、Docker Socket 隔离和无出网基线，校验失败不得标记为就绪。
- [x] 实施启动、停止、重建、删除和异常状态对账。
- [x] 实施基于所有者标签的孤儿容器/网络/卷扫描器，失败记录可重试墓碑，不依赖人工 `docker prune`。
- [x] 实施对话空闲自动停止，不自动删除工作区。
- [x] 编写 fake runtime 单元测试和真实 Docker 集成测试。

验收门槛：两个对话生成两个不同容器；停止/恢复互不影响；容器不能访问公网、宿主机 Docker Socket 或其他对话容器。

### 阶段 2：对话执行路由与文件生命周期

目标：容器模式的 OS 命令和脚本确实在对话容器内执行，而不是只有 UI 显示容器状态。

计划代码落点：

- `internal/security/`：抽象 host/container `ExecutionBackend`，保留现有输出流式化、PTY、取消、超时和溢出文件行为。
- `internal/mcp/` 与 Eino 执行上下文：必须传递 `conversation_id`、`runtime_mode` 和 `execution_location`。
- `internal/database/conversation.go`：对话运行模式、文件持久化选项和运行时摘要。

任务：

- [x] 创建对话时可选 `host`/`container`，存量对话显式迁移为 `host`。
- [x] 容器模式首次执行调用阶段 1 后台初始化协调器，未就绪前不将 OS 命令回退到宿主机，同时不冻结对话列表。
- [x] 将 `exec`、`execute`、脚本执行和命令型 YAML 工具统一路由到对话执行后端。
- [x] 保留 stdout/stderr 流式输出、取消、超时、PTY 回退、退出码和输出溢出语义。
- [x] 将超大工具输出落到该对话 `/workspace/.tool-output/`，数据库和模型上下文只保留有界摘要与文件引用。
- [x] 将 Agent 输入、上传文件和命令输出路径规范化到 `/workspace`，防止路径穿越。
- [x] 未启用持久化时，明确告知删除容器会删除文件；启用时创建每对话 named volume。
- [x] 删除对话时提供“保留工作区”和“一并删除”两种明确选项。
- [x] 审计中记录真实执行位置、container ID 和 image digest。
- [x] 编写 host/container 后端契约测试，确保返回格式和取消语义一致。

验收门槛：在容器工具输出中检查到容器标识且宿主机不产生测试文件；两个对话的 `/workspace` 不可互访；恢复、取消和超时均通过测试。

### 阶段 3：边界规则控制面与不可变快照

目标：先建立可测试的确定性规则引擎；本阶段容器仍然不开放出网。

计划代码落点：

- `internal/boundary/`：规则规范化、匹配、优先级、重定向重评估和私网/IP 阻断。
- `internal/database/boundary_policy.go`：策略、规则、快照和对话绑定。
- `internal/handler/boundary_policy.go`：CRUD、模拟判定、快照查看和 RBAC。

任务：

- [x] 实现 `allow-visit`、`allow-attack`、`blocked` 和 `auth-only` 访问标记。
- [x] 实现域名、IDNA、IPv4/IPv6、端口、scheme、path 和 method 规范化。
- [x] 实现默认拒绝、固定优先级和禁止目标集。
- [x] 实现规则模拟 API，返回命中规则和拒绝原因。
- [x] 对话首次启动前生成 canonical JSON 快照与 SHA-256，后续编辑不修改已绑定快照。
- [x] 边界变更只能通过“创建新快照 + 显式重建运行时”生效。
- [x] 单元测试覆盖重叠规则、通配符边界、编码、IPv6、私网、过期规则和重定向。

验收门槛：相同快照在多次判定中结果一致；编辑草案不改变运行对话；所有未命中目标默认被拒绝。

### 阶段 4：强制出站网关与策略 DNS（域名级）

目标：在不解密 HTTPS 正文的情况下，实现 HTTP 及 HTTPS CONNECT/SNI 强制边界。

计划代码落点：

- `cmd/cyberstrike-egress/`：独立的最小出站网关进程/镜像。
- `internal/egress/`：代理协议、快照加载、DNS 判定、连接重评估、限速和审计事件。
- `internal/runtime/container/`：每对话 internal 网络、网关 sidecar 和出口网络编排。

任务：

- [x] 将 Agent 容器从 `network=none` 迁移到每对话独立 internal 网络。
- [x] 启动每对话出站网关，只有网关同时连接出口网络。
- [x] 网关从只读配置加载已绑定快照，启动后回报快照 SHA-256；不在每个请求中信任 Agent 传入的范围。
- [x] 实现 HTTP forward proxy 及 HTTPS CONNECT 的 host/port/SNI 判定。
- [x] 实现策略 DNS：未允许名称返回 NXDOMAIN，网关连接前再次验证所有 IP。
- [x] 阻断直接 IP、自定义 DNS、DoH、重定向跳出、IPv6 绕过、DNS Rebinding 和宿主机网关访问。
- [x] 为客户端配置 proxy 环境变量，但用网络隔离验证即使客户端忽略它也无法直连。
- [x] 网关崩溃、快照不匹配或快照不可读时失败关闭。
- [x] 编写代理协议单元测试、Docker 网络集成测试和绕过回归测试。

验收门槛：允许域名只能经网关访问；blocked 和未知域名同时在 DNS 和网关被拒绝；任意直接网络方式不得绕过；网关不可用时容器无法出网。

### 阶段 5：上游单代理、代理组和凭据边界

目标：在已经强制的 CyberStrikeAI 出站网关之后增加用户可配置的上游出口。

任务：

- [x] 实现 HTTP/HTTPS/SOCKS 代理条目，服务端加密保存凭据，所有返回结果脱敏。
- [x] 实现代理组、多成员搜索选择、优先级、同优先级权重轮询、熔断和冷却。
- [x] 实现对话级的“无上游代理”、“单代理”和“代理组”绑定。
- [x] 实现用户/项目默认值的继承预览，对话级显式选择优先。
- [x] 所有上游都不可用时默认阻断，不返回直连。
- [x] `auth-only` 凭据由出站网关对匹配请求动态注入，Agent 和容器不能读取凭据原文。
- [x] 测试机动态发现虚拟机直连子网中的宿主机地址访问 `7897` 代理，不硬编码其他网络的 `172.*` 地址。
- [x] 测试凭据隐藏、代理轮询、熔断、冷却、失败关闭和跨对话隔离。

验收门槛：单代理与代理组路由结果可解释；凭据不出现在 API、DOM、日志、容器 env 或命令行；所有上游失败时没有直连流量。

### 阶段 6：容器管理 UI、出站审计与确定性健康监控

目标：用户能清楚看到执行位置、初始化、网络决策和失败原因，不将多个管理域堆在同一长页面。

任务：

- [x] 实现“容器管理”可折叠侧栏与 7 个独立子页，页头跟随当前子页。
- [x] 创建对话时显示执行模式、文件持久化作用、边界策略和出口选择。
- [x] 展示容器/网关/DNS/工作区状态、资源用量、镜像 digest、快照 hash 和最后错误。
- [x] 实现统一可搜索单选/多选组件，修复弹层、层级、宽度、键盘可访问性和空状态。
- [x] 实现 10/20/50/100 每页、服务端分页、搜索、状态筛选和 URL 状态保留。
- [x] 实现对话出站网络活动实时流，页面可立即看到新的域名请求、解析 IP、允许/阻断和命中规则。
- [x] 审计 DNS、HTTP、CONNECT、拒绝、限速、上游路由和生命周期事件，支持搜索与导出。
- [x] 日志记录 `conversation_id`、`container_id`、`agent_id`、快照 hash、目标、判定、命中规则和上游；敏感 header/body 默认不保存。
- [x] 对每个对话的审计事件增加前序 hash，可检测删除或篡改。
- [x] 实现确定性限速、并发上限、429 冷却、连续登录失败、WAF/CAPTCHA 信号和手动恢复。
- [x] 完成桌面和窄屏 UI 浏览器验收，无刷新卡死、空对话、错误页头或下拉框遮挡。

验收门槛：管理页不依赖单页长滚动；状态与 Docker 实际资源一致；发起测试请求后能在网络活动页立即看到域名与决策；拒绝、熔断和停止都能追溯到决策与快照。

### 阶段 8（提前实施）：HTTPS 完整审计

按 2026-08-23 的实施范围调整，本阶段提前到阶段 7 之前完成；能力仍默认关闭，只有显式启用的对话才注入独立 CA 并进行 HTTPS 解密。

- [x] 为每个对话生成独立短期 CA，只向对应 Agent 注入公开证书，私钥仅挂载到该对话网关。
- [x] 增加不解密域名列表和证书固定兼容策略，精确匹配配置域名及其子域。
- [x] 解密后按真实 HTTPS method/path 重新执行边界规则；header/body 只参与受控转发，不进入规则结果或审计持久化。
- [x] 请求/响应正文始终不持久化；本阶段不提供正文持久化开关，避免以未完成的脱敏、加密、限量和清理能力扩大数据面。
- [x] 对密码、Cookie、Authorization、Token、文件上传和二进制响应编写专门数据泄露测试。

验收门槛：启用完整审计的对话可检查 HTTPS URL 与方法；未启用的对话不信任任何相关 CA；证书和正文不跨对话泄露。

### 阶段 7：安全加固、端到端验收与渐进发布

目标：在阶段 8 验收完成后，完成绕过测试、故障演练和 ARM64 验证，再允许生产启用。根据 2026-08-22 的明确范围调整，不再执行 AMD64 构建或验收。

任务：

- [ ] 验证 ARM64 镜像 SBOM、来源、digest 锁定、签名或离线校验和及真实可运行性。
- [ ] 进行直接 IP、自定义 DNS、DoH、IPv6、DNS Rebinding、重定向、宿主机网关、Docker API 和跨对话访问绕过测试。
- [ ] 进行网关崩溃、Docker 重启、CyberStrikeAI 重启、数据库暂停、审计缓冲区填满和磁盘空间不足演练。
- [ ] 验证对话删除、容器删除、卷保留/删除和孤儿资源回收。
- [ ] 验证 RBAC：普通用户不能修改系统镜像、规则快照、他人代理凭据或审计保留策略。
- [ ] 使用功能开关按用户/项目小范围开启，默认不改变现有 host 模式。
- [ ] 在 ARM64 测试机完成真实对话、容器命令、工作区、规则和代理全链路验收。
- [ ] 更新安全模型、配置、部署、运维、审计和排错文档。

验收门槛：ARM64 安全回归全部通过，测试机实际验收通过，未解决的高风险项为 0，支持一键回退到原 host 执行模式。

## 8. 每阶段固定执行流程

后续必须按以下顺序完成每个阶段：

1. 只将当前阶段标记为进行中，不同时开始后续阶段。
2. 编写数据迁移、后端、前端和测试；未完成的能力放在默认关闭的功能开关后。
3. 本地执行格式化、单元测试、静态前端测试和必要的 Docker 集成测试。
4. 审查本阶段 diff，确认无凭据、测试产物、大二进制或无关文件。
5. 将本次源码更新到测试机，校验测试机工作树只包含本阶段变更，从源码重建并重启 CyberStrikeAI。
6. 在测试机执行该阶段 API、Docker 实际状态和负向安全用例；保存命令、结果和服务版本作为验收证据。
7. 使用 Codex 内置浏览器打开测试机，核对 URL/页面标题、非空白、无框架错误层、控制台健康、目标交互和截图。若内置浏览器截图后端明确返回无法捕获，必须记录该失败，并同时保留 URL、title、可见 DOM 和 console error/warning 四项证据，不得跳过浏览器验收。
8. 只有本地、测试机和内置浏览器三类证据都证明验收门槛通过，才勾选当前阶段、记录日期/提交/证据摘要，再开始下一阶段。

不允许以“能编译”、“页面能打开”或“主路径成功”代替阶段验收。

## 9. 全局必测安全用例

- [ ] 默认策略拒绝未知域名。
- [ ] `blocked` 同时在 DNS 和网关拒绝。
- [ ] `allow-visit` 允许 GET，但拒绝未授权 POST。
- [ ] `allow-attack` 只允许规定主机、端口和路径。
- [x] `auth-only` 凭据只在网关匹配请求时使用，Agent 无法读取。
- [ ] 直接 IP、自定义 DNS、DoH、IPv6 和跳转到 blocked 主机均被拒绝。
- [ ] DNS 重绑定到私网或宿主地址被拒绝。
- [ ] 移除代理 env 后，Agent 容器仍无法直连外网。
- [ ] 出站网关停止、快照损坏、上游代理全部失败时均失败关闭。
- [ ] Agent 无法访问 Docker Socket、宿主管理端口或其他对话网络/工作区。
- [ ] 跨对话复用网关身份、快照或凭据失败。
- [ ] 每个决策可追溯到对话、容器、快照 hash 和命中规则。

## 10. 非首版范围

以下能力不得暗中混入首版，需要单独设计和验收：

- 通用 TCP/UDP 内容解析和审计。
- 默认开启的 HTTPS TLS 解密。
- Kubernetes、Swarm 或跨 Docker 主机调度。
- 任意宿主机目录 bind mount。
- 将外部 MCP、WebShell 或 C2 声称为已被对话容器隔离。
- 依赖模型判断代替确定性网络规则。
- Agent 浏览器运行时、浏览器会话/profile 和每 Agent 浏览器命名空间。当前系统没有 Agent 浏览器，所以不实现、不预留虚假状态；文档中“Codex 内置浏览器”仅用于测试机 UI 验收。

## 11. 阶段验收记录

| 阶段 | 状态 | 完成日期 | 源码提交 | 本地验收 | 测试机/API | 内置浏览器 | 备注 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 已完成 | 2026-08-20 | `8c2c6bc` | Go 全量通过；前端 115/115 | 源码/文档已同步；服务 active；`GET /` 200 | `#chat` 非空白、无 console 错误；交互进入 `#dashboard` | 执行面全部归属；CGO 候选构建失败已回滚，当前服务健康 |
| 1 | 已完成 | 2026-08-20 | `58ff685`（第 1 项）；`45e8da3` + `1645256`（第 2 项）；`36ab2d3`（第 3 项）；`7c17fd5`（第 4 项）；`49f0256`（第 5 项）；`338e047`（第 6 项）；`b4024d6`（第 7 项）；`45ef059`（第 8 项）；`93ff9a7`（第 9 项）；`b44f018`（第 10 项）；`99b3e10`（第 11 项） | Go 全包、`go vet ./...`、前端 115/115 及容器/数据库完整 race 通过；fake runtime 覆盖创建、就绪、生命周期、孤儿资源和空闲停止；真实验收发现并修复非 root 镜像的 tmpfs 工作区不可写问题 | 最终 Zig CGO Linux ARM64 服务 SHA-256 `93a33f7f…17c547b`，active / HTTP 200 / `NRestarts=0`；阶段探针 SHA-256 `f2ef6d69…bdc77c2`；仅使用测试机已有 `cyberstrike/agent` ARM64 镜像并跳过远端 manifest，未下载安全工具；两容器 provider 不同、无默认路由、无 Docker Socket、运行时工作区隔离、停止 A 不影响 B、未持久化 tmpfs 恢复后按设计重置，删除后容器/网络/卷残留均为 0 | 通过 SSH 本地转发访问同一测试机 `?qa=20260820-stage1-item11#dashboard`：URL/标题正确，仪表盘非空白，console 日志为空，截图成功；自动化未填写敏感密码 | 阶段 1 全部验收通过；阶段 2 开始后才持久化 host/container 选择、将 Agent 执行路由到容器并实现可选 named volume；当前仍不声称 Agent 已在容器执行；不实现 Agent 浏览器 |
| 2 | 已完成 | 2026-08-21 | `361ba97`（第 1 项）；`28d9ad2` + `45eb12a`（第 2 项及异步续跑补强）；`a292b52`（第 3 项）；`424e084` + `9926f2c` + `9535a57` + `0fe6fa6` + `629d06f`（第 4 项）；`43c8084` + `637cf14` + `067f513`（第 5 项）；`02d786d` + `0aace18`（第 6 项）；`6125b5c` + `369d35b`（第 7 项）；`9faf158` + `9add95c` + `ef6222b` + `38e7cca`（第 8 项及弹窗居中、可视视口补强）；`c09fc40` + `9299fcb`（第 9 项）；`9cc10cd`（第 10 项） | 第 1—8 项详细证据保留于历史版本。第 9 项：Go 全包、静态检查、MCP 定向与 race、前端 126/126 均通过，数据库迁移/回读、伪造审计输入拒绝、ExecutionService、HTTP MCP 直连和 Eino 执行路径均有回归覆盖。第 10 项：host/container 后端契约定向与 race、`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、前端 126/126、`git diff --check` 全部通过，覆盖成功、非零退出、取消和无输出超时 | 第 9 项真实 host/container 审计记录与 Docker inspect/SQLite/API 三方一致。第 10 项已推送并精确部署 `9cc10cd`；Linux ARM64 二进制 SHA-256 `822d0768ae004aac8ee5b65e8cf0bc47759f29cfe0a7e60d432d6d42c467c5cd`，服务 `active/running`、`NRestarts=0`，直连首页、登录、Bearer 鉴权均 HTTP 200，测试源码哈希与本地一致 | 内置浏览器可枚举最终 URL/title，但最终页的 DOM/console/screenshot 连续超时并重置连接，已如实记录并使用本机 Playwright 降级验收。`#mcp-monitor` 真实详情交互显示 `Container`、完整 container ID 和 image digest，1800×1000/390×844 无越界且 console 为空；截图 SHA-256 `083d3c3e…03a1d53` / `7b24992b…bf872a`。第 10 项无 UI 变更 | 阶段 2 第 1—10 项验收全部通过。删除弹窗另在 1800×1000/390×844 真实菜单路径复验居中、全屏遮罩与零 console 错误，未点击最终删除按钮；相关实施、补强和契约测试提交均已推送远端；`38e7cca` 将删除弹窗提升至 `body` 并按 layout/visual viewport 固定定位，桌面 1800×1000、Retina 902×484@2x、390×844 与 2×可视缩放中心偏差均为 0，打开/关闭、全屏遮罩、按钮可见性、console/page error/5xx 均通过 |
| 3 | 已完成 | 第 1—7 项：2026-08-21 | `25a4b0e`（第 1 项）；`7500867`（第 2 项）；`7ddfdf0`（第 3 项）；`a0691fe`（第 4 项）；`795441c`（第 5 项）；`a65a8a8`（第 6 项）；`e57b8ad`（第 7 项） | 第 1 项四种 effect 与数据库约束通过。第 2 项覆盖域名/IDNA、IPv4/IPv6、端口、HTTP(S) scheme、编码 path、method、规则去重排序与幂等性，解析差异均有拒绝回归。第 3 项覆盖默认拒绝、固定优先级、同级具体性、过期规则、CIDR、公网直接 IP 显式授权，loopback/私网/link-local/multicast/元数据/Docker API/DNS rebinding 阻断。第 4 项覆盖命中规则 ID、规范化目标、`blocked`、默认拒绝、DNS rebinding、非法 URL/IP、最多 64 个解析地址、策略不存在、未授权、权限缺失、own-scope 所有者隔离与 OpenAPI 路径。第 5 项覆盖固定 canonical JSON/硬编码 SHA-256、20 路并发首次绑定幂等、默认拒绝空快照、草案编辑隔离、新对话新 hash、选择权限、服务重启迁移、worker claim/手动启动/执行后端三重失败关闭、SQLite 不可变触发器、篡改检测、对话级查看 API 与 OpenAPI。第 6 项覆盖新快照准备但不生效、显式重建后与 runtime generation 原子激活、维护重建沿用同一快照、失败保留旧快照、12 路并发只生成一个待处理快照、快照令牌生命周期 CAS 防抢占、重启中断标记与显式替换、权限/参数校验、执行期间 pending 或 generation 不一致时失败关闭、追加激活不可变与旧库迁移。第 7 项覆盖重叠规则固定优先级、同级稳定决胜与插入顺序无关，精确主机/子域/后缀伪装和 path 前缀边界，编码点段/斜杠/双重编码，公网 IPv6/IPv4-mapped IPv6/IPv6 CIDR，RFC1918/loopback/ULA/link-local/DNS rebinding，过期临界点，以及每跳重定向到允许域、未授权域、编码阻断路径、私网和 rebinding 的独立重评估；所有功能均先验收后提交。定向与 race、`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、前端 128/128、`git diff --check` 全部通过 | 第 1 项数据库约束回滚验收通过。第 2 项精确部署 `7500867` 且 ARM64 规范化用例全通过。第 3 项精确部署 `7ddfdf0`，ARM64 策略用例全通过。第 4 项精确部署 `a0691fe`。第 5 项 ARM64 database/handler/app 测试二进制 SHA-256 分别为 `23b46af2…1a5227`、`a221c94a…1acf0b`、`37f6e8d4…c3e2fd`，候选版本先完成真实管理员登录、API、数据库与 UI 验收后才提交。最终已推送并精确部署 `795441c`（`vcs.revision=795441cd129230385deac7150bd46672f205b28c`、`vcs.modified=false`），Linux ARM64 服务二进制 SHA-256 `9a10b3cbb7894c47867b5e69d71e004b5848a85ad00f4ba57211c890ee53f1c4`，源码归档 SHA-256 `109e7d6dd1c4035b4f05dab2e045049f01aef3b277c3639a509ae595aea734c4`。真实 API 完成了选择策略创建、启动前 404/绑定后 200、两次 hash 重算、草案编辑后旧快照字节不变/新对话 hash 变化、删除草案后快照可读、未登录 401、host 绑定 400、策略缺失 404、默认拒绝空快照和 OpenAPI 验收；数据库迁移后已有运行时缺失快照数为 0，更新/存活绑定删除均被触发器阻断；服务 `active/running`、`NRestarts=0`、直连首页 HTTP 200，部署后 warning/error 日志为空。第 6 项 ARM64 database/handler/app 测试二进制 SHA-256 分别为 `abe6f104…f4992`、`13387b83…5a105`、`612eb987…cc02` 且全部通过；真实 QA 容器完成 generation 1→2 新快照显式重建、2→3 同快照维护重建、运行态重建 409 保留旧快照并恢复 stopped/idle，激活历史追加为 3 条、pending 为 0，源策略删除后快照仍可读且 SHA-256 重算一致。最终已推送并精确部署 `a65a8a8`（`vcs.revision=a65a8a89ac120459761edbafa9aff323dff26329`、`vcs.modified=false`），Linux ARM64 二进制 SHA-256 `b3b7227a1501554618e096f77597dc23a23bf775eb1cef8cb76dfbc8725e9fdd`，源码归档 SHA-256 `6050d257d6059e1d4545eadc10e1be8cdfa5cc9a0623f75f8e0e75e9b455cb67`；精确版本维护重建至 generation 4 后快照 ID/hash 不变，SQLite integrity/foreign-key check、全局 runtime/activation 对齐均通过，服务 active/running、NRestarts=0、首页 200 且本次启动后 warning/error 日志为空。第 7 项 boundary race、覆盖矩阵 10 次重复、Go 全包、`go vet`、`go mod tidy -diff`、前端 128/128 与 diff 检查全通过；Linux ARM64 boundary 测试二进制 SHA-256 `5c41cdff…cbc92` 在虚拟机原生 7 组全部 PASS。最终已推送并精确部署 `e57b8ad`（`vcs.revision=e57b8ad9b472c93ace6f22e17e497f51c1e9837d`、`vcs.modified=false`），服务二进制 SHA-256 `ea7aa5a17f52b1b2a18d96f8d97522fecc3ec1ba41c4195f783d7d4f72c3468b`，源码归档 SHA-256 `2bed94695f8839fb85683f31eec9499ea569d5079bbc8161b82fbbc45760bada`；服务 active/running、NRestarts=0、首页 200 且启动后无 warning/error | 第 1—7 项均无 UI 功能变更。第 5 项内置浏览器取得候选地址/标题并成功读取完整可见 DOM，但截图/控制台联合读取超时并重置；已如实记录并用本机 Playwright 直连 `?qa=20260821-stage3-item5-exact#chat` 降级验收：HTTP 200、标题 `CyberStrikeAI`、登录弹窗可见且居中、无框架错误层、console warning/error 与 page error 均为空，截图 SHA-256 `0dbff1ee820ee39cb6e3448e47998c6685b124b91cd14ec30367001e1ae28906`。第 6 项内置浏览器两次导航均超时并重置，已按流程降级到本机已安装 Chrome 的 Playwright，直连 `?qa=20260821-stage3-item6-exact#chat`：HTTP 200、标题/页面非空、登录弹窗精确居中、无 framework overlay、console warning/error、page error 或 5xx；截图 SHA-256 `817f244ec01b2849c301d31769ffb6b0de48ca817fe377500c8c113d3a5223cb` | 阶段 3 的控制面、不可变快照、生效事务与完整规则矩阵均验收完成；当前仍为 `network=none`，未开放容器出网；阶段 4 第 1 项将迁移到每对话独立 internal 网络 |
| 4 | 已完成 | 2026-08-21 | `7a7d01f`（第 1 项）；`0940cb8`（第 2 项）；`20ad08a`（第 3 项）；`66c8679`（第 4 项）；`70ea888`（第 5 项）；`5f3b237`（第 6 项）；`f0dddc5`（第 7 项）；`bf6fd1c`（第 8 项）；`998f787`（第 9 项） | 第 1 项证据同前。第 2 项容器/数据库/app/config/egress 定向与 race、`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、前端 128/128 与 `git diff --check` 全部通过；覆盖每对话 Agent+网关+内部网+出口网创建/回滚/启停/删除，固定镜像、最小权限与资源限制漂移拒绝，孤儿资源认领，启停失败原子回滚，旧运行时显式迁移与持久工作区保留。第 3 项同样通过 Go 全包、相关包 race、`go vet ./...`、`go mod tidy -diff`、前端 128/128 和差异检查；覆盖 canonical 快照文件原子发布、`0700` 受信目录/`0444` 文件、精确 SHA/模式校验、只给网关的单一只读 bind、启动/健康报告、Agent 启动前等待、缺失/篡改/错误报告失败关闭、显式快照迁移、持久卷兼容及旧本地镜像标签移动后的不可变 ID 校验。第 4 项在提交前通过 egress/container/app/database 定向与相关包 race、`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、前端 128/128 和差异检查；覆盖绝对形式 HTTP、Host 一致性、逐跳头剥离、CONNECT 分片 ClientHello、真实 TLS 1.3 SNI、缺失/重复/非法 SNI、ECH/ESNI、未知目标及 DNS 重绑定失败关闭。第 5 项继续通过上述完整矩阵，并覆盖 UDP/TCP DNS、只对有活动允许规则的规范域名解析、未知/blocked 名称不触发上游查询、解析结果全地址重评估、混合公网/私网答案、过期规则、blocked 公网网段、解析失败/空答案、并发与取消；运行时为快照网关动态发现内部 IPv4 并设为 Agent 唯一 DNS，创建、readiness、运行态检查均拒绝缺失、伪造或漂移地址。第 6 项同样在提交前通过相关包定向与 race、Go 全包、`go vet ./...`、`go mod tidy -diff`、前端 128/128 和差异检查；新增 DNS 服务端口 53/784/853/8853、已知加密 DNS 服务主机及后缀边界、DoH 路径/媒体类型、重定向逐跳重评估、混合 IPv6 Rebinding、internal 网络 `inhibit_ipv4` 以及 Agent/网关端点宿主网关漂移拒绝覆盖。第 7 项在提交前继续通过 Go 全包、container race、`go vet ./...`、`go mod tidy -diff`、前端 128/128 和差异检查；覆盖快照型网关 HTTP/HTTPS/ALL proxy 大小写变量与空 `NO_PROXY/no_proxy` 的精确生成，创建、运行态和 readiness 对缺失、外部代理、绕过列表、重复键及无网关意外代理的失败关闭。第 8 项在提交前通过 egress/container 定向测试各连续 10 次、相关包 race、`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、前端 128/128 与 `git diff --check`；覆盖运行中快照模式漂移主动退出，以及运行态对网关崩溃、unhealthy 和健康报告错配的失败关闭。第 9 项新增畸形 CONNECT authority 单元表、DNS/私网/元数据绕过回归表，以及默认安全跳过、显式启用后执行真实 Docker 的嵌入式集成测试；提交前通过 Go 全包、egress/container/Docker 测试 race、`go vet ./...`、`go mod tidy -diff`、前端 128/128 和差异检查 | 第 1 项候选和精确部署证据同前。第 2 项先在提交前候选版本完成真实旧运行时 generation 1→2 显式迁移，持久文件保留；两对话内部/出口网络 ID 与子网均不同，每个 Agent 只有自己的 internal 网，每个出口网仅网关挂载，默认 bridge 挂载数为 0。已推送并精确部署 `0940cb8`（`vcs.revision=0940cb859b06135e3ca6a2c66471e674578b2bea`、`vcs.modified=false`）；Linux ARM64 服务、网关二进制、容器测试、数据库测试和源码归档 SHA-256 分别为 `d0b5ece5…b57d72`、`10cf3517…165fd37`、`879e306e…936ad2`、`b4a9b7d3…c5c088d`、`b5db8c8d…32a9cab`，网关镜像 digest 为 `sha256:8b36ac60…3fa3fa26`。精确版本新对话的 SQLite 规格、Agent/网关 Docker 标签及镜像 digest 一致；运行态 internal 网挂载 2、出口网挂载 1，Agent 直连 `1.1.1.1` 退出码 7，网关以 UID/GID 65532、只读根、`cap-drop=ALL`、`no-new-privileges`、零 bind/端口、固定 CPU/内存/PID/tmpfs 限制运行；停止后两网挂载均为 0，删除后容器/网络/卷/数据库记录全部清零。第 3 项候选真实容器将 item-2 运行时显式迁移到 generation 2，工作区标记保留；网关仅挂载快照文件且命令/健康检查绑定同一 ID/SHA，首次健康报告结束于 `17:05:27.518`，Agent 于 `17:05:27.537` 才启动；临时移走快照后启动为 409、运行时记录为 `security_or_specification_drift` 且两容器保持退出，恢复后 reconcile/start/stop 均为 200。已推送并精确部署 `20ad08a`（`vcs.revision=20ad08a1fe58279b9595c0a4ba3540d0b67024c4`、`vcs.modified=false`）；服务、网关、container/app/database/egress 测试与源码归档 SHA-256 分别为 `f9932e03…0c3880`、`379148ed…5eb97`、`bdeb2d9e…e4a415`、`eb235230…8778e3`、`11a1525c…2cb88c`、`60dda040…c8e044`、`b66c16b8…2cb88c`，精确网关镜像为 `sha256:1c861667…c9634`；ARM64 原生测试全部通过，镜像在无网络、只读根、非 root、无 capability 的临时容器内回报精确快照 ID/SHA，服务 active、`NRestarts=0`、首页 200 且启动后无 warning/error。第 4 项 ARM64 原生 egress/container/app/database 测试全部 PASS；精确提交 `66c86790e273bfa3e47031326ee187295c72c060` 的服务、网关和源码归档 SHA-256 分别为 `d4af5613…26cd5`、`fe501458…cf392`、`7471a5f3…688db`，最终网关镜像为 `sha256:e40597d6…18cc5`。真实 HTTP 与 HTTPS CONNECT 均返回 559 字节；未知目标返回 403，SNI 不匹配与缺失均在上游连接前失败，强制解析到 `127.0.0.1` 返回 502；镜像以 UID/GID 65532、只读根、`cap-drop=ALL`、`no-new-privileges` 和单一只读快照挂载运行。精确服务已部署，运行进程哈希匹配，服务 active/running、`NRestarts=0`、首页 200 且启动后 warning/error 为 0。第 5 项候选与精确提交均在虚拟机通过 boundary/egress/container ARM64 原生测试，精确提交 `70ea888268598a93b51e65c22c57d6599860499d` 的服务、网关与源码归档 SHA-256 分别为 `a8a557df…734fb9`、`ef1da97a…cbfd3d`、`677f65ed…7e6f8`，最终镜像为 `sha256:b624a5a4…cd281a`。真实 UDP/TCP DNS 对 `example.com` 返回 NOERROR，未知 `iana.org` 返回 NXDOMAIN，loopback 重绑定同时返回 DNS NXDOMAIN 与代理 502；真实隔离 Agent 的唯一 DNS 为同网络网关 `172.20.0.2`，允许解析 6 行、未知解析退出 2、经代理 HTTP 为 559 字节、无代理直连退出 7，internal/egress 网络挂载数分别为 2/1。精确服务已部署且进程哈希匹配，服务 active/running、`NRestarts=0`、首页 200、启动后 warning/error 为 0。第 6 项候选与精确版本均通过 boundary/egress/container ARM64 原生测试，精确版 app/database 也为 PASS；精确提交 `5f3b237fd669dd0270c48273d4b49580a0001e21` 的服务、网关二进制与源码归档 SHA-256 分别为 `89b1839f…f2c6f1d1`、`0542e17e…03ab5f5`、`17a28d0e…6b095`，最终镜像为 `sha256:9dce4229…a7bddf`。真实隔离 Agent 的唯一 DNS 为 `172.20.0.1`，内部网 IPAM/Agent/网关端点均无宿主网关，宿主 bridge 无 IPv4，Agent 仅有直连子网路由且没有 IPv6 路由；授权 HTTP 为 200，DoH 路径/媒体类型、未知/私网 IP、DNS 端口和 IPv6 代理绕过均为 403，已知 DoH CONNECT 为 403，直接 HTTP、自定义 DNS TCP 与直接 IPv6 均失败。精确服务进程哈希匹配，配置固定镜像摘要可解析，服务 active/running、`NRestarts=0`、虚拟机内和直连首页均 200、启动后 warning/error 为 0。第 7 项候选和精确提交均通过 ARM64 container 原生测试，精确版 app/database 也为 PASS；精确提交 `f0dddc59d871c7d024ff7fe67f68bbc796f7450d` 的服务与源码归档 SHA-256 分别为 `ba9d7ca1…dd7430`、`eb3f02dc…96c3ef`。真实 Agent 自动继承 `http://172.20.0.1:3128` 的大小写 HTTP/HTTPS/ALL proxy，`NO_PROXY/no_proxy` 为空，未显式传 proxy 的 HTTP/HTTPS 均为 200；删除全部代理变量、强制 `NO_PROXY=*` 或替换为外部代理均因只有直连子网路由而失败。精确服务进程哈希匹配，服务 active/running、`NRestarts=0`、虚拟机内和直连首页均 200、启动后 warning/error 为 0。第 8 项候选首次 container 测试准确暴露 `CGO_ENABLED=0` 的 SQLite stub，提交前改用 Zig/CGO 重建并从头通过 egress/container 原生测试与故障矩阵。精确提交 `bf6fd1c71598495d2f224797106b7210b101d87f` 的服务、网关、boundary/egress/container/app/database 测试和源码归档 SHA-256 分别为 `52afe181…278da`、`87d9a3d5…d6fda`、`acba9026…aa42`、`559820d8…4bf3`、`f77de033…3651`、`f1c7a2c3…7c71`、`db181528…f792`、`be0731e5…8dd6`，精确网关镜像为 `sha256:306b6ed0…12935`；错误 SHA 和不可读快照启动退出码均为 1，网关崩溃后 Agent 代理与直连都失败，运行中快照变为可写后网关主动退出且两条出网路径继续失败。精确服务进程哈希匹配，固定镜像摘要可解析，服务 active/running、`NRestarts=0`、虚拟机内和直连首页均 200、启动后 warning/error 为 0。第 9 项候选真实测试先后纠正 scratch 镜像不能使用 CLI `CMD-SHELL` 健康检查、Docker 空网关显示为 `invalid IP`、显式授权公网 IP 应经网关访问而只阻断直连三项测试假设，修正后连续 3 次及最终复测均 PASS、容器/网络残留为 0。精确提交 `998f787b84c9a6ac91ab7f4dc0c4bdc999bdc64e` 的服务、网关、boundary/egress/Docker/container/app/database 测试与源码归档 SHA-256 分别为 `f372d4f7…a0fa`、`15192b76…a504`、`acba9026…aa42`、`fe2e93d4…a3f8`、`6fdbd3d4…7656`、`f77de033…3651`、`f1c7a2c3…7c71`、`db181528…f792`、`e6053d52…8a6e`，精确网关镜像为 `sha256:5901c2b0…d0d7c`；ARM64 五组原生测试及真实 Docker 三连测全部 PASS，隔离拓扑 internal/egress 挂载数固定为 2/1，允许 HTTP 为 200，直连、自定义 DNS、DoH、IPv6、`NO_PROXY`、外部代理和网关崩溃绕过均被阻断，残留为 0。精确服务进程哈希匹配，固定镜像摘要可解析，服务 active/running、`NRestarts=0`、虚拟机内和直连首页均 200、启动后 warning/error 为 0 | 第 1—9 项均无 UI 功能变更，未重复浏览器视觉验收；管理员网页登录保留到后续统一 UI 验收并等待即时敏感操作确认 | 新运行时为每对话 Agent 仅 internal、网关 internal+专属出口网络；存量旧运行时只在用户显式重建时迁移。网关现在只信任控制面生成并以单文件只读挂载的不可变快照，启动与健康检查都回报精确 SHA-256；第 4 项已实现 HTTP forward proxy、HTTPS CONNECT/SNI 判定与连接前全地址重评估，第 5 项已实现 UDP/TCP 策略 DNS 和 Agent 唯一 DNS 绑定，第 6 项通过 Docker bridge `inhibit_ipv4` 取消内部网宿主桥地址和默认网关，并以唯一策略 DNS、默认拒绝、连接前全地址重评估、已知加密 DNS 服务主机/端口以及明文 DoH 形态识别补齐绕过矩阵；不解密 HTTPS 正文，管理员显式授权的任意自建 HTTPS 端点仍属于受信策略输入。第 7 项已为快照型 Agent 注入同网关 HTTP/HTTPS/ALL proxy 大小写变量并清空绕过列表，创建、readiness 和运行态均与网关地址精确核验；网络隔离仍是强制边界，客户端删除、绕过或篡改代理变量都无法直连。第 8 项已增加持续快照完整性监控，任何不可读、可写、内容或摘要漂移都会终止网关；运行时检查同时拒绝崩溃、unhealthy 或健康报告不精确的网关，internal 网络保证网关退出后 Agent 仍无直连路径。第 9 项已将协议、真实 Docker 隔离拓扑与完整绕过矩阵固化为可重复自动化测试；阶段 4 的强制出站网关与策略 DNS 全部完成，进入阶段 5 上游代理与凭据边界 |
| 5 | 进行中（第 1—7 项完成） | 第 1—7 项：2026-08-22 | `6711855`（第 1 项）；`bf5ad57`（第 2 项）；`681ea99`（第 3 项）；`9825cf1`（第 4 项）；`74d7fa9`（第 5 项）；`a03830d`（第 6 项）；测试机动态发现与配置（第 7 项，无产品源码变更） | 第 1 项提交前通过 egress/database/handler/config/security/app 定向测试、相关包 race、`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、前端 128/128 与 `git diff --check`；覆盖 HTTP/HTTPS/SOCKS5 地址规范化、AES-256-GCM 随机 nonce、记录 ID AAD、密文篡改与错密钥失败关闭、密钥持久化/权限/符号链接拒绝、CRUD/RBAC/owner scope、凭据保留/替换/清除、API 安全 JSON、SQLite/WAL 与错误日志无明文及 OpenAPI 写入专用 schema。第 2 项继续通过 Go 全包、相关新增矩阵连续 10 次与 race、`go vet ./...`、`go mod tidy -diff`、前端 128/128 和差异检查；覆盖 100 成员上限、搜索分页与通配符转义、priority 回退、稳定平滑加权轮询、40 路并发精确 3:1 分配、连续失败熔断、迟到失败不延长冷却、成功/冷却恢复、成员/代理/组禁用、全部不可用失败关闭、成员级健康状态、更新保留熔断、外键级联、owner/assignment 与跨用户成员拒绝。第 3 项通过新增矩阵连续 10 次、相关 race、Go 全包、vet/tidy、前端 128/128 与差异检查；覆盖选择/绑定两阶段、单代理/代理组/无代理、显式与隐式 none 来源、32 路并发首次启动、SQL CHECK/FK/不可变触发器/完整性哨兵、安全投影、REST/聊天/OpenAPI、独立 RBAC，以及 scheduler/worker/手动启动与存量运行时迁移失败关闭。第 4 项在提交前通过新增 database/handler/security 场景、相关 race、四个相关包完整测试、`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、前端 128/128 与 `git diff --check`；覆盖 `conversation > project > user > implicit none` 固定优先级、显式 `none`、清除待启动覆盖后恢复继承、首次启动冻结、32 路并发原子绑定、SQL CHECK/FK/级联/删除限制/损坏外键完整性哨兵、安全投影、CRUD/预览/OpenAPI 与独立 RBAC/资源范围。第 5 项在提交前通过新增上游路由矩阵连续 10 次、相关包 race 连续 3 次、四个相关包与 Go 全包、`go vet ./...`、`go mod tidy -diff`、前端 128/128、脚本语法及 `git diff --check`；覆盖 canonical 不可变路由、`0700` 目录/`0444` 文件、HTTP/HTTPS/SOCKS5 与凭据握手、固定目标 IP、单代理和代理组、权重/优先级/熔断/冷却、上下文取消、精确健康报告、只给网关的只读挂载、Agent env/命令/标签无凭据，以及全部上游不可用时 502 且绝不直连回退。第 6 项在提交前通过相关包定向与 race、`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、前端 128/128、脚本语法和 `git diff --check`；覆盖认证档案加密/脱敏 CRUD、写入专用 API、作用域 RBAC、引用删除保护、不可变网关文档、精确策略绑定、伪造头唯一覆盖、解析后重评估、Agent 无挂载、元数据与日志无明文、错配/缺失/权限漂移失败关闭。第 7 项无需产品代码变更；提交前以虚拟机直连网段 `10.211.55.0/24` 动态匹配宿主活动网卡，唯一发现 `bridge100/10.211.55.2`，并验证该地址不是旧 `172.*`、HTTP/HTTPS 代理均可用 | 第 1 项精确提交 `6711855dfe7074a8fdd54ef2b2da4fff7570284f` 的服务 SHA-256 为 `7ae611a8…ee10b`，密钥权限和错误模式验证同前。第 2 项候选在 ARM64 虚拟机通过 egress 连续 3 次、database/handler/security 连续 3 次及 app 全包后才提交；精确提交 `bf5ad5717ebafcc72152fbe7e345759681f60723` 以 `vcs.modified=false` 构建，服务、app/database/egress/handler/security 测试二进制 SHA-256 分别为 `c0d1d510…9737a`、`1be7f02c…50e68`、`51dd5ed7…f8103`、`8038b87d…09467`、`c0a453e7…49ad8`、`f4734f5f…e5a4`；精确 ARM64 原生测试全部通过。真实库新增组/成员表分别为 9/13 列且初始 0 行，integrity 为 ok、外键违规 0；精确服务进程/文件哈希一致，active/running、`NRestarts=0`，虚拟机内及宿主直连首页 200，未登录代理组/搜索 API 401，启动后 warning/error 为 0。第 3 项候选与精确 ARM64 database/handler/app/security 原生测试均通过；精确提交 `681ea991e3d11f7fe12b852b52e19cc75e7e9dff` 以 `vcs.modified=false` 构建，服务及 app/database/handler/security 测试二进制 SHA-256 分别为 `d43f21f3…e1fb`、`52d5bde2…8111`、`0ec3ead2…5638`、`179b11a5…f25`、`1e4643c4…19e5`。真实库选择/绑定表分别为 5/6 列，30 个持久运行时已生成 30 个绑定且缺失 0，integrity 为 ok、外键违规 0、不可变触发器 2；精确服务进程/文件哈希一致，active/running、`NRestarts=0`，虚拟机内及宿主直连首页 200，未登录出口 API 401，启动后 warning/error 为 0。第 4 项候选先通过 ARM64 新增场景重复 3 次及 database/handler/security/app 全包才提交；精确提交 `9825cf11cbf2c27e340240401c69b9d51000eee9` 以 `vcs.modified=false` 构建，服务及 app/database/handler/security 测试二进制 SHA-256 分别为 `dd2eba45…1fb`、`513d6b6f…7fd0`、`b3c36210…8411`、`f8e1f534…30ab`、`1e8fa6c5…fd99`，精确 ARM64 原生测试全部通过。真实库用户/项目默认表均为 5 列、索引 4 个、初始 0 行，integrity 为 ok、外键违规 0；30 个持久运行时仍有 30 个绑定且缺失 0。精确服务进程/文件哈希一致，active/running、`NRestarts=0`，虚拟机内及宿主直连首页 200，新增未登录 API 全部 401，启动后 warning/error/panic/fatal 为 0。第 5 项候选和精确 ARM64 定向重复测试及 app/egress/container/database/cmd 全包均通过；精确提交 `74d7fa99471ce205619d153a79c26ba3d9f286e2` 以 `vcs.modified=false` 构建，服务、网关和源码归档 SHA-256 分别为 `67a6d350…63fd`、`d82b2eee…e292`、`dead2635…0023`，精确网关镜像为 `sha256:7fdba565…5eadb`。真实 Docker 隔离与绕过矩阵连续 3 次 PASS：直接模式允许 HTTP 200，不可达上游固定返回 502，直连回退为 false，凭据未进入 inspect 元数据或日志，临时容器/网络自动清理。精确服务进程/文件哈希一致，active/running、`NRestarts=0`，虚拟机内及宿主直连首页 200，未登录出口 API 全部 401；数据库 integrity 为 ok、外键违规 0、30/30 绑定无缺失，受信路由目录权限 0700，启动后 warning/error/panic/fatal 为 0。第 6 项候选 ARM64 原生七组测试全部 PASS，真实 Docker 隔离与 `auth-only` 矩阵连续 3 次 PASS。精确提交 `a03830d0e24e6a2222a4cbc27a91929063769bb9` 以 `vcs.modified=false` 构建，服务、网关、Docker 测试与源码归档 SHA-256 分别为 `fc6d2cc8…440d2`、`67fd2159…3f073`、`5da04fc1…777f`、`fb190079…18f9`，精确网关镜像为 `sha256:a2687a06…61794`；ARM64 七组原生测试和真实 Docker 三连测均通过，临时容器/网络残留为 0。精确服务进程与文件哈希一致，active/running、`NRestarts=0`、首页 200，未登录认证档案集合/单项 API 均 401；数据库 integrity 为 ok、外键违规 0、表为 9 列、兼容触发器 3 个、初始记录 0，启动后 warning/error/panic/fatal 为 0。第 7 项真实隔离 Agent→网关→宿主 `7897` 连续 3 轮均为 HTTP 200、HTTPS 200，移除代理后直连为 false，拓扑固定 internal=2/egress=1；活动 systemd/config 中旧 `172.*:7897` 为 0，临时容器/网络残留均为 0，服务保持 active、`NRestarts=0`、首页 200 | 第 1—5 项无管理 UI 变更；第 3 项候选与精确版本均用宿主直连虚拟机地址完成匿名 Chrome/Playwright 验收：首页 200、标题正确、登录框可见且居中、无遮罩/控制台错误/页面错误/5xx/内部字段泄漏，截图 SHA-256 均为 `6b457533…dc4f`。第 4 项候选与精确版本再次经宿主直连 Chrome/Playwright 验收：可见登录表单/密码框各 1 个、无水平溢出或可见对话框，console/page error/5xx/凭据泄漏均为 0，精确截图保存在测试产物目录。第 5 项内置浏览器两次在导航阶段超时并重置，已按流程降级到本机 Chrome/Playwright；候选与精确版本均为首页 200、标题正确、登录表单/密码框各 1 个、登录卡相对 1800×1000 视口中心偏差 `(0,-0.01)`、无水平溢出/可见对话框/框架错误层/console/page error/5xx/凭据标记泄漏，精确截图 SHA-256 为 `817f244e…5223`。管理员登录保留到后续统一 UI 验收并等待即时敏感操作确认。第 6 项精确部署经宿主直连 Chrome/Playwright 验收：1800×1000、Retina 902×484@2x、390×844 均为 HTTP 200、标题正确；删除对话弹窗直属 `body`、遮罩精确覆盖视口、中心偏差均为 `(0,0)`、按钮可见，无横向溢出、console/page error/5xx/凭据标记，截图 SHA-256 为 `c4e4a1a1…17c287`。第 7 项无 UI 或产品源码变更，沿用第 6 项精确部署浏览器证据 | 对话选择仅在首次运行前可修改，首次 scheduler/worker/手动启动前原子冻结为不可变绑定；缺省值记录为 `none/none`，显式无代理记录为 `none/conversation`，安全投影不返回凭据或组运行权重。第 4 项已实现用户/项目默认出口的动态预览与对话显式覆盖，首次启动后继承结果冻结且默认值漂移不影响既有绑定；API 只返回脱敏目标摘要，不返回凭据、密文或组调度权重。第 5 项已将冻结绑定解析为网关专用不可变路由文件，网关只经单代理/代理组建立上游隧道；上游连接、认证、TLS、SOCKS 或全部组成员失败时统一失败关闭，绝不拨号目标直连，凭据不进入 Agent、API、DOM、容器元数据或日志。第 6 项已实现按不可变边界快照精确选择认证档案，由网关在匹配的明文 HTTP 请求上删除 Agent 伪造值后唯一注入；认证档案以服务端作用域 AEAD 加密保存，明文仅存在于宿主受限目录的网关专用只读不可变文件，Agent、API、DOM、环境、命令、标签、inspect 和日志均不可见。HTTPS `CONNECT` 不做中间人解密，因此 `auth-only` 对该路径失败关闭。第 7 项已通过虚拟机直连网段与宿主活动网卡动态匹配可访问的宿主代理地址，明确区分 Linux 默认路由器 `10.211.55.1` 与实际承载 `7897` 的宿主 `bridge100/10.211.55.2`，未使用旧网络 `172.*` 地址。进入第 8 项凭据隐藏、代理轮询、熔断、冷却、失败关闭和跨对话隔离总验收 |
| 6 | 已完成 | 第 1—6 项：2026-08-22；第 7—11 项：2026-08-23 | `d9c48ef`（第 1 项）；`f2e1e64`（第 2 项）；`96e647d`（第 3 项）；`33c6f95`（第 4 项）；`0e8da1c`（第 5 项）；`ac26c63`（第 6 项）；`2bd258b`（第 7 项）；`39689f0`（第 8 项）；`1102344`（第 9 项）；`152758f`（第 10 项）；`ef065e5`（第 11 项） | 第 1—10 项证据见下方各验收节。第 11 项通过 Go 全包、`go vet`、`go mod tidy -diff`、前端 159/159、脚本语法、凭据扫描与 `git diff --check`；新增边界快照只读页和代理/组/凭据完整 CRUD，修复窄屏滚动/溢出、隐藏字段、可选成员统计、动态语言刷新和标题挤压 | 第 10 项精确 ARM64/CGO 服务和网关继续运行；第 11 项精确 Web 提交为 `ef065e53c51940a139ac6f804ce6b2b8f844e637`，归档 SHA-256 `b33f2dda…1ec1b`。服务 active、`NRestarts=0`、首页 200、资源版本与提交一致、启动 warning/error 为 0；真实 CRUD 验收数据已按组→凭据→代理顺序清理为 0 | 7 个子页和创建对话容器策略面板均完成桌面/390×844 验收；无横向溢出，运行环境页真实滚动到底部，边界 SHA/规则、审计链、网络流和出口 CRUD 数据均正确。精确页自动登录后 console warning/error `[]`，无占位文案或 fixture 残留 | 阶段 6 全部完成；进入阶段 7。内置浏览器原生 confirm 接管曾阻塞旧验收标签页，已关闭该标签页；产品删除入口、确认触发和受保护 API 删除均已验证 |
| 8（提前） | 已完成 | 2026-08-23 | `b736a9f` | Go 全包、`go vet`、`go mod tidy -diff`、前端 159/159、egress race 与差异检查全部通过 | ARM64 原生 TLS/网关/容器/app 测试通过；真实 HTTP/HTTPS 允许与阻断、原始 TCP 直连失败、CA/私钥隔离和审计脱敏均通过 | 边界策略名称、说明、HTTPS 开关、不解密域名及规则字段均可输入；新增、编辑、刷新持久化和页面滚动通过，截图成功，console warning/error 为 `[]` | HTTPS 完整审计默认关闭；正文不持久化，也不提供未完成的正文持久化开关 |
| 7 | 进行中 | 2026-08-23 | - | - | - | - | 仅执行 ARM64；在阶段 8 完成后开始安全加固与端到端验收 |

### 阶段 5 第 8 项补充验收（2026-08-22）

阶段 5 表格中“第 1—7 项完成”的状态由本节更新为：**第 1—8 项功能、安全矩阵和内置浏览器验收全部完成；阶段 5 整体完成，可以进入阶段 6**。

- 源码提交：`b48f2e4`（认证档案/上游路由绑定与 Docker 28 策略 DNS）；`a68d23d`（启动状态只显示在顶部耗时摘要，正文不再重复初始化事件）。
- 本地：精确 `HEAD=a68d23d08d0f216041a369e3c90b6fac9a5e502b` 的 `go test ./... -count=1`、关键包 race、`go vet ./...`、`go mod tidy -diff`、前端 130/130、脚本语法与差异检查全部通过。凭据隐藏、稳定加权轮询、熔断/冷却、全部上游失败关闭、跨对话路由/网关身份和跨快照认证档案复用拒绝均有回归覆盖。
- 测试机：精确服务二进制 SHA-256 为 `7e51107646b70a1fd428bc9cd5a2fa753b816cc054897c394c74ea36bc7c03b7`，`vcs.revision=a68d23d08d0f216041a369e3c90b6fac9a5e502b`、`vcs.modified=false`；静态网关二进制 SHA-256 为 `250d860cba6767f55582069c75c703e8efcf09c40247c6eaee4b232b5d61347b`，精确 ARM64 镜像固定为 `sha256:ceb82fedcf7b3f603982b7a521ff77458a7c2854002f3cc159a29195bc517177`。真实 Docker 安全矩阵连续 3 轮 PASS，临时容器/网络残留为 0；服务 active/running、`NRestarts=0`、首页 200、匿名容器状态 API 401、启动后 warning 为 0、SQLite integrity=ok 且外键违规为 0。
- Docker 28 回归：停止态动态地址不再被误当作策略 DNS；控制面从 internal 网络 IPAM 安全选择静态地址并绑定网关端点，运行态继续要求实际地址精确一致。候选版本真实新对话从 requested 到 ready 约 0.15 秒且无初始化错误，精确版本源码、二进制和配置均已部署。
- UI：服务端与四个静态资源作为同一制品集部署，`chat.js`/`monitor.js`/中英文资源的线上哈希与源码一致；用户刷新后已人工确认“容器正在启动中”只显示在顶部耗时区域、就绪后恢复普通对话耗时、正文不再显示初始化过程。
- 内置浏览器：先确认 `http://10.211.55.16:8080/?qa=20260822-stage5-item8-exact-a68d23d#dashboard`、标题 `CyberStrikeAI`；软件恢复后继续使用同一内置浏览器，在 `?qa=20260822-stage5-item8-browser-final#chat?conversation=61136294-10e8-49a3-9188-7dd5b7f15a23` 成功取得完整可见 DOM。真实容器对话只显示 `已中断 · 耗时 15 秒`，正文没有残留“容器正在启动”事件，编辑器、会话上下文和轮次导航均正常；console warning/error 列表为空。URL、title、可见 DOM 与 console 四项证据齐全，未使用其他浏览器降级。

### 阶段 6 第 1 项验收（2026-08-22）

- 源码提交：`d9c48ef580113761f5d66f7a49a7cbf77ec378b8`。新增可折叠“容器管理”入口和容器概览、对话容器、运行环境、边界规则、出站代理、网络活动、出站审计 7 个独立子页；每页使用独立 hash、标题、副标题和管理域说明，不采用单页长滚动。
- 本地：提交前先运行 `node --check` 与全部前端测试，134/134 通过；随后 `go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、中英文 JSON 校验和 `git diff --check` 全部通过。候选浏览器验收发现并修复了窄屏正文被 200px 侧栏挤压、折叠菜单底部超出视口两个问题，修复后重新从头运行前端回归。
- 测试机：从精确干净提交以 Zig/CGO 构建 Linux ARM64 服务，SHA-256 为 `63141feafd63ebe9b8da6c16d168001ab95192cd7b6d69b79458703b32971c02`，build info 为 `vcs.revision=d9c48ef580113761f5d66f7a49a7cbf77ec378b8`、`vcs.modified=false`。运行进程 `/proc/191010/exe` 与部署文件哈希一致；首页模板、CSS、路由、容器管理脚本和双语资源 7 个文件的线上哈希逐一匹配本地提交。服务 `active/running`、`NRestarts=0`、首页 200，本次启动以来 warning 日志为空。
- 内置浏览器：使用虚拟机直连地址并以测试管理员登录；桌面逐项点击 7 个侧栏子页，每项的 hash、标题、`display:flex`、唯一活动页和唯一选中导航均正确。390×844 下自动折叠主侧栏至 64px，正文为 326px、卡片为 258px且无横向溢出；折叠菜单 7 项均为 `menuitem`，范围为 top `529.21` / bottom `836`，完整位于 844px 视口内，点击最后一项能切换到 `#egress-audit` 并自动关闭。最终基线交互切换到 `#network-activity` 后 console warning/error 为 `[]`，截图成功，未使用其他浏览器降级。
- 范围说明：第 1 项只完成信息架构、路由、双语文案和桌面/窄屏导航可用性。页面中的“管理数据接入中”明确表示后续任务尚未接入，不作为容器状态、审计或实时流已完成的证据；下一步进入第 2 项。

### 阶段 6 第 2 项验收（2026-08-22）

- 源码提交：`f2e1e64633d40bfbed1f17c0ee2c58df83d27a2f`。新建对话的运行设置现在同时展示 host/container 执行位置、临时或持久工作区作用、默认拒绝或可访问边界策略、项目/用户出口继承预览，以及无代理、单代理和代理组选择；选择只随首次容器对话创建请求提交，既有对话保持锁定。
- 安全边界：新增 `GET /api/boundary-policies` 仅返回当前账号可访问策略的 `id/name/description/updatedAt` 安全摘要；边界策略纳入资源分配和只读 RBAC。前端只读取脱敏的代理/代理组安全投影，不把凭据、密文、认证 header、组运行权重写入响应、DOM 或浏览器存储。
- 本地：候选 UI 实测先发现 390×844 下运行设置面板仍相对桌面主内容区定位、整体落在视口外；修复为窄屏固定定位和受限滚动高度后重新验收。最终前端 138/138、`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff` 和 `git diff --check` 全部通过；候选 ARM64 database/handler 包与边界模拟 RBAC 定向测试通过。
- 测试机：从干净提交以 Zig/CGO 构建 Linux ARM64 服务，SHA-256 为 `5bcea697b8dec7c52d5c84f366355b6efe8e9c27bf4ff1c3435b820d9437078a`，build info 为 `vcs.revision=f2e1e64633d40bfbed1f17c0ee2c58df83d27a2f`、`vcs.modified=false`。运行进程 `/proc/195327/exe` 与部署文件哈希一致；首页模板、CSS、`chat.js`、设置脚本和双语资源 7 个文件的线上哈希逐一匹配。服务 `active`、`NRestarts=0`、首页 200，本次启动近两分钟 warning 日志为空。
- API：管理员安全投影读取、默认拒绝空策略、无默认出口继承预览均通过。候选版临时创建并回读单代理、代理组及两种容器对话选择，字段与预期一致；对话使用显式 `workspace_action=delete` 删除。精确版复验后临时代理和代理组 GET 均为 404、按名称搜索残留均为 0，登录响应临时文件已立即删除。
- 内置浏览器：桌面逐项验证设置状态为“已加载”，边界默认拒绝，工作区默认临时且有永久删除警示；继承、无代理、单代理、代理组四种出口模式的目标列表和预览文案均正确。候选版窄屏修复后 390×844 面板边界为 left `8` / right `382`、宽 `374`、无横向溢出且 `overflow-y:auto`；精确提交再次截图确认全部控件位于视口内。服务重启导致的预登录未授权日志不计入登录后基线；登录后重新操作出口控件，新增 console warning/error 为 `[]`，未使用其他浏览器降级。
- 范围说明：第 2 项只完成创建入口及安全读取投影；容器/网关/DNS/工作区实时状态、资源用量、镜像 digest、快照 hash 和最后错误由第 3 项实现。

### 阶段 6 第 3 项验收（2026-08-22）

- 源码提交：`96e647d5c6534a79ff1fd2e1d815042820eabf7d`。容器概览、对话容器和运行环境页接入真实数据；对话详情展示 Agent、出站网关、策略 DNS、工作区、实时资源统计、固定镜像摘要、运行时规格 hash、边界快照 hash、工具就绪状态和最后错误。列表默认读取持久化状态，只有选中详情才以 `observe=1` 触发 Docker 实时观测，并限制为最多 6 路并发请求。
- 安全边界：Docker 观测只接受数据库中的受信运行时规格，并在返回前校验 CyberStrikeAI 所有权、不可变规格摘要、镜像、网关拓扑、策略 DNS 与安全配置。API 只返回聚合 CPU/内存/PID/网络/块 I/O、状态和安全摘要；不返回容器 env、mount、label、command、credential、工作区 named volume 名称或原始 Docker inspect 数据。前端全部通过 `textContent` 构造节点，不将服务端文本写入 `innerHTML`。
- 本地：前端 139/139、`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、`git diff --check`、container 完整 race、handler 新路径定向 race 与 app race 全部通过；新增 Docker stats 计数、CPU 计数器回退、策略 DNS 状态、observe opt-in、RBAC、敏感 volume 名称不泄漏和 OpenAPI 回归。handler 全包 race 单独发现既有 `TestExternalMCPHandler_AddOrUpdateExternalMCP_Stdio` 中配置环境展开与异步 MCP `os/exec` 的竞争，本项新增路径不涉及该代码，已如实保留并待对应阶段处理。
- 测试机原生测试：ARM64 container、handler、app 测试二进制 SHA-256 分别为 `7969cb5e986216d41467f6ab0f04b459003013be882d6695be072d8d7b7fe772`、`ca316f8d32144d891c3148bf9dd50e936d417114456cd17a396707adf8b4dc60`、`3604e5ffd66495ff0af2f1b6cbb62143e000a3372e0aadaf7771dd0d22b6a43c`，均在虚拟机原生 PASS，临时测试二进制随后删除。
- 精确部署：从干净提交以 Zig/CGO 构建 Linux ARM64 服务，SHA-256 为 `d673b9e52c41ee4754a21d2561fe2234b733ce97e632204259a576ed323eccd8`，源码归档 SHA-256 为 `65af54e8a33df4ab38fbd31b4922229e94d167919f4a632db852cef83e1097c9`，build info 为 `vcs.revision=96e647d5c6534a79ff1fd2e1d815042820eabf7d`、`vcs.modified=false`。运行进程与部署文件哈希一致，首页模板、CSS、容器管理脚本和双语资源哈希逐一匹配；服务 `active/running`、`NRestarts=0`、首页 200，本次启动以来 warning 为 0。
- API 与真实 Docker：默认初始化状态查询为 200 且不含 `observation`，但包含安全 `desired` 投影；`observe=1` 为 200。真实对话启动后 Agent/网关均为 `running` 且资源统计可用，策略 DNS/工作区均为 `ready`，Agent/网关镜像摘要与期望值一致，边界快照 hash 存在，敏感字段命中数为 0；停止为 200，最终 Agent 与策略 DNS 均为 `stopped`。
- 内置浏览器：使用已登录会话直连 `http://10.211.55.16:8080/?qa=20260822-stage6-item3-exact-96e647d#container-overview`，加载 35 个对话容器；桌面对话详情正确显示 Agent/网关/DNS/工作区和 512 MiB/128 PID、128 MiB/64 PID 限额及镜像/快照摘要。真实运行态显示 Agent `0.0%`、672 KiB、2 PID，网关 `1.4%`、1.9 MiB、7 PID，并显示网络与块 I/O；停止刷新后 Agent/网关/DNS 均恢复为已停止、工作区保持就绪。390×844 窄屏截图无明显横向越界；运行环境页、新标签页登录续用和刷新均正常，console warning/error 为 `[]`，未使用其他浏览器降级。
- 范围说明：第 3 项完成容器状态和资源详情的真实只读展示，不增加生命周期修改按钮，也不实现筛选、实时网络流或审计存储。下一步进入第 4 项统一可搜索单选/多选组件。

### 阶段 6 第 4 项验收（2026-08-22）

- 源码提交：`33c6f95ee0692464b2f590dec213fd1e23260864`。新增统一可搜索单选/多选组件，以原生 `select` 作为唯一数据源并派发标准 `input/change` 事件；支持 NFKC 搜索、禁用项、动态选项刷新、单选/多选、无匹配空状态、双语、暗色模式和销毁恢复。新对话的边界策略、出口模式与出口目标三个选择器已迁移到该组件。
- 可访问性与安全：触发器、搜索框和选项列表使用 `listbox/option`、`aria-selected`、`aria-multiselectable`、`aria-activedescendant` 与关联 label；支持方向键、Home/End、Enter/Space、Escape 和 Tab。选项仅以 `textContent` 创建，不使用 `innerHTML`。菜单通过 `body` portal 固定定位、视口边界夹取与上下翻转，`z-index:6200`，同时阻止菜单点击和键盘事件冒泡到外层聊天快捷键。
- 提交前回归：候选浏览器首先发现 Enter 选择会冒泡关闭整个运行设置面板，修复后又在英文长文案下发现 flex 子区块被限高压缩、工作区卡片覆盖容器选项；改为面板区块保持自然高度并由面板统一滚动，同时加入回归断言。最终 `node --check web/static/js/unified-select.js`、前端 144/144、`go test ./...`、`go vet ./...`、`go mod tidy -diff` 与 `git diff --check` 全部通过。
- 精确部署：从干净提交以 Zig/CGO 构建 Linux ARM64 服务，SHA-256 为 `1193e9eaf765d8a80980538c5032d71461da73bad7df56f65358d77e85a4b791`，源码归档 SHA-256 为 `dfa83b1668ffa3e29b9de0deea3ea5343325df053bf5dfc45a42bffeb3550941`，build info 为 `vcs.revision=33c6f95ee0692464b2f590dec213fd1e23260864`、`vcs.modified=false`。部署文件、运行进程、模板、CSS 与组件脚本哈希逐一一致；服务 `active/running`、`NRestarts=0`、首页 200，最近 warning 日志为空。
- 内置浏览器：候选与精确版本均使用虚拟机直连地址和已登录会话。中文、英文桌面和 390×844 下运行设置面板、工作区、容器安全与出口区块不重叠；搜索框显示正确双语占位，任意无匹配查询显示对应空状态；键盘将出口切到“不使用上游代理”后菜单关闭但外层面板保持打开；窄屏菜单完整落在 390×844 视口内。刷新后 3 个组件只初始化一次，新标签页直接复用登录会话；服务重启窗口在旧标签留下的一条历史未授权轮询错误已通过稳定后的全新标签隔离复核，干净标签 console warning/error 为 `[]`。
- 范围说明：第 4 项提供统一组件并完成创建对话入口迁移，不在本项增加列表数据接口。下一步进入第 5 项，实现 10/20/50/100 每页、服务端分页、搜索、状态筛选和 URL 状态保留。

### 阶段 6 第 5 项验收（2026-08-22）

- 源码提交：`0e8da1cc779f3004e1c6e564c1e0a53e4965b229`。新增 `GET /api/container-runtimes` 服务端列表契约，容器概览、对话容器和运行环境三页统一支持 10/20/50/100 每页、翻页、标题或对话 ID 搜索、`all/not_requested/pending/running/stopped/failed` 封闭状态筛选，并将页码、每页数量、搜索和状态写入 URL，同时保留既有 `qa` 参数与页面 hash。
- 数据与安全边界：查询在 SQLite 层完成筛选、访问范围、排序、计数和分页，不再先取 1000 条对话或逐行请求详情；汇总数字来自完整筛选集合而不是当前页。列表只返回持久化安全投影，不包含 `providerId`、原始规格或 Docker 观测；仅选中的对话详情继续使用既有 `observe=1` 实时观测。新路由纳入 `chat:read` 和对话资源范围，匿名访问为 401，非法每页数量和状态均为 400。
- 提交前回归：数据库与 handler 新增分页、字面量 `%/_/\\` 搜索转义、状态优先级、RBAC、敏感字段不泄漏、非法参数和 OpenAPI 枚举覆盖。最终前端 144/144、`go test ./...` 与 `git diff --check` 全部通过；候选浏览器验收发现容器管理页继承 `.page { overflow:hidden }` 后无法继续向下滚动，修复为页面自身 `overflow-y:auto`、限制横向溢出并保留稳定滚动条后重新从头验收。
- 精确部署：从干净提交以 Zig/CGO 构建 Linux ARM64 服务，SHA-256 为 `cd708dd64bf864df05112cd9957e1346ebce2df48d1bf76fd9f284a0ec9c21b8`，源码归档 SHA-256 为 `101c743edad3fd81ab6368a63c8b605f228b599d5758be198a578a40d081ca3c`，build info 为 `vcs.revision=0e8da1cc779f3004e1c6e564c1e0a53e4965b229`、`vcs.modified=false`。运行文件哈希与上传制品一致；模板、CSS、容器管理脚本 SHA-256 分别为 `fe09a606…06937`、`d2c013b2…17175`、`77f23859…01fea`。服务 `active/running`、`NRestarts=0`、首页 200，本次启动后的 error/alert 日志为空，活动 Web 目录 AppleDouble 文件数为 0。
- API：真实数据总数为 35；10/20/50/100 每页分别返回 10/20/35/35 条和 4/2/1/1 页。状态集合 `all/not_requested/pending/running/stopped/failed` 分别为 35/2/0/0/31/2，汇总与筛选总数一致；精确对话 ID 搜索只返回 1 条。未授权为 401，非法每页数量与状态为 400，列表的 `providerId/spec/observation` 泄漏检查为 false。
- 内置浏览器：使用虚拟机直连地址和已授权测试管理员登录。真实交互验证下一页为 15 条、每页 10 条时为 4 页且三页控件同步、失败筛选为 2 条、组合搜索为 1 条、刷新后 URL 状态不丢失，切换到对话容器页后筛选继续保留且实时详情可见。中英文动态加载摘要和分页分别显示 `显示 1–20，共 35 个对话容器` / `第 1 / 2 页，共 35 条` 与 `Showing 1–20 of 35 conversation containers` / `Page 1 of 2 · 35 total`。
- 滚动与窄屏：桌面容器概览、运行环境和对话容器均通过真实滚轮操作到达底部并看到最后一项及分页。390×844 下运行环境页 `clientHeight=772`、`scrollHeight=5289`，真实滚动达到 `4517/4517`；`body/html/viewport` 宽度均为 390，分页位于可视区 `top=694.34` / `bottom=776.79`。最终精确地址为 `?qa=20260822-stage6-item5-exact-final-0e8da1c&container_page=1&container_page_size=20&container_status=all#runtime-environments`，console warning/error 为 `[]`，未使用其他浏览器降级。
- 范围说明：第 5 项只完成现有容器列表的服务端检索和可恢复页面状态，不实现实时网络活动或审计事件存储；下一步进入第 6 项，对话出站网络活动实时流。

### 阶段 6 第 6 项验收（2026-08-22）

- 源码提交：`ac26c630ff8fa7419dcc032b70b87c4423211f6c`。网关为 DNS、HTTP 和 CONNECT 决策生成只含安全元数据的结构化活动事件；Docker provider 只按数据库中受信运行时规格读取当前对话自有网关日志，并通过 `GET /api/conversations/{id}/egress-activity/stream` 以 SSE 增量输出。维护重建允许把已创建运行时升级到当前配置的精确网关镜像和资源规格，但最终规格摘要、边界快照、上游路由和认证绑定仍必须完整一致。
- API 与安全：SSE 路由纳入 `chat:read` 和对话资源范围，匿名访问为 401，非法 `tail` 为 400；停止容器时返回 `ready` 后以 `stream_error/not_ready` 明确结束。查询字符串与敏感 header/body 不进入事件；真实 `?token=stage6-secret-marker` 探针中标记和禁止键命中均为 0，HTTP path 仅为 `/`。稳定事件键和最多 1000 个已见键避免刷新、断线重连与 Docker tail 重放造成重复，页面只保留 500 条，暂停缓冲同样限制为 500 条。
- UI：新增独立“实时决策流”页，支持对话、域名/IP、请求类型、策略判定、Agent、工具和代理出口过滤；支持暂停、待显示计数、恢复、跟随最新、清空与显式刷新。过滤状态写入 URL 并在刷新后恢复；事件行展示时间、请求、目标、解析/连接、规则判定、上下文、结果、时延和字节数，全部使用安全字段与 `textContent`。
- 提交前测试：`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、`git diff --check`、`node --check web/static/js/network-activity.js` 和前端 149/149 全部通过；egress、runtime/container、database、app race 以及本项新增 handler/security race 连续 3 次通过。handler 全包 race 仍会暴露既有 `TestExternalMCPHandler_AddOrUpdateExternalMCP_Stdio` 的环境展开与异步 `os/exec` 竞争，本项新增路径不涉及该代码，未以扩大范围的方式掩盖。
- 候选真实验收：QA 对话 `c7474670-3249-4d02-88c7-0bb4d37f3745` 使用边界快照 `sha256:3e4f6fea8f0eae32b69b9bc1bd53d3c95ecc7d6cecb8fab62f728ba36914749e`。允许 `http://example.com/` 返回 200，未知域名由策略 DNS 阻断，两类事件均实时进入 SSE；匿名/非法参数/停止态错误流和 OpenAPI `text/event-stream` 契约均通过。存量运行时也从旧网关显式升级，generation 递增且快照 SHA 不变，并产生真实阻断 DNS 事件。
- 精确构建与部署：从干净提交以 Zig/CGO 构建 Linux ARM64 服务，SHA-256 为 `44c2ef6ff709f71235ee1406244cd02a3bb297e6320036a7456f25637150df18`；网关二进制、源码归档、Web 归档和网关构建上下文 SHA-256 分别为 `bf45f06487c64c21441b23048c8440aa4e3df13d8ebb6bdf93ab1a88524ae917`、`1beccdd8c4adbcb60f2d9924b72cc0fef4c3e05b52dd5a85a998734f7cf8e898`、`e98138a0639f3b9a1b5b2b88b713465b1c8938955b6bdd57eb5e10e4125b644e`、`9b29e1093b7a0c074bd96c08df327a7cf2b0841308b678aa242023ae28d8448c`，build info 为 `vcs.revision=ac26c630ff8fa7419dcc032b70b87c4423211f6c`、`vcs.modified=false`。虚拟机离线构建的精确网关镜像为 `sha256:496d6d2b3b0a293cc3a2995df41a76b63cb79aa2009e65f809306d2ff2f32934`；部署文件与运行进程哈希一致，配置权限为 `parallels:parallels/0600`，服务 `active/running`、`NRestarts=0`、首页 200、活动 Web/源码 AppleDouble 文件数为 0，启动日志无 panic/fatal/权限或端口错误。
- 精确运行时：上述 QA 运行时经维护重建从候选网关 `sha256:9de09159…5221e` 升级到精确网关 `sha256:496d6d2b…f32934`，generation 2→3，边界快照 SHA 完全不变。Agent 内真实 HTTP 请求返回 200，未知 DNS 查询失败关闭；订阅流收到 1 条允许 HTTP 和 4 条阻断 DNS（解析器同时查询原名与 `.localdomain`），Docker 容器镜像与期望精确摘要一致。
- 内置浏览器：使用已登录会话直连 `?qa=20260822-stage6-item6-exact-ac26c63&activity_conversation=c7474670-3249-4d02-88c7-0bb4d37f3745&activity_domain=stage6-exact-blocked&activity_type=dns&activity_decision=blocked&activity_agent=container-agent&activity_tool=unknown&activity_route=direct#network-activity`。六个过滤条件完整恢复，精确页显示“已接收 5 条，当前显示 4 条”、允许 1/阻断 4，四行目标与真实 DNS 事件一致，刷新后没有重放重复；候选阶段另完成暂停后待显示 2、恢复并入、连接重建、页面/表格滚动和零横向溢出验收。运行环境页针对用户报告的无法下滑问题再次以真实滚轮验证 `scrollTop 0→760`，滚动容器 `clientHeight=663`、`scrollHeight=1605`、`overflow-y:auto`。最终精确页 console warning/error 为 `[]`，未使用其他浏览器降级。
- 范围说明：第 6 项提供即时、非持久的运行时可观测性，不将其冒充审计账本；第 7 项再实现 DNS/HTTP/CONNECT、拒绝、限速、上游路由和生命周期事件的持久化、搜索与导出。

### 阶段 6 第 7 项验收（2026-08-22）

- 源码提交：`2bd258b376383a3033764c4fdcb281a75b22c409`。新增 `egress_audit_events` 持久表、索引和生命周期触发器；后台采集器对所有运行中网关执行有界历史重放并继续跟随 Docker 日志，以稳定事件键在数据库层去重。创建、创建失败、启动、停止、维护重建、删除以及 DNS/HTTP/CONNECT 网络决策均可在服务重启和页面刷新后继续检索。
- API 与权限：新增 `/api/egress-audit-events`、`/api/egress-audit-events/:id` 和 `/api/egress-audit-events/export`，统一纳入 `audit:read` 和对话所有者范围。支持 10/20/50/100 每页、全文、类别、事件类型、判定和时间范围筛选；JSON/CSV 导出最多 5000 条并防止 CSV 公式注入。匿名访问为 401、非法筛选为 400，列表和详情只返回封闭枚举及有界安全字段。
- 安全与范围：网络活动通过安全投影验证字段类型、长度、控制字符、数值和封闭枚举；生命周期失败只保存通用失败原因，不持久化 provider 凭据或原始底层错误。已为 `rate_limited`、`rate_limit_exceeded`、上游路由 ID 和 HTTP 429 的持久化、展示与回归测试建立契约；确定性限速和实际信号生成仍由阶段 6 第 10 项实现，不在本项虚构已生效的实时限速。第 8 项将继续完成正式的审计字段矩阵与敏感内容最小化验收。
- 提交前测试：`go test ./... -count=1`、`go vet ./...`、database/egressaudit/runtime-container/handler/security 定向 race、`go mod tidy -diff`、中英文 JSON 校验、凭据扫描、`git diff --check` 和前端 153/153 全部通过。macOS race 链接器输出既有 `LC_DYSYMTAB` 警告但退出码为 0，不影响测试结论。
- 候选部署与回滚：首次误用 `CGO_ENABLED=0` 的候选包在真实 SQLite 初始化时准确失败；事务部署脚本完整恢复旧二进制、数据库、Web 和源码，旧服务恢复为 `active` 且 `NRestarts=0`。随后改用 Zig/CGO 重新构建，并从头完成服务、API、真实生命周期和浏览器验收，证明部署回滚链路可用。
- 候选 API 与真实事件：真实对话 `c7474670-3249-4d02-88c7-0bb4d37f3745` 完成启动与空闲停止，生命周期事件包含快照、容器和成功结果。网关历史重放得到 5 条网络事件，其中允许 HTTP 1 条、阻断 DNS 4 条，全部带对话、容器、Agent、快照和目标安全摘要；服务重启后网络事件仍为 5 条，证明重放去重稳定。详情、所有筛选、JSON/CSV 导出、未授权和非法参数均通过，禁止字段命中为 0。
- 候选内置浏览器：桌面 1375×918 下总计 74 条、网络 5 条、生命周期 69 条、阻断 4 条、失败 3 条，20 行列表和 7 列表头正确；切换每页 10 条得到 8 页，网络类别得到精确 5 行，HTTP + 允许组合得到精确 1 行。390×844 下表头隐藏并改为卡片网格，页面宽度保持 390，无横向溢出；真实滚动从顶部到达 `1511.5/1511.5` 并看到分页。候选 console warning/error 为 `[]`。
- 精确构建与部署：从干净提交以 Zig/CGO 构建 Linux ARM64 服务，SHA-256 为 `e994e4139793098684923491d7ee6bc817a840933e318135827c72845771fad8`；Web 归档、源码归档、首页模板、CSS、审计脚本和中文资源 SHA-256 分别为 `9087d067e1db053e10b280aa2bac5d046c52b63a8ad8c402aebf1029a174fdaa`、`b14afe7690a156adadb5d97e6c185ff93325f3ae5614eddb964d250baf7bba5e`、`a7e7c8c4c6c59dc2ae9a6b17275823f487a4c6cfa6579c46c7fac8da07743e3f`、`c197b41343fc192a15ca0e1522eededfee255819edade2f4f508ac4580faee8c`、`65a2016aad45aee7c2ebfb2728bacb37599a3c82ccfcb7da93d3c5da307602b4`、`6d788aa7ded7fe95053d72003b35a8f9d88ff050d6cf6d8bce2b9216a03c4314`；build info 为 `vcs.revision=2bd258b376383a3033764c4fdcb281a75b22c409`、`vcs.modified=false`。精确部署备份位于 `backups/stage6-item7-exact-pre-20260822-224845`，服务 `active/running`、`NRestarts=0`、首页 200，活动目录 AppleDouble 文件数为 0，启动日志无 panic/fatal/采集器启动失败。
- 精确 API：精确部署后总计 140 条、生命周期 135 条、网络 5 条、阻断 4 条、失败 5 条；服务重启会按设计通过运行时协调写入新的唯一生命周期事件，因此生命周期总数增长，而网络事件稳定保持 5 条。网络导出仍精确包含 DNS/HTTP、允许/阻断两类判定，敏感字段检查为 false。
- 精确内置浏览器：使用虚拟机直连地址和测试管理员登录。桌面 1375×918 下活动页为“出站审计”，类别为网络、每页 10 条，页面加载 5 行、7 列，汇总为总计 5 / 网络 5 / 生命周期 0 / 阻断 4 / 失败 0，分页为第 1/1 页且文档横向溢出为 0。390×844 下表头隐藏、事件行为单列卡片，页面滚动容器 `clientHeight=772`、`scrollHeight=4480`、`overflow-y:auto`，真实滚动达到 `3708/3708` 后分页位于可视区，文档和页面横向溢出均为 0。登录前轮询产生的一条历史 401 已通过登录态新标签隔离；干净精确标签再次读取同一 5 条数据且 console warning/error 为 `[]`，未使用其他浏览器降级。

### 阶段 6 第 8 项验收（2026-08-23）

- 源码提交：`39689f0060ef700284d6052138cc1af69c90700f`。数据库写入前新增第二道安全验证，网络事件必须与受信运行时的对话、容器、generation、边界快照和上游绑定一致；域名、IP、端口、method、path、状态、计数器、封闭代码字段及时间戳均需通过规范化和有界校验。HTTP path 明确拒绝 query/fragment，网关日志解码继续以 `DisallowUnknownFields` 拒绝 `authorization`、cookie、header、request/response body 等额外字段。
- 安全投影与导出：审计列表、详情和导出统一返回 `Cache-Control: no-store`、`Pragma: no-cache` 和 `X-Content-Type-Options: nosniff`。OpenAPI 的 `EgressAuditEvent` 为 `additionalProperties=false` 的 31 字段封闭模型，敏感 header/body/query/cookie/authorization/credential/password/secret 字段数为 0；前端同样使用精确 31 字段白名单拒绝未知字段。CSV 对全部单元格清理控制字符并防止前导空白后的公式注入，标题截断改为 UTF-8 安全处理。
- 提交前测试：`go test ./... -count=1`、`go vet ./...`、database/runtime-container/handler 定向 race、`go mod tidy -diff`、`node --check web/static/js/egress-audit.js`、前端 153/153、凭据与敏感字段检查以及 `git diff --check` 全部通过。macOS race 链接器仍仅输出既有 `LC_DYSYMTAB` 警告且退出码为 0。候选源码在完成本地、真实 ARM64 服务/API 和内置浏览器验收后才提交。
- 候选部署：Zig/CGO Linux ARM64 候选二进制 SHA-256 为 `e79cdd5a152d503697bee8d1118eca8251ebb19f19c84e6cb19543760a54d963`，build info 为 `vcs.revision=3c7021936da0871767fd3b37eabe96b8ac2f4866`、`vcs.modified=true`；Web、源码归档、首页和审计脚本 SHA-256 分别为 `0464a0994cb580165aef6a13cd1a5c73737558bef47baac0fb2c67f501e633ad`、`c893d1e1b85364a2cab42a686ba25c5cb9bf883c7885942bac20e7d69175936b`、`f9f478d10946a90f607ef0158f779c913fe6cccca2842b0462c633d56a4964cc`、`571d9ca6ec6e47e6429785e905842908a5cf7c3610ba93b1b059f096103136bd`。候选备份位于 `backups/stage6-item8-candidate-pre-20260822-232505`，服务 `active/running`、`NRestarts=0`、首页 200 且日志错误计数为 0。
- 候选 API 与浏览器：网络列表精确为 5 条、阻断 4 条，核心追溯字段完整，path 含 query/fragment 为 0，禁止键为 0；详情、JSON/CSV 导出、匿名 401 和 31 字段 OpenAPI 均通过。桌面端刷新前后保持 5 行、7 列和汇总 5/5/0/4/0，无横向溢出；390×844 下页面内部滚动容器真实到达 `3708/3708`，分页可见且宽度保持 390，console error 为 `[]`。
- 精确构建与部署：从干净提交构建的 Linux ARM64 + CGO 二进制 SHA-256 为 `b3f2f173453fb9c8027a739ac5ae54a2279f14ef68c4992c95902f1db80e7950`，build info 为 `vcs.revision=39689f0060ef700284d6052138cc1af69c90700f`、`vcs.modified=false`。Web 归档、源码归档、首页、审计脚本和部署脚本 SHA-256 分别为 `07248bad5d87a8016f6d2e091d02afef8ae65a0086097eef0525b62491fd879c`、`65d06d2f7d65b8b025224e27906a8e7963c0b5a6b876279642e0d9b087006e73`、`f9f478d10946a90f607ef0158f779c913fe6cccca2842b0462c633d56a4964cc`、`571d9ca6ec6e47e6429785e905842908a5cf7c3610ba93b1b059f096103136bd`、`4cd9b1c8733b4cd8f7ba019524e648c5c25362285522f55e14a4c059a3d2a48c`。第一次未通过 sudo 调用在停止服务前即被权限策略拒绝，没有发生文件切换；随后以无 TTY `sudo -S` 事务部署成功，备份位于 `backups/stage6-item8-exact-pre-20260822-233907`。
- 精确服务与 API：运行进程和磁盘二进制哈希均精确匹配 `b3f2f173…e7950`，首页和审计脚本线上哈希一致，活动 Web/源码 AppleDouble 文件数为 0；服务 `active/running`、`NRestarts=0`、首页 200，部署及浏览器验收后的 fatal/panic/审计错误计数均为 0。网络列表仍为 5 条、阻断 4 条；所有事件核心追溯字段完整，允许事件携带命中规则，默认拒绝事件明确为 `default-deny`，直连场景不虚构上游。JSON/CSV 网络导出均为 5 条，CSV 为 31 列，详情与导出禁止键和值命中均为 0；全局审计总数 206 条，其中网络稳定为 5 条，生命周期消息只包含通用成功/失败描述。匿名访问为 401。
- 精确内置浏览器：服务重启后按本轮授权重新登录虚拟机直连地址。桌面 1375×918 下网络类别、每页 10 条、5 行、7 列、汇总 5/5/0/4/0 和第 1/1 页均正确，文档宽度为 1375/1375。390×844 下表头隐藏、表格转为卡片布局，5 行完整保留，活动页滚动容器为 `clientHeight=772`、`scrollHeight=4480`，真实滚动达到 `3708/3708` 后分页位于可视区，文档宽度为 390/390。预登录历史 401 通过登录态新标签隔离，干净精确标签 console error 为 `[]`，未使用其他浏览器降级；临时视口已恢复。
- 范围说明：本项完成审计安全字段矩阵和敏感内容最小化，不实现前序 hash；下一步进入第 9 项，为每个对话的审计事件增加可验证的前序 hash，并覆盖删除、修改和重排检测。

### 阶段 6 第 9 项验收（2026-08-23）

- 源码提交：`1102344a947192d2b909b26711b29751de869b48`。每个对话的审计事件新增严格递增 `chain_sequence`、`previous_hash` 和 `event_hash`，并由独立 `egress_audit_chain_heads` 记录链头。自定义确定性 SQLite SHA-256 函数和 `AFTER INSERT` 触发器在同一事务中封链、推进链头；拒绝预封链写入，已封链事件禁止修改和删除。旧库只在全部事件均未封链且不存在链头时执行一次确定性迁移，之后每次启动仅验证，混合或被篡改状态会阻止启动而不会重新定基线。
- 完整性与 API：验证覆盖事件内容修改、删除、序号重排、前序哈希错误和链头篡改。列表、详情、JSON/CSV 导出以及独立 `/api/egress-audit-events/integrity` 均先验证并在异常时以 409 失败关闭；事件模型扩展为 34 字段封闭契约，CSV 为 34 列。前端使用同一严格白名单，展示链验证状态、序号、前序哈希和事件哈希。
- 提交前测试：`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、相关数据库和处理器 race、`node --check`、中英文资源校验、前端 154/154 以及 `git diff --check` 全部通过。Linux ARM64 原生数据库矩阵验证事件修改、删除、重排和链头修改均可检测，旧库仅迁移一次且篡改库阻止启动；20 路并发写入连续 5 轮均形成无分叉、无缺口的有效链。
- 精确构建与部署：从干净提交构建的 Linux ARM64 + CGO 二进制 SHA-256 为 `ec833fa2af86d809611cc12098968127cf4b7f233155c6e1f9f061fe4902c91b`，build info 为 `vcs.revision=1102344a947192d2b909b26711b29751de869b48`、`vcs.modified=false`；Web 与源码归档 SHA-256 分别为 `d97e2b45f50e0e648b897387a0fe924b7b17df49e91c5bc4881e9e5f13193e79`、`63b270bf318288b306f1cf59f657921ad4272ae7ef9b989e2bd74a94722095a0`。精确备份位于 `backups/stage6-item9-exact-pre-20260823-005138`。首次精确部署因测试机磁盘写满而由事务脚本自动回滚；只删除 3.1 GiB 可重建的 VM Go 构建缓存后，候选服务恢复，精确部署重试成功，未删除数据库、备份、源码或测试制品。
- 精确服务与 API：运行文件和进程哈希与精确制品一致，首页、CSS 和审计脚本线上哈希匹配；服务 `active/running`、`NRestarts=0`、首页 200，成功启动后无 fatal/panic/审计或数据库初始化错误。数据库共有 309 条事件且 309 条全部封链，35 个链头对应 35 个对话，链头事件数和序号总数均为 309，分组异常为 0。完整性、列表、详情、JSON/CSV 导出和 OpenAPI 均为 200，匿名完整性访问为 401；完整性结果为 309 条、35 个对话，网络筛选为 5 条，CSV 为 34 列。
- 精确内置浏览器：桌面端链状态为“链已验证 · 309 条”，网络类别 5 行、7 列，汇总为 5/5/0/4/0，追溯列展示链序号、前序哈希和事件哈希；点击刷新及整页刷新后状态保持一致、无空白或遮罩，console error 为 `[]`。390×844 下文档宽度为 390/390、无横向溢出，事件表转为可读卡片；真实滚动达到 `3787/3787`，5 条事件和分页完整可见，单页的上一页/下一页均禁用。测试结束后已恢复默认视口。
- 范围说明：本项只实现持久审计链和篡改检测；下一步进入第 10 项，实现确定性限速、并发上限、429 冷却、连续登录失败、WAF/CAPTCHA 信号和手动恢复。

### 阶段 6 第 10 项验收（2026-08-23）

- 源码提交：`152758f636b13586841579cbc47206bbb3fe4b0d`。边界规则新增不可变 `rateLimit`，包含每秒请求数、突发容量和最大并发；网关使用确定性令牌桶、全局/规则并发门控以及有界 `Retry-After` 冷却。上游 429 进入自动冷却，连续三次登录失败、WAF 与 CAPTCHA 信号进入必须人工恢复的暂停态；固定优先级保证暂停不会被较弱信号覆盖。
- 健康状态与审计：新增 generation 感知的对话出站健康表、健康事件和 API；旧 generation 的暂停/冷却不会污染重建后的当前运行时。健康转换和网络决策进入同一对话级 hash 链，API、导出和 DOM 只包含封闭安全字段。容器管理列表、详情和出站审计展示健康状态、信号与恢复入口；暂停/冷却优先成为主状态，同时 Agent 和网关仍分别展示真实运行状态。恢复成功会同步清除页面的旧观测错误。
- 提交前测试：`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、`git diff --check`、相关 egress/egressaudit/database/runtime-container/handler race 和前端 155/155 全部通过。Linux ARM64 原生请求守卫、代理、数据库 generation/hash-chain/list 投影测试通过；真实 Docker 双并发 `/delay/3` 精确得到一个 200 和一个 429，审计原因为 `rule_concurrency_limit`，健康保持 `healthy`。
- 候选验收与回归修正：候选真实 429 触发 `cooldown` 且本地后续请求为 429，CAPTCHA 触发 `paused`，手动恢复后回到 `healthy`。验收发现并修复两项投影问题：暂停/冷却必须优先于普通 `running` 主状态；读取健康状态必须绑定当前 runtime generation。候选 v2 的 ARM64 原生数据库和网关测试、真实 HTTP/并发、API 及浏览器均重新通过后才提交源码。
- 精确构建与部署：从干净提交以 Zig/CGO 构建 Linux ARM64 服务和网关，SHA-256 分别为 `33e0097ea391ca80750d7c7e589d75a19a8cece37784dc67eb4a49978d4a06f8`、`e34a700fb4e8d020854189a4125e8b8b563b3308a227beb4cde931e113e055f8`；源码、Web 与网关上下文归档 SHA-256 分别为 `be31f81911bdbd3637c97eb861e0a9d87af61e71ee63e9b06d022a9d369ff966`、`8cca2fc883d8b1e4047d27a33760e9a8546712918dcbd64bd0745ddf442ff9c8`、`4da1c01c3fcccf787187852a32a10b6f01d52e7a71705351f4c60cc4d5d501db`，build info 为 `vcs.revision=152758f636b13586841579cbc47206bbb3fe4b0d`、`vcs.modified=false`。首轮部署在文件切换前因校验脚本的 `strings | grep -q` 在 `pipefail` 下收到 SIGPIPE 而安全中止，原服务保持健康；改为直接扫描二进制后事务部署成功，备份位于 `backups/stage6-item10-exact-152758f-pre-20260823-112948`，精确网关镜像为 `sha256:cfeec36de901afdea399193f85a2b13a4b5cd3c058e8dbed77bc90948549b910`。
- 精确服务与真实容器：运行文件和 `/proc/{pid}/exe` 哈希均与精确服务一致，配置固定镜像摘要可解析；服务 `active/running`、`NRestarts=0`、首页 200、匿名健康 API 401、认证健康 API 200，SQLite integrity/foreign-key check 通过，启动 warning 为 0。精确 QA 对话 `97763ea6-be35-4245-87f4-f95210f53f9d` 的 Agent/网关使用当前 generation 1 和精确网关摘要；真实 HTTP 先后验证正常 200、上游 429、冷却期本地 429、恢复、CAPTCHA 暂停、暂停期本地 429、再次恢复，以及两个并发请求精确为 200/429。13 条对话审计记录的链完整性为 `verified`，包含 `upstream_rate_limited`、`captcha_challenge`、`manual_recovery` 和 `rule_concurrency_limit`，未发现凭据或密码字段。
- 精确内置浏览器：使用虚拟机直连地址和已授权测试管理员会话。桌面端对话卡与实时详情主状态均显示“已暂停”，Agent/出站网关仍显示运行中，出站健康卡显示 CAPTCHA 原因和“手动恢复”；通过 UI 点击恢复后主状态与出站健康立即回到运行中/健康，恢复按钮消失。390×844 下文档宽度为 390/390、页面宽度为 326/326，无横向溢出；内部滚动容器 `clientHeight=772`、`scrollHeight=2254`，真实滚动达到 `1482/1482` 并看到完整镜像、Hash、DNS 与工具状态。最终 console warning/error 为 `[]`，临时视口已恢复。
- 范围说明：第 10 项完成确定性健康保护和恢复闭环；下一步进入第 11 项，对 7 个容器管理子页、创建对话控件、刷新/导航/筛选/分页/弹层和桌面/窄屏状态进行统一浏览器验收。

### 阶段 6 第 11 项验收（2026-08-23）

- 源码提交：`ef065e53c51940a139ac6f804ce6b2b8f844e637`。原“边界规则”和“出站代理”占位页已替换为真实管理功能：边界页从运行时列表选择对话并只读展示不可变快照、完整 SHA-256、generation、固定优先级规则和限流；出口页提供代理、代理组和认证档案的创建、编辑、删除、搜索、脱敏状态、成员优先级/权重、熔断冷却摘要和 URL 标签状态。创建对话面板同步加载精确边界策略和安全出口目标。
- 安全与可用性：所有服务端字符串只经 `textContent`/DOM 节点输出，不注入非受信 HTML；密码输入仅随当前写请求发送，保存后立即清空，不进入 URL、浏览器存储或回显 DOM。真实创建/编辑代理与认证档案后，页面正文和 `outerHTML` 均不含一次性测试凭据，只显示“凭据已配置”。代理组的可选成员统计只计算启用且未冷却的成员；隐藏的清除凭据控件不会被 flex 样式错误显示；动态状态随中英文切换即时刷新。
- 提交前测试：`node --test web/static/js/*.test.cjs` 为 159/159，`go test ./...`、`go vet ./...`、`GOCACHE=/private/tmp/cyberstrike-go-cache go mod tidy -diff`、三份脚本 `node --check`、测试凭据/fixture 扫描和 `git diff --check` 全部通过。首次 `go mod tidy -diff` 仅因系统 Go 缓存目录受沙箱限制退出，改用任务专用临时缓存后无差异通过，不属于代码失败。
- 候选真实 CRUD：通过内置浏览器创建并编辑 1 个代理、1 个代理组和 1 个认证档案，验证代理停用、组成员优先级/权重、0 个可选成员、凭据保留/脱敏和表单清空；聊天创建面板成功切换到 `Stage6 Item10 deterministic health QA` 不可变策略以及本轮代理组，未发送测试对话。删除入口成功触发浏览器原生 confirm；内置浏览器对原生 confirm 的自动接管阻塞旧标签页事件队列，因此关闭该测试标签页，并通过同一认证管理 API 按代理组→认证档案→代理的依赖顺序删除各 1 条，刷新与 API 均确认 fixture 为 0。
- 候选完整浏览器矩阵：桌面端 7 个独立子页均为文档宽度 `1056/1056`，容器总览、对话容器、运行环境、边界规则、出站代理、网络活动和出站审计均无占位页、错误页头或水平溢出；边界页读取 1 条精确规则且 SHA 校验通过，审计页读取每页 10 条且 22 条网络事件的链验证通过。390×844 下各活动页内容宽度均为 `326/326`；运行环境卡片修正为单列后卡片/标题/详情宽度分别为 `222/222`、`190/190`、`190/190`，真实滚动达到 `3803.5/3803.5` 并看到底部信息。创建对话的容器安全与出口弹层可滚动，三份边界选择和继承/无代理/停用代理/代理组目标均可读可选。最终候选 console warning/error 为 `[]`。
- 精确 Web 部署：从干净提交使用 `git archive` 生成 Web 归档，SHA-256 为 `b33f2dda976c815fbc509adcf49d2f39a8aa30190b6719b8dddecf108b71ec1b`；事务部署脚本校验归档、四个 cache-busting 资源版本和 AppleDouble 文件后切换 Web，失败时自动回滚。精确回滚点位于 `backups/stage6-item11-exact-ef065e5-pre-20260823-143548`，活动 Web 的 `.source-commit` 和 `.archive-sha256` 与本地精确制品一致；边界和出口脚本线上 SHA-256 分别为 `7b6b3a44…26703`、`faa4691f…964b`。第 10 项精确服务二进制不变，服务 `active`、`NRestarts=0`、首页 200，部署后 warning/error 日志为空。
- 精确内置浏览器：服务重启后使用已授权测试管理员自动登录虚拟机直连地址。边界页加载精确策略 `qa-stage6-item10-policy`、1 条规则和 SHA 已验证状态；出口页显示已加载 0/0/0，文档宽度 `1280/1280`、无占位文案或 fixture，脚本版本为 `boundary-rules.js?v=20260823-2`、`egress-management.js?v=20260823-2`、`container-management.js?v=20260823-6`，console warning/error 为 `[]`。浏览器最终恢复桌面视口。
- 阶段结论：阶段 6 的 7 个管理域、创建对话控件、实时网络活动、审计链、健康保护以及桌面/窄屏交互全部完成验收；按调整后的顺序先完成阶段 8，再进入阶段 7 的 ARM64 镜像供应链与端到端验收。

### 阶段 8 提前实施验收（2026-08-23）

- 源码提交：`b736a9f`。HTTPS 完整审计在阶段 7 前完成，保持默认关闭。控制面为每个启用对话生成独立、短期、可轮换的 ECDSA CA；Agent 只得到公开证书和组合信任链，私钥只以只读文件挂载到同一对话的出站网关。证书、私钥和不可变边界快照均有独立 SHA-256 绑定，跨对话 CA、快照或挂载漂移会失败关闭。
- 策略与数据面：边界策略草案和不可变快照新增 HTTPS 完整审计开关及不解密域名列表。网关在 CONNECT/SNI 预检后终止客户端 TLS，以会话 CA 签发短期叶证书，再按真实 HTTPS method/path 重新执行原边界规则；命中证书固定兼容域名及其子域时只执行 CONNECT/SNI/端口边界，不解密。请求/响应 header 和正文不进入活动或审计持久化，本阶段不提供正文持久化开关。
- 明确阻断反馈：HTTP、HTTPS、CONNECT、DoH 和认证档案不可用均返回 HTTP 403、`X-CyberStrikeAI-Blocked: true`、安全原因/规则标识以及中英文说明“CyberStrikeAI 出站边界已禁止访问该网站”；响应不包含 URL query、路径、Authorization、Cookie、Token、密码或正文。HTTPS 拦截响应设置精确 `Content-Length` 并完成 TLS close，真实 curl 不再得到意外 EOF。
- 提交前回归：`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、`node --test web/static/js/*.test.cjs`（159/159）、egress TLS/阻断竞态测试和 `git diff --check` 全部通过。专项测试覆盖对话 CA 隔离/轮换、证书固定绕过边界、HTTPS GET/POST/path、密码、Cookie、Authorization、Token、表单/文件样式上传、二进制响应、私钥挂载隔离和 Agent 只读证书允许列表。
- ARM64 与真实网络：Linux ARM64 原生 egress/container/app 最终测试二进制全部 PASS。测试机服务保持 `active/running`、`NRestarts=0`，最终网关镜像为 ARM64 `sha256:9405fcb3170040a046103af0be59050d3fd4b3b27cb0b2cb209c38664277b569`，网关健康。真实隔离 Agent 中：HTTP 阻断返回明确 403，允许 HTTP 到上游；启用会话 CA 后 HTTPS 阻断返回明确 403，允许 HTTPS 到上游；绕过代理的原始 TCP 直连失败。Agent 无 CA 私钥，网关同时具备受信证书/私钥挂载；审计链包含 HTTP、HTTPS 与 CONNECT 决策，敏感标记命中为 0。
- API 与内置浏览器：边界策略及规则完整 CRUD、模拟、TLS 配置规范化、OpenAPI 和 RBAC 测试通过。内置浏览器直连测试机边界规则页，策略名称、说明、HTTPS 开关、不解密域名、host、scheme、port、path、method 和并发字段均可输入；成功新增规则、将路径从 `/stage8` 编辑为 `/stage8/edited`，刷新后全部值仍在。页面可滚动到规则及只读快照区，两次截图成功，标题为 `CyberStrikeAI`，可见 DOM 无框架错误层，console warning/error 为 `[]`。
- 阶段结论：阶段 8 的 CA 隔离、HTTPS 细粒度规则、证书固定兼容、正文零持久化、明确阻断反馈、ARM64 实机与 UI 输入问题均已完成；随后按调整后的顺序进入阶段 7，仅执行 ARM64 加固和端到端验收。
