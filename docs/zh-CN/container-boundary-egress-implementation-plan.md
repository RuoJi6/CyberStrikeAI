# Agent 容器、边界规则与出站代理实施计划

> 状态：执行中  
> 当前阶段：阶段 4 第 2 项已完成（第 3 项进行中：网关只读加载已绑定快照）
> 最后更新：2026-08-21
> 工作分支：`codex/docker-agent-runtime`

本文档是 Agent 容器化的唯一执行清单。以后每完成一个阶段，必须先通过本地测试和测试机验收，再将该阶段勾选为完成，然后进入下一阶段。

## 1. 已确认的产品决策

- [x] 一个对话对应一个 Agent 容器，同一对话的主 Agent 和子 Agent 共享该容器。
- [x] 创建对话时，用户可以选择“容器执行”或“本机执行”。
- [x] 容器模式使用 `ghcr.io/usestrix/strix-sandbox:1.3.0` 作为首选基础环境；生产配置使用镜像 digest 锁定，不依赖浮动 tag。
- [x] 启用前检查镜像是否同时支持 `linux/amd64` 和 `linux/arm64`；不支持时由 CyberStrikeAI 维护可复现的多架构派生镜像。
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
- [ ] 网关崩溃、快照不匹配或快照不可读时失败关闭。
- [ ] 编写代理协议单元测试、Docker 网络集成测试和绕过回归测试。

验收门槛：允许域名只能经网关访问；blocked 和未知域名同时在 DNS 和网关被拒绝；任意直接网络方式不得绕过；网关不可用时容器无法出网。

### 阶段 5：上游单代理、代理组和凭据边界

目标：在已经强制的 CyberStrikeAI 出站网关之后增加用户可配置的上游出口。

任务：

- [ ] 实现 HTTP/HTTPS/SOCKS 代理条目，服务端加密保存凭据，所有返回结果脱敏。
- [ ] 实现代理组、多成员搜索选择、优先级、同优先级权重轮询、熔断和冷却。
- [ ] 实现对话级的“无上游代理”、“单代理”和“代理组”绑定。
- [ ] 实现用户/项目默认值的继承预览，对话级显式选择优先。
- [ ] 所有上游都不可用时默认阻断，不返回直连。
- [ ] `auth-only` 凭据由出站网关对匹配请求动态注入，Agent 和容器不能读取凭据原文。
- [ ] 测试机使用虚拟机实际默认网关地址访问宿主机 `7897` 代理，不硬编码其他网络的 `172.*` 地址。
- [ ] 测试凭据隐藏、代理轮询、熔断、冷却、失败关闭和跨对话隔离。

验收门槛：单代理与代理组路由结果可解释；凭据不出现在 API、DOM、日志、容器 env 或命令行；所有上游失败时没有直连流量。

### 阶段 6：容器管理 UI、出站审计与确定性健康监控

目标：用户能清楚看到执行位置、初始化、网络决策和失败原因，不将多个管理域堆在同一长页面。

任务：

- [ ] 实现“容器管理”可折叠侧栏与 7 个独立子页，页头跟随当前子页。
- [ ] 创建对话时显示执行模式、文件持久化作用、边界策略和出口选择。
- [ ] 展示容器/网关/DNS/工作区状态、资源用量、镜像 digest、快照 hash 和最后错误。
- [ ] 实现统一可搜索单选/多选组件，修复弹层、层级、宽度、键盘可访问性和空状态。
- [ ] 实现 10/20/50/100 每页、服务端分页、搜索、状态筛选和 URL 状态保留。
- [ ] 实现对话出站网络活动实时流，页面可立即看到新的域名请求、解析 IP、允许/阻断和命中规则。
- [ ] 审计 DNS、HTTP、CONNECT、拒绝、限速、上游路由和生命周期事件，支持搜索与导出。
- [ ] 日志记录 `conversation_id`、`container_id`、`agent_id`、快照 hash、目标、判定、命中规则和上游；敏感 header/body 默认不保存。
- [ ] 对每个对话的审计事件增加前序 hash，可检测删除或篡改。
- [ ] 实现确定性限速、并发上限、429 冷却、连续登录失败、WAF/CAPTCHA 信号和手动恢复。
- [ ] 完成桌面和窄屏 UI 浏览器验收，无刷新卡死、空对话、错误页头或下拉框遮挡。

验收门槛：管理页不依赖单页长滚动；状态与 Docker 实际资源一致；发起测试请求后能在网络活动页立即看到域名与决策；拒绝、熔断和停止都能追溯到决策与快照。

### 阶段 7：安全加固、端到端验收与渐进发布

目标：完成绕过测试、故障演练和 ARM64/AMD64 验证，再允许生产启用。

任务：

- [ ] 验证镜像 SBOM、来源、digest 锁定、签名/校验和 amd64/arm64 可运行性。
- [ ] 进行直接 IP、自定义 DNS、DoH、IPv6、DNS Rebinding、重定向、宿主机网关、Docker API 和跨对话访问绕过测试。
- [ ] 进行网关崩溃、Docker 重启、CyberStrikeAI 重启、数据库暂停、审计缓冲区填满和磁盘空间不足演练。
- [ ] 验证对话删除、容器删除、卷保留/删除和孤儿资源回收。
- [ ] 验证 RBAC：普通用户不能修改系统镜像、规则快照、他人代理凭据或审计保留策略。
- [ ] 使用功能开关按用户/项目小范围开启，默认不改变现有 host 模式。
- [ ] 在测试机完成真实对话、容器命令、工作区、规则和代理全链路验收。
- [ ] 更新安全模型、配置、部署、运维、审计和排错文档。

验收门槛：安全回归全部通过，测试机实际验收通过，未解决的高风险项为 0，支持一键回退到原 host 执行模式。

### 阶段 8（可选）：HTTPS 完整审计

此阶段不阻塞首版发布，且默认关闭。

- [ ] 为每个对话生成独立短期 CA，只注入该对话容器。
- [ ] 增加不解密域名列表和证书固定兼容策略。
- [ ] 解密后对 method/path/header/body 重新执行边界规则。
- [ ] 请求/响应正文默认不持久化；显式开启时必须脱敏、加密、限量和按期清理。
- [ ] 对密码、Cookie、Authorization、Token、文件上传和二进制响应编写专门数据泄露测试。

验收门槛：启用完整审计的对话可检查 HTTPS URL 与方法；未启用的对话不信任任何相关 CA；证书和正文不跨对话泄露。

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
- [ ] `auth-only` 凭据只在网关匹配请求时使用，Agent 无法读取。
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
| 4 | 进行中（第 1—7 项已完成） | 第 1—7 项：2026-08-21 | `7a7d01f`（第 1 项）；`0940cb8`（第 2 项）；`20ad08a`（第 3 项）；`66c8679`（第 4 项）；`70ea888`（第 5 项）；`5f3b237`（第 6 项）；`f0dddc5`（第 7 项） | 第 1 项证据同前。第 2 项容器/数据库/app/config/egress 定向与 race、`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、前端 128/128 与 `git diff --check` 全部通过；覆盖每对话 Agent+网关+内部网+出口网创建/回滚/启停/删除，固定镜像、最小权限与资源限制漂移拒绝，孤儿资源认领，启停失败原子回滚，旧运行时显式迁移与持久工作区保留。第 3 项同样通过 Go 全包、相关包 race、`go vet ./...`、`go mod tidy -diff`、前端 128/128 和差异检查；覆盖 canonical 快照文件原子发布、`0700` 受信目录/`0444` 文件、精确 SHA/模式校验、只给网关的单一只读 bind、启动/健康报告、Agent 启动前等待、缺失/篡改/错误报告失败关闭、显式快照迁移、持久卷兼容及旧本地镜像标签移动后的不可变 ID 校验。第 4 项在提交前通过 egress/container/app/database 定向与相关包 race、`go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、前端 128/128 和差异检查；覆盖绝对形式 HTTP、Host 一致性、逐跳头剥离、CONNECT 分片 ClientHello、真实 TLS 1.3 SNI、缺失/重复/非法 SNI、ECH/ESNI、未知目标及 DNS 重绑定失败关闭。第 5 项继续通过上述完整矩阵，并覆盖 UDP/TCP DNS、只对有活动允许规则的规范域名解析、未知/blocked 名称不触发上游查询、解析结果全地址重评估、混合公网/私网答案、过期规则、blocked 公网网段、解析失败/空答案、并发与取消；运行时为快照网关动态发现内部 IPv4 并设为 Agent 唯一 DNS，创建、readiness、运行态检查均拒绝缺失、伪造或漂移地址。第 6 项同样在提交前通过相关包定向与 race、Go 全包、`go vet ./...`、`go mod tidy -diff`、前端 128/128 和差异检查；新增 DNS 服务端口 53/784/853/8853、已知加密 DNS 服务主机及后缀边界、DoH 路径/媒体类型、重定向逐跳重评估、混合 IPv6 Rebinding、internal 网络 `inhibit_ipv4` 以及 Agent/网关端点宿主网关漂移拒绝覆盖。第 7 项在提交前继续通过 Go 全包、container race、`go vet ./...`、`go mod tidy -diff`、前端 128/128 和差异检查；覆盖快照型网关 HTTP/HTTPS/ALL proxy 大小写变量与空 `NO_PROXY/no_proxy` 的精确生成，创建、运行态和 readiness 对缺失、外部代理、绕过列表、重复键及无网关意外代理的失败关闭 | 第 1 项候选和精确部署证据同前。第 2 项先在提交前候选版本完成真实旧运行时 generation 1→2 显式迁移，持久文件保留；两对话内部/出口网络 ID 与子网均不同，每个 Agent 只有自己的 internal 网，每个出口网仅网关挂载，默认 bridge 挂载数为 0。已推送并精确部署 `0940cb8`（`vcs.revision=0940cb859b06135e3ca6a2c66471e674578b2bea`、`vcs.modified=false`）；Linux ARM64 服务、网关二进制、容器测试、数据库测试和源码归档 SHA-256 分别为 `d0b5ece5…b57d72`、`10cf3517…165fd37`、`879e306e…936ad2`、`b4a9b7d3…c5c088d`、`b5db8c8d…32a9cab`，网关镜像 digest 为 `sha256:8b36ac60…3fa3fa26`。精确版本新对话的 SQLite 规格、Agent/网关 Docker 标签及镜像 digest 一致；运行态 internal 网挂载 2、出口网挂载 1，Agent 直连 `1.1.1.1` 退出码 7，网关以 UID/GID 65532、只读根、`cap-drop=ALL`、`no-new-privileges`、零 bind/端口、固定 CPU/内存/PID/tmpfs 限制运行；停止后两网挂载均为 0，删除后容器/网络/卷/数据库记录全部清零。第 3 项候选真实容器将 item-2 运行时显式迁移到 generation 2，工作区标记保留；网关仅挂载快照文件且命令/健康检查绑定同一 ID/SHA，首次健康报告结束于 `17:05:27.518`，Agent 于 `17:05:27.537` 才启动；临时移走快照后启动为 409、运行时记录为 `security_or_specification_drift` 且两容器保持退出，恢复后 reconcile/start/stop 均为 200。已推送并精确部署 `20ad08a`（`vcs.revision=20ad08a1fe58279b9595c0a4ba3540d0b67024c4`、`vcs.modified=false`）；服务、网关、container/app/database/egress 测试与源码归档 SHA-256 分别为 `f9932e03…0c3880`、`379148ed…5eb97`、`bdeb2d9e…e4a415`、`eb235230…8778e3`、`11a1525c…2cb88c`、`60dda040…c8e044`、`b66c16b8…2cb88c`，精确网关镜像为 `sha256:1c861667…c9634`；ARM64 原生测试全部通过，镜像在无网络、只读根、非 root、无 capability 的临时容器内回报精确快照 ID/SHA，服务 active、`NRestarts=0`、首页 200 且启动后无 warning/error。第 4 项 ARM64 原生 egress/container/app/database 测试全部 PASS；精确提交 `66c86790e273bfa3e47031326ee187295c72c060` 的服务、网关和源码归档 SHA-256 分别为 `d4af5613…26cd5`、`fe501458…cf392`、`7471a5f3…688db`，最终网关镜像为 `sha256:e40597d6…18cc5`。真实 HTTP 与 HTTPS CONNECT 均返回 559 字节；未知目标返回 403，SNI 不匹配与缺失均在上游连接前失败，强制解析到 `127.0.0.1` 返回 502；镜像以 UID/GID 65532、只读根、`cap-drop=ALL`、`no-new-privileges` 和单一只读快照挂载运行。精确服务已部署，运行进程哈希匹配，服务 active/running、`NRestarts=0`、首页 200 且启动后 warning/error 为 0。第 5 项候选与精确提交均在虚拟机通过 boundary/egress/container ARM64 原生测试，精确提交 `70ea888268598a93b51e65c22c57d6599860499d` 的服务、网关与源码归档 SHA-256 分别为 `a8a557df…734fb9`、`ef1da97a…cbfd3d`、`677f65ed…7e6f8`，最终镜像为 `sha256:b624a5a4…cd281a`。真实 UDP/TCP DNS 对 `example.com` 返回 NOERROR，未知 `iana.org` 返回 NXDOMAIN，loopback 重绑定同时返回 DNS NXDOMAIN 与代理 502；真实隔离 Agent 的唯一 DNS 为同网络网关 `172.20.0.2`，允许解析 6 行、未知解析退出 2、经代理 HTTP 为 559 字节、无代理直连退出 7，internal/egress 网络挂载数分别为 2/1。精确服务已部署且进程哈希匹配，服务 active/running、`NRestarts=0`、首页 200、启动后 warning/error 为 0。第 6 项候选与精确版本均通过 boundary/egress/container ARM64 原生测试，精确版 app/database 也为 PASS；精确提交 `5f3b237fd669dd0270c48273d4b49580a0001e21` 的服务、网关二进制与源码归档 SHA-256 分别为 `89b1839f…f2c6f1d1`、`0542e17e…03ab5f5`、`17a28d0e…6b095`，最终镜像为 `sha256:9dce4229…a7bddf`。真实隔离 Agent 的唯一 DNS 为 `172.20.0.1`，内部网 IPAM/Agent/网关端点均无宿主网关，宿主 bridge 无 IPv4，Agent 仅有直连子网路由且没有 IPv6 路由；授权 HTTP 为 200，DoH 路径/媒体类型、未知/私网 IP、DNS 端口和 IPv6 代理绕过均为 403，已知 DoH CONNECT 为 403，直接 HTTP、自定义 DNS TCP 与直接 IPv6 均失败。精确服务进程哈希匹配，配置固定镜像摘要可解析，服务 active/running、`NRestarts=0`、虚拟机内和直连首页均 200、启动后 warning/error 为 0。第 7 项候选和精确提交均通过 ARM64 container 原生测试，精确版 app/database 也为 PASS；精确提交 `f0dddc59d871c7d024ff7fe67f68bbc796f7450d` 的服务与源码归档 SHA-256 分别为 `ba9d7ca1…dd7430`、`eb3f02dc…96c3ef`。真实 Agent 自动继承 `http://172.20.0.1:3128` 的大小写 HTTP/HTTPS/ALL proxy，`NO_PROXY/no_proxy` 为空，未显式传 proxy 的 HTTP/HTTPS 均为 200；删除全部代理变量、强制 `NO_PROXY=*` 或替换为外部代理均因只有直连子网路由而失败。精确服务进程哈希匹配，服务 active/running、`NRestarts=0`、虚拟机内和直连首页均 200、启动后 warning/error 为 0 | 第 1—7 项均无 UI 功能变更，未重复浏览器视觉验收；管理员网页登录保留到后续统一 UI 验收并等待即时敏感操作确认 | 新运行时为每对话 Agent 仅 internal、网关 internal+专属出口网络；存量旧运行时只在用户显式重建时迁移。网关现在只信任控制面生成并以单文件只读挂载的不可变快照，启动与健康检查都回报精确 SHA-256；第 4 项已实现 HTTP forward proxy、HTTPS CONNECT/SNI 判定与连接前全地址重评估，第 5 项已实现 UDP/TCP 策略 DNS 和 Agent 唯一 DNS 绑定，第 6 项通过 Docker bridge `inhibit_ipv4` 取消内部网宿主桥地址和默认网关，并以唯一策略 DNS、默认拒绝、连接前全地址重评估、已知加密 DNS 服务主机/端口以及明文 DoH 形态识别补齐绕过矩阵；不解密 HTTPS 正文，管理员显式授权的任意自建 HTTPS 端点仍属于受信策略输入。第 7 项已为快照型 Agent 注入同网关 HTTP/HTTPS/ALL proxy 大小写变量并清空绕过列表，创建、readiness 和运行态均与网关地址精确核验；网络隔离仍是强制边界，客户端删除、绕过或篡改代理变量都无法直连。第 8 项开始验证网关崩溃和快照异常时失败关闭 |
| 5 | 未开始 | - | - | - | - | - | - |
| 6 | 未开始 | - | - | - | - | - | - |
| 7 | 未开始 | - | - | - | - | - | - |
| 8（可选） | 未开始 | - | - | - | - | - | - |
