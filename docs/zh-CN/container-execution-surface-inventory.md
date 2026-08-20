# Agent 容器执行面盘点

> 对应阶段：容器、边界规则与出站代理实施计划的阶段 0  
> 源码基线：`35f7fa4a87f861747e56009892af564010f747e5`  
> 盘点日期：2026-08-20

本文档回答两个问题：当前命令实际在哪里执行，对话启用容器后应该在哪里执行。“执行位置”和“访问的网络目标”是两个维度：例如 FOFA 命令包装器可在容器中执行，但它访问的是第三方 API。

## 1. 执行位置定义

| 位置 | 定义 | 是否受对话容器隔离 |
| --- | --- | --- |
| `container` | 在该对话独立 Agent 容器内执行 | 是 |
| `control-plane` | 在 CyberStrikeAI 服务进程或管理型子进程中执行 | 否，必须单独做 RBAC、审计和出站管理 |
| `external` | 由独立 MCP Server、WebShell 目标、C2 Implant 或其他外部系统执行 | 否，不得声称已被对话容器隔离 |

## 2. 当前执行路径与目标归属

| 执行面 | 当前代码路径 | 当前位置 | 容器模式目标位置 | 阶段 2 必须处理的事项 |
| --- | --- | --- | --- | --- |
| `exec` | `internal/security/executor.go` 特殊分支调用 `exec.CommandContext` | `control-plane` | `container` | 使用对话 `ExecutionBackend`，保留流式输出、PTY、取消、超时、后台任务和退出码语义 |
| YAML 命令工具 | `internal/security/executor.go` 对 `security.tools` 统一调用 `exec.CommandContext` | `control-plane` | `container` | 所有外部命令都经过同一执行后端，不允许工具名称特判回退宿主机 |
| YAML 内部工具 | `query_execution_result` 的 `command` 为 `internal:query_execution_result` | `control-plane` | `control-plane` | 保持数据库/执行状态查询，不进入容器 |
| Eino `execute` | `internal/multiagent/eino_skills.go` 注入 `security.NewEinoStreamingShell()`，底层使用本地 Shell | `control-plane` | `container` | 不能只改 MCP `exec`；必须替换 Eino filesystem middleware 的 Shell backend |
| Eino 文件工具 | CloudWeGo filesystem middleware + `eino-ext/adk/backend/local` | `control-plane` | `container` | `read_file`/`write_file`/`edit_file`/`ls`/`glob`/`grep` 限定在 `/workspace`；Skill 源文件仍由控制面只读加载 |
| 漏洞、资产、项目事实、知识库 | `internal/app/*_tools.go` 和相关 handler | `control-plane` | `control-plane` | 保持服务端数据库事务和 RBAC，不把数据库凭据放入容器 |
| 工具执行查询/等待/取消 | `internal/mcp/execution_control_tools.go` | `control-plane` | `control-plane` | 管理执行记录，取消操作再转发到容器 backend |
| 工作流工具节点 | `internal/workflow/nodes.go` 调用 `ExecuteMCPToolForConversation` | 继承工具现状 | 继承对话绑定 | 传递 `conversation_id`/`runtime_mode`，不新建独立宿主 Shell 路径 |
| 批量任务 | `internal/handler/batch_queue_executor.go` 为子任务创建对话并运行 Agent | 继承工具现状 | 继承每个子任务对话绑定 | 每个子任务对话独立容器；队列并发必须受全局容器配额限制 |
| 对话主 Agent/子 Agent | 单 Agent、Deep、Supervisor、Plan-Execute 共享同一 MCP 工具集 | 继承工具现状 | 共享该对话容器 | 所有子 Agent 传递同一个不可变运行时与边界快照，不按 Agent 再创建容器 |
| 管理终端 | `/api/terminal/*` 直接调用宿主 Shell/PTY | `control-plane` | `control-plane` | 这是管理员系统终端，不是 Agent 工具；必须在 UI/API 标识“宿主机”并保持独立 RBAC/审计 |
| 本地 stdio MCP | `internal/mcp/client_sdk.go` 使用 `exec.Command` 启动已配置 Server | `control-plane` | `external` | 定义为平台外部执行器；首版不随对话迁入容器，页面不得标记为 `container` |
| HTTP/SSE 外部 MCP | `internal/mcp/external_manager.go` 通过独立 MCP Server 执行 | `external` | `external` | 保持外部，另行实施服务级出站和凭据边界 |
| WebShell 命令/文件 | `internal/handler/webshell.go` 由控制面 HTTP Client 向目标发请求 | `external` | `external` | 命令在远程 WebShell 主机上执行，不经 Agent 容器；保留独立 RBAC、HITL 和审计 |
| C2 监听/任务 | `internal/c2/` 和 `internal/app/c2_tools.go` | `control-plane` + `external` | `control-plane` + `external` | Listener/任务调度属平台，Implant 在外部主机；不纳入对话容器安全声明 |
| C2 Payload 编译 | `internal/c2/payload_builder.go` 本地调用 `go build` | `control-plane` | `control-plane` | 属平台编译服务，后续可独立为 build sandbox，不与 Agent 容器混同 |
| 上传文件 | `internal/handler/chat_uploads.go` 接收并持久化 | `control-plane` | 控制面接收 + 受控导入 `container` | 执行前复制到 `/workspace`，严禁将任意宿主路径 bind mount 进容器 |
| 超大工具输出 | `internal/tooloutput/` 当前落宿主机 reduction 目录 | `control-plane` | `container` 工作区 | 容器执行改为 `/workspace/.tool-output/`，控制面只保存摘要和引用 |

### 2.1 阶段 2 路径边界增量

容器会话现已将命令工作目录和 Eino 文件工具统一绑定到 `/workspace`：

- 空或相对路径会规范化为 `/workspace` 或其子路径；绝对宿主路径、`..` 越界、反斜杠和 NUL 在触达 Docker 前拒绝。
- `read_file`、`write_file`、`edit_file`、`ls`、`glob`、`grep` 根据可信对话运行模式选择 backend。宿主模式保留本地 backend；容器模式通过该对话的执行 backend 操作 `/workspace`，不再读取控制面同名路径。
- 容器内读取和工作目录逐段拒绝符号链接；受控写入使用固定的非特权 exec stdin、逐段目录校验、大小核对和原子重命名。
- 控制面上传仍持久化在 `chat_uploads/<date>/<conversationId>/...`，但 Agent 执行前会导入为 `/workspace/uploads/<date>/...`。异步初始化期间保存的附件会在容器就绪后的下一次执行前补同步。
- 消息历史与模型上下文只暴露容器路径；跨对话附件路径、符号链接源和非普通文件失败关闭。超大命令输出继续固定为 `/workspace/.tool-output/<executionId>`。

## 3. YAML 工具清单

基线共有 90 个 `tools/*.yaml`：89 个有外部 `command`，目标位置统一为 `container`；1 个内部查询工具为 `control-plane`。

### 3.1 `container`（89）

`amass`, `angr`, `api-schema-analyzer`, `arjun`, `arp-scan`, `binwalk`, `bloodhound`, `checkov`, `checksec`, `clair`, `cloudmapper`, `dalfox`, `dirsearch`, `dnsenum`, `dnslog`, `dotdotpwn`, `enum4linux-ng`, `exec`, `execute-python-script`, `exiftool`, `falco`, `feroxbuster`, `ffuf`, `fierce`, `fofa_search`, `foremost`, `fscan`, `gau`, `gdb`, `ghidra`, `gobuster`, `graphql-scanner`, `hashcat`, `hashpump`, `http-framework-test`, `hydra`, `impacket`, `install-python-package`, `jaeles`, `john`, `jwt-analyzer`, `katana`, `kube-bench`, `kube-hunter`, `libc-database`, `lightx`, `linpeas`, `masscan`, `metasploit`, `msfvenom`, `nbtscan`, `netexec`, `nikto`, `nmap`, `nuclei`, `objdump`, `one-gadget`, `pacu`, `paramspider`, `prowler`, `pwninit`, `pwntools`, `quake_search`, `radare2`, `responder`, `ropgadget`, `ropper`, `rpcclient`, `rustscan`, `scout-suite`, `shodan_search`, `smbmap`, `sqlmap`, `steghide`, `strings`, `subfinder`, `terrascan`, `trivy`, `virustotal_search`, `volatility3`, `wafw00f`, `waybackurls`, `wpscan`, `x8`, `xsser`, `xxd`, `zap`, `zoomeye_search`, `zsteg`.

这个列表表示“命令调用在容器内发生”，不表示所有工具都获得额外权限。依赖内核能力、硬件、Docker/Kubernetes Socket、GUI 或特权的工具，在默认安全 profile 下可能为 `unsupported`；不得为了“所有工具可运行”给整个容器授予特权。

`fofa_search`, `quake_search`, `shodan_search`, `virustotal_search`, `zoomeye_search` 等 API 包装命令仍在容器执行，但凭据不能固化在镜像、命令参数或容器长期环境变量中。在凭据代理实现前，这些工具在容器模式下必须显式标记为不可用，不能悄然回退到宿主机。

### 3.2 `control-plane`（1）

- `query_execution_result`：查询 CyberStrikeAI 已持久化的工具执行状态，不启动外部命令。

## 4. 内置 MCP 与 Eino 工具归属

| 工具组 | 工具 | 目标位置 |
| --- | --- | --- |
| Eino 工作区 | `execute`, `read_file`, `write_file`, `edit_file`, `ls`, `glob`, `grep` | `container` |
| 漏洞 | `record_vulnerability`, `list_vulnerabilities`, `get_vulnerability` | `control-plane` |
| 资产 | `create_asset`, `get_asset`, `query_assets`, `update_asset`, `delete_asset`, `complete_asset_scan` | `control-plane` |
| 项目事实 | `upsert_project_fact`, `get_project_fact`, `list_project_facts`, `search_project_facts`, `deprecate_project_fact`, `restore_project_fact` | `control-plane` |
| 知识库 | `list_knowledge_risk_types`, `search_knowledge_base` | `control-plane` |
| 视觉分析 | `analyze_image` | `control-plane` |
| 执行控制 | `get_tool_execution`, `wait_tool_execution`, `cancel_tool_execution` | `control-plane` |
| 批量任务管理 | `batch_task_list`, `batch_task_get`, `batch_task_create`, `batch_task_start`, `batch_task_rerun`, `batch_task_pause`, `batch_task_delete`, `batch_task_update_metadata`, `batch_task_update_schedule`, `batch_task_schedule_enabled`, `batch_task_add_task`, `batch_task_update_task`, `batch_task_remove_task` | `control-plane` |
| WebShell | `webshell_exec`, `webshell_file_list`, `webshell_file_read`, `webshell_file_write`, `manage_webshell_list`, `manage_webshell_add`, `manage_webshell_update`, `manage_webshell_delete`, `manage_webshell_test` | `external` |
| C2 | `c2_listener`, `c2_session`, `c2_task`, `c2_task_manage`, `c2_payload`, `c2_event`, `c2_profile`, `c2_file` | `control-plane` + `external` |
| Agent 编排 | `skill`, `task`, `plan` 等 Eino middleware/编排工具 | `control-plane`（其调用的业务工具再按本表路由） |

## 5. 不可隐式跨越的边界

1. `container` 工具不得在 Docker 不可用、容器未就绪或工具缺失时回退到宿主机。
2. 控制面不向 Agent 容器提供数据库、Docker Socket、平台管理 API 或第三方凭据原文。
3. 工作流、批量任务、机器人和子 Agent 不能丢失对话的 `runtime_mode`、`conversation_id` 和边界快照。
4. 管理终端是宿主机管理能力，不与 Agent 容器模式共用执行后端。
5. WebShell、C2 和外部 MCP 的安全边界必须单独呈现，不因对话选择了容器就显示为“已隔离”。
6. 当前系统没有 Agent 浏览器功能，不创建浏览器会话、profile 或浏览器命名空间。

## 6. 代码搜索交叉验证

阶段 0 使用以下搜索与代码阅读交叉验证：

```bash
rg -n '"os/exec"|exec\.Command|exec\.CommandContext|syscall\.Exec' --glob '*.go' --glob '!**/*_test.go'
rg -n 'RegisterTool|ExecuteTool|executeSystemCommand|executeInternalTool' internal
rg -n 'filesystem.New|NewEinoStreamingShell|backend/local' internal/multiagent
rg -n '^command:' tools/*.yaml
find tools -maxdepth 1 -name '*.yaml' -type f | wc -l
```

直接调用本机进程的生产代码集中在：

- `internal/security/`：Agent `exec`、YAML 命令工具和 Eino Streaming Shell。
- `internal/handler/terminal*`：平台管理终端。
- `internal/mcp/client_sdk.go`：本地 stdio MCP Server。
- `internal/c2/payload_builder.go`：C2 Payload 编译。
- CloudWeGo `eino-ext/adk/backend/local`：Eino 文件与 Shell 工具的当前本地 backend。

以上每一类都已在第 2 节给出目标归属，没有“容器模式下位置不确定”的执行面。

## 7. 阶段 0 基线与验收证据

### 7.1 本地

- 分支、`main` 和 `origin/main` 在开始时均指向 `35f7fa4a87f861747e56009892af564010f747e5`，本地无旧容器实现。
- `env GOCACHE=/private/tmp/cyberstrike-go-build-cache go test ./...`：通过。涉及 `httptest` 的用例在允许本机回环端口后完整执行。
- `node --test web/static/js/*.test.cjs`：15 个测试文件，115 项通过，0 失败。
- `git diff --check`：通过。

### 7.2 测试机

- 主机：`10.211.55.16`，部署目录：`/home/parallels/cyberstrike-agent-container-test-01a00efc`。
- 受版本控制的源码与阶段 0 新增文档已同步；本地/远端两份阶段文档 SHA-256 一致。
- `cyberstrike-ai-test.service`：`active (running)`；`GET http://10.211.55.16:8080/` 返回 200。
- 测试机不安装 Go/Node，因此源码测试在本地/构建环境执行，测试机只验收构建产物、API、Docker 实际状态和 UI。
- 一个 `CGO_ENABLED=0` 的 ARM64 候选产物被 SQLite 驱动在启动时拒绝；系统已使用预先保留的二进制完整回滚并恢复 200。后续 Linux ARM64 应用产物必须在支持 CGO 的可复现构建环境生成。

### 7.3 Codex 内置浏览器

- 页面身份：`http://10.211.55.16:8080/?qa=20260820-5#chat`，标题 `CyberStrikeAI`。
- DOM 包含完整顶部导航、侧栏、对话列表、欢迎状态和输入区，不是空白页，未发现框架错误层。
- 控制台 `error`/`warn` 为 0。
- 点击“仪表盘”后 URL 变为 `#dashboard`，成功渲染运行对话、漏洞、工具调用、成功率和能力总览，交互验收通过。
