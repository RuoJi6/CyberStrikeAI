# 全工具 Agent 镜像构建、发布与验收计划

> 状态：后端与 ARM64 运行态通过，UI 验收阻断
> 当前阶段：Agent 与 Egress 新 digest 已切换生产并通过容器、网络和持久审计验收；内置浏览器新建页面在导航前超时，UI 待浏览器连接恢复后复验
> 最后更新：2026-08-26
> 工作分支：`codex/docker-agent-runtime`
> ARM64 验收环境：`10.211.55.16`（凭据不写入本文档或仓库）

本文档是“从 Strix 派生镜像切换到 CyberStrikeAI 自有全工具镜像”的执行清单和验收标准。任何一道门禁失败，都不得进入下一道会改变部署状态的步骤。

## 1. 目标与非目标

### 1.1 目标

- 以官方最小 Kali Rolling 镜像为基础，不再继承 Strix 镜像。
- 只安装 CyberStrikeAI 当前已启用工具及它们的运行时依赖，不安装 `kali-linux-everything` 元包。
- 产出 `linux/arm64` 和 `linux/amd64` 两个平台镜像及同一个 Docker Hub 多架构标签。
- 配置覆盖固定为 77/77；平台实际可用性独立报告。上游仅提供 AMD64
  二进制且没有已采用 ARM64 安装来源的工具，必须在锁文件中明确声明平台限制，
  ARM64 验收可显式跳过，禁止用占位哈希或静默安装失败冒充可用。
- 用户已用 Docker Build Cloud 完成双架构构建；ARM64 必须在实际虚拟机直接从 Hub 拉取、部署和原生运行验收，AMD64 只记录 manifest 与构建探针结果，不冒充为实机验收。
- 镜像按不可变 digest 部署，每个平台生成与该 digest 精确绑定的工具 inventory、SBOM 和校验和。
- 新镜像在虚拟机切换并通过端到端验收后，才允许删除旧 Agent/Strix 镜像。

### 1.2 非目标

- 不在 GitHub Actions 上构建或保存镜像。
- 不将 Docker Hub 密码或 PAT 写入脚本、环境文件、镜像层、命令行记录或 Git。
- 不因为“工具多”而使用 `--privileged`、host network、Docker Socket 或 `SYS_ADMIN`。
- 不在对话启动时临时下载全部工具。可写工作区中的用户主动安装行为不代替发布 inventory。
- 不在新镜像验收前改变当前正在运行的对话容器。

## 2. 当前事实基线

### 2.1 工具是如何被加载和执行的

```text
config.yaml: security.tools_dir
        │
        ▼
internal/config/config.go
  LoadToolsFromDir / MergeToolsFromDir
        │ 只接受 enabled=true 工具
        ▼
internal/security/executor.go
  RegisterTools / buildCommandArgs
        │ 生成 argv，不拼接默认 shell
        ▼
internal/security/execution_backend.go
        │
        ├─ host 对话 → HostExecutionBackend
        └─ container 对话
              ▼
internal/app/conversation_execution_backend.go
  核对边界快照、runtime generation、初始化和 readiness
              ▼
internal/runtime/container
  使用预先存在本机的 repository@digest 执行 Docker Exec
```

已确认的约束：

1. YAML 目录定义优先于内联工具定义；解析失败的文件会跳过并记录警告。
2. `internal:` 命令由控制面完成；命令型 YAML 工具、`exec`、Eino 命令和文件工具都经过同一执行后端。
3. 容器后端失败时不会静默回退到宿主机。
4. 创建容器前必须在本机找到指定 `repository@digest`；当前运行时不会自动拉取缺失镜像。
5. 配置中的镜像 digest、平台、inventory 中的 digest/平台和实际容器镜像必须一致。
6. 修改全局镜像配置不会偷换已有对话的持久化 RuntimeSpec；测试对话必须显式重建或新建。

### 2.2 当前镜像差距

- `container/agent/Dockerfile` 已切换到 digest 锁定的 Kali Rolling；用户提供的 Docker Build Cloud 多架构镜像已发布到 `ruoji6/cyberstrikeai-agent`。
- `tools/` 共有 90 个 YAML 定义：77 个启用，13 个禁用；`prowler` 因当前
  512 MiB 容器限制下稳定 OOM，已从发布范围移除并改为禁用。
- 候选 `container/agent/tool-inventory.entries.json` 已扩展到 83 个命令/运行时条目，
  并由平台映射过滤；实际镜像可用性仍须由镜像内探针证明。
- 当前 ARM64 虚拟机已直接从 Docker Hub 拉取 index digest `sha256:14bed42067163e75430e5ea4bf335c18e9631569742da591894c2a1c0a38111d`。发布物来自干净提交 `21b1ca30dfda14092a52225a0e1f2ef09572de76`，版本为 `full-tools-seclists-20260826`；77/77 配置映射、75/77 ARM64 平台支持、全工具功能探针和无网络安全冒烟均通过。
- 当前 81 项 ARM64 inventory 内容摘要为 `sha256:83173e182532f08cbbfc67ab2083a3c09e4df428a139a096c4a29b10e1d66759`；旧 Agent 镜像及其已停止测试容器已清理，工作区卷保留。

## 3. 工具范围

发布门禁以 `tools/*.yaml` 的实时 `enabled` 值为真实来源，不以本文档中的手工计数替代自动比对。当前 77 个启用定义分类如下。

### 3.1 运行时与内部封装（5）

`exec`、`execute-python-script`、`install-python-package`、`http-framework-test`、`query_execution_result`。

`query_execution_result` 是控制面内部工具；其余封装要求镜像提供 Shell、Python、venv、pip、HTTP 库和可写工作区。

### 3.2 网络侦察与 Web（30）

`amass`、`api-schema-analyzer`、`arjun`、`arp-scan`、`dalfox`、`dirsearch`、`dnsenum`、`dnslog`、`dotdotpwn`、`ffuf`、`fierce`、`gau`、`graphql-scanner`、`jaeles`、`jwt-analyzer`、`katana`、`masscan`、`nbtscan`、`nikto`、`nmap`、`nuclei`、`paramspider`、`rustscan`、`sqlmap`、`subfinder`、`wafw00f`、`waybackurls`、`wpscan`、`x8`、`xsser`。

### 3.3 凭据、AD 与内网（10）

`bloodhound`、`enum4linux-ng`、`hashcat`、`hydra`、`impacket`、`john`、`netexec`、`responder`、`rpcclient`、`smbmap`。

### 3.4 二进制、逆向与取证（21）

`angr`、`binwalk`、`checksec`、`exiftool`、`foremost`、`gdb`、`ghidra`、`hashpump`、`libc-database`、`objdump`、`one-gadget`、`pwninit`、`pwntools`、`radare2`、`ropgadget`、`ropper`、`steghide`、`strings`、`volatility3`、`xxd`、`zsteg`。

### 3.5 云、容器与合规（8）

`checkov`、`cloudmapper`、`falco`、`kube-bench`、`kube-hunter`、`scout-suite`、`terrascan`、`trivy`。

### 3.6 利用与后渗透（3）

`linpeas`、`metasploit`、`msfvenom`。

### 3.7 当前禁用定义（13）

`clair`、`feroxbuster`、`fofa_search`、`fscan`、`gobuster`、`lightx`、`pacu`、`prowler`、`quake_search`、`shodan_search`、`virustotal_search`、`zap`、`zoomeye_search`。

禁用不等于必须从镜像删除，但它们不得被计入“77/77 启用工具通过”。远程 API 封装还需要外部凭据和网络，不以镜像内的命令存在性代替功能验收。

## 4. 构建设计

### 4.1 基础镜像

- 基础使用官方 `kalilinux/kali-rolling` 多架构镜像，`FROM` 必须锁定多架构 manifest digest，不直接使用浮动 `latest`。
- 优先使用 Kali APT 包；APT 缺失的工具在独立 builder 阶段从锁定版本或提交构建。
- Go/Rust/Java/Ruby/Python 构建依赖不得无必要地留在最终运行时层。
- 每一个非 APT 下载都必须锁定版本和 SHA-256，不执行未锁定的 `curl | sh`。

### 4.2 运行时基线

最终镜像至少提供：

- `sh`、`bash`、coreutils、findutils、grep、sed、awk、tar、gzip、zip/unzip。
- `curl`、`wget`、`git`、`jq`、`rg`、CA 证书。
- Python 3 + venv + pip、Ruby、Java Runtime、Node.js；只在工具确实需要时保留对应运行时。
- `ip`、`ping`、`dig`、`nc`、`ssh`、`mysql`、`tcpdump`等基础网络命令。
- 非 root 用户 `pentester`，home 目录和 `/workspace` 约定与现有控制面保持一致。
- 镜像入口可被控制面的固定 keepalive 进程安全替换，不依赖自有守护进程。

### 4.3 建议代码落点

| 文件 | 用途 |
| --- | --- |
| `container/agent/Dockerfile` | 多阶段、多架构 Agent 镜像 |
| `container/agent/toolchain.lock` | 非 APT 工具的版本/提交/SHA-256 锁定 |
| `container/agent/tool-inventory.entries.json` | readiness 工具名、绝对路径、版本和分类 |
| `scripts/verify-agent-toolset.sh` | 工具命令、Python/Ruby 模块和关键功能探针 |
| `scripts/build-agent-image.sh` | 参数化的本地构建，不保存凭据 |
| `scripts/publish-agent-image.sh` | 在已完成 `docker login` 的环境上传并回读 digest；默认发布 Provenance，`--registry-sbom` 显式开启注册表 SBOM |
| `container/agent-tool-inventory-linux-*.json` | 与发布 digest 精确绑定的平台 inventory |

全工具镜像生成的 SPDX 可能超过 Docker Build Cloud 的内嵌证明大小上限。注册表未内嵌 SBOM 时，仍须通过 `scripts/verify-container-release.sh` 生成并校验与平台 digest 精确绑定的离线 SPDX 和 `SHA256SUMS`。

## 5. 执行阶段

### 阶段 0：加载链路与范围冻结

- [x] 确认 YAML 工具加载、覆盖优先级和 enabled 过滤。
- [x] 确认参数生成和特殊封装工具的真实子依赖。
- [x] 确认 host/container 路由、容器初始化和失败关闭语义。
- [x] 确认镜像不自动拉取，部署前必须预拉取。
- [x] 确认当前虚拟机架构、Docker 环境、磁盘和当前配置。

门禁：命令执行位置和镜像加载时机无未知项。

### 阶段 1：镜像实现

- [x] 锁定 Kali 基础 manifest digest。
- [x] 建立 APT 包、外部二进制、源码构建和运行时模块的明确映射。
- [x] 实现非 root 运行时、稳定 PATH 和可写工作区。
- [x] 实现 77 个启用工具与其真实子依赖的自动覆盖检查。
- [x] 更新 inventory entries 和构建/校验脚本。

门禁：Dockerfile 不使用 Strix，不使用浮动下载，配置覆盖比对为 77/77；
平台支持声明、SHA-256 和依赖锁检查全部通过。

### 阶段 2：ARM64 镜像拉取与镜像内验收

- [x] 在 ARM64 虚拟机直接从 Docker Hub 拉取用户提供的多架构镜像。
- [x] 运行安全基线冒烟、全工具存在性和平台过滤探针。
- [x] 生成并校验 ARM64 inventory、镜像元数据和内容摘要。
- [x] 对新 digest 重跑全工具功能探针；`amass -version` 和其余 ARM64 声明支持工具均通过。
- [x] 对新 digest 重复无网络冒烟，确认对话启动阶段不下载工具。

门禁：ARM64 构建成功，当前平台声明支持的工具自动探针 100% 通过，
平台不支持项必须与锁文件一致且单独报告，证据包可重算。

### 阶段 3：AMD64 与多架构发布候选

- [x] Docker Build Cloud 完成 AMD64 构建与映射探针。
- [x] 记录 AMD64 平台 manifest digest。
- [x] 回读包含 `linux/arm64` 和 `linux/amd64` 的多架构 index。
- [ ] AMD64 实机运行验收（不属于本次用户要求，不冒充已完成）。

门禁：manifest 仅包含两个期望平台，两者的工具清单差异仅限锁文件中
明确声明的平台限制，无其他意外分歧。

### 阶段 4：Docker Hub 上传与回读验证

- [x] 用户已将版本标签和 `latest` 上传到 Docker Hub。
- [x] 从 Docker Hub 回读 manifest digest、平台 digest、OCI 标签和平台列表。
- [x] 确认版本标签与 `latest` 当前解析到同一个 index digest。
- [x] 在 ARM64 VM 使用精确 repository/index digest 拉取并重跑冒烟。
- [x] 新 `latest` 由干净提交 `21b1ca30dfda14092a52225a0e1f2ef09572de76` 重建，版本为 `full-tools-seclists-20260826`。

门禁：Hub 上内容与本地候选一致，按 digest 可在无本地 tag 依赖时拉取和执行。

### 阶段 5：系统切换

- [x] 备份虚拟机当前 `config.yaml`、当前 Agent digest 和 inventory。
- [x] 在修改配置前预拉取 Hub 镜像，并用运行时 inspector 验证本地 RepoDigest 和平台。
- [x] 以实际部署 digest 生成 `container/agent-tool-inventory-linux-arm64.json`。
- [x] 修改仓库示例、虚拟机生产配置和供应链文档中的 repository/digest/inventory digest。
- [x] 重启 CyberStrikeAI，检查 systemd active、HTTP 200、无重启循环和无镜像校验错误。
- [x] 新建专用验收对话，不以旧 RuntimeSpec 伪充切换完成；实际 Agent 容器使用目标镜像且 UID 为 `pentester`。

门禁：新对话容器的实际镜像、平台、inventory 和配置完全一致。

### 阶段 6：端到端功能验收

- [x] 新建容器对话，观察初始化、启动和工作区状态，并验证停止/恢复。
- [ ] 从容器内 exec 和交互式 Shell 验证命令位于同一对话容器。
- [x] 在授权面向自有靶场测试 HTTP、HTTPS、TCP、UDP 以及 DNS `A/AAAA/NS/MX/TXT/SRV`。
- [x] 验证允许、显式阻断、默认策略、对话筛选和完整出站审计。
- [ ] 验证完整报文显示、审计关闭开关和大量流量下的页面响应。
- [ ] 用内置浏览器新开页面验收容器状态、工作区和交互式终端 UI；页面无 console 错误。

门禁：容器、工具、网络、审计和 UI 全部通过，无宿主机回退或未经授权的实际攻击。

### 阶段 7：清理、提交与推送

- [ ] 仅在阶段 6 通过后，删除虚拟机的旧 Agent/Strix 镜像和本次候选 tag。
- [x] 删除本次产生的 `/tmp/cyberstrike-*`、测试容器、网络、临时卷和无用构建缓存。
- [x] 检查现有运行容器不引用将被删除的镜像；旧镜像因新 digest 尚未通过而主动保留。
- [x] 运行 Go 全包、race、vet、前端和发布脚本测试。
- [x] 核对仓库只包含预期修改，不包含凭据、SBOM 大文件和本地数据。
- [ ] 提交并推送 `codex/docker-agent-runtime`。

门禁：清理后系统仍可用，工作树干净，远程分支包含已验收提交。

## 6. 详细验收流程

### A. 源码与输入门禁

1. 记录 Git 分支、40 位提交 SHA 和工作树状态。
2. 计算 Dockerfile、锁定文件、inventory entries 和验收脚本 SHA-256。
3. 自动解析 `tools/*.yaml`，断言 enabled 工具名集与验收 manifest 完全相等，报告缺失、多余和重复项。
4. 检查所有外部下载均有锁定版本和 SHA-256，未出现 PAT、Cookie、管理员密码或代理凭据。

通过标准：输入可重现，工具范围与实时 YAML 一致，没有未锁定的网络安装步骤。

### B. 镜像元数据与架构门禁

1. 检查 OCI `source`、`revision`、`version`、`created`、`licenses` 和基础镜像 digest 标签。
2. 检查非 root 用户 `pentester`、工作目录 `/workspace` 和稳定入口。
3. 检查 Hub manifest 精确包含 `linux/arm64` 和 `linux/amd64`，无额外未审查平台。
4. 按平台记录 image ID、platform manifest digest、多架构 index digest 和大小。

通过标准：每个 digest 都能回溯到本次 Git SHA 和锁定输入。

### C. 镜像安全基线门禁

在 `--network none --read-only --cap-drop ALL --security-opt no-new-privileges` 下检查：

- 默认 UID 不是 0，用户名是 `pentester`。
- 没有免密 sudo，没有 Docker Socket，没有构建时私钥或公开测试 CA 私钥。
- rootfs 不可写，仅 `/tmp`、`/run`和 `/workspace` 按运行时约定可写。
- 容器不使用 privileged、host network、host PID/IPC 或宿主机 bind mount。
- 长期运行用户没有有效 capabilities；仅受信的 root exec 边界获得闭集 capabilities。

通过标准：现有 `smoke-container-images.sh` 和新工具验收脚本均返回 0。

### D. 工具完整性门禁

分三层验收：

1. **结构层**：inventory 中每个绝对路径存在且可执行，工具名唯一。
2. **加载层**：Python/Ruby/Java/Node 工具所需模块可导入，包装脚本的真实子命令可找到。
3. **功能层**：执行无破坏的 `--version`/`--help`/内建自检；对 nmap、masscan、arp-scan、tcpdump、gdb 在隔离授权靶场中校验需要的 capability 和基本功能。

特殊映射必须显式验收：

| YAML 名称 | 实际依赖 |
| --- | --- |
| `api-schema-analyzer` | `spectral` |
| `bloodhound` | `bloodhound-python` |
| `ghidra` | `analyzeHeadless` |
| `graphql-scanner` | `graphqlmap` |
| `jwt-analyzer` | `jwt_tool` |
| `metasploit` | `msfconsole` |
| `one-gadget` | `one_gadget` |
| `radare2` | `r2` |
| `ropgadget` | `ROPgadget` |
| `scout-suite` | `scout` |

通过标准：配置覆盖比对 77/77；AMD64 声明可用 77/77；当前 ARM64 声明
可用 75/77，显式跳过 `pwninit`、`x8`；各平台结构和加载探针无失败，
功能探针无未解释失败。

### E. 容器运行时门禁

1. 后台初始化从 queued 到 created/ready，刷新页面不丢状态。
2. 容器启动后工作区前立即显示正确状态，无需手动刷新。
3. 工具调用返回 `execution_location=container`，容器 ID 与该对话绑定一致。
4. 停止后再执行可安全恢复；启动失败不回退宿主机。
5. 临时与持久工作区的重启/删除语义符合 UI 说明。
6. 交互式终端可执行命令、resize、关闭和重连，已停止容器只显示目录信息。

通过标准：新建对话全程只在指定 Agent 镜像中执行，无跨对话泄漏。

### F. 网络、边界与审计门禁

仅对明确授权的自有靶场执行：

1. 无绑定边界时，按产品当前的“不设边界=允许访问”语义测试 HTTP/HTTPS/TCP/UDP。
2. 绑定 allow 规则时，目标、端口、协议和可选 HTTP 方法命中后允许。
3. 绑定 block 规则时，Agent 收到明确的双语阻断原因，请求未发送到目标。
4. 验证 DNS `A`、`AAAA`、`NS`、`MX`、`TXT`、`SRV` 的转发和策略判定。
5. 验证 HTTP/HTTPS 完整报文审计，以及 TCP/UDP 连接元数据审计。
6. 验证对话筛选、类型筛选、暂停显示、跟随最新、审计关闭和指定事件删除。
7. 模拟 fuzz 大量流量，审计关闭时不持久化数据包，页面不因历史事件量卡死。

通过标准：规则判定、Agent 错误、实际网络结果和审计事件四者一致。

### G. UI 门禁

1. 必须在内置浏览器新开页面，使用新验收查询参数，避免复用旧页面的超时会话。
2. 验收对话页的容器状态、工作区、启动耗时、交互式终端与无刷新更新。
3. 验收对话容器页的策略切换、目录信息、侧边终端和可拖动 resize。
4. 验收边界策略列表、搜索、分页、查看使用关系、编辑、删除和悬浮新建窗口。
5. 验收网络活动和出站审计在 500 条及更多事件下仍可滚动、筛选和查看完整报文。
6. 检查浅色/深色、主要桌面分辨率、滚动锁定、焦点、对齐、溢出和浏览器 console。

通过标准：关键交互可完成，无卡死、闪动、裁切、错位或 console 错误。

### H. 回滚演练门禁

1. 保留旧 repository/digest/inventory 和配置备份。
2. 停止专用验收对话，恢复旧配置。
3. 重启服务并新建一个回滚对话，检查旧镜像 readiness 和命令执行。
4. 再切回新 digest，确认双向切换无数据损失。

通过标准：回滚路径已实际执行，不是仅保存文本命令。

## 7. 发布证据与验收记录

证据不提交到 Git，保存在虚拟机本次发布目录，验收完成后按用户的临时文件清理要求删除。至少包含：

```text
release-evidence/
  source-inputs.json
  build-metadata.json
  images.json
  agent-image-arm64.json
  agent-image-amd64.json
  agent-sbom-arm64.spdx.json
  agent-sbom-amd64.spdx.json
  agent-tool-inventory-linux-arm64.json
  agent-tool-inventory-linux-amd64.json
  tool-probes-arm64.json
  tool-probes-amd64.json
  runtime-acceptance.json
  ui-acceptance.md
  SHA256SUMS
```

实施过程在下表中留下摘要，不记录密码、PAT、Cookie 或完整凭据报文。

| 阶段 | 结果 | 证据/摘要 | 日期 |
| --- | --- | --- | --- |
| 0. 加载链路和范围 | 通过 | YAML → MCP → backend → digest/inventory 链路已核对 | 2026-08-25 |
| 1. 镜像实现 | 源码通过 | 77/77 配置覆盖；ARM64 75/77、AMD64 77/77；Amass wrapper 与稳定 PATH 修复已进入源码 | 2026-08-25 |
| 2. ARM64 拉取/镜像内验收 | 通过 | 新 Hub digest 的安全基线、全工具功能和无网络冒烟通过；`amass` 命中 `/usr/local/bin/amass`，版本 `v5.1.1` | 2026-08-25 |
| 3. AMD64/多架构 | 部分通过 | 双平台 index 已回读；AMD64 77/77 映射，按用户要求不做 AMD64 实机运行验收 | 2026-08-25 |
| 4. Docker Hub | 通过 | `latest` 指向 index `sha256:14bed420…38111d`，OCI revision 为干净提交 `21b1ca30dfda14092a52225a0e1f2ef09572de76` | 2026-08-26 |
| 5. 系统切换 | 通过 | VM 配置、inventory、systemd/HTTP、新建对话实际镜像、ARM64、`pentester`、只读根文件系统和容器安全参数均通过；旧 Agent 镜像仅因仍被现存对话容器引用而保留 | 2026-08-26 |
| 6. 端到端功能 | 部分通过 | 容器初始化、状态/工作区、停止恢复、HTTP、TCP/UDP 混合放行与立即阻断、默认开放策略、按对话持久审计及完整性校验通过；内置浏览器可连接，但新建页面在导航前超时，交互终端和页面 UI 未验收 | 2026-08-26 |
| 7. 清理、提交和推送 | 通过 | QA 对话、策略、审计、候选/旧 Egress 镜像及本轮临时文件已精准清理；Go 全包、vet、tidy、174 项前端测试和 diff 门禁通过；ARM64 禁网 SPDX（Agent 859 包、Egress 112 包）及 SHA256 回读通过；旧 Agent 镜像因仍被现存容器引用而保留 | 2026-08-26 |

## 8. 停止条件

任何一项发生时立即停止发布或切换：

- 启用工具与验收 manifest 不一致。
- 任何外部制品无锁定版本/SHA-256 或来源不明。
- 镜像存在凭据、私钥、Docker Socket、免密 sudo 或过宽 capability。
- ARM64 声明支持的工具探针未全部通过，或平台排除项与锁文件不一致。
- Hub digest 回读与本地候选不一致。
- 系统在新配置下出现启动循环、镜像/inventory 不一致或宿主机回退。
- 没有可验证的回滚配置或旧镜像已被提前删除。
- 用于上传的 Docker Hub 命名空间或登录状态未确认。

## 9. 当前下一步

1. 浏览器连接恢复后，用内置浏览器新建页面验收容器状态、工作区、交互式终端、审计筛选和页面 console；当前创建/导航在取得 DOM 前超时，不得记为通过。
2. 在页面 UI 中复验完整 HTTP/HTTPS 审计报文和审计关闭开关；后端的默认允许、显式阻断、TCP/UDP、DNS 和按对话审计链已通过。
3. 现存对话容器删除或切换到新 digest 后，再删除其仍引用的旧 Agent 镜像；不得为释放空间强制破坏运行中/已停止的用户容器。
