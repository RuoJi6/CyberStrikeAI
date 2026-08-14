# ASM 平台能力与适配基线

> 文档版本：2.9
> 基线日期：2026-08-14
> 适用范围：CyberStrikeAI 内置 ARL、XingRin、ScopeSentry 适配器
> 维护原则：上游版本、API 或任务参数变化时，先更新本文，再调整 MCP schema、适配器与界面。

本文回答两个不同的问题：平台本身能做什么，以及 CyberStrikeAI 当前已经允许 Agent 做什么。表格中的“上游能力”不等于“当前 MCP 已支持”。

## 1. 状态说明

| 标记 | 含义 |
| --- | --- |
| 上游 | 对应平台在本文固定版本中提供的能力 |
| 已适配 | CyberStrikeAI 当前适配器及 MCP 已完整映射 |
| 部分适配 | 能调用平台，但只开放部分阶段或参数 |
| 待适配 | 上游存在，当前尚未通过统一 MCP 暴露 |

## 2. 可复现版本基线

| 平台 | 上游仓库 | 固定版本 | 发布日期 | tag commit | 说明 |
| --- | --- | --- | --- | --- | --- |
| ARL / 灯塔 | [Aabyss-Team/ARL](https://github.com/Aabyss-Team/ARL) | [2.6.3](https://github.com/Aabyss-Team/ARL/releases/tag/2.6.3) | 2025-03-04 | `89a5d010e8260020c7db55cec53ed977b6315452` | 原仓库已删除；本文以该维护备份的 2.6.3 tag 为基线 |
| XingRin / 星环 | [yyhuni/xingrin](https://github.com/yyhuni/xingrin) | [v1.5.8](https://github.com/yyhuni/xingrin/releases/tag/v1.5.8) | 2026-01-11 | `bd1dd2c0d5eb5f127dc9067b2aa114af2e91748e` | 采用最新稳定 release，不以 `-dev` tag 作为生产基线 |
| ScopeSentry | [Autumn-27/ScopeSentry](https://github.com/Autumn-27/ScopeSentry) | [v1.9.3](https://github.com/Autumn-27/ScopeSentry/releases/tag/v1.9.3) | 2026-07-26 | `a7f1aedf4c9a93b1eaf0ab9a8c3e9bc6b8c2d44c` | 本文按 v1.9.3 README、任务模板和 API 行为核对 |

## 3. CyberStrikeAI 统一 MCP 动作

Agent 当前看到的是以下 11 个内置工具，而不是直接看到三套平台的全部 API：

| MCP 工具 | 动作 | 是否改变远端状态 |
| --- | --- | --- |
| `asm_list_resources` | 列出已启用的 ASM、类型、连接状态与能力 | 否 |
| `asm_test_connection` | 验证地址与凭据并更新连接状态 | 仅更新本地连接状态 |
| `asm_get_task_profile` | 读取平台版本、任务模式、字段、默认值和依赖 | 否 |
| `asm_list_task_options` | 实时查询单类策略、引擎、字典、节点、模板、插件、POC 和弱口令插件；`kind=template_presets` 读取本地内置预设；`kind=all` 聚合所有列表型类别 | 否 |
| `asm_create_template` | 按 `preset_id` 创建或校准 ARL 策略、ScopeSentry 模板；两者均支持平台原生的受控自定义参数 | 是 |
| `asm_create_task` | 向指定资源创建扫描/资产发现任务 | 是 |
| `asm_list_tasks` | 按任务 ID、名称、目标、状态分页查询任务 | 否 |
| `asm_get_task` | 读取单个任务的进度、阶段、统计与配置 | 否 |
| `asm_list_assets` | 按平台结果类型分页读取 CyberStrikeAI 本地快照；先从 profile 的 `result_types` 获取合法类型 | 否 |
| `asm_stop_task` | 停止指定远端任务 | 是 |
| `asm_manage_task` | 重跑、恢复、删除或结果同步 | 是 |

调用链为：`asm_list_resources` 取得 `resource_id` → `asm_get_task_profile` 读取平台差异 → 必要时用 `asm_list_task_options` 获取实时 ID/名称或内置预设 → ARL/ScopeSentry 可选调用 `asm_create_template` 创建策略/模板 → 按用户已授权的目标调用 `asm_create_task`。平台地址和凭据保留在服务端，不进入模型上下文。

`asm_list_task_options(kind=all)` 表示一次查询该资源声明的所有列表型动态选项，不表示扫描全部目标，也不表示无分页获取全部记录。`page` 和 `page_size` 会分别应用到每个类别（默认每类第 1 页 20 条）；`policy_detail`、`template_detail` 等需要具体 `id` 的详情类别会跳过并返回原因，个别类别失败时会返回 `partial=true` 和分类错误，其余成功结果仍可使用。

### 3.1 CyberStrikeAI 内置分级模板

ASM 资源页和 MCP 共用同一份服务端预设，不在浏览器或 Agent 提示词中复制参数。`template_presets` 只从本地代码读取摘要；仅在调用 `asm_create_template` 时向上游创建对应的 ARL 策略或 ScopeSentry 任务模板。

`template_presets` 的每个条目会按当前资源返回 `provider`、`provider_kind`、`provider_config` 和 `mcp_usage`：ARL 返回真实策略字段（端口档位、字典、功能开关、POC/弱口令选择与并发参数），ScopeSentry 返回端口表达式、并发及启用的插件能力，不再用一份通用摘要代替平台差异。ASM 资源页的“查看具体配置”直接展示同一份结构化数据；上游已创建策略/模板另通过 `policy_detail` 或 `template_detail` 实时回读。

| `preset_id` | 等级 | 主要用途 | ARL 端口范围 | ScopeSentry 端口范围 |
| --- | --- | --- | --- | --- |
| `quick_discovery` | 低 | 常见端口、服务指纹、站点与 TLS 快速存活探测 | TOP100 | 常见服务端口集 |
| `information_collection` | 中 | 子域、扩展端口、站点截图、URL 和爬虫，不主动执行漏洞 POC | TOP1000 | `1-10000` |
| `vulnerability_assessment` | 中高 | 在资产识别基础上进行文件泄露与默认漏洞检测；ARL 选择全部已安装 POC | TOP1000 | `1-10000` |
| `full_scan` | 高 | 大字典子域、全端口、站点/爬虫/敏感信息、漏洞 POC；ARL 另启用全部弱口令插件 | 全端口 | `1-65535` |

内置名称固定为 `CyberStrikeAI · <预设名>`。重复创建会精确查找已有上游记录并按当前预设校准，而不是盲目复用旧配置；因此升级预设后无需删除旧策略。ARL 的漏洞巡检实时分页读取 `plugin_type=poc` 并写入全部已安装 POC，全量扫描还读取 `plugin_type=brute` 并写入全部弱口令插件；上游未返回相应插件时创建会失败，不会生成名不副实的策略。预设不接受任务级覆盖。创建操作不再额外弹出漏洞扫描确认框；ScopeSentry 基模板若未启用预设声明的插件能力，适配器会从上游已安装插件中自动补入其哈希与上游默认参数并回读验证。能力判断同时核对模块和具体插件：例如 `sensitive_scan` 必须启用 `URLSecurity/sensitive`，不能由同模块的 `trufflehog` 冒充。v1.9.3 默认插件库没有 `PassiveScan` 实现，因此内置“全量扫描”不声明该空模块；若其他必需模块确实未安装，创建会返回明确的缺失能力清单，不会降级为名不副实的模板。XingRin 无原生模板创建 API，因此不暴露该功能。

## 4. 上游能力矩阵

| 动作/能力 | ARL 2.6.3 | XingRin v1.5.8 | ScopeSentry v1.9.3 |
| --- | --- | --- | --- |
| 子域名发现/爆破 | 支持：域名爆破、DNS 查询插件、搜索引擎 | 支持：Subfinder、Amass、PureDNS | 支持：子域名枚举插件 |
| 子域名接管检测 | 未作为独立模块声明 | 未作为核心阶段声明 | 支持 |
| IP/CIDR 与端口扫描 | 支持 | 支持：Naabu | 支持：端口扫描插件 |
| 服务/操作系统识别 | 支持 | 通过端口与站点阶段产出 | 支持：端口指纹与资产识别 |
| 站点发现与 Web 指纹 | 支持 | 支持：HTTPX、XingFinger | 支持：资产识别、自定义 Web 指纹 |
| 页面截图 | 支持 | 支持：Playwright | 可由资产映射/插件配置提供 |
| URL 收集与爬虫 | 支持站点爬虫 | 支持：Waymore、Katana | 支持 URL 提取和 Web 爬虫 |
| 目录扫描 | 未作为独立任务阶段声明 | 支持：FFUF | 支持 |
| 漏洞/POC 扫描 | 支持 Nuclei | 支持：Nuclei、Dalfox | 支持漏洞插件与 POC 导入 |
| 文件/敏感信息泄露 | 支持文件泄露与 WebInfoHunter | 可通过扫描阶段扩展 | 支持敏感信息泄露检测 |
| 虚拟主机碰撞 | 支持 | 未作为核心阶段声明 | 可通过插件扩展 |
| 资产搜索、分组、导出 | 支持资产组与搜索 | 支持全局表达式搜索、快照/差异、导出 | 支持资产分组 |
| 定时/监控任务 | 定时任务、GitHub/域名/IP/站点变化监控 | Cron 定时扫描、通知 | 页面监控、Webhook |
| 多节点/分布式执行 | 未作为该版本核心能力声明 | 支持 Worker 与负载调度 | 支持多节点扫描 |
| 弱口令爆破 | 策略 `brute_config` 选择已安装插件；直接任务另有 `service_brute` 开关 | 未作为核心阶段声明 | **v1.9.3 README 仍列为 TODO，不能标记为支持** |

## 5. 创建任务时可选择的动作

### 5.1 ARL 2.6.3

ARL 有两条实际上游请求路径，未知字段和类型错误会被适配器拒绝：

- `task_mode=direct`：调用 `/api/task/`，支持下表直接任务开关。`port_scan_type` 为 `test|top100|top1000|all`。
- `task_mode=policy`：调用 `/api/task/policy/`，必须提供从 `policies` 实时查询的 `policy_id`；可选 `task_tag=task|risk_cruising` 和 `result_set_id`。
- ASM 任务中心与 MCP 使用相同语义：界面的“直接自定义扫描”提交 `task_mode=direct`，“使用策略模板”提交 `task_mode=policy + policy_id`；切换模式时不会把另一模式的字段混入请求。
- `asm_create_template`：在 ARL 中表示创建“策略”，新建使用 `/api/policy/add/`，同名内置策略校准使用 `/api/policy/edit/`；自定义字段由 `asm_get_task_profile.template_create_options` 声明，指定端口使用 `port_scan_type=custom + port_custom`，并发使用 `port_parallelism`，不能混用 ScopeSentry 的 `ports/concurrency/enabled_capabilities`。
- 创建或校准 ARL 策略后会立即从 `/api/policy/` 回读实际配置，响应的 `effective_policy` 是最终依据；只有请求字段与回读一致时才返回 `template_verified=true`。Agent 不得在字段错误时通过删除用户要求的选项静默降级。
- 自定义端口、排除端口、宿主超时、端口并发/速率、POC 和弱口令字典属于策略本身；policy 任务 API 不接受任务级覆盖，因此 MCP 不会伪装成可直接传入。
- `asm_list_task_options(kind=pocs)` 只读取 `plugin_type=poc`，`kind=brute_plugins` 只读取 `plugin_type=brute`。漏洞巡检选择全部实时 POC；全量扫描同时选择全部实时 POC 与弱口令插件，并在响应 `plugin_summary` 中返回实际数量。

| 分组 | options 字段 | 默认值 | 用途 |
| --- | --- | --- | --- |
| 域名 | `domain_brute`, `domain_brute_type`, `alt_dns`, `dns_query_plugin`, `search_engines` | 关闭；类型为 `test` | 子域爆破、智能字典、DNS 插件、搜索引擎 |
| 端口与服务 | `port_scan`, `port_scan_type`, `service_detection`, `service_brute`, `os_detection`, `skip_scan_cdn_ip` | 扫描关闭；跳过 CDN IP 开启 | 端口、服务、弱口令、OS 识别 |
| Web | `site_identify`, `site_capture`, `site_spider`, `file_leak`, `findvhost` | 仅站点识别开启 | 站点识别、截图、爬虫、泄露、vhost 碰撞 |
| 关联数据 | `arl_search`, `ssl_cert` | 关闭 | ARL 历史资产与证书关联 |
| 漏洞 | `nuclei_scan`, `web_info_hunter` | 关闭 | Nuclei 与 WebInfoHunter |

### 5.2 XingRin v1.5.8

上游完整流水线包含子域、端口、站点、指纹、URL、目录、漏洞和截图。CyberStrikeAI 已使用类型化字段生成受控 YAML：

| options 字段 | 默认值 | 当前映射 |
| --- | --- | --- |
| `port_scan` | `true` | Naabu 主动端口扫描 |
| `site_identify` | `true` | HTTPX 站点发现 + XingFinger 指纹 |
| `site_capture` | `false` | Playwright 截图；开启时自动启用站点发现 |
| `nuclei_scan` | `false` | Nuclei，仅 medium/high/critical 和 CVE 标签；开启时自动启用站点发现 |
| `ports` | `80,443,8080,8083` | 端口或端口范围，逗号分隔 |
| `rate_limit` | `20` | 1–1000 |
| `concurrency` | `5` | 1–200 |

额外已映射：子域发现/爆破/变异/DNS 验证、子域字典、被动端口、Top N 端口、指纹库、目录扫描与字典、URL 收集与深度、截图来源、Nuclei 模板仓库/等级/标签、Dalfox、请求超时和 `engine_ids`。引擎、Worker、字典和 Nuclei 仓库可实时查询；引擎列表只返回 ID/名称摘要，传入引擎 `id` 时才返回完整 YAML。多个目标会按换行、逗号或空白拆分，上游为每个目标生成独立扫描 ID；CyberStrikeAI 会遍历全部 `response.scans[]`、为每个远程扫描落库，并用统一 `batch_id` 保留同次 MCP 下发关系。任意原始 YAML 不对 Agent 开放。

### 5.3 ScopeSentry v1.9.3

上游任务模板含 `TargetHandler`、`SubdomainScan`、`SubdomainSecurity`、`PortScanPreparation`、`PortScan`、`PortFingerprint`、`AssetMapping`、`AssetHandle`、`URLScan`、`WebCrawler`、`URLSecurity`、`DirScan`、`VulnerabilityScan`、`PassiveScan`。

当前有两种创建方式：提供 `template_id` 时完整复用上游模板，因而支持其中已配置的端口/文件字典、插件、POC 和全部模块；未提供时则按端口、并发、截图与 TLS 设置的配置指纹生成独立 `CyberStrikeAI low-load <fingerprint>` 模板，避免不同任务互相覆盖：

| options 字段 | 默认值 | 当前映射 |
| --- | --- | --- |
| `port_scan` | `true` | `PortScan` + `PortFingerprint` |
| `site_identify` | `true` | `AssetMapping`；`AssetHandle` 始终保留 |
| `ports` | `80,443,8080,8082` | 端口或端口范围，逗号分隔 |
| `concurrency` | `20` | 1–200 |
| `site_capture` | `false` | 低负载模板的截图开关 |
| `tls_probe` | `false` | 低负载模板的 TLS 探测开关 |

已映射节点/全节点、排除目标、去重、目标来源、项目筛选、资产查询表达式/结构化过滤、定时任务和恢复/重跑/删除。定时创建后会通过 `/api/task/scheduled` 回查远端 ID，因此可进入 ASM 任务中心，并可通过 `/api/task/scheduled/detail` 同步；定时记录是调度定义，不能使用普通 `stop/resume/restart`，仅允许用户明确要求时调用 `delete`。POC 使用 `/api/poc` 实时搜索和分页；模板、端口字典、插件和 POC 列表只返回轻量摘要，避免大量配置或 1 万以上 POC 挤占 Agent 上下文。插件命令行必须先在上游模板审核，不允许 Agent 临时传入。ScopeSentry 的弱口令爆破不能提供为任务类型，因为 v1.9.3 上游仍未实现该能力。

使用上游 `template_id` 时实行创建前强制校验：Agent 必须单独调用 `asm_list_task_options(kind=template_detail,id=...)`，读取可机读的 `capability_summary` 和 `verification_token`，创建时传回 `template_verification_token`。用户要求全端口时必须传 `required_port_scope=all`；用户指定的子域、端口、指纹、截图、URL、爬虫、敏感信息、目录、漏洞等能力必须通过 `required_capabilities` 逐项声明。MCP 会重新读取上游模板，校验令牌、端口和能力后才创建；成功响应的 `effective_template` 回显实际生效配置。模板名称、任务名称和 POC 库总数均不能作为“全功能”证据。

`asm_create_template` 与 ASM 任务中心使用同一后端能力：选择 `base_template_id`，按需启用 `enabled_capabilities`，并可修改 `ports`、`concurrency`、`site_capture`、`tls_probe` 和 `poc_ids`。`asm_get_task_profile` 实时返回 `available_template_capabilities` 和 `unavailable_template_capabilities`；界面仅禁用上游确实未安装的能力，已安装但基模板未启用的能力仍可选择。适配器优先复用基模板插件，缺少所选能力时自动合并上游已安装的系统插件及其默认参数，但仍不允许提交任意命令行。创建响应会返回新 `template_id`、插件级 `capability_summary`、自动补入的插件摘要和 `verification_token`，任务中心在同一次提交中立即用它下发任务。

## 6. 当前适配范围与差距

| 平台 | 连接与任务 | 结果读取 | 当前结论 |
| --- | --- | --- | --- |
| ARL | direct/policy 创建、内置分级策略创建/复用、策略/POC/资产范围选项、查询、详情、停止、重跑、删除、同步 | site/domain/ip/cert/service/fileleak/url/vulnerability/npoc_service/cip/nuclei_result/stat_finger/wih | 已适配上游任务详情页 13 类结果；自定义端口等高级字段按上游规则归属策略 |
| XingRin | 子域、端口、站点、指纹、目录、URL、截图、Nuclei/Dalfox；引擎/字典/模板仓库实时选择 | site/domain/ip/url/service/directory/vulnerability/screenshot，可按任务限定 | 已适配扫描快照中的目录、漏洞与原生截图；截图二进制由 CyberStrikeAI 自动认证拉取并本地缓存；不开放任意 YAML |
| ScopeSentry | 低负载生成模板、内置分级模板或完整上游模板；节点、项目、字典、插件、POC、定时与生命周期动作 | site/domain/ip/url/service/crawler/sensitive/directory/takeover/vulnerability，可按任务限定 | 已适配爬虫、敏感信息、目录、子域接管和漏洞列表；漏洞请求/响应通过上游详情接口按需读取；不开放任意插件命令行 |

统一 `asm_create_task` schema 是三套平台字段的并集，三个适配器现在都会严格拒绝未知选项和错误类型。Agent 必须以 provider-specific profile 为准，避免“字段看似可选但被平台忽略”。

## 7. 当前适配器依赖的 API

这些是 CyberStrikeAI 代码实际调用的路径；升级上游时必须做兼容性核对。

| 平台 | 认证/连通性 | 任务 | 资产 |
| --- | --- | --- | --- |
| ARL | `POST /api/user/login`, `GET /api/console/info` | `/api/task/`, `/api/task/policy/`, `/api/task/stop/:id`, `/api/task/restart/`, `/api/task/delete/`, `/api/task/sync/`; `/api/policy/`, `/api/policy/add/`, `/api/poc/`, `/api/asset_scope/` | `/api/site/`, `/api/domain/`, `/api/ip/`, `/api/cert/`, `/api/service/`, `/api/fileleak/`, `/api/url/`, `/api/vuln/`, `/api/npoc_service/`, `/api/cip/`, `/api/nuclei_result/`, `/api/stat_finger/`, `/api/wih/` |
| XingRin | `POST /api/auth/login/`, `GET /api/auth/me/` | `/api/scans/quick/`, `/api/scans/`, `/api/scans/:id/`, `/api/scans/:id/stop/`; `/api/engines/`, `/api/workers/`, `/api/wordlists/`, `/api/nuclei/repos/` | `/api/assets/:type/`, `/api/scans/:id/:type/` |
| ScopeSentry | `POST /api/user/login`, `GET /api/node/online` | `/api/task/template*`, `/api/task/add`, `/api/task/scheduled/add`, `/api/task/scheduled`, `/api/task/scheduled/detail`, `/api/task/scheduled/delete`, `/api/task/`, `/api/task/detail`, `/api/task/stop`, `/api/task/start`, `/api/task/retest`, `/api/task/delete`; `/api/dictionary/*`, `/api/plugin`, `/api/poc`, `/api/project/all` | `/api/assets/asset`, `/api/assets/subdomain`, `/api/assets/ip`, `/api/assets/url`, `/api/assets/crawler`, `/api/assets/sensitive`, `/api/assets/dirscan`, `/api/assets/subdomain/taker`, `/api/assets/vulnerability`, `/api/assets/vulnerability/detail` |

任务中心不再把三套平台结果塞入固定列：每种结果使用平台字段模型生成摘要卡片，完整字段可展开，漏洞显示级别、来源、目标、证据及请求/响应。任务完成后，后台 worker 会顺序遍历 profile 中的所有 `result_types` 和所有上游分页，按“任务 + 结果类型 + 单条记录”写入本地数据库；ScopeSentry 漏洞独立详情也在此阶段合并缓存。任务中心和 `asm_list_assets` 后续都使用本地分页、搜索与详情，不在每次查看时重复请求上游。

上游仅在以下场景请求：运行中任务的周期性进度同步、检测到完成后的首次全量结果同步、本地缺少某结果类型时 MCP 的首次兜底同步，以及用户显式点击“重新同步结果”或调用 `asm_manage_task(action=sync_results)`。任务中心分开显示“扫描进度”和“结果本地化进度”，包含已同步类型数、本地记录数、当前类型、最后时间和错误。

ASM 任务中心通过独立的“Agent 联动设置”按钮按资源配置扫描完成动作，默认在全部关联子任务完成且结果、截图本地化结束后，恢复创建扫描任务的对话。设置窗口分别保存“Agent 当时仍在运行”和“Agent 已停止”两套可编辑提示词；如果用户主动点击停止来源对话，则对应待处理联动会持久化为 `user_stopped`，即使扫描之后完成也不会重新启动 Agent。该策略不属于扫描参数，任务中心手工下发不会绑定当前聊天，Agent 也不能通过 `asm_create_task` 在单次任务中覆盖用户设置。MCP 创建任务以及通过 `asm_manage_task` 重跑或恢复已有任务时，系统自动绑定当前 MCP 对话。`asm_list_resources`、`asm_create_task` 和 `asm_manage_task` 的 MCP 描述会明确告知 Agent 当前已有资源级联动；创建、重跑或恢复响应也返回 `agent_continuation.wait_strategy` 与操作说明。任务开始后 Agent 不应调用 `sleep` 或循环轮询，只有用户明确要求即时查看进度时才进行一次有界状态查询。XingRin 多目标下发只创建一条批次联动，必须等全部远程子任务及本地结果同步完成才触发。联动状态持久化在本地数据库，服务重启后可恢复；权限按原任务所属用户重新校验，未关联对话的任务不会自动新建 Agent 对话。

截图二进制也由同步流程自动认证拉取到 CyberStrikeAI，无需人工点击缓存；界面将截图放在对应站点记录旁边，同时保留“已缓存截图”总览。

ASM 任务中心也复用同一 provider profile：手动创建时先读取 `create_options`，再从上游动态加载 ARL 策略、XingRin 引擎/字典以及 ScopeSentry 模板/节点/项目。ScopeSentry 模板在界面选中后会自动读取 `template_detail`、显示实际能力并携带校验令牌。任务详情可直接调用上游停止动作；ScopeSentry 即时任务可后续恢复，ARL 需重跑，XingRin 停止后需新建任务。

XingRin 截图只在 `site_capture=true` 或选中的上游引擎包含 screenshot 阶段时产生。任务中心会优先从本地 `screenshot` 结果记录发现图片路径，仅对未缓存的图片进行认证下载，不会为寻找截图重复拉取整份上游结果列表。

## 8. 真实 MCP 调用验证

2026-08-12 使用 CyberStrikeAI 相同的 MCP 注册、权限策略、资源数据库和加密凭据，在已授权的公司 IP 上依次验证：

| 平台 | 任务 | 实际验证结果 |
| --- | --- | --- |
| ARL 2.6.3 | direct，低负载端口 + 站点识别 | 连接、profile、policy/POC/scope 选项、创建、列表、详情、IP 结果和停止通过；兼容 `response.items[0].task_id` 创建响应 |
| XingRin v1.5.8 | 受控 YAML，仅 80/443，并发 2，漏洞/目录/截图关闭 | 引擎/Worker/字典/Nuclei 仓库、创建、列表、详情、结果和停止通过；本地任务历史已记录 |
| ScopeSentry v1.9.3 | 生成低负载模板，仅 80/443，并发 2，截图/TLS 关闭；另建立不立即执行的定时定义 | 节点/模板/字典/插件/POC/项目、即时创建/列表/详情/结果/停止通过；13,510 个 POC 可实时分页；定时任务远端 ID、本地历史、列表、详情、显式删除均通过 |

上述流程固化为默认跳过的 `TestASMRealMCPFlow`，只在明确设置 `CYBERSTRIKE_ASM_REAL_TEST=1` 且提供资源 ID 时连接真实 ASM。

2026-08-13 另使用 ScopeSentry v1.9.3 完成模板创建专项验证：任务中心成功克隆 `default` 基模板、按结构化字段设置端口与并发并立即完成任务；MCP 的 `asm_create_template` 成功创建独立模板，随后由 `asm_create_task` 使用该模板下发任务，并通过 `asm_get_task` 读取后由 `asm_manage_task` 停止。两条路径均返回经过回读校验的模板 ID、能力摘要和校验令牌。

## 9. 上游升级维护流程

每次准备支持新版本时：

1. 记录稳定 release、发布日期与 tag commit；开发版必须单独标注，不能覆盖稳定基线。
2. 对比该 tag 与本文基线之间的 README、任务 schema、认证方式和第 7 节 API 路径。
3. 更新第 4–6 节能力矩阵；明确区分上游能力、已适配能力和待适配能力。
4. 更新 provider-specific 创建任务 profile、MCP 描述和页面表单；不得静默忽略新旧字段。
5. 运行适配器单元测试、MCP 注册测试和前端导航/表单测试。
6. 在低资源测试环境中一次只启动一个 ASM，依次验证连接、创建、列表、详情、进度、结果、搜索、停止和截图缓存。
7. 将本节下方的文档版本递增，并写明兼容性变化。

## 10. 文档变更记录

| 文档版本 | 日期 | 平台基线 | 变化 |
| --- | --- | --- | --- |
| 2.9 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 用户主动停止来源对话会持久化取消待处理联动；任务历史统一返回并展示 ScopeSentry 模板、ARL 策略或 XingRin 引擎执行配置 |
| 2.8 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | MCP 资源与任务描述显式声明系统托管等待，创建响应返回等待策略，禁止 Agent 以 `sleep` 或循环轮询代替后台联动 |
| 2.7 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | ASM 任务中心新增独立 Agent 联动设置；MCP 任务自动绑定来源对话，结果本地化后按运行/空闲状态使用可编辑提示词恢复，并持久化等待、重试与重启恢复状态 |
| 2.6 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 内置模板按平台返回并展示精确 `provider_config` 与 `mcp_usage`；资源页新增内置及上游模板点击详情，Agent 可据真实 ARL 策略或 ScopeSentry 插件配置选型 |
| 2.5 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | ARL 漏洞巡检实时选择全部 POC，全量扫描同时选择全部 POC 与弱口令插件；同名内置策略可通过 UI/MCP 原位校准，修复旧策略空 `poc_config`/`brute_config` |
| 2.4 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | ScopeSentry 改为插件级能力识别；`sensitive_scan` 精确对应 sensitive；任务面板与 MCP 按实时已安装插件统一可用能力，已安装但基模板未启用的能力可自动补齐 |
| 2.3 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | ScopeSentry 内置模板可从已安装插件库自动补齐基模板未启用的模块；已有同名预设可原位修复；页面取消漏洞/全量模板创建确认弹窗 |
| 2.2 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | ASM 资源页新增分级模板库和上游模板查看；MCP 新增 `template_presets` 查询及 `preset_id` 幂等创建；ARL 策略与 ScopeSentry 模板共用四级受控预设 |
| 2.1 | 2026-08-13 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 新增 `asm_create_template`，Agent 和任务中心均可克隆 ScopeSentry 基模板、设置受控能力/端口/并发/POC 并立即用新模板下发任务 |
| 2.0 | 2026-08-13 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 任务中心新增 provider-native 手动创建、任务停止/暂停操作，并使 XingRin 截图首次缓存优先复用本地结果索引 |
| 1.9 | 2026-08-13 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | XingRin 多目标创建响应改为全量子任务落库，MCP 返回完整本地/远程 ID 列表，任务中心按 `batch_id` 折叠展示同次下发 |
| 1.8 | 2026-08-13 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | ScopeSentry 模板创建新增详情校验令牌、全端口/能力断言与实际生效配置回显，防止 Agent 仅根据模板名误判“全功能” |
| 1.7 | 2026-08-13 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | `asm_list_task_options` 新增 `kind=all`，按统一分页聚合所有列表型动态选项，跳过需 ID 的详情类型并返回分类错误 |
| 1.6 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 完成后自动全量同步所有结果类型与分页；任务中心与 MCP 改为本地分页/搜索/详情；新增结果同步状态、查看兜底、显式重同步和自动截图缓存 |
| 1.5 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 任务中心改为平台专属完整结果卡片；补齐 XingRin 目录/截图与 ScopeSentry 爬虫/敏感信息/目录/接管/漏洞详情；截图自动缓存；增加上游总数分页和页大小 |
| 1.4 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | profile 暴露平台专属 `result_types`；补齐 ARL 任务详情 13 类结果，任务中心按平台动态展示并分页读取 |
| 1.3 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | ScopeSentry 低负载模板改为配置指纹隔离；定时任务回查 ID、进入任务中心并支持详情/显式删除 |
| 1.2 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 记录三平台真实 MCP 创建/读取/停止测试；增加大型动态选项的分页和摘要化约束 |
| 1.1 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 新增 provider profile/动态选项/管理 MCP；补齐 ARL policy、XingRin 快速扫描阶段和 ScopeSentry 模板/节点/定时能力 |
| 1.0 | 2026-08-11 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 首次建立版本、能力、API 与适配差距基线 |
