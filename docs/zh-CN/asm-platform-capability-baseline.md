# ASM 平台能力与适配基线

> 文档版本：1.5
> 基线日期：2026-08-12
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

Agent 当前看到的是以下 10 个内置工具，而不是直接看到三套平台的全部 API：

| MCP 工具 | 动作 | 是否改变远端状态 |
| --- | --- | --- |
| `asm_list_resources` | 列出已启用的 ASM、类型、连接状态与能力 | 否 |
| `asm_test_connection` | 验证地址与凭据并更新连接状态 | 仅更新本地连接状态 |
| `asm_get_task_profile` | 读取平台版本、任务模式、字段、默认值和依赖 | 否 |
| `asm_list_task_options` | 实时查询策略、引擎、字典、节点、模板、插件和 POC | 否 |
| `asm_create_task` | 向指定资源创建扫描/资产发现任务 | 是 |
| `asm_list_tasks` | 按任务 ID、名称、目标、状态分页查询任务 | 否 |
| `asm_get_task` | 读取单个任务的进度、阶段、统计与配置 | 否 |
| `asm_list_assets` | 按平台结果类型分页读取扫描结果；先从 profile 的 `result_types` 获取合法类型 | 否 |
| `asm_stop_task` | 停止指定远端任务 | 是 |
| `asm_manage_task` | 重跑、恢复、删除或结果同步 | 是 |

调用链为：`asm_list_resources` 取得 `resource_id` → `asm_get_task_profile` 读取平台差异 → 必要时用 `asm_list_task_options` 获取实时 ID/名称 → 按用户已授权的目标调用 `asm_create_task`。平台地址和凭据保留在服务端，不进入模型上下文。

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
| 弱口令爆破 | `service_brute` 任务开关 | 未作为核心阶段声明 | **v1.9.3 README 仍列为 TODO，不能标记为支持** |

## 5. 创建任务时可选择的动作

### 5.1 ARL 2.6.3

ARL 有两条实际上游请求路径，未知字段和类型错误会被适配器拒绝：

- `task_mode=direct`：调用 `/api/task/`，支持下表直接任务开关。`port_scan_type` 为 `test|top100|top1000|all`。
- `task_mode=policy`：调用 `/api/task/policy/`，必须提供从 `policies` 实时查询的 `policy_id`；可选 `task_tag=task|risk_cruising` 和 `result_set_id`。
- 自定义端口、排除端口、宿主超时、端口并发/速率、POC 和弱口令字典属于策略本身；policy 任务 API 不接受任务级覆盖，因此 MCP 不会伪装成可直接传入。

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

额外已映射：子域发现/爆破/变异/DNS 验证、子域字典、被动端口、Top N 端口、指纹库、目录扫描与字典、URL 收集与深度、截图来源、Nuclei 模板仓库/等级/标签、Dalfox、请求超时和 `engine_ids`。引擎、Worker、字典和 Nuclei 仓库可实时查询；引擎列表只返回 ID/名称摘要，传入引擎 `id` 时才返回完整 YAML。多个目标会按换行、逗号或空白拆分，任意原始 YAML 不对 Agent 开放。

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

## 6. 当前适配范围与差距

| 平台 | 连接与任务 | 结果读取 | 当前结论 |
| --- | --- | --- | --- |
| ARL | direct/policy 创建、策略/POC/资产范围选项、查询、详情、停止、重跑、删除、同步 | site/domain/ip/cert/service/fileleak/url/vulnerability/npoc_service/cip/nuclei_result/stat_finger/wih | 已适配上游任务详情页 13 类结果；自定义端口等高级字段按上游规则归属策略 |
| XingRin | 子域、端口、站点、指纹、目录、URL、截图、Nuclei/Dalfox；引擎/字典/模板仓库实时选择 | site/domain/ip/url/service/directory/vulnerability/screenshot，可按任务限定 | 已适配扫描快照中的目录、漏洞与原生截图；截图二进制由 CyberStrikeAI 自动认证拉取并本地缓存；不开放任意 YAML |
| ScopeSentry | 低负载生成模板或完整上游模板；节点、项目、字典、插件、POC、定时与生命周期动作 | site/domain/ip/url/service/crawler/sensitive/directory/takeover/vulnerability，可按任务限定 | 已适配爬虫、敏感信息、目录、子域接管和漏洞列表；漏洞请求/响应通过上游详情接口按需读取；不开放任意插件命令行 |

统一 `asm_create_task` schema 是三套平台字段的并集，三个适配器现在都会严格拒绝未知选项和错误类型。Agent 必须以 provider-specific profile 为准，避免“字段看似可选但被平台忽略”。

## 7. 当前适配器依赖的 API

这些是 CyberStrikeAI 代码实际调用的路径；升级上游时必须做兼容性核对。

| 平台 | 认证/连通性 | 任务 | 资产 |
| --- | --- | --- | --- |
| ARL | `POST /api/user/login`, `GET /api/console/info` | `/api/task/`, `/api/task/policy/`, `/api/task/stop/:id`, `/api/task/restart/`, `/api/task/delete/`, `/api/task/sync/`; `/api/policy/`, `/api/poc/`, `/api/asset_scope/` | `/api/site/`, `/api/domain/`, `/api/ip/`, `/api/cert/`, `/api/service/`, `/api/fileleak/`, `/api/url/`, `/api/vuln/`, `/api/npoc_service/`, `/api/cip/`, `/api/nuclei_result/`, `/api/stat_finger/`, `/api/wih/` |
| XingRin | `POST /api/auth/login/`, `GET /api/auth/me/` | `/api/scans/quick/`, `/api/scans/`, `/api/scans/:id/`, `/api/scans/:id/stop/`; `/api/engines/`, `/api/workers/`, `/api/wordlists/`, `/api/nuclei/repos/` | `/api/assets/:type/`, `/api/scans/:id/:type/` |
| ScopeSentry | `POST /api/user/login`, `GET /api/node/online` | `/api/task/template*`, `/api/task/add`, `/api/task/scheduled/add`, `/api/task/scheduled`, `/api/task/scheduled/detail`, `/api/task/scheduled/delete`, `/api/task/`, `/api/task/detail`, `/api/task/stop`, `/api/task/start`, `/api/task/retest`, `/api/task/delete`; `/api/dictionary/*`, `/api/plugin`, `/api/poc`, `/api/project/all` | `/api/assets/asset`, `/api/assets/subdomain`, `/api/assets/ip`, `/api/assets/url`, `/api/assets/crawler`, `/api/assets/sensitive`, `/api/assets/dirscan`, `/api/assets/subdomain/taker`, `/api/assets/vulnerability`, `/api/assets/vulnerability/detail` |

任务中心不再把三套平台结果塞入固定列：每种结果使用平台字段模型生成摘要卡片，完整字段可展开，漏洞显示级别、来源、目标、证据及请求/响应。分页使用上游 `total` 与页码，每页可选 10/20/50/100。截图作为独立结果视图，读取站点/截图结果后自动排队下载到 CyberStrikeAI，不再依赖人工“缓存截图”按钮；Agent 通过 MCP 读取站点或截图结果时同样触发自动缓存。

## 8. 真实 MCP 调用验证

2026-08-12 使用 CyberStrikeAI 相同的 MCP 注册、权限策略、资源数据库和加密凭据，在已授权的公司 IP 上依次验证：

| 平台 | 任务 | 实际验证结果 |
| --- | --- | --- |
| ARL 2.6.3 | direct，低负载端口 + 站点识别 | 连接、profile、policy/POC/scope 选项、创建、列表、详情、IP 结果和停止通过；兼容 `response.items[0].task_id` 创建响应 |
| XingRin v1.5.8 | 受控 YAML，仅 80/443，并发 2，漏洞/目录/截图关闭 | 引擎/Worker/字典/Nuclei 仓库、创建、列表、详情、结果和停止通过；本地任务历史已记录 |
| ScopeSentry v1.9.3 | 生成低负载模板，仅 80/443，并发 2，截图/TLS 关闭；另建立不立即执行的定时定义 | 节点/模板/字典/插件/POC/项目、即时创建/列表/详情/结果/停止通过；13,510 个 POC 可实时分页；定时任务远端 ID、本地历史、列表、详情、显式删除均通过 |

上述流程固化为默认跳过的 `TestASMRealMCPFlow`，只在明确设置 `CYBERSTRIKE_ASM_REAL_TEST=1` 且提供资源 ID 时连接真实 ASM。

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
| 1.5 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 任务中心改为平台专属完整结果卡片；补齐 XingRin 目录/截图与 ScopeSentry 爬虫/敏感信息/目录/接管/漏洞详情；截图自动缓存；增加上游总数分页和页大小 |
| 1.4 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | profile 暴露平台专属 `result_types`；补齐 ARL 任务详情 13 类结果，任务中心按平台动态展示并分页读取 |
| 1.3 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | ScopeSentry 低负载模板改为配置指纹隔离；定时任务回查 ID、进入任务中心并支持详情/显式删除 |
| 1.2 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 记录三平台真实 MCP 创建/读取/停止测试；增加大型动态选项的分页和摘要化约束 |
| 1.1 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 新增 provider profile/动态选项/管理 MCP；补齐 ARL policy、XingRin 快速扫描阶段和 ScopeSentry 模板/节点/定时能力 |
| 1.0 | 2026-08-11 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 首次建立版本、能力、API 与适配差距基线 |
