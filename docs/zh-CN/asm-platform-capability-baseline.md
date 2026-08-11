# ASM 平台能力与适配基线

> 文档版本：1.0
> 基线日期：2026-08-11
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

Agent 当前看到的是以下 7 个内置工具，而不是直接看到三套平台的全部 API：

| MCP 工具 | 动作 | 是否改变远端状态 |
| --- | --- | --- |
| `asm_list_resources` | 列出已启用的 ASM、类型、连接状态与能力 | 否 |
| `asm_test_connection` | 验证地址与凭据并更新连接状态 | 仅更新本地连接状态 |
| `asm_create_task` | 向指定资源创建扫描/资产发现任务 | 是 |
| `asm_list_tasks` | 按任务 ID、名称、目标、状态分页查询任务 | 否 |
| `asm_get_task` | 读取单个任务的进度、阶段、统计与配置 | 否 |
| `asm_list_assets` | 读取站点、域名、IP、URL、服务或漏洞结果 | 否 |
| `asm_stop_task` | 停止指定远端任务 | 是 |

调用链为：Agent 先调用 `asm_list_resources` 取得 `resource_id`，再按用户已授权的目标调用 `asm_create_task`；任务创建后通过任务、资产与停止工具持续操作。平台地址和凭据保留在服务端，不进入模型上下文。

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

ARL 是当前参数映射最完整的平台。`asm_create_task.options` 可传以下字段，未知字段会被适配器拒绝：

| 分组 | options 字段 | 默认值 | 用途 |
| --- | --- | --- | --- |
| 域名 | `domain_brute`, `domain_brute_type`, `alt_dns`, `dns_query_plugin`, `search_engines` | 关闭；类型为 `test` | 子域爆破、智能字典、DNS 插件、搜索引擎 |
| 端口与服务 | `port_scan`, `port_scan_type`, `service_detection`, `service_brute`, `os_detection`, `skip_scan_cdn_ip` | 扫描关闭；跳过 CDN IP 开启 | 端口、服务、弱口令、OS 识别 |
| Web | `site_identify`, `site_capture`, `site_spider`, `file_leak`, `findvhost` | 仅站点识别开启 | 站点识别、截图、爬虫、泄露、vhost 碰撞 |
| 关联数据 | `arl_search`, `ssl_cert` | 关闭 | ARL 历史资产与证书关联 |
| 漏洞 | `nuclei_scan`, `web_info_hunter` | 关闭 | Nuclei 与 WebInfoHunter |

### 5.2 XingRin v1.5.8

上游完整流水线包含子域、端口、站点、指纹、URL、目录、漏洞和截图。当前 CyberStrikeAI 只生成一个受控的低负载配置：

| options 字段 | 默认值 | 当前映射 |
| --- | --- | --- |
| `port_scan` | `true` | Naabu 主动端口扫描 |
| `site_identify` | `true` | HTTPX 站点发现 + XingFinger 指纹 |
| `site_capture` | `false` | Playwright 截图；开启时自动启用站点发现 |
| `nuclei_scan` | `false` | Nuclei，仅 medium/high/critical 和 CVE 标签；开启时自动启用站点发现 |
| `ports` | `80,443,8080,8083` | 端口或端口范围，逗号分隔 |
| `rate_limit` | `20` | 1–1000 |
| `concurrency` | `5` | 1–200 |

子域、URL 收集、目录扫描和 Dalfox 等上游阶段目前为待适配。任务创建时适配器自动选择可用的全扫描引擎。

### 5.3 ScopeSentry v1.9.3

上游任务模板含 `TargetHandler`、`SubdomainScan`、`SubdomainSecurity`、`PortScanPreparation`、`PortScan`、`PortFingerprint`、`AssetMapping`、`AssetHandle`、`URLScan`、`WebCrawler`、`URLSecurity`、`DirScan`、`VulnerabilityScan`、`PassiveScan`。

当前 CyberStrikeAI 会基于上游默认模板创建或更新专用的 `CyberStrikeAI low-load` 模板，并只保留以下阶段：

| options 字段 | 默认值 | 当前映射 |
| --- | --- | --- |
| `port_scan` | `true` | `PortScan` + `PortFingerprint` |
| `site_identify` | `true` | `AssetMapping`；`AssetHandle` 始终保留 |
| `ports` | `80,443,8080,8082` | 端口或端口范围，逗号分隔 |
| `concurrency` | `20` | 1–200 |

其他模板模块当前会被显式清空，以适配低资源测试机并避免用户未选择的扫描阶段被意外执行。ScopeSentry 的弱口令爆破不能提供为任务类型，因为 v1.9.3 上游仍未实现该能力。

## 6. 当前适配范围与差距

| 平台 | 连接与任务 | 结果读取 | 当前结论 |
| --- | --- | --- | --- |
| ARL | 创建、查询、详情、停止；任务开关完整映射 | site/domain/ip/url/service/vulnerability | 已适配；后续重点是按平台动态展示参数，而非扩充基础 API |
| XingRin | 创建、查询、详情、停止；只映射 7 个低负载参数 | site/domain/ip/url/service/vulnerability，可按任务限定 | 部分适配；上游子域、URL、目录等阶段待开放 |
| ScopeSentry | 创建、查询、详情、停止；只映射低负载模板 | site/domain/ip/url/service/vulnerability，可按任务限定 | 部分适配；完整任务模板与插件选择待开放 |

当前统一 `asm_create_task` schema 是三套平台字段的并集。ARL 会拒绝未知选项；XingRin 与 ScopeSentry 只读取自己的字段。因此后续界面应根据资源的 `provider` 显示不同任务类型和表单，并让 MCP schema/能力描述也返回同一份 provider-specific profile，避免“字段看似可选但被平台忽略”。

## 7. 当前适配器依赖的 API

这些是 CyberStrikeAI 代码实际调用的路径；升级上游时必须做兼容性核对。

| 平台 | 认证/连通性 | 任务 | 资产 |
| --- | --- | --- | --- |
| ARL | `POST /api/user/login`, `GET /api/console/info` | `/api/task/`, `GET /api/task/stop/:id` | `/api/site/`, `/api/domain/`, `/api/ip/`, `/api/url/`, `/api/service/`, `/api/vuln/` |
| XingRin | `POST /api/auth/login/`, `GET /api/auth/me/`, `GET /api/engines/` | `/api/scans/quick/`, `/api/scans/`, `/api/scans/:id/`, `/api/scans/:id/stop/` | `/api/assets/:type/`, `/api/scans/:id/:type/` |
| ScopeSentry | `POST /api/user/login`, `GET /api/node/online` | `/api/task/template*`, `/api/task/add`, `/api/task/`, `/api/task/detail`, `/api/task/stop` | `/api/assets/asset`, `/api/assets/subdomain`, `/api/assets/ip`, `/api/assets/url`, `/api/assets/vulnerability` |

## 8. 上游升级维护流程

每次准备支持新版本时：

1. 记录稳定 release、发布日期与 tag commit；开发版必须单独标注，不能覆盖稳定基线。
2. 对比该 tag 与本文基线之间的 README、任务 schema、认证方式和第 7 节 API 路径。
3. 更新第 4–6 节能力矩阵；明确区分上游能力、已适配能力和待适配能力。
4. 更新 provider-specific 创建任务 profile、MCP 描述和页面表单；不得静默忽略新旧字段。
5. 运行适配器单元测试、MCP 注册测试和前端导航/表单测试。
6. 在低资源测试环境中一次只启动一个 ASM，依次验证连接、创建、列表、详情、进度、结果、搜索、停止和截图缓存。
7. 将本节下方的文档版本递增，并写明兼容性变化。

## 9. 文档变更记录

| 文档版本 | 日期 | 平台基线 | 变化 |
| --- | --- | --- | --- |
| 1.0 | 2026-08-11 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | 首次建立版本、能力、API 与适配差距基线 |
