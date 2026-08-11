# ASM Platform Capability and Adapter Baseline

> Document version: 1.0
> Baseline date: 2026-08-11
> Scope: CyberStrikeAI built-in adapters for ARL, XingRin, and ScopeSentry

This document separates upstream platform capabilities from actions currently exposed to agents by CyberStrikeAI. Update this baseline before changing MCP schemas, adapters, or UI after an upstream release.

## Reproducible upstream baseline

| Platform | Upstream | Version | Release date | Tag commit | Note |
| --- | --- | --- | --- | --- | --- |
| ARL | [Aabyss-Team/ARL](https://github.com/Aabyss-Team/ARL) | [2.6.3](https://github.com/Aabyss-Team/ARL/releases/tag/2.6.3) | 2025-03-04 | `89a5d010e8260020c7db55cec53ed977b6315452` | Maintained backup used after deletion of the original repository |
| XingRin | [yyhuni/xingrin](https://github.com/yyhuni/xingrin) | [v1.5.8](https://github.com/yyhuni/xingrin/releases/tag/v1.5.8) | 2026-01-11 | `bd1dd2c0d5eb5f127dc9067b2aa114af2e91748e` | Latest stable release; development tags are not the production baseline |
| ScopeSentry | [Autumn-27/ScopeSentry](https://github.com/Autumn-27/ScopeSentry) | [v1.9.3](https://github.com/Autumn-27/ScopeSentry/releases/tag/v1.9.3) | 2026-07-26 | `a7f1aedf4c9a93b1eaf0ab9a8c3e9bc6b8c2d44c` | Verified against v1.9.3 README, task templates, and adapter API behavior |

## Unified MCP actions

Agents currently use seven normalized tools: `asm_list_resources`, `asm_test_connection`, `asm_create_task`, `asm_list_tasks`, `asm_get_task`, `asm_list_assets`, and `asm_stop_task`. An agent first selects a server-side `resource_id`, then creates and observes tasks without receiving the platform credential.

## Upstream action matrix

| Capability | ARL 2.6.3 | XingRin v1.5.8 | ScopeSentry v1.9.3 |
| --- | --- | --- | --- |
| Subdomain discovery | Brute force, DNS plugins, search engines | Subfinder, Amass, PureDNS | Plugin-based enumeration |
| Ports and services | Port, service, OS detection | Naabu plus site stages | Port scan and fingerprint modules |
| Web discovery/fingerprints | Site discovery and fingerprinting | HTTPX and XingFinger | Asset mapping and custom fingerprints |
| URL/crawling/directories | Spider and leak discovery | Waymore, Katana, FFUF | URL, crawler, URL-security, and directory modules |
| Vulnerability scanning | Nuclei and WebInfoHunter | Nuclei and Dalfox | Vulnerability plugins and POC import |
| Screenshots | Supported | Playwright | Available through asset mapping/plugins |
| Scheduling/monitoring | Scheduled tasks and multiple monitors | Cron, snapshots/diffs, notifications | Page monitoring and webhook |
| Distributed execution | Not a declared core feature | Workers and load-aware scheduling | Multi-node scans |
| Weak-password brute force | `service_brute` option | Not a core stage | **Still listed as TODO in v1.9.3** |

## Provider-specific task profile currently implemented

| Provider | Current `asm_create_task.options` mapping | Upstream actions not yet exposed |
| --- | --- | --- |
| ARL | Full adapter mapping for domain, port/service, Web, correlation, and vulnerability switches | Dynamic provider-specific schema/UI |
| XingRin | `port_scan`, `site_identify`, `site_capture`, `nuclei_scan`, `ports`, `rate_limit`, `concurrency` | Subdomain, URL collection, directories, Dalfox, and advanced engine settings |
| ScopeSentry | `port_scan`, `site_identify`, `ports`, `concurrency`; creates/updates `CyberStrikeAI low-load` template | Remaining task-template modules and plugin selection |

ARL rejects unsupported option keys. XingRin and ScopeSentry read only their mapped subset. The current common schema is therefore a superset; future task forms and MCP capability descriptions should expose a provider-specific profile to prevent silently ignored choices.

## API compatibility surface

| Platform | Authentication/connectivity | Tasks | Assets |
| --- | --- | --- | --- |
| ARL | `POST /api/user/login`, `GET /api/console/info` | `/api/task/`, `GET /api/task/stop/:id` | `/api/site/`, `/api/domain/`, `/api/ip/`, `/api/url/`, `/api/service/`, `/api/vuln/` |
| XingRin | `POST /api/auth/login/`, `GET /api/auth/me/`, `GET /api/engines/` | `/api/scans/quick/`, `/api/scans/`, `/api/scans/:id/`, `/api/scans/:id/stop/` | `/api/assets/:type/`, `/api/scans/:id/:type/` |
| ScopeSentry | `POST /api/user/login`, `GET /api/node/online` | `/api/task/template*`, `/api/task/add`, `/api/task/`, `/api/task/detail`, `/api/task/stop` | `/api/assets/asset`, `/api/assets/subdomain`, `/api/assets/ip`, `/api/assets/url`, `/api/assets/vulnerability` |

## Upgrade checklist

1. Record the stable release, date, and tag commit; label development baselines separately.
2. Diff README capability claims, task schemas, authentication, and API paths against this baseline.
3. Update the upstream/current/gap matrix before changing implementation.
4. Update provider-specific task profiles, MCP descriptions, and forms without silently ignoring fields.
5. Run adapter, MCP registration, navigation, and form tests.
6. Start one ASM at a time on the constrained test host and verify connection, create, list, detail, progress, results, search, stop, and screenshot caching.
7. Increment the document version and record compatibility changes.

## Document history

| Version | Date | Platform baseline | Change |
| --- | --- | --- | --- |
| 1.0 | 2026-08-11 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Initial version, capability, API, and adapter-gap baseline |
