# ASM Platform Capability and Adapter Baseline

> Document version: 1.5
> Baseline date: 2026-08-12
> Scope: CyberStrikeAI built-in adapters for ARL, XingRin, and ScopeSentry

This document distinguishes upstream platform capabilities from actions currently exposed to agents by CyberStrikeAI. Update it before changing MCP schemas, adapters, or UI after an upstream release.

## Reproducible upstream baseline

| Platform | Upstream | Version | Release date | Tag commit |
| --- | --- | --- | --- | --- |
| ARL | [Aabyss-Team/ARL](https://github.com/Aabyss-Team/ARL) | [2.6.3](https://github.com/Aabyss-Team/ARL/releases/tag/2.6.3) | 2025-03-04 | `89a5d010e8260020c7db55cec53ed977b6315452` |
| XingRin | [yyhuni/xingrin](https://github.com/yyhuni/xingrin) | [v1.5.8](https://github.com/yyhuni/xingrin/releases/tag/v1.5.8) | 2026-01-11 | `bd1dd2c0d5eb5f127dc9067b2aa114af2e91748e` |
| ScopeSentry | [Autumn-27/ScopeSentry](https://github.com/Autumn-27/ScopeSentry) | [v1.9.3](https://github.com/Autumn-27/ScopeSentry/releases/tag/v1.9.3) | 2026-07-26 | `a7f1aedf4c9a93b1eaf0ab9a8c3e9bc6b8c2d44c` |

## Unified MCP actions

Agents use ten normalized tools:

| Tool | Purpose |
| --- | --- |
| `asm_list_resources` | List enabled resources, state, and capabilities |
| `asm_test_connection` | Verify the address and server-side credential |
| `asm_get_task_profile` | Read the provider version, modes, typed fields, defaults, and dependencies |
| `asm_list_task_options` | Query live policies, engines, dictionaries, nodes, templates, plugins, POCs, or projects |
| `asm_create_task` | Create a task for an explicitly authorized target |
| `asm_list_tasks` / `asm_get_task` | Read task lists, progress, stages, statistics, and configuration |
| `asm_list_assets` | Page through a provider-specific result type from the CyberStrikeAI local snapshot; discover valid IDs from profile `result_types` |
| `asm_stop_task` | Stop a remote task |
| `asm_manage_task` | Restart, resume, delete, or synchronize results when supported |

The expected call sequence is `asm_list_resources` -> `asm_get_task_profile` -> optionally `asm_list_task_options` -> `asm_create_task`. Credentials remain on the server and are never placed in model context.

## Upstream action matrix

| Capability | ARL 2.6.3 | XingRin v1.5.8 | ScopeSentry v1.9.3 |
| --- | --- | --- | --- |
| Subdomain discovery | Brute force, DNS plugins, search engines | Subfinder, Amass, PureDNS | Plugin-based enumeration |
| Ports and services | Port, service, OS detection | Naabu plus site stages | Port scan and fingerprint modules |
| Web discovery/fingerprints | Site discovery and fingerprinting | HTTPX and XingFinger | Asset mapping and custom fingerprints |
| URL/crawling/directories | Spider and leak discovery | Waymore, Katana, FFUF | URL, crawler, URL-security, and directory modules |
| Vulnerability scanning | Nuclei and WebInfoHunter | Nuclei and Dalfox | Vulnerability plugins and imported POCs |
| Screenshots | Supported | Playwright | Asset-mapping/plugin dependent |
| Scheduling/distribution | Scheduled monitors | Cron and Workers | Scheduled tasks and multi-node execution |
| Weak-password brute force | `service_brute` | Not a core stage | Still listed as TODO in v1.9.3 |

## Provider task profiles

### ARL 2.6.3

- `task_mode=direct` maps to `/api/task/` and exposes typed domain, port/service, Web, correlation, and vulnerability switches.
- `task_mode=policy` maps to `/api/task/policy/` and requires a live `policy_id`.
- Custom ports, excluded ports, rate/parallelism, POCs, and brute-force dictionaries belong to an upstream policy. They are not accepted as fake per-task overrides.
- Lifecycle actions: restart, delete, and result synchronization.

### XingRin v1.5.8

CyberStrikeAI generates controlled YAML from typed options for subdomain discovery/brute force, active/passive ports, custom or top-N ports, HTTP probing, fingerprints, directories, URL collection, screenshots, Nuclei, Dalfox, rate, concurrency, and timeouts. Arbitrary YAML is not exposed.

Live choices include engines, Workers, wordlists, and Nuclei repositories. Engine lists return compact ID/name metadata; a specific engine `id` must be supplied to retrieve its complete YAML configuration. Quick Scan accepts up to 5,000 targets.

### ScopeSentry v1.9.3

With `template_id`, the adapter reuses an upstream-reviewed template and all of its configured modules, dictionaries, plugins, and POCs. Without it, CyberStrikeAI generates a controlled low-load template whose name includes a fingerprint of ports, concurrency, site identification, screenshots, and TLS settings, preventing one task profile from overwriting another.

Node selection, ignore/duplicate rules, target sources, projects, structured asset filters, scheduling, resume, restart, and delete are mapped. Scheduled creation resolves the new remote ID through `/api/task/scheduled`, records it in the local task center, and reads it through `/api/task/scheduled/detail`. A scheduled definition cannot be stopped/resumed/restarted as an immediate scan; only explicit deletion is supported. Arbitrary plugin command lines are not exposed. POCs use the paginated `/api/poc` endpoint; template, dictionary, plugin, and POC lists are compacted so large upstream payloads do not consume the agent context.

## API compatibility surface

| Platform | Authentication/connectivity | Tasks/options | Assets |
| --- | --- | --- | --- |
| ARL | `/api/user/login`, `/api/console/info` | `/api/task/`, `/api/task/policy/`, stop/restart/delete/sync; policy/POC/scope lists | `/api/site/`, `/api/domain/`, `/api/ip/`, `/api/cert/`, `/api/service/`, `/api/fileleak/`, `/api/url/`, `/api/vuln/`, `/api/npoc_service/`, `/api/cip/`, `/api/nuclei_result/`, `/api/stat_finger/`, `/api/wih/` |
| XingRin | `/api/auth/login/`, `/api/auth/me/` | `/api/scans/quick/`, scans/detail/stop; engines/Workers/wordlists/Nuclei repositories | `/api/assets/:type/`, `/api/scans/:id/:type/` |
| ScopeSentry | `/api/user/login`, `/api/node/online` | task templates, immediate/scheduled task creation and lifecycle; dictionary/plugin/POC/project choices | site/domain/IP/URL plus crawler, sensitive, directory, takeover, vulnerability list and vulnerability detail APIs |

The task center now renders provider-aware rich cards rather than forcing all providers into a fixed generic table. Complete fields can be expanded; vulnerability cards expose severity, target, scanner evidence, and request/response detail. After a task completes, the background worker walks every provider `result_type` and all upstream pages, stores one local database row per result, enriches ScopeSentry vulnerability details, and automatically downloads authenticated screenshots. The task center and `asm_list_assets` then use local pagination, search, and detail reads instead of querying the ASM on every view.

Upstream result requests are limited to the initial completion sync, a first-read fallback when a completed type is missing locally, and explicit refresh through the task center or `asm_manage_task(action=sync_results)`. Scan progress and local-result synchronization are shown independently, including completed type count, local row count, current type, last synchronization time, and errors.

## Live MCP validation

On 2026-08-12, all three adapters were tested through the same MCP registrations, authorization policy, database, and encrypted credentials used by the application, against explicitly authorized company IPs:

| Platform | Validation |
| --- | --- |
| ARL | Connection, profile, live options, low-load direct creation, list, detail, IP results, and stop passed; `response.items[0].task_id` is supported |
| XingRin | Engine/Worker/dictionary/repository discovery and a controlled 80/443 task at concurrency 2 passed; local history recording and stop passed |
| ScopeSentry | Node/template/dictionary/plugin/POC/project discovery and a generated 80/443 low-load task passed; 13,510 POCs were available through real pagination; scheduled remote-ID lookup, local history, list, detail, and explicit deletion also passed |

The reusable `TestASMRealMCPFlow` remains skipped unless `CYBERSTRIKE_ASM_REAL_TEST=1` and an explicit resource ID are supplied.

## Upgrade checklist

1. Record the stable release, date, and tag commit.
2. Diff capability claims, task schemas, authentication, and API paths.
3. Update the capability and adapter matrices before implementation.
4. Update the provider profile, MCP descriptions, and task form without silently ignoring fields.
5. Run adapter, MCP authorization/registration, and frontend tool tests.
6. On constrained infrastructure, validate one ASM at a time: connection, options, create, list, detail, progress, results, search, stop, and screenshot caching.
7. Increment this document version and record compatibility changes.

## Document history

| Version | Date | Platform baseline | Change |
| --- | --- | --- | --- |
| 1.6 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Added automatic full result synchronization after completion, local row-level pagination/search/detail for the task center and MCP, explicit sync state and refresh actions, and automatic screenshot caching |
| 1.5 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Added provider-specific rich result cards, upstream-total pagination and page sizes; mapped XingRin directory/screenshot results and ScopeSentry crawler/sensitive/directory/takeover/vulnerability details; made screenshot caching automatic for UI and MCP reads |
| 1.4 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Added provider-specific `result_types`; mapped all 13 ARL task-detail collections; added provider-aware tabs and paged task-center reads |
| 1.3 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Isolated generated ScopeSentry templates by configuration fingerprint and added scheduled-task ID resolution, task-center visibility, detail, and explicit deletion semantics |
| 1.2 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Completed provider-specific task capabilities, compact live option discovery, and real MCP create/read/stop validation |
| 1.0 | 2026-08-11 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Initial version, capability, API, and adapter-gap baseline |
