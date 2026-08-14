# ASM Platform Capability and Adapter Baseline

> Document version: 2.9
> Baseline date: 2026-08-14
> Scope: CyberStrikeAI built-in adapters for ARL, XingRin, and ScopeSentry

This document distinguishes upstream platform capabilities from actions currently exposed to agents by CyberStrikeAI. Update it before changing MCP schemas, adapters, or UI after an upstream release.

## Reproducible upstream baseline

| Platform | Upstream | Version | Release date | Tag commit |
| --- | --- | --- | --- | --- |
| ARL | [Aabyss-Team/ARL](https://github.com/Aabyss-Team/ARL) | [2.6.3](https://github.com/Aabyss-Team/ARL/releases/tag/2.6.3) | 2025-03-04 | `89a5d010e8260020c7db55cec53ed977b6315452` |
| XingRin | [yyhuni/xingrin](https://github.com/yyhuni/xingrin) | [v1.5.8](https://github.com/yyhuni/xingrin/releases/tag/v1.5.8) | 2026-01-11 | `bd1dd2c0d5eb5f127dc9067b2aa114af2e91748e` |
| ScopeSentry | [Autumn-27/ScopeSentry](https://github.com/Autumn-27/ScopeSentry) | [v1.9.3](https://github.com/Autumn-27/ScopeSentry/releases/tag/v1.9.3) | 2026-07-26 | `a7f1aedf4c9a93b1eaf0ab9a8c3e9bc6b8c2d44c` |

## Unified MCP actions

Agents use eleven normalized tools:

| Tool | Purpose |
| --- | --- |
| `asm_list_resources` | List enabled resources, state, and capabilities |
| `asm_test_connection` | Verify the address and server-side credential |
| `asm_get_task_profile` | Read the provider version, modes, typed fields, defaults, and dependencies |
| `asm_list_task_options` | Query live policies, plugins, POCs, and ARL brute-force plugins; read local built-ins with `kind=template_presets`; or aggregate every list-style kind with `kind=all` |
| `asm_create_template` | Create or reconcile an ARL policy or ScopeSentry template from `preset_id`; ScopeSentry also supports controlled base-template cloning |
| `asm_create_task` | Create a task for an explicitly authorized target |
| `asm_list_tasks` / `asm_get_task` | Read task lists, progress, stages, statistics, and configuration |
| `asm_list_assets` | Page through a provider-specific result type from the CyberStrikeAI local snapshot; discover valid IDs from profile `result_types` |
| `asm_stop_task` | Stop a remote task |
| `asm_manage_task` | Restart, resume, delete, or synchronize results when supported |

The expected call sequence is `asm_list_resources` -> `asm_get_task_profile` -> optionally `asm_list_task_options` -> optionally `asm_create_template` for ARL or ScopeSentry -> `asm_create_task`. Credentials remain on the server and are never placed in model context.

`asm_list_task_options(kind=all)` queries every list-style dynamic option kind declared by the selected resource. It does not scan all targets or retrieve an unbounded option corpus: `page` and `page_size` apply independently to every kind (defaulting to the first 20 records of each). Detail kinds such as `policy_detail` and `template_detail` are skipped because they require a specific `id`. A per-kind failure produces `partial=true` and a categorized error while preserving successful results.

### Built-in tiered templates

The ASM resource page and MCP share one server-side preset catalog. `template_presets` reads local metadata without contacting upstream; `asm_create_template` creates the native ARL policy or ScopeSentry task template.

Each `template_presets` entry is specialized for the selected resource and includes `provider`, `provider_kind`, exact `provider_config`, and `mcp_usage`. ARL entries expose policy switches, port tier, dictionaries, POC/brute selection, and concurrency controls; ScopeSentry entries expose the port expression, concurrency, and enabled plugin capabilities. The resource page renders the same structure through “view exact configuration”, while existing upstream profiles are read through `policy_detail` or `template_detail`.

| `preset_id` | Tier | Purpose | ARL ports | ScopeSentry ports |
| --- | --- | --- | --- | --- |
| `quick_discovery` | Low | Common ports, services, sites, and TLS | TOP100 | Curated common-service ports |
| `information_collection` | Medium | Subdomains, broader ports, screenshots, URLs, and crawling without active vulnerability POCs | TOP1000 | `1-10000` |
| `vulnerability_assessment` | Medium-high | Asset identification followed by leak and vulnerability checks; ARL selects every installed POC | TOP1000 | `1-10000` |
| `full_scan` | High | Broad subdomain, all-port, site/crawler/sensitive-data, vulnerability POCs, plus every installed ARL brute plugin | All ports | `1-65535` |

Names are fixed as `CyberStrikeAI · <preset name>`. A repeat call finds the exact upstream record and reconciles it with the current preset, so old policies need not be deleted after a preset upgrade. ARL vulnerability assessment pages through every live `plugin_type=poc`; full scan additionally selects every `plugin_type=brute` plugin. Creation fails if an asserted live catalog is empty rather than producing a misleading policy. Presets cannot be overridden per request. Creation no longer opens an extra vulnerability-scan confirmation dialog. If a ScopeSentry base template has not enabled a declared capability, the adapter automatically copies installed upstream plugin hashes and upstream-owned default parameters, then verifies the saved template. Capability checks include concrete plugin identity: `sensitive_scan`, for example, requires `URLSecurity/sensitive` and is not satisfied by `trufflehog` merely sharing the module. The v1.9.3 default plugin catalog has no `PassiveScan` implementation, so the full built-in does not declare that empty module. XingRin has no native template-creation API and therefore does not advertise this feature.

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
| Weak-password brute force | Policy `brute_config` selects installed plugins; direct tasks also expose `service_brute` | Not a core stage | Still listed as TODO in v1.9.3 |

## Provider task profiles

### ARL 2.6.3

- `task_mode=direct` maps to `/api/task/` and exposes typed domain, port/service, Web, correlation, and vulnerability switches.
- `task_mode=policy` maps to `/api/task/policy/` and requires a live `policy_id`.
- The ASM task center and MCP use the same semantics: “direct custom scan” submits `task_mode=direct`, while “use policy template” submits `task_mode=policy + policy_id`; fields from the inactive mode are not mixed into the request.
- `asm_create_template` creates native ARL policies at `/api/policy/add/` and reconciles existing built-ins through `/api/policy/edit/`. Custom fields come from `asm_get_task_profile.template_create_options`: custom ports use `port_scan_type=custom` plus `port_custom`, and ARL concurrency uses `port_parallelism`; ScopeSentry-only `ports`, `concurrency`, and `enabled_capabilities` must not be mixed in.
- After creation or reconciliation, CyberStrikeAI reads the policy back from `/api/policy/`. `effective_policy` is the final authority and `template_verified=true` is returned only when the requested policy fields match the upstream result. An Agent must not silently drop user-requested fields after a validation error.
- Custom ports, excluded ports, rate/parallelism, POCs, and brute-force dictionaries belong to an upstream policy. They are not accepted as fake per-task overrides.
- `kind=pocs` reads only `plugin_type=poc`; `kind=brute_plugins` reads only `plugin_type=brute`. Vulnerability assessment selects all live POCs, while full scan selects all live POCs and brute plugins and reports the actual counts in `plugin_summary`.
- Lifecycle actions: restart, delete, and result synchronization.

### XingRin v1.5.8

CyberStrikeAI generates controlled YAML from typed options for subdomain discovery/brute force, active/passive ports, custom or top-N ports, HTTP probing, fingerprints, directories, URL collection, screenshots, Nuclei, Dalfox, rate, concurrency, and timeouts. Arbitrary YAML is not exposed.

Live choices include engines, Workers, wordlists, and Nuclei repositories. Engine lists return compact ID/name metadata; a specific engine `id` must be supplied to retrieve its complete YAML configuration. Quick Scan accepts up to 5,000 targets. XingRin creates one remote scan ID per target; CyberStrikeAI persists every `response.scans[]` child and links children from the same MCP request with one `batch_id`.

### ScopeSentry v1.9.3

With `template_id`, the adapter reuses an upstream-reviewed template and all of its configured modules, dictionaries, plugins, and POCs. Without it, CyberStrikeAI generates a controlled low-load template whose name includes a fingerprint of ports, concurrency, site identification, screenshots, and TLS settings, preventing one task profile from overwriting another.

`asm_create_template` and the task-center form can also clone a selected upstream template, enable a typed `enabled_capabilities` set, and adjust `ports`, `concurrency`, `site_capture`, `tls_probe`, and `poc_ids`. `asm_get_task_profile` returns live `available_template_capabilities` and `unavailable_template_capabilities`; the UI disables only capabilities whose plugins are genuinely absent. Installed capabilities missing from the base template remain selectable and are merged with upstream-owned default parameters. Arbitrary plugin command lines remain forbidden. The response includes the new `template_id`, plugin-aware `capability_summary`, and `verification_token`, so the new template can be used immediately by `asm_create_task`.

Node selection, ignore/duplicate rules, target sources, projects, structured asset filters, scheduling, resume, restart, and delete are mapped. Scheduled creation resolves the new remote ID through `/api/task/scheduled`, records it in the local task center, and reads it through `/api/task/scheduled/detail`. A scheduled definition cannot be stopped/resumed/restarted as an immediate scan; only explicit deletion is supported. Arbitrary plugin command lines are not exposed. POCs use the paginated `/api/poc` endpoint; template, dictionary, plugin, and POC lists are compacted so large upstream payloads do not consume the agent context.

Upstream `template_id` creation now requires a preflight inspection. The agent must call `asm_list_task_options(kind=template_detail,id=...)`, inspect the machine-readable `capability_summary`, and pass its `verification_token` back as `template_verification_token`. Full-port requests must assert `required_port_scope=all`; explicitly requested stages must be listed in `required_capabilities`. MCP re-reads the upstream template and validates its token, ports, and capabilities before creating anything. Successful responses include `effective_template`, which is the only authoritative basis for capability claims; template names, task names, and the total POC catalog size are not evidence that every feature is enabled.

## API compatibility surface

| Platform | Authentication/connectivity | Tasks/options | Assets |
| --- | --- | --- | --- |
| ARL | `/api/user/login`, `/api/console/info` | `/api/task/`, `/api/task/policy/`, stop/restart/delete/sync; `/api/policy/`, `/api/policy/add/`, POC/scope lists | `/api/site/`, `/api/domain/`, `/api/ip/`, `/api/cert/`, `/api/service/`, `/api/fileleak/`, `/api/url/`, `/api/vuln/`, `/api/npoc_service/`, `/api/cip/`, `/api/nuclei_result/`, `/api/stat_finger/`, `/api/wih/` |
| XingRin | `/api/auth/login/`, `/api/auth/me/` | `/api/scans/quick/`, scans/detail/stop; engines/Workers/wordlists/Nuclei repositories | `/api/assets/:type/`, `/api/scans/:id/:type/` |
| ScopeSentry | `/api/user/login`, `/api/node/online` | task templates, immediate/scheduled task creation and lifecycle; dictionary/plugin/POC/project choices | site/domain/IP/URL plus crawler, sensitive, directory, takeover, vulnerability list and vulnerability detail APIs |

The task center now renders provider-aware rich cards rather than forcing all providers into a fixed generic table. Complete fields can be expanded; vulnerability cards expose severity, target, scanner evidence, and request/response detail. After a task completes, the background worker walks every provider `result_type` and all upstream pages, stores one local database row per result, enriches ScopeSentry vulnerability details, and automatically downloads authenticated screenshots. The task center and `asm_list_assets` then use local pagination, search, and detail reads instead of querying the ASM on every view.

Manual task creation in the task center reads the same provider profile used by MCP and loads live ARL policies, XingRin engines/wordlists, or ScopeSentry templates/nodes/projects. Selecting a ScopeSentry template automatically inspects its detail and carries the verification token. Task details expose the provider-native stop action: ScopeSentry immediate tasks can later resume, ARL tasks can restart, while stopped XingRin scans require a new task.

XingRin produces screenshots only when `site_capture=true` or the selected upstream engine includes its screenshot stage. The task center discovers XingRin screenshot paths from localized `screenshot` rows first and only authenticates upstream to download image bytes that are not yet cached.

Upstream result requests are limited to the initial completion sync, a first-read fallback when a completed type is missing locally, and explicit refresh through the task center or `asm_manage_task(action=sync_results)`. Scan progress and local-result synchronization are shown independently, including completed type count, local row count, current type, last synchronization time, and errors.

The ASM task center exposes a standalone Agent Continuation Settings action whose policy is stored per resource. By default, the conversation that created the scan resumes only after every related child task has completed and all results and screenshots have been localized. The settings dialog stores separate editable prompts for cases where the Agent was still running or had already stopped. If the user explicitly stops the source conversation, pending continuations are durably marked `user_stopped` and the Agent is never restarted when the scan later completes. This policy is not a scan option: manual task-center submissions do not bind the currently open chat, and an agent cannot override the user setting through a one-off `asm_create_task` argument. MCP task creation and `asm_manage_task` restart/resume actions bind their current conversation automatically. The `asm_list_resources`, `asm_create_task`, and `asm_manage_task` descriptions explicitly tell the Agent that this resource-level continuation already exists, and create/restart/resume responses return `agent_continuation.wait_strategy` plus action guidance. Once a task starts, an Agent must not call `sleep` or repeatedly poll merely to wait; a single bounded status read is appropriate only when the user explicitly asks for the current progress. A XingRin multi-target request creates one batch continuation and waits for every upstream child. Continuation state and retries are durable across service restarts, authorization is re-evaluated as the original owner, and an unlinked task never creates a new Agent conversation implicitly.

## Live MCP validation

On 2026-08-12, all three adapters were tested through the same MCP registrations, authorization policy, database, and encrypted credentials used by the application, against explicitly authorized company IPs:

| Platform | Validation |
| --- | --- |
| ARL | Connection, profile, live options, low-load direct creation, list, detail, IP results, and stop passed; `response.items[0].task_id` is supported |
| XingRin | Engine/Worker/dictionary/repository discovery and a controlled 80/443 task at concurrency 2 passed; local history recording and stop passed |
| ScopeSentry | Node/template/dictionary/plugin/POC/project discovery and a generated 80/443 low-load task passed; 13,510 POCs were available through real pagination; scheduled remote-ID lookup, local history, list, detail, and explicit deletion also passed |

The reusable `TestASMRealMCPFlow` remains skipped unless `CYBERSTRIKE_ASM_REAL_TEST=1` and an explicit resource ID are supplied.

On 2026-08-13, ScopeSentry v1.9.3 received an additional template-creation validation. The task center cloned the `default` base template, applied typed port and concurrency settings, and immediately completed a task. MCP created a separate template through `asm_create_template`, submitted a task with it through `asm_create_task`, read it through `asm_get_task`, and stopped it through `asm_manage_task`. Both paths returned a template ID, capability summary, and verification token that had been validated by reading the saved template back from ScopeSentry.

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
| 2.9 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | A manual user stop durably cancels pending Agent continuation; task history now exposes and renders the ScopeSentry template, ARL policy, or XingRin engines used for execution |
| 2.8 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | MCP resource/task descriptions now declare system-managed waiting, task creation returns its wait strategy, and Agents are instructed not to replace background continuation with `sleep` or polling loops |
| 2.7 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Added standalone task-center Agent continuation settings; MCP tasks bind their source conversation automatically and resume with editable running/idle prompts after localization, with durable wait, retry, and restart recovery state |
| 2.6 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Built-in presets now expose and render exact provider-specific `provider_config` and `mcp_usage`; the resource page adds click-through details for built-in and upstream profiles so agents can select from real ARL policy or ScopeSentry plugin settings |
| 2.5 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | ARL vulnerability assessment now selects every live POC and full scan selects every live POC plus brute plugin; UI/MCP repeat calls reconcile existing built-ins and repair empty `poc_config`/`brute_config` arrays |
| 2.4 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Added plugin-level ScopeSentry capability checks; mapped `sensitive_scan` to the concrete sensitive plugin; unified task-center and MCP availability with the live installed-plugin catalog |
| 2.3 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | ScopeSentry built-ins now auto-enable installed plugins missing from the base template, repair an existing preset in place, and create vulnerability/full presets without an extra UI confirmation dialog |
| 2.2 | 2026-08-14 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Added the tiered template library and upstream-template view to ASM resources; MCP now exposes `template_presets` and idempotent `preset_id` creation; ARL policies and ScopeSentry templates share four controlled built-ins |
| 2.1 | 2026-08-13 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Added `asm_create_template`; agents and the task center can clone a ScopeSentry base template, configure controlled capabilities/ports/concurrency/POCs, and immediately create a task with it |
| 2.0 | 2026-08-13 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Added provider-native manual creation and stop actions to the task center, and made first-time XingRin screenshot caching reuse localized result indexes |
| 1.9 | 2026-08-13 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Persisted every XingRin multi-target child, returned complete local/remote ID lists from MCP, and grouped children from one request under a collapsible `batch_id` in the task center |
| 1.8 | 2026-08-13 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Added mandatory ScopeSentry template inspection tokens, full-port/capability assertions, pre-create validation, and effective-template response summaries to prevent name-based “full scan” claims |
| 1.7 | 2026-08-13 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Added `kind=all` to `asm_list_task_options`, with per-kind pagination, detail-kind skips, and categorized partial failures |
| 1.6 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Added automatic full result synchronization after completion, local row-level pagination/search/detail for the task center and MCP, explicit sync state and refresh actions, and automatic screenshot caching |
| 1.5 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Added provider-specific rich result cards, upstream-total pagination and page sizes; mapped XingRin directory/screenshot results and ScopeSentry crawler/sensitive/directory/takeover/vulnerability details; made screenshot caching automatic for UI and MCP reads |
| 1.4 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Added provider-specific `result_types`; mapped all 13 ARL task-detail collections; added provider-aware tabs and paged task-center reads |
| 1.3 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Isolated generated ScopeSentry templates by configuration fingerprint and added scheduled-task ID resolution, task-center visibility, detail, and explicit deletion semantics |
| 1.2 | 2026-08-12 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Completed provider-specific task capabilities, compact live option discovery, and real MCP create/read/stop validation |
| 1.0 | 2026-08-11 | ARL 2.6.3 / XingRin v1.5.8 / ScopeSentry v1.9.3 | Initial version, capability, API, and adapter-gap baseline |
