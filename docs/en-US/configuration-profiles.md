# Configuration Profiles

[中文](../zh-CN/configuration-profiles.md)

These profiles are not full `config.yaml` files. They show the key sections that most affect safety and operability.

## Local Development

Goal: easy debugging with local capabilities.

Common startup:

```bash
chmod +x run.sh && ./run.sh
```

```yaml
server:
  host: 127.0.0.1
  port: 8080
  tls_enabled: true
  tls_auto_self_sign: true
auth:
  session_duration_hours: 12
audit:
  enabled: true
  retention_days: 7
c2:
  enabled: false
multi_agent:
  enabled: true
  eino_skills:
    filesystem_tools: true
```

Not for shared or public use.

## Internal Team

Goal: shared team instance with audit and limited high-risk surface.

```yaml
server:
  host: 127.0.0.1
  port: 8080
  tls_enabled: false
auth:
  session_duration_hours: 12
audit:
  enabled: true
  retention_days: 30
monitor:
  retention_days: 90
c2:
  enabled: false
mcp:
  enabled: false
hitl:
  default_reviewer: human
  tool_whitelist: [read_file, glob, grep, tool_search]
```

Pair with reverse-proxy HTTPS, IP allowlist, and backups.

## Knowledge-Only Assistant

Goal: use CyberStrikeAI as a knowledge-augmented assistant with minimal attack surface.

```yaml
c2:
  enabled: false
mcp:
  enabled: false
knowledge:
  enabled: true
  base_path: knowledge_base
  retrieval:
    top_k: 5
    similarity_threshold: 0.4
multi_agent:
  eino_skills:
    filesystem_tools: false
```

Use read-only roles and avoid storing sensitive customer data.

## High-Audit Production

Goal: long-running production red-team or security platform.

```yaml
auth:
  session_duration_hours: 8
audit:
  enabled: true
  retention_days: 90
monitor:
  retention_days: 180
hitl:
  default_reviewer: human
  retention_days: 180
  tool_whitelist: [read_file, glob, grep, tool_search]
c2:
  enabled: false
multi_agent:
  eino_callbacks:
    enabled: true
    mode: log_only
    sse_trace_to_client: false
```

Pair with proxy auth, dedicated OS user, log collection, encrypted backups, and project closeout cleanup.

## C2 Exercise Window

Goal: temporarily enable C2 only during authorized exercise.

```yaml
c2:
  enabled: true
hitl:
  default_reviewer: human
  tool_whitelist: [read_file, glob, grep, tool_search]
audit:
  enabled: true
monitor:
  retention_days: 180
```

Requirements:

- confirm scope before exercise;
- separate listener ports from admin UI;
- run C2 cleanup afterward;
- restore `c2.enabled: false`.

## External MCP Automation

Goal: connect trusted internal tool services.

```yaml
external_mcp:
  servers: {}
multi_agent:
  eino_middleware:
    tool_search_enable: true
    tool_search_min_tools: 20
hitl:
  default_reviewer: audit_agent
  tool_whitelist: [read_file, glob, grep, tool_search]
```

Guidance:

- every MCP tool needs clear schema;
- high-risk MCP tools stay out of allowlist;
- stdio MCP gets its own working directory;
- HTTP MCP must authenticate.

## ARM64 Conversation-Container Rollout

Use an allowlist before broad enablement; conversations outside the rollout continue to default to host mode.

```yaml
container:
  enabled: true
  rollout_user_ids: [admin]
  rollout_project_ids: []
  owner_id: cyberstrike-production-01
  image_repository: ruoji6/cyberstrikeai-agent
  image_digest: sha256:14bed42067163e75430e5ea4bf335c18e9631569742da591894c2a1c0a38111d
  image_platform: linux/arm64
  egress_image_repository: ruoji6/cyberstrikeai-egress
  egress_image_digest: sha256:5e9c03756eea3ca22a0fb3a6235d8fdf9ee0a992af36c64f367e664d9423c3d5
  egress_image_platform: linux/arm64
  tool_inventory_path: container/agent-tool-inventory-linux-arm64.json
  tool_inventory_digest: sha256:83173e182532f08cbbfc67ab2083a3c09e4df428a139a096c4a29b10e1d66759
```

- User and project allowlists use OR semantics; both empty means all authenticated users.
- A failed or unavailable rollout check keeps the UI in host mode.
- Pin the Agent image, gateway image, and inventory by digest. The deployed Agent and Egress indexes both contain `linux/arm64` and `linux/amd64`; this rollout's runtime acceptance scope is `linux/arm64`.
