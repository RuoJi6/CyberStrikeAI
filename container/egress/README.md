# CyberStrikeAI Egress Gateway

Multi-platform outbound policy gateway for CyberStrikeAI conversation containers.

CyberStrikeAI uses this image as an internal runtime component. The application creates one isolated gateway for each container-backed conversation and loads an immutable policy snapshot. Users normally do not start this image directly.

## Capabilities

- Enforces per-conversation HTTP, HTTPS, DNS, CONNECT, TCP, UDP, and ICMP boundary decisions.
- Supports allow, deny, audit-only, and credential-injection policy effects.
- Routes traffic through configured direct or upstream proxy exits.
- Produces traceable network activity and tamper-evident egress audit events.
- Decrypts and fully audits HTTPS traffic by default, including conversations without an explicit boundary policy; the generated short-lived CA remains isolated per conversation.
- Supports optional per-conversation HTTP request, TCP connection, and UDP datagram pacing; controls are disabled by default and zero means unlimited.
- Preserves upstream HTTP 429 responses unless an explicit CyberStrikeAI boundary rule enables traffic governance.
- Handles mixed-target and mixed-port scans per network tuple, so one denied tuple does not stop allowed tuples in the same scan.

## Current release

| Item | Value |
| --- | --- |
| Tag | `https-default-20260827` |
| Platforms | `linux/amd64`, `linux/arm64` |
| Multi-platform digest | `sha256:68e3b5873bb62a1448c22dd689b3d38768663f0f3ad3f402a58a7ee506c20855` |
| AMD64 manifest | `sha256:85624a043bcf4d5dfb7407645bf32341cb11944f82c168a58de9d969ea8de00d` |
| ARM64 manifest | `sha256:29473ae320b9e97c6106f4dc6e1ea96b5c442c6d9c8a1c47cbee4a3b94035c56` |

Production deployments should pin the multi-platform digest. The `latest` tag is a discovery channel, not a runtime trust anchor; it is intentionally not claimed as part of this candidate release.

## Runtime security

The published image is designed for a read-only root filesystem, drops all Linux capabilities before restoring only `NET_ADMIN` and `NET_RAW`, enables `no-new-privileges`, and consumes boundary snapshots through a read-only mount.

---

# CyberStrikeAI 出站网关

这是 CyberStrikeAI 对话容器使用的多架构出站策略网关。系统会为每个容器对话创建独立网关并加载不可变策略快照，用户通常不需要单独启动该镜像。

网关支持 HTTP、HTTPS、DNS、CONNECT、TCP、UDP 和 ICMP 边界判定、上游出口、网络活动与出站审计。即使对话未选择边界策略，HTTPS 也默认使用对话独立短期 CA 解密并完整审计。按对话可选的 HTTP 请求、TCP 新连接和 UDP 数据报速率控制默认关闭，数值为 0 表示不限制；未启用明确流量治理规则时，上游服务返回的 HTTP 429 会原样传递。生产环境应固定使用上述多架构 digest，不应将 `latest` 作为运行时信任依据。
