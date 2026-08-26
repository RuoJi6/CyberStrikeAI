# CyberStrikeAI Egress Gateway

Multi-platform outbound policy gateway for CyberStrikeAI conversation containers.

CyberStrikeAI uses this image as an internal runtime component. The application creates one isolated gateway for each container-backed conversation and loads an immutable policy snapshot. Users normally do not start this image directly.

## Capabilities

- Enforces per-conversation HTTP, HTTPS, DNS, CONNECT, TCP, UDP, and ICMP boundary decisions.
- Supports allow, deny, audit-only, and credential-injection policy effects.
- Routes traffic through configured direct or upstream proxy exits.
- Produces traceable network activity and tamper-evident egress audit events.
- Supports optional per-conversation HTTP request, TCP connection, and UDP datagram pacing.
- Handles mixed-target and mixed-port scans per network tuple, so one denied tuple does not stop allowed tuples in the same scan.

## Current release

| Item | Value |
| --- | --- |
| Tags | `runtime-controls-20260826`, `latest` |
| Platforms | `linux/amd64`, `linux/arm64` |
| Multi-platform digest | `sha256:14c6b318f82fd5fcf85a1add501a329f01d5a0b02280668a0ab18483b883c511` |
| AMD64 manifest | `sha256:614abfc446fb35832a0335b86389c0c766f2e24f8be1aad383e2902a0ee32392` |
| ARM64 manifest | `sha256:8315466e05ddfcaae46de008a36ceeee614bcfb115f1ca78db5408285bade7c0` |

Production deployments should pin the multi-platform digest. The `latest` tag is a discovery channel, not a runtime trust anchor.

## Runtime security

The published image is designed for a read-only root filesystem, drops all Linux capabilities before restoring only `NET_ADMIN` and `NET_RAW`, enables `no-new-privileges`, and consumes boundary snapshots through a read-only mount.

---

# CyberStrikeAI 出站网关

这是 CyberStrikeAI 对话容器使用的多架构出站策略网关。系统会为每个容器对话创建独立网关并加载不可变策略快照，用户通常不需要单独启动该镜像。

网关支持 HTTP、HTTPS、DNS、CONNECT、TCP、UDP 和 ICMP 边界判定、上游出口、网络活动与出站审计，以及按对话可选的 HTTP 请求、TCP 新连接和 UDP 数据报速率控制。生产环境应固定使用上述多架构 digest，不应将 `latest` 作为运行时信任依据。
