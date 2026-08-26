# Agent and Egress Container Image Supply Chain

CyberStrikeAI now uses its own Docker Hub multi-platform Agent image and no longer uses Strix as the runtime base. Production configuration must reference an immutable digest. The `latest` tag is only a discovery channel and is not a runtime trust anchor.

## Currently deployed candidate

| Item | Value |
| --- | --- |
| Repository | `ruoji6/cyberstrikeai-agent` |
| Tags | `full-tools-seclists-20260826`, `latest` |
| Multi-platform index | `sha256:14bed42067163e75430e5ea4bf335c18e9631569742da591894c2a1c0a38111d` |
| ARM64 manifest | `sha256:aeacc44686dc93697ede82ab6f1455d49b691b1d70372f1ff8363d38d18ffa1a` |
| AMD64 manifest | `sha256:ae742a453c3627ed984c4a174b83d37a6a5c2404f5c5a171b28fa60e70570dc4` |
| ARM64 inventory | `container/agent-tool-inventory-linux-arm64.json` |
| Inventory digest | `sha256:83173e182532f08cbbfc67ab2083a3c09e4df428a139a096c4a29b10e1d66759` |

The `latest` tag currently resolves to the index digest above. The ARM64 VM pulls the image directly from Docker Hub and runs it as `repository@digest`. This digest has passed 77/77 configuration coverage, 75/77 ARM64 platform availability, all image functional probes, and the network-disabled container-security smoke test.

## Current Egress release

| Item | Value |
| --- | --- |
| Repository | `ruoji6/cyberstrikeai-egress` |
| Tags | `runtime-controls-20260826`, `latest` |
| Multi-platform index | `sha256:14c6b318f82fd5fcf85a1add501a329f01d5a0b02280668a0ab18483b883c511` |
| ARM64 manifest | `sha256:8315466e05ddfcaae46de008a36ceeee614bcfb115f1ca78db5408285bade7c0` |
| AMD64 manifest | `sha256:614abfc446fb35832a0335b86389c0c766f2e24f8be1aad383e2902a0ee32392` |
| OCI revision | `7454258` |

The Egress image is also pulled from Docker Hub by index digest. Both platform manifests passed the publisher smoke test. Its ARM64 runtime keeps a read-only root filesystem, drops all capabilities before restoring only `NET_ADMIN`/`NET_RAW`, enables `no-new-privileges`, and loads an immutable boundary snapshot. This release retains immediate per-tuple TCP/UDP denial and adds optional HTTP request, TCP connection, and UDP datagram pacing configured per conversation.

## Tool and platform coverage

- The mapping covers all 77 enabled CyberStrikeAI tool definitions. `prowler` is disabled and removed because it consistently exceeds the 512 MiB runtime limit.
- AMD64 declares 77/77 available.
- ARM64 declares 75/77 available. `pwninit` and `x8` are explicitly excluded because this release's locked sources only provide AMD64 artifacts.
- The ARM64 inventory contains 81 executable/runtime entries. It has passed the offline structural probes with a read-only root filesystem, all capabilities dropped, `no-new-privileges`, and the non-root `pentester` user.

## Build provenance

The image is based on a digest-pinned official Kali Rolling image and the repository's Dockerfile, tool mapping, and artifact lock. Non-APT artifacts must pin a version or revision and SHA-256.

This candidate was supplied from Docker Build Cloud, not GitHub Actions. Its OCI revision label is the clean commit `21b1ca30dfda14092a52225a0e1f2ef09572de76`, and its version label is `full-tools-seclists-20260826`. The ARM64 image has passed the functional gate for every tool declared supported on that platform.

`scripts/verify-container-release.sh` accepts separate Agent and Egress revisions because the two images can be published from different clean commits. The current ARM64 pair passed its network-disabled SPDX 2.3 OS-package inventory and `SHA256SUMS` readback (859 Agent packages and 112 Egress packages); the independent Agent tool inventory remains the functional source of truth for bundled security tools.

## Deployment gates and rollback

Before switching, verify the Hub index/platform manifests, local VM `RepoDigests`, configured platform, inventory image/platform/content digest, and the actual images used by a newly created conversation. Container failures must not fall back to host execution. The egress gateway remains the separate minimal `ruoji6/cyberstrikeai-egress` image.

Keep the previous configuration and inventory backup. Restore the previous repository/digest/inventory tuple, restart CyberStrikeAI, and rebuild affected RuntimeSpecs. Remove old Agent/Strix images only after end-to-end acceptance and after confirming that no container references them.
