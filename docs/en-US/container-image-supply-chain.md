# Agent and Egress Container Image Supply Chain

CyberStrikeAI now uses its own Docker Hub multi-platform Agent image and no longer uses Strix as the runtime base. Production configuration must reference an immutable digest. The `latest` tag is only a discovery channel and is not a runtime trust anchor.

## Currently deployed candidate

| Item | Value |
| --- | --- |
| Repository | `ruoji6/cyberstrikeai-agent` |
| Tags | `full-tools-slim2-20260825`, `latest` |
| Multi-platform index | `sha256:a535bbe3da57a2d103df60fbca37fdd7b8937c882d8b49e9be49050b9d974f50` |
| ARM64 manifest | `sha256:13b24dec5541d7bac77ce439c7dab5044a2fd5775987924e5bbdd9414e354b8f` |
| AMD64 manifest | `sha256:4e8d11662efa90c700a3d48241fa303f992d6ad04a195323a0da8fc329736b85` |
| ARM64 inventory | `container/agent-tool-inventory-linux-arm64.json` |
| Inventory digest | `sha256:3664b426c9de1cb86fa914f336005c797685eff18643bdae0f78e5c8ff7437b4` |

Both published tags currently resolve to the same index digest. The ARM64 VM pulls the image directly from Docker Hub and runs it as `repository@digest`. This digest has passed the ARM64 full-tool functional gate and offline container-security smoke test, including the `/usr/local/bin/amass` wrapper. Production configuration and the inventory now pin this digest. A previous Agent image is retained only while an existing conversation container still references it; it must not be force-removed.

## Current Egress release

| Item | Value |
| --- | --- |
| Repository | `ruoji6/cyberstrikeai-egress` |
| Tags | `fast-reject-20260825`, `latest` |
| Multi-platform index | `sha256:5e9c03756eea3ca22a0fb3a6235d8fdf9ee0a992af36c64f367e664d9423c3d5` |
| ARM64 manifest | `sha256:5c109b32fe43418e154f2ce20d60fca6ea23ae29090edcdc9b7376f6473d7905` |
| AMD64 manifest | `sha256:588cdb0c6cc63935d430ff1ca1e99782a425a856d84a62d70d6b82d090bfc0fa` |
| OCI revision | `1b00ebb1215fb08b25958e2c251b727af1afe003` |

The Egress image is also pulled from Docker Hub by index digest. Its ARM64 manifest has passed a read-only-rootfs smoke test with all capabilities dropped, only `NET_ADMIN`/`NET_RAW` restored, `no-new-privileges`, and an immutable boundary snapshot health check. The production VM then passed HTTP, mixed TCP/UDP allow-and-block, persistent audit-chain, restart, and exact-runtime-image acceptance. This release immediately rejects evaluated denied TCP/UDP tuples. Mixed-port scans are decided independently per `(IP, port, protocol)`, so denied ports neither terminate nor affect allowed ports in the same scan.

## Tool and platform coverage

- The mapping covers all 77 enabled CyberStrikeAI tool definitions. `prowler` is disabled and removed because it consistently exceeds the 512 MiB runtime limit.
- AMD64 declares 77/77 available.
- ARM64 declares 75/77 available. `pwninit` and `x8` are explicitly excluded because this release's locked sources only provide AMD64 artifacts.
- The ARM64 inventory contains 81 executable/runtime entries. It has passed the offline structural probes with a read-only root filesystem, all capabilities dropped, `no-new-privileges`, and the non-root `pentester` user.

## Build provenance

The image is based on a digest-pinned official Kali Rolling image and the repository's Dockerfile, tool mapping, and artifact lock. Non-APT artifacts must pin a version or revision and SHA-256.

This candidate was supplied from Docker Build Cloud, not GitHub Actions. Its OCI revision label is the clean commit `1007db0523a18c0f123d3a19899648eff57a91fb`, and its version label is `full-tools-slim2-20260825`. The ARM64 image has passed the Amass probe and the functional gate for every tool declared supported on that platform.

`scripts/verify-container-release.sh` accepts separate Agent and Egress revisions because the two images can be published from different clean commits. The current ARM64 pair passed its network-disabled SPDX 2.3 OS-package inventory and `SHA256SUMS` readback (859 Agent packages and 112 Egress packages); the independent Agent tool inventory remains the functional source of truth for bundled security tools.

## Deployment gates and rollback

Before switching, verify the Hub index/platform manifests, local VM `RepoDigests`, configured platform, inventory image/platform/content digest, and the actual images used by a newly created conversation. Container failures must not fall back to host execution. The egress gateway remains the separate minimal `ruoji6/cyberstrikeai-egress` image.

Keep the previous configuration and inventory backup. Restore the previous repository/digest/inventory tuple, restart CyberStrikeAI, and rebuild affected RuntimeSpecs. Remove old Agent/Strix images only after end-to-end acceptance and after confirming that no container references them.
