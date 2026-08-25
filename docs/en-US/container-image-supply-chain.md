# Agent Container Image Supply Chain

CyberStrikeAI now uses its own Docker Hub multi-platform Agent image and no longer uses Strix as the runtime base. Production configuration must reference an immutable digest. The `latest` tag is only a discovery channel and is not a runtime trust anchor.

## Currently deployed candidate

| Item | Value |
| --- | --- |
| Repository | `ruoji6/cyberstrikeai-agent` |
| Tags | `full-tools-slim1-20260825`, `latest` |
| Multi-platform index | `sha256:524788d05d4b5a66b569efe1f57a6ae49ad792eddfa7e44ce67a798c918afebb` |
| ARM64 manifest | `sha256:22714122c415f5cb8e6e51fdf2660f0174a06f5d12354c6a858d273c5f5557c3` |
| AMD64 manifest | `sha256:0114f51b57605fc64d25acf61f1b882c5c28ea40942770932ece3c2cc723193c` |
| ARM64 inventory | `container/agent-tool-inventory-linux-arm64.json` |
| Inventory digest | `sha256:a0da4e891f68f16edb8cd1294340314c5af61e19e6f2aa7fc905c4084a2e21f8` |

Both published tags currently resolve to the same index digest. The ARM64 VM pulls the image directly from Docker Hub and runs it as `repository@digest`. This digest is not the final accepted release: its structural probes pass, but `amass -version` reaches Kali's sudo-based launcher and fails under `no-new-privileges`. The repository now includes `/usr/local/bin/amass`; Docker Build Cloud must rebuild from the clean commit and publish a new digest before the full tool gate can pass.

## Tool and platform coverage

- The mapping covers all 77 enabled CyberStrikeAI tool definitions. `prowler` is disabled and removed because it consistently exceeds the 512 MiB runtime limit.
- AMD64 declares 77/77 available.
- ARM64 declares 75/77 available. `pwninit` and `x8` are explicitly excluded because this release's locked sources only provide AMD64 artifacts.
- The ARM64 inventory contains 81 executable/runtime entries. The new release candidate must repeat the offline structural probes with a read-only root filesystem, all capabilities dropped, `no-new-privileges`, and the non-root `pentester` user before deployment.

## Build provenance

The image is based on a digest-pinned official Kali Rolling image and the repository's Dockerfile, tool mapping, and artifact lock. Non-APT artifacts must pin a version or revision and SHA-256.

This candidate was supplied from Docker Build Cloud, not GitHub Actions. Its OCI revision label is `b1450eb70bb1-dirty`. It must not be represented as accepted or fully reproducible from a clean 40-character Git revision. The replacement release must be rebuilt from a clean commit, carry the complete commit SHA, and pass the Amass functional probe.

## Deployment gates and rollback

Before switching, verify the Hub index/platform manifests, local VM `RepoDigests`, configured platform, inventory image/platform/content digest, and the actual image used by a newly created conversation container. Container failures must not fall back to host execution. The egress gateway remains a separate minimal `cyberstrike/egress` image.

Keep the previous configuration and inventory backup. Restore the previous repository/digest/inventory tuple, restart CyberStrikeAI, and rebuild affected RuntimeSpecs. Remove old Agent/Strix images only after end-to-end acceptance and after confirming that no container references them.
