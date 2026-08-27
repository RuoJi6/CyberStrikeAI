# Agent 与 Egress 容器镜像供应链

CyberStrikeAI 当前使用 Docker Hub 上的自有多架构 Agent 镜像，不再使用 Strix 作为运行时基础镜像。生产配置必须引用不可变 digest，`latest` 只用于人工发现版本，不能作为运行时信任根。

## 当前已部署候选

| 项目 | 值 |
| --- | --- |
| 仓库 | `ruoji6/cyberstrikeai-agent` |
| 版本标签 | `full-tools-seclists-20260826`、`latest` |
| 多架构 index digest | `sha256:14bed42067163e75430e5ea4bf335c18e9631569742da591894c2a1c0a38111d` |
| ARM64 manifest | `sha256:aeacc44686dc93697ede82ab6f1455d49b691b1d70372f1ff8363d38d18ffa1a` |
| AMD64 manifest | `sha256:ae742a453c3627ed984c4a174b83d37a6a5c2404f5c5a171b28fa60e70570dc4` |
| ARM64 inventory | `container/agent-tool-inventory-linux-arm64.json` |
| inventory 内容摘要 | `sha256:83173e182532f08cbbfc67ab2083a3c09e4df428a139a096c4a29b10e1d66759` |

`latest` 当前指向上述 index digest。ARM64 虚拟机从 Hub 直接拉取该镜像，并以 `repository@digest` 运行；本地 tag 不能替代 digest 校验。该 digest 已通过 77/77 配置覆盖、75/77 ARM64 平台支持、全工具功能探针和无网络容器安全冒烟。

## 当前 Egress 发布版本

| 项目 | 值 |
| --- | --- |
| 仓库 | `ruoji6/cyberstrikeai-egress` |
| 版本标签 | `https-default-20260827` |
| 多架构 index digest | `sha256:68e3b5873bb62a1448c22dd689b3d38768663f0f3ad3f402a58a7ee506c20855` |
| ARM64 manifest | `sha256:29473ae320b9e97c6106f4dc6e1ea96b5c442c6d9c8a1c47cbee4a3b94035c56` |
| AMD64 manifest | `sha256:85624a043bcf4d5dfb7407645bf32341cb11944f82c168a58de9d969ea8de00d` |
| OCI revision | `8c75a4fb` |

Egress 镜像也从 Docker Hub 按 index digest 拉取。ARM64 已在虚拟机完成无边界策略 HTTPS 默认解密与完整请求/响应审计端到端验收；AMD64 二进制执行和多架构清单已验证。ARM64 运行时保持只读 rootfs、`cap-drop ALL`、仅增加 `NET_ADMIN`/`NET_RAW`、`no-new-privileges` 和不可变边界快照；该版本保留按目标元组即时拒绝 TCP/UDP 的行为，并保留默认关闭的按对话流量控制。该候选因本地 Buildx 不可用而采用平台镜像组装并发布，未生成发布脚本提供的 SBOM/来源证明，`latest` 标签未随候选移动。

## 工具与平台范围

- 配置覆盖为 77/77 个启用工具；`prowler` 因 512 MiB 运行限制下稳定 OOM 已禁用并从镜像移除。
- AMD64 映射声明支持 77/77。
- ARM64 映射声明支持 75/77；`pwninit` 和 `x8` 因当前锁定来源仅提供 AMD64 而被明确排除，不会用空脚本伪装成功。
- ARM64 inventory 共 81 个可执行命令或运行时条目；已完成无网络、只读 rootfs、`cap-drop ALL`、`no-new-privileges`、非 root 用户结构探针。

## 构建与可追溯性

镜像基于 digest 锁定的官方 Kali Rolling 基础镜像，通过仓库内的 Dockerfile、工具映射和锁文件构建。非 APT 制品必须锁定版本/提交和 SHA-256；发布前运行配置覆盖、平台映射和镜像内探针。

本次候选由用户提供的 Docker Build Cloud 制品发布，不是 GitHub Actions 构建。OCI `revision` 标签为干净提交 `21b1ca30dfda14092a52225a0e1f2ef09572de76`，版本标签为 `full-tools-seclists-20260826`；ARM64 镜像已通过全工具功能探针。

`scripts/verify-container-release.sh` 支持分别传入 Agent 与 Egress revision，因为两个镜像可以由不同的干净提交发布。当前 ARM64 镜像组合已通过禁网 SPDX 2.3 OS 软件包清单与 `SHA256SUMS` 回读（Agent 859 个包、Egress 112 个包）；独立的 Agent 工具 inventory 仍是镜像内安全工具功能范围的权威依据。

## 部署门禁

切换前必须同时核对 Hub index 的 ARM64/AMD64 平台和平台 manifest、VM 本地 `RepoDigests`、配置平台、inventory 的镜像/平台/内容摘要，以及新建对话容器的实际镜像。执行失败不得回退宿主机。

出站网关仍是单独的最小 `ruoji6/cyberstrikeai-egress` 镜像；Agent 全工具镜像不会替代网关，也不能通过增加 Agent 工具放宽网络策略。

## 回滚

保留切换前的 `config.yaml` 和 inventory 备份，恢复上一组 repository/digest/inventory 后重启服务，并为受影响对话重建 RuntimeSpec。旧 Agent/Strix 镜像只有在新镜像端到端验收通过、确认无容器引用后才可删除。

完整执行清单见[全工具 Agent 镜像构建、发布与验收计划](full-agent-image-build-acceptance-plan.md)。
