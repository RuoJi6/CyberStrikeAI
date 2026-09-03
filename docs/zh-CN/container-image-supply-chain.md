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
| 版本标签 | `network-access-v5-20260903-e5530838`、`latest` |
| 多架构 index digest | `sha256:17c106a08688000fb6d9385b237f7025296cdaa6eee22817f79851d1324a05dc` |
| ARM64 manifest | `sha256:8457ab74f0d4051624fbf674df52c32947ad79d603f19481fa70017a23a9eece` |
| AMD64 manifest | `sha256:0ac36ef34209adf8974cbd038c195a6708cc02a970848edc0067d61a32f5e44a` |
| OCI revision | `e5530838f36cf4c72e0936ce5a5ce5ad265b0578` |

Egress 镜像从 Docker Hub 按 index digest 拉取，`latest` 指向同一个 index。AMD64 与 ARM64 分别在对应原生架构上构建；两个平台的运行层均为 gzip 压缩，AMD64 为 36.45 MiB，ARM64 为 37.58 MiB。AMD64 manifest 保留 BuildKit 来源证明，拆分发布的 ARM64 manifest 不包含证明附件。运行态验收要求只读 rootfs、`cap-drop ALL`、仅增加 `NET_ADMIN`/`NET_RAW`、`no-new-privileges` 和不可变边界快照。

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
