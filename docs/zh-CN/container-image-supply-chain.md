# Agent 与 Egress 容器镜像供应链

CyberStrikeAI 当前使用 Docker Hub 上的自有多架构 Agent 镜像，不再使用 Strix 作为运行时基础镜像。生产配置必须引用不可变 digest，`latest` 只用于人工发现版本，不能作为运行时信任根。

## 当前已部署候选

| 项目 | 值 |
| --- | --- |
| 仓库 | `ruoji6/cyberstrikeai-agent` |
| 版本标签 | `full-tools-slim2-20260825`、`latest` |
| 多架构 index digest | `sha256:a535bbe3da57a2d103df60fbca37fdd7b8937c882d8b49e9be49050b9d974f50` |
| ARM64 manifest | `sha256:13b24dec5541d7bac77ce439c7dab5044a2fd5775987924e5bbdd9414e354b8f` |
| AMD64 manifest | `sha256:4e8d11662efa90c700a3d48241fa303f992d6ad04a195323a0da8fc329736b85` |
| ARM64 inventory | `container/agent-tool-inventory-linux-arm64.json` |
| inventory 内容摘要 | `sha256:3664b426c9de1cb86fa914f336005c797685eff18643bdae0f78e5c8ff7437b4` |

`latest` 与版本标签当前指向同一个 index digest。ARM64 虚拟机从 Hub 直接拉取该镜像，并以 `repository@digest` 运行；本地 tag 不能替代 digest 校验。该 digest 已通过 ARM64 全工具功能门禁和无网络容器安全冒烟，包括 `/usr/local/bin/amass` wrapper。生产配置和 inventory 已切换到该 digest；旧 Agent 镜像仅因仍有现存对话容器引用而保留，不得强制删除。

## 当前 Egress 发布版本

| 项目 | 值 |
| --- | --- |
| 仓库 | `ruoji6/cyberstrikeai-egress` |
| 版本标签 | `fast-reject-20260825`、`latest` |
| 多架构 index digest | `sha256:5e9c03756eea3ca22a0fb3a6235d8fdf9ee0a992af36c64f367e664d9423c3d5` |
| ARM64 manifest | `sha256:5c109b32fe43418e154f2ce20d60fca6ea23ae29090edcdc9b7376f6473d7905` |
| AMD64 manifest | `sha256:588cdb0c6cc63935d430ff1ca1e99782a425a856d84a62d70d6b82d090bfc0fa` |
| OCI revision | `1b00ebb1215fb08b25958e2c251b727af1afe003` |

Egress 镜像也从 Docker Hub 按 index digest 拉取。ARM64 镜像已通过只读 rootfs、`cap-drop ALL`、仅增加 `NET_ADMIN`/`NET_RAW`、`no-new-privileges` 和不可变边界快照健康检查；生产虚拟机还通过了 HTTP、TCP/UDP 混合放行与阻断、持久审计链、服务重启和实际运行镜像摘要验收。该版本会立即拒绝已判定阻断的 TCP/UDP 目标元组；混合端口扫描按 `(IP, 端口, 协议)` 独立判定，阻断端口不会终止或误伤同批允许端口。

## 工具与平台范围

- 配置覆盖为 77/77 个启用工具；`prowler` 因 512 MiB 运行限制下稳定 OOM 已禁用并从镜像移除。
- AMD64 映射声明支持 77/77。
- ARM64 映射声明支持 75/77；`pwninit` 和 `x8` 因当前锁定来源仅提供 AMD64 而被明确排除，不会用空脚本伪装成功。
- ARM64 inventory 共 81 个可执行命令或运行时条目；已完成无网络、只读 rootfs、`cap-drop ALL`、`no-new-privileges`、非 root 用户结构探针。

## 构建与可追溯性

镜像基于 digest 锁定的官方 Kali Rolling 基础镜像，通过仓库内的 Dockerfile、工具映射和锁文件构建。非 APT 制品必须锁定版本/提交和 SHA-256；发布前运行配置覆盖、平台映射和镜像内探针。

本次候选由用户提供的 Docker Build Cloud 制品发布，不是 GitHub Actions 构建。OCI `revision` 标签为干净提交 `1007db0523a18c0f123d3a19899648eff57a91fb`，版本标签为 `full-tools-slim2-20260825`；ARM64 镜像已通过 Amass 和其余平台声明支持工具的功能探针。

`scripts/verify-container-release.sh` 支持分别传入 Agent 与 Egress revision，因为两个镜像可以由不同的干净提交发布。当前 ARM64 镜像组合已通过禁网 SPDX 2.3 OS 软件包清单与 `SHA256SUMS` 回读（Agent 859 个包、Egress 112 个包）；独立的 Agent 工具 inventory 仍是镜像内安全工具功能范围的权威依据。

## 部署门禁

切换前必须同时核对 Hub index 的 ARM64/AMD64 平台和平台 manifest、VM 本地 `RepoDigests`、配置平台、inventory 的镜像/平台/内容摘要，以及新建对话容器的实际镜像。执行失败不得回退宿主机。

出站网关仍是单独的最小 `ruoji6/cyberstrikeai-egress` 镜像；Agent 全工具镜像不会替代网关，也不能通过增加 Agent 工具放宽网络策略。

## 回滚

保留切换前的 `config.yaml` 和 inventory 备份，恢复上一组 repository/digest/inventory 后重启服务，并为受影响对话重建 RuntimeSpec。旧 Agent/Strix 镜像只有在新镜像端到端验收通过、确认无容器引用后才可删除。

完整执行清单见[全工具 Agent 镜像构建、发布与验收计划](full-agent-image-build-acceptance-plan.md)。
