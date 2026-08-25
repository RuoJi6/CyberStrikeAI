# Agent 容器镜像供应链

CyberStrikeAI 当前使用 Docker Hub 上的自有多架构 Agent 镜像，不再使用 Strix 作为运行时基础镜像。生产配置必须引用不可变 digest，`latest` 只用于人工发现版本，不能作为运行时信任根。

## 当前已部署候选

| 项目 | 值 |
| --- | --- |
| 仓库 | `ruoji6/cyberstrikeai-agent` |
| 版本标签 | `full-tools-slim1-20260825`、`latest` |
| 多架构 index digest | `sha256:524788d05d4b5a66b569efe1f57a6ae49ad792eddfa7e44ce67a798c918afebb` |
| ARM64 manifest | `sha256:22714122c415f5cb8e6e51fdf2660f0174a06f5d12354c6a858d273c5f5557c3` |
| AMD64 manifest | `sha256:0114f51b57605fc64d25acf61f1b882c5c28ea40942770932ece3c2cc723193c` |
| ARM64 inventory | `container/agent-tool-inventory-linux-arm64.json` |
| inventory 内容摘要 | `sha256:a0da4e891f68f16edb8cd1294340314c5af61e19e6f2aa7fc905c4084a2e21f8` |

`latest` 与版本标签当前指向同一个 index digest。ARM64 虚拟机从 Hub 直接拉取该镜像，并以 `repository@digest` 运行；本地 tag 不能替代 digest 校验。该 digest 还不是最终验收版本：结构探针通过，但 `amass -version` 命中 Kali 的 sudo 启动器并被 `no-new-privileges` 拒绝。仓库现已加入 `/usr/local/bin/amass` wrapper，必须由 Docker Build Cloud 基于干净提交重建并发布新 digest 后，才能通过全工具门禁。

## 工具与平台范围

- 配置覆盖为 77/77 个启用工具；`prowler` 因 512 MiB 运行限制下稳定 OOM 已禁用并从镜像移除。
- AMD64 映射声明支持 77/77。
- ARM64 映射声明支持 75/77；`pwninit` 和 `x8` 因当前锁定来源仅提供 AMD64 而被明确排除，不会用空脚本伪装成功。
- ARM64 inventory 共 81 个可执行命令或运行时条目；新候选发布后须重新完成无网络、只读 rootfs、`cap-drop ALL`、`no-new-privileges`、非 root 用户结构探针。

## 构建与可追溯性

镜像基于 digest 锁定的官方 Kali Rolling 基础镜像，通过仓库内的 Dockerfile、工具映射和锁文件构建。非 APT 制品必须锁定版本/提交和 SHA-256；发布前运行配置覆盖、平台映射和镜像内探针。

本次候选由用户提供的 Docker Build Cloud 制品发布，不是 GitHub Actions 构建。OCI `revision` 标签为 `b1450eb70bb1-dirty`，因此它不能被描述为“已完成验收”或“由干净的 40 位 Git 提交完全复现”。替换版本必须从干净提交重建、把完整提交 SHA 写入 OCI 标签，并通过 Amass 功能探针。

## 部署门禁

切换前必须同时核对 Hub index 的 ARM64/AMD64 平台和平台 manifest、VM 本地 `RepoDigests`、配置平台、inventory 的镜像/平台/内容摘要，以及新建对话容器的实际镜像。执行失败不得回退宿主机。

出站网关仍是单独的最小 `cyberstrike/egress` 镜像；Agent 全工具镜像不会替代网关，也不能通过增加 Agent 工具放宽网络策略。

## 回滚

保留切换前的 `config.yaml` 和 inventory 备份，恢复上一组 repository/digest/inventory 后重启服务，并为受影响对话重建 RuntimeSpec。旧 Agent/Strix 镜像只有在新镜像端到端验收通过、确认无容器引用后才可删除。

完整执行清单见[全工具 Agent 镜像构建、发布与验收计划](full-agent-image-build-acceptance-plan.md)。
