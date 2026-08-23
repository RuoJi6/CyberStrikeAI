# ARM64 容器镜像供应链

CyberStrikeAI 的 Agent 运行环境和每对话出站网关均使用本地构建、digest
锁定的 `linux/arm64` 镜像。生产配置不得使用浮动 tag。

## 构建边界

- 在受控 ARM64 部署虚拟机上，从已审查 Git 提交构建两个镜像；该发布路径不使用 GitHub 托管构建。
- 两个 Dockerfile 都必须传入 `BUILD_DATE`、`SOURCE_URL`、`VCS_REF` 和 `VERSION`。
- Agent 基础镜像和出站网关 Go 构建镜像已在 Dockerfile 中按 digest 锁定。
- 将构建结果的本地镜像 ID（`sha256:...`）作为运行时配置 digest。
- 必须针对该 Agent 镜像的精确 digest 重新生成工具 inventory。

## 离线验证包

在虚拟机上运行 `scripts/verify-container-release.sh`，传入带 digest 的本地镜像引用、
精确工具 inventory 和新的输出目录。脚本会：

1. 校验 `linux/arm64`、镜像 ID、非 root 用户、入口、源码地址和提交 OCI 标签；
2. 使用 digest 锁定 Agent 镜像内的 Trivy 0.73.0，在断网状态下扫描 Agent 文件系统和已导出的网关 rootfs，生成 SPDX JSON SBOM；
3. 校验工具 inventory 与 Agent 镜像精确 digest 绑定；
4. 写入标准化镜像元数据和 `images.json`；
5. 生成并回读校验 `SHA256SUMS`；
6. 可选运行两个镜像的加固冒烟测试。

输出目录就是离线验证包，应与部署记录一起保存，不应拷贝进应用镜像或源码仓库。

## 运行时校验与回退

开启容器模式前，必须确认配置中的镜像仓库、digest、平台、inventory digest 和
网关 digest 与验证包一致，任何不一致均失败关闭。回退时恢复上一组 digest 锁定配置与
inventory，重启 CyberStrikeAI，并重建受影响的对话运行时。host 执行仍为默认值，镜像发布
不会改变现有 host 对话。
