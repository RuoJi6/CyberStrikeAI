# 流量证据与 Transform Runner 运维

> 适用分支：`codex/mitm-traffic-evidence`（基于 `codex/docker-agent-runtime`）  
> 当前范围：Docker Agent 抓包、HTTPS 隧道元数据、漏洞证据、离线脚本测试和异步 observe 解码

## 1. 当前数据路径

```text
Agent 容器
  → 每对话 Egress Gateway
      ├─ HTTP：保存完整语义请求/响应
      ├─ HTTPS 未解密：保存 CONNECT 与隧道字节统计
      └─ fuzz/突发：保存一个完整代表事务和聚合摘要
  → 每对话 spool 子目录
  → 控制面校验并导入 SQLite
  → [可选] 私有 Transform Runner 执行 active observe decode
  → 流量证据页面 / 漏洞详情 / Agent MCP
```

Gateway 只挂载当前对话 spool 子目录。Agent 和 Transform Runner 都不挂载 spool；完整正文也不经过 Docker stdout。spool 总目录是 `0700`，会话子目录只向无 capabilities 的 Gateway 开放 write+traverse，导入器会校验目录会话 ID、schema、事务和消息后才写库。

## 2. 配置 Docker 抓包

在 `config.yaml` 启用 `container`，并配置由本次代码构建的、固定 digest 的 Agent 与 Egress 镜像：

```yaml
container:
  enabled: true
  owner_id: your-unique-deployment-owner
  image_repository: your-agent-image
  image_digest: sha256:...
  image_platform: linux/arm64
  egress_image_repository: your-egress-image
  egress_image_digest: sha256:...
  egress_image_platform: linux/arm64
  egress_snapshot_dir: data/egress-snapshots
  traffic_spool_dir: data/traffic-spool
```

`traffic_spool_dir` 必须位于控制面可访问的本地文件系统。远程 Docker Engine 暂不支持直接复用此 bind-mount ingestion 方式。

创建 `runtimeMode=container` 的对话后，平台会自动把 Agent 的 HTTP(S) 出口强制经过对话 Gateway；页面将这类记录标为 `enforced`。

## 3. 启动隔离 Transform Runner

Runner 不发布宿主端口，只连接 Docker internal network。首次启动会构建镜像并生成权限为 `0600` 的随机 token：

```bash
./scripts/run-transform-runner.sh build
./scripts/run-transform-runner.sh start
```

`start` 输出控制面所需的两个环境变量。使用输出值启动 CyberStrikeAI，例如：

```bash
export CYBERSTRIKE_TRANSFORM_RUNNER_URL=http://172.x.x.x:9089
export CYBERSTRIKE_TRANSFORM_RUNNER_TOKEN_FILE=/absolute/path/data/traffic-transform-runner.token
./cyberstrike-ai --config config.yaml
```

Runner 约束包括：非 root、只读 rootfs、`cap-drop=ALL`、`no-new-privileges`、32 PID、256 MiB、0.5 CPU、无公网，以及仅只读挂载 token。控制面向 Runner 发送 revision；Runner 不连接数据库、Docker Socket、Agent 工作区或目标系统。

## 4. Agent 编写和使用加解密脚本

Agent 通过以下顺序使用，不需要也不能创建自己的网络监听服务：

1. `list_traffic_transactions` 找到普通事务或 fuzz 代表事务。
2. `get_traffic_transaction` 读取完整 wire message，判断密文位于 query、Header 或 body。
3. `create_traffic_transform` 提交 Python 源码、Hook 和锁定依赖，形成不可变 revision。
4. `validate_traffic_transform` 在隔离 Runner 内做语法、AST、依赖和 Hook 校验。
5. `test_traffic_transform` 对历史完整报文执行 decode→mutate→encode dry-run，检查 round-trip 和每个阶段 hash。
6. `activate_traffic_transform` 只能由 Agent 激活 `observe`。新证据导入后异步生成 `decoded_request`/`decoded_response`，不改变线上流量。
7. `link_traffic_evidence` 把原始或代表事务关联到漏洞，角色为 `primary`、`supporting` 或 `retest`。

脚本实现固定 Hook，而不是 shell 命令：

```python
from cyberstrike_transform import Message

def decode_request(ctx, wire: Message) -> Message:
    plaintext = application_decode(wire.body)
    return wire.with_body(plaintext, content_type="application/json")

def encode_request(ctx, logical: Message, original_wire: Message) -> Message:
    ciphertext = application_encode(logical.body)
    return original_wire.with_body(ciphertext, content_type="application/octet-stream")
```

当前 Runner inventory 允许标准库中的安全纯计算模块，并预装锁定版本 `cryptography==38.0.4`。任意文件访问、子进程、动态导入、socket 和网络依赖会被拒绝。脚本配置只能包含 Agent 本来就有权知道的值，平台隐藏凭据不会传给脚本。

## 5. 本机执行与容器执行的区别

| 能力 | Docker Agent | Host Agent |
| --- | --- | --- |
| HTTP 出口强制经过 Gateway | 已实现，`enforced` | 尚未实现 |
| 完整 HTTP 语义报文 | 已实现 | 尚未实现 |
| 未解密 HTTPS CONNECT 元数据 | 已实现 | 尚未实现 |
| Transform dry-run | 已实现，与运行模式无关 | 可对已有历史事务使用 |
| active observe 自动解码 | 已实现 | 等 Host 捕获入口实现 |
| inline 修改并重新编码 | 尚未实现 | 尚未实现 |

Host 后续使用 loopback Gateway 和 `ProxiedExecutionBackend`，只给本次子进程注入 `HTTP_PROXY`、`HTTPS_PROXY`、CA 与追踪令牌，不修改系统全局代理或信任库。Host 程序仍可忽略代理变量或自行建立 socket，因此只会标记为 `best_effort`；若要求强制全流量，需要单独的 TUN/透明代理与管理员授权。

## 6. 当前限制

- “完整数据包”是解析后的 HTTP 消息，不是 TCP 分段或 PCAP。
- 单方向正文最多保存 10 MiB；超限记录真实长度并标记 `complete=false`。
- 未启用对话 CA/TLS interception 时，HTTPS 只显示 CONNECT 和隧道字节数。
- inline 实时 mutate/encode、管理员审批和二次边界校验尚未接入 Gateway；Agent 无法自行激活 inline。
- 当前 observe Runner 是控制面共享的私有无状态实例，后续才演进为每对话 sidecar。
- 正文 blob、配额、保留周期和导出仍需后续实现。
