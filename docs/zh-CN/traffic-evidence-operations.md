# 流量证据与 Transform Runner 运维

> 适用分支：`codex/mitm-traffic-evidence`（基于 `codex/docker-agent-runtime`）  
> 当前范围：Docker Agent 强制抓包、Host Agent 尽力抓包、HTTPS MITM、漏洞证据、离线脚本测试和异步 observe 解码

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

Host Agent 子进程
  → 每对话 127.0.0.1 随机端口代理（仅注入子进程环境）
      ├─ HTTP：保存完整语义请求/响应
      ├─ HTTPS：注入短期对话 CA 后执行 TLS MITM
      └─ fuzz/突发：复用相同聚合策略
  → 直接写入 SQLite，并触发相同的 active observe decode
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

## 4. 重发捕获请求

在“流量证据”打开一个完整请求，点击“发送到重发包”即可载入方法、URL、Header 和 UTF-8 正文。重发器遵守以下边界：

- 根据原事务的可信 `conversation_id` 解析执行后端；容器事务仍在原对话容器中执行，本机事务仍在控制面本机执行。
- 用户可以修改方法、路径、查询参数、Header 和正文，但协议、主机和端口必须与原事务保持一致。
- `Host`、`Content-Length`、hop-by-hop Header 和代理认证 Header 由重发器管理，不能手动覆盖。
- 当前只重发正文完整的 UTF-8 请求；二进制或已截断正文会拒绝。
- 重发前按对话、协议、网站、方法、路径和 Content-Type 匹配启用的 Transform。存在 `encode_request` 时按优先级执行第一个匹配脚本的 `decode_request → mutate_request → encode_request` 链，再把最终密文报文交给原执行后端。
- 只有 `decode_request` 的旁路脚本会在 observe 模式检查编辑器中的原始密文，但其解密输出不会替换待发送数据；重发器仍原样发送编辑器中的 wire request，因此不再因为缺少 `encode_request` 拒绝重发。
- 脚本包含 `mutate_request` 却缺少 `encode_request`、完整重编码链执行失败或返回非法报文时仍失败关闭，绝不会把中间明文发给目标。旁路解密失败时遵守 observe 的 continue 策略，原样发送密文并在响应元数据中明确标记失败。
- 容器和本机重发仍经过对应对话 Gateway，因此会形成新的流量事务；重发器使用会被 Gateway 消费并删除的内部归因 Header 记录规则/版本，Header 不会发送给目标，用户输入也不能伪造该字段。
- 证据列表和详情会标记事务已由脚本处理；存在 observe 解码输出时，进一步突出显示 `decoded_request`/`decoded_response`。

REST 接口是 `POST /api/traffic-transactions/:id/replay`，需要 `traffic:replay` 和 `traffic:read_sensitive`；响应包含原始 HTTP 响应、状态码、实际执行位置，以及 Transform 是否匹配、是否执行和 `inline`/`observe`/`passthrough` 策略等安全元数据。

## 5. Agent 或用户编写和使用加解密脚本

Agent 通过以下顺序使用，不需要也不能创建自己的网络监听服务：

1. `list_traffic_transactions` 找到普通事务或 fuzz 代表事务。
2. `get_traffic_transaction` 读取完整 wire message，判断密文位于 query、Header 或 body。
3. `create_traffic_transform` 提交 Python 源码、Hook 和锁定依赖，形成不可变 revision。
4. `validate_traffic_transform` 在隔离 Runner 内做语法、AST、依赖和 Hook 校验。
5. `test_traffic_transform` 对历史完整报文执行 decode→mutate→encode dry-run，检查 round-trip 和每个阶段 hash。
6. `activate_traffic_transform` 只能由 Agent 激活 `observe`，并且必须通过 `matcher.hosts` 限定目标网站；可继续用路径、方法和正文类型收窄。同一对话中的其他网站不会进入脚本 Runner。新证据导入后异步生成 `decoded_request`/`decoded_response`，不改变线上流量。
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

有 `traffic_transform:write` 权限的用户也可在“加密解密 → 手写脚本”直接填写源码、历史事务和目标网站。`POST /api/traffic-transforms/manual` 会依次创建不可变 revision、在隔离 Runner 中验证、对所选历史包 dry-run，并可在全部通过后创建限定 `matcher.hosts` 的 observe binding。该入口不会授予脚本额外能力，也不能由用户界面绕过 Runner 或站点匹配。

“加密解密”不再提供独立的“使用案例”视图：脚本是唯一主对象，选择脚本后可在右侧“作用范围”中查看其全部 observe binding。有 `traffic_transform:activate_observe` 权限的用户可通过“新增作用范围”将已有脚本注入有权访问的对话，并配置网站、协议、方法、路径、Content-Type、优先级和是否立即启用；现有范围也可继续编辑并独立启停。已停用的作用范围可以删除，删除只移除 binding 与其中的配置，脚本 revision、流量证据和历史运行记录继续保留。该界面和接口不会返回或覆盖可能包含密钥、IV 的 binding config。inline binding 仍需要后续独立审批能力，不能从该界面启用、修改或删除。

脚本详情提供脚本级编辑与删除。修改源码会先完成静态检查和隔离 Runner 验证，通过后生成新的不可变 revision 并切换现有 observe binding；验证失败不会替换当前版本。脚本只有在全部作用范围均已删除后才能删除，删除采用软删除，因此 revision 和 Runner 历史仍可审计。页面的 Runner 视图只展示执行时间、Hook、模式、动作、耗时、事务和 Runner 身份等安全元数据；关联脚本已软删除时明确标为“脚本已删除”。源码弹窗按行显示行号和总行数。

## 6. 本机执行与容器执行的区别

| 能力 | Docker Agent | Host Agent |
| --- | --- | --- |
| HTTP 出口经过 Gateway | 已实现，`enforced` | 已实现代理环境注入，`best_effort` |
| 完整 HTTP 语义报文 | 已实现 | 已实现，客户端需遵循代理变量 |
| HTTPS 应用层语义报文 | 已实现对话 CA/TLS interception | 已实现临时对话 CA/TLS interception |
| Transform dry-run | 已实现，与运行模式无关 | 可对已有历史事务使用 |
| 修改并重发捕获请求 | 已实现，沿原对话容器边界执行并再次捕获 | 已实现，沿原本机边界执行；捕获仍为尽力覆盖 |
| active observe 自动解码 | 已实现 | 已实现 |
| 重发包 inline 修改并重新编码 | 已实现，匹配规则后发送前执行 | 已实现，匹配规则后发送前执行 |
| 普通 Agent 实时流量 inline 修改 | 尚未实现 | 尚未实现 |

Host 现在为每个对话懒加载一个带随机认证凭据的 loopback Gateway，并由 `ProxiedExecutionBackend` 只给本次子进程注入大小写 `HTTP_PROXY`、`HTTPS_PROXY`、常见客户端 CA 变量和 `NO_PROXY`；CA 文件由宿主系统根证书与对话 CA 组合，不破坏 `NO_PROXY` 直连 HTTPS 的原有信任。该实现不修改系统全局代理或信任库。CA、代理凭据和监听端口均按对话隔离，应用关闭后清理。Host 程序仍可忽略代理变量、证书固定、直接建立 socket，或因私有/回环地址命中 `NO_PROXY` 而绕过，因此只标记为 `best_effort`；若要求强制全流量，需要单独的 TUN/透明代理与管理员授权。

## 7. 当前限制

- “完整数据包”是解析后的 HTTP 消息，不是 TCP 分段或 PCAP。
- 单方向正文最多保存 10 MiB；超限记录真实长度并标记 `complete=false`。
- 不遵循代理/CA 环境变量、启用证书固定或直接使用原始 socket 的 Host 客户端不会形成完整 HTTPS 证据。
- inline 实时 mutate/encode、管理员审批和二次边界校验尚未接入 Gateway；Agent 无法自行激活 inline。
- 当前 observe Runner 是控制面共享的私有无状态实例，后续才演进为每对话 sidecar。
- 正文 blob、配额、保留周期和导出仍需后续实现。
