# Passwall-Node 交接文档

> 你接手的是**一个由外部控制面驱动的 xray / sing-box 节点后端**。
> 控制面（[Passwall-Sub-Panel](https://github.com/KazuhaHub/Passwall-Sub-Panel)）决定一切，本项目只执行和上报。
>
> **设计记录不在这个仓库**,在 PSP 的 `docs/psp-node-agent.md`（为什么这样定）
> 和 `docs/psp-node-plan.md`（做什么、什么顺序）。本文档只讲**这个仓库**的事。

## 1. 现在有什么（B1 / B2 / C2 / B3-Xray / B3-sing-box 已完成，2026-09-11）

```
protocol/     线上契约，本地实现已定稿
  keys.go       ClientKey / SubjectKey —— 两个不能互换的类型
  version.go    Version{Epoch, Version} —— 成对，不是裸 int64
  segments.go   Segment[T] + 三段的 body
  report.go     NodeReport —— 节点的上行
  envelope.go   SyncResponse + Envelope + ShouldSendFull
  validate.go   不可信报告的唯一边界校验
  protocol_test.go
internal/agent/       HTTP 拨出、三段接收、可重入应用、报告与调度
internal/state/       持久化端口
internal/state/sqlite SQLite schema v7：流、对象、计数、配额闸、幂等 outbox、core 部署与 sing-box 事件账本
cmd/contract-agent/   C2 真 agent 契约执行器（仅 core 为确定性替身）
cmd/node/             生产 daemon：同步、安装、编译、运行、观测、离线执法、优雅退出
internal/core/        Compiler / Supervisor / Telemetry + Xray / sing-box 实现
corecatalog/          精确、校验和固定、跨平台的 Xray / sing-box 版本目录
.github/workflows/    test/race/vet、六平台编译、Release + GHCR 多架构镜像
```

**Xray 与 sing-box 生产路径均已接通。** 一轮同步把本地观测、期望文档接收和至多一次 core 收敛串成一个提交边界；
精确 core 安装、配置校验、原子替换、失败回滚、重启前 digest 核验、Xray 计数读取与断网时到期/配额
停用都在生产 composition root 中。三类长期服务由统一 supervisor 管理，任何一项异常都会取消并排空
其余服务，goroutine panic 不会悄悄留下半活进程。

sing-box 固定核验 `1.14.0`，原生编译 VLESS、VMess、Trojan 和 Shadowsocks-2022。其官方 API
仅绑定回环地址并使用本机持久随机 Bearer secret；长期 gRPC 连接事件先进入 SQLite 幂等账本，再汇成
用户/监听累计计数。重连 reset 以绝对计数去重，core 重启结转已落盘累计值。reset 中缺失先前已知的
活跃连接会明确报 `core_telemetry_gap`；但 sing-box 上游只保留最近 1000 条关闭连接，且 reset 没有单调
cursor/完整性标记，
因此断线期间“完全新建又关闭、且已被历史淘汰”的连接目前无法被证明或归户。不得声称任意长断线下精确计量。
`TestRealityHandshakeMatrix` 用本地 TLS 伪装端与 HTTP 目标实际跑通 Xray 26.6.27、Mihomo 1.19.30、
sing-box 1.14.0 三客户端，目录中的 handshake evidence 对应这条可重复测试。

HTTP/SQLite/apply/report 已由
PSP 的 `TestLive_RealNodeAgentContract` 启动真实进程跑过两轮合流验收。跨仓发布顺序固定为：
先发布本仓库，再更新 PSP 的 pseudo-version；发布前 PSP 只可通过父目录 `go.work` 联调。

## 2. 一分钟看懂协议

节点**主动连**面板，一个端点、一次往返、双向：

```
        POST /v1/node/sync
节点 ──────────────────────────▶ PSP
     上行 NodeReport（我持有哪些版本、收敛到哪一步、计数器）
     下行 SyncResponse（三段带版本的内容 + 信封）
```

三个流，各自独立编版本，装在同一个响应里：

| 流 | 装什么 | 为什么单独一段 |
|---|---|---|
| `config` | 监听器 | **reload 隔离**——停用一个用户不该让监听器配置的 ETag 失效 |
| `roster` | 客户端名册 | 变动最频繁的那一份 |
| `directives` | 配额、影子并发预算 | 由 PSP 聚合全车队后算出，与前两者节奏不同 |

**两个周期，都由 PSP 在响应里下发，节点不存策略：**

| | 字段 | 默认 | 决定什么 |
|---|---|---|---|
| 轮询周期 | `next_poll_seconds` | **30 秒** | 配置多快到达节点 |
| 全量上报周期 | `full_report_seconds` | **60 秒** | 车队计数拼图能有多陈旧 |

轻量轮询带 `partial: true`,省掉 `objects` / `listener_counters` / `clients` / `subjects`。
判定用 `protocol.ShouldSendFull`,**不要自己写一遍**。

## 3. 下一步做什么

### B1 — `protocol/conformance` 一致性测试

**状态：已完成。** 引用完整性、对象四态与配额残差都有变异体/反例测试。

类型已经守住了六条决定（见 [README](README.md) 的表）。剩下三条**类型守不住，只能靠测试**：

1. **引用完整性的三态裁定**
   - `roster_ahead_of_config` = **自愈中的正常态，不告警**,超过 K 轮才升 Issue
   - 版本闭合但 key 找不到 = `attachment_unknown_listener`,PSP 侧缺陷
   - 监听器被拒 → 该挂载记 `blocked`,**该 client 不得判 applied**
2. **闸态迁移**:`applied` / `pending` / `rejected` / `blocked` 之间哪些迁移合法，
   以及 `pending` 与 `rejected` 两个可超时态的超时行为
3. **残差算术**:滞后的聚合值**不许被表述成「满足了上限」**

**完成判据**:每组都要能被一个**故意写错的实现**打红。写完之后对每条至少构造一个变异体，
确认它真被抓住——本项目反复出现的失效模式是「测了函数，没测调用点」。

### B2 — agent 骨架

**状态：已完成。** 真实 HTTP client、SQLite schema v7、三段独立接收、可重入 join、
config add/update → roster → config delete 顺序、epoch 恢复、全量/轻量报告、配额周期推进、
对象超时升级与幂等 outbox 均已落地。outbox 成功投递后保留 dedupe tombstone：持续存在的
同一问题不会在每轮重新触发即时上报、把未来生产同步循环拖进无间隔自旋。

`POST /v1/node/sync` 的客户端侧、三段的应用、状态上报。**先不碰 core。**

必须照做的几条（写错了很难在后期发现）：

- **应用顺序**:config 新增与修改 → roster 全量 → config 删除
- **join 必须可重入**。**禁止 `requires_config_version >= N` 这类门**——
  可重入的 join 严格强于一个有序投递保证
- **交集为空仍物化 client,绝不删除**（删除会让累计计数从 0 重来）
- **epoch 变高就清零本地已提交版本**。没有这条，一次 DB 还原会让 agent 永久拒收、
  无限期以旧配置服务，唯一出路是重装——**而 DB 还原是常规运维事件**
- **心跳数字没变也发**
- **`objects[]` 对 clients 是含零值的全量枚举**（`partial=false` 时）
- **产生 Issue 时不等周期，立即发一次报告**（用 `partial` 报告）。
  上行事件驱动、下行定时轮询——因为「有东西要取」只有 PSP 知道
- config / roster 的覆盖度必须与本地全量物化集合精确相等；directives 的覆盖度是 PSP
  声明的**全车队分母**，只要求不小于本机收到的条目，不能误判为本机数组长度
- **相同配额文档重放必须是内容幂等**。本地跨过周期边界后不能被旧文档复活上一期授权；
  每次同步（包括 partial）在生成报告前先推进到期授权
- **`Applied` 只能是字节真收到并落盘的版本**,绝不是从 `unchanged` 响应上读来的
- `(epoch, version)` 必须两项都为正；半零坐标在接收、状态机、SQLite 三层都拒绝
- 已 applied 且内容和 listener 依赖都未变的 client 不触碰 runtime；pending / blocked 仍重试
- §9 定义任务执行与 exactly-once 状态前，非空 `tasks[]` 明确拒绝，绝不静默吞掉
- 同步单向载荷上限统一由协议包固定为 16 MiB；Issue 字段在进入 outbox 前 UTF-8 安全截断，
  live IP 在持久化前解析、去重并规范化，避免一个坏观测永久毒化后续报告
- 响应调度字段在 outbox 确认前整体校验（心跳至多 1 小时、全量周期至多 1 天）；
  分段缺陷仍按协议只拒收该段，不能把独立流退化成全有或全无
- 删除集每轮都由“当前文档 vs 本地持久化 runtime 行”重算，不能只依赖首次变更的 old/new diff；
  runtime 删除失败会跨后续 `unchanged` 心跳重试，成功后 runtime 与对象状态同事务清理

### B3 — core 配置生成 + 进程管理

**明确排最后。** 前面的价值全部依赖对着真 PSP 的契约测试能跑起来；
先写 core 会得到一堆没有验收标准的代码。

**状态：Xray 与 sing-box 路径已完成（2026-09-11）。** 发布矩阵与 PSP 一致（六平台二进制 + Linux
amd64/arm64 Docker）、core
采用 `Compiler / Supervisor / Telemetry` 三端口且先实现 Xray、TLS 证书由 PSP 管理并由 agent
原子安装。`corecatalog/` 是 Node 安装/编译与 PSP 选择器共用的唯一目录：只接受精确列出的版本，
不接受 `latest`，每个平台资产固定官方 SHA-256，受限版本必须显式确认。Xray 默认固定
`26.6.27`；`26.7.28` 自动写 `minClientVer=0.0.0`，三客户端握手已核验；`26.9.9` 只允许
Xray 与 `chrome + support-x25519mlkem768` 的 Mihomo，sing-box 的失败也已作为预期失败写进证据。
完整 REALITY 兼容门见 PSP ADR 0029。PSP 已接通严格 Bearer `/v1/node/sync` 生产路由；创建
原生节点时铸造 agent ID + 长期随机凭据，只存 SHA-256 摘要、原文只展示一次，且支持立即吊销旧值的
一次性凭据轮换。`Client.ExpiresAtMS` 已由 PSP 的单一有效到期链铸造，runtime 在 PSP 断线时仍按
绝对截止时间本地停用。断线后才发生的人工/策略撤销若要更短窗口，仍需租约或第二通道。

sing-box `1.14.0` 的六平台官方资产同样固定 SHA-256，安装器支持安全的嵌套 tar.gz/ZIP 解包；切换
engine/version/binary/命令参数是一个原子部署身份，启动失败会整体回滚。当前 sing-box 编译范围刻意
限制为 VLESS、VMess、Trojan、Shadowsocks-2022；没有证据的协议不进入“推荐”承诺。
遥测重连能对已知活跃连接去重和查缺，但上述 1000 条历史边界是未解决的运营风险；在上游提供单调 cursor，
或我们加入可独立核对的全局累计边界前，长时间 telemetry 中断后的计数必须视为有条件，不能视为数学上完整。

后续增量：agent 自升级、带 exactly-once 状态的任务协议、RealityProbe。不要为了实现这些能力复用
或放宽当前 `tasks[]` 的明确拒绝语义。

## 4. 十条不要

1. **不要把 email 或任何派生串当主键**——包括 `partKey.canon()`,它是**位置相关**的
2. **不要加 `requires_config_version >= N` 的门**
3. **不要给三态字段加 `omitempty`**（`headroom_bytes` 的 `null`/`0`/`N` 必须可分辨）
4. **不要让心跳在没有流量时跳过**（上游 V2bX 正是这样翻的车）
5. **不要让 `NodeReport` 写 `desired_*`**;健康探测目标只能来自期望文档
6. **不要把版本差当存活信号**——失联判定是 PSP 侧的 `last_seen`
7. **不要在 `rejected` 上无限重试而不超时**——它是唯一「重试同一内容无用」的终态
8. **不要让一台 agent 服务多个 panel 作用域**
9. **不要把时间戳或版本号放进 ETag**——ETag 是纯内容
10. **不要把「断网」当成放行的理由**。条目缺席 = 保持上次的 `(baseline, headroom)`,
    **没有 TTL,永不解释成无限额**;`unconfigured` 也不等于无限额

## 5. 怎么验收

**C2 已通过。** 在 PSP 仓库运行：

```bash
PSP_LIVE_NODE_REPO=/absolute/path/to/Passwall-Node \
  go test ./internal/service/nodesync -run TestLive_RealNodeAgentContract -v
```

它启动本仓库的 `cmd/contract-agent`，不是 PSP 侧假造一个客户端；两轮覆盖 HTTP、SQLite、
apply、report 与 PSP `PanelClient` 投影。B3 后仍应保留这条为跨仓发布闸门。

## 6. 协议是公开契约

`protocol/` 里的类型是**对外承诺**。目标是别人也能用这个后端，代价是：
协议要对外文档化、保持稳定，破坏性变更要走废弃周期。
**这是一项长期成本，接受它是这个项目的前提之一。**

改协议之前先读 PSP 的 `docs/psp-node-agent.md` §8.5「关掉了哪些选项」——
有些门是**永久关闭**的，重新打开需要一次破坏性协议升级。
