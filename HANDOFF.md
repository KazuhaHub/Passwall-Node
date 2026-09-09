# Passwall-Node 交接文档

> 你接手的是**一个由外部控制面驱动的 xray / sing-box 节点后端**。
> 控制面（[Passwall-Sub-Panel](https://github.com/KazuhaHub/Passwall-Sub-Panel)）决定一切，本项目只执行和上报。
>
> **设计记录不在这个仓库**,在 PSP 的 `docs/psp-node-agent.md`（为什么这样定）
> 和 `docs/psp-node-plan.md`（做什么、什么顺序）。本文档只讲**这个仓库**的事。

## 1. 现在有什么

```
protocol/     线上契约，已定稿并推送
  keys.go       ClientKey / SubjectKey —— 两个不能互换的类型
  version.go    Version{Epoch, Version} —— 成对，不是裸 int64
  segments.go   Segment[T] + 三段的 body
  report.go     NodeReport —— 节点的上行
  envelope.go   SyncResponse + Envelope + ShouldSendFull
  protocol_test.go
```

**没有 agent 实现。** 这是下一步的主体。

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

轻量轮询带 `partial: true`,省掉 `objects` / `clients` / `subjects`。
判定用 `protocol.ShouldSendFull`,**不要自己写一遍**。

## 3. 下一步做什么

### B1 — `protocol/conformance` 一致性测试

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
- **`Applied` 只能是字节真收到并落盘的版本**,绝不是从 `unchanged` 响应上读来的

### B3 — core 配置生成 + 进程管理

**明确排最后。** 前面的价值全部依赖对着真 PSP 的契约测试能跑起来；
先写 core 会得到一堆没有验收标准的代码。

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

**唯一的验收是对着一个真 PSP 跑的契约测试**（PSP §0.5 约束 3）。
PSP 仓库里已有 `client_live_test.go` / `client_live_surface_test.go` 这类活体测试的先例，照做。

在那之前，一致性测试和单元测试都只是「我们这边的想象」。

## 6. 协议是公开契约

`protocol/` 里的类型是**对外承诺**。目标是别人也能用这个后端，代价是：
协议要对外文档化、保持稳定，破坏性变更要走废弃周期。
**这是一项长期成本，接受它是这个项目的前提之一。**

改协议之前先读 PSP 的 `docs/psp-node-agent.md` §8.5「关掉了哪些选项」——
有些门是**永久关闭**的，重新打开需要一次破坏性协议升级。
