# 阶段 0 spawn API — 设计质量评审

> 评审时间：2026-08-14（arch-validate）
> 对象：`docs/arch/codewhale-integration/design-spawn-api.md`（阶段 0 详细设计，13 项决策 D-A1~A13）
> 范围：全量维度（可行性 / 可维护性 / 可理解性 / 性能与可靠性）
> 上层：`design.md`（已批准）+ `context.md`（已定稿）+ ADR 006（已批准）
> 结论：**整体稳健，可行 🟢；3 个易修复缺口 + 2 个需讨论点，无架构级问题**

---

## 1. 维度判定

| 维度 | 判定 | 摘要 |
|---|---|---|
| 可行性 | 🟢 绿 | SCM_CREDENTIALS 已实测（宿主 pid）；全部改动纯 libc syscall，零新依赖（信号处理除外，见 R2）；实现周期可控 |
| 可维护性 | 🟡 黄 | 模块边界清晰（child.rs / linux / child_setup 职责分明）；但 worker 生命周期 + kill_pid 语义复杂度高，3 个缺口需补（R1/R3/R5） |
| 可理解性 | 🟡 黄 | 文档质量高（实测验证 + 时序图 + 资源账本）；但 pid-ns double-fork + SCM_CREDENTIALS + 合并 hello 的组合对新人门槛高，概念（wait_pid / kill_pid / business pid）需在代码注释再强化 |
| 性能与可靠性 | 🟢 绿 | 资源账本明确（每 child ≤1 worker 线程、fd 稳态 3、0 线程 execute）；有界阻塞 spawn 消除竞态；可靠性缺口集中在 spawn 错误路径（R1） |

## 2. 验证通过的关键设计（评审确认正确）

- **blocked() 最终值时序严密**：USER_NOTIF 下被拦 syscall 阻塞到 NOTIF_SEND 回复后才 continue；
  worker 写 `Arc<Mutex>` 先于子进程退出 → reap 后读必为最终值。无需 join 后才读，逻辑自洽。
- **有界阻塞 spawn（A4）** 消除 kill_pid 未初始化竞态——`kill()`/`wait_timeout()` 无需轮询分支，
  镜像 std::process exec-readiness，正确。
- **合并单消息（A3）** 消除「pid 先 / listener 后」顺序依赖与 worker recv_fd 竞态，一次 recvmsg 原子解析，正确。
- **setpgid 先于 seccomp（A6）**：setpgid/dup2 在 seccomp 安装前执行，用户 `--seccomp-deny-nr`
  清单不会误伤；`kill(-pgid)` 目标恒为 B 自建新组，不触碰调用方终端组。正确。
- **零堆约束内实现**：`setpgid`/`dup2`/`close`/`sendmsg` 全 async-signal-safe，`ChildIo` 为 repr(C)
  POD，ADR 0003 约束保持。正确。
- **资源账本**：线程 = `has_deny ? 1 : 0`（栈 256KB）；fd 稳态 Piped = 3；execute 0 线程（边读边 wait
  drain loop，每 tick ~2 syscall，30s 超时 ≈ 6000 syscall ≈ 噪音级）。合理。

## 3. 风险排序（影响 × 可能性）

| # | 风险 | 影响 | 可能性 | 说明 |
|---|---|---|---|---|
| R1 | **spawn 错误路径泄漏子进程**：`recv_hello` 超时/EOF → 只返回 Err，不清理。已 fork 的 P（及 pid-ns 下可能已 exec 的 B）无 waitpid → 僵尸/孤儿 | 高 | 中 | §6.1 唯一路径是 `Err("child exited during setup")`，无清理步骤 |
| R2 | **cmd_run 信号转发未设计透**：async-signal-safe handler + 全局 kill_pid 状态；Cargo.toml 无 signal 依赖（clap/anyhow/dirs/libc/landlock） | 高 | 中 | 决策点 §9.1 定了「默认 true + 转发」，但实现机制未定 |
| R3 | **wait() 幂等性未明确**：设计只说 try_wait 幂等（§4.1）；reaped 后再次 wait() → waitpid ECHILD → io::Error | 中 | 高 | ✅ **已解决**：`reaped: Option<ExitStatus>` 合并字段，wait 幂等 = 直接返回 Some（见 §6） |
| R4 | **SCM_CREDENTIALS 容器化部署语义**：实测在 init pid-ns；容器 pid-ns 内内核交付的 pid 相对容器 init-ns | 中 | 低 | 已有阶段 3 探针测试兜底 |
| R5 | **execute stdin 大输入 + 全量内存**：非阻塞写 + poll 集合动态管理复杂度；stdout/stderr 全量进 Vec（CodeWhale 同步路径固有需求） | 低 | 中 | 文档已标注 drain 防死锁；内存上限固有 |
| R6 | **wait_timeout 返回 `Option` 但永不 `None`**（到期必杀 + reap）——API 形状冗余 | 低 | 低 | 可简化 `ExitStatus`，或保留镜像 std 形状并文档注明 |

## 4. 改进建议（分层）

### 易修复（实现期直接补）

1. **R1 — spawn 错误路径清理**：`recv_hello` 失败（poll 超时 / EOF / 错误）时，在返回 `Err` 前：
   `kill(wait_pid, SIGKILL)` + `waitpid(wait_pid)`（尽力收割）。pid-ns 下 P 被 kill 后 A/B 可能
   孤儿（B 尚未 send_hello 即未 exec，setup 中会 `_exit`），属罕见边角，文档注明「尽力而为」。
   补一条测试：`spawn_setup_failure_no_leak`（触发 setup 失败 → 断言无僵尸）。
2. **R5 — drain loop 细节**：stdin 非阻塞写失败 EAGAIN 时把写端并入 poll 集合，写完后从集合移除；
   `try_wait` 命中后 `read_to_end` 两读端到 EOF。补测试：`execute_with_stdin_large`（已计划）。

### 需讨论（已采纳，见 design-spawn-api.md §6.5/§4.1）

3. **R2 — 信号转发实现机制** ✅ **已采纳**：手写 `AtomicI32 CHILD_PGID` + handler
   `kill(-pgid, sig)` + `_exit(128+sig)`（全 async-signal-safe），**职责限定 cmd_run（CLI 层）**
   不进库——库 execute 同步阻塞、可并发调用，全局 pgid 会串扰；CodeWhale 用 tokio 信号。
   见 design-spawn-api.md §6.5。
4. **R6 — wait_timeout 返回形状** ✅ **已采纳**：简化为 `io::Result<ExitStatus>`（到期必杀+reap，
   恒有已退出状态，`Option` 的 None 语义与「超时被杀」冲突）。ADR 006 A10 已同步修订注记。
   见 design-spawn-api.md §4.1。

### 架构级

5. 无。设计整体稳健，无需架构级调整。

## 6. 可维护性/可理解性提升措施（已采纳进 design-spawn-api.md）

| 措施 | 针对 | 落点 |
|---|---|---|
| `reaped: bool` + `last_status` → `reaped: Option<ExitStatus>`；删 `has_deny`（由 `notif_worker.is_some()` 推出） | 消除 2 处「字段间必须一致」的不变量 + 解决 R3 | §4.2 |
| 进程树拓扑图 + 三 pid 角色表（wait_pid / kill_pid / business） | 可理解性（复杂度源头是 pid-ns 三进程树） | §5.0 |
| hello 协议类型化：`recv_hello -> Hello { listener_fd, business_pid }`，`send_fd`→`send_hello` 单点定义 | 消息协议不散落，调用方不碰 cmsg | §5.1 |
| 公开方法契约注释（`wait_timeout` 到期即杀、`id()` 语义） | 有违直觉的契约显式化 | 实现期 §4.1 |
| Drop 顺序显式化：kill+reap → join worker → 关 fd | 生命周期可审计 | 实现期 §6.4 |
| worker 线程 trade-off 写入文档（暴露 `listener_fd()` 供 tokio 调用方事件循环的演进选项） | 保留 0 线程演进路径，不丢失可维护性 | 实现期 |

> 可维护性/可理解性维度维持 🟡 不变——设计层面的措施已采纳，但最终判定取决于实现落地
> （字段、注释、测试是否按此执行）。实现期以 §6 为准。

## 5. 评审结论

阶段 0 设计**可行性充分、架构正确**，承重墙（SCM_CREDENTIALS）已实测验证，资源账本与并发
时序论证严密。放行实现；实现期优先补 R1/R3（错误路径清理 + wait 幂等），R2 按推荐机制
（AtomicI32 + handler 职责限 CLI）落地，R6 在写接口签名时顺手简化。修复后无需重新评审。
