# ADR 001：seccomp 拦截采用 USER_NOTIF 而非 SIGSYS handler

- **状态：** 已实现（commit `841ed14`，branch `feat/seccomp-deny-message`）
- **来源：** `feat/seccomp-deny-message` 特性实现过程中的关键转向
- **影响范围：** `src/linux/{mod,seccomp}.rs`，`src/lib.rs`（`CommandOutput.blocked_syscall`），`tests/seccomp_test.rs`

---

## 上下文

Phase 1 的 seccomp 黑名单最初用 `SECCOMP_RET_KILL_PROCESS`——匹配黑名单的 syscall 直接被内核投递 SIGSYS 杀死，子进程 exit_code 变为 159，拒绝消息是固定字符串 `"Blocked by seccomp filter (SIGSYS)"`。

`feat/seccomp-deny-message` 特性的原始目标是**把拒绝消息升级为富诊断格式**（携带 syscall 名、分类、号、架构）。最初设计（plan 阶段）选择了 `SECCOMP_RET_TRAP` 路径：handler 内捕获 `siginfo_t` 中的 `(nr, arch)`，写入 stderr marker 行，然后 `_exit(159)`。

## 决策

改为 `SECCOMP_RET_USER_NOTIF` 路径：

- BPF filter 命中黑名单时返回 `SECCOMP_RET_USER_NOTIF`（而非 KILL 或 TRAP）
- 内核挂起该 syscall，向 listener fd 投递 `seccomp_notif { data.nr, data.arch, ... }`
- 父进程 worker 线程从 socketpair 收到的 listener fd 上 `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` 读取拦截详情
- 父进程回复 `EPERM`（`SECCOMP_IOCTL_NOTIF_SEND`），子进程的 syscall 以权限错误返回、继续运行，最终正常退出
- `(nr, arch)` 通过共享 `Arc<Mutex<Option<(u32, u32)>>>` 从 worker 传递到 `execute()` 的 reap 阶段
- 拒绝消息由父进程在 `classify_exit()` 中根据结构化 `blocked_syscall` 字段生成

## 理由

### TRAP 路径的固有缺陷

1. **handler 无法可靠写 stderr**：`execve` 后子进程的 stderr 可能被重定向、关闭、或指向无头终端。TRAP handler 必须调用 `write(2)` 来输出 marker，但在某些执行环境下 write 可能失败或阻塞。
2. **execve 重置信号 handler**：`execve(2)` 会将 `SA_SIGINFO` handler 重置为 `SIG_DFL`。如果目标程序自身调用了黑名单 syscall 之外的 syscall 但触发了架构不匹配分支（`SECCOMP_RET_KILL_PROCESS`），`SIG_DFL` 下的 SIGSYS 默认行为是 core dump，无法被捕获。
3. **`_exit(159)` 掩盖了子进程的原始退出码**：TRAP handler 中调用 `_exit(159)` 会丢失子进程在 handler 之前积累的退出信息。
4. **async-signal-safe 约束限制输出内容**：handler 内只能做 `write(2)` + `_exit(2)`，无法使用 `format!`、堆分配或 `std::io::Write`。

### USER_NOTIF 的优势

1. **子进程不受影响**：黑名单 syscall 以 EPERM 返回，子进程继续运行并正常退出——不产生额外信号、不丢失退出码。
2. **父进程侧结构化捕获**：`ioctl(NOTIF_RECV)` 返回内核提供的 `seccomp_notif` 结构体，天然包含 `(nr, arch, args[6])`，无需在 async-signal-safe 上下文中手动编码。
3. **兼容所有执行环境**：父进程侧的 worker 是普通线程，可以正常使用堆分配、格式化、`ioctl`——没有 async-signal-safe 限制。
4. **信息完整**：即便子进程早已 execve 重置了所有信号 handler，父进程侧的 worker 仍能捕获每个黑名单 syscall 拦截事件。

### 代价

1. **额外线程 + 跨线程协调**：需要 spawn worker 线程 + socketpair + self-pipe shutdown 机制，复杂度高于 TRAP handler。
2. **`(nr, arch)` 传递需要线程安全共享变量**：引入 `Arc<Mutex<Option<(u32, u32)>>>`，有死锁风险（教训详见 `docs/learned.md` 的 USER_NOTIF worker hang 记录）。
3. **worker 线程的生命周期管理**：worker 在 `ioctl(NOTIF_RECV)` 上阻塞，正常退出时需 self-pipe 唤醒 → poll 检测到 shutdown → break → join。不当实现会导致父线程永久挂起。
4. **`classify_exit` 的 fallback 逻辑仍保留**：TRAP 路径的 SIGSYS 退出码（31/159）检测留存为 fallback，用于架构不匹配分支仍走 KILL 的场景。

## 替代方案

### A：`SECCOMP_RET_TRAP` + SIGSYS handler（原始 plan）

- 子进程被杀前通过 handler 输出 marker 到 stderr
- 实现简单，无需 worker 线程
- 缺陷如上所述：stderr 不可靠、execve 重置 handler、async-signal-safe 约束

### B：`SECCOMP_RET_KILL_PROCESS` + 读 `/proc/<pid>/syscall`

- 子进程被 SIGSYS 杀死后，父进程从 `/proc/<pid>/syscall` 读取最后一次 syscall 号
- 无需 worker 线程或 socketpair
- 缺陷：`/proc/<pid>/syscall` 在进程退出后立即不可读；且其值可能已被内核在退出时清空

### C：`SECCOMP_RET_USER_NOTIF`（最终选择 ✓）

## 影响

- `CommandOutput` 新增 `blocked_syscall: Option<(u32, u32)>` 字段
- `Sandbox::classify_exit` 签名从 `(exit_code, stderr)` 改为 `(exit_code, blocked: Option<(u32, u32)>)`，`blocked` 有值时优先于其他所有判断路径
- 拒绝消息中对 SIGSYS 的引用（`signal=SIGSYS`）是语义标签，并非实际信号——USER_NOTIF 下子进程不会被 SIGSYS 杀死
- 后续扩展方向：对特定 syscall 回复 `SECCOMP_RET_ALLOW` 以实现运行时放行，无需修改 BPF filter

## 相关文档

- [docs/design-final/seccomp-deny-message.md](docs/design-final/seccomp-deny-message.md) — 最终设计文档，含完整数据流图
- [docs/design-plans/completed/feat-seccomp-deny-message.md](docs/design-plans/completed/feat-seccomp-deny-message.md) — 原始设计提案（D1 决策为 TRAP）
- [docs/exec-plans/completed/feat-seccomp-deny-message.md](docs/exec-plans/completed/feat-seccomp-deny-message.md) — 原始执行计划
- [docs/learned.md](docs/learned.md) — USER_NOTIF worker hang 踩坑记录
- [CONTEXT.md](CONTEXT.md) — `USER_NOTIF`、`Seccomp 拒绝消息`、`CommandOutput` 词汇定义
