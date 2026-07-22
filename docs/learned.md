# 经验教训

跨会话累积踩坑记录。**每条经验教训保持 10 句话以内**，只记录核心问题、修复、教训。CLAUDE.md 中的精简版优先于本文档。

---

## USER_NOTIF worker hang（2026-07-18）

`ioctl(SECCOMP_IOCTL_NOTIF_RECV)` 阻塞等待通知，worker 唯一退出条件是收到 notification 后 break。子进程正常退出且不触发黑名单 syscall（如 `/bin/true`）时 worker 永久阻塞，`worker_thread.join()` 卡死。原 13 个 seccomp 测试全部触发黑名单，happy path 完全裸漏。

**修复**：self-pipe trick——主线程 `pipe()` 创建 shutdown 通道，worker 用 `poll([listener_fd, shutdown_r])` 同时监听两个 fd。主线程 wait 结束后写 1 字节唤醒 worker。提取 `UserNotifHandle` struct 封装 shutdown + join 生命周期。

**教训**：阻塞 syscall 必须配中断路径（poll/timeout/signal），主线程不能 join 可能永久阻塞的 worker。集成测试需要覆盖 happy path（正常退出），不能只测异常路径。提取独立 helper struct 后可单测。

**回归**：`normal_exit_does_not_hang_worker`——跑 `/bin/true`，`Instant` 测时 < 10s，断言 exit_code=0 且无 denial。

---

## unshare(CLONE_NEWPID) 的 fork 语义 + reaper 模型（2026-07-22）

`unshare(CLONE_NEWPID)` 后，调用进程**不是** PID 1。只有 fork() 的子进程才是 PID 1。
早期理解认为"unshare 后当前进程是 init"，导致业务进程直接当 PID 1。

PID 1 在 PID namespace 中有特殊行为：SIGTERM 等信号在无 handler 时被内核屏蔽，
且必须承担孤儿进程收割职责。让业务进程当 PID 1 轻则杀不死，重则满屏僵尸。

**修复**：两次 fork——unshare 后第一次 fork 得到 PID 1，PID 1 再 fork 出业务进程
（PID 2）。PID 1 做专职 reaper（只 wait → \_exit），业务进程当普通员工。

**教训**：unshare(CLONE_NEWPID) 的语义与 clone(CLONE_NEWPID) 不同：
- clone → 子进程直接是 PID 1
- unshare → 调用进程保持原 PID，子进程 fork 后才是 PID 1

设计 reaper 模型时必须验证退出码转发链路：业务进程 → PID 1 → 父进程。退出码不改
地逐层转发，不能丢或篡改。

PID namespace 在非 root 下需要 user ns 获取 CAP_SYS_ADMIN。由 CLI 层自动隐含
（参照 bwrap：非 root 时 `--unshare-pid` 自动补 `--unshare-user`），不留给用户自行
组合。

**测试**：N15（exit 42 → 42）验证退出码转发。N8（echo $$ = 2）验证业务进程不是 PID 1。
