# 经验教训

跨会话累积踩坑记录。**每条经验教训保持 10 句话以内**，只记录核心问题、修复、教训。CLAUDE.md 中的精简版优先于本文档。

---

## USER_NOTIF worker hang（2026-07-18）

`ioctl(SECCOMP_IOCTL_NOTIF_RECV)` 阻塞等待通知，worker 唯一退出条件是收到 notification 后 break。子进程正常退出且不触发黑名单 syscall（如 `/bin/true`）时 worker 永久阻塞，`worker_thread.join()` 卡死。原 13 个 seccomp 测试全部触发黑名单，happy path 完全裸漏。

**修复**：self-pipe trick——主线程 `pipe()` 创建 shutdown 通道，worker 用 `poll([listener_fd, shutdown_r])` 同时监听两个 fd。主线程 wait 结束后写 1 字节唤醒 worker。提取 `UserNotifHandle` struct 封装 shutdown + join 生命周期。

**教训**：阻塞 syscall 必须配中断路径（poll/timeout/signal），主线程不能 join 可能永久阻塞的 worker。集成测试需要覆盖 happy path（正常退出），不能只测异常路径。提取独立 helper struct 后可单测。

**回归**：`normal_exit_does_not_hang_worker`——跑 `/bin/true`，`Instant` 测时 < 10s，断言 exit_code=0 且无 denial。
