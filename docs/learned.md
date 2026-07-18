# 经验教训

跨会话累积踩坑记录。每个 bug 包含：坑 / 修复 / 教训 / 回归测试。

CLAUDE.md 中的 `## 经验教训` 章节给出 1-3 句精简版与链接，详细内容以本文档为准。

---

## USER_NOTIF worker hang（2026-07-18）

### 坑

`src/linux/mod.rs::run_user_notif_worker` 用 `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` 阻塞等待通知。worker 唯一退出条件是收到 notification 后 break。

**触发条件：** 子进程正常退出且不触发黑名单 syscall（如 `echo hello` / `/bin/true`）。worker 永远阻塞，主线程 `worker_thread.join()` 永久卡死。

**为什么之前没暴露：** 原 13 个 `seccomp_test` 端到端测试**全部**触发黑名单 syscall，worker 都能收到 notification 退出。`deny_detect_test` 直接调 `classify_exit`，不走 `execute()`。`examples/` 只是 println，不调 sandbox。

**用户报告：** `cargo test --tests --examples` 不终止。

### 修复

**Self-pipe trick**（canonical Unix 模式）：

1. 主线程 `libc::pipe(&mut [shutdown_r, shutdown_w])` 创建 self-pipe
2. worker 用 `poll([listener_fd, shutdown_r], -1)` 同时监听两个 fd
3. 主线程 `wait_with_output()` 返回后 `write(1 byte, shutdown_w)` 唤醒 worker
4. worker 检测 `shutdown_r` 可读 → break → `join()` 立即返回

**代码组织改进：** 提取 `UserNotifHandle` struct 封装 worker 生命周期：

```rust
struct UserNotifHandle {
    worker: Option<std::thread::JoinHandle<()>>,
    shutdown_w: RawFd,
}

impl UserNotifHandle {
    fn shutdown(&self) {
        let buf = b"x";
        unsafe { let _ = libc::write(self.shutdown_w, buf.as_ptr() as *const _, 1); }
    }
    fn join(mut self) {
        if let Some(h) = self.worker.take() { let _ = h.join(); }
        unsafe { libc::close(self.shutdown_w); }
    }
}
```

主线程 `execute()` 变为：

```rust
let notif_handle = spawn_user_notif_worker(parent_sock_raw, &blocked)?;
let output = output.wait_with_output()?;
notif_handle.shutdown();
notif_handle.join();
```

### 教训

1. **阻塞 syscall + 跨线程协调 = 死锁温床**。任何阻塞调用都必须配中断路径（poll/timeout/signal）。主线程不能 join 一个可能被永久阻塞的 worker。
2. **集成测试要覆盖 happy path**。只测"触发异常"的路径会漏掉"异常不发生"时的协调 bug。每个端到端测试至少 1 个"正常退出"用例。
3. **代码组织影响可调试性**。worker 散在 `execute()` 内联逻辑 → 难以独立审查 → bug 不易被发现。提取独立 helper + struct 后可单测。

### 回归测试

`tests/seccomp_test.rs::normal_exit_does_not_hang_worker`：

- 跑 `/bin/true`（或 `/usr/bin/true` 回退）
- 显式 `std::time::Instant` 测时（< 10s）
- 断言 `exit_code == Some(0)` 且无 `"Sandbox denial"`
- 双重防护：耗时断言 + cargo test 全局 timeout

### 涉及文件

- `src/linux/mod.rs` — 新增 `spawn_user_notif_worker` + `UserNotifHandle`；worker 主循环改用 `poll([listener_fd, shutdown_r])`
- `tests/seccomp_test.rs` — 新增 `normal_exit_does_not_hang_worker`
- `docs/design-final/seccomp-deny-message.md` — 末尾追加 "Bug 修复记录（2026-07-18）"
- `CLAUDE.md` — 末尾追加 `## 经验教训` 章节

### 验证

- `cargo test --test seccomp_test`：16 passed（含 1 新增）
- `cargo test --lib`：39 passed
- `cargo test --test deny_detect_test`：11 passed
- `cargo clippy --tests -- -D warnings`：0 warning
- `./target/release/sandbox-runtime run --policy full-access -- /bin/true`：exit=0，无 hang