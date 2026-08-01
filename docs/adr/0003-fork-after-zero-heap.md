# ADR 0003: fork 后子进程零堆操作

**状态**：已采纳（2026-07-27）

## 背景

seabox 同时提供 CLI 和 crate API。作为 crate 可能被多线程 agent 框架引用。

`fork()` 后子进程中若调用了任何涉及堆操作（malloc/free/realloc）的函数，而 fork 时其他线程正持有 malloc 内部锁，则子进程会死锁。

## 约束

**子进程在 exec 之前，只能使用 fork 前已分配好的资源 + 纯 syscall 新申请的内核资源。** 任何经过用户态分配器的操作都不能做。

```
✓ fork 前 static 内存         → Vec<CString>、Vec<*const c_char> 等
✓ 纯 syscall                 → unshare / prctl / landlock / seccomp / execve / _exit
❌ 堆分配操作                 → CString::new / format! / Vec::push / setenv / clearenv / execvp
```

## 决策

1. **fork 前预计算** argv（CString + 指针数组）、envp（CString + 指针数组）、cwd CString、程序路径（已解析，execve 不搜 PATH）
2. **child 中只调纯 syscall**：`unshare` / `fork` / `waitpid` / `prctl` / `open` / `write` / `close` / `chdir` / `syscall(SYS_landlock_restrict_self)` / `syscall(SYS_seccomp)` / `sendmsg` / `execve` / `_exit`
3. **`execvp` → `execve`**：前者搜索 PATH 时调 malloc，后者是纯 syscall
4. **外部 BPF 对齐**：`Vec<u8>` → `&[sock_filter]` 的 `from_raw_parts` 对齐 UB，改为 fork 前预对齐
5. **保持 `fork()`**：不改 `clone()`。两者在锁继承问题上行为一致，clone 不解决任何实际问题

## 理由

这是唯一的在多线程 fork 下保证安全的方式。

### 为什么不直接用 `std::process::Command`？

`std::process::Command` 的 `spawn()` 底层也是 `fork()` + `execve()`，且它是线程安全的——因为它在 fork 前准备好 envp/argv，child 直接 `execve`，不碰堆。

但它的 API 不让我们在 fork 和 exec 之间插入代码。我们需要在 child 中执行 `unshare` / `prctl` / `landlock_restrict_self` / `seccomp` / `sendmsg` 等沙箱设置，`std::process::Command` 没有对应的接口。我们只能用 raw `fork()`，自己管理 child 的执行流。

### 为什么不直接用 `posix_spawn()`？

`posix_spawn()` 内部使用 `clone(CLONE_VM | CLONE_VFORK | SIGCHLD)` 创建子进程。共享地址空间（CLONE_VM）意味着 child 不复制堆、不继承锁；CLONE_VFORK 让 parent 阻塞到 child exec。child 只做预定义的 file actions（close/dup2/open）和 `execve`，不碰用户态分配器，所以是线程安全的。

但 `posix_spawn()` 的 child 只支持有限的操作（file actions、signal mask、sched params），不支持 `unshare` / `prctl` / `landlock` / `seccomp` / `sendmsg`。我们不能用它做沙箱。

### 本质上是一样的

无论是 `std::process::Command`、`posix_spawn` 还是我们的方案，核心都是：**spawn/fork 前把所有数据准备好，child 只调纯 syscall，不碰任何用户态资源。** 区别只是我们的 child 需要多调几个 syscall（unshare/prctl/landlock/seccomp）。

### bubblewrap 为什么不需要这个

bubblewrap 是 CLI——每次被调用都在**新进程**中运行。没有别的线程，没有继承的锁。它天然没有多线程 fork 问题。我们提供 crate API，被嵌入到多线程进程中，所以需要此保证。

## 结果

- 多线程下任意线程调 `execute()` 安全
- 不需要全局序列化锁（可完全并行调用）
- 不需要 worker 进程
- 不需要改 `clone()`（与 `fork()` 的锁继承问题相同）
- child 代码全部为 async-signal-safe 函数
- 方案与 `posix_spawn()` 采用了相同策略：child 零堆操作，只调纯 syscall

## 参考

- Bubblewrap（CLI 形态，无此问题）
- glibc posix_spawn 实现（`clone(CLONE_VM|CLONE_VFORK|SIGCHLD)` + child 纯 syscall）
- `std::process::Command`（`fork` + `execve`，但不由用户管理 child）
- `man 7 signal-safety`
