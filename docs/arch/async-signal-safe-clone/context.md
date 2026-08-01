# Async-signal-safety & clone() — 架构上下文

## 概述

分析 seabox 中子进程创建的 async-signal-safety 问题，以及是否应重构为 `clone()` 创建进程。

## 现有架构

### 进程创建模型

当前采用 `libc::fork()` + 手动 setup + `execvp()` 模型（`src/linux/mod.rs:169-387`）：

```
fork()
  → child: unshare(namespaces)     // user/ipc/net/uts/cgroup
  → child: unshare(CLONE_NEWPID)   // PID ns（如需）
  → child: fork() → PID 1（reaper）→ fork() → PID 2（业务进程）
  → child: clearenv + setenv + chdir        ← 堆操作
  → child: prctl(NO_NEW_PRIVS)
  → child: write uid/gid maps, sethostname
  → child: landlock_restrict_self
  → child: seccomp(NEW_LISTENER) → sendmsg(SCM_RIGHTS)
  → child: execvp()                         ← 堆操作（PATH 搜索）
parent: spawn_user_notif_worker()   // 线程
parent: waitpid()
parent: classify_exit()
```

child 中涉及堆操作的地方：`clearenv`（free）、`setenv`（malloc/realloc）、`CString::new()` × N、`execvp`（PATH 搜索调 malloc）。

### 线程模型

- fork 时主进程**单线程**（USER_NOTIF worker 是 fork 后才创建的）
- fork 后 parent 通过 `std::thread::spawn()` 创建 USER_NOTIF worker 线程
- 子进程在 exec 前始终单线程

### 当前信号处理

- **无任何 signal handler 注册**（项目代码 + 传递依赖）
- 无 `sigaction`、`signal`、`alarm`、`setitimer`、`timerfd`、`signalfd`、`eventfd` 使用
- `waitpid()` 无限期阻塞（timeout 字段已定义但未实施）

## 约束

| 维度 | 说明 |
|------|------|
| 技术 | Linux only；Rust + libc raw syscall；无容器运行时依赖 |
| 演进 | 向后兼容 CLI flag 和 crate API |
| 安全 | Landlock → seccomp → exec 顺序不能乱；USER_NOTIF 必须 work |
| 使用方式 | **同时提供 CLI 和 crate API**（"编译在一起"免外部依赖） |

## 分析结论

### 场景一：仅 CLI 使用（如 bwrap）

```
agent 框架 → exec("seabox run ...") → 全新进程 → fork → child
```

全新进程，单线程，无锁继承问题，child 里调 setenv/execvp 都安全。

bwrap 走的就是这条路。**CLI 天然没有多线程 fork 安全问题。**

### 场景二：Crate API 被多线程框架引用

```
agent 线程 A → sandbox.execute()
agent 线程 B → HashMap::insert → 持 malloc 锁
                                     ↓
                                  fork()
                                     ↓
                                  child 碰 malloc → 死锁
```

**这是真正的问题。** 不是 async-signal-safety 那套"信号处理程序会中断"的理论，而是 **fork 时其他线程的锁被继承到子进程**。

### fork() vs clone()

**clone 不解决锁继承问题。**

| | fork() | clone(flags, NULL) |
|---|---|---|
| 锁继承 | 子进程继承其他线程的锁 | 子进程继承其他线程的锁（**相同**） |
| atfork handlers | 运行 | 不运行 |
| namespace flags | 需额外 unshare | 可直接传 |
| PID ns | unshare + double fork | CLONE_NEWPID flag |

`CLONE_VM` 在多线程并发下更危险（多个子进程共享同一地址空间互相踩）。结论：**不改 clone。**

### 真正的解法：child 零堆操作

借鉴 `posix_spawn()` 的思路——child 只做纯 syscall，不碰堆：

```
fork() 前（parent 侧，正常分配）：
  预计算 argv 指针数组
  预计算 envp 指针数组（"KEY=val\0" 格式）
  预计算 cwd CString
  预解析程序完整路径（execve 不搜 PATH）

fork() 后（child 侧，纯 syscall）：
  unshare / chdir / prctl / landlock / seccomp / sendmsg / execve / _exit
  ↑ 没有任何堆操作
```

即使其他线程在 fork 时持有 malloc 锁，child 不碰 malloc 就安全。**这是唯一一个在多线程 fork 下保证安全的方法。**

### 是否值得保留 crate API？

Crate 的好处：
- 编译在一起，不需要外部依赖特定版本
- 结构化 `ExitReason` 诊断（比 CLI stderr 解析更可靠）
- 不适合用 CLI 的场景（内嵌沙箱）

改造成本：三十四行预计算代码，不是大工程。**保留 crate API。**

---

## clone() 最终判断

**不改。** fork 和 clone 在锁继承问题上行为一致，clone 不解决任何实际安全问题。将来如果需要 `CLONE_INTO_CGROUP`（cgroup v2）或 `clone3` 的 `set_tid` 再改，替换路径很清晰。

---

## bubblewrap 的参考价值

| 维度 | bubblewrap | seabox |
|------|------------|-----------------|
| 形态 | 纯 CLI | CLI + crate |
| 多线程约束 | 无（每次新进程） | 有（同进程引用） |
| child 堆操作 | setenv + execvp | 计划清为零 |
| clone vs fork | raw_clone | fork，不改 |
| env 设置 | parent clearenv + setenv | pre-compute envp → execve |

bubblewrap 的做法对我们参考价值有限——它作为 CLI 天然不受多线程问题困扰，而我们作为 crate 需要更严格的 child 约束。

---

## 实施

见计划文件 `async-signal-safe-clone-delegated-sutherland.md`。核心：

1. fork 前预计算 argv/envp/cwd/exec_path
2. child 中删除 clearenv/setenv/CString::new/execvp
3. child 用 execve 传预计算值
4. 修复外部 BPF 的 sock_filter 指针对齐（`from_raw_parts` UB）
