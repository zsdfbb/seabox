# Linux 沙箱机制

最低支持内核：Linux 5.13（Landlock ABI v1）。低于 5.13 时 `sandbox-runtime check` 报告 Landlock 不可用。

所有机制均通过 Rust 直接调用内核 syscall，**零外部二进制依赖**。

## 内核能力矩阵

| 维度 | 机制 | 内核要求 | 实现状态 |
|---|---|---|---|
| 文件系统读写 | Landlock ruleset（`landlock_create_ruleset` + `landlock_add_rule` + `landlock_restrict_self`） | 5.13+ | ✅ Phase 1 |
| 危险 syscall 拦截 | seccomp BPF USER_NOTIF（`SECCOMP_SET_MODE_FILTER` + `SECCOMP_RET_USER_NOTIF`） | 5.0+ | ✅ Phase 1 |
| 用户/UID 隔离 | `unshare(CLONE_NEWUSER)` | 3.8+ | 🚧 Phase 2 |
| 网络阻断 | `unshare(CLONE_NEWNET)` + lo down | 2.6.24+ | 🚧 Phase 2 |
| 进程命名空间 | `unshare(CLONE_NEWPID)`（可选） | 2.6.24+ | 📋 计划 |
| eBPF 网络过滤 | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` + aya | 4.10+, cgroup v2 | 📋 Phase 2b |

## Landlock ABI 版本

| ABI | Linux 内核 | 新增访问权限 |
|---|---|---|
| 1 | 5.13 | 初始：read/write/execute |
| 2 | 5.19 | `REFER`（跨目录树 rename/link） |
| 3 | 6.2 | `TRUNCATE` |
| 4 | 6.7 | `IOCTL_DEV` |
| 5 | 6.10 | TCP bind/connect |
| 6 | 6.12 | `Scope`（AF_UNIX / signal） |
| 7 | 6.15 | restrict_self 的 log flags |

运行时在 `get_abi_version()` 中通过 `CompatLevel::HardRequirement` 从 ABI v7 向下探测。

## Seccomp 黑名单

13 个被拦截的 syscall，按分类：

| 分类 | syscall | x86_64 nr | aarch64 nr |
|---|---|---|---|
| `mount`（文件系统挂载） | mount, umount2, pivot_root, chroot | 165/166/155/161 | 40/39/41/51 |
| `debug`（调试跟踪） | ptrace | 101 | 117 |
| `boot`（重启/内核加载） | kexec_load, kexec_file_load, reboot | 246/320/169 | 104/294/142 |
| `module`（内核模块） | init_module, finit_module, delete_module | 175/313/176 | 105/106/107 |
| `namespace`（命名空间逃逸） | unshare | 97 | 97 |
| `bpf`（额外 BPF 加载） | bpf | 357 | 280 |

### 拦截机制

采用 `SECCOMP_RET_USER_NOTIF`（非传统 SIGSYS），流程：

1. 父进程构建 BPF filter（n+6 条指令）
2. 子进程在 `pre_exec` 中加载 filter 并取得 listener fd
3. listener fd 通过 `sendmsg(SCM_RIGHTS)` 传回父进程
4. 父进程 worker 线程在 `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` 上阻塞等待
5. 命中黑名单时，worker 读取 `(nr, arch)` 并回复 `EPERM`
6. 子进程以 EPERM 返回，继续运行并正常退出

拒绝消息格式：`Blocked by seccomp filter (SIGSYS): syscall='mount' category='mount' nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS`

## 执行流程

父进程构建 Landlock ruleset_fd + seccomp BPF 数组 → `Command::spawn()` + `pre_exec` 闭包（零分配，只做系统调用）：

1. `prctl(PR_SET_NO_NEW_PRIVS, 1)` — 设置 no_new_privs
2. `landlock_restrict_self(ruleset_fd, 0)` — 施加 Landlock ACL（如有规则）
3. `seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER, &fprog)` — 加载 BPF filter，返回 listener fd
4. `sendmsg(SCM_RIGHTS)` — 把 listener fd 经 socketpair 传给父进程
5. `execve(...)` — 执行目标程序
