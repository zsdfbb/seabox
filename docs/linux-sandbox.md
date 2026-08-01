# Linux 沙箱机制

最低支持内核：Linux 5.13（Landlock ABI v1）。低于 5.13 时 `seabox check` 报告 Landlock 不可用。

所有机制均通过 Rust 直接调用内核 syscall，**零外部二进制依赖**。

## 内核能力矩阵

| 维度 | 机制 | 内核要求 | 实现状态 |
|---|---|---|---|
| 文件系统读写 | Landlock ruleset（`landlock_create_ruleset` + `landlock_add_rule` + `landlock_restrict_self`） | 5.13+ | ✅ Phase 1 |
| 危险 syscall 拦截 | seccomp BPF USER_NOTIF（`SECCOMP_SET_MODE_FILTER` + `SECCOMP_RET_USER_NOTIF`） | 5.0+ | ✅ Phase 1 |
| 用户/UID 隔离 | `unshare(CLONE_NEWUSER)` | 3.8+ | ✅ Phase 2 |
| 网络阻断 | `unshare(CLONE_NEWNET)` + lo down | 2.6.24+ | ✅ Phase 2 |
| 进程命名空间 | `unshare(CLONE_NEWPID)` | 2.6.24+ | ✅ Phase 2 |
| IPC 隔离 | `unshare(CLONE_NEWIPC)` | 2.6.24+ | ✅ Phase 2 |
| 主机名隔离 | `unshare(CLONE_NEWUTS)` + `sethostname()` | 2.6.24+ | ✅ Phase 2 |
| Cgroup 隔离 | `unshare(CLONE_NEWCGROUP)` | 4.6+ | ✅ Phase 2 |
| IP 级网络过滤 | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` + aya / nftables | 4.10+ / 6.8+ | ⏸️ 搁置，待 Phase 4 评估 |

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

## Seccomp（动态策略）

seccomp 策略完全由用户驱动，不设默认黑名单。

### CLI 接口

```
# USER_NOTIF 拦截指定 syscall（精确诊断）
seabox run --seccomp-deny-nr 165 -- ls

# 外部 cBPF 堆叠（prctl 直装，无诊断）
seabox run --seccomp-filter-fd 3 -- ls 3< block.bpf

# 混合：内部 deny 兜底 + 外部 BPF 收紧
seabox run --seccomp-deny-nr 165 --seccomp-filter-fd 3 -- ls 3< extra.bpf

# 不传 seccomp 参数 → 不装任何 filter
```

### 三条执行路径

| 条件 | 路径 | 安装方式 | 诊断 |
|---|---|---|---|
| `--seccomp-deny-nr` 非空 | A | NEW_LISTENER + USER_NOTIF | ✅ 精确到 nr/arch |
| 仅 `--seccomp-filter-fd` | B | prctl 直装 | ❌ 无 |
| 无 seccomp 参数 | C | 不装 filter | — |

### 路径 A：USER_NOTIF（有诊断）

1. 父进程构建 deny filter（n+6 条 BPF 指令）
2. 子进程加载 deny filter（NEW_LISTENER）并取得 listener fd
3. listener fd 通过 `sendmsg(SCM_RIGHTS)` 传回父进程
4. 子进程继续安装外部 BPF（如有）
5. 父进程 worker 线程在 `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` 上阻塞等待
6. 命中时，worker 读取 `(nr, arch)` 并回复 `EPERM`
7. 子进程以 EPERM 返回，继续运行并正常退出

拒绝消息格式：`Blocked by seccomp filter (SIGSYS): syscall='mount' nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS`

### 路径 B：外部 BPF（无诊断）

- 子进程通过 `prctl(PR_SET_SECCOMP)` 直装外部 BPF
- 无 socketpair、无 worker 线程
- 外部 BPF 的行为完全由其作者决定

### 多 filter 堆叠

多个 `--seccomp-filter-fd` 按顺序安装，内核按逆序评估（后装先查）。外部 BPF 只能进一步收紧，不能放行内部 deny 拦掉的 syscall。

### 已知 syscall 诊断查表

`SYSCALLS` 表保留用于 `syscall_name()` 诊断查表：

| syscall | x86_64 nr | aarch64 nr |
|---|---|---|
| mount | 165 | 40 |
| umount2 | 166 | 39 |
| pivot_root | 155 | 41 |
| chroot | 161 | 51 |
| ptrace | 101 | 117 |
| kexec_load | 246 | 104 |
| kexec_file_load | 320 | 294 |
| reboot | 169 | 142 |
| init_module | 175 | 105 |
| finit_module | 313 | 106 |
| delete_module | 176 | 107 |
| unshare | 97 | 97 |
| bpf | 357 | 280 |

## 命名空间支持

| 命名空间 | `clone` / `unshare` 标志 | 内核要求 | CLI 标志 |
|---|---|---|---|
| User | `CLONE_NEWUSER` | 3.8+ | `--unshare-user` / `--unshare-user-try` |
| IPC | `CLONE_NEWIPC` | 2.6.24+ | `--unshare-ipc` |
| PID | `CLONE_NEWPID` | 2.6.24+ | `--unshare-pid` |
| Network | `CLONE_NEWNET` | 2.6.24+ | `--unshare-net` |
| UTS | `CLONE_NEWUTS` | 2.6.24+ | `--unshare-uts` |
| Cgroup | `CLONE_NEWCGROUP` | 4.6+ | `--unshare-cgroup` / `--unshare-cgroup-try` |

快捷方式：`--unshare-all` 等价于以上 6 个同时启用（不含 try 变体）。

额外的关联参数：

| 参数 | 依赖 | 说明 |
|---|---|---|
| `--uid UID` | `--unshare-user` / `--unshare-all` | user ns 内的 uid 映射（默认：当前 uid） |
| `--gid GID` | `--unshare-user` / `--unshare-all` | user ns 内的 gid 映射（默认：当前 gid） |
| `--hostname NAME` | `--unshare-uts` / `--unshare-all` | UTS ns 内的 hostname |

预执行顺序：`unshare` 必须在 `seccomp` 之前（seccomp 黑名单含 `unshare(2)`）。
User ns 必须在其他命名空间之前（user ns 授予 ns 内的全部 capability，使后续 net/pid/uts 等 ns 创建可以不需要主机 CAP_SYS_ADMIN）。

父进程构建 Landlock ruleset_fd + seccomp BPF 数组 + namespace 配置 → `Command::spawn()` + `pre_exec` 闭包（零分配，只做系统调用）：

1. `unshare(flags)` — 逐个创建命名空间（在 seccomp 之前，因为 seccomp 黑名单会拦截 `unshare`）
2. `prctl(PR_SET_NO_NEW_PRIVS, 1)` — 设置 no_new_privs（uid_map 和 seccomp 的前置条件）
3. `write(/proc/self/uid_map + setgroups(deny) + gid_map)` — 映射 user ns UID/GID（如需要）
4. `sethostname(name)` — 设置 UTS 命名空间主机名（如需要）
5. `landlock_restrict_self(ruleset_fd, 0)` — 施加 Landlock ACL（如有规则）
6. `seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER, &fprog)` — 加载 BPF filter，返回 listener fd
7. `sendmsg(SCM_RIGHTS)` — 把 listener fd 经 socketpair 传给父进程
8. `execve(...)` — 执行目标程序
