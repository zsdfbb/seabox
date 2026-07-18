# Linux 沙箱策略

最低支持内核：Linux 5.13（Landlock ABI v1）。低于 5.13 时 `sandbox-runtime check` 报告不支持并退出非零。

所有机制均通过 Rust 直接调用内核 syscall，**零外部二进制依赖**。

## 内核能力矩阵

| 维度 | 机制 | 内核要求 |
|---|---|---|
| 文件系统读写 | Landlock ruleset (`landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`) | 5.13+ (ABI v1) |
| 危险 syscall 拦截 | seccomp BPF (`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`) | 3.5+ |
| 用户/UID 隔离 | `unshare(CLONE_NEWUSER)` | 3.8+ |
| 网络阻断（本地） | `unshare(CLONE_NEWNET)` + lo down | 2.6.24+ |
| 进程命名空间 | `unshare(CLONE_NEWPID)` *(可选, 见 future-extensions.md)* | 2.6.24+ |
| 网络过滤（云容器，未来） | eBPF `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` + aya | 4.10+, cgroup v2 |

## 环境适配策略

Linux 后端根据运行环境自动选择最佳机制：

```
可用性矩阵：

                  本地笔记本    云 VM (KVM)    容器内 (K8s)
  Landlock         ✅             ❌ 常见关闭     ❌
  user_namespace   ✅             ⚠️ 受限         ❌ 无 CAP
  netns            ✅             ✅             ❌ 无 CAP_NET_ADMIN
  cgroup v2        ⚠️ 不一定      ✅             ✅
  eBPF             ✅             ✅             ✅

路由逻辑：
  首选 Landlock + netns（本地，零额外依赖）
  ↓ Landlock/netns 不可用时
  降级 eBPF + cgroup v2（云 VM / 容器）
  ↓ 都不支持时
  跳过沙箱，报 warning
```

## Landlock ABI 版本

- ABI v1 (5.13): `FS_READ_FILE`, `FS_WRITE_FILE`, `FS_READ_DIR`, `FS_EXECUTE`
- ABI v2 (5.19): `FS_TRUNCATE`
- ABI v3 (6.2): `FS_IOCTL_DEV`, `FS_REFER`（硬链接/重命名限制）

运行时通过 `landlock_create_ruleset(... LANDLOCK_CREATE_RULESET_VERSION)` 探测可用 ABI，按高到低降级到 v1。

## Seccomp 基础过滤

预编译 BPF 规则禁用以下 syscall：

- `mount`, `umount2`, `pivot_root`, `chroot`
- `ptrace`
- `kexec_load`, `kexec_file_load`
- `reboot`
- `init_module`, `finit_module`, `delete_module`
- `unshare(CLONE_NEWUSER)` *(— 防止逃逸到 root)*
- `bpf` *(— 防止加载额外 BPF 程序)*

Phase 2 末会允许按策略动态调整这个白名单。