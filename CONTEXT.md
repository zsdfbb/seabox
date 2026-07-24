# CONTEXT.md

领域词汇表，不含实现细节。

| 术语 | 定义 |
|---|---|
| Sandbox | 通过 OS 内核机制对进程强制施加资源访问限制的运行时 |
| SandboxPolicy | 声明式的资源访问权限声明，决定 Sandbox 的行为边界 |
| SandboxConfig | SandboxPolicy + 超时等运行时参数的完整配置。包含 `filesystem.landlock: Vec<LandlockRule>`、`network.enabled: bool`、`timeout` |
| Landlock | Linux 5.13+ 内核 LSM，允许进程自限文件系统访问（grant-only 模型）。支持 ABI v1-v7，进程通过 `landlock_create_ruleset` + `landlock_add_rule` + `landlock_restrict_self` 在 fork-exec 之间施加 |
| Seccomp | Linux 内核系统调用过滤机制。提供两种 filter 安装方式：`--seccomp-deny-nr`（USER_NOTIF，精确诊断）和 `--seccomp-filter-fd`（prctl 直装外部 BPF，无诊断）。不传参数则不装 filter |
| Seccomp 动态策略 | 用户通过 `--seccomp-deny-nr <NR>` 指定要拦截的 syscall 号（可重复），或通过 `--seccomp-filter-fd <FD>` 堆叠外部原始 cBPF。无默认黑名单 |
| USER_NOTIF | seccomp filter 返回 `SECCOMP_RET_USER_NOTIF` 时，内核将拦截事件投递到 listener fd 而非杀死进程，由父进程通过 `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` 读取 `(nr, arch)` 后回复 `EPERM`，子进程继续运行 |
| Seccomp 拒绝消息 | 富诊断格式：`syscall='mount' nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS`。包含 syscall 名、号、架构 |
| CommandOutput | `{ exit_code: i32, blocked_syscall: Option<(u32, u32)> }`。`blocked_syscall` 仅在 seccomp USER_NOTIF 拦截发生时记录 `(syscall_nr, arch)` |
| ExitReason | `Sandbox` trait 对命令退出方式的分类：`Ok` / `Denied { mechanism: DenyMechanism, message }` / `Program(i32)` / `InternalError(String)`。`classify_exit(exit_code, blocked)` 决定。优先级：blocked 结构化数据 > exit_code=126(Landlock) > exit_code=0(OK) > exit_code=31/159(Seccomp SIGSYS) > 其他 |
| DenyMechanism | 拒绝机制枚举：`Landlock`（文件系统 ACL 拒绝）、`Seccomp`（syscall 过滤拒绝）、`Unknown` |
| CLI 子命令 | `sandbox-runtime run [--landlock path:perm...] [--allow-network] [--seccomp-deny-nr NR...] [--seccomp-filter-fd FD...] -- <COMMAND>`、`sandbox-runtime check`、`sandbox-runtime serve`（stub） |
| Landlock 权限展开 | `expand_perm()` 支持预设组合：`ro`/`rx`(execute+read-file+read-dir), `rw`(ro+write), `rwx`(rw+make-sock/fifo/block/char), `all`(rwx+refer+ioctl-dev)。个体权限名直通 `LandlockPerm` 枚举 |
