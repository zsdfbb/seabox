# CONTEXT.md

领域词汇表，不含实现细节。

| 术语 | 定义 |
|---|---|
| Sandbox | 通过 OS 内核机制对进程强制施加资源访问限制的运行时 |
| SandboxPolicy | 声明式的资源访问权限声明，决定 Sandbox 的行为边界 |
| SandboxConfig | SandboxPolicy + 超时等运行时参数的完整配置 |
| Landlock | Linux 5.13+ 内核 LSM，允许进程自限文件系统访问（grant-only 模型） |
| Seccomp | Linux 内核系统调用过滤机制，本项目的 seccomp BPF 采用黑名单策略 |
| deny-then-allow | 读取权限策略：默认允许所有，显式拒绝特定路径，再在拒绝区域内显式允许子路径（Phase 2 用 bind mount 实现） |
| allow-only | 写入权限策略：默认拒绝所有，显式允许特定路径 |
| Phase 1 Landlock 策略 | ReadOnly → grant read to `/`；WorkspaceWrite → grant read to `/` + grant write to cwd, /tmp, allow_write；FullAccess → 不调用 Landlock。`deny_read` 推迟到 Phase 2 |
| Seccomp 黑名单 | Phase 1 实现宽名单：mount, umount2, pivot_root, chroot, ptrace, kexec_load, kexec_file_load, reboot, init_module, finit_module, delete_module, unshare(CLONE_NEWUSER), bpf。共 13 个 syscall。手写 BPF + prctl 加载 |
| 执行流程 | 父进程构建 Landlock ruleset_fd + seccomp BPF 数组；`pre_exec` 闭包里只做零分配系统调用（prctl + landlock_restrict_self + prctl(SECCOMP)）|
| ExitReason | enum { Ok, Denied { mechanism: DenyMechanism, message }, Program(exit_code), InternalError(String) }。DenyMechanism 枚举 { Landlock, Seccomp, Unknown } |
| CLI 结构 | 显式子命令：`sandbox-runtime run [OPTIONS] <COMMAND>...`、`sandbox-runtime check`、`sandbox-runtime serve` |
| Config 命名 | `FilesystemConfig { policy: FsPolicy, allow_write: Vec<String> }`。FsPolicy 枚举 { FullAccess, ReadOnly, WorkspaceWrite }。`NetworkConfig { enabled: bool }` 独立。`allow_write` 用 Vec<String>，运行时统一展开 ~ |
| ExitReason | Sandbox 对命令退出方式的分类：正常退出 / 被沙箱拒绝 / 内部错误 |
