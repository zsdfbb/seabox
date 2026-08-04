//! 基于 Landlock + seccomp BPF 的 Linux 沙箱实现。
//!
//! 提供实现了 [`SandboxImpl`] trait 的 [`LinuxSandbox`]：
//! 通过 Landlock ACL 做文件系统访问控制，通过手写的 seccomp BPF 黑名单
//! 做系统调用过滤。
//!
//! ## 执行流程
//!
//! 1. **父进程** 构建 Landlock 规则集、seccomp BPF filter、namespace 配置。
//! 2. **父进程** 创建 `socketpair(AF_UNIX, SOCK_SEQPACKET)`，得到两端。
//! 3. **父进程** `libc::fork()` 创建子进程。
//! 4. **子进程** 依次执行：
//!    - `unshare(namespace_flags)`（创建 user/ipc/net/uts/cgroup 命名空间）
//!    - `unshare(CLONE_NEWPID)` + `fork()`（PID 命名空间 + reaper，如需要）
//!    - 环境变量通过 execve envp 参数传递（fork 前预计算）
//!    - `chdir()`（工作目录）
//!    - `prctl(PR_SET_NO_NEW_PRIVS, 1, …)`
//!    - `write(/proc/self/uid_map + gid_map)`（user ns 映射，如需要）
//!    - `sethostname()`（UTS 主机名，如需要）
//!    - `landlock_restrict_self(ruleset_fd, 0)`（Landlock ACL，如规则存在）
//!    - `seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER, &fprog)`（加载 BPF，返回 listener fd）
//!    - `sendmsg(SCM_RIGHTS)`（将 listener fd 经 socketpair 传给父进程）
//!    - `execve(...)`（启动目标程序，envp 指向预计算数组）
//! 5. **父进程** worker 线程：
//!    - 从 socketpair 用 `recvmsg(SCM_RIGHTS)` 拿到 listener fd
//!    - 循环 `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` 阻塞读拦截通知
//!    - 捕获 `seccomp_notif.data.{nr,arch}`，记录到 `blocked`
//!    - 用 `ioctl(SECCOMP_IOCTL_NOTIF_SEND)` 回复 `error = EPERM`，
//!      让拦截的 syscall 直接以权限错误返回（不进入 syscall 主体）。
//! 6. **父进程** 在 reap 时从 `siginfo` 拿到 exit_code / 退出原因。
//! 7. **关键**：USER_NOTIF 下子进程通常**不会**被信号杀死，进程收到
//!    EPERM 后继续运行并以正常 exit_code 退出（多数 syscall_probe 会
//!    自行返回 0）。worker 线程把 `(nr, arch)` 写入共享
//!    `Arc<Mutex<Option<(nr, arch)>>>`，`execute` 返回后 `classify_exit`
//!    读取该值，在 exit_code=0 的情况下仍然把命令归类为 `Denied { Seccomp }`。

pub mod child_setup;
pub mod landlock;
pub mod mount;
pub mod namespaces;
pub mod net;
pub mod seccomp;

use std::collections::HashMap;
use std::ffi::CString;
use std::mem::{self, MaybeUninit};
use std::os::fd::FromRawFd;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use anyhow::Context;

use crate::config::{MountConfig, SandboxConfig};
use crate::{CommandOutput, CommandSpec, ExitReason, SandboxImpl};

// ---------------------------------------------------------------------------
// 常量（不依赖 libc 版本）
// ---------------------------------------------------------------------------

/// `socket(2)` 地址族：本地（Unix 域）。libc 0.2 各平台都暴露 `AF_UNIX`。
const AF_UNIX: libc::c_int = libc::AF_UNIX;

/// `socketpair(2)` 类型：有序可靠 datagram。选 SOCK_SEQPACKET 让
/// `sendmsg` 一次交付完整消息边界（便于父端只 `recv` 一次就拿到完整
/// 控制字）。
const SOCK_SEQPACKET: libc::c_int = libc::SOCK_SEQPACKET;

/// `setsockopt(SO_PASSCRED)` / cmsg 类型：传递文件描述符。libc 在
/// linux_like 平台暴露 `SCM_RIGHTS = 0x01`。
const SCM_RIGHTS: libc::c_int = libc::SCM_RIGHTS;

// ---------------------------------------------------------------------------
// LinuxSandbox
// ---------------------------------------------------------------------------

/// 使用 Landlock ACL 与 seccomp BPF filter 强制施加文件系统与系统调用限制
/// 的沙箱。
#[derive(Debug)]
pub struct LinuxSandbox {
    pub config: SandboxConfig,
}

// ---------------------------------------------------------------------------
// SandboxImpl trait 实现
// ---------------------------------------------------------------------------

impl SandboxImpl for LinuxSandbox {
    /// 在沙箱内执行一条命令。
    ///
    /// 在**父进程**中构建 Landlock 规则集与 seccomp BPF filter，
    /// 然后在 `fork()` 后的**子进程**中依次施加命名空间隔离、Landlock ACL、
    /// seccomp BPF filter，并通过 `SECCOMP_RET_USER_NOTIF` 将拦截事件转发到
    /// listener fd，由父进程 worker 线程处理后写入共享 `blocked` 变量。
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<CommandOutput> {
        // ── 步骤 1：构建 Landlock 规则集并取出其 fd ────────────────────
        let ruleset_fd: Option<OwnedFd> = self.prepare_ruleset_fd()?;
        let raw_ruleset_fd: i32 = ruleset_fd.as_ref().map(|fd| fd.as_raw_fd()).unwrap_or(-1);

        // ── 步骤 2：构建 seccomp BPF filter ───────────────────────────
        let bpf_filter = self.build_bpf_filter();
        let has_deny = bpf_filter.is_some();
        // ── 预对齐外部 BPF filter（修复 from_raw_parts 对齐 UB）──
        let aligned_ext_filters: Vec<Vec<seccomp::sock_filter>> = self
            .config
            .seccomp_filter_bytes
            .iter()
            .map(|bytes| {
                assert!(
                    bytes.len() % mem::size_of::<seccomp::sock_filter>() == 0,
                    "external BPF bytes length {} is not a multiple of sock_filter size {}",
                    bytes.len(),
                    mem::size_of::<seccomp::sock_filter>()
                );
                bytes
                    .chunks(mem::size_of::<seccomp::sock_filter>())
                    .map(|chunk| unsafe {
                        std::ptr::read_unaligned(chunk.as_ptr() as *const seccomp::sock_filter)
                    })
                    .collect()
            })
            .collect();

        // ── 预对齐外部 BPF filter 描述（child 可见的指针 + 长度数组）──
        let ext_filters_desc: Vec<child_setup::ExtFilterDesc> = aligned_ext_filters
            .iter()
            .map(|v| child_setup::ExtFilterDesc {
                data: v.as_ptr(),
                len: v.len(),
            })
            .collect();

        // ── 步骤 3：必要时在 cwd 中展开 ~ ─────────────────────────────
        let cwd = match spec.cwd.to_str() {
            Some(s) => PathBuf::from(crate::config::expand_tilde(s)),
            None => spec.cwd.clone(),
        };

        // ── 步骤 4：创建 socketpair（仅 USER_NOTIF 路径需要）────────────
        let (parent_stream, child_sock) = if has_deny {
            let (p, c) = create_socketpair()?;
            (Some(p), Some(c))
        } else {
            (None, None)
        };
        let child_fd_raw = child_sock.as_ref().map(|fd| fd.as_raw_fd()).unwrap_or(-1);
        let parent_fd_raw_for_child = parent_stream
            .as_ref()
            .map(|fd| fd.as_raw_fd())
            .unwrap_or(-1);

        // ── 计算 namespace 参数 ────────────────────────────────
        let ns = &self.config.namespaces;

        // PID ns 在非 root 下需要 user ns 来获取 CAP_SYS_ADMIN。
        // 这里规范化 so 无论 CLI 还是 crate API 路径都覆盖。
        let effective_user = if ns.pid && !ns.user && unsafe { libc::geteuid() } != 0 {
            true
        } else {
            ns.user
        };

        // 常规 namespace（不含 PID，PID 通过 double-fork 单独处理）
        let ns_ops: Vec<child_setup::NsOp> = {
            let mut v = Vec::new();
            if effective_user {
                v.push(child_setup::NsOp {
                    flag: libc::CLONE_NEWUSER,
                    try_mode: ns.user_try as i32,
                });
            }
            if ns.mnt {
                v.push(child_setup::NsOp {
                    flag: libc::CLONE_NEWNS,
                    try_mode: 0,
                });
            }
            if ns.ipc {
                v.push(child_setup::NsOp {
                    flag: libc::CLONE_NEWIPC,
                    try_mode: 0,
                });
            }
            if ns.net {
                v.push(child_setup::NsOp {
                    flag: libc::CLONE_NEWNET,
                    try_mode: 0,
                });
            }
            if ns.uts {
                v.push(child_setup::NsOp {
                    flag: libc::CLONE_NEWUTS,
                    try_mode: 0,
                });
            }
            if ns.cgroup {
                v.push(child_setup::NsOp {
                    flag: libc::CLONE_NEWCGROUP,
                    try_mode: ns.cgroup_try as i32,
                });
            }
            v
        };
        let need_pid_reaper = ns.pid;

        // ── 预计算 uid_map/gid_map 内容（如果 user ns）─────────────
        let real_uid: u32 = unsafe { libc::getuid() };
        let real_gid: u32 = unsafe { libc::getgid() };
        let sandbox_uid = ns.uid.unwrap_or(real_uid);
        let sandbox_gid = ns.gid.unwrap_or(real_gid);
        let uid_map_content: Vec<u8> = format!("{sandbox_uid} {real_uid} 1\n").into_bytes();
        let gid_map_content: Vec<u8> = format!("{sandbox_gid} {real_gid} 1\n").into_bytes();

        // ── 预计算 hostname bytes ────────────────────────────
        let hostname_bytes: Option<Vec<u8>> = ns.hostname.as_ref().map(|h| h.as_bytes().to_vec());

        // ── 预计算 envp（"KEY=val\0" NULL-terminated 数组）──
        let envp_cstrings: Vec<CString> = spec
            .env
            .iter()
            .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap_or_default())
            .collect();
        let mut envp: Vec<*const libc::c_char> = envp_cstrings.iter().map(|s| s.as_ptr()).collect();
        envp.push(std::ptr::null());

        // ── 预计算 argv（program + args, NULL-terminated）──
        let argv_cstrings: Vec<CString> = std::iter::once(spec.program.clone())
            .chain(spec.args.clone())
            .map(|a| CString::new(a).unwrap_or_default())
            .collect();
        let mut argv: Vec<*const libc::c_char> = argv_cstrings.iter().map(|a| a.as_ptr()).collect();
        argv.push(std::ptr::null());

        // ── 预计算 cwd CString（chdir 用）──
        let cwd_c = CString::new(cwd.to_str().unwrap_or("/")).unwrap_or_default();

        // ── 解析程序路径（execve 不搜 PATH，需提前解析）──
        let exec_path = resolve_exec_path(&spec.program, &spec.env);

        // ── 预计算 mount 操作 ──────────────────────────────────
        let mount_config = &self.config.mount;
        let has_mounts = !mount_config.specs.is_empty() || mount_config.enabled;
        let (mount_ops, _mount_ops_cstrings) =
            prepare_mount_ops(mount_config).with_context(|| "failed to prepare mount ops")?;
        let mount_ops_ptr = mount_ops.as_ptr();
        let mount_ops_len = mount_ops.len();
        let do_private = has_mounts;

        // ── 步骤 5：raw fork + 手动 setup ──────────────────────
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "fork() failed for '{}'. \
                         Note: seabox does NOT interpret shell metacharacters \
                         (>, >>, |, *, &&, etc.) — it runs the program directly via execve. \
                         To use shell syntax, invoke 'sh -c' explicitly, e.g. \
                         `-- sh -c \"your shell command here\"`. \
                         Or split the command into separate args without shell metacharacters.",
                    spec.program
                )
            });
        }

        if pid == 0 {
            // ── 子进程：委托给 child_setup（此模块只接受 raw 类型，杜绝无意的堆操作）──
            // SAFETY: 所有 raw pointer 引用的 backing storage（CString、Vec 等）
            // 都是本函数中的局部变量，在 child 中不会被 drop（因为只调 execve / _exit）。
            unsafe {
                let configure_lo = ns.net && self.config.network.loopback;
                child_setup::enter_child(
                    exec_path.as_ptr(),
                    argv.as_ptr(),
                    envp.as_ptr(),
                    cwd_c.as_ptr(),
                    raw_ruleset_fd,
                    bpf_filter
                        .as_ref()
                        .map(|f| f.as_ptr())
                        .unwrap_or(std::ptr::null()),
                    bpf_filter.as_ref().map(|f| f.len()).unwrap_or(0),
                    child_fd_raw,
                    parent_fd_raw_for_child,
                    ext_filters_desc.as_ptr(),
                    ext_filters_desc.len(),
                    ns_ops.as_ptr(),
                    ns_ops.len(),
                    need_pid_reaper,
                    effective_user,
                    uid_map_content.as_ptr(),
                    uid_map_content.len(),
                    gid_map_content.as_ptr(),
                    gid_map_content.len(),
                    hostname_bytes
                        .as_ref()
                        .map(|h| h.as_ptr())
                        .unwrap_or(std::ptr::null()),
                    hostname_bytes.as_ref().map(|h| h.len()).unwrap_or(0),
                    configure_lo,
                    mount_ops_ptr,
                    mount_ops_len,
                    do_private,
                );
            }
        }

        // ── 父进程 ──
        drop(child_sock);

        let blocked = std::sync::Arc::new(std::sync::Mutex::new(None::<(u32, u32)>));
        let _notif_handle = if let Some(ref parent_stream) = parent_stream {
            let parent_fd_raw = parent_stream.as_raw_fd();
            Some(spawn_user_notif_worker(parent_fd_raw, &blocked)?)
        } else {
            None
        };

        // waitpid 替代 waitid
        let mut status: i32 = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            drop(parent_stream);
            return Err(e).with_context(|| {
                format!("waitpid() failed for sandboxed process '{}'", spec.program)
            });
        }
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            -1
        };

        let blocked_val = blocked.lock().ok().and_then(|g| *g);
        Ok(CommandOutput {
            exit_code,
            blocked_syscall: blocked_val,
        })
    }

    /// 将已完成命令的退出码与可选的 `(nr, arch)` 归类为一个 [`ExitReason`]，
    /// 区分沙箱拒绝（Landlock、seccomp 等）与正常程序退出。
    ///
    /// 检测依据（按优先级）：
    ///
    /// 1. **`blocked` Option** → USER_NOTIF 命中黑名单（由 `execute`
    ///    从 worker 上报的 `(nr, arch)`）。即使 `exit_code == 0`
    ///    （黑名单 syscall 返回 EPERM，进程继续并正常退出）也能正确归类为
    ///    `Denied { Seccomp, rich_message }`。
    /// 2. **退出码 126** → Landlock 拒绝（EPERM/EACCES 无法访问文件系统）。
    /// 3. **退出码 0** → 正常退出。
    /// 4. **退出码 31 或 159** → SIGSYS（传统 BPF KILL 路径）。
    /// 5. **其他情况** → 普通程序退出。
    fn classify_exit(&self, exit_code: i32, blocked: Option<(u32, u32)>) -> ExitReason {
        use crate::DenyMechanism;
        use crate::ExitReason::*;

        // ── 优先级 1：结构化 blocked (nr, arch) ─────────────────────
        // 首选来源。直接查表生成富诊断消息。即便 exit_code == 0 也命中 Denied。
        if let Some((nr, arch)) = blocked {
            let name = seccomp::syscall_name(nr).unwrap_or("unknown");
            return Denied {
                mechanism: DenyMechanism::Seccomp,
                message: format!(
                    "Blocked by seccomp filter (SIGSYS): \
                     syscall='{name}' nr={nr} \
                     arch=0x{arch:x} reason=blacklist signal=SIGSYS"
                ),
            };
        }

        // ── 优先级 2：退出码 126 → Denied(Landlock) ────────────────
        // Landlock 拒绝会导致 EACCES/EPERM，某些程序在被拒绝后以 126 退出。
        if exit_code == 126 {
            return Denied {
                mechanism: DenyMechanism::Landlock,
                message: "Sandbox denial (Landlock): blocked by Landlock ruleset".into(),
            };
        }

        // ── 优先级 3：退出码 0 → 成功 ───────────────────────────────
        if exit_code == 0 {
            return Ok;
        }

        // ── 优先级 4：SIGSYS 退出码 → Denied(Seccomp) ──────────────
        // 退出码 31（直接）或 159（128 + SIGSYS，Unix shell 习惯）
        // → seccomp 杀死了进程。当 seccomp filter 返回 KILL_PROCESS
        // （如架构不匹配分支）时，内核会投递 SIGSYS。
        if exit_code == 31 || exit_code == 159 {
            return Denied {
                mechanism: DenyMechanism::Seccomp,
                message: "Blocked by seccomp filter (SIGSYS)".into(),
            };
        }

        // ── 正常的程序退出（非零） ─────────────────────────────────
        Program(exit_code)
    }
}

// ---------------------------------------------------------------------------
// 内部辅助函数
// ---------------------------------------------------------------------------

impl LinuxSandbox {
    /// 构建 Landlock 规则集并返回其可选的文件描述符。
    ///
    /// 空规则 → 返回 `None`（不施加 Landlock 限制）。
    fn prepare_ruleset_fd(&self) -> anyhow::Result<Option<OwnedFd>> {
        let created = landlock::build_ruleset(&self.config.landlock, &std::env::current_dir()?)?;

        // 取出可选的 fd —— 这会消费 RulesetCreated。
        // `From<RulesetCreated> for Option<OwnedFd>` 在 landlock crate
        // 中定义（ruleset.rs 第 985 行附近）。
        Ok(match created {
            Some(ruleset) => {
                let fd: Option<OwnedFd> = ruleset.into();
                fd
            }
            None => None,
        })
    }

    /// 构建 seccomp BPF 黑名单 filter。
    ///
    /// 当 `config.seccomp_deny_nrs` 非空时返回 `Some(filter)`，
    /// 否则返回 `None`（不装 seccomp filter）。
    fn build_bpf_filter(&self) -> Option<Vec<seccomp::sock_filter>> {
        if self.config.seccomp_deny_nrs.is_empty() {
            None
        } else {
            Some(seccomp::build_deny_filter(&self.config.seccomp_deny_nrs))
        }
    }
}

// ── fork-safe 辅助函数 ────────────────────────────────────────────────

/// fork 前解析程序路径。含 '/' 直接返回原始路径；否则搜索 PATH。
/// 优先检查 spec.env 中的 PATH 覆盖，fallback 到父进程环境变量。
fn resolve_exec_path(program: &str, spec_env: &HashMap<String, String>) -> CString {
    if program.contains('/') {
        return CString::new(program).unwrap_or_default();
    }
    // 先检查 spec.env，fallback 到父进程环境变量。
    // PATH 字符串必须绑定到局部变量，否则 as_deref 引用的临时变量被 drop。
    let parent_path = std::env::var("PATH").ok();
    let path: &str = spec_env
        .get("PATH")
        .map(|s| s.as_str())
        .or(parent_path.as_deref())
        .unwrap_or("/usr/bin:/bin");
    for dir in std::env::split_paths(&path) {
        let full = dir.join(program);
        if full.is_file() {
            if let Some(s) = full.to_str() {
                return CString::new(s).unwrap_or_default();
            }
        }
    }
    CString::new(program).unwrap_or_default()
}

/// fork 前将 [`MountConfig`] 中的规格预编码为子进程可见的
/// `mount::RawMountOp` 数组。
///
/// 为每条 ops.`fstype` 对应的 CString 都存入 `cstrings` Vec 以防止提前 drop，
/// 所有 `RawMountOp` 的指针指向 `cstrings` 中的稳定存储。
///
/// # CString 生命周期
///
/// 调用方必须保证返回的 `cstrings` Vec 在 `enter_child` 调用期间存活。
/// `prepare_mount_ops` 预分配了足够容量避免后续 reallocation，
/// 因此返回的 ops 指针在 `cstrings` 生命周期内稳定有效。
/// 解析 `/proc/self/mountinfo` 的 opts 字段（如 `rw,nosuid,nodev,relatime`）为
/// `mount(2)` 的 MS_* flags。无法识别的选项忽略。
///
/// 只映射 userns 里会被内核**锁定**的 flags（NOSUID/NODEV/NOEXEC/RO/ATIME 模式）。
/// `--ro-bind` 的只读 remount 必须保留源挂载的锁定 flags，否则非 root 下
/// remount 返回 EPERM（见 docs/learned.md 与 docs/arch/mount-namespace/design.md §8.5）。
fn parse_mount_opts_flags(opts: &str) -> u64 {
    use mount::{
        MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSUID, MS_RDONLY, MS_RELATIME,
        MS_STRICTATIME,
    };
    let mut flags: u64 = 0;
    for opt in opts.split(',') {
        match opt {
            "ro" => flags |= MS_RDONLY,
            "nosuid" => flags |= MS_NOSUID,
            "nodev" => flags |= MS_NODEV,
            "noexec" => flags |= MS_NOEXEC,
            "noatime" => flags |= MS_NOATIME,
            "nodiratime" => flags |= MS_NODIRATIME,
            "relatime" => flags |= MS_RELATIME,
            "strictatime" => flags |= MS_STRICTATIME,
            _ => {}
        }
    }
    flags
}

/// 从 `/proc/self/mountinfo` 找出 `path` 所在挂载的 MS_* flags。
///
/// 取 mountpoint 是 path 的路径前缀（且边界正确）的**最深**挂载行，解析其 opts。
/// 找不到时返回 0（保持旧行为，root 场景仍可用）。
fn source_mount_flags(path: &std::path::Path) -> u64 {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let target = canonical.to_string_lossy();
    let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return 0;
    };
    let mut best_len: usize = 0;
    let mut best_opts: &str = "";
    for line in info.lines() {
        let mut it = line.split_whitespace();
        it.next(); // id
        it.next(); // parent
        it.next(); // maj:min
        it.next(); // root
        let Some(mp) = it.next() else { continue };
        let Some(opts) = it.next() else { continue };
        let is_prefix = if mp == "/" {
            true
        } else if let Some(rest) = target.strip_prefix(mp) {
            rest.starts_with('/')
        } else {
            false
        };
        if is_prefix && mp.len() > best_len {
            best_len = mp.len();
            best_opts = opts;
        }
    }
    parse_mount_opts_flags(best_opts)
}

fn prepare_mount_ops(
    config: &MountConfig,
) -> anyhow::Result<(Vec<mount::RawMountOp>, Vec<CString>)> {
    // ── 预检：检查 source/target 路径存在性 ──────────────────────
    for (i, spec) in config.specs.iter().enumerate() {
        let target = std::path::Path::new(&spec.target);
        if !target.exists() {
            anyhow::bail!(
                "mount #{}: target path '{}' does not exist",
                i + 1,
                spec.target
            );
        }
        if spec.fstype == "none" {
            if let Some(ref src) = spec.source {
                if !std::path::Path::new(src).exists() {
                    anyhow::bail!("mount #{}: source path '{}' does not exist", i + 1, src);
                }
            }
        }
    }

    let mut cstrings: Vec<CString> = Vec::with_capacity(config.specs.len() * 2);
    let mut ops: Vec<mount::RawMountOp> = Vec::new();

    for spec in &config.specs {
        match spec.fstype.as_str() {
            "tmpfs" => {
                cstrings.push(CString::new(spec.target.as_str()).unwrap_or_default());
                cstrings.push(CString::new("tmpfs").unwrap_or_default());
                ops.push(mount::RawMountOp {
                    source: std::ptr::null(),
                    target: cstrings[cstrings.len() - 2].as_ptr(),
                    fstype: cstrings[cstrings.len() - 1].as_ptr(),
                    flags: spec.flags as libc::c_ulong,
                    data: std::ptr::null(),
                });
            }
            "none" => {
                let src = spec.source.as_deref().unwrap_or("");
                cstrings.push(CString::new(spec.target.as_str()).unwrap_or_default());

                if spec.readonly {
                    cstrings.push(CString::new(src).unwrap_or_default());
                    let target_ptr = cstrings[cstrings.len() - 2].as_ptr();
                    let src_ptr = cstrings[cstrings.len() - 1].as_ptr();

                    // 第一条: bind mount
                    ops.push(mount::RawMountOp {
                        source: src_ptr,
                        target: target_ptr,
                        fstype: std::ptr::null(),
                        flags: spec.flags as libc::c_ulong,
                        data: std::ptr::null(),
                    });
                    // 第二条: remount ro（bind + remount + rdonly + rec）
                    // 必须带上源挂载已有的 flags（nosuid/nodev/noexec/atime 等）：
                    // userns 里这些 flag 被内核锁定，remount 不带它们 = 尝试移除 → EPERM。
                    let existing_flags = source_mount_flags(std::path::Path::new(src));
                    ops.push(mount::RawMountOp {
                        source: std::ptr::null(),
                        target: target_ptr,
                        fstype: std::ptr::null(),
                        flags: (existing_flags
                            | mount::MS_BIND
                            | mount::MS_REMOUNT
                            | mount::MS_RDONLY
                            | mount::MS_REC) as libc::c_ulong,
                        data: std::ptr::null(),
                    });
                } else {
                    cstrings.push(CString::new(src).unwrap_or_default());
                    let target_ptr = cstrings[cstrings.len() - 2].as_ptr();
                    let src_ptr = cstrings[cstrings.len() - 1].as_ptr();

                    ops.push(mount::RawMountOp {
                        source: src_ptr,
                        target: target_ptr,
                        fstype: std::ptr::null(),
                        flags: spec.flags as libc::c_ulong,
                        data: std::ptr::null(),
                    });
                }
            }
            _ => {}
        }
    }

    Ok((ops, cstrings))
}

// ---------------------------------------------------------------------------
// socketpair + SCM_RIGHTS helpers
// ---------------------------------------------------------------------------

/// 创建 `socketpair(AF_UNIX, SOCK_SEQPACKET, 0)` 并返回两端 `OwnedFd`。
///
/// 调用方在 fork 后需手动关闭子进程继承的父端（通过其 raw fd），
/// 子端在子进程完成 `sendmsg(SCM_RIGHTS)` 后显式 `libc::close`。
///
/// # 错误
///
/// `socketpair` 失败时返回 `io::Error`。常见原因：fd 上限耗尽。
fn create_socketpair() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY：socketpair(2) 接受有效协议族与 type，flags=0 是默认；
    // 输出数组长度为 2，对应一个 read fd + 一个 write fd。
    let ret = unsafe { libc::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY：两个 fd 都是 socketpair 刚创建的有效 fd；移交给 OwnedFd 后由 RAII 管理，
    // 超出作用域时自动 close。
    let parent = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let child = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((parent, child))
}

/// 从 unix socket 收一个 `SCM_RIGHTS` fd。
///
/// 在父进程侧的 worker 线程调用。阻塞直到对端 sendmsg 或对端关闭
///（后者让 recvmsg 返回 0 / EAGAIN）。
///
/// 返回收到的 fd（>=0）。调用方负责 close。
fn recv_fd(socket_fd: RawFd) -> std::io::Result<RawFd> {
    // 接收 1 字节载荷。
    let mut payload = [0u8; 1];
    let iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut _,
        iov_len: payload.len(),
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as libc::c_uint) } as usize;
    let mut cmsg_buf = [MaybeUninit::<u8>::uninit(); 64];

    let mut msghdr = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &iov as *const _ as *mut _,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr() as *mut _,
        msg_controllen: cmsg_space as _,
        msg_flags: 0,
    };

    // SAFETY：msghdr 完整初始化，cmsg 缓冲区对齐且足够大。
    let n = unsafe { libc::recvmsg(socket_fd, &mut msghdr, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if n == 0 {
        // 对端关闭 → 没有 fd。
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "recvmsg returned 0: peer closed without sending fd",
        ));
    }

    // 取出 cmsg 中的 fd。
    // SAFETY：recvmsg 已写入 msghdr.msg_controllen；用 CMSG_FIRSTHDR
    // 拿到第一条 cmsg，类型必须是 SCM_RIGHTS。
    unsafe {
        let cmsg_ptr = libc::CMSG_FIRSTHDR(&msghdr);
        if cmsg_ptr.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "recvmsg: no cmsg header",
            ));
        }
        if (*cmsg_ptr).cmsg_level != libc::SOL_SOCKET || (*cmsg_ptr).cmsg_type != SCM_RIGHTS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "recvmsg: cmsg is not SCM_RIGHTS",
            ));
        }
        let data_ptr = libc::CMSG_DATA(cmsg_ptr) as *const RawFd;
        Ok(std::ptr::read(data_ptr))
    }
}

/// 父进程 USER_NOTIF worker 的生命周期句柄。
///
/// 通过 [`spawn_user_notif_worker`] 创建。
///
/// worker 线程在子进程退出、listener fd 收到 POLLHUP 后自然退出。
/// 调用 [`UserNotifHandle::shutdown`] 可提前唤醒 worker 阻塞的 `poll`，
/// [`UserNotifHandle::join`] 等待 worker 线程退出并清理资源。
/// 若未手动 join，worker 线程在句柄 drop 时 detach。
#[allow(dead_code)]
struct UserNotifHandle {
    /// worker 线程句柄。`join()` 取走后置 None 防止重复 join。
    worker: Option<std::thread::JoinHandle<()>>,
}

#[allow(dead_code)]
impl UserNotifHandle {
    /// 等待 worker 线程退出。
    ///
    /// `self` by value：消费 `Option<JoinHandle>`，避免外部误用已
    /// join 的句柄二次 join。
    fn join(mut self) {
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

/// Spawn worker 线程，负责响应 seccomp USER_NOTIF 通知。
///
/// # 参数
///
/// * `parent_sock_raw` —— socketpair 父端的 raw fd。fork 后子进程
///   通过 `sendmsg(SCM_RIGHTS)` 把 listener fd 发到这里。worker 在
///   自己闭包里调用 `recv_fd(parent_sock_raw)` 拿 listener。
/// * `blocked` —— 共享 `(nr, arch)` 状态；worker 把每次拦截的 syscall
///   信息写进去，主线程在 `waitpid` 后读。
///
/// worker 在 `poll(listener_fd, -1)` 中等待 notification 或 POLLHUP。
/// 子进程退出 → listener fd POLLHUP → worker 自然退出。
fn spawn_user_notif_worker(
    parent_sock_raw: RawFd,
    blocked: &std::sync::Arc<std::sync::Mutex<Option<(u32, u32)>>>,
) -> std::io::Result<UserNotifHandle> {
    let blocked_for_worker = std::sync::Arc::clone(blocked);

    let worker = std::thread::spawn(move || {
        // 1) 收 listener fd。阻塞直到子进程 sendmsg 或子进程已死。
        let listener_fd_raw = match recv_fd(parent_sock_raw) {
            Ok(fd) => fd,
            Err(_e) => {
                // 子进程未发出 listener 就退出。
                return;
            }
        };
        // SAFETY：listener_fd_raw 是 recv_fd 返回的有效 fd，
        // 移交给 OwnedFd 后由 RAII 在闭包退出时关闭。
        let listener_fd = unsafe { OwnedFd::from_raw_fd(listener_fd_raw) };

        // 2) 主循环：poll(listener_fd, -1)，等待 notification 或 POLLHUP。
        loop {
            let mut pollfd = libc::pollfd {
                fd: listener_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY：timeout=-1 表示永久阻塞直到就绪或被信号打断。
            let r = unsafe { libc::poll(&mut pollfd, 1, -1) };
            if r < 0 {
                break;
            }
            if pollfd.revents == 0 {
                continue;
            }

            // listener_fd 可读 → 处理一条 notification。
            let mut notif: seccomp::seccomp_notif = unsafe { mem::zeroed() };
            let r = unsafe {
                libc::ioctl(
                    listener_fd.as_raw_fd(),
                    seccomp::SECCOMP_IOCTL_NOTIF_RECV,
                    &mut notif,
                )
            };
            if r != 0 {
                break;
            }

            // 记录 (nr, arch) 到共享变量。
            if let Ok(mut g) = blocked_for_worker.lock() {
                *g = Some((notif.data.nr as u32, notif.data.arch));
            }

            // 回复 EPERM（不调用 syscall 主体）。
            let resp = seccomp::seccomp_notif_resp {
                id: notif.id,
                val: 0,
                error: libc::EPERM,
                flags: 0,
            };
            let r = unsafe {
                libc::ioctl(
                    listener_fd.as_raw_fd(),
                    seccomp::SECCOMP_IOCTL_NOTIF_SEND,
                    &resp,
                )
            };
            if r != 0 {
                break;
            }
        }
    });

    Ok(UserNotifHandle {
        worker: Some(worker),
    })
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::parse_mount_opts_flags;
    use crate::linux::mount;

    #[test]
    fn parse_opts_flags_common() {
        let f = parse_mount_opts_flags("rw,nosuid,nodev,relatime");
        assert_ne!(f & mount::MS_NOSUID, 0, "nosuid mapped");
        assert_ne!(f & mount::MS_NODEV, 0, "nodev mapped");
        assert_ne!(f & mount::MS_RELATIME, 0, "relatime mapped");
        assert_eq!(f & mount::MS_RDONLY, 0, "rw not ro");
    }

    #[test]
    fn parse_opts_flags_ro_and_atime() {
        let f = parse_mount_opts_flags("ro,noexec,noatime,nodiratime");
        assert_ne!(f & mount::MS_RDONLY, 0);
        assert_ne!(f & mount::MS_NOEXEC, 0);
        assert_ne!(f & mount::MS_NOATIME, 0);
        assert_ne!(f & mount::MS_NODIRATIME, 0);
    }

    #[test]
    fn parse_opts_flags_unknown_ignored() {
        let f = parse_mount_opts_flags("rw,usrquota,grpquota");
        assert_eq!(f, 0);
    }
}
