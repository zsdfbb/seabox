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
//!    - `clearenv()` + `setenv()`（环境变量）
//!    - `chdir()`（工作目录）
//!    - `prctl(PR_SET_NO_NEW_PRIVS, 1, …)`
//!    - `write(/proc/self/uid_map + gid_map)`（user ns 映射，如需要）
//!    - `sethostname()`（UTS 主机名，如需要）
//!    - `landlock_restrict_self(ruleset_fd, 0)`（Landlock ACL，如规则存在）
//!    - `seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER, &fprog)`（加载 BPF，返回 listener fd）
//!    - `sendmsg(SCM_RIGHTS)`（将 listener fd 经 socketpair 传给父进程）
//!    - `execvp(...)`（启动目标程序）
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

pub mod landlock;
pub mod namespaces;
pub mod seccomp;

use std::ffi::CString;
use std::mem::{self, MaybeUninit};
use std::os::fd::FromRawFd;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use anyhow::Context;

use crate::config::SandboxConfig;
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

/// 我们用作 "control ping" 的字节载荷（一个 magic byte）。
/// 子进程 sendmsg 时附带 listener fd，载荷是单字节 `0x42`。
const CTRL_PAYLOAD: [u8; 1] = [0x42];

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
        // 提取外部 BPF 字节（fork 后子进程需要 owned 数据）
        let ext_filter_bytes: Vec<Vec<u8>> = self.config.seccomp_filter_bytes.clone();

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
        let ns_ops: Vec<(i32, bool)> = {
            let mut v = Vec::new();
            if effective_user {
                v.push((libc::CLONE_NEWUSER, ns.user_try));
            }
            if ns.ipc {
                v.push((libc::CLONE_NEWIPC, false));
            }
            if ns.net {
                v.push((libc::CLONE_NEWNET, false));
            }
            if ns.uts {
                v.push((libc::CLONE_NEWUTS, false));
            }
            if ns.cgroup {
                v.push((libc::CLONE_NEWCGROUP, ns.cgroup_try));
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

        // ── 步骤 5：raw fork + 手动 setup ──────────────────────
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "fork() failed for '{}'. \
                         Note: sandbox-runtime does NOT interpret shell metacharacters \
                         (>, >>, |, *, &&, etc.) — it runs the program directly via execve. \
                         To use shell syntax, invoke 'sh -c' explicitly, e.g. \
                         `-- sh -c \"your shell command here\"`. \
                         Or split the command into separate args without shell metacharacters.",
                    spec.program
                )
            });
        }

        if pid == 0 {
            // ── 子进程：namespace + sandbox setup + exec ──

            // 第 1 步：创建常规 namespace（含 user ns）
            let mut user_ns_active = false;
            for &(flag, try_mode) in &ns_ops {
                let ret = unsafe { libc::syscall(libc::SYS_unshare, flag as libc::c_long) };
                if ret != 0 {
                    if try_mode {
                        continue;
                    }
                    unsafe {
                        libc::_exit(1);
                    }
                }
                if (flag & libc::CLONE_NEWUSER) != 0 {
                    user_ns_active = true;
                }
            }

            // 第 2 步：PID namespace（如果需要）
            if need_pid_reaper {
                let ret =
                    unsafe { libc::syscall(libc::SYS_unshare, libc::CLONE_NEWPID as libc::c_long) };
                if ret != 0 {
                    unsafe {
                        libc::_exit(1);
                    }
                }

                // unshare 后 fork() 的子进程是 PID 1（init）。需要两次 fork：
                //   第一次 fork: 父进程（非 PID 1）wait → _exit
                //               子进程（PID 1）继续
                //   第二次 fork: PID 1（reaper）wait → _exit
                //               子进程（PID 2）执行业务
                let pid2 = unsafe { libc::fork() };
                if pid2 < 0 {
                    unsafe {
                        libc::_exit(1);
                    }
                }
                if pid2 > 0 {
                    // 第一次 fork 的父进程（非 PID 1）：等待 PID 1
                    let mut status: i32 = 0;
                    unsafe {
                        libc::waitpid(pid2, &mut status, 0);
                    }
                    let exit_code = if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status)
                    } else if libc::WIFSIGNALED(status) {
                        128 + libc::WTERMSIG(status)
                    } else {
                        1
                    };
                    unsafe {
                        libc::_exit(exit_code);
                    }
                }
                // ── PID 1（init）：第二次 fork ──
                let pid3 = unsafe { libc::fork() };
                if pid3 < 0 {
                    unsafe {
                        libc::_exit(1);
                    }
                }
                if pid3 > 0 {
                    // PID 1（reaper）：等所有子进程退出后转发退出码
                    let exit_code = do_reaper(pid3);
                    unsafe {
                        libc::_exit(exit_code);
                    }
                }
                // ── PID 2（业务进程）：继续后续 setup ──
            }

            // 第 3 步：clearenv + setenv
            unsafe {
                libc::clearenv();
            }
            for (key, val) in &spec.env {
                let k = CString::new(key.as_str()).unwrap_or_default();
                let v = CString::new(val.as_str()).unwrap_or_default();
                unsafe {
                    libc::setenv(k.as_ptr(), v.as_ptr(), 1);
                }
            }

            // 第 4 步：chdir
            let cwd_str = cwd.to_str().unwrap_or("/");
            let cwd_c = CString::new(cwd_str).unwrap_or_default();
            if unsafe { libc::chdir(cwd_c.as_ptr()) } != 0 {
                unsafe {
                    libc::_exit(1);
                }
            }

            // 第 5 步：prctl(NO_NEW_PRIVS)
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                unsafe {
                    libc::_exit(1);
                }
            }

            // 第 6 步：uid/gid map
            if user_ns_active {
                unsafe {
                    namespaces::write_ns_file(b"/proc/self/uid_map\0", &uid_map_content).ok();
                }
                unsafe {
                    let _ = namespaces::write_ns_file(b"/proc/self/setgroups\0", b"deny\n");
                }
                unsafe {
                    namespaces::write_ns_file(b"/proc/self/gid_map\0", &gid_map_content).ok();
                }
            }

            // 第 7 步：sethostname
            if let Some(ref h) = hostname_bytes {
                unsafe {
                    namespaces::set_hostname(h).ok();
                }
            }

            // 第 8 步：landlock
            if raw_ruleset_fd >= 0 {
                let ret =
                    unsafe { libc::syscall(libc::SYS_landlock_restrict_self, raw_ruleset_fd, 0) };
                if ret != 0 {
                    unsafe {
                        libc::_exit(1);
                    }
                }
                unsafe {
                    libc::close(raw_ruleset_fd);
                }
            }

            // 第 9 步：seccomp（如果需要）
            if let Some(ref filter) = bpf_filter {
                // USER_NOTIF 路径：安装 deny filter 并获取 listener fd
                let listener_fd = match seccomp::install_user_notif_filter(filter) {
                    Ok(fd) => fd,
                    Err(_) => unsafe {
                        libc::_exit(1);
                    },
                };

                // 第 10 步：sendmsg SCM_RIGHTS（将 listener fd 发给父进程）
                if send_fd(child_fd_raw, listener_fd).is_err() {
                    unsafe {
                        libc::close(listener_fd);
                    }
                    unsafe {
                        libc::close(child_fd_raw);
                    }
                    unsafe {
                        libc::_exit(1);
                    }
                }
                unsafe {
                    libc::close(child_fd_raw);
                }
                // 关掉子进程继承的 parent_stream 端
                if parent_fd_raw_for_child >= 0 {
                    unsafe {
                        libc::close(parent_fd_raw_for_child);
                    }
                }
            }

            // 安装外部 BPF filter（prctl 直装，无 NEW_LISTENER）
            for ext_bytes in &ext_filter_bytes {
                // 将字节转为 sock_filter 切片
                // SAFETY: ext_bytes 由外部用户提供，必须是合法的 cBPF 字节码。
                // 内核会在 prctl 时校验；格式不合法会返回 EINVAL。
                let filter = unsafe {
                    std::slice::from_raw_parts(
                        ext_bytes.as_ptr() as *const seccomp::sock_filter,
                        ext_bytes.len() / std::mem::size_of::<seccomp::sock_filter>(),
                    )
                };
                if seccomp::install_plain_filter(filter).is_err() {
                    unsafe {
                        libc::_exit(1);
                    }
                }
            }

            // 第 11 步：execvp
            let cstring_args: Vec<CString> = std::iter::once(spec.program.clone())
                .chain(spec.args.clone())
                .map(|a| CString::new(a).unwrap_or_default())
                .collect();
            let mut argv: Vec<*const libc::c_char> =
                cstring_args.iter().map(|a| a.as_ptr()).collect();
            argv.push(std::ptr::null());
            unsafe {
                libc::execvp(argv[0], argv.as_ptr());
            }

            // execvp 失败才走到这里
            unsafe {
                libc::_exit(127);
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

/// 把一个 fd 通过 `sendmsg(SCM_RIGHTS)` 经 unix socket 发出去。
///
/// 在 `pre_exec`（fork 后 exec 前）调用，**不能**使用任何堆分配或
/// `std::io::Write`。本函数只操作栈上 POD（msghdr / iovec / cmsghdr / fd数组）。
///
/// 载荷是一个 magic byte `0x42`，让父端能确认消息完整收到。
fn send_fd(socket_fd: RawFd, fd_to_send: RawFd) -> std::io::Result<()> {
    // iovec 描述载荷（1 字节 magic）。
    let payload = CTRL_PAYLOAD;
    let iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len: payload.len(),
    };

    // cmsg 缓冲区：容纳一个 cmsghdr + 一个 i32 fd。
    // CMSG_SPACE(sizeof(i32)) = align(cmsghdr + sizeof(i32)) = 24 字节（在 64 位）。
    // 用 union 确保对齐。`libc::cmsghdr` 在不同 libc 版本上 padding 各异，
    // 这里用 `MaybeUninit<u8>` 裸缓冲区 + `CMSG_SPACE` 算大小。
    let cmsg_space = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as libc::c_uint) } as usize;
    let mut cmsg_buf = [MaybeUninit::<u8>::uninit(); 64];
    assert!(
        cmsg_space <= cmsg_buf.len(),
        "cmsg buffer too small: need {cmsg_space}, have {}",
        cmsg_buf.len()
    );

    let msghdr = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &iov as *const _ as *mut _,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr() as *mut _,
        msg_controllen: cmsg_space as _,
        msg_flags: 0,
    };

    // 把 cmsghdr 写入缓冲区头部，data 区域写 fd。
    // SAFETY：
    // - `cmsg_buf` 至少 `CMSG_SPACE(sizeof(fd))` 字节。
    // - `CMSG_FIRSTHDR` 返回的指针位于该缓冲区内，对齐正确。
    unsafe {
        let cmsg_ptr = libc::CMSG_FIRSTHDR(&msghdr);
        if cmsg_ptr.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        (*cmsg_ptr).cmsg_level = libc::SOL_SOCKET;
        (*cmsg_ptr).cmsg_type = SCM_RIGHTS;
        (*cmsg_ptr).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as libc::c_uint) as _;

        // 把 fd 写到 cmsg data 区域。
        let data_ptr = libc::CMSG_DATA(cmsg_ptr) as *mut RawFd;
        // 关键：必须把 fd 的**原始数值**写入 data；内核随后会在
        // 收端自动 dup 一个新 fd 给收方。
        std::ptr::write(data_ptr, fd_to_send);
    }

    // SAFETY：msghdr 完整初始化，iovec 与 cmsg 都在缓冲区有效期内。
    let sent = unsafe { libc::sendmsg(socket_fd, &msghdr, 0) };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
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

/// PID namespace 的 init 进程（reaper）。
///
/// 循环 `waitpid(-1)` 收割所有子进程和托孤进程。
/// 当业务进程（`business_pid`）退出时记录退出码，继续收割。
/// 当 `waitpid` 返回 ECHILD（无子进程）时退出，返回业务进程退出码。
///
/// 参照 bwrap `do_init()` 的实现。
fn do_reaper(business_pid: libc::pid_t) -> i32 {
    // SAFETY: 全部 libc 调用都是 async-signal-safe 的 waitpid/macro。
    // 此函数只在 fork 后的 PID 1 单线程子进程中调用。
    unsafe {
        let mut exit_code = 1;
        loop {
            let mut status: i32 = 0;
            let wpid = libc::waitpid(-1, &mut status, 0);
            if wpid == business_pid {
                exit_code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else if libc::WIFSIGNALED(status) {
                    128 + libc::WTERMSIG(status)
                } else {
                    1
                };
            } else if wpid < 0 {
                break;
            }
        }
        exit_code
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
