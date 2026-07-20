//! 基于 Landlock + seccomp BPF 的 Linux 沙箱实现。
//!
//! 提供实现了 [`Sandbox`] trait 的 [`LinuxSandbox`]：
//! 通过 Landlock ACL 做文件系统访问控制，通过手写的 seccomp BPF 黑名单
//! 做系统调用过滤。
//!
//! ## 执行流程（USER_NOTIF 路径）
//!
//! 1. **父进程** 构建 Landlock 规则集以及 seccomp BPF filter。
//! 2. **父进程** 创建 `socketpair(AF_UNIX, SOCK_SEQPACKET)`，得到两端
//!    `ctrl_parent` / `ctrl_child`，稍后将 fd 经 fork 继承给子进程。
//! 3. **父进程** `Command::spawn()` 并附带一个 `pre_exec` 闭包。
//! 4. **子进程**（fork → pre_exec → execve）依次执行：
//!    - `prctl(PR_SET_NO_NEW_PRIVS, 1, …)`
//!    - `landlock_restrict_self(ruleset_fd, 0)`（若存在规则集）
//!    - `seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER, &fprog)` 加载 BPF 并
//!      拿到 listener fd
//!    - `sendmsg(SCM_RIGHTS)` 把 listener fd 跨 unix socket 交给父进程
//!    - `execve(...)` 启动目标程序
//! 5. **父进程** worker 线程：
//!    - 从 socketpair 用 `recvmsg(SCM_RIGHTS)` 拿到 listener fd
//!    - 循环 `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` 阻塞读拦截通知
//!    - 捕获 `seccomp_notif.data.{nr,arch}`，记录到 `blocked`
//!    - 用 `ioctl(SECCOMP_IOCTL_NOTIF_SEND)` 回复 `error = EPERM`，
//!      让拦截的 syscall 直接以权限错误返回（不进入 syscall 主体）。
//! 6. **父进程** 在 reap 时从 `siginfo` 拿到 exit_code / 退出原因。
//! 7. **关键**：USER_NOTIF 下子进程通常**不会**被信号杀死，进程收到
//!    EPERM 后继续运行并以正常 exit_code 退出（多数 syscall_probe 会
//!    自行返回 0）。`execute` 把 `(nr, arch)` 编码为 `BLOCKED_MARKER`
//!    行追加到 `CommandOutput::stderr`；`classify_exit` 解析该标记以
//!    在 exit_code=0 的情况下仍然把命令归类为 `Denied { Seccomp }`。

pub mod landlock;
pub mod namespaces;
pub mod seccomp;

use std::mem::{self, MaybeUninit};
use std::os::fd::FromRawFd;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use anyhow::Context;

use crate::config::SandboxConfig;
use crate::{CommandOutput, CommandSpec, ExitReason, Sandbox};

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
// Sandbox trait 实现
// ---------------------------------------------------------------------------

impl Sandbox for LinuxSandbox {
    /// 在沙箱内执行一条命令。
    ///
    /// 在**父进程**中构建 Landlock 规则集与 seccomp BPF filter，
    /// 然后在**子进程**中通过 `pre_exec` 闭包（零分配上下文）施加两者，
    /// 并通过 `SECCOMP_RET_USER_NOTIF` 把拦截事件转发到父进程侧的
    /// listener fd，由 worker 线程处理后填入 `BLOCKED_MARKER`。
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<CommandOutput> {
        // 在 spawn 之前先复制 program 名，用于失败时的诊断消息。
        // sandbox-runtime 通过 `execve` 直接执行单个程序，不解释 shell
        // 元字符（`>`、`>>`、`|`、`*` 等）；用户传入含 shell 语法的 token
        // 时，spawn 会以 ENOENT 失败，要在错误里把修改建议说清楚。
        let program_for_error = spec.program.clone();

        // ── 步骤 1：构建 Landlock 规则集并取出其 fd ────────────────────
        let ruleset_fd: Option<OwnedFd> = self.prepare_ruleset_fd()?;
        let raw_ruleset_fd: i32 = ruleset_fd.as_ref().map(|fd| fd.as_raw_fd()).unwrap_or(-1);

        // ── 步骤 2：构建 seccomp BPF filter ───────────────────────────
        let bpf_filter = self.build_bpf_filter();
        // USER_NOTIF 路径下不再需要把 sock_fprog 传入 pre_exec：
        // 子进程在 pre_exec 内自己调用 `seccomp::install_user_notif_filter`，
        // 它会就地构造 sock_fprog 并通过 seccomp(2) 提交。

        // ── 步骤 3：必要时在 cwd 中展开 ~ ─────────────────────────────
        let cwd = match spec.cwd.to_str() {
            Some(s) => PathBuf::from(crate::config::expand_tilde(s)),
            None => spec.cwd.clone(),
        };

        // ── 步骤 4：创建 socketpair（父端 + 子端）─────────────────────
        //
        // socketpair(AF_UNIX, SOCK_SEQPACKET, 0) → 返回 [parent_fd, child_fd]。
        //
        // - 父端保留 `parent_stream` 用于 `recvmsg` 收 listener fd。
        // - 子端原始 fd 数值 `child_fd` 通过 `i32` 传入 `pre_exec` 闭包
        //   （async-signal-safe），由 `send_fd` 调用后显式 `libc::close`。
        let (parent_stream, child_sock) = create_socketpair()?;
        // 提取原始 fd 数值供 pre_exec 闭包使用（闭包内只能访问 i32 Copy，
        // 不能持有 OwnedFd——闭包在 fork 后 drop 会双关同一 fd）。
        let child_fd_raw = child_sock.as_raw_fd();

        // ── 计算 namespace 参数 ────────────────────────────────
        let ns = &self.config.namespaces;
        let ns_ops: Vec<(i32, bool)> = {
            let mut v = Vec::new();
            if ns.user {
                v.push((libc::CLONE_NEWUSER, ns.user_try));
            }
            if ns.ipc {
                v.push((libc::CLONE_NEWIPC, false));
            }
            if ns.pid {
                v.push((libc::CLONE_NEWPID, false));
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

        // ── 预计算 uid_map/gid_map 内容（如果 user ns）─────────────
        let real_uid: u32 = unsafe { libc::getuid() };
        let real_gid: u32 = unsafe { libc::getgid() };
        let sandbox_uid = ns.uid.unwrap_or(real_uid);
        let sandbox_gid = ns.gid.unwrap_or(real_gid);
        let uid_map_content: Vec<u8> = format!("{sandbox_uid} {real_uid} 1\n").into_bytes();
        let gid_map_content: Vec<u8> = format!("{sandbox_gid} {real_gid} 1\n").into_bytes();

        // ── 预计算 hostname bytes ────────────────────────────
        let hostname_bytes: Option<Vec<u8>> = ns.hostname.as_ref().map(|h| h.as_bytes().to_vec());

        // ── 步骤 5：以 pre_exec 施加限制并 spawn 子进程 ───────────────
        //
        // 关于 `pre_exec` 的 SAFETY：
        //
        // 该闭包在 `fork()` 之后、`execve()` 之前执行。我们特别注意：
        //
        // * 只捕获 `raw_ruleset_fd`（一个 `i32`）与 `child_fd_raw`（一个 `i32`）。
        // * 在闭包内**不**进行任何堆分配或 `format!`（async-signal-safe）。
        // * 仅调用 `libc::prctl`、`libc::syscall`、`libc::close` 与
        //   `libc::sendmsg` —— 这些都是 async-signal-safe 的。
        //
        // 子进程内的 BPF filter 数据通过 `seccomp::install_user_notif_filter`
        // 的内部栈上 `sock_fprog` 提供，调用返回后数据已被内核拷走，
        // 不会越界引用父进程内存。
        let child = unsafe {
            std::process::Command::new(&spec.program)
                .args(&spec.args)
                .current_dir(&cwd)
                .env_clear() // 清空继承的环境变量，只保留 spec.env
                .envs(&spec.env)
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .pre_exec(move || {
                    // ── 第 1 步：逐个创建 namespace ───────────────────
                    let mut user_ns_active = false;
                    for &(flag, try_mode) in &ns_ops {
                        let ret = libc::syscall(libc::SYS_unshare, flag as libc::c_long);
                        if ret != 0 {
                            if try_mode {
                                continue;
                            }
                            return Err(std::io::Error::last_os_error());
                        }
                        if (flag & libc::CLONE_NEWUSER) != 0 {
                            user_ns_active = true;
                        }
                    }

                    // ── 第 2 步：prctl(NO_NEW_PRIVS) ───────────────────
                    // seccomp 和 Landlock（非 root 下）均需要 no_new_privs。
                    // 放在 uid_map 之后没有问题——写 uid_map 不需要该标志。
                    let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                    if ret != 0 {
                        return Err(std::io::Error::last_os_error());
                    }

                    // ── 第 3 步：如果 user ns 创建成功，写 uid/gid map ───
                    if user_ns_active {
                        namespaces::write_ns_file(b"/proc/self/uid_map\0", &uid_map_content)?;
                        let _ = namespaces::write_ns_file(b"/proc/self/setgroups\0", b"deny\n");
                        namespaces::write_ns_file(b"/proc/self/gid_map\0", &gid_map_content)?;
                    }

                    // ── 第 4 步：sethostname（如果设置了 hostname）───────
                    if let Some(ref h) = hostname_bytes {
                        namespaces::set_hostname(h)?;
                    }

                    // ── 第 5 步：landlock_restrict_self ─────────────────
                    if raw_ruleset_fd >= 0 {
                        // SAFETY：`raw_ruleset_fd` 是父进程经由
                        // `landlock_create_ruleset(2)` 创建的有效 fd。
                        // 内核会校验访问权限。
                        let ret =
                            libc::syscall(libc::SYS_landlock_restrict_self, raw_ruleset_fd, 0);
                        if ret != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        // 在子进程中关闭 fd，已经不再需要。
                        libc::close(raw_ruleset_fd);
                    }

                    // ── 第 6 步：seccomp BPF filter ───────────────────
                    let listener_fd = match seccomp::install_user_notif_filter(&bpf_filter) {
                        Ok(fd) => fd,
                        Err(_) => {
                            return Err(std::io::Error::other("install_user_notif_filter failed"));
                        }
                    };

                    // ── 第 7 步：sendmsg SCM_RIGHTS ───────────────────
                    if let Err(e) = send_fd(child_fd_raw, listener_fd) {
                        libc::close(listener_fd);
                        libc::close(child_fd_raw);
                        return Err(e);
                    }
                    // 子端 fd 已用过，关闭以避免泄漏到 exec 后的进程。
                    libc::close(child_fd_raw);
                    // listener fd 留在本进程（不关）——execve 后 BPF filter
                    // 仍在生效，但 listener 是由父进程持有的引用，
                    // 子进程不再需要它。让它随 exec 自然消失即可。

                    Ok(())
                })
                .spawn()
                .with_context(|| {
                    format!(
                        "Failed to spawn sandboxed process '{program_for_error}'. \
                         Note: sandbox-runtime does NOT interpret shell metacharacters \
                         (>, >>, |, *, &&, etc.) — it runs the program directly via execve. \
                         To use shell syntax, invoke 'sh -c' explicitly, e.g. \
                         `-- sh -c \"your shell command here\"`. \
                         Or split the command into separate args without shell metacharacters."
                    )
                })?
        };

        // 关闭子端 socketpair fd（OwnedFd drop → RAII close）。无论 pre_exec
        // 是否成功执行 sendmsg，子端都必须在父进程中关闭；否则 socketpair 连接
        // 存活，worker 线程的 recvmsg 永远阻塞（死锁详见 docs/learned.md）。
        drop(child_sock);

        let pid = child.id() as libc::id_t;

        // ── 步骤 6：spawn USER_NOTIF worker + 共享 blocked ─────────
        //
        // worker 线程负责：
        // 1. 通过 `recvmsg(SCM_RIGHTS)` 从父端 socketpair 拿到 listener fd。
        // 2. 进入循环 `poll([listener_fd, shutdown_r])`：
        //    - listener_fd 可读 → `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` 读拦截
        //      并通过 `ioctl(SECCOMP_IOCTL_NOTIF_SEND)` 回复 EPERM。
        //    - shutdown_r 可读 → 主线程已 wait 完，写了 1 字节，break 退出。
        //
        // 关键：用 self-pipe 让 worker 在子进程**正常退出**（未触发黑名单）
        // 也能立即醒来退出。原来的实现 `ioctl(RECV)` 阻塞会 hang。
        //
        // worker 把捕获到的最后一个 `(nr, arch)` 写入共享 `blocked`
        // （多个 syscall 时记录**最后一次**——黑名单每次只触发一条）。
        let blocked = std::sync::Arc::new(std::sync::Mutex::new(None::<(u32, u32)>));

        // 把父端 socketpair 的 raw fd 抽出来传给 helper，避免
        // 把 OwnedFd 移进闭包后外面还要 drop（helper 内部只借用 raw fd）。
        let parent_fd_raw = parent_stream.as_raw_fd();
        let _notif_handle = spawn_user_notif_worker(parent_fd_raw, &blocked)?;

        // ── 步骤 8：waitid(WEXITED) —— 阻塞到子进程退出 ─────────────
        //
        // 与 TRAP 路径不同：USER_NOTIF 下子进程**不会**被信号杀死，
        // 而是黑名单 syscall 在入口返回 EPERM，进程自然继续。
        // 因此 exit_code 与普通程序一样。
        //
        // SAFETY：siginfo 由 waitid 写入。
        let mut siginfo: libc::siginfo_t = unsafe { mem::zeroed() };
        let r = unsafe { libc::waitid(libc::P_PID, pid, &mut siginfo, libc::WEXITED) };
        if r != 0 {
            let e = std::io::Error::last_os_error();
            // waitid 失败，关闭父端 socketpair 让 worker recv_fd 退出。
            drop(parent_stream);
            return Err(e).with_context(|| {
                format!("waitid(WEXITED) failed for sandboxed process '{program_for_error}'")
            });
        }

        // 子进程已退出。worker 线程会在 listener fd 上收到 POLLHUP 后自然退出。
        // notif_handle 在函数结束时被 drop。

        // ── 步骤 9：读取 blocked ─────────────────────────────────
        let blocked_val = blocked.lock().ok().and_then(|g| *g);

        // 退出码：正常退出 → ExitCode；信号杀死 → 128 + signum。
        // SAFETY：siginfo 由上面的 waitid 调用写入并填充了 si_code/si_status。
        let exit_code = if siginfo.si_code == libc::CLD_EXITED {
            unsafe { siginfo.si_status() }
        } else if siginfo.si_code == libc::CLD_KILLED || siginfo.si_code == libc::CLD_DUMPED {
            128 + unsafe { siginfo.si_status() }
        } else {
            -1
        };

        // ── 步骤 10：构造 CommandOutput ───────────────────────────
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
            let category = seccomp::syscall_by_name(name)
                .map(|s| s.category.tag())
                .unwrap_or("unknown");
            return Denied {
                mechanism: DenyMechanism::Seccomp,
                message: format!(
                    "Blocked by seccomp filter (SIGSYS): \
                     syscall='{name}' category='{category}' nr={nr} \
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
        let created =
            landlock::build_ruleset(&self.config.filesystem.landlock, &std::env::current_dir()?)?;

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
    /// 返回一个包含 `BLACKLIST.len() + 6` 条 `sock_filter` 指令的 `Vec`
    ///（详见 [`seccomp::build_blacklist_filter`]）。
    fn build_bpf_filter(&self) -> Vec<seccomp::sock_filter> {
        seccomp::build_blacklist_filter()
    }
}

// ---------------------------------------------------------------------------
// socketpair + SCM_RIGHTS helpers
// ---------------------------------------------------------------------------

/// 创建 `socketpair(AF_UNIX, SOCK_SEQPACKET, 0)` 并返回父端 `OwnedFd` 与
/// 子端原始 fd（i32，由调用方在 pre_exec 中显式 close）。
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

/// Spawn worker 线程，负责响应 seccomp USER_NOTIF 通知。
///
/// # 参数
///
/// * `parent_sock_raw` —— socketpair 父端的 raw fd（pre_exec 中子进程
///   通过 `sendmsg(SCM_RIGHTS)` 把 listener fd 发到这里）。worker 在
///   自己闭包里调用 `recv_fd(parent_sock_raw)` 拿 listener。
/// * `blocked` —— 共享 `(nr, arch)` 状态；worker 把每次拦截的 syscall
///   信息写进去，主线程在 `waitid` 后读。
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
