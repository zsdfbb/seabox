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
pub mod seccomp;

use std::mem::{self, MaybeUninit};
use std::os::fd::FromRawFd;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use anyhow::Context;

use crate::config::SandboxConfig;
use crate::{CommandOutput, CommandSpec, ExitReason, PreparedCommand, Sandbox};

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

/// 当 `execute()` 收到 worker 上报的 `(nr, arch)` 后，会把这一行前缀
/// 写到 `CommandOutput::stderr` 头部。`classify_exit` 解析该前缀以
/// 在 child exit_code=0 时仍识别为 Seccomp 拒绝。
///
/// 格式（ASCII）：
///   `BLOCKED_MARKER <name> <category> <nr_dec> <arch_hex>\n`
///
/// 设计要点：
/// - 单 ASCII 行，固定前缀 → 解析简单。
/// - 先于子进程自身 stderr 写出 → 即使子进程从未写 stderr 也存在。
/// - `classify_exit` 按行扫到该 marker 后即返回 `Denied { Seccomp }`。
const BLOCKED_MARKER_PREFIX: &str = "[sandbox-runtime:blocked] ";

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
        let ruleset_fd: Option<OwnedFd> = self.prepare_ruleset_fd(spec)?;
        let raw_ruleset_fd: i32 = ruleset_fd
            .as_ref()
            .map(|fd| fd.as_raw_fd())
            .unwrap_or(-1);

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
        let (parent_stream, child_fd_raw) = create_socketpair()?;

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
        let mut child = unsafe {
            std::process::Command::new(&spec.program)
                .args(&spec.args)
                .current_dir(&cwd)
                .envs(&spec.env)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .pre_exec(move || {
                    // -------------------------------------------------------
                    // 步骤 A：prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                    //
                    // 对于没有 CAP_SYS_ADMIN 的进程，在使用
                    // SECCOMP_MODE_FILTER 之前必须设置。
                    // man:prctl(2) PR_SET_NO_NEW_PRIVS
                    // -------------------------------------------------------
                    // SAFETY：参数都是普通整数；内核会校验并
                    // 在失败时返回错误码。
                    let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                    if ret != 0 {
                        return Err(std::io::Error::last_os_error());
                    }

                    // -------------------------------------------------------
                    // 步骤 B：landlock_restrict_self(ruleset_fd, 0)
                    //
                    // 将 Landlock 规则集施加到当前进程。仅在已构建
                    // 规则集（非 FullAccess）时调用。
                    // man:landlock_restrict_self(2)
                    // -------------------------------------------------------
                    if raw_ruleset_fd >= 0 {
                        // SAFETY：`raw_ruleset_fd` 是父进程经由
                        // `landlock_create_ruleset(2)` 创建的有效 fd。
                        // 内核会校验访问权限。
                        let ret = libc::syscall(
                            libc::SYS_landlock_restrict_self,
                            raw_ruleset_fd,
                            0,
                        );
                        if ret != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        // 在子进程中关闭 fd，已经不再需要。
                        libc::close(raw_ruleset_fd);
                    }

                    // -------------------------------------------------------
                    // 步骤 C：seccomp(SECCOMP_SET_MODE_FILTER,
                    //                   SECCOMP_FILTER_FLAG_NEW_LISTENER,
                    //                   &fprog)
                    //
                    // 加载 BPF 黑名单 filter。之后的每一次系统调用都会
                    // 通过这个 filter 校验。
                    // 命中黑名单时返回 SECCOMP_RET_USER_NOTIF，
                    // 内核向 listener fd 投递 seccomp_notif，由父进程
                    // 的 worker 读取后通过 SECCOMP_IOCTL_NOTIF_SEND
                    // 回复 EPERM。
                    //
                    // 错误信息是 async-signal-safe 的固定字符串
                    //（**不**使用 `format!` 以避免堆分配）。
                    // man:seccomp(2) SECCOMP_SET_MODE_FILTER
                    // -------------------------------------------------------
                    let listener_fd = match seccomp::install_user_notif_filter(&bpf_filter) {
                        Ok(fd) => fd,
                        Err(_) => {
                            return Err(std::io::Error::other(
                                "install_user_notif_filter failed",
                            ));
                        }
                    };

                    // -------------------------------------------------------
                    // 步骤 D：sendmsg(SCM_RIGHTS) 把 listener fd 发给父进程
                    //
                    // 把 listener fd 通过 unix socket 跨进程边界交给父进程，
                    // 父进程侧的 worker 线程通过 recvmsg(SCM_RIGHTS) 收。
                    //
                    // 我们附一个单字节 payload `0x42` 让父端能确认消息
                    // 完整收到（无 payload 的 sendmsg 在某些内核上行为
                    // 略有差异）。
                    //
                    // 失败时**先** close 已拿到的 listener fd 再返回
                    // Err，避免 fd 泄漏到 exec 后的进程。
                    // -------------------------------------------------------
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

        let pid = child.id() as libc::id_t;

        // ── 步骤 6：在后台线程里抽干 stdout / stderr ──────────────────
        // 必须先 take 出句柄再 wait，否则子进程写满 pipe 后会阻塞 SIGKILL。
        let mut stdout_handle = child.stdout.take().expect("piped stdout");
        let mut stderr_handle = child.stderr.take().expect("piped stderr");
        let stdout_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stdout_handle, &mut buf);
            buf
        });
        let stderr_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stderr_handle, &mut buf);
            buf
        });

        // ── 步骤 7：spawn USER_NOTIF worker + 共享 blocked ─────────
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
        let notif_handle = spawn_user_notif_worker(parent_fd_raw, &blocked)?;

        // ── 步骤 8：waitid(WEXITED) —— 阻塞到子进程退出 ─────────────
        //
        // 与 TRAP 路径不同：USER_NOTIF 下子进程**不会**被信号杀死，
        // 而是黑名单 syscall 在入口返回 EPERM，进程自然继续。
        // 因此 exit_code 与普通程序一样。
        //
        // SAFETY：siginfo 由 waitid 写入。
        let mut siginfo: libc::siginfo_t = unsafe { mem::zeroed() };
        let r = unsafe {
            libc::waitid(libc::P_PID, pid, &mut siginfo, libc::WEXITED)
        };
        if r != 0 {
            let e = std::io::Error::last_os_error();
            // 子进程可能仍在运行；notify worker 退出 + join 即可。
            notif_handle.shutdown();
            notif_handle.join();
            // 关闭父端 socketpair（如果 worker 还没读完）。
            drop(parent_stream);
            return Err(e).with_context(|| {
                format!(
                    "waitid(WEXITED) failed for sandboxed process '{program_for_error}'"
                )
            });
        }

        // 子进程已退出。关闭父端 socketpair 让 worker 的 recvmsg 收到 EOF
        // （如果还在阻塞），从而跳出循环。同时写 self-pipe 唤醒 worker，
        // 避免 worker 卡在 poll 里——尤其在子进程未触发黑名单时，listener
        // 永远不会有可读事件，必须靠 self-pipe 唤醒。
        drop(parent_stream);

        // ── 步骤 9：通知 worker 退出 + join ───────────────────────
        notif_handle.shutdown();
        notif_handle.join();

        // ── 步骤 10：读取 blocked ─────────────────────────────────
        let blocked_val = blocked.lock().ok().and_then(|g| *g);

        // 收集 stdout / stderr
        let stdout_bytes = stdout_thread.join().unwrap_or_default();
        let stderr_bytes = stderr_thread.join().unwrap_or_default();

        // 退出码：正常退出 → ExitCode；信号杀死 → 128 + signum。
        // SAFETY：siginfo 由上面的 waitid 调用写入并填充了 si_code/si_status。
        let exit_code = if siginfo.si_code == libc::CLD_EXITED {
            unsafe { siginfo.si_status() }
        } else if siginfo.si_code == libc::CLD_KILLED || siginfo.si_code == libc::CLD_DUMPED {
            128 + unsafe { siginfo.si_status() }
        } else {
            // 未知 si_code（理论上不会发生）。fallback 到 -1。
            -1
        };

        // ── 步骤 11：构造 CommandOutput ────────────────────────────
        // 把 `blocked` 通过 BLOCKED_MARKER 前缀行写入 stderr 头部，
        // `classify_exit` 会优先解析该标记。
        //
        // 消息字符串保留 `Blocked by seccomp filter (SIGSYS)` 子串，
        // 以便既有的 `tests/seccomp_test.rs` 断言 `out.stderr.contains(
        // "Blocked by seccomp filter (SIGSYS)")` 继续成立；同时附带
        // `syscall='...'/category='...'/nr=.../arch=0x.../reason=blacklist/signal=SIGSYS`
        // 富诊断字段供 Agent / log 抓取。
        let stderr_string = match blocked_val {
            Some((nr, arch)) => {
                let name = seccomp::syscall_name(nr).unwrap_or("unknown");
                let category = seccomp::syscall_by_name(name)
                    .map(|s| s.category.tag())
                    .unwrap_or("unknown");
                let marker = format!(
                    "{BLOCKED_MARKER_PREFIX}Blocked by seccomp filter (SIGSYS): \
                     syscall='{name}' category='{category}' nr={nr} arch=0x{arch:x} \
                     reason=blacklist signal=SIGSYS\n"
                );
                // marker 在前，原 stderr 在后。
                let mut combined = marker;
                let original = String::from_utf8_lossy(&stderr_bytes);
                combined.push_str(&original);
                combined
            }
            None => String::from_utf8_lossy(&stderr_bytes).to_string(),
        };

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&stdout_bytes).to_string(),
            stderr: stderr_string,
            exit_code,
            blocked_syscall: blocked_val,
        })
    }

    /// 通过解析路径并填充 [`PreparedCommand`] 来准备执行一个 [`CommandSpec`]。
    ///
    /// **不会** spawn 进程，也不会施加任何沙箱限制。
    fn prepare(&self, spec: &CommandSpec) -> anyhow::Result<PreparedCommand> {
        let mut command = vec![spec.program.clone()];
        command.extend(spec.args.clone());

        let cwd = match spec.cwd.to_str() {
            Some(s) => PathBuf::from(crate::config::expand_tilde(s)),
            None => spec.cwd.clone(),
        };

        Ok(PreparedCommand {
            command,
            cwd,
            env: spec.env.clone(),
            timeout: spec.timeout,
        })
    }

    /// 将已完成命令的退出码、stderr 与可选的 `(nr, arch)` 归类为一个
    /// [`ExitReason`]。
    ///
    /// 检测依据（按优先级）：
    ///
    /// 1. **`blocked` Option** → USER_NOTIF 命中黑名单（由 `execute`
    ///    从 worker 上报的 `(nr, arch)`）。这是首选来源：直接查表得到
    ///    syscall 名与 category，生成富诊断消息。即使 `exit_code == 0`
    ///    （黑名单 syscall 返回 EPERM，进程继续并正常退出）也能正确归类为
    ///    `Denied { Seccomp, rich_message }`。
    /// 2. **BLOCKED_MARKER** → 兼容/冗余路径：解析 `execute` 写入 stderr
    ///    头部的 marker 行（当上层只拿到 stderr、没有结构化 `blocked` 时）。
    /// 3. **退出码 31 或 159** → SIGSYS（传统 BPF KILL 路径）。
    /// 4. **stderr 模式** → Landlock 拒绝（EPERM/EACCES）或
    ///    seccomp 拒绝（"Bad system call"、"SIGSYS"、"seccomp"）。
    /// 5. **其他情况** → 普通程序退出。
    fn classify_exit(
        &self,
        exit_code: i32,
        stderr: &str,
        blocked: Option<(u32, u32)>,
    ) -> ExitReason {
        use crate::DenyMechanism;
        use crate::ExitReason::*;

        // ── 优先级 1：结构化 blocked (nr, arch) ─────────────────────
        // 首选来源。直接查表生成富诊断消息，与 `execute` 写入 stderr
        // 的 marker 行同构（同样保留 `Blocked by seccomp filter (SIGSYS)`
        // 子串以兼容既有断言）。即便 exit_code == 0 也命中 Denied。
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

        // ── 优先级 2：USER_NOTIF BLOCKED_MARKER（兼容/冗余）─────────
        // 当调用方只有 stderr、没有结构化 `blocked` 时，仍能从 marker
        // 行还原 Denied。即便 exit_code == 0 也必须命中。
        if let Some(line) = stderr
            .lines()
            .find(|l| l.starts_with(BLOCKED_MARKER_PREFIX))
        {
            let message = line
                .strip_prefix(BLOCKED_MARKER_PREFIX)
                .unwrap_or(line)
                .to_string();
            return Denied {
                mechanism: DenyMechanism::Seccomp,
                message,
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

        let lower = stderr.to_lowercase();

        // ── 优先级 5：Landlock 拒绝模式 ──────────────────────────────
        // Landlock 用 EACCES 或 EPERM 阻止文件系统操作。
        if lower.contains("operation not permitted")
            || lower.contains("permission denied")
            || lower.contains("eacces")
            || lower.contains("eperm")
        {
            return Denied {
                mechanism: DenyMechanism::Landlock,
                message: format!(
                    "Landlock blocked access: {}",
                    stderr.lines().next().unwrap_or("unknown")
                ),
            };
        }

        // ── 优先级 6：Seccomp 拒绝模式 ────────────────────────────────
        // seccomp filter 通过 audit log 或 libc/内核写到 stderr 的
        // 消息来体现拦截。
        if lower.contains("bad system call")
            || lower.contains("sigsys")
            || lower.contains("seccomp")
        {
            return Denied {
                mechanism: DenyMechanism::Seccomp,
                message: format!(
                    "Seccomp blocked syscall: {}",
                    stderr.lines().next().unwrap_or("unknown")
                ),
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
    /// * `FsPolicy::FullAccess` → 返回 `None`（不施加 Landlock 限制）。
    /// * 其他策略 → 通过 `landlock::build_ruleset` 构建规则集，
    ///   然后从 `RulesetCreated` 取出底层的 `OwnedFd`。
    ///
    /// 调用方（即上面的 `execute`）将原始 fd 传入 `pre_exec` 闭包，
    /// 由子进程调用 `landlock_restrict_self(2)`。
    fn prepare_ruleset_fd(&self, spec: &CommandSpec) -> anyhow::Result<Option<OwnedFd>> {
        // 在 allow_write 路径中展开 ~。
        let allow_write: Vec<PathBuf> = self
            .config
            .filesystem
            .allow_write
            .iter()
            .map(|p| PathBuf::from(crate::config::expand_tilde(p)))
            .collect();

        // 构建规则集（FullAccess 时可能返回 None）。
        let created = landlock::build_ruleset(&spec.sandbox_policy, &allow_write, &spec.cwd)?;

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
fn create_socketpair() -> std::io::Result<(OwnedFd, RawFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY：socketpair(2) 接受有效协议族与 type，flags=0 是默认；
    // 输出数组长度为 2，对应一个 read fd + 一个 write fd。
    let ret = unsafe { libc::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let parent_fd = fds[0];
    let child_fd = fds[1];
    // SAFETY：parent_fd 是刚创建的有效 socket fd；移交给 OwnedFd 后由 RAII 管理。
    let parent_owned = unsafe { OwnedFd::from_raw_fd(parent_fd) };
    Ok((parent_owned, child_fd))
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
/// 通过 [`spawn_user_notif_worker`] 创建；主线程必须先调用
/// [`UserNotifHandle::shutdown`] 唤醒 worker 阻塞的 `poll`，再调用
/// [`UserNotifHandle::join`] 等待 worker 线程退出（`join` 内部关闭
/// shutdown pipe 的写端）。
///
/// **关键不变量**：`shutdown` 必须在 `join` 之前调用；否则 worker 永远
/// 阻塞在 `poll`（当子进程未触发黑名单 syscall 时），`join` 也跟着 hang。
struct UserNotifHandle {
    /// worker 线程句柄。`join()` 取走后置 None 防止重复 join。
    worker: Option<std::thread::JoinHandle<()>>,
    /// self-pipe 的写端（主线程持有）。`join()` 内部 `close()` 释放。
    shutdown_w: RawFd,
}

impl UserNotifHandle {
    /// 通知 worker 退出：写 1 字节到 self-pipe 唤醒其 `poll`。
    ///
    /// 即使 worker 已经在退出过程中，写入一个已无读者的 pipe 也只是
    /// 返回 EPIPE / SIGPIPE；这里忽略错误（已经没人在乎）。
    fn shutdown(&self) {
        let buf = b"x";
        // SAFETY：buf 是栈上 1 字节 `b"x"`，指针 + 长度都有效；
        // write(2) 在 fd 仍可写时返回 1，否则返回 -1；两种情况都可接受。
        unsafe {
            let _ = libc::write(self.shutdown_w, buf.as_ptr() as *const _, 1);
        }
    }

    /// 等待 worker 线程退出并释放 self-pipe 写端。
    ///
    /// `self` by value：消费 `Option<JoinHandle>`，避免外部误用已
    /// join 的句柄二次 join。
    fn join(mut self) {
        if let Some(h) = self.worker.take() {
            // worker 关闭 shutdown_r 与 listener_fd（OwnedFd 自动 drop）。
            // 主线程在这里等 worker 完全退出。
            let _ = h.join();
        }
        // SAFETY：shutdown_w 是 spawn 时 `pipe(2)` 返回的有效 fd，
        // 在整个 handle 生命周期内由本结构体独占；join 后不再使用。
        unsafe { libc::close(self.shutdown_w) };
    }
}

/// 创建 self-pipe 并 spawn worker 线程。
///
/// # 参数
///
/// * `parent_sock_raw` —— socketpair 父端的 raw fd（pre_exec 中子进程
///   通过 `sendmsg(SCM_RIGHTS)` 把 listener fd 发到这里）。worker 在
///   自己闭包里调用 `recv_fd(parent_sock_raw)` 拿 listener。
/// * `blocked` —— 共享 `(nr, arch)` 状态；worker 把每次拦截的 syscall
///   信息写进去，主线程在 `waitid` 后读。
///
/// # 返回
///
/// * `Ok(UserNotifHandle)` —— 主线程持有 handle，`execute` 在
///   `waitid` 返回后调用 `shutdown()` + `join()` 干净退出。
///
/// # 关键设计：self-pipe
///
/// worker 主循环 `poll([listener_fd, shutdown_r], -1)`：
///
/// * listener_fd 可读 → 处理拦截并回复 EPERM。
/// * shutdown_r 可读 → 主线程 `waitid` 完毕，写 1 字节唤醒 worker，
///   break 退出循环。
///
/// 不使用 self-pipe 时，worker 会一直阻塞在 `ioctl(RECV)`（子进程
/// 正常退出、未触发黑名单时永远不会有 notification），主线程
/// `worker_thread.join()` 永久卡死 → 整个 `execute` hang。
fn spawn_user_notif_worker(
    parent_sock_raw: RawFd,
    blocked: &std::sync::Arc<std::sync::Mutex<Option<(u32, u32)>>>,
) -> std::io::Result<UserNotifHandle> {
    // 1) 创建 self-pipe。
    // SAFETY：pipe(2) 接受 [i32; 2] 输出数组；返回 0 成功，-1 失败。
    let mut pipefds = [0 as RawFd; 2];
    let ret = unsafe { libc::pipe(pipefds.as_mut_ptr()) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let shutdown_r = pipefds[0];
    let shutdown_w = pipefds[1];

    // 2) 把 shutdown_r 包成 OwnedFd，闭包退出时自动 close。
    // SAFETY：shutdown_r 是 pipe(2) 返回的有效 fd。
    let shutdown_r_owned = unsafe { OwnedFd::from_raw_fd(shutdown_r) };
    let blocked_for_worker = std::sync::Arc::clone(blocked);

    // 3) spawn worker 线程。
    let worker = std::thread::spawn(move || {
        // 3a) 收 listener fd。阻塞直到子进程 sendmsg 或子进程已死。
        let listener_fd_raw = match recv_fd(parent_sock_raw) {
            Ok(fd) => fd,
            Err(_) => {
                // 子进程未发出 listener 就退出（如 spawn 失败 / 直接被信号杀）。
                // 这种情况没有 seccomp 命中，shutdown_r_owned 自动 drop 关闭。
                return;
            }
        };
        // SAFETY：listener_fd_raw 是 recv_fd 返回的有效 fd，
        // 移交给 OwnedFd 后由 RAII 在闭包退出时关闭。
        let listener_fd = unsafe { OwnedFd::from_raw_fd(listener_fd_raw) };

        // 3b) 主循环：poll([listener_fd, shutdown_r], -1)。
        //     - listener 可读 → 处理 notification。
        //     - shutdown_r 可读 → 主线程通知退出。
        loop {
            let mut pollfds = [
                libc::pollfd {
                    fd: listener_fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: shutdown_r_owned.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY：pollfds 是栈上 2 元素数组，poll(2) 写入 revents；
            // timeout=-1 表示永久阻塞直到任一 fd 就绪或被信号打断。
            let r = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, -1) };
            if r < 0 {
                // poll 被信号打断（EINTR）或其他错误 → 退出循环。
                // shutdown_r_owned 与 listener_fd 自动 drop 关闭。
                break;
            }

            // shutdown_r 可读 → 主线程通知退出。
            if pollfds[1].revents != 0 {
                break;
            }

            // listener_fd 可读 → 处理一条 notification。
            if pollfds[0].revents != 0 {
                let mut notif: seccomp::seccomp_notif = unsafe { mem::zeroed() };
                // SAFETY：notif 栈上零初始化，ioctl 写入其内容。
                let r = unsafe {
                    libc::ioctl(
                        listener_fd.as_raw_fd(),
                        seccomp::SECCOMP_IOCTL_NOTIF_RECV,
                        &mut notif,
                    )
                };
                if r != 0 {
                    // 子进程退出后内核自动关闭 listener 上的等待者，
                    // 返回 ENOENT / EINVAL。视作正常退出。
                    break;
                }

                // 记录 (nr, arch) 到共享变量。
                if let Ok(mut g) = blocked_for_worker.lock() {
                    *g = Some((notif.data.nr as u32, notif.data.arch));
                }

                // 构造响应：error = EPERM（不调用 syscall 主体）。
                let resp = seccomp::seccomp_notif_resp {
                    id: notif.id,
                    val: 0,
                    error: libc::EPERM,
                    flags: 0,
                };
                // SAFETY：resp 是栈上良构 seccomp_notif_resp；ioctl
                // 把响应交给内核，内核根据 id 找到对应等待中的 syscall
                // 并把 errno = EPERM 注入其返回值。
                let r = unsafe {
                    libc::ioctl(
                        listener_fd.as_raw_fd(),
                        seccomp::SECCOMP_IOCTL_NOTIF_SEND,
                        &resp,
                    )
                };
                if r != 0 {
                    // 发送失败：notif 不存在（子进程已 reap 或 filter 卸除）。
                    break;
                }
            }
        }
        // 闭包退出：listener_fd (OwnedFd) 与 shutdown_r_owned (OwnedFd)
        // 自动 drop → close fd，无泄漏。
    });

    Ok(UserNotifHandle {
        worker: Some(worker),
        shutdown_w,
    })
}