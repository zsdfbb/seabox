//! macOS Seatbelt 后端实现侧：`MacSandbox` / `MacChild` / canary 预检 / fd 清扫 / 拒绝归因。
//!
//! 整模块由 `mod.rs` 侧的 `#[cfg(target_os = "macos")]` 门控（本文件内**不再**写 `#![cfg]`）。
//!
//! 权威设计：`docs/arch/macos-seatbelt/design.md` §9（两道安全闸门）、§10（拒绝归因）；
//! 执行计划：`docs/exec-plans/macos-seatbelt.md` Task 10。
//!
//! # 施加机制
//!
//! `sandbox-exec -D k=v ... -p <profile> -- <program> <args...>`。它是**原地 exec**，
//! `sandbox-exec` 进程的 pid 就是目标程序的 pid（不像 Linux 侧需要 pid 映射表）。
//! profile 语法/参数错误 ⇒ rc=65 且目标程序**不会执行**（fail-closed，design §5.1）。
//!
//! # 三道防线
//!
//! 1. **构造期**（[`MacSandbox::new`]）：`validate()` → `sbpl::build()` → canary 预检。
//!    配置错误与「策略语义失效」都在这时暴露，而不是推迟到第一次 spawn（design §3）。
//! 2. **canary 预检**（[`canary_check`]）：用同一个 [`Plan`] 跑一个「应当被拒」的探针；
//!    探针若成功说明 `(deny default)` 之类的语义没生效 ⇒ `bail!`（design §9.1）。
//!    三优先级降级：写探针 → 读探针 → 显式警告后继续。
//! 3. **fd 清扫**（[`collect_leaky_fds`] + `pre_exec`）：Seatbelt 是 **fd 快照**语义，
//!    施加前已打开的 fd **不受策略约束**（实测可逃逸）。故 `pre_exec` 关闭全部
//!    「继承来的、非 `FD_CLOEXEC`、且未显式声明」的 fd（design §9.2）。
//!
//! # fork 后零堆操作（ADR 0003）
//!
//! `pre_exec` 闭包运行在 `fork()` 之后、`execve()` 之前，**只做纯 syscall**：
//! `setpgid(0, 0)` + 对**预分配** `Vec<i32>` 的 `close()` 循环。闭包经 `move` 捕获
//! fd 列表，循环内不得出现 `format!` / `String` / `Vec::push` / `to_string`。

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::macos::config::{MacOsConfig, ResolvedPolicy};
use crate::macos::sbpl::{self, Plan};
use crate::{
    CommandOutput, CommandSpec, DenyMechanism, ExitReason, SandboxChild, SandboxChildImpl,
    SandboxImpl, StdioConfig,
};

/// `sandbox-exec` 的绝对路径（**不**走 `PATH`：被劫持的 `sandbox-exec` 等于无沙箱）。
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// `> 2` 的 fd 才可能被清扫（0/1/2 是标准流，恒不动）。
const FIRST_SWEEPABLE_FD: i32 = 3;

/// 探针目录名（落在 `/tmp` 或 `$TMPDIR` / `$HOME` 下，**绝不**落进工程目录）。
const PROBE_SUBDIR: &str = "sbxp";

/// stderr 中 Seatbelt 拒绝的典型措辞（EACCES/EPERM 都由内核转成它）。
const DENIED_MARKER: &str = "Operation not permitted";

/// stderr 中「`sandbox-exec` 自己出错」的前缀（profile 被拒 / `execvp` 失败）。
const SANDBOX_EXEC_MARKER: &str = "sandbox-exec:";

// ---------------------------------------------------------------------------
// MacSandbox
// ---------------------------------------------------------------------------

/// 使用 Seatbelt（SBPL + `sandbox-exec`）强制施加文件系统与网络策略的沙箱。
///
/// 构造期完成全部昂贵且易错的工作（`validate` → `build` → canary → fd 枚举），
/// 因此 `spawn` 只剩「拼参数 + stdio + fork + fd 清扫 + exec」。
pub(crate) struct MacSandbox {
    /// 定型 SBPL 计划（profile + `-D` 参数表），构造后**不可变**。
    plan: Plan,
    /// fork 前枚举好的待清扫 fd 基线（保证 `pre_exec` 内零分配）。
    leaky_fd_base: Vec<i32>,
}

impl MacSandbox {
    /// 构造沙箱：配置校验 + SBPL 生成 + canary 预检，一次做完。
    ///
    /// `cwd` 用于 `WorkspaceWrite` 预设的 `WS` 根与 `.git` carve-out。
    ///
    /// # 为何全部检查都在构造期
    ///
    /// Seatbelt 最危险的失败模式是「看起来在工作，实际没工作」：profile 语法正确但语义
    /// 写宽了，`sandbox-exec` 不会报警。canary 预检是**唯一**能直接观测「策略真的生效」
    /// 的手段（design §9.1），因此不能推迟到第一次 `spawn`——否则用户会先拿到一条
    /// 完全不受限的执行，然后才看到错误。
    pub(crate) fn new(config: &MacOsConfig, cwd: &Path) -> Result<Self> {
        // ① 配置面硬错误（SBPL 注入字符 / 空 Only 读白名单）
        config
            .validate()
            .context("macOS sandbox config is invalid")?;

        // ② 定型策略 + SBPL 文本（路径 canonicalize 失败在此硬错误，design §6.2）
        let policy = config.resolve(cwd);
        let plan = sbpl::build(&policy, cwd).context("failed to build the Seatbelt profile")?;

        // ③ canary 预检：策略语义是否真的生效（fail-closed）
        canary_check(&plan, &policy)?;

        // ④ fork 前枚举待清扫 fd（`/dev/fd` 枚举 ~0.026ms，design §9.2）
        let leaky_fd_base = collect_leaky_fds(&[]);

        Ok(Self {
            plan,
            leaky_fd_base,
        })
    }

    /// 本次 spawn 的待清扫 fd 列表（`fork` **前**算好，供 `pre_exec` 只读遍历）。
    ///
    /// 以当时的 `/dev/fd` 实况为准（[`collect_leaky_fds`]），再补上构造期基线里的残留项：
    /// 构造之后 fd 号可能被关闭并复用，所以基线项**逐个重新核对** `fcntl(F_GETFD)`——
    /// 已关闭（返回 `-1`）或已置 `FD_CLOEXEC`（内核会在 exec 时自动关）的都不进清扫列表，
    /// 避免关掉 `exec` 之前新开的合法 fd。
    fn leaky_fds_for(&self, keep: &[i32]) -> Vec<i32> {
        let mut fds = collect_leaky_fds(keep);
        for &fd in &self.leaky_fd_base {
            if fd < FIRST_SWEEPABLE_FD || keep.contains(&fd) || fds.contains(&fd) {
                continue;
            }
            // man:fcntl(2) —— F_GETFD 取 fd flags；-1 表示该 fd 号已关闭
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags == -1 || flags & libc::FD_CLOEXEC != 0 {
                continue;
            }
            fds.push(fd);
        }
        fds.sort_unstable();
        fds
    }

    /// 按 design §10.2 判定表，用**完整输出**（含 stderr）归类退出状态。
    ///
    /// 与 [`SandboxImpl::classify_exit`] 的区别：Seatbelt 的拒绝**不会可靠传播为退出码**
    /// （`sh -c '... > denied 2>/dev/null; exit 0'` ⇒ rc=0），只有 stderr 能兜住这种情况。
    ///
    /// Task 12 会把本方法接到 `SandboxImpl::classify_output`（trait 默认实现委托
    /// `classify_exit`）；在那之前它只是 `MacSandbox` 上的普通方法。
    pub(crate) fn classify_output(&self, output: &CommandOutput) -> ExitReason {
        classify_with_stderr(output.exit_code, Some(&output.stderr))
    }
}

// ---------------------------------------------------------------------------
// SandboxImpl
// ---------------------------------------------------------------------------

impl SandboxImpl for MacSandbox {
    /// 在沙箱内启动命令，返回活句柄（非阻塞）。
    ///
    /// 流程：探测 `sandbox-exec` 存在性 → 拼 `-D`/`-p`/`--` → `current_dir` +
    /// `env_clear().envs()` → stdio 接法 → `pre_exec`（`setpgid` + fd 清扫）→ `spawn`。
    ///
    /// **`sandbox-exec` 缺失即 `bail!`**：绝不降级为「无沙箱直接执行」——
    /// 那正是本工具最该避免的失效模式（静默放开）。
    fn spawn(&self, spec: &CommandSpec, stdio: StdioConfig) -> Result<SandboxChild> {
        require_sandbox_exec()?;

        let mut cmd = sandbox_exec_command(&self.plan);

        // ── 命令本体：program + args ────────────────────────────────
        cmd.arg(&spec.program);
        cmd.args(&spec.args);

        // ── 工作目录与环境 ────────────────────────────────────────
        cmd.current_dir(&spec.cwd);
        // 与 Linux 侧一致：环境完全由 CommandSpec 决定，不继承父进程
        cmd.env_clear();
        cmd.envs(&spec.env);

        // ── stdio：只有显式声明的 fd 会被传递 ─────────────────────
        // `keep` = exec 后仍须保留的 fd 集合，**fork 前**算好（`pre_exec` 只读它）。
        let mut keep: Vec<i32> = vec![libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO];
        match stdio {
            // 继承父进程 0/1/2（零额外 fd）
            StdioConfig::Inherit => {}
            StdioConfig::Piped => {
                cmd.stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
            }
            StdioConfig::Fd {
                stdin,
                stdout,
                stderr,
            } => {
                // `-1` = 不修改对应标准流（与 Linux 侧 child_setup 约定一致）
                for (fd, slot) in [
                    (stdin, StreamSlot::Stdin),
                    (stdout, StreamSlot::Stdout),
                    (stderr, StreamSlot::Stderr),
                ] {
                    if fd < 0 {
                        continue;
                    }
                    // `Stdio::from` 会在 exec 前把这个副本 dup2 到 0/1/2；副本自身标
                    // `FD_CLOEXEC` 后由内核在 exec 时自动关闭，不会在目标进程里多留一个 fd。
                    // 调用方**声明的** fd 属于显式放行，进 `keep`。
                    let owned = dup_fd(fd)
                        .with_context(|| format!("spawn: failed to dup stdio fd {fd}"))?;
                    set_cloexec(&owned)?;
                    keep.push(fd);
                    slot.install(&mut cmd, owned);
                }
            }
        }

        // ── pre_exec：setpgid + fd 清扫（零堆操作，ADR 0003）───────
        let leaky_fds = self.leaky_fds_for(&keep);
        // SAFETY: 闭包在 fork 后的子进程中执行，只调 setpgid(2) / close(2) 两个
        // async-signal-safe 的纯 syscall；不分配内存（无 format!/String/Vec::push）、
        // 不加锁、不访问堆上可变状态。`leaky_fds` 在 fork **前**建好，经 `move`
        // 捕获进闭包，闭包体内只做只读遍历。
        unsafe {
            cmd.pre_exec(move || {
                // man:setpgid(2) —— 自成进程组，使 kill(-pgid) 能一次杀掉整棵进程树
                if libc::setpgid(0, 0) == -1 {
                    // 错误路径只取 errno（io::Error::last_os_error 不做堆分配）
                    return Err(io::Error::last_os_error());
                }
                // man:close(2) —— 关闭全部「继承来、未声明、非 CLOEXEC」的 fd。
                // Seatbelt 是 fd 快照语义：策略施加前已打开的 fd 不受约束，必须清扫。
                for &fd in &leaky_fds {
                    libc::close(fd);
                }
                Ok(())
            });
        }

        let child = cmd.spawn().with_context(|| {
            format!(
                "spawn: failed to start '{}' via {SANDBOX_EXEC}",
                spec.program
            )
        })?;

        // `sandbox-exec` 原地 exec ⇒ 子进程 pid 就是 business 进程 pid，无映射表。
        let pgid = child.id() as i32;
        Ok(SandboxChild {
            inner: Box::new(MacChild {
                child,
                pgid,
                timed_out: false,
            }),
        })
    }

    // `execute` 用 trait 默认实现（`spawn(Piped)` + `src/child.rs::run_to_output`）。
    //
    // ⚠️ **已知能力降级**：`StdioConfig::Inherit` 路径拿不到 stderr，此时归因退化为
    // 仅退出码判据（`65` 一律算 `Program(65)`，`134` 仍算 `Denied`）。要完整的
    // `Operation not permitted` 判据，请用 `Sandbox::execute`（内部恒用 `Piped`）。

    /// 仅凭退出码归类（拿不到 stderr 时的降级路径，design §10.2）。
    ///
    /// - `0` ⇒ [`ExitReason::Ok`]
    /// - `134`（SIGABRT）⇒ `Denied { .. }`：宁可误报拒绝，不可误报成功
    /// - 其它（含 `65`）⇒ [`ExitReason::Program`]：**65 / 134 都有歧义**，
    ///   `sandbox-exec` 自身失败返回 65，但目标程序也可能自己 `exit 65`；
    ///   没有 stderr 时无法区分，只能当普通程序退出。
    ///
    /// 带 stderr 的完整归因（trait override）。
    ///
    /// **必须显式 override**：`Sandbox::execute` 通过 `Box<dyn SandboxImpl>` 调用，
    /// trait object 的方法解析只看得见 trait 方法；固有方法 `MacSandbox::classify_output`
    /// 对 trait object **不可见**，不写这一层就会静默退回默认实现（委托 `classify_exit`），
    /// 于是「被 Seatbelt 拒绝」会被误报为普通 `Program(1)` —— 实测踩到过。
    fn classify_output(&self, output: &CommandOutput) -> ExitReason {
        MacSandbox::classify_output(self, output)
    }

    /// 带 stderr 的完整归因见 [`MacSandbox::classify_output`]。
    fn classify_exit(&self, exit_code: i32, _blocked: Option<(u32, u32)>) -> ExitReason {
        // Seatbelt 无结构化拒绝通道，`blocked` 恒为 `None`（那是 seccomp 的概念）
        classify_with_stderr(exit_code, None)
    }
}

// ---------------------------------------------------------------------------
// 拒绝归因（design §10.2）
// ---------------------------------------------------------------------------

/// 拒绝归因使用的 [`DenyMechanism`]。
///
/// [`DenyMechanism::Seatbelt`] 由 Task 12 在 `src/lib.rs` 中加入；本函数是
/// 它在本模块的唯一出口（所有 `Denied` 构造点经它，不散落字面量）。
fn seatbelt_mechanism() -> DenyMechanism {
    DenyMechanism::Seatbelt
}

/// 按 design §10.2 判定表归类；`stderr` 为 `None` 时降级为仅退出码判据。
///
/// | exit | 判据 | 结果 |
/// |---|---|---|
/// | 65 | stderr 含 `sandbox-exec:` | `InternalError`（SBPL profile 被拒 ⇒ 我们的 bug） |
/// | 65 | 无判据 | `Program(65)`（目标程序自己返回 65） |
/// | 134 | — | `Denied`（SIGABRT，message 标「可能」） |
/// | 其它 | stderr 含 `Operation not permitted` | `Denied` |
/// | 0 | — | `Ok` |
/// | 其它 | — | `Program(code)` |
///
/// `0` 的判据排在拒绝判据**之后**：`sh -c 'echo x > denied 2>/dev/null; exit 0'` 会得到
/// rc=0 且 stderr 含拒绝信息，这种情况仍必须归类为 `Denied`——这正是
/// [`SandboxImpl::classify_exit`] 的签名容不下 stderr、需要 `classify_output` 的理由
/// （design §10.1，测试 G5）。
fn classify_with_stderr(exit_code: i32, stderr: Option<&[u8]>) -> ExitReason {
    let owned = stderr
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    let text: &str = &owned;

    // ① sandbox-exec 自己拒绝了这个 profile（语法错 / 未定义 param）⇒ 内部错误
    if exit_code == 65 && text.contains(SANDBOX_EXEC_MARKER) {
        return ExitReason::InternalError(format!(
            "sandbox-exec rejected the SBPL profile (syntax error or unbound -D param): {}",
            text.trim()
        ));
    }

    // ② 65 无判据：目标程序自己返回 EX_DATAERR，与沙箱无关
    if exit_code == 65 {
        return ExitReason::Program(65);
    }

    // ③ 134 = 128 + SIGABRT：经验上多见于读白名单过窄导致 dyld 崩溃，故归 Denied
    //    （message 标「可能」：程序自身 abort 也会 134）
    if exit_code == 134 {
        return ExitReason::Denied {
            mechanism: seatbelt_mechanism(),
            message: "process aborted (SIGABRT) under the Seatbelt policy; this is probably a \
                      sandbox denial — the read whitelist may be too narrow"
                .to_string(),
        };
    }

    // ④ stderr 判据：Seatbelt 拒绝的典型形态（EACCES/EPERM 一律呈现为它）
    if text.contains(DENIED_MARKER) {
        return ExitReason::Denied {
            mechanism: seatbelt_mechanism(),
            message: format!(
                "Seatbelt denied a filesystem or network operation (exit code {exit_code}): {}",
                text.trim()
            ),
        };
    }

    // ⑤ 正常退出
    if exit_code == 0 {
        return ExitReason::Ok;
    }

    // ⑥ 普通非零退出
    ExitReason::Program(exit_code)
}

// ---------------------------------------------------------------------------
// MacChild
// ---------------------------------------------------------------------------

/// macOS 沙箱子进程的活句柄（实现 [`SandboxChildImpl`]）。
///
/// `sandbox-exec` 是**原地 exec**：`Command::spawn` 返回的 pid 在 exec 之后仍是同一个
/// 进程，所以 business 进程 pid 天然等于子进程 pid，**无 pid 映射表**。
///
/// `kill` 走 `kill(-pgid, SIGKILL)` 杀整个进程组（子进程在 `pre_exec` 里
/// `setpgid(0, 0)` 自成一组），避免 Agent 命令的子孙进程逃逸。
pub(crate) struct MacChild {
    child: Child,
    /// 子进程自成的进程组 id（= 子进程 pid）。
    pgid: i32,
    timed_out: bool,
}

impl SandboxChildImpl for MacChild {
    /// 非阻塞收割（`WNOHANG` 语义）。`std::process::Child::try_wait` 自带缓存，幂等。
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// 阻塞收割至退出。
    fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child.wait()
    }

    /// 有界等待；到期强制 `kill()` + 收割后返回已退出状态（超时强杀为 137），
    /// 是否超时用 [`timed_out`](Self::timed_out) 查询。
    fn wait_timeout(&mut self, d: Duration) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + d;
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                self.kill()?;
                let status = self.wait()?;
                self.timed_out = true;
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// 杀死整个进程组；`ESRCH`（组未建立 / 已空）退化为单杀，仍返回 `Ok(())`。
    fn kill(&mut self) -> io::Result<()> {
        // 已收割 / 已退出 ⇒ 无事可做（避免 std 报 "can't kill an exited process"）
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        // man:kill(2) —— 负 pid 表示「整个进程组」
        let r = unsafe { libc::kill(-self.pgid, libc::SIGKILL) };
        if r == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            // 组尚未建立（`pre_exec` 的 setpgid 还没跑到）或组已空 ⇒ 退化为单杀，
            // 保证「返回 Ok 就真的没人还在跑」
            Some(libc::ESRCH) => {
                let _ = self.child.kill();
                Ok(())
            }
            _ => Err(err),
        }
    }

    /// business 进程 pid（= `sandbox-exec` 原地 exec 后的同一 pid）。
    fn id(&self) -> u32 {
        self.child.id()
    }

    #[cfg(unix)]
    fn take_stdout(&mut self) -> Option<OwnedFd> {
        self.child.stdout.take().map(OwnedFd::from)
    }

    #[cfg(unix)]
    fn take_stderr(&mut self) -> Option<OwnedFd> {
        self.child.stderr.take().map(OwnedFd::from)
    }

    #[cfg(unix)]
    fn take_stdin(&mut self) -> Option<OwnedFd> {
        self.child.stdin.take().map(OwnedFd::from)
    }

    /// Seatbelt 无 seccomp USER_NOTIF 等价物，恒为 `None`。
    fn blocked(&self) -> Option<(u32, u32)> {
        None
    }

    fn timed_out(&self) -> bool {
        self.timed_out
    }
}

impl Drop for MacChild {
    /// 机会式收割：已退出则 reap 掉避免僵尸；仍在跑则放生（std 语义，
    /// 不替调用方决定「杀死可能仍在正常工作的进程」）。
    fn drop(&mut self) {
        let _ = self.child.try_wait();
    }
}

// ---------------------------------------------------------------------------
// fd 清扫（design §9.2）
// ---------------------------------------------------------------------------

/// 枚举「继承来的、exec 后会泄漏」的 fd：`/dev/fd` 中编号 `> 2`、不在 `keep` 内、
/// 且**未**置 `FD_CLOEXEC` 的项。
///
/// # 为什么不用 `close_range` / 大范围循环
///
/// macOS 没有 `close_range`（Linux 5.9+ syscall，本机编译直接报 undeclared）。
/// 而 `close(3.._SC_OPEN_MAX)` 实测 ~14.5ms、`fcntl` 探测到 `getdtablesize()`
/// ~11.5ms——两者都要遍历 9 万~100 万个空槽，直接吃掉整个 spawn 预算。
/// `/dev/fd` 枚举只看真实存在的 fd（典型 3~10 个），实测 ~0.026ms，快 500 倍。
///
/// # 为什么要过滤 `FD_CLOEXEC`
///
/// CLOEXEC 的 fd 由内核在 `execve` 时自动关闭，不必扫。更重要的是：`fork()` 与
/// `execve()` 之间可能新开合法的 CLOEXEC fd（例如 Rust std 用来回报 exec 失败的管道），
/// 误关它会让子进程的失败上报路径失效。
///
/// # 分配
///
/// 本函数在 `fork` **前**运行，可自由分配；`pre_exec` 只读它的结果。
fn collect_leaky_fds(keep: &[i32]) -> Vec<i32> {
    let mut out = Vec::new();
    // `/dev/fd` 是 macOS 的 fd 伪文件系统
    let Ok(rd) = std::fs::read_dir("/dev/fd") else {
        return out; // 没有 /dev/fd 就退化为「不清扫」，不阻塞 spawn
    };
    for entry in rd.flatten() {
        let Some(n) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        if n < FIRST_SWEEPABLE_FD || keep.contains(&n) {
            continue;
        }
        // man:fcntl(2) —— F_GETFD 读 fd flags；-1 ⇒ 该 fd 已关闭（枚举与读取之间消失）
        let flags = unsafe { libc::fcntl(n, libc::F_GETFD) };
        if flags == -1 || flags & libc::FD_CLOEXEC != 0 {
            continue;
        }
        out.push(n);
    }
    out.sort_unstable();
    out
}

// ---------------------------------------------------------------------------
// canary 预检（design §9.1）
// ---------------------------------------------------------------------------

/// 用同一个 [`Plan`] 跑一个「应当被拒」的探针，验证策略**语义**真的生效。
///
/// 三优先级降级（design §9.1）：
///
/// | 优先级 | 探针 | 何时可用 |
/// |---|---|---|
/// | 1 | 在策略**不允许写**的位置写文件，期望被拒 | 存在既被策略拒绝、又对本进程可写的目录 |
/// | 2 | 读一个被 `deny_read` 封禁且本进程可读的文件，期望被拒 | 存在可读的 deny 路径（如 `~/.ssh/*`） |
/// | 3 | 跳过并 `eprintln!` 显式警告 | 极端配置（`FullAccess` 且无 deny） |
///
/// 探针成功（「本该被拒却成功了」）⇒ 策略未生效 ⇒ `bail!`，且**先清理**探针文件。
/// 探针目录一律落在 `/tmp` / `$TMPDIR` / `$HOME` 下（[`PROBE_SUBDIR`]），
/// **绝不**落进工程目录，用完立即删除。
///
/// 与设计稿的细微差别：设计稿的写探针固定用 `$TMPDIR/.seabox-canary-*`，因而受
/// `tmp_writable` 牵制（该值为 `true` 时 `$TMPDIR` 本来就可写，探针失去区分力）。
/// 这里改为「先挑一个被策略拒绝的目录」，对 `tmp_writable` 的两个取值都成立，
/// 读探针因此成为真正的兜底而非分支。
fn canary_check(plan: &Plan, policy: &ResolvedPolicy) -> Result<()> {
    require_sandbox_exec()?;

    // ── 优先级 1：写探针 ────────────────────────────────────────
    if let Some(dir) = write_probe_dir(policy) {
        let canary = dir.join(format!(
            ".seabox-canary-{}-{}",
            std::process::id(),
            nanos_since_epoch()
        ));
        // 反向对照：沙箱外必须写得进去，否则「写不进去」不能证明策略生效
        let sandbox_free_writable = probe_write_outside(&dir, &canary);

        let mut cmd = sandbox_exec_command(plan);
        cmd.arg("/bin/sh")
            .arg("-c")
            .arg("printf C > \"$1\"")
            .arg("sh")
            .arg(&canary);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let out = cmd
            .output()
            .context("canary: failed to run the write probe under sandbox-exec")?;
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        // profile 本身被拒 ⇒ 这是我们自己的 bug，不能当成「已生效」
        if stderr.contains(SANDBOX_EXEC_MARKER) {
            let _ = std::fs::remove_file(&canary);
            cleanup_probe_dir(&dir);
            bail!(
                "canary: sandbox-exec rejected the SBPL profile: {}",
                stderr.trim()
            );
        }

        if canary.exists() {
            // 策略失效：本该被拒却写成功了（对应 design §9.1 的第 3 步）
            let _ = std::fs::remove_file(&canary);
            cleanup_probe_dir(&dir);
            bail!(
                "Seatbelt policy did NOT take effect: the canary write to {} succeeded inside \
                 the sandbox, although the policy does not allow writing there. The profile \
                 probably widened to `(allow default)` or a whitelist path is wrong. \
                 Probe stderr: {}",
                canary.display(),
                stderr.trim()
            );
        }
        if !sandbox_free_writable {
            // 反向对照失败 ⇒ 探针没有区分力，只能告警（不得静默）
            eprintln!(
                "seabox: warning: canary write probe in {} is not writable even outside the \
                 sandbox, so it cannot prove the policy is effective",
                dir.display()
            );
        } else if !out.status.success() && !stderr.contains(DENIED_MARKER) {
            // 探针进程非零退出但不是拒绝形态 ⇒ 无法判断，显式告警
            eprintln!(
                "seabox: warning: canary write probe exited with {:?} without a Seatbelt denial \
                 marker, so the policy check is inconclusive. Probe stderr: {}",
                out.status.code(),
                stderr.trim()
            );
        }
        cleanup_probe_dir(&dir);
        return Ok(());
    }

    // ── 优先级 2：读探针 ────────────────────────────────────────
    if let Some(target) = read_probe_target(policy) {
        let mut cmd = sandbox_exec_command(plan);
        cmd.arg("/bin/cat")
            .arg(&target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let out = cmd
            .output()
            .context("canary: failed to run the read probe under sandbox-exec")?;
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        if stderr.contains(SANDBOX_EXEC_MARKER) {
            bail!(
                "canary: sandbox-exec rejected the SBPL profile: {}",
                stderr.trim()
            );
        }
        if out.status.success() {
            bail!(
                "Seatbelt policy did NOT take effect: the canary read of {} succeeded inside the \
                 sandbox, although `deny_read`/the credential list denies it. Probe stderr: {}",
                target.display(),
                stderr.trim()
            );
        }
        if !stderr.contains(DENIED_MARKER) {
            eprintln!(
                "seabox: warning: canary read probe on {} failed without a Seatbelt denial \
                 marker, so the policy check is inconclusive. Probe stderr: {}",
                target.display(),
                stderr.trim()
            );
        }
        return Ok(());
    }

    // ── 优先级 3：两者都不可用 ⇒ 显式警告后继续（不得静默）────────
    eprintln!(
        "seabox: warning: no Seatbelt canary probe is available for this policy (there is no \
         writable-but-denied directory and no readable `deny_read` path), so the sandbox policy \
         was NOT verified to be effective. This warning is not a failure."
    );
    Ok(())
}

/// 选一个「策略不允许写、但本进程可写」的目录作为写探针落点。
///
/// 顺序：`/tmp/sbxp` → `$TMPDIR/sbxp` → `$HOME/.sbxp`。`FullAccess` 下不存在
/// 「策略不允许写」的位置，直接返回 `None`（降级到读探针）。
fn write_probe_dir(policy: &ResolvedPolicy) -> Option<PathBuf> {
    if policy.full_access {
        return None;
    }
    let mut candidates: Vec<PathBuf> = vec![Path::new("/tmp").join(PROBE_SUBDIR)];
    candidates.push(std::env::temp_dir().join(PROBE_SUBDIR));
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(format!(".{PROBE_SUBDIR}")));
    }

    for dir in candidates {
        // 目录由父进程（未施加沙箱时）建出来，再 realpath：
        // `/tmp` → `/private/tmp`，SBPL 的 `subpath` 按字面比较（design §6.2）
        if std::fs::create_dir_all(&dir).is_err() {
            continue;
        }
        let Ok(real) = std::fs::canonicalize(&dir) else {
            continue;
        };
        if policy_allows_write(policy, &real) {
            continue; // 策略允许写 ⇒ 不能当「应当被拒」的探针
        }
        return Some(real);
    }
    None
}

/// 静态判定「策略是否允许写 `path`」（纯规则比对，不跑进程）。
///
/// 判据与 SBPL 生成的段序一致（后写赢）：`FullAccess` ⇒ 全放；TMP 段 ⇒ `$TMPDIR` 下可写；
/// 写白名单 ⇒ `subpath` 覆盖即可写；最后 `deny_write` 命中则回到不可写。
fn policy_allows_write(policy: &ResolvedPolicy, path: &Path) -> bool {
    if policy.full_access {
        return true;
    }
    // `deny_write` 是最后一条写侧 file 规则（后写赢），命中即不可写
    if policy.deny_write.iter().any(|d| path_under(path, d)) {
        return false;
    }
    let tmp_allowed = policy.tmp_writable && path_under(path, &std::env::temp_dir());
    let write_allowed = policy.write.iter().any(|w| path_under(path, w));
    tmp_allowed || write_allowed
}

/// `path` 是否位于 `base` 之下。两者都尽量 canonicalize，失败时退回字面值。
///
/// 用「路径分段前缀」（[`Path::starts_with`]）而非字符串前缀——字符串前缀会让
/// `/proj` 命中 `/proj-backup`，这正是 design §6.4 禁用 SBPL `prefix` 匹配符的理由。
///
/// 注意：`~` 未展开的 deny 条目在这里会退化为字面比较（不匹配），因此本函数只用于
/// **探针落点选择**这一启发式判定，绝不用于决定是否施加规则。
fn path_under(path: &Path, base: &Path) -> bool {
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let path = canon(path);
    let base = canon(base);
    path == base || path.starts_with(&base)
}

/// 反向对照：在**不施加沙箱**的情况下确认探针位置可写（否则探针没有区分力）。
///
/// 返回 `true` 表示确已成功写入并清理，说明「沙箱内写成功」确实是策略失效的信号。
fn probe_write_outside(dir: &Path, canary: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    match std::fs::write(canary, b"C") {
        Ok(()) => {
            let _ = std::fs::remove_file(canary);
            true
        }
        Err(_) => false,
    }
}

/// 选一个「被 `deny_read` 封禁、且本进程可读」的文件作为读探针目标。
///
/// 必须 **realpath**（`/tmp` → `/private/tmp`）：SBPL 的 `subpath` 按字面比较、
/// 不解析 symlink，不规范化就永不匹配，探针会假阳性通过（design §9.1 实测踩到的坑）。
/// 凭据清单多为目录（如 `~/.ssh`），故目录条目取其中一个可读文件。
fn read_probe_target(policy: &ResolvedPolicy) -> Option<PathBuf> {
    for denied in &policy.deny_read {
        let Ok(real) = std::fs::canonicalize(denied) else {
            continue; // 不存在 ⇒ 沙箱内外都是 ENOENT，无区分力
        };
        let file = if real.is_file() {
            real
        } else if real.is_dir() {
            let mut found = None;
            if let Ok(rd) = std::fs::read_dir(&real) {
                for entry in rd.flatten() {
                    let p = entry.path();
                    if p.is_file() && std::fs::read(&p).is_ok() {
                        found = Some(p);
                        break;
                    }
                }
            }
            match found {
                Some(p) => p,
                None => continue,
            }
        } else {
            continue;
        };
        // 父进程（沙箱外）必须读得到，否则「读失败」不构成策略生效的证据
        if std::fs::read(&file).is_ok() {
            return Some(file);
        }
    }
    None
}

/// 尽力清理探针目录（只删空目录，不递归删除——避免误删用户内容）。
fn cleanup_probe_dir(dir: &Path) {
    let _ = std::fs::remove_dir(dir);
}

/// 纳秒时间戳：让探针文件名不可预测，避免并发构造同一策略时互相覆盖。
fn nanos_since_epoch() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 命令拼装 / 小工具
// ---------------------------------------------------------------------------

/// 构造 `sandbox-exec -D k=v ... -p <profile> --` 前缀（调用方再补 program + args）。
///
/// 每个 param 一条独立 `-D`（不合并、不排序——顺序无关但保持与 [`Plan`] 一致）；
/// profile 走 `-p`；`--` 之后才是目标命令。
fn sandbox_exec_command(plan: &Plan) -> Command {
    let mut cmd = Command::new(SANDBOX_EXEC);
    for (key, value) in &plan.params {
        cmd.arg("-D").arg(format!("{key}={value}"));
    }
    cmd.arg("-p").arg(&plan.profile);
    cmd.arg("--");
    cmd
}

/// `sandbox-exec` 必须在场：缺失即硬错误，**绝不**降级为无沙箱执行。
fn require_sandbox_exec() -> Result<()> {
    if !Path::new(SANDBOX_EXEC).exists() {
        bail!(
            "macOS sandbox is unavailable: {SANDBOX_EXEC} does not exist. \
             seabox refuses to run the command without a sandbox (fail-closed)."
        );
    }
    Ok(())
}

/// `dup(2)` 一个调用方给出的 fd，返回拥有所有权的副本。
///
/// 不能直接拿调用方的 fd 造 `Stdio`：那会让 `Command` 在 drop 时关掉**别人的** fd。
/// `dup` 返回的副本不带 `FD_CLOEXEC`（`dup` 总是清该标志），因此能跨 exec 生效；
/// 需要「只用作 dup2 源」的场景由调用方再 [`set_cloexec`]。
fn dup_fd(fd: RawFd) -> Result<OwnedFd> {
    // man:dup(2)
    let dup = unsafe { libc::dup(fd) };
    if dup == -1 {
        return Err(io::Error::last_os_error()).with_context(|| format!("dup({fd}) failed"));
    }
    // SAFETY: dup 返回新分配的、由本进程独占的 fd
    Ok(unsafe { OwnedFd::from_raw_fd(dup) })
}

/// 给 fd 置 `FD_CLOEXEC`（让内核在 `execve` 时自动关闭它）。
fn set_cloexec(fd: &OwnedFd) -> Result<()> {
    // man:fcntl(2) —— F_GETFD / F_SETFD
    let raw = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error()).with_context(|| format!("fcntl(F_GETFD, {raw})"));
    }
    if unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("fcntl(F_SETFD, FD_CLOEXEC, {raw})"));
    }
    Ok(())
}

/// `StdioConfig::Fd` 的三个标准流槽位。
///
/// 单独成枚举是因为 `Command::stdin` / `stdout` / `stderr` 是三个方法，
/// 无法用一个数组统一调用。
enum StreamSlot {
    Stdin,
    Stdout,
    Stderr,
}

impl StreamSlot {
    /// 把一个已 dup 的 fd 装到对应标准流。
    fn install(self, cmd: &mut Command, fd: OwnedFd) {
        let stdio = Stdio::from(fd);
        match self {
            StreamSlot::Stdin => cmd.stdin(stdio),
            StreamSlot::Stdout => cmd.stdout(stdio),
            StreamSlot::Stderr => cmd.stderr(stdio),
        };
    }
}

// ---------------------------------------------------------------------------
// 测试：拒绝归因（design §10.2 / 合同 N8 的 G1-G5）
// ---------------------------------------------------------------------------

/// 本组测试只喂**构造的** [`CommandOutput`]，不 spawn 进程、不跑 canary。
///
/// 被测对象是 [`classify_with_stderr`]——它是 [`MacSandbox::classify_output`] 的
/// 实现体（后者只有一行委托），也是 `SandboxImpl::classify_output` /
/// `SandboxImpl::classify_exit` 的共同出口，故在此测它覆盖 G1-G5 全部语义。
///
/// 测试模块由 `mod.rs` 的 `#[cfg(target_os = "macos")]` 门控，只在 macOS 编译。
#[cfg(test)]
mod tests {
    use super::{classify_with_stderr, DENIED_MARKER, SANDBOX_EXEC_MARKER};
    use crate::{DenyMechanism, ExitReason};

    /// 断言是 `Denied` 且 `mechanism == Seatbelt`，返回 message 供进一步检查。
    fn assert_seatbelt_denied(reason: &ExitReason) -> &str {
        match reason {
            ExitReason::Denied { mechanism, message } => {
                assert_eq!(
                    *mechanism,
                    DenyMechanism::Seatbelt,
                    "拒绝机制必须是 Seatbelt，实际 {mechanism:?}"
                );
                message
            }
            other => panic!("应为 Denied{{Seatbelt}}，实际 {other:?}"),
        }
    }

    /// G1：stderr 含 `Operation not permitted` ⇒ `Denied{Seatbelt}`。
    #[test]
    fn g1_operation_not_denied_marker_is_seatbelt_denial() {
        let stderr = b"sh: /tmp/x: Operation not permitted\n";
        let reason = classify_with_stderr(1, Some(stderr));
        let message = assert_seatbelt_denied(&reason);
        assert!(
            message.contains(DENIED_MARKER),
            "message 应带回原始 stderr 判据，实际 {message:?}"
        );
    }

    /// G2：rc=65 且 stderr 含 `sandbox-exec:` ⇒ `InternalError`（profile 被拒）。
    #[test]
    fn g2_rc65_with_sandbox_exec_prefix_is_internal_error() {
        let stderr = b"sandbox-exec: unexpected token\n";
        let reason = classify_with_stderr(65, Some(stderr));
        match reason {
            ExitReason::InternalError(msg) => assert!(
                msg.contains("SBPL"),
                "message 应指明是 SBPL profile 的问题，实际 {msg:?}"
            ),
            other => panic!("应为 InternalError（profile 被拒），实际 {other:?}"),
        }
        assert!(String::from_utf8_lossy(stderr).contains(SANDBOX_EXEC_MARKER));
    }

    /// G3：rc=65 **无** stderr 判据 ⇒ `Program(65)`（目标程序自己的 EX_DATAERR）。
    #[test]
    fn g3_rc65_without_marker_is_program_exit() {
        for stderr in [Some(&b""[..]), None] {
            match classify_with_stderr(65, stderr) {
                ExitReason::Program(code) => assert_eq!(code, 65),
                other => panic!("rc=65 无判据应为 Program(65)，实际 {other:?}"),
            }
        }
    }

    /// G4：rc=134（SIGABRT）⇒ `Denied{Seatbelt}`，message 标「可能」。
    #[test]
    fn g4_rc134_is_probable_seatbelt_denial() {
        let reason = classify_with_stderr(134, Some(b""));
        let message = assert_seatbelt_denied(&reason);
        assert!(
            message.contains("probably"),
            "134 是启发式，message 必须标「可能」而非断言，实际 {message:?}"
        );
    }

    /// G5：**拒绝但 rc=0**（`... 2>/dev/null; exit 0` 形态）⇒ 仍 `Denied`。
    ///
    /// 这是 `classify_output` 存在的理由：只看退出码会把它误判为成功。
    #[test]
    fn g5_denied_with_rc_zero_still_denied() {
        let reason = classify_with_stderr(0, Some(b"sh: /x: Operation not permitted\n"));
        let message = assert_seatbelt_denied(&reason);
        assert!(
            message.contains("exit code 0"),
            "message 应记录实际退出码以便排查，实际 {message:?}"
        );
    }

    /// G-extra：干净退出 ⇒ `Ok`。
    #[test]
    fn g_extra_clean_exit_is_ok() {
        assert_eq!(classify_with_stderr(0, Some(b"")), ExitReason::Ok);
    }

    /// G-extra2：普通非零退出且无拒绝判据 ⇒ `Program(1)`（不误报为拒绝）。
    #[test]
    fn g_extra2_unrelated_nonzero_is_program_exit() {
        match classify_with_stderr(1, Some(b"some random error\n")) {
            ExitReason::Program(code) => assert_eq!(code, 1),
            other => panic!("无关错误不应报拒绝，实际 {other:?}"),
        }
    }
}
