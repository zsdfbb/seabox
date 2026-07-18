//! 基于 Landlock + seccomp BPF 的 Linux 沙箱实现。
//!
//! 提供实现了 [`Sandbox`] trait 的 [`LinuxSandbox`]：
//! 通过 Landlock ACL 做文件系统访问控制，通过手写的 seccomp BPF 黑名单
//! 做系统调用过滤。
//!
//! ## 执行流程
//!
//! 1. **父进程** 构建 Landlock 规则集（经由 `build_ruleset`）以及
//!    seccomp BPF filter 数组。
//! 2. **父进程** 调用 `Command::spawn()` 并附带一个 `pre_exec` 闭包。
//! 3. **子进程**（fork → pre_exec → execve）依次执行：
//!    - `prctl(PR_SET_NO_NEW_PRIVS, 1, …)`
//!    - `landlock_restrict_self(ruleset_fd, 0)`（若存在规则集）
//!    - `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`
//! 4. **父进程** 捕获 stdout/stderr 与退出状态。

pub mod landlock;
pub mod seccomp;

use std::os::unix::io::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;

use anyhow::Context;

use crate::config::SandboxConfig;
use crate::{CommandOutput, CommandSpec, ExitReason, PreparedCommand, Sandbox};

// ---------------------------------------------------------------------------
// LinuxSandbox
// ---------------------------------------------------------------------------

/// 使用 Landlock ACL 与 seccomp BPF filter 强制施加文件系统与系统调用限制
/// 的 Linux 沙箱。
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
    /// 然后在**子进程**中通过 `pre_exec` 闭包（零分配上下文）施加两者。
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<CommandOutput> {
        // ── 步骤 1：构建 Landlock 规则集并取出其 fd ────────────────────
        let ruleset_fd: Option<OwnedFd> = self.prepare_ruleset_fd(spec)?;
        let raw_ruleset_fd: i32 = ruleset_fd
            .as_ref()
            .map(|fd| fd.as_raw_fd())
            .unwrap_or(-1);

        // ── 步骤 2：构建 seccomp BPF filter ───────────────────────────
        let bpf_filter = self.build_bpf_filter();
        let bpf_prog = seccomp::build_sock_fprog(&bpf_filter);

        // ── 步骤 3：必要时在 cwd 中展开 ~ ─────────────────────────────
        let cwd = match spec.cwd.to_str() {
            Some(s) => PathBuf::from(crate::config::expand_tilde(s)),
            None => spec.cwd.clone(),
        };

        // ── 步骤 4：以 pre_exec 施加限制并 spawn 子进程 ───────────────
        //
        // 关于 `pre_exec` 的 SAFETY：
        //
        // 该闭包在 `fork()` 之后、`execve()` 之前执行。我们特别注意：
        //
        // * 只捕获 `raw_ruleset_fd`（一个 `i32`）和 `bpf_prog`
        //   （一个通过 unsafe impl 获得 `Send + Sync` 的 `sock_fprog`）。
        // * 在闭包内不进行任何堆分配。
        // * 仅调用 `libc::prctl`、`libc::syscall` 与 `libc::close` —
        //   这些都是 async-signal-safe 的。
        //
        // `bpf_filter` 这个 `Vec` **不会**被捕获；它位于父进程的栈上，
        // 直到 `spawn()` 返回后才被 drop。fork 后子进程拥有自己的 COW
        // 栈帧副本，因此 `bpf_prog.filter` 指针在子进程地址空间中
        // 仍然有效，直到 `prctl` 将程序拷入内核内存。
        let output = unsafe {
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
                    // 步骤 C：prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)
                    //
                    // 加载 BPF 黑名单 filter。之后的每一次系统调用都会
                    // 通过这个 filter 校验。
                    // man:prctl(2) PR_SET_SECCOMP
                    // -------------------------------------------------------
                    // SAFETY：`bpf_prog` 是由 `build_sock_fprog` 产出的
                    // 良构 `sock_fprog`。其背后的 filter 数据有效
                    // （`bpf_filter` 的子进程 COW 副本仍位于父进程栈帧上，
                    // 可通过子进程克隆的地址空间访问）。`prctl` 会将程序
                    // 拷入内核内存，调用结束后指针就不再需要。
                    let ret = libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER,
                        &bpf_prog as *const seccomp::sock_fprog,
                    );
                    if ret != 0 {
                        return Err(std::io::Error::last_os_error());
                    }

                    Ok(())
                })
                .spawn()
                .context("Failed to spawn sandboxed process")?
        };

        let output = output
            .wait_with_output()
            .context("Failed to wait for sandboxed process")?;

        // `ruleset_fd` 在此 drop → fd 在父进程中关闭。

        // ── 步骤 5：转换输出 ────────────────────────────────────────
        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or_else(|| {
                output.status.signal().map(|s| 128 + s).unwrap_or(-1)
            }),
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

    /// 将已完成命令的退出码与 stderr 归类为一个 [`ExitReason`]。
    ///
    /// 检测依据：
    ///
    /// * **退出码 31 或 159** → `SIGSYS`（seccomp 杀死了进程）。
    ///   31 是直接的 SIGSYS 退出；159（128 + SIGSYS）是 Unix shell
    ///   表示被信号杀死的进程的习惯写法。
    /// * **stderr 模式** → Landlock 拒绝（`EPERM`/`EACCES`）或
    ///   seccomp 拒绝（"Bad system call"、"SIGSYS"、"seccomp"）。
    /// * **其他情况** → 普通程序退出。
    fn classify_exit(&self, exit_code: i32, stderr: &str) -> ExitReason {
        use crate::DenyMechanism;
        use crate::ExitReason::*;

        // 退出码 0 → 成功。
        if exit_code == 0 {
            return Ok;
        }

        // 退出码 31（直接）或 159（128 + SIGSYS，Unix shell 习惯）
        // → seccomp 杀死了进程。当 seccomp filter 返回 KILL 时，
        // 内核会投递 SIGSYS。
        if exit_code == 31 || exit_code == 159 {
            return Denied {
                mechanism: DenyMechanism::Seccomp,
                message: "Blocked by seccomp filter (SIGSYS)".into(),
            };
        }

        let lower = stderr.to_lowercase();

        // ── Landlock 拒绝模式 ───────────────────────────────────────
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

        // ── Seccomp 拒绝模式 ─────────────────────────────────────────
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
    /// 返回一个包含 19 条 `sock_filter` 指令的 `Vec`
    ///（详见 [`seccomp::build_blacklist_filter`]）。
    fn build_bpf_filter(&self) -> Vec<seccomp::sock_filter> {
        seccomp::build_blacklist_filter()
    }
}