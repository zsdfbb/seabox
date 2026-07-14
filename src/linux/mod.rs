//! Linux sandbox implementation using Landlock + seccomp BPF.
//!
//! Provides [`LinuxSandbox`] which implements the [`Sandbox`] trait:
//! filesystem access control via Landlock ACLs and syscall filtering
//! via a hand-written seccomp BPF blacklist.
//!
//! ## Execution flow
//!
//! 1. **Parent process** builds the Landlock ruleset (via `build_ruleset`)
//!    and the seccomp BPF filter array.
//! 2. **Parent process** calls `Command::spawn()` with a `pre_exec` closure.
//! 3. **Child process** (fork → pre_exec → execve) applies:
//!    - `prctl(PR_SET_NO_NEW_PRIVS, 1, …)`
//!    - `landlock_restrict_self(ruleset_fd, 0)` (if a ruleset exists)
//!    - `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`
//! 4. **Parent process** captures stdout/stderr and exit status.

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

/// A Linux sandbox that enforces filesystem and syscall restrictions using
/// Landlock ACLs and seccomp BPF filters.
#[derive(Debug)]
pub struct LinuxSandbox {
    pub config: SandboxConfig,
}

// ---------------------------------------------------------------------------
// Sandbox trait implementation
// ---------------------------------------------------------------------------

impl Sandbox for LinuxSandbox {
    /// Execute a command inside the sandbox.
    ///
    /// Builds the Landlock ruleset and seccomp BPF filter in the **parent**
    /// process, then applies both in the **child** via a `pre_exec` closure
    /// (zero-allocation context).
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<CommandOutput> {
        // ── Step 1: Build Landlock ruleset and extract its fd ────────────
        let ruleset_fd: Option<OwnedFd> = self.prepare_ruleset_fd(spec)?;
        let raw_ruleset_fd: i32 = ruleset_fd
            .as_ref()
            .map(|fd| fd.as_raw_fd())
            .unwrap_or(-1);

        // ── Step 2: Build seccomp BPF filter ───────────────────────────
        let bpf_filter = self.build_bpf_filter();
        let bpf_prog = seccomp::build_sock_fprog(&bpf_filter);

        // ── Step 3: Expand ~ in cwd if needed ──────────────────────────
        let cwd = match spec.cwd.to_str() {
            Some(s) => PathBuf::from(crate::config::expand_tilde(s)),
            None => spec.cwd.clone(),
        };

        // ── Step 4: Spawn child with pre_exec restrictions ─────────────
        //
        // SAFETY for `pre_exec`:
        //
        // The closure runs after `fork()` but before `execve()`.  We take
        // extreme care to:
        //
        // * Capture only `raw_ruleset_fd` (a plain `i32`) and `bpf_prog`
        //   (a `sock_fprog` struct with `Send + Sync` via unsafe impl).
        // * Not perform any heap allocation inside the closure.
        // * Only call `libc::prctl`, `libc::syscall`, and `libc::close` —
        //   all async-signal-safe.
        //
        // The `bpf_filter` Vec is **not** captured; it lives on the
        // parent's stack and is only dropped after `spawn()` returns.
        // After fork the child has its own COW copy of the stack frames,
        // so the `bpf_prog.filter` pointer remains valid in the child's
        // address space until `prctl` copies the program into kernel
        // memory.
        let output = unsafe {
            std::process::Command::new(&spec.program)
                .args(&spec.args)
                .current_dir(&cwd)
                .envs(&spec.env)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .pre_exec(move || {
                    // -------------------------------------------------------
                    // Step A: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                    //
                    // Required before SECCOMP_MODE_FILTER for
                    // non-CAP_SYS_ADMIN processes.
                    // man:prctl(2) PR_SET_NO_NEW_PRIVS
                    // -------------------------------------------------------
                    // SAFETY: All arguments are plain integers; the kernel
                    // validates and returns an error code on failure.
                    let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                    if ret != 0 {
                        return Err(std::io::Error::last_os_error());
                    }

                    // -------------------------------------------------------
                    // Step B: landlock_restrict_self(ruleset_fd, 0)
                    //
                    // Apply the Landlock ruleset to the current process.
                    // Only called when a ruleset was created (not FullAccess).
                    // man:landlock_restrict_self(2)
                    // -------------------------------------------------------
                    if raw_ruleset_fd >= 0 {
                        // SAFETY: `raw_ruleset_fd` is a valid fd from
                        // `landlock_create_ruleset(2)` created by the parent.
                        // The kernel validates access rights.
                        let ret = libc::syscall(
                            libc::SYS_landlock_restrict_self,
                            raw_ruleset_fd,
                            0,
                        );
                        if ret != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        // Close the fd in the child; no longer needed.
                        libc::close(raw_ruleset_fd);
                    }

                    // -------------------------------------------------------
                    // Step C: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)
                    //
                    // Load the BPF blacklist filter.  Every subsequent syscall
                    // is checked against this filter.
                    // man:prctl(2) PR_SET_SECCOMP
                    // -------------------------------------------------------
                    // SAFETY: `bpf_prog` is a well-formed `sock_fprog` produced
                    // by `build_sock_fprog`.  The backing filter data is valid
                    // (the child's COW copy of `bpf_filter` still lives on the
                    // parent's stack frame, accessible via the child's cloned
                    // address space).  `prctl` copies the program into kernel
                    // memory, so the pointer is only needed during the call.
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

        // `ruleset_fd` is dropped here → fd closed in parent.

        // ── Step 5: Convert output ────────────────────────────────────
        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or_else(|| {
                output.status.signal().map(|s| 128 + s).unwrap_or(-1)
            }),
        })
    }

    /// Prepare a [`CommandSpec`] for execution by resolving paths and
    /// populating a [`PreparedCommand`].
    ///
    /// Does **not** spawn a process or apply any sandbox restrictions.
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

    /// Classify a completed command's exit code and stderr into an
    /// [`ExitReason`].
    ///
    /// Detection relies on:
    ///
    /// * **Exit code 31 or 159** → `SIGSYS` (seccomp killed the process).
    ///   31 is a direct SIGSYS exit; 159 (128 + SIGSYS) is the shell convention
    ///   for signal-killed processes on Unix.
    /// * **Stderr patterns** → Landlock denial (`EPERM`/`EACCES`) or
    ///   seccomp denial ("Bad system call", "SIGSYS", "seccomp").
    /// * **Everything else** → normal program exit.
    fn classify_exit(&self, exit_code: i32, stderr: &str) -> ExitReason {
        use crate::DenyMechanism;
        use crate::ExitReason::*;

        // Exit code 0 → success.
        if exit_code == 0 {
            return Ok;
        }

        // Exit code 31 (direct) or 159 (128 + SIGSYS, Unix shell convention)
        // → seccomp killed the process.  The kernel delivers SIGSYS when a
        // seccomp filter returns KILL.
        if exit_code == 31 || exit_code == 159 {
            return Denied {
                mechanism: DenyMechanism::Seccomp,
                message: "Blocked by seccomp filter (SIGSYS)".into(),
            };
        }

        let lower = stderr.to_lowercase();

        // ── Landlock denial patterns ───────────────────────────────────
        // Landlock blocks filesystem operations with EACCES or EPERM.
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

        // ── Seccomp denial patterns ───────────────────────────────────
        // seccomp filters signal through the audit log or stderr messages
        // from libc/kernel.
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

        // ── Normal program exit (non-zero) ─────────────────────────────
        Program(exit_code)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

impl LinuxSandbox {
    /// Build the Landlock ruleset and return its optional file descriptor.
    ///
    /// * `FsPolicy::FullAccess` → returns `None` (no Landlock restrictions).
    /// * Other policies → builds the ruleset via `landlock::build_ruleset`,
    ///   then extracts the underlying `OwnedFd` from the `RulesetCreated`.
    ///
    /// The caller (our `execute` above) passes the raw fd into the
    /// `pre_exec` closure where the child process calls
    /// `landlock_restrict_self(2)`.
    fn prepare_ruleset_fd(&self, spec: &CommandSpec) -> anyhow::Result<Option<OwnedFd>> {
        // Expand tilde in allow_write paths.
        let allow_write: Vec<PathBuf> = self
            .config
            .filesystem
            .allow_write
            .iter()
            .map(|p| PathBuf::from(crate::config::expand_tilde(p)))
            .collect();

        // Build the ruleset (may return None for FullAccess).
        let created = landlock::build_ruleset(&spec.sandbox_policy, &allow_write, &spec.cwd)?;

        // Extract the optional fd — consumes the RulesetCreated.
        // `From<RulesetCreated> for Option<OwnedFd>` is defined in the
        // landlock crate (ruleset.rs line 985).
        Ok(match created {
            Some(ruleset) => {
                let fd: Option<OwnedFd> = ruleset.into();
                fd
            }
            None => None,
        })
    }

    /// Build the seccomp BPF blacklist filter.
    ///
    /// Returns a `Vec` of 19 `sock_filter` instructions (see
    /// [`seccomp::build_blacklist_filter`] for details).
    fn build_bpf_filter(&self) -> Vec<seccomp::sock_filter> {
        seccomp::build_blacklist_filter()
    }
}
