//! Core types and traits for sandbox-runtime.
//!
//! This module defines the platform-agnostic abstractions:
//! - [`Sandbox`] trait (the main abstraction over sandbox backends)
//! - [`SandboxType`], [`FsPolicy`], [`DenyMechanism`], [`ExitReason`]
//! - Command specifications: [`CommandSpec`], [`PreparedCommand`], [`CommandOutput`]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub mod config;

#[cfg(target_os = "linux")]
pub mod linux;

// ---------------------------------------------------------------------------
// SandboxType
// ---------------------------------------------------------------------------

/// Identifies which sandbox backend is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxType {
    /// No sandbox enforcement.
    None,
    /// Linux Landlock filesystem ACL (requires Linux 5.13+).
    #[cfg(target_os = "linux")]
    LinuxLandlock,
}

// ---------------------------------------------------------------------------
// FsPolicy (core type, also used by config)
// ---------------------------------------------------------------------------

/// Filesystem access policy for the sandbox.
///
/// This is a core type that is also used by [`crate::config::FilesystemConfig`]
/// and can be serialized/deserialized from TOML or JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "kebab-case")]
pub enum FsPolicy {
    /// Allow full access to the filesystem (no Landlock rules).
    FullAccess,
    /// Allow read-only access; write operations are blocked.
    ReadOnly,
    /// Allow writes only to the workspace directory, /tmp, and explicitly
    /// listed paths (see `allow_write` in [`crate::config::FilesystemConfig`]).
    #[serde(rename = "workspace")]
    WorkspaceWrite,
}

// ---------------------------------------------------------------------------
// DenyMechanism
// ---------------------------------------------------------------------------

/// The kernel mechanism that denied a sandboxed operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyMechanism {
    /// Denied by Landlock (filesystem ACL).
    Landlock,
    /// Denied by seccomp (syscall filter).
    Seccomp,
    /// Unknown or unrecognised mechanism.
    Unknown,
}

// ---------------------------------------------------------------------------
// ExitReason
// ---------------------------------------------------------------------------

/// Classifies the exit status of a sandboxed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitReason {
    /// Command exited successfully (exit code 0).
    Ok,
    /// Command was denied by a sandbox mechanism.
    Denied {
        /// Which mechanism denied the operation.
        mechanism: DenyMechanism,
        /// Diagnostic message from the kernel / runtime.
        message: String,
    },
    /// Command exited with a non-zero exit code (not sandbox-related).
    Program(i32),
    /// An internal error occurred (e.g. timeout, I/O error).
    InternalError(String),
}

impl ExitReason {
    /// Returns `true` if the command was denied by the sandbox.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    /// Returns `true` if the command exited successfully.
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

// ---------------------------------------------------------------------------
// CommandSpec
// ---------------------------------------------------------------------------

/// A fully-specified command to run inside the sandbox.
///
/// This is the input to [`Sandbox::prepare`] and [`Sandbox::execute`].
#[derive(Debug, Clone)]
pub struct CommandSpec {
    /// The program to execute (path or name resolved via `PATH`).
    pub program: String,
    /// Arguments passed to the program (without the program name).
    pub args: Vec<String>,
    /// Working directory for the command.
    pub cwd: PathBuf,
    /// Environment variables for the command.
    pub env: HashMap<String, String>,
    /// Maximum wall-clock time before the command is killed.
    pub timeout: Duration,
    /// Filesystem policy for this command.
    pub sandbox_policy: FsPolicy,
}

// ---------------------------------------------------------------------------
// PreparedCommand
// ---------------------------------------------------------------------------

/// A command that has been prepared for execution (resolved paths, etc.).
#[derive(Debug, Clone)]
pub struct PreparedCommand {
    /// The full command line (program + args).
    pub command: Vec<String>,
    /// Working directory for the command.
    pub cwd: PathBuf,
    /// Environment variables for the command.
    pub env: HashMap<String, String>,
    /// Maximum wall-clock time before the command is killed.
    pub timeout: Duration,
}

// ---------------------------------------------------------------------------
// CommandOutput
// ---------------------------------------------------------------------------

/// The result of executing a sandboxed command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Standard output captured from the command.
    pub stdout: String,
    /// Standard error captured from the command.
    pub stderr: String,
    /// Exit code of the command.
    pub exit_code: i32,
}

// ---------------------------------------------------------------------------
// Sandbox trait
// ---------------------------------------------------------------------------

/// Platform-agnostic sandbox abstraction.
///
/// Implementations provide filesystem isolation and syscall filtering
/// using the kernel mechanisms available on the target platform
/// (e.g. Landlock + seccomp on Linux, Seatbelt on macOS).
pub trait Sandbox: Send + Sync {
    /// Prepare a [`CommandSpec`] for execution, resolving paths and
    /// building the sandbox ruleset where possible before spawning.
    fn prepare(&self, spec: &CommandSpec) -> anyhow::Result<PreparedCommand>;

    /// Execute a command under sandbox restrictions and return its output.
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<CommandOutput>;

    /// Classify the exit code and stderr of a completed command into an
    /// [`ExitReason`], detecting sandbox denials (Landlock, seccomp, etc.)
    /// vs. normal program exits vs. internal errors.
    fn classify_exit(&self, exit_code: i32, stderr: &str) -> ExitReason;
}
