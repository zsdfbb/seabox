//! Sandbox configuration parsing and builder.
//!
//! Provides [`SandboxConfig`] (deserialisable from TOML), a [`SandboxConfigBuilder`],
//! and the [`expand_tilde`] utility for path expansion.
//!
//! ## TOML Example
//!
//! ```toml
//! [filesystem]
//! policy = "workspace"
//! allow_write = [".", "/tmp"]
//!
//! [network]
//! enabled = false
//!
//! [timeout]
//! default_secs = 30
//! max_secs = 300
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::FsPolicy;

// ---------------------------------------------------------------------------
// SandboxConfig
// ---------------------------------------------------------------------------

/// Complete sandbox configuration.
///
/// Deserialisable from TOML. Constructed directly, via [`SandboxConfig::from_toml`],
/// or through the [`SandboxConfig::builder`] fluent API.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxConfig {
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub timeout: TimeoutConfig,
}

impl SandboxConfig {
    /// Load a [`SandboxConfig`] from a TOML file on disk.
    pub fn from_toml(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let config: SandboxConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Create a [`SandboxConfigBuilder`] for programmatic construction.
    pub fn builder() -> SandboxConfigBuilder {
        SandboxConfigBuilder::default()
    }
}

// ---------------------------------------------------------------------------
// SandboxConfigBuilder
// ---------------------------------------------------------------------------

/// Fluent builder for [`SandboxConfig`].
///
/// # Example
///
/// ```ignore
/// use sandbox_runtime::config::SandboxConfig;
/// use sandbox_runtime::FsPolicy;
///
/// let config = SandboxConfig::builder()
///     .policy(FsPolicy::ReadOnly)
///     .allow_write(vec!["/tmp".to_string()])
///     .network_enabled(false)
///     .timeout(60, 600)
///     .build();
/// ```
#[derive(Debug)]
pub struct SandboxConfigBuilder {
    policy: Option<FsPolicy>,
    allow_write: Vec<String>,
    network_enabled: bool,
    timeout_default_secs: u64,
    timeout_max_secs: u64,
}

impl Default for SandboxConfigBuilder {
    fn default() -> Self {
        Self {
            policy: None,
            allow_write: Vec::new(),
            network_enabled: false,
            timeout_default_secs: 30,
            timeout_max_secs: 300,
        }
    }
}

impl SandboxConfigBuilder {
    /// Set the filesystem policy.
    pub fn policy(mut self, policy: FsPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set additional writable paths (in addition to workspace and /tmp).
    pub fn allow_write(mut self, paths: impl Into<Vec<String>>) -> Self {
        self.allow_write = paths.into();
        self
    }

    /// Enable or disable network access (Phase 1: placeholder only).
    pub fn network_enabled(mut self, enabled: bool) -> Self {
        self.network_enabled = enabled;
        self
    }

    /// Set both default and maximum timeout (in seconds).
    ///
    /// `default_secs` is the timeout applied when the caller does not specify one.
    /// `max_secs` is the hard upper bound the sandbox will accept.
    pub fn timeout(mut self, default_secs: u64, max_secs: u64) -> Self {
        self.timeout_default_secs = default_secs;
        self.timeout_max_secs = max_secs;
        self
    }

    /// Consume the builder and produce a [`SandboxConfig`].
    pub fn build(self) -> SandboxConfig {
        SandboxConfig {
            filesystem: FilesystemConfig {
                policy: self.policy.unwrap_or(FsPolicy::WorkspaceWrite),
                allow_write: self.allow_write,
            },
            network: NetworkConfig {
                enabled: self.network_enabled,
            },
            timeout: TimeoutConfig {
                default_secs: self.timeout_default_secs,
                max_secs: self.timeout_max_secs,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// FilesystemConfig
// ---------------------------------------------------------------------------

/// Filesystem access configuration for the sandbox.
///
/// The `policy` field controls the broad access mode. `allow_write` lists
/// additional paths (beyond the workspace directory and `/tmp`) that the
/// sandboxed process may write to.
///
/// # TOML
///
/// ```toml
/// [filesystem]
/// policy = "workspace"       # "full-access" | "read-only" | "workspace"
/// allow_write = ["output", "/var/log/app"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemConfig {
    /// Access policy preset.
    ///
    /// `#[serde(flatten)]` inlines the `FsPolicy` tag so that TOML writes
    /// `policy = "read-only"` directly instead of a nested `[filesystem.policy]`.
    #[serde(flatten)]
    pub policy: FsPolicy,

    /// Additional write-allowed paths (in addition to workspace dir and `/tmp`).
    ///
    /// Paths are stored as strings and support `~` expansion at runtime.
    #[serde(default)]
    pub allow_write: Vec<String>,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            policy: FsPolicy::WorkspaceWrite,
            allow_write: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// NetworkConfig
// ---------------------------------------------------------------------------

/// Network access configuration.
///
/// Phase 1: this is a placeholder. Network sandboxing is not yet implemented.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Whether network access is enabled.
    #[serde(default)]
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// TimeoutConfig
// ---------------------------------------------------------------------------

/// Timeout configuration for sandboxed commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Default command timeout in seconds.
    #[serde(default = "default_timeout")]
    pub default_secs: u64,
    /// Maximum allowed command timeout in seconds.
    #[serde(default = "default_max_timeout")]
    pub max_secs: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            default_secs: default_timeout(),
            max_secs: default_max_timeout(),
        }
    }
}

fn default_timeout() -> u64 {
    30
}

fn default_max_timeout() -> u64 {
    300
}

// ---------------------------------------------------------------------------
// expand_tilde
// ---------------------------------------------------------------------------

/// Expand a leading `~` or `~/` in a path string to the user's home directory.
///
/// If `$HOME` is not set (unusual on Linux/macOS), the string is returned
/// unchanged.
///
/// # Examples
///
/// ```
/// use sandbox_runtime::config::expand_tilde;
///
/// let expanded = expand_tilde("~/projects");
/// assert!(!expanded.starts_with("~/"));
/// assert!(expanded.ends_with("/projects"));
///
/// // Absolute paths pass through unchanged.
/// assert_eq!(expand_tilde("/tmp"), "/tmp");
/// ```
pub fn expand_tilde(s: &str) -> String {
    if s.starts_with("~/") || s == "~" {
        if let Some(home) = dirs::home_dir() {
            return s.replacen('~', &home.to_string_lossy(), 1);
        }
    }
    s.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FsPolicy;

    #[test]
    fn test_default_config() {
        let config = SandboxConfig::default();
        assert_eq!(config.filesystem.policy, FsPolicy::WorkspaceWrite);
        assert!(config.filesystem.allow_write.is_empty());
        assert!(!config.network.enabled);
        assert_eq!(config.timeout.default_secs, 30);
        assert_eq!(config.timeout.max_secs, 300);
    }

    #[test]
    fn test_expand_tilde() {
        let result = expand_tilde("~/test");
        assert!(!result.starts_with("~/"), "tilde should be expanded");
        assert!(result.ends_with("/test"), "suffix should be preserved");

        let just_tilde = expand_tilde("~");
        assert!(!just_tilde.starts_with('~'), "bare tilde should expand");

        // Absolute paths pass through unchanged.
        assert_eq!(expand_tilde("/tmp/foo"), "/tmp/foo");

        // Paths without leading tilde pass through.
        assert_eq!(expand_tilde("relative/path"), "relative/path");
    }

    #[test]
    fn test_builder_default() {
        let config = SandboxConfig::builder().build();
        assert_eq!(config.filesystem.policy, FsPolicy::WorkspaceWrite);
        assert!(!config.network.enabled);
        assert_eq!(config.timeout.default_secs, 30);
        assert_eq!(config.timeout.max_secs, 300);
    }

    #[test]
    fn test_builder_roundtrip() {
        let config = SandboxConfig::builder()
            .policy(FsPolicy::ReadOnly)
            .allow_write(vec!["/tmp".to_string(), "./output".to_string()])
            .network_enabled(true)
            .timeout(60, 600)
            .build();

        assert_eq!(config.filesystem.policy, FsPolicy::ReadOnly);
        assert_eq!(config.filesystem.allow_write, vec!["/tmp", "./output"]);
        assert!(config.network.enabled);
        assert_eq!(config.timeout.default_secs, 60);
        assert_eq!(config.timeout.max_secs, 600);
    }

    #[test]
    fn test_filesystem_default() {
        let fs = FilesystemConfig::default();
        assert_eq!(fs.policy, FsPolicy::WorkspaceWrite);
        assert!(fs.allow_write.is_empty());
    }

    #[test]
    fn test_network_default() {
        let net = NetworkConfig::default();
        assert!(!net.enabled);
    }

    #[test]
    fn test_timeout_default() {
        let t = TimeoutConfig::default();
        assert_eq!(t.default_secs, 30);
        assert_eq!(t.max_secs, 300);
    }

    #[test]
    fn test_from_toml_nonexistent() {
        let err = SandboxConfig::from_toml("/nonexistent/path.toml").unwrap_err();
        assert!(err.to_string().contains("No such file") || err.to_string().contains("file not found"));
    }

    #[test]
    fn test_toml_roundtrip() {
        // Serialise a config to TOML and deserialise it back.
        let config = SandboxConfig {
            filesystem: FilesystemConfig {
                policy: FsPolicy::WorkspaceWrite,
                allow_write: vec!["/data".to_string()],
            },
            network: NetworkConfig { enabled: false },
            timeout: TimeoutConfig {
                default_secs: 60,
                max_secs: 600,
            },
        };

        let toml_str = toml::to_string(&config).expect("serialisation should succeed");
        let deserialised: SandboxConfig =
            toml::from_str(&toml_str).expect("deserialisation should succeed");

        assert_eq!(deserialised.filesystem.policy, FsPolicy::WorkspaceWrite);
        assert_eq!(deserialised.filesystem.allow_write, vec!["/data"]);
        assert!(!deserialised.network.enabled);
        assert_eq!(deserialised.timeout.default_secs, 60);
        assert_eq!(deserialised.timeout.max_secs, 600);
    }

    #[test]
    fn test_toml_deserialize_flattened_policy() {
        // Verify that the flattened `policy` tag works: `policy = "read-only"` at
        // the `[filesystem]` level, not inside a nested `[filesystem.policy]`.
        let toml_str = r#"
[filesystem]
policy = "read-only"
allow_write = ["/tmp"]

[network]
enabled = true

[timeout]
default_secs = 10
max_secs = 120
"#;
        let config: SandboxConfig = toml::from_str(toml_str).expect("TOML should parse");
        assert_eq!(config.filesystem.policy, FsPolicy::ReadOnly);
        assert_eq!(config.filesystem.allow_write, vec!["/tmp"]);
        assert!(config.network.enabled);
        assert_eq!(config.timeout.default_secs, 10);
        assert_eq!(config.timeout.max_secs, 120);
    }

    #[test]
    fn test_toml_full_access() {
        let toml_str = r#"
[filesystem]
policy = "full-access"
"#;
        let config: SandboxConfig = toml::from_str(toml_str).expect("TOML should parse");
        assert_eq!(config.filesystem.policy, FsPolicy::FullAccess);
    }

    #[test]
    fn test_toml_invalid_policy() {
        let toml_str = r#"
[filesystem]
policy = "invalid-policy"
"#;
        let result: Result<SandboxConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err(), "invalid policy should fail to deserialise");
    }

    #[test]
    fn test_tilde_in_builder_paths() {
        // Builder stores paths as-is; expansion is a runtime concern.
        let config = SandboxConfig::builder()
            .allow_write(vec!["~/workspace".to_string()])
            .build();
        assert_eq!(config.filesystem.allow_write, vec!["~/workspace"]);
        // expand_tilde at runtime
        let expanded = expand_tilde(&config.filesystem.allow_write[0]);
        assert!(!expanded.starts_with("~/"));
        assert!(expanded.ends_with("/workspace"));
    }
}
