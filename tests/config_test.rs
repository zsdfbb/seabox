//! Integration tests for SandboxConfig: TOML deserialization, Builder construction,
//! expand_tilde, invalid policy rejection, partial TOML defaults, and round-trip.
//!
//! These tests exercise the external `sandbox_runtime::config` API surface.

use sandbox_runtime::config::SandboxConfig;
use sandbox_runtime::FsPolicy;

// ---------------------------------------------------------------------------
// TOML → SandboxConfig deserialization (three policy variants)
// ---------------------------------------------------------------------------

#[test]
fn test_toml_full_access() {
    let toml_str = r#"
[filesystem]
policy = "full-access"
"#;
    let config: SandboxConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.filesystem.policy, FsPolicy::FullAccess);
    assert!(config.filesystem.allow_write.is_empty());
    // Defaults for unspecified sections
    assert!(!config.network.enabled);
    assert_eq!(config.timeout.default_secs, 30);
    assert_eq!(config.timeout.max_secs, 300);
}

#[test]
fn test_toml_read_only() {
    let toml_str = r#"
[filesystem]
policy = "read-only"
"#;
    let config: SandboxConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.filesystem.policy, FsPolicy::ReadOnly);
    assert!(config.filesystem.allow_write.is_empty());
}

#[test]
fn test_toml_workspace_write() {
    let toml_str = r#"
[filesystem]
policy = "workspace"
allow_write = ["/data", "/var/log"]
"#;
    let config: SandboxConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.filesystem.policy, FsPolicy::WorkspaceWrite);
    assert_eq!(
        config.filesystem.allow_write,
        vec!["/data", "/var/log"]
    );
}

// ---------------------------------------------------------------------------
// Builder → SandboxConfig construction, matching TOML deserialization
// ---------------------------------------------------------------------------

#[test]
fn test_builder_matches_toml() {
    let builder_config = SandboxConfig::builder()
        .policy(FsPolicy::ReadOnly)
        .allow_write(vec!["/tmp".to_string()])
        .network_enabled(true)
        .timeout(60, 600)
        .build();

    let toml_str = r#"
[filesystem]
policy = "read-only"
allow_write = ["/tmp"]

[network]
enabled = true

[timeout]
default_secs = 60
max_secs = 600
"#;
    let toml_config: SandboxConfig = toml::from_str(toml_str).unwrap();

    assert_eq!(
        builder_config.filesystem.policy,
        toml_config.filesystem.policy
    );
    assert_eq!(
        builder_config.filesystem.allow_write,
        toml_config.filesystem.allow_write
    );
    assert_eq!(builder_config.network.enabled, toml_config.network.enabled);
    assert_eq!(
        builder_config.timeout.default_secs,
        toml_config.timeout.default_secs
    );
    assert_eq!(
        builder_config.timeout.max_secs,
        toml_config.timeout.max_secs
    );
}

// ---------------------------------------------------------------------------
// expand_tilde
// ---------------------------------------------------------------------------

#[test]
fn test_expand_tilde() {
    // ~/path → $HOME/path
    let expanded = sandbox_runtime::config::expand_tilde("~/projects");
    assert!(!expanded.starts_with("~/"));
    assert!(expanded.ends_with("/projects"));

    // bare ~ → $HOME
    let bare = sandbox_runtime::config::expand_tilde("~");
    assert!(!bare.starts_with('~'), "bare tilde should expand");

    // ~otheruser stays unchanged (only leading ~/ or bare ~ are expanded)
    assert_eq!(
        sandbox_runtime::config::expand_tilde("~otheruser"),
        "~otheruser"
    );

    // Absolute path without tilde → unchanged
    assert_eq!(
        sandbox_runtime::config::expand_tilde("/absolute/path"),
        "/absolute/path"
    );

    // Relative path without tilde → unchanged
    assert_eq!(
        sandbox_runtime::config::expand_tilde("relative/path"),
        "relative/path"
    );
}

// ---------------------------------------------------------------------------
// Invalid policy value rejected by serde
// ---------------------------------------------------------------------------

#[test]
fn test_invalid_policy_rejected() {
    let toml_str = r#"
[filesystem]
policy = "invalid-policy"
"#;
    let result: Result<SandboxConfig, _> = toml::from_str(toml_str);
    assert!(result.is_err(), "invalid policy should fail to deserialise");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown variant") || err.contains("unknown"),
        "error should mention unknown variant, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Partial TOML (only [filesystem]) uses defaults for [network] and [timeout]
// ---------------------------------------------------------------------------

#[test]
fn test_partial_toml_uses_defaults() {
    let toml_str = r#"
[filesystem]
policy = "full-access"
"#;
    let config: SandboxConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.filesystem.policy, FsPolicy::FullAccess);
    // Default values for unspecified sections
    assert!(!config.network.enabled);
    assert_eq!(config.timeout.default_secs, 30);
    assert_eq!(config.timeout.max_secs, 300);
}

// ---------------------------------------------------------------------------
// TOML round-trip: serialise → deserialise → values unchanged
// ---------------------------------------------------------------------------

#[test]
fn test_toml_round_trip() {
    let original = SandboxConfig::builder()
        .policy(FsPolicy::WorkspaceWrite)
        .allow_write(vec!["/data".to_string()])
        .network_enabled(false)
        .timeout(60, 600)
        .build();

    let toml_str = toml::to_string(&original).unwrap();
    let deserialized: SandboxConfig = toml::from_str(&toml_str).unwrap();

    assert_eq!(
        original.filesystem.policy,
        deserialized.filesystem.policy
    );
    assert_eq!(
        original.filesystem.allow_write,
        deserialized.filesystem.allow_write
    );
    assert_eq!(original.network.enabled, deserialized.network.enabled);
    assert_eq!(
        original.timeout.default_secs,
        deserialized.timeout.default_secs
    );
    assert_eq!(
        original.timeout.max_secs,
        deserialized.timeout.max_secs
    );
}
