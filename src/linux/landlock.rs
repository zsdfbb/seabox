//! Landlock ruleset construction.
//!
//! Provides functions to build Landlock filesystem ACL rulesets
//! based on the [`FsPolicy`] configuration.
//!
//! Uses the `landlock` crate with [`CompatLevel::BestEffort`] for
//! automatic ABI version detection and graceful degradation on
//! kernels that don't support the full access set requested.
//!
//! # Usage
//!
//! ```ignore
//! use landlock::RulesetCreated;
//!
//! let created: Option<RulesetCreated> = build_ruleset(
//!     &FsPolicy::ReadOnly, &[], Path::new("/"),
//! )?;
//! if let Some(ruleset) = created {
//!     // Ruleset is configured but NOT yet applied.
//!     // Restrict at the right moment (e.g. in a pre_exec closure):
//!     let status = ruleset.restrict_self()?;
//! }
//! ```

use std::path::{Path, PathBuf};

use landlock::{
    Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, path_beneath_rules, ABI,
};

use crate::FsPolicy;

// ---------------------------------------------------------------------------
// Availability
// ---------------------------------------------------------------------------

/// Check whether Landlock is available on the current system.
///
/// Returns `true` if the kernel supports Landlock (Linux 5.13+ with
/// `CONFIG_SECURITY_LANDLOCK=y` / `lsm=landlock`) **and** the running
/// process has the necessary capabilities.
///
/// # Method
///
/// Creates a minimal [`Ruleset`] with [`CompatLevel::HardRequirement`] and
/// tries to handle [`ABI::V1`] read access.  If the `handle_access` call
/// succeeds, Landlock is usable.  No actual ruleset FD is created and no
/// process state is modified — the probe is purely in-memory.
pub fn is_available() -> bool {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_read(ABI::V1))
        .is_ok()
}

/// Get the Landlock ABI version that the running kernel supports.
///
/// Returns `None` if Landlock is not available at all.
///
/// # Method
///
/// Probes from the highest ABI known to the crate (V7) down to V1 using
/// [`CompatLevel::HardRequirement`] and returns the first version whose
/// full [`AccessFs::from_all`] set is accepted by the kernel.
///
/// Landlock ABI versions correspond to kernel releases:
///
/// | ABI | Linux kernel | New access rights              |
/// |-----|--------------|-------------------------------|
/// | 1   | 5.13         | Initial: read/write/execute   |
/// | 2   | 5.19         | `REFER` (rename/link across   |
/// |     |              | directory trees)               |
/// | 3   | 6.2          | `TRUNCATE`                    |
/// | 4   | 6.7          | `IOCTL_DEV`                   |
/// | 5   | 6.10         | TCP bind/connect              |
/// | 6   | 6.12         | `Scope` (AF_UNIX / signal)    |
/// | 7   | 6.15         | Log flags for restrict_self   |
pub fn get_abi_version() -> Option<i32> {
    // Fast path: if V1 read access is not even supported, Landlock is
    // unavailable.
    if !is_available() {
        return None;
    }

    // Probe from highest known ABI down to V1.  Because access rights are
    // cumulative across versions, the first version for which
    // AccessFs::from_all(abi) is fully accepted (no PartiallyCompatible /
    // Incompatible error) is the kernel's effective ABI.
    for v in (1..=7usize).rev() {
        // ABI::from maps 1→V1, 2→V2, …, ≥8 → V7
        let abi = ABI::from(v as i32);
        if Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .is_ok()
        {
            return Some(v as i32);
        }
    }

    // Safety net — at least V1 must be supported because `is_available()`
    // returned true above.
    Some(1)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Return the Landlock ABI to use for constructing access masks.
///
/// If Landlock is unavailable on the running kernel, falls back to
/// [`ABI::V1`] so that [`AccessFs::from_read`] / [`AccessFs::from_write`]
/// still return non-empty bit sets.  The subsequent [`Ruleset::create`] call
/// will detect the incompatibility via the `BestEffort` compat state and
/// return a no-op (dummy) [`RulesetCreated`].
fn get_effective_abi() -> ABI {
    // ABI::from maps any value < 1 to Unsupported, 1→V1, 2→V2, …
    match get_abi_version() {
        Some(v) => ABI::from(v),
        None => ABI::V1,
    }
}

// ---------------------------------------------------------------------------
// Ruleset construction
// ---------------------------------------------------------------------------

/// Build a Landlock ruleset according to the given filesystem policy.
///
/// The returned [`RulesetCreated`] is **configured with rules but not yet
/// applied**. The caller must call [`RulesetCreated::restrict_self`] at the
/// appropriate point (e.g. in a `pre_exec` closure after `fork()` but before
/// `execve()`).  This two-phase construction allows the parent process to
/// build the ruleset while the child applies it in a zero-allocation context.
///
/// # Policy → Landlock mapping
///
/// | `FsPolicy`      | Handled access                     | Rules                                   |
/// |-----------------|------------------------------------|-----------------------------------------|
/// | `FullAccess`    | No Landlock ruleset created        | — (returns `None`)                      |
/// | `ReadOnly`      | `READ_FILE \| READ_DIR`            | Read on `/`                             |
/// | `WorkspaceWrite`| `READ_FILE \| READ_DIR \| WRITE_FILE \| REMOVE_DIR \| REMOVE_FILE \| MAKE_DIR \| MAKE_REG \| MAKE_SYM \| TRUNCATE` | Read on `/` + write on cwd, `/tmp`, `allow_write` paths |
///
/// # Path resolution
///
/// All paths are opened via [`PathFd`] internally (which uses `O_PATH`).
/// Paths that **do not exist** are **silently skipped**, following CodeWhale
/// convention.  This includes `cwd` and `/tmp` if they are absent from the
/// filesystem.
///
/// The `allow_write` paths are expected to be pre-expanded and
/// pre-canonicalised by the caller (see [`crate::config::expand_tilde`]).
///
/// # Errors
///
/// Returns an error if Landlock access rights configuration itself is
/// inconsistent (e.g. empty handled-access), or if the ruleset creation
/// syscall fails on a kernel where Landlock *is* available.
///
/// Kernels without any Landlock support will **not** cause an error here:
/// with [`CompatLevel::BestEffort`] the builder returns a no-op
/// [`RulesetCreated`] whose [`restrict_self`](RulesetCreated::restrict_self)
/// will report [`RulesetStatus::NotEnforced`].
///
/// [`PathFd`]: landlock::PathFd
/// [`RulesetStatus::NotEnforced`]: landlock::RulesetStatus
pub fn build_ruleset(
    policy: &FsPolicy,
    allow_write: &[PathBuf],
    cwd: &Path,
) -> anyhow::Result<Option<RulesetCreated>> {
    match policy {
        // ------------------------------------------------------------------
        // FullAccess: no Landlock restrictions at all
        // ------------------------------------------------------------------
        FsPolicy::FullAccess => Ok(None),

        // ------------------------------------------------------------------
        // ReadOnly: deny all writes by handling both read and write access
        // rights, but only granting read access in the rules.
        //
        // In Landlock, only access rights declared in the "handled" set are
        // checked.  If write rights are not handled, the kernel allows all
        // writes unconditionally.  By handling the full (read | write) mask
        // and only granting read access via rules, all write attempts are
        // denied (handled but not granted).
        // ------------------------------------------------------------------
        FsPolicy::ReadOnly => {
            let abi = get_effective_abi();
            let read_access = AccessFs::from_read(abi);
            let write_access = AccessFs::from_write(abi);
            let handled = read_access | write_access;

            let ruleset = Ruleset::default()
                .set_compatibility(CompatLevel::BestEffort)
                .handle_access(handled)?
                .create()?;

            // Grant read access to "/".  Write access is handled but never
            // granted, so all writes are denied.
            // path_beneath_rules silently skips paths that cannot be opened
            // (impossible for "/" on any real system, but handled defensively).
            let ruleset = ruleset
                .add_rules(path_beneath_rules([Path::new("/")], read_access))?;

            Ok(Some(ruleset))
        }

        // ------------------------------------------------------------------
        // WorkspaceWrite: read on "/" + write on cwd, /tmp, allow_write
        // ------------------------------------------------------------------
        FsPolicy::WorkspaceWrite => {
            let abi = get_effective_abi();
            let read_access = AccessFs::from_read(abi);
            let write_access = AccessFs::from_write(abi);
            let handled = read_access | write_access;

            let ruleset = Ruleset::default()
                .set_compatibility(CompatLevel::BestEffort)
                .handle_access(handled)?
                .create()?;

            // --- Read rule on "/" ---
            let ruleset = ruleset
                .add_rules(path_beneath_rules([Path::new("/")], read_access))?;

            // --- Collect writable paths ---
            // path_beneath_rules silently skips non-existent paths, so we
            // just collect candidates and let the helper filter.
            let mut writable_paths: Vec<PathBuf> =
                Vec::with_capacity(2 + allow_write.len());

            // 1. /tmp (standard temp directory)
            writable_paths.push(PathBuf::from("/tmp"));

            // 2. Current working directory
            writable_paths.push(cwd.to_path_buf());

            // 3. Externally-provided allow_write paths (already expanded
            //    and canonicalised by the caller).
            writable_paths.extend(allow_write.iter().cloned());

            // Deduplicate — the same path could appear in multiple sources
            // (e.g. cwd == /tmp, or allow_write contains /tmp twice).
            writable_paths.sort();
            writable_paths.dedup();

            // --- Write rules ---
            let ruleset = if !writable_paths.is_empty() {
                ruleset.add_rules(path_beneath_rules(writable_paths, write_access))?
            } else {
                ruleset
            };

            Ok(Some(ruleset))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_is_available_returns_bool() {
        // Should always return a bool without panicking.
        let _available = is_available();
        // No assertion needed — reaching here means no panic.
    }

    #[test]
    fn test_abi_version_consistent_with_available() {
        let available = is_available();
        let version = get_abi_version();
        if available {
            assert!(version.is_some(), "Landlock available => version must be Some");
            let v = version.unwrap();
            assert!(v >= 1, "ABI version must be >= 1, got {v}");
        } else {
            assert!(version.is_none(), "Landlock unavailable => version must be None");
        }
    }

    #[test]
    fn test_build_ruleset_full_access_returns_none() {
        let result = build_ruleset(&FsPolicy::FullAccess, &[], Path::new("/"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_build_ruleset_read_only_returns_ruleset() {
        // build_ruleset should succeed even without Landlock support
        // (returns a dummy RulesetCreated with BestEffort).
        let result = build_ruleset(&FsPolicy::ReadOnly, &[], Path::new("/"));
        assert!(
            result.is_ok(),
            "build should succeed even without Landlock: {:?}",
            result.err()
        );
        let ruleset = result.unwrap();
        assert!(
            ruleset.is_some(),
            "ReadOnly should produce a ruleset (not None)"
        );
    }

    #[test]
    fn test_build_ruleset_workspace_write_returns_ruleset() {
        let result = build_ruleset(&FsPolicy::WorkspaceWrite, &[], Path::new("/tmp"));
        assert!(
            result.is_ok(),
            "build should succeed even without Landlock: {:?}",
            result.err()
        );
        let ruleset = result.unwrap();
        assert!(
            ruleset.is_some(),
            "WorkspaceWrite should produce a ruleset (not None)"
        );
    }

    #[test]
    fn test_build_ruleset_with_additional_paths() {
        let allow = vec![PathBuf::from("/usr"), PathBuf::from("/etc")];
        let result = build_ruleset(&FsPolicy::WorkspaceWrite, &allow, Path::new("/tmp"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_build_ruleset_non_existent_paths_skipped() {
        // Non-existent paths should be silently skipped by path_beneath_rules.
        let allow = vec![
            PathBuf::from("/this/path/should/not/exist/abc123xyz"),
            PathBuf::from("/tmp"), // exists
        ];
        let result = build_ruleset(&FsPolicy::WorkspaceWrite, &allow, Path::new("/tmp"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_dedup_writable_paths() {
        let allow = vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"), // duplicate
        ];
        let result = build_ruleset(&FsPolicy::WorkspaceWrite, &allow, Path::new("/tmp"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_build_ruleset_for_missing_cwd() {
        // cwd that doesn't exist should be silently skipped.
        let result = build_ruleset(
            &FsPolicy::WorkspaceWrite,
            &[],
            Path::new("/nonexistent_cwd_xyz"),
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_get_effective_abi_never_unsupported() {
        let abi = get_effective_abi();
        // Must never be Unsupported (ABI::Unsupported == ABI::from(0)).
        assert_ne!(abi, ABI::Unsupported);
    }
}
