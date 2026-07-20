//! Landlock 规则集构造。
//!
//! 提供根据 [`FsPolicy`] 配置构建 Landlock 文件系统 ACL 规则集的函数。
//!
//! 使用 `landlock` crate 的 [`CompatLevel::BestEffort`]，
//! 自动检测 ABI 版本并在不支持完整访问集的内核上优雅降级。
//!
//! # 用法
//!
//! ```ignore
//! use landlock::RulesetCreated;
//!
//! let created: Option<RulesetCreated> = build_ruleset(
//!     &FsPolicy::ReadOnly, &[], Path::new("/"),
//! )?;
//! if let Some(ruleset) = created {
//!     // 规则集已配置但**尚未生效**。
//!     // 在合适的时机（如 pre_exec 闭包内）施加：
//!     let status = ruleset.restrict_self()?;
//! }
//! ```

use std::path::{Path, PathBuf};

use landlock::{
    path_beneath_rules, Access, AccessFs, BitFlags, CompatLevel, Compatible, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, ABI,
};

use crate::{LandlockPerm, LandlockRule};

// ---------------------------------------------------------------------------
// 可用性
// ---------------------------------------------------------------------------

/// 检查当前系统是否支持 Landlock。
///
/// 当且仅当内核支持 Landlock（Linux 5.13+ 且
/// `CONFIG_SECURITY_LANDLOCK=y` / `lsm=landlock`）**且**当前进程
/// 具备所需能力时返回 `true`。
///
/// # 方法
///
/// 用 [`CompatLevel::HardRequirement`] 创建一个最小 [`Ruleset`]，并尝试
/// [`ABI::V1`] 的 read 访问。`handle_access` 调用成功即表明 Landlock
/// 可用。本次探测不创建实际的规则集 FD、不修改进程状态 —— 它是纯内存的。
pub fn is_available() -> bool {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_read(ABI::V1))
        .is_ok()
}

/// 获取当前内核支持的 Landlock ABI 版本。
///
/// 若 Landlock 完全不可用则返回 `None`。
///
/// # 方法
///
/// 用 [`CompatLevel::HardRequirement`] 从 crate 已知最高 ABI（V7）向下探测
/// 至 V1，返回第一个被内核完全接受（无 PartiallyCompatible /
/// Incompatible 错误）的 [`AccessFs::from_all`] 版本。
///
/// Landlock ABI 版本与内核版本对应：
///
/// | ABI | Linux 内核 | 新增的访问权限                  |
/// |-----|------------|--------------------------------|
/// | 1   | 5.13       | 初始：read/write/execute       |
/// | 2   | 5.19       | `REFER`（跨目录树的 rename/link）|
/// |     |            |                                |
/// | 3   | 6.2        | `TRUNCATE`                     |
/// | 4   | 6.7        | `IOCTL_DEV`                    |
/// | 5   | 6.10       | TCP bind/connect               |
/// | 6   | 6.12       | `Scope`（AF_UNIX / signal）    |
/// | 7   | 6.15       | restrict_self 的 log flags     |
pub fn get_abi_version() -> Option<i32> {
    // 快速路径：若连 V1 的读访问都不支持，则 Landlock 不可用。
    if !is_available() {
        return None;
    }

    // 从已知最高 ABI 向下探测至 V1。由于访问权限在各版本之间是
    // 累积的，第一个让 AccessFs::from_all(abi) 完全被接受（没有
    // PartiallyCompatible / Incompatible 错误）的版本就是内核
    // 的有效 ABI。
    for v in (1..=7usize).rev() {
        // ABI::from 的映射：1→V1, 2→V2, …, ≥8 → V7
        let abi = ABI::from(v as i32);
        if Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .is_ok()
        {
            return Some(v as i32);
        }
    }

    // 安全网 —— 至少 V1 必须被支持，因为上面的 `is_available()` 返回了 true。
    Some(1)
}

// ---------------------------------------------------------------------------
// 内部辅助
// ---------------------------------------------------------------------------

/// 返回用于构造访问掩码的 Landlock ABI。
///
/// 若内核不支持 Landlock，则回退到 [`ABI::V1`]，使得
/// [`AccessFs::from_read`] / [`AccessFs::from_write`] 仍能返回非空的位集。
/// 后续的 [`Ruleset::create`] 调用会通过 BestEffort 兼容状态检测到
/// 不兼容，并返回一个 no-op（dummy）的 [`RulesetCreated`]。
fn get_effective_abi() -> ABI {
    // ABI::from 将任何 < 1 的值映射为 Unsupported，1→V1, 2→V2, …
    match get_abi_version() {
        Some(v) => ABI::from(v),
        None => ABI::V1,
    }
}

// ---------------------------------------------------------------------------
// 规则集构造
// ---------------------------------------------------------------------------

/// 根据给定的文件系统策略构建 Landlock 规则集。
///
/// 返回的 [`RulesetCreated`] 已**配置好规则但尚未生效**。调用方必须在合适的
/// 时刻（例如在 `pre_exec` 闭包中、位于 `fork()` 之后、`execve()` 之前）
/// 调用 [`RulesetCreated::restrict_self`]。这种两阶段构造允许父进程构建
/// 规则集，而子进程在零分配上下文中施加它。
///
/// # Landlock 规则
///
/// 每条 [`LandlockRule`] 指定一个路径和一组权限。
/// 空 rules 表示不激活 Landlock。
#[allow(clippy::assign_op_pattern)]
pub fn build_ruleset(
    rules: &[LandlockRule],
    _cwd: &Path,
) -> anyhow::Result<Option<RulesetCreated>> {
    if rules.is_empty() {
        return Ok(None);
    }

    let abi = get_effective_abi();
    let read_access = AccessFs::from_read(abi);
    let write_access = AccessFs::from_write(abi);
    // 只要有规则，就同时处理 read + write（write 被处理但不授予 = 拒绝写）
    let handled = read_access | write_access;

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(handled)?
        .create()?;

    for rule in rules {
        let path = if rule.path.starts_with("~") {
            PathBuf::from(crate::config::expand_tilde(
                rule.path.to_str().unwrap_or(""),
            ))
        } else {
            rule.path.clone()
        };

        let mut access: BitFlags<AccessFs> = BitFlags::EMPTY;
        for perm in &rule.perms {
            match perm {
                LandlockPerm::Execute => access = access | AccessFs::Execute,
                LandlockPerm::ReadFile => access = access | AccessFs::ReadFile,
                LandlockPerm::ReadDir => access = access | AccessFs::ReadDir,
                LandlockPerm::WriteFile => access = access | AccessFs::WriteFile,
                LandlockPerm::RemoveDir => access = access | AccessFs::RemoveDir,
                LandlockPerm::RemoveFile => access = access | AccessFs::RemoveFile,
                LandlockPerm::MakeChar => access = access | AccessFs::MakeChar,
                LandlockPerm::MakeDir => access = access | AccessFs::MakeDir,
                LandlockPerm::MakeReg => access = access | AccessFs::MakeReg,
                LandlockPerm::MakeSock => access = access | AccessFs::MakeSock,
                LandlockPerm::MakeFifo => access = access | AccessFs::MakeFifo,
                LandlockPerm::MakeBlock => access = access | AccessFs::MakeBlock,
                LandlockPerm::MakeSym => access = access | AccessFs::MakeSym,
                LandlockPerm::Refer => access = access | AccessFs::Refer,
                LandlockPerm::Truncate => access = access | AccessFs::Truncate,
                LandlockPerm::IoctlDev => access = access | AccessFs::IoctlDev,
            }
        }
        ruleset = ruleset.add_rules(path_beneath_rules([&path], access))?;
    }

    Ok(Some(ruleset))
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_is_available_returns_bool() {
        let _available = is_available();
    }

    #[test]
    fn test_abi_version_consistent_with_available() {
        let available = is_available();
        let version = get_abi_version();
        if available {
            assert!(
                version.is_some(),
                "Landlock available => version must be Some"
            );
            let v = version.unwrap();
            assert!(v >= 1, "ABI version must be >= 1, got {v}");
        } else {
            assert!(
                version.is_none(),
                "Landlock unavailable => version must be None"
            );
        }
    }

    #[test]
    fn test_build_ruleset_empty_rules_returns_none() {
        let result = build_ruleset(&[], Path::new("/"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_build_ruleset_read_only_returns_ruleset() {
        let rules = vec![LandlockRule {
            path: "/".into(),
            perms: vec![
                LandlockPerm::Execute,
                LandlockPerm::ReadFile,
                LandlockPerm::ReadDir,
            ],
        }];
        let result = build_ruleset(&rules, Path::new("/"));
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
    fn test_build_ruleset_with_rules_returns_ruleset() {
        let rules = vec![LandlockRule {
            path: "/tmp".into(),
            perms: vec![
                LandlockPerm::Execute,
                LandlockPerm::ReadFile,
                LandlockPerm::ReadDir,
                LandlockPerm::WriteFile,
                LandlockPerm::RemoveDir,
                LandlockPerm::RemoveFile,
                LandlockPerm::MakeDir,
                LandlockPerm::MakeReg,
                LandlockPerm::MakeSym,
                LandlockPerm::Truncate,
            ],
        }];
        let result = build_ruleset(&rules, Path::new("/tmp"));
        assert!(
            result.is_ok(),
            "build should succeed even without Landlock: {:?}",
            result.err()
        );
        let ruleset = result.unwrap();
        assert!(
            ruleset.is_some(),
            "rules should produce a ruleset (not None)"
        );
    }

    #[test]
    fn test_build_ruleset_multiple_rules() {
        let rw_perms = vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
            LandlockPerm::WriteFile,
            LandlockPerm::RemoveDir,
            LandlockPerm::RemoveFile,
            LandlockPerm::MakeDir,
            LandlockPerm::MakeReg,
            LandlockPerm::MakeSym,
            LandlockPerm::Truncate,
        ];
        let ro_perms = vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
        ];
        let rules = vec![
            LandlockRule {
                path: "/tmp".into(),
                perms: rw_perms,
            },
            LandlockRule {
                path: "/usr".into(),
                perms: ro_perms.clone(),
            },
            LandlockRule {
                path: "/etc".into(),
                perms: ro_perms,
            },
        ];
        let result = build_ruleset(&rules, Path::new("/tmp"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_build_ruleset_non_existent_paths_skipped() {
        let ro_perms = vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
        ];
        let rw_perms = vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
            LandlockPerm::WriteFile,
            LandlockPerm::RemoveDir,
            LandlockPerm::RemoveFile,
            LandlockPerm::MakeDir,
            LandlockPerm::MakeReg,
            LandlockPerm::MakeSym,
            LandlockPerm::Truncate,
        ];
        let rules = vec![
            LandlockRule {
                path: "/this/path/should/not/exist/abc123xyz".into(),
                perms: ro_perms,
            },
            LandlockRule {
                path: "/tmp".into(),
                perms: rw_perms,
            },
        ];
        let result = build_ruleset(&rules, Path::new("/tmp"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_dedup_paths() {
        let rw_perms = vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
            LandlockPerm::WriteFile,
            LandlockPerm::RemoveDir,
            LandlockPerm::RemoveFile,
            LandlockPerm::MakeDir,
            LandlockPerm::MakeReg,
            LandlockPerm::MakeSym,
            LandlockPerm::Truncate,
        ];
        let rules = vec![
            LandlockRule {
                path: "/tmp".into(),
                perms: rw_perms.clone(),
            },
            LandlockRule {
                path: "/tmp".into(),
                perms: rw_perms,
            },
        ];
        let result = build_ruleset(&rules, Path::new("/tmp"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_build_ruleset_for_missing_cwd() {
        let rules = vec![LandlockRule {
            path: "/tmp".into(),
            perms: vec![
                LandlockPerm::Execute,
                LandlockPerm::ReadFile,
                LandlockPerm::ReadDir,
                LandlockPerm::WriteFile,
                LandlockPerm::RemoveDir,
                LandlockPerm::RemoveFile,
                LandlockPerm::MakeDir,
                LandlockPerm::MakeReg,
                LandlockPerm::MakeSym,
                LandlockPerm::Truncate,
            ],
        }];
        let result = build_ruleset(&rules, Path::new("/nonexistent_cwd_xyz"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_get_effective_abi_never_unsupported() {
        let abi = get_effective_abi();
        assert_ne!(abi, ABI::Unsupported);
    }
}
