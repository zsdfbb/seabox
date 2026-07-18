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
    Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, path_beneath_rules, ABI,
};

use crate::FsPolicy;

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
/// # 策略 → Landlock 映射
///
/// | `FsPolicy`       | 处理的访问                            | 规则                                       |
/// |------------------|---------------------------------------|--------------------------------------------|
/// | `FullAccess`     | 不创建任何 Landlock 规则集            | —（返回 `None`）                           |
/// | `ReadOnly`       | `READ_FILE \| READ_DIR`               | 在 `/` 上授予读                            |
/// | `WorkspaceWrite` | `READ_FILE \| READ_DIR \| WRITE_FILE \| REMOVE_DIR \| REMOVE_FILE \| MAKE_DIR \| MAKE_REG \| MAKE_SYM \| TRUNCATE` | 在 `/` 上授予读 + 在 cwd、`/tmp`、`allow_write` 路径上授予写 |
///
/// # 路径解析
///
/// 所有路径在内部通过 [`PathFd`]（使用 `O_PATH`）打开。
/// **不存在**的路径会被**静默跳过**，沿用 CodeWhale 的惯例。
/// 这包括 `cwd` 与 `/tmp`（若它们在文件系统中不存在）。
///
/// `allow_write` 路径应由调用方预先展开和规范化
///（见 [`crate::config::expand_tilde`]）。
///
/// # 错误
///
/// 当 Landlock 访问权限本身的配置不一致（例如 handled-access 为空）、
/// 或在支持 Landlock 的内核上 ruleset 创建 syscall 失败时返回错误。
///
/// 在完全没有 Landlock 支持的内核上**不会**因此返回错误：
/// 使用 [`CompatLevel::BestEffort`] 时，builder 会返回一个 no-op
/// [`RulesetCreated`]，其 [`restrict_self`](RulesetCreated::restrict_self)
/// 会报告 [`RulesetStatus::NotEnforced`]。
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
        // FullAccess：完全不加 Landlock 限制
        // ------------------------------------------------------------------
        FsPolicy::FullAccess => Ok(None),

        // ------------------------------------------------------------------
        // ReadOnly：通过同时处理 read 与 write 访问权限并仅在规则中
        // 授予读权限来拒绝所有写入。
        //
        // 在 Landlock 中，只有 "handled" 集合中声明的访问权限才会被检查。
        // 如果 write 权限未被处理，内核会无条件允许所有写操作。通过处理
        // 完整的（read | write）掩码但只在规则中授予读访问，所有写尝试
        // 都会被拒绝（被处理但未被授予）。
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

            // 向 "/" 授予读访问。write 权限被处理但从未被授予，
            // 因此所有写都被拒绝。
            // path_beneath_rules 会静默跳过无法打开的路径
            //（实际系统中对 "/" 不会发生，但做了防御性处理）。
            let ruleset = ruleset
                .add_rules(path_beneath_rules([Path::new("/")], read_access))?;

            Ok(Some(ruleset))
        }

        // ------------------------------------------------------------------
        // WorkspaceWrite：在 "/" 上读 + 在 cwd、/tmp、allow_write 上写
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

            // --- 在 "/" 上加读规则 ---
            let ruleset = ruleset
                .add_rules(path_beneath_rules([Path::new("/")], read_access))?;

            // --- 收集可写路径 ---
            // path_beneath_rules 会静默跳过不存在的路径，因此我们
            // 仅收集候选，由辅助函数过滤。
            let mut writable_paths: Vec<PathBuf> =
                Vec::with_capacity(2 + allow_write.len());

            // 1. /tmp（标准临时目录）
            writable_paths.push(PathBuf::from("/tmp"));

            // 2. 当前工作目录
            writable_paths.push(cwd.to_path_buf());

            // 3. 外部传入的 allow_write 路径（已由调用方展开并规范化）。
            writable_paths.extend(allow_write.iter().cloned());

            // 去重 —— 同一路径可能来自多个来源
            //（例如 cwd == /tmp，或 allow_write 包含 /tmp 两次）。
            writable_paths.sort();
            writable_paths.dedup();

            // --- 写规则 ---
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
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_is_available_returns_bool() {
        // 应当始终返回 bool 而不 panic。
        let _available = is_available();
        // 不需要断言 —— 走到这里即说明未 panic。
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
        // 即便没有 Landlock 支持，build_ruleset 也应成功
        //（通过 BestEffort 返回一个 dummy RulesetCreated）。
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
        // 不存在的路径应被 path_beneath_rules 静默跳过。
        let allow = vec![
            PathBuf::from("/this/path/should/not/exist/abc123xyz"),
            PathBuf::from("/tmp"), // 存在
        ];
        let result = build_ruleset(&FsPolicy::WorkspaceWrite, &allow, Path::new("/tmp"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_dedup_writable_paths() {
        let allow = vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"), // 重复
        ];
        let result = build_ruleset(&FsPolicy::WorkspaceWrite, &allow, Path::new("/tmp"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_build_ruleset_for_missing_cwd() {
        // 不存在的 cwd 应被静默跳过。
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
        // 永远不能是 Unsupported（ABI::Unsupported == ABI::from(0)）。
        assert_ne!(abi, ABI::Unsupported);
    }
}