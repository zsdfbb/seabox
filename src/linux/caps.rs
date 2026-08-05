//! Linux capability 权限管理。
//!
//! 提供三条 raw syscall 原语（[`apply_caps`]：`capset(V3)` +
//! `PR_CAPBSET_DROP` + `PR_CAP_AMBIENT_RAISE`）的零堆、async-signal-safe
//! 封装（fork 后子进程专用，符合 ADR 0003），以及父进程侧的按需解析
//! （[`resolve_caps`]）与系统状态读取（[`current_effective`] /
//! [`read_bounding_set`]）。
//!
//! 设计依据：`docs/adr/0004-capability-management.md` D3/D5 +
//! `docs/design-plans/cap-management.md`。实测锚点 F2/F3 决定 bounding 与
//! ambient 的触发条件：F2（非 root capset 清零后不可重提 → 非 root 不需要
//! bounding 收缩）；F3（`PR_CAP_AMBIENT_RAISE` 需 cap 同时在 permitted 与
//! inheritable → capset 必须先把 inheritable 设为 requested）。

use crate::config::{CapOp, CapabilityConfig};

// ---------------------------------------------------------------------------
// prctl / capability 常量
// ---------------------------------------------------------------------------

/// `prctl(PR_CAPBSET_DROP, cap)` —— 从 bounding set 移除一个 capability。
const PR_CAPBSET_DROP: libc::c_int = 24; // include/uapi/linux/prctl.h

/// `prctl(PR_CAP_AMBIENT, ...)` —— ambient capability 操作入口。
const PR_CAP_AMBIENT: libc::c_int = 47; // include/uapi/linux/prctl.h

/// `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap)` —— 把 cap 抬进 ambient set。
const PR_CAP_AMBIENT_RAISE: libc::c_int = 2; // include/uapi/linux/prctl.h

/// capget/capset 的 V3 协议版本 magic 常量（`_LINUX_CAPABILITY_VERSION_3`）。
const _LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522; // include/uapi/linux/capability.h

/// `CAP_SETPCAP` 的 capability 编号。
const CAP_SETPCAP_NR: u32 = 8; // include/uapi/linux/capability.h

/// 最高 capability 编号（`CHECKPOINT_RESTORE`，Linux 5.9 引入）。
const CAP_LAST_CAP: u32 = 40; // include/uapi/linux/capability.h

// ---------------------------------------------------------------------------
// V3 结构体（man:capset(2)）
// ---------------------------------------------------------------------------

/// `capget`/`capset` 的 V3 头部（`struct __user_cap_header_struct`）。
///
/// 布局与内核 `include/uapi/linux/capability.h` 一致，POD、`#[repr(C)]`。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CapHeader {
    /// 协议版本（必须是 [`_LINUX_CAPABILITY_VERSION_3`]）。
    pub version: u32,
    /// 目标进程 pid；0 表示当前进程。
    pub pid: i32,
}

/// `capget`/`capset` 的单字 capability 数据（`struct __user_cap_data_struct`）。
///
/// V3 协议需要 2 个该结构体（lo/hi 双字），分别承载 bit 0-31 与 bit 32-63。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CapData {
    /// effective set。
    pub effective: u32,
    /// permitted set。
    pub permitted: u32,
    /// inheritable set。
    pub inheritable: u32,
}

// ---------------------------------------------------------------------------
// flags 常量
// ---------------------------------------------------------------------------

/// 需要执行 `capset(V3)` 收窄 effective/permitted/inheritable。
pub const CAP_F_NEED_CAPSET: u8 = 1;

/// 需要执行 `PR_CAPBSET_DROP` 收缩 bounding set（仅 host-root 无 userns 场景）。
pub const CAP_F_NEED_BOUNDING: u8 = 2;

/// 需要执行 `PR_CAP_AMBIENT_RAISE` 在 exec 前抬 ambient cap（非 root 场景）。
pub const CAP_F_NEED_AMBIENT: u8 = 4;

// ---------------------------------------------------------------------------
// apply_caps —— fork 后子进程，零堆
// ---------------------------------------------------------------------------

/// 在 fork 后、exec 前按 `requested` 应用 capability。
///
/// 三条 raw syscall 原语按序执行（bwrap 语义），失败时对非 best-effort
/// 错误直接 `_exit(1)`：
///
/// 1. **bounding**（`CAP_F_NEED_BOUNDING`）：先 `capset` 临时保留
///    `CAP_SETPCAP`，再对不在 `requested` 里的 cap 逐个 `PR_CAPBSET_DROP`
///    （EINVAL/EPERM 忽略）。
/// 2. **capset**（`CAP_F_NEED_CAPSET`）：`capset(V3)` 把 effective/permitted/
///    inheritable 全部设为 `requested`（失败非 EPERM → `_exit(1)`）。
/// 3. **ambient**（`CAP_F_NEED_AMBIENT`）：对每个 `requested` 中的 cap
///    `PR_CAP_AMBIENT_RAISE`（EPERM 忽略；F3 要求 cap 同时在 permitted 与
///    inheritable，capset 阶段已满足）。
///
/// # Safety
///
/// 只能在 `fork()` 之后的子进程、`execve()` 之前调用。零堆、async-signal-safe
/// （ADR 0003）：不执行任何堆分配，只用栈上 POD 与纯 syscall。
pub unsafe fn apply_caps(requested: u64, flags: u8) {
    if flags & CAP_F_NEED_BOUNDING != 0 {
        // 阶段 1：临时保留 SETPCAP，以便能对 bounding set 执行 PR_CAPBSET_DROP。
        // 失败（如 userns 内 EPERM / 非 root 无 CAP_SETPCAP）视为 best-effort，
        // 继续后续 drop——每个 drop 自身会再次被内核拒绝并忽略。
        let _ = capset_all(requested | (1u64 << CAP_SETPCAP_NR));
        // 阶段 2：对不在 requested 里的 cap 逐个从 bounding set drop。
        // 忽略 EINVAL/EPERM（bwrap 语义）。
        for cap in 0u64..=CAP_LAST_CAP as u64 {
            if (requested >> cap) & 1 == 0 {
                // SAFETY: man:prctl(2) PR_CAPBSET_DROP；cap 是合法 capability 编号。
                libc::prctl(PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
            }
        }
    }

    if flags & CAP_F_NEED_CAPSET != 0 {
        // 最终收窄：只有 EPERM 是 best-effort（如 setuid 后无权改 caps），
        // 其余错误（EINVAL/EFAULT 等）为硬失败。
        if let Err(errno) = capset_all(requested) {
            if errno != libc::EPERM {
                libc::_exit(1);
            }
        }
    }

    if flags & CAP_F_NEED_AMBIENT != 0 {
        for cap in 0u64..=CAP_LAST_CAP as u64 {
            if (requested >> cap) & 1 != 0 {
                // SAFETY: man:prctl(2) PR_CAP_AMBIENT；
                // cap 已在 permitted 且 inheritable（capset 阶段置位），EPERM 忽略。
                libc::prctl(
                    PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_RAISE as libc::c_ulong,
                    cap as libc::c_ulong,
                    0,
                    0,
                );
            }
        }
    }
}

/// 通过 `capset(V3)` 把 effective/permitted/inheritable 三个 set 全部设为
/// `mask`（lo/hi 双字各写一份）。
///
/// 返回 `Err(errno)`（内核返回非 0 时）。调用方负责决定吞掉还是硬失败。
///
/// # Safety
///
/// 调用 `libc::syscall(SYS_capset, ...)`，是 unsafe 系统调用封装。`CapHeader`
/// 与 `CapData` 与内核 ABI 布局一致；`header.pid = 0` 表示作用于当前进程。
unsafe fn capset_all(mask: u64) -> Result<(), libc::c_int> {
    let header = CapHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let lo = mask as u32;
    let hi = (mask >> 32) as u32;
    let data = [
        CapData {
            effective: lo,
            permitted: lo,
            inheritable: lo,
        },
        CapData {
            effective: hi,
            permitted: hi,
            inheritable: hi,
        },
    ];
    // SAFETY: man:capset(2)；
    // header/data 是栈上 POD，与内核 V3 布局一致，data 长度 2 承载 lo/hi 双字。
    let ret = libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr());
    if ret != 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// resolve_caps —— 父进程，纯逻辑可单测
// ---------------------------------------------------------------------------

/// 按需解析结果：子进程 `apply_caps` 的完整输入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedCaps {
    /// 目标 capability 位图（41 位）。
    pub requested: u64,
    /// 需要执行的原语组合（[`CAP_F_NEED_CAPSET`] 等）。
    pub flags: u8,
}

/// 按需解析 capability 目标集与执行 flags（父进程、fork 前调用）。
///
/// 计算 `requested` 位图：起点为 `cfg.inherit_base` 时当前进程 effective caps、
/// 否则空集，然后按命令行顺序应用 `cfg.ops`。`natural` 是"什么都不做"时
/// 子进程在 `apply_caps` 时刻已有的 caps（userns creator / host root 都是全量；
/// 非 root 无 userns 是 0），据此与 D5 按需规则判定需要哪些原语。
///
/// # 参数
///
/// - `is_root`：宿主 euid == 0。
/// - `userns_active`：沙箱会进入 user namespace。
/// - `ns_root`：userns 内映射 uid == 0（即 `--uid 0`）。
pub fn resolve_caps(
    cfg: &CapabilityConfig,
    is_root: bool,
    userns_active: bool,
    ns_root: bool,
) -> ResolvedCaps {
    let full: u64 = (1u64 << (CAP_LAST_CAP + 1)) - 1; // 41 位全置
    let mut base: u64 = if cfg.inherit_base {
        current_effective()
    } else {
        0
    };
    for op in &cfg.ops {
        match op {
            CapOp::Add(c) => base |= 1u64 << c.as_u16(),
            CapOp::Drop(c) => base &= !(1u64 << c.as_u16()),
            CapOp::AddAll => base = full,
            CapOp::DropAll => base = 0,
        }
    }
    let requested = base;
    // natural = "什么都不做"时 child 在 apply 时刻已有的 caps
    //（userns creator / host root 都是全量；非 root 无 userns 是 0）
    let natural = if userns_active || is_root { full } else { 0 };

    let mut flags = 0u8;
    if requested != natural {
        flags |= CAP_F_NEED_CAPSET;
    }
    // ambient 只在 ns 内非 root 场景需要：非 root 跨 exec 靠 ambient 保留 cap。
    // 排除 host-root 无 userns：此时 euid=0，capset 后 effective 已全量，无需 ambient，
    // 也避免 --cap-inherit 空转 41 次 PR_CAP_AMBIENT_RAISE（Fix B）。
    // host-root + userns 仍需要：子进程在 ns 内可能映射为非 root（--uid <非0>），
    // 跨 exec 必须靠 ambient 保留。
    if requested != 0 && !ns_root && (!is_root || userns_active) {
        flags |= CAP_F_NEED_AMBIENT;
        // F3 前提：PR_CAP_AMBIENT_RAISE 需 cap 同时在 permitted 与 inheritable，
        // 而只有 capset 会填 inheritable。requested == natural 时（如非 root +
        // userns + `--cap-add ALL`）capset 原本不触发、inheritable=0 → ambient
        // 全 EPERM-ignored → exec 后零 cap。强制耦合：ambient 必然连带 capset。
        flags |= CAP_F_NEED_CAPSET;
    }
    // bounding 只对 host-root 无 userns 场景需要（ns 内无 init-ns CAP_SETPCAP，
    // drop 恒 EPERM），且只有确实有东西要 drop 时才设（D5 按需）。
    // bounding set 读取失败按 fail-closed 处理（bounding_needs_drop(None) == true）。
    if !userns_active
        && is_root
        && requested != full
        && bounding_needs_drop(requested, read_bounding_set())
    {
        flags |= CAP_F_NEED_BOUNDING;
    }

    ResolvedCaps { requested, flags }
}

// ---------------------------------------------------------------------------
// 父进程状态读取
// ---------------------------------------------------------------------------

/// 读取当前进程 effective capability 位图（`capget` V3，父进程用）。
///
/// 用于 `--cap-inherit` 时作为起点位图。失败时返回 0（安全降级为空集）。
pub fn current_effective() -> u64 {
    let header = CapHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: man:capget(2)；
    // header/data 与内核 ABI 布局一致，data 长度 2 对应 V3 双字格式。
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &header as *const CapHeader,
            data.as_mut_ptr(),
        )
    };
    if ret != 0 {
        return 0;
    }
    (u64::from(data[1].effective) << 32) | u64::from(data[0].effective)
}

/// 读取当前进程 bounding set 位图（解析 `/proc/self/status` 的 `CapBnd:` 行）。
///
/// 读取或十六进制解析失败时返回 `None`（fail-closed：调用方按"bounding 未知"
/// 处理，即默认需要 bounding 收缩，见 [`bounding_needs_drop`]）。
pub fn read_bounding_set() -> Option<u64> {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return None;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapBnd:") {
            return u64::from_str_radix(rest.trim(), 16).ok();
        }
    }
    None
}

/// 判定 bounding set 是否需要收缩（fail-closed）。
///
/// `bnd == None`（读取失败，bounding 未知）→ 返回 `true`（保守：宁可多 drop 一遍）；
/// 否则只在 bounding set 里存在不在 `requested` 中的 bit 时返回 `true`。
fn bounding_needs_drop(requested: u64, bnd: Option<u64>) -> bool {
    match bnd {
        None => true,
        Some(bnd) => (bnd & !requested) != 0,
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CapOp, Capability, CapabilityConfig};

    /// 41 位全置的 capability 位图（与 `resolve_caps` 内部一致）。
    fn full_mask() -> u64 {
        (1u64 << (CAP_LAST_CAP + 1)) - 1
    }

    /// 非 root + userns + 无 ops → requested=0，natural=full → 需要 capset 收零，
    /// 无 ambient（requested==0）、无 bounding（userns）。
    #[test]
    fn non_root_userns_no_ops() {
        let cfg = CapabilityConfig::default();
        let r = resolve_caps(&cfg, false, true, false);
        assert_eq!(r.requested, 0);
        assert_ne!(
            r.flags & CAP_F_NEED_CAPSET,
            0,
            "requested(0) != natural(full)"
        );
        assert_eq!(r.flags & CAP_F_NEED_AMBIENT, 0);
        assert_eq!(r.flags & CAP_F_NEED_BOUNDING, 0);
    }

    /// 非 root + userns + `--cap-add CHOWN` → requested=bit0，natural=full →
    /// 需要 capset + ambient（非 root 跨 exec 靠 ambient 保留）。
    #[test]
    fn non_root_userns_cap_add_chown() {
        let cfg = CapabilityConfig {
            ops: vec![CapOp::Add(Capability::CHOWN)],
            inherit_base: false,
        };
        let r = resolve_caps(&cfg, false, true, false);
        assert_eq!(r.requested, 1u64 << Capability::CHOWN.as_u16());
        assert_ne!(r.flags & CAP_F_NEED_CAPSET, 0);
        assert_ne!(r.flags & CAP_F_NEED_AMBIENT, 0);
        assert_eq!(r.flags & CAP_F_NEED_BOUNDING, 0);
    }

    /// host-root 无 userns 无 ops → requested=0，natural=full → 需要 capset；
    /// bounding 收缩遵循 fail-closed：读取失败 → 置位；有可 drop 的 bit → 置位。
    #[test]
    fn host_root_no_userns_default() {
        let cfg = CapabilityConfig::default();
        let r = resolve_caps(&cfg, true, false, false);
        assert_eq!(r.requested, 0);
        assert_ne!(r.flags & CAP_F_NEED_CAPSET, 0);
        assert_eq!(r.flags & CAP_F_NEED_AMBIENT, 0);
        match read_bounding_set() {
            // 读取失败 → 保守置位（fail-closed）。
            None => assert_ne!(r.flags & CAP_F_NEED_BOUNDING, 0),
            Some(bnd) if bnd != 0 => {
                assert_ne!(r.flags & CAP_F_NEED_BOUNDING, 0);
            }
            Some(_) => assert_eq!(r.flags & CAP_F_NEED_BOUNDING, 0),
        }
    }

    /// host-root + userns + `--uid <非0>`（ns 内非 root）→ 跨 exec 仍需 ambient 保留。
    #[test]
    fn host_root_userns_non_root_uid_needs_ambient() {
        let cfg = CapabilityConfig {
            ops: vec![CapOp::Add(Capability::CHOWN)],
            inherit_base: false,
        };
        // is_root=true, userns_active=true, ns_root=false
        let r = resolve_caps(&cfg, true, true, false);
        assert_ne!(r.flags & CAP_F_NEED_AMBIENT, 0);
    }

    /// bounding set 读取失败 → fail-closed：置 NEED_BOUNDING（保守收缩）。
    #[test]
    fn bounding_fail_closed_when_read_fails() {
        // None（读取失败）→ 保守 true。
        assert!(bounding_needs_drop(0, None));
        assert!(bounding_needs_drop(
            1u64 << Capability::CHOWN.as_u16(),
            None
        ));
        // Some 且 bounding 与 requested 无交集 → false。
        assert!(!bounding_needs_drop(0, Some(0)));
        assert!(!bounding_needs_drop(full_mask(), Some(0)));
        // Some 且 bounding 有可 drop 的 bit → true。
        assert!(bounding_needs_drop(0, Some(1)));
    }

    /// `--uid 0`（ns_root）+ `--cap-add ALL` → requested=full=natural →
    /// 无 capset，无 ambient（ns_root 跨 exec 自动保留 ns caps）。
    #[test]
    fn ns_root_cap_add_all_no_flags() {
        let cfg = CapabilityConfig {
            ops: vec![CapOp::AddAll],
            inherit_base: false,
        };
        let r = resolve_caps(&cfg, false, true, true);
        assert_eq!(r.requested, full_mask());
        assert_eq!(r.flags & CAP_F_NEED_CAPSET, 0, "requested == natural");
        assert_eq!(r.flags & CAP_F_NEED_AMBIENT, 0, "ns_root 无需 ambient");
        assert_eq!(r.flags & CAP_F_NEED_BOUNDING, 0);
    }

    /// Bug 2 回归：非 root + userns + `--cap-add ALL` → requested=full=natural，
    /// NEED_CAPSET 原本不置位，但 ambient 依赖 capset 填 inheritable（F3）——
    /// NEED_AMBIENT 必须强制连带 NEED_CAPSET，否则 exec 后丢光 caps。
    #[test]
    fn non_root_userns_cap_add_all_forces_capset() {
        let cfg = CapabilityConfig {
            ops: vec![CapOp::AddAll],
            inherit_base: false,
        };
        let r = resolve_caps(&cfg, false, true, false);
        assert_eq!(r.requested, full_mask());
        assert_ne!(r.flags & CAP_F_NEED_AMBIENT, 0);
        assert_ne!(
            r.flags & CAP_F_NEED_CAPSET,
            0,
            "ambient 依赖 capset 填 inheritable，必须强制连带"
        );
        assert_eq!(r.flags & CAP_F_NEED_BOUNDING, 0);
    }

    /// inherit_base=true → 起点位图 = 当前进程 effective caps。
    #[test]
    fn inherit_base_uses_current_effective() {
        let cfg = CapabilityConfig {
            ops: vec![],
            inherit_base: true,
        };
        let r = resolve_caps(&cfg, false, true, false);
        assert_eq!(r.requested, current_effective());
    }

    /// 调用不 panic（不校验具体值）。
    #[test]
    fn read_bounding_set_does_not_panic() {
        let _ = read_bounding_set();
    }

    /// 调用不 panic（不校验具体值）。
    #[test]
    fn current_effective_does_not_panic() {
        let _ = current_effective();
    }
}
