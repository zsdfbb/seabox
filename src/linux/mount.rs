//! Mount namespace 操作。
//!
//! 提供 fork 后子进程中执行 mount(2) 系列操作的基础设施：
//! - 将当前 mount ns 从宿主传播树中断开（`make_private`）
//! - 批量执行预计算的 mount 操作（`do_mounts`）
//! - 探测内核 mount namespace 可用性（`is_mount_namespace_available`）
//!
//! 此模块只接收 raw pointer / POD 类型，不进行堆分配。
//! 所有 [`RawMountOp`] 中的 raw pointer 指向 fork 前预分配的有效内存。

use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// mount(2) flags（从内核头文件翻译）
// ---------------------------------------------------------------------------
// 这些常量在 libc crate 中可能已定义（如 libc::MS_BIND），但为了在 child 中
// 不依赖 libc 常量解析（某些平台可能缺失），我们定义自己的副本。

/// `mount(2)` flag: 执行 bind mount。
pub const MS_BIND: libc::c_ulong = 4096; // 0x1000

/// `mount(2)` flag: 递归操作（常与 MS_BIND 或 MS_PRIVATE 组合）。
pub const MS_REC: libc::c_ulong = 16384; // 0x4000

/// `mount(2)` flag: 文件系统只读。
pub const MS_RDONLY: libc::c_ulong = 1;

/// `mount(2)` flag: 禁止 set-user-ID 和 set-group-ID。
pub const MS_NOSUID: libc::c_ulong = 2;

/// `mount(2)` flag: 禁止访问块设备。
pub const MS_NODEV: libc::c_ulong = 4;

/// `mount(2)` flag: 使挂载为私有（不接收也不传播 mount 事件）。
pub const MS_PRIVATE: libc::c_ulong = 1 << 18; // 0x40000

/// `mount(2)` flag: 使挂载为从属（接收宿主传播但不往外发）。
pub const MS_SLAVE: libc::c_ulong = 1 << 19; // 0x80000

/// `mount(2)` flag: 重新挂载已存在的挂载点。
pub const MS_REMOUNT: libc::c_ulong = 32;

// ---------------------------------------------------------------------------
// RawMountOp
// ---------------------------------------------------------------------------

/// 子进程可见的 mount 操作描述符（POD，repr(C)）。
///
/// 所有 raw pointer 指向 fork 前预分配的 CString 存储。
/// 子进程中零堆操作：只读指针，直接传给 libc::mount。
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RawMountOp {
    /// 源路径（对应 mount(2) 的 source 参数）。null 表示传 NULL。
    pub source: *const libc::c_char,
    /// 挂载目标路径。
    pub target: *const libc::c_char,
    /// 文件系统类型（对应 mount(2) 的 fstype 参数）。null 表示传 NULL。
    pub fstype: *const libc::c_char,
    /// mount(2) flags。
    pub flags: libc::c_ulong,
    /// mount data 字符串。null 表示传 NULL。
    pub data: *const libc::c_char,
}

// ---------------------------------------------------------------------------
// make_private
// ---------------------------------------------------------------------------

/// 将当前 mount ns 的 / 从宿主传播树中断开。
///
/// 先尝试 `MS_PRIVATE | MS_REC`，失败则降级为 `MS_SLAVE | MS_REC`。
/// 此函数应在 fork 后、unshare(CLONE_NEWNS) 之后、其他 mount 操作之前调用。
///
/// # Safety
///
/// 仅在 fork 后、初始 mount 阶段调用。
pub unsafe fn make_private() -> bool {
    // 先尝试 MS_PRIVATE|MS_REC
    let ret = libc::mount(
        std::ptr::null(),
        b"/\0" as *const _ as *const libc::c_char,
        std::ptr::null(),
        MS_PRIVATE | MS_REC,
        std::ptr::null(),
    );
    if ret == 0 {
        return true;
    }

    // 降级：MS_SLAVE|MS_REC（宿主 mount 事件仍可传播进来，但本 ns 的操作不出去）
    let ret2 = libc::mount(
        std::ptr::null(),
        b"/\0" as *const _ as *const libc::c_char,
        std::ptr::null(),
        MS_SLAVE | MS_REC,
        std::ptr::null(),
    );
    ret2 == 0
}

// ---------------------------------------------------------------------------
// do_mounts
// ---------------------------------------------------------------------------

/// 在子进程中执行 mount 操作。
///
/// 遍历 [`RawMountOp`] 数组，逐个调用 `libc::mount()`。
/// 返回 0 = 全部成功，非 0 = 1-based 失败序号（第几个 op 失败了）。
///
/// # Safety
///
/// - 仅在 fork 后的子进程中调用
/// - `ops` 必须指向 fork 前预分配的 `RawMountOp` 数组
/// - 所有指针必须在整个函数调用期间有效
pub unsafe fn do_mounts(ops: *const RawMountOp, count: usize) -> i32 {
    let slice = std::slice::from_raw_parts(ops, count);
    for (i, op) in slice.iter().enumerate() {
        let source = if op.source.is_null() {
            std::ptr::null()
        } else {
            op.source
        };
        let target = op.target;
        let fstype = if op.fstype.is_null() {
            std::ptr::null()
        } else {
            op.fstype
        };
        let data = if op.data.is_null() {
            std::ptr::null()
        } else {
            op.data as *const libc::c_void
        };

        let ret = libc::mount(source, target, fstype, op.flags, data);
        if ret != 0 {
            // 写 stderr
            let msg = b"[sandbox-runtime] mount #";
            libc::write(libc::STDERR_FILENO, msg.as_ptr() as *const _, msg.len());
            // 写失败序号（十进制，支持多位）
            let idx = (i + 1) as i32;
            write_decimal(idx);
            libc::write(libc::STDERR_FILENO, b"\n" as *const _ as *const _, 1);
            return (i + 1) as i32;
        }
    }
    0
}

// ---------------------------------------------------------------------------
// is_mount_namespace_available
// ---------------------------------------------------------------------------

/// 检查当前内核是否支持 mount namespace（`CLONE_NEWNS`）。
///
/// 使用 `fork` + `unshare` 模式（与 `namespaces.rs` 同理）。
/// 结果由 `OnceLock` 缓存，仅首次调用时执行 fork。
pub fn is_mount_namespace_available() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        // SAFETY: fork(2) 是 async-signal-safe 的。子进程只调 unshare 和 _exit。
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            // SAFETY: 子进程只调 unshare 和 _exit，不进行堆操作。
            let ret = unsafe { libc::unshare(libc::CLONE_NEWNS) };
            unsafe { libc::_exit(if ret == 0 { 0 } else { 1 }) };
        }
        // 父进程
        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    })
}

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

/// 将十进制整数写到 stderr（仅 async-signal-safe 的 libc::write）。
/// 支持 0 和正数。
unsafe fn write_decimal(mut val: i32) {
    if val == 0 {
        libc::write(libc::STDERR_FILENO, b"0" as *const _ as *const _, 1);
        return;
    }
    // 最大 i32 为 10 位数字 + 负号，栈缓冲区足够
    let mut buf = [0u8; 12];
    let mut pos = buf.len();
    while val > 0 {
        pos -= 1;
        buf[pos] = (val % 10) as u8 + b'0';
        val /= 10;
    }
    let len = buf.len() - pos;
    libc::write(libc::STDERR_FILENO, buf[pos..].as_ptr() as *const _, len);
}
