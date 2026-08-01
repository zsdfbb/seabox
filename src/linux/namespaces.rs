//! Linux 命名空间（namespace）操作工具。
//!
//! 提供异步信号安全的函数，用于在 `pre_exec` 闭包中设置命名空间隔离，
//! 以及通过 `fork()` + `unshare()` 探测内核命名空间功能可用性。
//!
//! # 异步信号安全
//!
//! [`write_ns_file`]、[`setup_user_ns`]、[`set_hostname`] 以及内部使用的
//! [`fork_and_try_unshare`] 仅调用 `libc` 的 async-signal-safe 函数
//!（`open`、`write`、`close`、`fork`、`unshare`、`waitpid`、`_exit` 等），
//! **不进行堆分配**，因此可在 `fork()` 后的 `pre_exec` 闭包中使用。

use std::io;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// unshare_flags
// ---------------------------------------------------------------------------

/// 根据 6 个命名空间类型的启用状态，计算 `unshare(2)` 的 flags 位掩码。
///
/// 返回的 `i32` 可直接传给 `libc::unshare()`。
pub fn unshare_flags(user: bool, ipc: bool, pid: bool, net: bool, uts: bool, cgroup: bool) -> i32 {
    let mut flags: i32 = 0;
    if user {
        flags |= libc::CLONE_NEWUSER;
    }
    if ipc {
        flags |= libc::CLONE_NEWIPC;
    }
    if pid {
        flags |= libc::CLONE_NEWPID;
    }
    if net {
        flags |= libc::CLONE_NEWNET;
    }
    if uts {
        flags |= libc::CLONE_NEWUTS;
    }
    if cgroup {
        flags |= libc::CLONE_NEWCGROUP;
    }
    flags
}

// ---------------------------------------------------------------------------
// 异步信号安全的低层级文件写入
// ---------------------------------------------------------------------------

/// 以异步信号安全的方式将 `content` 写入 `path` 指定的文件。
///
/// # 异步信号安全
///
/// 只使用 `libc::open` / `libc::write` / `libc::close`，无堆分配。
///
/// # 参数
///
/// * `path` — 要写入的文件的路径，**必须以 `\0` 结尾**（如 `b"/proc/self/uid_map\0"`）
///   因为 `libc::open` 需要 C 字符串。
/// * `content` — 要写入的内容（不需要 NUL 结尾）。
///
/// # Safety
///
/// `path` 必须以 NUL 结尾，且指向可读内存。调用者必须确保操作
/// 在当前上下文中是安全的（如在 `pre_exec` 闭包中）。
pub unsafe fn write_ns_file(path: &[u8], content: &[u8]) -> io::Result<()> {
    // SAFETY：调用者保证 path 以 \0 结尾且指向有效内存。
    let fd = libc::open(
        path.as_ptr() as *const libc::c_char,
        libc::O_WRONLY | libc::O_CLOEXEC,
    );
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // 写入所有字节。write(2) 可能部分写入，需循环重试。
    let mut written = 0usize;
    while written < content.len() {
        // SAFETY：content 在调用者生命周期内有效；fd 是我们刚打开的合法 fd。
        let n = libc::write(
            fd,
            content[written..].as_ptr() as *const libc::c_void,
            content.len() - written,
        );
        if n < 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }
        written += n as usize;
    }

    libc::close(fd);
    Ok(())
}

// ---------------------------------------------------------------------------
// 用户命名空间设置（pre_exec）
// ---------------------------------------------------------------------------

/// 在 `CLONE_NEWUSER` 之后设置 UID/GID 映射。
///
/// 写入顺序：
/// 1. `/proc/self/uid_map` — 传入的 `uid_map` 内容
/// 2. `/proc/self/setgroups` — 写入 `b"deny"`（忽略 `ENOENT` 错误，
///    因为内核 < 3.19 上该文件不存在）
/// 3. `/proc/self/gid_map` — 传入的 `gid_map` 内容
///
/// # 异步信号安全
///
/// 所有写入只调用 `libc::open` / `libc::write` / `libc::close`，无堆分配。
///
/// # Safety
///
/// 必须在 `unshare(CLONE_NEWUSER)` **之后**、`execve()` **之前**调用。
/// 两个映射参数都不需要以 `\0` 结尾（内部会自动传长度给 `write`），
/// 但文件路径常量是 NUL 结尾的。
pub unsafe fn setup_user_ns(uid_map: &[u8], gid_map: &[u8]) -> io::Result<()> {
    // 1. 写 uid_map
    write_ns_file(b"/proc/self/uid_map\0", uid_map)?;

    // 2. 尝试写 setgroups（"deny"），忽略 ENOENT（内核 < 3.19）
    // SAFETY：path 以 \0 结尾；write_ns_file 返回 ENOENT 时我们吞掉。
    let setgroups_result = write_ns_file(b"/proc/self/setgroups\0", b"deny");
    if let Err(ref e) = setgroups_result {
        if e.kind() != io::ErrorKind::NotFound {
            return setgroups_result;
        }
    }

    // 3. 写 gid_map
    write_ns_file(b"/proc/self/gid_map\0", gid_map)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// 设置主机名（异步信号安全）
// ---------------------------------------------------------------------------

/// 设置 UTS 命名空间中的主机名。
///
/// 用 `libc::syscall(SYS_sethostname, name.as_ptr(), name.len())` 直接
/// 调用内核，不依赖 libc 包装函数，确保异步信号安全。
///
/// # Safety
///
/// 必须在 `unshare(CLONE_NEWUTS)` **之后**、`execve()` **之前**调用。
pub unsafe fn set_hostname(name: &[u8]) -> io::Result<()> {
    // SAFETY：SYS_sethostname 在 libc 中各 Linux 架构均有定义。
    // name.as_ptr() 在 `&[u8]` 生命周期内有效。
    let ret = libc::syscall(
        libc::SYS_sethostname,
        name.as_ptr() as *const libc::c_char,
        name.len(),
    );
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 命名空间可用性探测（fork + unshare）
// ---------------------------------------------------------------------------

/// 内部辅助：`fork()` 子进程尝试 `unshare(flags)`，父进程检查状态。
///
/// 子进程在成功时 `_exit(0)`，失败时 `_exit(1)`。
/// 父进程等待子进程退出后返回 `true`（退出码 0）或 `false`（其他）。
///
/// 本函数**不进行堆分配**（`format!` / `Vec` / 闭包捕获），仅调用
/// async-signal-safe 的 libc 函数。
fn fork_and_try_unshare(flags: i32) -> bool {
    // SAFETY：fork(2) 是 async-signal-safe 的。我们在子进程中只调
    // 用 async-signal-safe 的 unshare/_exit，以及父进程调用的 waitpid。
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // fork 失败——不能确定可用性，保守返回 false。
        return false;
    }

    if pid == 0 {
        // ── 子进程 ──
        // SAFETY：unshare(2) 是 async-signal-safe 的；成功时 _exit(0)，
        // 失败时 _exit(1)。不进行任何堆操作。
        let ret = unsafe { libc::unshare(flags) };
        let exit_code = if ret == 0 { 0 } else { 1 };
        // SAFETY：_exit(2) 是 async-signal-safe 的，不会运行 atexit 钩子。
        unsafe { libc::_exit(exit_code) };
    }

    // ── 父进程 ──
    // SAFETY：waitpid 等待子进程退出。status 由 waitpid 内核写入。
    let mut status: libc::c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited < 0 {
        return false;
    }

    // 检查子进程是否正常退出且退出码为 0。
    // WIFEXITED 和 WEXITSTATUS 在 libc 中是 const fn，无需 unsafe。
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

/// 检查当前内核是否支持 User 命名空间（`CLONE_NEWUSER`）。
///
/// 结果由 `OnceLock` 缓存，仅首次调用时执行 `fork()` + `unshare()`。
pub fn is_user_namespace_available() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| fork_and_try_unshare(libc::CLONE_NEWUSER))
}

/// 检查当前内核是否支持 IPC 命名空间（`CLONE_NEWIPC`）。
///
/// 结果由 `OnceLock` 缓存。
pub fn is_ipc_namespace_available() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| fork_and_try_unshare(libc::CLONE_NEWIPC))
}

/// 检查当前内核是否支持 PID 命名空间（`CLONE_NEWPID`）。
///
/// 结果由 `OnceLock` 缓存。
pub fn is_pid_namespace_available() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| fork_and_try_unshare(libc::CLONE_NEWPID))
}

/// 检查当前内核是否支持网络命名空间（`CLONE_NEWNET`）。
///
/// 非特权进程无法直接创建 netns（需要 CAP_SYS_ADMIN），但可先进入
/// user namespace 获得该命名空间内的全部 capabilities 再创建（rootless
/// 容器原理）。因此探测同时覆盖两条路径。
///
/// 结果由 `OnceLock` 缓存。
pub fn is_net_namespace_available() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(fork_and_try_net)
}

/// 内部辅助：`fork()` 子进程尝试创建网络命名空间。
///
/// 先直接 `unshare(CLONE_NEWNET)`（root 或已有 CAP_SYS_ADMIN 时成功）；
/// 失败则退化为 `unshare(CLONE_NEWUSER)` → `unshare(CLONE_NEWNET)`
/// （无特权 userns 路径，与 child_setup 的实际 unshare 顺序一致）。
///
/// 子进程全程仅调用 async-signal-safe 的 libc 函数，不做堆操作。
fn fork_and_try_net() -> bool {
    // SAFETY：fork(2) 是 async-signal-safe 的。子进程只调用
    // async-signal-safe 的 unshare/_exit；父进程调用 waitpid。
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // fork 失败——不能确定可用性，保守返回 false。
        return false;
    }

    if pid == 0 {
        // ── 子进程 ──
        // SAFETY：unshare(2) / _exit(2) 均为 async-signal-safe。
        let exit_code = unsafe {
            // `||` 短路：直接 unshare 成功则跳过 userns 路径；失败才退化尝试。
            if libc::unshare(libc::CLONE_NEWNET) == 0
                || (libc::unshare(libc::CLONE_NEWUSER) == 0
                    && libc::unshare(libc::CLONE_NEWNET) == 0)
            {
                0
            } else {
                1
            }
        };
        unsafe { libc::_exit(exit_code) };
    }

    // ── 父进程 ──
    // SAFETY：waitpid 等待子进程退出。status 由 waitpid 内核写入。
    let mut status: libc::c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited < 0 {
        return false;
    }
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

/// 检查当前内核是否支持 UTS 命名空间（`CLONE_NEWUTS`）。
///
/// 结果由 `OnceLock` 缓存。
pub fn is_uts_namespace_available() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| fork_and_try_unshare(libc::CLONE_NEWUTS))
}

/// 检查当前内核是否支持 Cgroup 命名空间（`CLONE_NEWCGROUP`）。
///
/// 结果由 `OnceLock` 缓存。
pub fn is_cgroup_namespace_available() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| fork_and_try_unshare(libc::CLONE_NEWCGROUP))
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 全开：所有 6 个命名空间位都应置位。
    #[test]
    fn test_unshare_flags_all() {
        let flags = unshare_flags(true, true, true, true, true, true);
        assert!(
            flags & libc::CLONE_NEWUSER != 0,
            "CLONE_NEWUSER must be set"
        );
        assert!(flags & libc::CLONE_NEWIPC != 0, "CLONE_NEWIPC must be set");
        assert!(flags & libc::CLONE_NEWPID != 0, "CLONE_NEWPID must be set");
        assert!(flags & libc::CLONE_NEWNET != 0, "CLONE_NEWNET must be set");
        assert!(flags & libc::CLONE_NEWUTS != 0, "CLONE_NEWUTS must be set");
        assert!(
            flags & libc::CLONE_NEWCGROUP != 0,
            "CLONE_NEWCGROUP must be set"
        );
        // 确认没有多余位（仅这 6 个 type 的位）
        let all_known = libc::CLONE_NEWUSER
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWUTS
            | libc::CLONE_NEWCGROUP;
        assert_eq!(flags & !all_known, 0, "no unknown bits should be set");
    }

    /// 全关：flags 应为 0。
    #[test]
    fn test_unshare_flags_none() {
        let flags = unshare_flags(false, false, false, false, false, false);
        assert_eq!(flags, 0, "all flags false => 0");
    }

    /// 仅 user + net：只有那两个位置位。
    #[test]
    fn test_unshare_flags_partial() {
        let flags = unshare_flags(true, false, false, true, false, false);
        assert!(
            flags & libc::CLONE_NEWUSER != 0,
            "CLONE_NEWUSER must be set"
        );
        assert!(flags & libc::CLONE_NEWNET != 0, "CLONE_NEWNET must be set");
        assert_eq!(
            flags & libc::CLONE_NEWIPC,
            0,
            "CLONE_NEWIPC must NOT be set"
        );
        assert_eq!(
            flags & libc::CLONE_NEWPID,
            0,
            "CLONE_NEWPID must NOT be set"
        );
        assert_eq!(
            flags & libc::CLONE_NEWUTS,
            0,
            "CLONE_NEWUTS must NOT be set"
        );
        assert_eq!(
            flags & libc::CLONE_NEWCGROUP,
            0,
            "CLONE_NEWCGROUP must NOT be set"
        );
    }

    /// 探测函数调用不应 panic（不校验返回值，仅验证调用不崩溃）。
    #[test]
    fn test_probe_no_panic() {
        let _user = is_user_namespace_available();
        let _ipc = is_ipc_namespace_available();
        let _pid = is_pid_namespace_available();
        let _net = is_net_namespace_available();
        let _uts = is_uts_namespace_available();
        let _cgroup = is_cgroup_namespace_available();
        // 如果走到这里，说明没有 panic。
    }
}
