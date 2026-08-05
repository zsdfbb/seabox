//! fork 后 child 进程的初始化流程。
//!
//! 此模块只接受 raw pointer / i32 / bool 参数，避免在 fork 后的
//! 子进程中使用堆分配。
//!
//! # Safety
//!
//! 此模块中的全部函数只能在 `fork()` 后的子进程中调用。
//! 调用者必须保证所有指针参数在整个函数调用期间有效。

use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;

use super::mount::RawMountOp;
use super::namespaces;
use super::seccomp;

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// `SCM_RIGHTS`——传递文件描述符。
const SCM_RIGHTS: libc::c_int = 0x01;

/// 用作 "control ping" 的字节载荷（一个 magic byte）。
/// 子进程 sendmsg 时附带 listener fd，载荷是单字节 `0x42`。
const CTRL_PAYLOAD: [u8; 1] = [0x42];

/// `prctl` 选项：设置 no_new_privs（man:prctl(2) PR_SET_NO_NEW_PRIVS）。
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

// ---------------------------------------------------------------------------
// 辅助 POD 类型
// ---------------------------------------------------------------------------

/// 命名空间操作描述：一组 `unshare(2)` 调用。
#[repr(C)]
pub struct NsOp {
    /// `unshare(2)` 的 flag（如 `CLONE_NEWUSER`）。
    pub flag: i32,
    /// 是否为软性模式（0 = 严格；非 0 = 失败时静默跳过）。
    pub try_mode: i32,
}

/// 外部 BPF filter 描述。
#[repr(C)]
pub struct ExtFilterDesc {
    /// `sock_filter` 数组指针。
    pub data: *const seccomp::sock_filter,
    /// 数组中元素个数。
    pub len: usize,
}

// ---------------------------------------------------------------------------
// enter_child
// ---------------------------------------------------------------------------

/// fork 后子进程的完整初始化流程。
///
/// 依次执行：
/// 1. `unshare()` 创建常规 namespace（user/mnt/ipc/net/uts/cgroup）
/// 2. mount namespace 初始化（make_private + do_mounts）
/// 3. double-fork + reaper（PID namespace 需要）
/// 4. `chdir()`（工作目录）
/// 5. `prctl(PR_SET_NO_NEW_PRIVS)`
/// 6. uid/gid map 写入 `/proc/self/uid_map` 等（user ns 需要）
/// 7. `sethostname()`（UTS 需要）
/// 8. `landlock_restrict_self()`（Landlock 规则需要）
/// 9. capability 收窄（`capset` / bounding / ambient，仅 `--cap-*` 指定时）
/// 10. seccomp USER_NOTIF filter 安装 + `sendmsg(SCM_RIGHTS)`
/// 11. 外部 plain BPF filter 安装
/// 12. `execve()` 启动目标程序
///
/// # Safety
///
/// 调用者必须保证：
/// - 所有指针参数指向可读内存，且在整个函数调用期间有效
/// - 此函数只在 `fork()` 后的子进程中调用，子进程中无堆操作
/// - `ns_ops` / `ext_filters` 数组中的所有指针同样有效
/// - `uid_map` / `gid_map` 的内容格式符合 `/proc/self/*_map` 要求
/// - `hostname` 是合法的主机名字节序列（长度 <= 64）
/// - `mount_ops` 数组中的所有 `RawMountOp` 指针指向 fork 前预分配的 CString 存储
/// - `caps_requested` / `caps_flags` 是父进程 fork 前经 [`caps::resolve_caps`]
///   解析好的目标位图与原语 flags；`caps_flags != 0` 时会在 seccomp 安装前调用
///   零堆的 [`caps::apply_caps`] 收窄 capability
///
/// 此函数永远不返回：要么通过 `execve` 转为目标程序，要么 `_exit`。
#[allow(clippy::too_many_arguments)]
pub unsafe fn enter_child(
    exec_path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
    cwd: *const libc::c_char,
    ruleset_fd: i32,
    bpf_filter_ptr: *const seccomp::sock_filter,
    bpf_filter_len: usize,
    child_sock_fd: i32,
    parent_sock_fd: i32,
    ext_filters: *const ExtFilterDesc,
    ext_filters_len: usize,
    ns_ops: *const NsOp,
    ns_ops_len: usize,
    need_pid_reaper: bool,
    user_ns_active: bool,
    uid_map: *const u8,
    uid_map_len: usize,
    gid_map: *const u8,
    gid_map_len: usize,
    hostname: *const u8,
    hostname_len: usize,
    configure_lo: bool,
    mount_ops: *const RawMountOp,
    mount_ops_len: usize,
    do_private: bool,
    caps_requested: u64,
    caps_flags: u8,
) {
    // ── 第 1 步：创建常规 namespace（不含 PID）────────────────────
    let mut user_ns_active = user_ns_active;
    if ns_ops_len > 0 {
        // SAFETY: 调用方保证 ns_ops 有效且长度为 ns_ops_len。
        let ops = std::slice::from_raw_parts(ns_ops, ns_ops_len);
        for op in ops {
            let ret = libc::syscall(libc::SYS_unshare, op.flag as libc::c_long);
            if ret != 0 {
                if op.try_mode != 0 {
                    continue;
                }
                libc::_exit(1);
            }
            if (op.flag & libc::CLONE_NEWUSER) != 0 {
                user_ns_active = true;
            }
        }
    }

    // ── 第 2 步：mount namespace 初始化 ─────────────────────
    if do_private {
        super::mount::make_private();
    }
    if mount_ops_len > 0 {
        let r = super::mount::do_mounts(mount_ops, mount_ops_len);
        if r != 0 {
            libc::_exit(1);
        }
    }

    // ── 第 2 步：PID namespace（double-fork + reaper）─────────────
    if need_pid_reaper {
        let ret = libc::syscall(libc::SYS_unshare, libc::CLONE_NEWPID as libc::c_long);
        if ret != 0 {
            libc::_exit(1);
        }
        // 第一次 fork：当前进程 wait → _exit，子进程（PID 1）继续
        let pid2 = libc::fork();
        if pid2 < 0 {
            libc::_exit(1);
        }
        if pid2 > 0 {
            let mut status: i32 = 0;
            libc::waitpid(pid2, &mut status, 0);
            let exit_code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                1
            };
            libc::_exit(exit_code);
        }
        // ── PID 1（init）：第二次 fork ──
        let pid3 = libc::fork();
        if pid3 < 0 {
            libc::_exit(1);
        }
        if pid3 > 0 {
            // PID 1（reaper）：等所有子进程退出后转发退出码
            let exit_code = do_reaper(pid3);
            libc::_exit(exit_code);
        }
        // ── PID 2（业务进程）：继续后续 setup ──
    }

    // ── 第 3 步：chdir ──────────────────────────────────────────
    if libc::chdir(cwd) != 0 {
        libc::_exit(1);
    }

    // ── 第 4 步：prctl(PR_SET_NO_NEW_PRIVS) ────────────────────
    if libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        libc::_exit(1);
    }

    // ── 第 5 步：uid/gid map ──────────────────────────────────
    if user_ns_active && uid_map_len > 0 && gid_map_len > 0 {
        // SAFETY: 调用方保证 uid_map / gid_map 有效且长度正确。
        let uid_slice = std::slice::from_raw_parts(uid_map, uid_map_len);
        let gid_slice = std::slice::from_raw_parts(gid_map, gid_map_len);
        // SAFETY: write_ns_file 的 path 常量以 NUL 结尾，在 child 中安全调用。
        namespaces::write_ns_file(b"/proc/self/uid_map\0", uid_slice).ok();
        let _ = namespaces::write_ns_file(b"/proc/self/setgroups\0", b"deny");
        namespaces::write_ns_file(b"/proc/self/gid_map\0", gid_slice).ok();
    }

    // ── 第 6 步：loopback 配置（netns 中 lo UP + 127.0.0.1/8）───
    if configure_lo {
        super::net::configure_loopback();
    }

    // ── 第 7 步：sethostname ──────────────────────────────────
    if hostname_len > 0 {
        // SAFETY: 调用方保证 hostname 有效且长度正确。
        let host_slice = std::slice::from_raw_parts(hostname, hostname_len);
        namespaces::set_hostname(host_slice).ok();
    }

    // ── 第 7 步：landlock_restrict_self ──────────────────────
    if ruleset_fd >= 0 {
        // SAFETY: man:landlock_restrict_self(2)；ruleset_fd 是调用方传来的
        // 有效 fd，flags=0 是唯一合法值。
        let ret = libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0);
        if ret != 0 {
            libc::_exit(1);
        }
        libc::close(ruleset_fd);
    }

    // ── 第 8 步：capability 收窄（capset / bounding / ambient）──
    if caps_flags != 0 {
        // SAFETY: 调用方保证 caps_requested / caps_flags 是 resolve_caps 的
        // 合法输出；apply_caps 零堆、async-signal-safe，失败以 _exit(1) 收场。
        super::caps::apply_caps(caps_requested, caps_flags);
    }

    // ── 第 9 步：seccomp USER_NOTIF filter ──────────────────
    if bpf_filter_len > 0 {
        // SAFETY: 调用方保证 bpf_filter_ptr 有效且长度为 bpf_filter_len。
        let filter = std::slice::from_raw_parts(bpf_filter_ptr, bpf_filter_len);
        let listener_fd = match seccomp::install_user_notif_filter(filter) {
            Ok(fd) => fd,
            Err(_) => libc::_exit(1),
        };
        // sendmsg SCM_RIGHTS：把 listener fd 发给父进程
        if send_fd(child_sock_fd, listener_fd).is_err() {
            libc::close(listener_fd);
            libc::close(child_sock_fd);
            libc::_exit(1);
        }
        libc::close(child_sock_fd);
        if parent_sock_fd >= 0 {
            libc::close(parent_sock_fd);
        }
    }

    // ── 第 10 步：外部 plain BPF filter ─────────────────────
    if ext_filters_len > 0 {
        // SAFETY: 调用方保证 ext_filters 有效且长度为 ext_filters_len，
        // 且每个 desc.data 指向一个长度 >= desc.len 的 sock_filter 数组。
        let descs = std::slice::from_raw_parts(ext_filters, ext_filters_len);
        for desc in descs {
            if desc.data.is_null() || desc.len == 0 {
                continue;
            }
            // SAFETY: desc.data 指向一个长度为 desc.len 的 sock_filter 数组。
            let filter = std::slice::from_raw_parts(desc.data, desc.len);
            if seccomp::install_plain_filter(filter).is_err() {
                libc::_exit(1);
            }
        }
    }

    // ── 第 11 步：execve ─────────────────────────────────────
    // SAFETY: exec_path、argv、envp 由调用方保证有效且格式正确。
    // man:execve(2)
    libc::execve(exec_path, argv, envp);
    // execve 仅失败时返回
    libc::_exit(127);
}

// ---------------------------------------------------------------------------
// 内部辅助函数
// ---------------------------------------------------------------------------

/// PID namespace 的 init 进程（reaper）。
///
/// 循环 `waitpid(-1)` 收割所有子进程和托孤进程。
/// 当业务进程（`business_pid`）退出时记录退出码，继续收割。
/// 当 `waitpid` 返回 ECHILD（无子进程）时退出，返回业务进程退出码。
///
/// 参照 bwrap `do_init()` 的实现。
///
/// # Safety
///
/// 此函数只在 fork 后的 PID 1 单线程子进程中调用。
fn do_reaper(business_pid: libc::pid_t) -> i32 {
    // SAFETY: 全部 libc 调用都是 async-signal-safe 的 waitpid/macro。
    unsafe {
        let mut exit_code = 1;
        loop {
            let mut status: i32 = 0;
            let wpid = libc::waitpid(-1, &mut status, 0);
            if wpid == business_pid {
                exit_code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else if libc::WIFSIGNALED(status) {
                    128 + libc::WTERMSIG(status)
                } else {
                    1
                };
            } else if wpid < 0 {
                break;
            }
        }
        exit_code
    }
}

/// 把一个 fd 通过 `sendmsg(SCM_RIGHTS)` 经 unix socket 发出去。
///
/// 在 fork 后 exec 前的子进程中调用。**不进行堆分配**，只操作栈上
/// POD（msghdr / iovec / cmsghdr / fd 数组）。
///
/// 载荷是一个 magic byte `0x42`，让父端能确认消息完整收到。
///
/// # Safety
///
/// `socket_fd` 必须是一个有效的 Unix socket fd，`fd_to_send` 必须
/// 是一个有效的、要在对端打开的 fd。
fn send_fd(socket_fd: RawFd, fd_to_send: RawFd) -> Result<(), ()> {
    // iovec 描述载荷（1 字节 magic）。
    let payload = CTRL_PAYLOAD;
    let iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len: payload.len(),
    };

    // cmsg 缓冲区：容纳一个 cmsghdr + 一个 i32 fd。
    // CMSG_SPACE(sizeof(i32)) = 24 字节（在 64 位 Linux 上）。
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as libc::c_uint) } as usize;
    let mut cmsg_buf = [MaybeUninit::<u8>::uninit(); 64];
    if cmsg_space > cmsg_buf.len() {
        return Err(());
    }

    let msghdr = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &iov as *const _ as *mut _,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr() as *mut _,
        msg_controllen: cmsg_space as _,
        msg_flags: 0,
    };

    // 把 cmsghdr 写入缓冲区头部，data 区域写 fd。
    // SAFETY:
    // - `cmsg_buf` 至少 `CMSG_SPACE(sizeof(fd))` 字节。
    // - `CMSG_FIRSTHDR` 返回的指针位于该缓冲区内，对齐正确。
    unsafe {
        let cmsg_ptr = libc::CMSG_FIRSTHDR(&msghdr);
        if cmsg_ptr.is_null() {
            return Err(());
        }
        (*cmsg_ptr).cmsg_level = libc::SOL_SOCKET;
        (*cmsg_ptr).cmsg_type = SCM_RIGHTS;
        (*cmsg_ptr).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as libc::c_uint) as _;

        // 把 fd 写到 cmsg data 区域。
        let data_ptr = libc::CMSG_DATA(cmsg_ptr) as *mut RawFd;
        std::ptr::write(data_ptr, fd_to_send);
    }

    // SAFETY: msghdr 完整初始化，iovec 与 cmsg 都在缓冲区有效期内。
    let sent = unsafe { libc::sendmsg(socket_fd, &msghdr, 0) };
    if sent < 0 {
        return Err(());
    }
    Ok(())
}
