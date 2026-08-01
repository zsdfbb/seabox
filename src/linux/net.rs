//! NETLINK 网络配置。
//!
//! 在 netns 中通过 RTNETLINK 将 lo 设为 UP 并配置 127.0.0.1/8 地址。
//! 参照 bubblewrap `network.c` 的实现。
//!
//! 在 fork 后的子进程中调用，失败时不致命：写 stderr 警告后返回，
//! 调用方应继续 exec。

use std::mem;
use std::os::unix::io::RawFd;

// ---------------------------------------------------------------------------
// 内核常量（全部从 uapi 头文件翻译，man:rtnetlink(7)）
// ---------------------------------------------------------------------------

const AF_NETLINK: libc::c_int = 16; // linux/net.h
const NETLINK_ROUTE: libc::c_int = 0; // uapi/linux/netlink.h
const RTM_NEWADDR: u16 = 20; // uapi/linux/rtnetlink.h
const RTM_NEWLINK: u16 = 16;
const IFA_LOCAL: u16 = 2; // uapi/linux/if_addr.h
const IFA_ADDRESS: u16 = 1;
const NLM_F_REQUEST: u16 = 1; // uapi/linux/netlink.h
const NLM_F_ACK: u16 = 4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLMSG_ALIGNTO: usize = 4;
const IFF_UP: u32 = 0x1; // linux/if.h
const AF_INET: u8 = 2; // linux/in.h

// ---------------------------------------------------------------------------
// 自定 NETLINK 结构体（libc 不保证暴露这些，自己定义保证 ABI 稳定）
// ---------------------------------------------------------------------------

/// `struct nlmsghdr`（uapi/linux/netlink.h）。
#[repr(C)]
struct Nlmsghdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

/// `struct ifaddrmsg`（uapi/linux/if_addr.h）。
#[repr(C)]
struct Ifaddrmsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

/// `struct rtattr`（uapi/linux/rtnetlink.h）。
#[repr(C)]
struct Rtattr {
    rta_len: u16,
    rta_type: u16,
}

/// `struct ifinfomsg`（uapi/linux/rtnetlink.h）。
#[repr(C)]
struct Ifinfomsg {
    ifi_family: u8,
    ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

// ---------------------------------------------------------------------------
// 对齐宏
// ---------------------------------------------------------------------------

const fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

// ---------------------------------------------------------------------------
// configure_loopback
// ---------------------------------------------------------------------------

/// 在 netns 中配置 lo 接口。
///
/// 1. 创建 NETLINK socket
/// 2. 发送 RTM_NEWADDR 添加 127.0.0.1/8
/// 3. 发送 RTM_NEWLINK 设 IFF_UP
/// 4. 关闭 socket
///
/// 此函数预期在 fork 后的子进程中调用。失败时写 stderr 警告后返回，
/// 不终止进程——调用方应继续 exec 流程。
pub fn configure_loopback() {
    // SAFETY: 所有 NETLINK 操作在子进程中执行，使用栈缓冲区。
    let result = unsafe { configure_loopback_impl() };
    if let Err(msg) = result {
        // 手动写 stderr（子进程不可用 std::io 或 eprintln!）。
        // SAFETY: write(2) 是 async-signal-safe 的。
        unsafe {
            let stderr = libc::STDERR_FILENO;
            let prefix = b"[seabox] network: ";
            libc::write(stderr, prefix.as_ptr() as *const _, prefix.len());
            libc::write(stderr, msg.as_ptr() as *const _, msg.len());
            libc::write(stderr, b"\n" as *const _ as *const _, 1);
        }
    }
}

/// SAFETY: 仅在 fork 后的子进程中调用。
unsafe fn configure_loopback_impl() -> Result<(), &'static [u8]> {
    // ── 1. 创建 NETLINK socket ────────────────────────────────────
    let fd = libc::socket(
        AF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC,
        NETLINK_ROUTE,
    );
    if fd < 0 {
        return Err(b"socket(AF_NETLINK) failed\0");
    }

    // ── 2. 获取 lo 接口索引 ──────────────────────────────────────
    let lo_index = libc::if_nametoindex(b"lo\0" as *const _ as *const libc::c_char);
    if lo_index == 0 {
        libc::close(fd);
        return Err(b"if_nametoindex('lo') failed\0");
    }

    // ── 3. 构建并发送 RTM_NEWADDR（添加 127.0.0.1/8）─────────────
    // 消息布局：nlmsghdr(16) + ifaddrmsg(8) + IFA_LOCAL attr(8) + IFA_ADDRESS attr(8) = 40
    // 每个 attr = rtattr(4) + ip(4) = 8 字节，已 4 字节对齐无需额外 padding
    const ADDR_BUF_LEN: usize = 128;
    let mut buf = [0u8; ADDR_BUF_LEN];

    // nlmsghdr
    let nlh_len = mem::size_of::<Nlmsghdr>() as u32
        + mem::size_of::<Ifaddrmsg>() as u32
        + nlmsg_align(mem::size_of::<Rtattr>() + 4) as u32  // IFA_LOCAL
        + nlmsg_align(mem::size_of::<Rtattr>() + 4) as u32; // IFA_ADDRESS
    let nlh = Nlmsghdr {
        nlmsg_len: nlh_len,
        nlmsg_type: RTM_NEWADDR,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let local_ip: u32 = (127u32 << 24) | 1; // 127.0.0.1 in network byte order (big endian)

    // 顺序写入缓冲区
    let mut off = 0usize;
    let do_write = |buf: &mut [u8], off: &mut usize, data: &[u8]| {
        std::ptr::copy_nonoverlapping(data.as_ptr(), buf[*off..].as_mut_ptr(), data.len());
        *off += data.len();
    };

    // nlmsghdr
    do_write(&mut buf, &mut off, as_u8_slice(&nlh));
    // ifaddrmsg: AF_INET, prefixlen 8, flags 0, scope 0, ifa_index=lo_index
    let ifa = Ifaddrmsg {
        ifa_family: AF_INET,
        ifa_prefixlen: 8,
        ifa_flags: 0,
        ifa_scope: 0,
        ifa_index: lo_index,
    };
    do_write(&mut buf, &mut off, as_u8_slice(&ifa));
    // IFA_LOCAL = 127.0.0.1
    let rta_local = Rtattr {
        rta_len: (mem::size_of::<Rtattr>() + 4) as u16,
        rta_type: IFA_LOCAL,
    };
    do_write(&mut buf, &mut off, as_u8_slice(&rta_local));
    do_write(&mut buf, &mut off, as_u8_slice(&local_ip));
    // IFA_ADDRESS = 127.0.0.1
    let rta_addr = Rtattr {
        rta_len: (mem::size_of::<Rtattr>() + 4) as u16,
        rta_type: IFA_ADDRESS,
    };
    do_write(&mut buf, &mut off, as_u8_slice(&rta_addr));
    do_write(&mut buf, &mut off, as_u8_slice(&local_ip));

    if !netlink_send_recv(fd, &buf[..off]) {
        libc::close(fd);
        return Err(b"RTM_NEWADDR failed\0");
    }

    // ── 4. 构建并发送 RTM_NEWLINK（设 IFF_UP）────────────────────
    let mut link_buf = [0u8; 128];
    let mut link_off = 0usize;

    let link_nlh = Nlmsghdr {
        nlmsg_len: (mem::size_of::<Nlmsghdr>() + mem::size_of::<Ifinfomsg>()) as u32,
        nlmsg_type: RTM_NEWLINK,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
        nlmsg_seq: 2,
        nlmsg_pid: 0,
    };
    do_write(&mut link_buf, &mut link_off, as_u8_slice(&link_nlh));

    let ifi = Ifinfomsg {
        ifi_family: 0, // AF_UNSPEC
        ifi_pad: 0,
        ifi_type: 0, // kernel ignores ifi_type for RTM_NEWLINK
        ifi_index: lo_index as i32,
        ifi_flags: IFF_UP,
        ifi_change: IFF_UP,
    };
    do_write(&mut link_buf, &mut link_off, as_u8_slice(&ifi));

    if !netlink_send_recv(fd, &link_buf[..link_off]) {
        libc::close(fd);
        return Err(b"RTM_NEWLINK failed\0");
    }

    libc::close(fd);
    Ok(())
}

// ---------------------------------------------------------------------------
// NETLINK send/recv 辅助
// ---------------------------------------------------------------------------

/// 发送 NETLINK 请求并等待 NLMSG_ERROR ACK。
///
/// # Safety
///
/// `sock_fd` 必须是有效的 NETLINK socket fd，`buf` 为完整有效的 NLMSG。
unsafe fn netlink_send_recv(sock_fd: RawFd, buf: &[u8]) -> bool {
    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let msghdr = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &iov as *const _ as *mut _,
        msg_iovlen: 1,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };

    if libc::sendmsg(sock_fd, &msghdr, 0) < 0 {
        return false;
    }

    // 接收响应
    let mut recv_buf = [0u8; 256];
    let recv_iov = libc::iovec {
        iov_base: recv_buf.as_mut_ptr() as *mut _,
        iov_len: recv_buf.len(),
    };
    let mut recv_msghdr = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &recv_iov as *const _ as *mut _,
        msg_iovlen: 1,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    let n = libc::recvmsg(sock_fd, &mut recv_msghdr, 0);
    if n < 0 {
        return false;
    }
    let recv_slice = &recv_buf[..n as usize];

    // 检查 nlmsgerr.error 是否 == 0（ACK）
    let hdr_size = mem::size_of::<Nlmsghdr>();
    if recv_slice.len() < hdr_size + mem::size_of::<i32>() {
        return false;
    }
    let err_ptr = recv_slice.as_ptr().add(hdr_size) as *const i32;
    std::ptr::read(err_ptr) == 0
}

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

/// 将任意 T 的 memory 视为 &[u8]。
/// # Safety
/// T 必须为 `#[repr(C)]` POD 类型，不含未初始化 padding。
unsafe fn as_u8_slice<T: Sized>(val: &T) -> &[u8] {
    std::slice::from_raw_parts(val as *const T as *const u8, mem::size_of::<T>())
}
