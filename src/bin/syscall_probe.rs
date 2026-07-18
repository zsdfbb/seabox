//! syscall_probe 辅助二进制
//!
//! 接受一个 syscall 号与最多 6 个参数（以十进制或 0x 前缀十六进制表达），
//! 直接通过 `libc::syscall` 发起系统调用。专供 seccomp 集成测试用——
//! 调用方传入黑名单中的 syscall 号，观察 wrapper 把进程归类为
//! `Denied { Seccomp }` 并退出 126。
//!
//! ## 用法
//!
//! ```text
//! syscall_probe <nr> [arg0 arg1 arg2 arg3 arg4 arg5]
//! ```
//!
//! - `nr`：syscall 号（十进制或 `0x` 十六进制）。i64 范围。
//! - `argN`：可选参数（最多 6 个）；数字字面量，十进制或 `0x` 十六进制；
//!   也可写 `NULL`/`0` 表示 0。
//!
//! ## 退出码
//!
//! - `0`：syscall 返回非负值（视为成功；具体含义取决于 syscall）。
//! - `1`：参数解析失败。
//! - `100 + errno`：syscall 自身返回错误。errno 偏移 100 以避开
//!   shell 保留码（如 126 sandbox denial、127 command not found）。
//! - `2`：调用格式错误（参数数量错）。
//!
//! ## 设计意图
//!
//! 测试时所有黑名单 syscall 都用全 0 参数调用：seccomp 在 syscall **入口**
//! 检查黑名单并立即投递 SIGSYS，根本不会执行 syscall 真正的语义代码，
//! 因此参数合法性无关紧要。这样能可靠验证"黑名单拦截到位"，而不会被
//! syscall 自身的失败路径掩盖。

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("usage: syscall_probe <nr> [arg0 arg1 arg2 arg3 arg4 arg5]");
        return ExitCode::from(2u8);
    }

    // 解析 syscall 号
    let syscall_nr: i64 = match parse_i64(&args[1]) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("invalid syscall number {:?}: {}", args[1], e);
            return ExitCode::from(1u8);
        }
    };

    // 解析最多 6 个参数
    if args.len() - 2 > 6 {
        eprintln!("too many args (max 6), got {}", args.len() - 2);
        return ExitCode::from(2u8);
    }

    let syscall_args: Vec<i64> = args[2..]
        .iter()
        .map(|s| match parse_i64(s) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("invalid arg {:?}: {}", s, e);
                -1
            }
        })
        .collect();

    // 发起 syscall。unsafe 调用 libc::syscall，参数已经解析为 i64。
    // 安全性：调用方（测试）负责传入合理的 syscall 号。
    let result: i64 = unsafe { dispatch_syscall(syscall_nr, &syscall_args) };

    if result < 0 {
        // Linux syscall 约定：失败时返回 -errno。需要把绝对值还原为 errno。
        let errno = (-result) as i32;
        // 偏移 100 以避开 shell 保留码；cap 到 125（再往上就是 internal error）
        let exit_code: u8 = (100 + errno).min(125) as u8;
        eprintln!(
            "syscall({}) returned {} (errno={})",
            syscall_nr, result, errno
        );
        ExitCode::from(exit_code)
    } else {
        eprintln!("syscall({}) returned {}", syscall_nr, result);
        ExitCode::from(0u8)
    }
}

/// 把字符串解析为 i64。支持十进制与 `0x` 十六进制前缀。
fn parse_i64(s: &str) -> Result<i64, std::num::ParseIntError> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16)
    } else {
        s.parse::<i64>()
    }
}

/// 根据参数数量分派到对应的 `libc::syscall` 重载。
///
/// SAFETY：调用方传入的 syscall 号与参数是有效的 i64；`libc::syscall`
/// 本身是 unsafe 的 wrapper，其调用安全性由调用方承担。
unsafe fn dispatch_syscall(nr: i64, args: &[i64]) -> i64 {
    match args.len() {
        0 => libc::syscall(nr),
        1 => libc::syscall(nr, args[0]),
        2 => libc::syscall(nr, args[0], args[1]),
        3 => libc::syscall(nr, args[0], args[1], args[2]),
        4 => libc::syscall(nr, args[0], args[1], args[2], args[3]),
        5 => libc::syscall(nr, args[0], args[1], args[2], args[3], args[4]),
        6 => libc::syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]),
        _ => unreachable!("args.len() already capped at 6"),
    }
}