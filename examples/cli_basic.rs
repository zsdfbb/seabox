//! 最基本的沙箱使用示例。
//!
//! 运行: `cargo run --example cli_basic`
//!
//! 演示最简配置即可运行沙箱命令：配几条 Landlock 规则，执行一个命令，检查结果。
//! 等价于 CLI:
//!
//! ```bash
//! seabox run \
//!   --landlock '/:ro' --landlock '/tmp:rw' \
//!   -- sh -c 'echo hello; id'
//! ```

use std::path::PathBuf;
use std::time::Duration;

use seabox::config::SandboxConfig;
use seabox::{CommandSpec, ExitReason, Sandbox};

fn main() -> anyhow::Result<()> {
    // ── 1. 构建配置 ──────────────────────────────────
    // 根文件系统只读，/tmp 可写。
    let config = SandboxConfig::default()
        .with_landlock("/:ro")? // 根只读
        .with_landlock("/tmp:rw")? // /tmp 可写（供程序运行时使用）
        .with_timeout(10, 60); // 默认 10s 超时，上限 60s

    // ── 2. 创建沙箱 ──────────────────────────────────
    let sandbox = Sandbox::from_config(config)?;

    // ── 3. 执行命令 ──────────────────────────────────
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "echo 'hello from sandbox'; id"])
        .with_cwd(PathBuf::from("/tmp"))
        .with_timeout(Duration::from_secs(5));

    let (output, reason) = sandbox.execute(&spec)?;

    // ── 4. 处理结果 ──────────────────────────────────
    println!("exit_code: {}", output.exit_code);
    println!("reason:    {reason:?}");

    match reason {
        ExitReason::Ok => {
            println!("命令成功执行");
        }
        ExitReason::Denied { mechanism, message } => {
            eprintln!("沙箱拒绝 ({mechanism:?}): {message}");
            std::process::exit(126);
        }
        ExitReason::Program(code) => {
            eprintln!("命令以非零退出码 {code} 退出");
            std::process::exit(code);
        }
        ExitReason::InternalError(msg) => {
            eprintln!("内部错误: {msg}");
            std::process::exit(125);
        }
    }

    Ok(())
}
