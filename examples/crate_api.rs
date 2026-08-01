//! 演示如何将 seabox 作为 crate 使用（而非 CLI）。
//!
//! 通过 `SandboxConfig` 配置沙箱，调用 `Sandbox::from_config()` 创建实例，
//! 然后用 `execute()` 执行命令并检查结果。沙箱配置用 `SandboxConfig::with_*`，
//! 命令规格用 `CommandSpec::with_*`，CLI 和 crate API 保持对应。
//!
//! 运行: `cargo run --example crate_api`

use std::path::PathBuf;
use std::time::Duration;

use seabox::config::SandboxConfig;
use seabox::{CommandSpec, Sandbox};

fn main() -> anyhow::Result<()> {
    // ── 构建配置（等价于 CLI: --unshare-all --uid 1000
    //    --landlock '/:ro' --landlock '/tmp:rw') ───
    let config = SandboxConfig::default()
        .with_unshare_all()
        .with_uid(1000)
        .with_landlock("/:ro")?
        .with_landlock("/tmp:rw")?
        .with_timeout(10, 60);

    // ── 创建沙箱（Linux 上用 Landlock + seccomp + namespace）──
    //     非 Linux 平台返回错误 "requires Linux"。
    let sandbox = Sandbox::from_config(config)?;

    // ── 执行命令 ────────────────────────────────────────
    // 等价于 CLI: run --clearenv --env MSG="hello" -- sh -c 'echo $MSG'
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "echo $MSG"])
        .with_cwd(PathBuf::from("/"))
        .with_clearenv()
        .with_env("MSG", "hello from crate API")
        .with_timeout(Duration::from_secs(5));

    let (output, reason) = sandbox.execute(&spec)?;

    println!("exit_code: {}", output.exit_code);
    println!("reason:    {reason:?}");

    if output.exit_code != 0 {
        std::process::exit(output.exit_code);
    }
    Ok(())
}
