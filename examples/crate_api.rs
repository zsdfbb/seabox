//! 演示如何将 sandbox-runtime 作为 crate 使用（而非 CLI）。
//!
//! 通过 `SandboxConfig` 配置沙箱，调用 `Sandbox::from_config()` 创建实例，
//! 然后用 `execute()` 执行命令并检查结果。
//!
//! 运行: `cargo run --example crate_api`

use std::collections::HashMap;
use std::time::Duration;

use sandbox_runtime::config::SandboxConfig;
use sandbox_runtime::{CommandSpec, Sandbox};

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
    let spec = CommandSpec {
        program: "echo".into(),
        args: vec!["hello from crate API".into()],
        cwd: std::env::current_dir()?,
        env: HashMap::new(), // 空 = 无额外环境变量
        timeout: Duration::from_secs(5),
    };

    let (output, reason) = sandbox.execute(&spec)?;

    println!("exit_code: {}", output.exit_code);
    println!("reason:    {reason:?}");

    if output.exit_code != 0 {
        std::process::exit(output.exit_code);
    }
    Ok(())
}
