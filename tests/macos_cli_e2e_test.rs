#![cfg(target_os = "macos")]
//! macOS Seatbelt 后端的 **CLI 端到端**测试（真跑 `CARGO_BIN_EXE_seabox` 二进制）。
//!
//! # 与 `tests/macos_test.rs` 的分工
//!
//! `macos_test.rs` 走**库 API**（`Sandbox::execute`），验证策略语义与拒绝归因；
//! 本文件走**二进制**，验证 CLI 装配层：`clap` 解析 → `parse_run` → `SandboxConfig`
//! → `create_sandbox_impl` → `cmd_run`（流式 `spawn(Inherit)`）→ 退出码映射。
//!
//! 这层此前**零覆盖**：所有 macOS 断言都用库 API，`main.rs` 的退出码映射
//! （`Ok→0` / `Program(code)→code` / `Denied→126` / `InternalError→125` / 超时 `→124`）
//! 只有手工验证。回归例子：若 `cmd_run` 误把 `ExitReason::Ok` 映射成非零退出，
//! 库测试全绿而 CLI 用户立刻可见——本文件就是抓这个。
//!
//! # 已知能力降级（不是本文件的 bug）
//!
//! CLI 走流式 `spawn(StdioConfig::Inherit)`，**拿不到 stderr**，因此 macOS 的
//! `classify_output`（扫 stderr 判 `Operation not permitted`）不可用，
//! `classify_exit` 退化为仅退出码判据（design §10.2）。后果：
//!
//! - 被 Seatbelt 拒绝的写操作 → CLI 退出 **1**（`Program(1)`），不是 126。
//! - 要断言结构化的 `Denied { mechanism: Seatbelt, .. }`，必须用库 API
//!   （见 `tests/macos_test.rs` 的 D1）。
//!
//! README「已知限制」与 design §10.2 均已声明。本文件据此断言：拒绝场景下
//! **退出码非零 + stderr 含 `Operation not permitted` + 宿主侧文件未落盘**，
//! 不假装能拿到 126。
//!
//! # 安全约束
//!
//! 「应当被拒」的写目标**绝不能**建在 `$TMPDIR`——ReadOnly / WorkspaceWrite 预设
//! 故意放通 TMPDIR，那样测的是放通而非拒绝。本文件统一用 `$HOME` 下的临时目录
//! （见 [`home_scratch`]），且 `Drop` 时清理。

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// 预检与工具
// ---------------------------------------------------------------------------

/// Seatbelt 是否可用（`sandbox-exec` 存在）。
fn seatbelt_available() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| Path::new("/usr/bin/sandbox-exec").exists())
}

/// 预检宏：不可用时打印跳过信息并 `return`（自动跳过，不是 fail）。
macro_rules! require_seatbelt {
    () => {
        if !seatbelt_available() {
            eprintln!("sandbox-exec not available, skipping test");
            return;
        }
    };
}

/// Cargo 注入的 CLI 二进制绝对路径。
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_seabox")
}

/// 宿主 `$HOME`。
fn home() -> String {
    std::env::var("HOME").expect("HOME must be set")
}

/// `$HOME` 下的自清理临时目录。
///
/// **刻意不用 `tempfile::tempdir()`**：后者落在 `$TMPDIR`，而 macOS 预设
/// 故意放通 TMPDIR，导致「应当被拒」的写断言永远失败。测的是拒绝，所以写目标
/// 必须落在**不被任何预设放通**的位置——`$HOME` 下自建目录满足这点
/// （ReadOnly 只读 `$HOME`、WorkspaceWrite 只写 cwd、FullAccess 全开，
/// 前两者对 `$HOME` 下非 cwd 路径的写入都会被拒）。
struct HomeScratch {
    path: PathBuf,
}

impl HomeScratch {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = PathBuf::from(home()).join(format!(".seabox_e2e_{tag}_{nanos}"));
        std::fs::create_dir_all(&path).expect("create scratch dir under $HOME");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for HomeScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 跑 CLI：`seabox run <args...>`，返回 `Output`。
fn run_cli(args: &[&str], cwd: &Path) -> Output {
    Command::new(bin())
        .arg("run")
        .args(args)
        .current_dir(cwd)
        .env("HOME", home())
        .output()
        .expect("spawn seabox binary")
}

/// 退出码（被信号杀死时为 `128+sig`，与 `main.rs` 的 D-A1 约定一致）。
fn code_of(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// E2E-1 三预设的成功路径（CLI 装配层能否真的把命令跑起来）
// ---------------------------------------------------------------------------

/// `--mac-preset read-only` 能读系统文件并正常退出 0。
///
/// 这条覆盖 `main.rs` 的 `ExitReason::Ok => exit(0)` 映射。
#[test]
fn e2e_readonly_runs_command_and_exits_zero() {
    require_seatbelt!();
    let scratch = HomeScratch::new("ro_ok");

    let out = run_cli(
        &[
            "--mac-preset",
            "read-only",
            "--",
            "sh",
            "-c",
            "cat /etc/hosts >/dev/null && echo READ_OK",
        ],
        scratch.path(),
    );

    assert_eq!(code_of(&out), 0, "read-only 应当正常退出 0");
    assert!(
        stdout_of(&out).contains("READ_OK"),
        "stdout 应含 READ_OK，实际: {:?}",
        stdout_of(&out)
    );
}

/// `--mac-preset workspace-write` 能在 cwd 内创建并删除文件。
#[test]
fn e2e_workspace_write_can_write_cwd() {
    require_seatbelt!();
    let scratch = HomeScratch::new("wsw_ok");

    let out = run_cli(
        &[
            "--mac-preset",
            "workspace-write",
            "--",
            "sh",
            "-c",
            "touch ./w.txt && rm ./w.txt && echo WSW_OK",
        ],
        scratch.path(),
    );

    assert_eq!(code_of(&out), 0, "workspace-write 应能在 cwd 写");
    assert!(
        stdout_of(&out).contains("WSW_OK"),
        "stdout: {:?}",
        stdout_of(&out)
    );
}

/// `--mac-preset full-access` 能写 `$HOME` 下非 cwd 路径
/// （ReadOnly / WorkspaceWrite 都做不到，故这是 FullAccess 的判别特征）。
#[test]
fn e2e_full_access_can_write_outside_cwd() {
    require_seatbelt!();
    let scratch = HomeScratch::new("fa_ok");
    let outside = HomeScratch::new("fa_target");
    let target = outside.path().join("full.txt");

    let script = format!("echo FA > '{}' && echo FA_OK", target.display());
    let out = run_cli(
        &["--mac-preset", "full-access", "--", "sh", "-c", &script],
        scratch.path(),
    );

    assert_eq!(code_of(&out), 0, "full-access 应能写 cwd 外");
    assert!(
        target.exists(),
        "full-access 应真的落盘: {}",
        target.display()
    );
}

// ---------------------------------------------------------------------------
// E2E-2 拒绝路径（退出码映射 + 宿主侧无副作用）
// ---------------------------------------------------------------------------

/// read-only 写 `$HOME` 下 cwd **被拒**：非零退出 + stderr 有拒绝原因 + 未落盘。
///
/// 注意断言的是**非零**而非 126：CLI 流式路径拿不到 stderr，macOS 的
/// `classify_output` 不生效，拒绝退化为 `Program(1)`（design §10.2 已声明）。
/// 若将来 CLI 改为 `Piped` + `classify_output`，此断言仍成立（126 也是非零）；
/// 但那时应把本测试升级为断言 126——见文末 TODO。
#[test]
fn e2e_readonly_write_denied_is_nonzero_and_no_side_effect() {
    require_seatbelt!();
    let scratch = HomeScratch::new("ro_deny");
    let target = scratch.path().join("denied.txt");

    let script = format!("echo PWNED > '{}'", target.display());
    let out = run_cli(
        &["--mac-preset", "read-only", "--", "sh", "-c", &script],
        scratch.path(),
    );

    let code = code_of(&out);
    let stderr = stderr_of(&out);

    assert_ne!(code, 0, "read-only 下写 $HOME 必须非零退出，实际 {code}");
    assert!(
        stderr.contains("Operation not permitted") || stderr.contains("Permission denied"),
        "stderr 应含拒绝原因，实际: {stderr:?}"
    );
    assert!(
        !target.exists(),
        "拒绝后宿主侧不得有文件: {}",
        target.display()
    );
}

/// `~/.ssh` 私钥读在 read-only 下被拒（D4 的 CLI 版）。
///
/// 无任何可读私钥时跳过。
#[test]
fn e2e_readonly_read_private_key_denied() {
    require_seatbelt!();
    let scratch = HomeScratch::new("ssh_deny");

    let key = ["id_ed25519", "id_rsa", "id_ecdsa"]
        .iter()
        .map(|n| PathBuf::from(home()).join(".ssh").join(n))
        .find(|p| p.is_file());
    let Some(key) = key else {
        eprintln!("no ssh private key found, skipping test");
        return;
    };

    let script = format!("cat '{}' >/dev/null && echo LEAKED", key.display());
    let out = run_cli(
        &["--mac-preset", "read-only", "--", "sh", "-c", &script],
        scratch.path(),
    );

    let stderr = stderr_of(&out);
    assert_ne!(code_of(&out), 0, "读私钥必须非零退出");
    assert!(
        !stdout_of(&out).contains("LEAKED"),
        "私钥内容不得读出，stdout: {:?}",
        stdout_of(&out)
    );
    assert!(
        stderr.contains("Operation not permitted") || stderr.contains("Permission denied"),
        "stderr 应含拒绝原因，实际: {stderr:?}"
    );
}

// ---------------------------------------------------------------------------
// E2E-3 退出码透传与特殊约定
// ---------------------------------------------------------------------------

/// 命令自身退出码透传（`exit 42` → CLI 退 42），走 `ExitReason::Program(code)` 分支。
#[test]
fn e2e_program_exit_code_is_passed_through() {
    require_seatbelt!();
    let scratch = HomeScratch::new("code42");

    let out = run_cli(
        &["--mac-preset", "read-only", "--", "sh", "-c", "exit 42"],
        scratch.path(),
    );

    assert_eq!(code_of(&out), 42, "命令退出码应原样透传");
    assert!(
        stderr_of(&out).contains("exit code 42"),
        "非零退出应有提示，stderr: {:?}",
        stderr_of(&out)
    );
}

/// `--timeout` 到期以 124 退出（`timeout(1)` 惯例），走 `main.rs` 的超时分支。
#[test]
fn e2e_timeout_exits_124() {
    require_seatbelt!();
    let scratch = HomeScratch::new("timeout");

    let out = run_cli(
        &[
            "--mac-preset",
            "read-only",
            "--timeout",
            "1",
            "--",
            "sleep",
            "10",
        ],
        scratch.path(),
    );

    assert_eq!(code_of(&out), 124, "超时应以 124 退出");
    assert!(
        stderr_of(&out).contains("timed out"),
        "stderr 应含超时提示，实际: {:?}",
        stderr_of(&out)
    );
}

// ---------------------------------------------------------------------------
// E2E-4 参数切分边界（clap `trailing_var_arg` + `allow_hyphen_values`）
// ---------------------------------------------------------------------------

/// `--` 之后的 `-` 开头参数必须原样交给目标程序，不被 clap 当作自身 flag 吞掉。
///
/// `src/cli.rs` 的 command 字段带 `trailing_var_arg = true, allow_hyphen_values = true`，
/// 少了任一项这里就会失败（clap 会报 unexpected argument）。
#[test]
fn e2e_hyphen_args_after_double_dash_are_not_swallowed() {
    require_seatbelt!();
    let scratch = HomeScratch::new("hyphen");

    // 让 `sh` 自己逐个回显 `$@`：`echo` 会把自己收到的 `-n` 当 flag 吞掉，
    // 那样测的就不是 clap 的透传了。`printf` 不会。
    let out = run_cli(
        &[
            "--mac-preset",
            "read-only",
            "--",
            "sh",
            "-c",
            "printf 'ARG:%s\\n' \"$@\"",
            "sh",
            "-n",
            "-c",
            "--help",
            "-x",
        ],
        scratch.path(),
    );

    assert_eq!(code_of(&out), 0, "带连字符的参数不应让 clap 报错");
    let stdout = stdout_of(&out);
    for expected in ["ARG:-n", "ARG:-c", "ARG:--help", "ARG:-x"] {
        assert!(
            stdout.contains(expected),
            "argv 应原样透传，缺少 {expected:?}，stdout: {stdout:?}"
        );
    }
}

/// `--chdir` 覆盖工作目录（`RunSpec.chdir` → `CommandSpec.cwd`）。
///
/// macOS 上 `/tmp` 是 symlink 到 `/private/tmp`，`pwd` 返回解析后的物理路径，
/// 故断言「结尾匹配」而非全等。
#[test]
fn e2e_chdir_overrides_working_directory() {
    require_seatbelt!();
    let scratch = HomeScratch::new("chdir");

    let out = run_cli(
        &[
            "--mac-preset",
            "read-only",
            "--chdir",
            "/private/tmp",
            "--",
            "pwd",
        ],
        scratch.path(),
    );

    assert_eq!(code_of(&out), 0, "--chdir 应正常执行");
    assert!(
        stdout_of(&out).trim().ends_with("/private/tmp"),
        "pwd 应为 --chdir 指定目录，实际: {:?}",
        stdout_of(&out)
    );
}

// ---------------------------------------------------------------------------
// E2E-5 管道（沙箱内 shell 的 fd 1/2 接线没被 spawn 搞坏）
// ---------------------------------------------------------------------------

/// 沙箱内管道可用：`echo x | wc -l` 输出 1。
///
/// 防的是 `spawn(Inherit)` 把 0/1/2 接错（例如 stdin 没接导致 `wc` 读到 EOF 且不计数）。
#[test]
fn e2e_pipeline_inside_sandbox_works() {
    require_seatbelt!();
    let scratch = HomeScratch::new("pipe");

    let out = run_cli(
        &[
            "--mac-preset",
            "read-only",
            "--",
            "sh",
            "-c",
            "echo x | wc -l | tr -d ' '",
        ],
        scratch.path(),
    );

    assert_eq!(code_of(&out), 0);
    assert_eq!(stdout_of(&out).trim(), "1", "管道应正常工作");
}

// ---------------------------------------------------------------------------
// E2E-6 沙箱内看不到本进程继承的 fd（F1 的 CLI 版）
// ---------------------------------------------------------------------------

/// 父 shell 打开 fd 9 指向宿主文件，沙箱内写 fd 9 必须失败且宿主文件不变。
///
/// 这是 `pre_exec` 阶段 fd 清扫（`/dev/fd` 枚举 + `FD_CLOEXEC` 过滤）的 CLI 层回归。
/// 用 `>>`（追加）而非 `>`：后者打开即 truncate，即便逃逸被挡住宿主文件也已清空，
/// 无法区分「被拒绝」与「被清空」。
#[test]
fn e2e_inherited_fd_cannot_escape_sandbox() {
    require_seatbelt!();
    let scratch = HomeScratch::new("fd_escape");
    let host_file = scratch.path().join("host.txt");
    std::fs::write(&host_file, "ORIGINAL\n").expect("seed host file");

    // 单行脚本：先用宿主 shell 打开 fd 9，再跑 seabox。
    let script = format!(
        "exec 9>>'{host}'; '{bin}' run --mac-write '{dir}' -- sh -c 'echo PWNED >&9'",
        host = host_file.display(),
        bin = bin(),
        dir = scratch.path().display(),
    );

    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg(&script)
        .env("HOME", home())
        .output()
        .expect("run fd-escape scenario");

    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("Bad file descriptor"),
        "沙箱内 fd 9 应已关闭，stderr: {stderr:?}"
    );

    let after = std::fs::read_to_string(&host_file).expect("read host file");
    assert_eq!(after, "ORIGINAL\n", "F1/CLI: 宿主文件内容必须不变");
}

// TODO（若 CLI 改为 Piped + classify_output）：把 E2E-2 的断言从「非零」
// 收紧为「== 126」，届时 macOS CLI 才能真正区分「策略拒绝」与「程序自己退 1」。
// 当前 `cmd_run` 走 `spawn(StdioConfig::Inherit)` 拿不到 stderr，属已声明的
// 能力降级（README「已知限制」+ docs/arch/macos-seatbelt/design.md §10.2）。
//
// 与后端无关的 CLI 表面（`--version` / `--help`）在 `tests/cli_meta_test.rs`：
// 本文件带 `#![cfg(target_os = "macos")]`，放这里 Linux 就测不到。
