#![cfg(target_os = "macos")]
//! macOS Seatbelt 后端（`sandbox-exec` + SBPL）的集成测试。
//!
//! 覆盖合同：H4（`seabox check` 能力矩阵）、D1–D5（预设行为 + 凭据读写）、
//! F1（fd 逃逸回归）、F4（canary 预检）、H5（business-pid 回传）。
//!
//! # 归因一律走库 API，不解析 CLI 文本
//!
//! CLI 二进制在 macOS 侧用 `spawn(Inherit)`，拿不到 stderr，因此 Seatbelt 拒绝
//! 只会显示成 `Program(1)`（`src/macos/imp.rs` 的文档已声明这一能力降级）。
//! 唯一能断言 `Denied { mechanism: DenyMechanism::Seatbelt, .. }` 的路径是
//! [`seabox::Sandbox::execute`]（内部恒用 `Piped` + `classify_output`）。
//! 所以除 F1（必须借 shell 的 `exec 9>` 打开继承 fd）之外，全部断言用库 API。
//!
//! # 预检与安全约束
//!
//! - `/usr/bin/sandbox-exec` 缺失 ⇒ 所有测试打印 `skipping test` 后返回（自动跳过，
//!   与 `tests/landlock_test.rs` 同风格），不是 `fail`。
//! - 绝不写入仓库工程目录：写入目标只用 `tempfile::tempdir()`（落在 `$TMPDIR`）或
//!   `/private/tmp` 下自建目录。注意 `$TMPDIR` 在预设下**故意**可写，所以「应当被拒」
//!   的写目标不能放在 `$TMPDIR` 里，否则测的是 TMP 放通而非拒绝。
//!
//! # E 组（网络）刻意跳过
//!
//! `sbpl::build(&ResolvedPolicy, &Path)` 是 `pub(crate)`，`ResolvedPolicy` 同样是
//! `pub(crate)` 内部定型类型（`src/macos/config.rs`：`ResolvedPolicy` 不进入公开 API），
//! 外部集成测试**无法**从 profile 文本侧断言网络段。
//! 该组已由 `src/macos/sbpl.rs` 的内联单测覆盖（`network_loopback_and_ports`、
//! `network_is_orthogonal_to_preset` 等，共 18 个内联测试），此处不重复也不改用
//! 真实联网（本文件不依赖外网）。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use seabox::config::SandboxConfig;
use seabox::macos::config::{MacPreset, NetAccess};
use seabox::{CommandSpec, DenyMechanism, ExitReason, Sandbox, StdioConfig};

// ---------------------------------------------------------------------------
// 预检
// ---------------------------------------------------------------------------

/// Seatbelt 是否可用（`sandbox-exec` 存在）。
///
/// 结果用 [`OnceLock`] 缓存：预检本身是纯 `stat`，但缓存可保证同进程内
/// 后续断言看到的判断与首个测试一致（与 `landlock_test.rs` 的探针风格一致）。
fn seatbelt_available() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| Path::new("/usr/bin/sandbox-exec").exists())
}

/// 预检宏：不可用时打印跳过信息并 `return`。
macro_rules! require_seatbelt {
    () => {
        if !seatbelt_available() {
            eprintln!("sandbox-exec not available, skipping test");
            return;
        }
    };
}

/// Cargo 注入的 CLI 二进制绝对路径（F1 需要 shell + 二进制组合）。
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_seabox")
}

/// 宿主 `$HOME`（`CommandSpec` 会 `env_clear`，必须显式传下去）。
fn home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

/// 用指定配置建沙箱。构造期会跑 `validate → build → canary`，失败即测试失败。
fn sandbox(cfg: SandboxConfig) -> Sandbox {
    Sandbox::from_config(cfg).expect("Sandbox::from_config should succeed (canary included)")
}

/// 在沙箱内跑一段 `sh -c` 脚本，返回 `(exit_code, stderr, reason)`。
///
/// 环境变量逐项显式给出：`CommandSpec` 的环境**不继承**父进程
///（`imp.rs::spawn` 里 `env_clear().envs()`），所以 `PATH` / `HOME` / `TMPDIR`
/// 必须自己塞进去，否则脚本里的 `touch`、`~` 展开、`$TMPDIR` 全部失效。
fn run_sh(sb: &Sandbox, cwd: &Path, script: &str) -> (i32, String, ExitReason) {
    let spec = CommandSpec::default()
        .with_program("/bin/sh")
        .with_args(["-c", script])
        .with_cwd(cwd)
        .with_env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .with_env("HOME", home())
        .with_env("TMPDIR", std::env::temp_dir().to_string_lossy().to_string())
        .with_timeout(Duration::from_secs(30));
    let (out, reason) = sb.execute(&spec).expect("execute should not error");
    (
        out.exit_code,
        String::from_utf8_lossy(&out.stderr).into_owned(),
        reason,
    )
}

/// 断定为「被 Seatbelt 拒绝」。
fn assert_seatbelt_denied(reason: &ExitReason, stderr: &str, what: &str) {
    match reason {
        ExitReason::Denied { mechanism, message } => {
            assert_eq!(
                *mechanism,
                DenyMechanism::Seatbelt,
                "{what}: expected DenyMechanism::Seatbelt, got {mechanism:?} (stderr: {stderr})"
            );
            assert!(
                !message.is_empty(),
                "{what}: Denial message must not be empty"
            );
        }
        other => panic!("{what}: expected ExitReason::Denied, got {other:?} (stderr: {stderr})"),
    }
}

/// 断定为「正常退出」。
fn assert_ok(reason: &ExitReason, stderr: &str, what: &str) {
    assert_eq!(
        reason,
        &ExitReason::Ok,
        "{what}: expected ExitReason::Ok, got {reason:?} (stderr: {stderr})"
    );
}

// ---------------------------------------------------------------------------
// H4：`seabox check` 的能力矩阵（库函数 `check_capabilities()`）
// ---------------------------------------------------------------------------

/// H4：能力矩阵必须如实报告 Seatbelt 在场、setuid 硬限制、双读模式与三预设。
///
/// 直接调库函数（不是二进制）：`seabox check` 只是把它的返回值打到 stdout，
/// 断言库输出避免依赖 CLI 的格式化/重定向。
#[test]
fn h4_check_capabilities_reports_seatbelt_matrix() {
    require_seatbelt!();

    let text = seabox::check_capabilities();

    // ① 机制本体：运行时探测到的 sandbox-exec 路径
    assert!(
        text.contains("Seatbelt (sandbox-exec)"),
        "capability table must list the Seatbelt row:\n{text}"
    );
    assert!(
        text.contains("/usr/bin/sandbox-exec"),
        "Seatbelt row must name the probed binary:\n{text}"
    );

    // ② 硬限制：setuid 二进制在任何 profile 下都放不通（实测探针结论）
    assert!(
        text.contains("BLOCKED"),
        "hard-limit section must state BLOCKED (setuid / SIP):\n{text}"
    );

    // ③ 读侧双模式：All（默认，靠凭据 denylist 补偿）与 Only（真隔离 + 系统地板）
    assert!(
        text.contains("MacReadMode::All"),
        "read isolation section must mention MacReadMode::All:\n{text}"
    );
    assert!(
        text.contains("MacReadMode::Only"),
        "read isolation section must mention MacReadMode::Only:\n{text}"
    );

    // ④ 三个预设名逐字出现（用户据此拼 --mac-preset）
    for preset in ["read-only", "workspace-write", "full-access"] {
        assert!(
            text.contains(preset),
            "presets section must list `{preset}`:\n{text}"
        );
    }
}

// ---------------------------------------------------------------------------
// D1：ReadOnly 预设
// ---------------------------------------------------------------------------

/// D1（读侧）：ReadOnly 下读系统常青文件必须成功 —— 读是放开的，
/// 只靠凭据 denylist 收口（`MacReadMode::All` 语义）。
#[test]
fn d1_readonly_read_system_file_ok() {
    require_seatbelt!();

    let sb = sandbox(SandboxConfig::default().with_mac_preset(MacPreset::ReadOnly));
    let tmp = tempfile::tempdir().expect("tempdir");

    let (code, stderr, reason) = run_sh(&sb, tmp.path(), "head -1 /etc/hosts > /dev/null");
    assert_ok(&reason, &stderr, "D1 read /etc/hosts");
    assert_eq!(
        code, 0,
        "D1 read /etc/hosts should exit 0 (stderr: {stderr})"
    );
}

/// D1（写侧）：ReadOnly 下写当前工作目录必须被拒。
///
/// 工作目录选 `/private/tmp/sbxt-*`：它**不在** `std::env::temp_dir()`
/// （= `$TMPDIR` = `/var/folders/...`）之下，所以 TMP 放通盖不住它 —— 这正是
/// 「应当被拒」的写目标该有的位置。
#[test]
fn d1_readonly_write_cwd_denied() {
    require_seatbelt!();

    let sb = sandbox(SandboxConfig::default().with_mac_preset(MacPreset::ReadOnly));
    // 用 tempfile 建在 /private/tmp 下（不落工程目录，也不落 $TMPDIR）
    let cwd = tempfile::Builder::new()
        .prefix("sbxt-ro-")
        .tempdir_in("/private/tmp")
        .expect("tempdir in /private/tmp");

    let (code, stderr, reason) = run_sh(&sb, cwd.path(), "echo x > .seabox_test_target");
    assert_seatbelt_denied(&reason, &stderr, "D1 write cwd under ReadOnly");
    assert_ne!(code, 0, "denied write should not exit 0 (stderr: {stderr})");
    // 拒绝必须是**真的**拒绝：宿主侧不应出现该文件
    assert!(
        !cwd.path().join(".seabox_test_target").exists(),
        "D1: the denied write must not have created the file on the host"
    );
}

/// D1（TMP 放通）：ReadOnly 预设下 `$TMPDIR` 可写（`tmp_writable = true`）。
///
/// 写目标用 `std::env::temp_dir()` 本身 —— 与
/// `src/macos/sbpl.rs::push_tmp` 的 `TMP` 参数同源（避免 `$TMPDIR` 带尾斜杠
/// 造成 `subpath` 字面比较不一致）。
#[test]
fn d1_readonly_write_tmpdir_ok() {
    require_seatbelt!();

    let sb = sandbox(SandboxConfig::default().with_mac_preset(MacPreset::ReadOnly));
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = std::env::temp_dir().join(format!(".seabox-t1-{}", std::process::id()));
    let target_s = target.to_string_lossy().into_owned();

    // 目标放在 $TMPDIR 根下（不在 tmp.path() 子目录），确保测的是 TMP 段
    let script = format!("echo x > '{target_s}'");
    let (code, stderr, reason) = run_sh(&sb, tmp.path(), &script);
    // 沙箱内的写落在同一份宿主文件系统上 ⇒ 直接查宿主侧文件
    let existed = target.exists();
    let _ = std::fs::remove_file(&target); // 清理（无论断言结果）

    assert_ok(&reason, &stderr, "D1 write $TMPDIR under ReadOnly");
    assert_eq!(code, 0, "D1 write $TMPDIR should exit 0 (stderr: {stderr})");
    assert!(
        existed,
        "D1: TMPDIR must be writable under the ReadOnly preset (stderr: {stderr})"
    );
}

// ---------------------------------------------------------------------------
// D2 / D3：WorkspaceWrite 与 FullAccess
// ---------------------------------------------------------------------------

/// D2：WorkspaceWrite 下工作目录可写。
///
/// 显式用 `with_mac_workspace` 指定写根：预设默认写根是**进程** cwd
/// （`MacSandbox::new` 里的 `current_dir()`，即仓库根），那样断言「写成功」会
/// 落到工程目录里 —— 绝不允许。`--mac-workspace` 是**替换**而非追加（设计如此），
/// 所以这里 cwd 就等于写根。
#[test]
fn d2_workspace_write_cwd_ok() {
    require_seatbelt!();

    let ws = tempfile::Builder::new()
        .prefix("sbxt-ww-")
        .tempdir_in("/private/tmp")
        .expect("tempdir in /private/tmp");
    // `SandboxConfig` 没有 `with_mac_workspace`（只有 `MacOsConfig` 上有），
    // 故先 `with_mac_preset` 再用公开字段 `macos` 链式补一项。
    let mut cfg = SandboxConfig::default().with_mac_preset(MacPreset::WorkspaceWrite);
    cfg.macos = cfg.macos.with_mac_workspace(ws.path().to_path_buf());
    let sb = sandbox(cfg);

    let (code, stderr, reason) = run_sh(&sb, ws.path(), "echo x > f && echo WROTE");
    assert_ok(&reason, &stderr, "D2 write workspace");
    assert_eq!(
        code, 0,
        "D2 write workspace should exit 0 (stderr: {stderr})"
    );
    assert!(
        ws.path().join("f").exists(),
        "D2: workspace write must have produced the file on the host"
    );
}

/// D3：FullAccess 下任意写通过（`(allow default)`，只剩 setuid / SIP 硬限制）。
///
/// FullAccess 会跳过凭据保护且没有「应当被拒」的写探针 ⇒ canary 落到优先级 3，
/// 构造期在 stderr 打印一条 inconclusive 警告。这是**预期**行为，不影响断言。
#[test]
fn d3_full_access_write_tmpdir_ok() {
    require_seatbelt!();

    let sb = sandbox(SandboxConfig::default().with_mac_preset(MacPreset::FullAccess));
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = std::env::temp_dir().join(format!(".seabox-fa-{}", std::process::id()));
    let target_s = target.to_string_lossy().into_owned();

    let script = format!("echo x > '{target_s}' && echo WROTE");
    let (code, stderr, reason) = run_sh(&sb, tmp.path(), &script);
    let existed = target.exists();
    let _ = std::fs::remove_file(&target); // 清理

    assert_ok(&reason, &stderr, "D3 write under FullAccess");
    assert_eq!(code, 0, "D3 write should exit 0 (stderr: {stderr})");
    assert!(existed, "D3: FullAccess write should have created the file");
}

// ---------------------------------------------------------------------------
// D4 / D5：凭据读写（内置 denylist：~/.ssh 等 8 项）
// ---------------------------------------------------------------------------

/// D4：ReadOnly 下读 `~/.ssh/id_rsa` 必须被拒（`deny_read` 命中凭据清单）。
///
/// 跳过条件：目标键文件不存在（不存在时内建读探针也没有区分力：沙箱内外都是
/// ENOENT）。本机通常只有 `id_ed25519`，故按「`id_rsa` → `id_ed25519`」顺序
/// 取第一个**存在且可读**的私钥，保证这条断言在真实机器上跑得起来。
#[test]
fn d4_readonly_read_ssh_key_denied() {
    require_seatbelt!();

    let ssh = PathBuf::from(home()).join(".ssh");
    let Some(key) = ["id_rsa", "id_ed25519"]
        .iter()
        .map(|name| ssh.join(name))
        .find(|p| p.is_file() && std::fs::read(p).is_ok())
    else {
        eprintln!("no readable ~/.ssh private key, skipping test");
        return;
    };

    let sb = sandbox(SandboxConfig::default().with_mac_preset(MacPreset::ReadOnly));
    let tmp = tempfile::tempdir().expect("tempdir");

    let script = format!("cat '{}' > /dev/null", key.display());
    let (code, stderr, reason) = run_sh(&sb, tmp.path(), &script);

    assert_seatbelt_denied(&reason, &stderr, "D4 read ~/.ssh private key");
    assert_ne!(code, 0, "denied read should not exit 0 (stderr: {stderr})");
    assert!(
        stderr.contains("Operation not permitted"),
        "D4: Seatbelt denial marker expected in stderr, got: {stderr}"
    );
}

/// D5：ReadOnly 下**写** `~/.ssh/authorized_keys` 必须被拒（凭据清单同时封写）。
///
/// 安全约束：绝不真的写宿主凭据目录。
/// - 目标文件已存在 ⇒ 直接跳过（避免任何改写风险）；
/// - 命令是 `echo x > <path>`：若策略真失效，最坏结果是往**不存在**的这个名字
///   新建一个文件；发现后立刻删除并按失败上报（fail-closed，宁可测试红）。
#[test]
fn d5_readonly_write_authorized_keys_denied() {
    require_seatbelt!();

    let target = PathBuf::from(home()).join(".ssh").join("authorized_keys");
    if target.exists() {
        eprintln!(
            "{} already exists, skipping test to avoid clobbering it",
            target.display()
        );
        return;
    }

    let sb = sandbox(SandboxConfig::default().with_mac_preset(MacPreset::ReadOnly));
    let tmp = tempfile::tempdir().expect("tempdir");

    let script = format!("echo x > '{}'", target.display());
    let (code, stderr, reason) = run_sh(&sb, tmp.path(), &script);

    // 无论断言如何，先清掉「本不该出现」的文件（仅当沙箱失效时才会存在）
    if target.exists() {
        let _ = std::fs::remove_file(&target);
        panic!(
            "D5: Seatbelt failed to block a write to {} (stderr: {stderr})",
            target.display()
        );
    }

    assert_seatbelt_denied(&reason, &stderr, "D5 write ~/.ssh/authorized_keys");
    assert_ne!(code, 0, "denied write should not exit 0 (stderr: {stderr})");
}

// ---------------------------------------------------------------------------
// F1：fd 逃逸回归（Seatbelt 是 fd 快照语义，必须靠 pre_exec 清扫继承 fd）
// ---------------------------------------------------------------------------

/// F1：父 shell 先 `exec 9>>host.txt` 打开继承 fd，再套 seabox —— 子进程写 fd 9
/// 必须失败（`9: Bad file descriptor`），宿主文件内容保持不变。
///
/// 为什么用二进制而不用库 API：需要**外层 shell**持有一个非 `FD_CLOEXEC` 的 fd 9，
/// 且这个 fd 必须在 `seabox` 进程里存在（库 API 无法从测试进程伪造这一点，
/// 除非自己 dup 到固定号再拉长生命周期——用 shell 最贴近真实攻击面）。
///
/// 为什么不用 `exec 9>`：`>` 会在打开时 truncate，即便逃逸被挡住，宿主文件也已
/// 被清空，无法区分「被拒绝」与「被清空」。改用 `9>>`（追加）后，只要内容里
/// 没有 `PWNED` 就证明写入没发生 —— 原始内容 `ORIGINAL` 同时充当 sentinel。
///
/// 为什么 `--mac-write <dir>`（放行该目录写）也照样安全：这里**故意**把目录
/// 配成可写，于是唯一还能拦住这次写入的就是 fd 清扫 —— 参数化放开写、仍被拒绝，
/// 正是回归点。
#[test]
fn f1_fd_escape_does_not_touch_host_file() {
    require_seatbelt!();

    let dir = tempfile::tempdir().expect("tempdir");
    let host_file = dir.path().join("host.txt");
    std::fs::write(&host_file, "ORIGINAL\n").expect("seed host file");

    // 脚本（单行）：打开 fd 9 后运行 seabox，让沙箱内的 sh 往 fd 9 写 PWNED
    let script = format!(
        "exec 9>>'{host}'; '{bin}' run --mac-write '{dir}' -- sh -c 'echo PWNED >&9'",
        host = host_file.display(),
        bin = bin(),
        dir = dir.path().display(),
    );

    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg(&script)
        .env("HOME", home())
        .output()
        .expect("run the fd-escape scenario");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    // fd 清扫生效 ⇒ 写入失败 ⇒ seabox 自身非零退出
    assert!(
        !out.status.success(),
        "F1: the fd-9 write should fail inside the sandbox, but the command succeeded \
         (stderr: {stderr})"
    );
    assert!(
        stderr.contains("Bad file descriptor"),
        "F1: expected 'Bad file descriptor' from the swept fd 9, got: {stderr}"
    );

    // 宿主侧：内容既没被追加也没被改写
    let after = std::fs::read_to_string(&host_file).expect("read host file");
    assert!(
        !after.contains("PWNED"),
        "F1: fd escape leaked into the host file, content is now: {after:?}"
    );
    assert_eq!(
        after, "ORIGINAL\n",
        "F1: host file content must be untouched"
    );
}

// ---------------------------------------------------------------------------
// F4：canary 预检 —— 正常策略必须构造成功
// ---------------------------------------------------------------------------

/// F4：canary 在**构造期**跑（`MacSandbox::new` 第 ③ 步），所以「正常 ReadOnly
/// 策略能构造成功」本身就是「canary 判定策略已生效」的证据。
///
/// 反向路径（策略写宽 ⇒ canary `bail!`）需要构造一个语义失效的 profile，
/// 而 `ResolvedPolicy` / `sbpl::build` 都是 `pub(crate)`，外部无法从集成测试注入 ——
/// 该方向由 `src/macos/imp.rs` 的 canary 单元测试与 `src/macos/sbpl.rs` 的内联
/// 单测覆盖。
#[test]
fn f4_canary_passes_for_readonly_policy() {
    require_seatbelt!();

    let cwd = tempfile::Builder::new()
        .prefix("sbxt-canary-")
        .tempdir_in("/private/tmp")
        .expect("tempdir in /private/tmp");

    // 构造成功 = validate + build + canary 全部通过
    let sb = Sandbox::from_config(SandboxConfig::default().with_mac_preset(MacPreset::ReadOnly))
        .expect("F4: canary precheck must pass for a well-formed ReadOnly policy");

    // 附带确认这个沙箱真的在施加策略（拒绝可复现），而不只是一个能构造的空壳
    let (_, stderr, reason) = run_sh(&sb, cwd.path(), "echo x > .seabox_canary_check");
    assert_seatbelt_denied(&reason, &stderr, "F4 post-construction denial probe");
}

// ---------------------------------------------------------------------------
// H5：spawn 的 business-pid 回传 + try_wait 幂等
// ---------------------------------------------------------------------------

/// H5：`spawn` 返回的 `SandboxChild::id()` 必须是宿主命名空间里真实存活的 pid
/// （`sandbox-exec` 是原地 exec，无 pid 映射表），且 `try_wait` 可重复调用不 panic
/// （已收割后幂等返回缓存状态）。
#[test]
fn h5_spawn_business_pid_and_try_wait_idempotent() {
    require_seatbelt!();

    let sb = sandbox(SandboxConfig::default().with_mac_preset(MacPreset::ReadOnly));
    let tmp = tempfile::tempdir().expect("tempdir");
    let spec = CommandSpec::default()
        .with_program("/bin/sleep")
        .with_args(["2"])
        .with_cwd(tmp.path())
        .with_env("PATH", "/usr/bin:/bin")
        .with_timeout(Duration::from_secs(30));

    let mut child = sb.spawn(&spec, StdioConfig::Piped).expect("spawn");
    let pid = child.id();
    assert!(pid > 0, "H5: business pid must be a real pid, got {pid}");

    // 进程还在跑 ⇒ 第一次 try_wait 应为 None（非阻塞）
    match child.try_wait().expect("first try_wait") {
        None => {}
        // 极慢的机器上 sleep 2 也可能已结束；此时不得断言失败，只记录
        Some(status) => eprintln!("H5: child already exited early: {status:?}"),
    }

    // 幂等性：连续两次 try_wait 不得 panic，且不改变已收割语义
    let first = child.try_wait().expect("second try_wait");
    let second = child.try_wait().expect("third try_wait");
    assert_eq!(
        first, second,
        "H5: try_wait must be idempotent once the child is reaped"
    );

    // 收尾：杀掉并收割，避免残留进程
    let _ = child.kill();
    let status = child.wait().expect("wait");
    let after = child.try_wait().expect("try_wait after wait");
    assert_eq!(
        Some(status),
        after,
        "H5: try_wait after wait must return the cached status"
    );
}

// ---------------------------------------------------------------------------
// E 组：网络（刻意为空）
// ---------------------------------------------------------------------------

// E 组（`NetAccess::{Deny,Loopback,Ports,All}` / `inbound_loopback` 的 SBPL 文本）
// 在此文件**不实现**，原因见文件头：`sbpl::build` 与 `ResolvedPolicy` 均为
// `pub(crate)`，外部集成测试拿不到 profile 文本。若强行用二进制断言，只能靠
// 「跑一条注定失败的命令」（如连接 127.0.0.1 上不存在的端口）反推，那是
// 网络连通性测试，不是策略文本断言，且会引入对外网的隐含依赖。
// 该组由 `src/macos/sbpl.rs` 的内联单测覆盖（18 个，含
// `network_loopback_and_ports`、`network_is_orthogonal_to_preset`）。

/// 编译期自检：`NetAccess` 在外部可见（E 组虽跳过，但配置面确实是公开 API，
/// 万一哪天它被降级成 `pub(crate)`，这条断言会让本文件编译失败而不是静默失修）。
#[test]
fn e_group_net_config_type_is_publicly_constructible() {
    // 仅构造，不施加、不联网
    let _deny = NetAccess::Deny;
    let _all = NetAccess::All;
    let _ports = NetAccess::Ports(vec![443, 80]);
    let cfg = SandboxConfig::default().with_mac_net(NetAccess::Loopback);
    let net = cfg.macos.net.as_ref().expect("net config must be set");
    assert_eq!(net.outbound, NetAccess::Loopback);
}
