//! spawn / execute 库 API 集成测试（阶段 0）。
//!
//! 覆盖 `Sandbox::execute` 的捕获语义：stdout/stderr 内容、stdin 回显、
//! 超时强制。重点回归 **stdin 非阻塞写与 drain 交错**（D-A12，设计 §6.3）：
//! `cat` + ≥2MB 回显输入必须完成且输出正确（防 64KB pipe 写满死锁，
//! 实测旧实现无限挂起）。
//!
//! 下半部分（设计 §10 测试计划）覆盖 `Sandbox::spawn` + `SandboxChild` 的
//! 生命周期语义：timeout=None、try_wait/wait 幂等、wait_timeout 组杀、
//! pid-ns business-pid（SCM_CREDENTIALS）与整树回收、Fd 注入、手动 Read
//! 取 fd、seccomp 拦截分类、R1 setup 失败清理、CLI SIGINT 转发。

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use seabox::config::SandboxConfig;
use seabox::linux::namespaces;
use seabox::linux::seccomp::is_available as seccomp_is_available;
use seabox::{CommandSpec, DenyMechanism, ExitReason, Sandbox, StdioConfig};

// ---------------------------------------------------------------------------
// 基础辅助
// ---------------------------------------------------------------------------

/// 辅助函数：创建一个默认配置的 Sandbox（无 landlock / 无 ns / 无 deny）。
fn make_sandbox() -> Sandbox {
    Sandbox::from_config(SandboxConfig::default()).expect("create sandbox")
}

/// 构造 `cat`（回显 stdin→stdout）的 CommandSpec。
fn cat_spec() -> CommandSpec {
    CommandSpec::default().with_program("cat")
}

// ---------------------------------------------------------------------------
// execute 捕获基本行为
// ---------------------------------------------------------------------------

#[test]
fn execute_captures_stdout_stderr() {
    let sandbox = make_sandbox();
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "echo out; echo err >&2"]);
    let (output, reason) = sandbox.execute(&spec).expect("execute");

    assert_eq!(output.exit_code, 0);
    assert!(!output.timed_out);
    assert_eq!(output.stdout, b"out\n");
    assert_eq!(output.stderr, b"err\n");
    assert!(reason.is_ok());
}

// ---------------------------------------------------------------------------
// stdin 小输入回归
// ---------------------------------------------------------------------------

#[test]
fn execute_with_stdin_small() {
    let sandbox = make_sandbox();
    let spec = cat_spec().with_stdin("hi");
    let (output, _reason) = sandbox.execute(&spec).expect("execute");

    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, b"hi");
}

// ---------------------------------------------------------------------------
// 空 stdin EOF 回归（重构引入的挂死 bug）
// ---------------------------------------------------------------------------

#[test]
fn execute_no_stdin_reads_stdin_eof() {
    let sandbox = make_sandbox();
    // 无 stdin、无 timeout：子进程 `cat` 读 stdin 必须立即见 EOF 正常退出，
    // 而不是因父进程仍持有 stdin 写端而无限挂起（实测复现：旧实现外层
    // timeout 8 杀，EXIT=124）。
    let spec = cat_spec();
    let (output, reason) = sandbox.execute(&spec).expect("execute");

    assert_eq!(output.exit_code, 0, "cat should read stdin EOF and exit 0");
    assert!(!output.timed_out, "must complete, not hang and time out");
    assert!(output.stdout.is_empty(), "stdout should be empty");
    assert!(reason.is_ok());
}

// ---------------------------------------------------------------------------
// stdin ≥2MB 回显回归（本 bug 的实测复现场景）
// ---------------------------------------------------------------------------

#[test]
fn execute_with_stdin_large() {
    let sandbox = make_sandbox();

    // 2MB 回显输入：超过 64KB pipe 缓冲，逼出「stdout 反压 → 子进程停读 stdin →
    // 父进程写 stdin 阻塞」的死锁路径（旧实现：阻塞 fd 上 EAGAIN 永不触发，无限挂起）。
    let data: Vec<u8> = (0..(2 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
    let spec = cat_spec().with_stdin(data.clone());

    let start = Instant::now();
    let (output, _reason) = sandbox.execute(&spec).expect("execute large stdin");
    let elapsed = start.elapsed();

    assert_eq!(output.exit_code, 0, "cat should exit 0");
    assert!(!output.timed_out, "should complete, not time out");
    assert_eq!(
        output.stdout.len(),
        data.len(),
        "stdout must contain all echoed input"
    );
    assert_eq!(output.stdout, data, "cat must echo stdin verbatim");
    eprintln!(
        "execute_with_stdin_large: {} bytes in {elapsed:?}",
        data.len()
    );
}

// ---------------------------------------------------------------------------
// 超时强制（deadline 兜底必须可达，不依赖 EAGAIN）
// ---------------------------------------------------------------------------

#[test]
fn execute_timeout_enforced() {
    let sandbox = make_sandbox();
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "sleep 30"])
        .with_timeout(Duration::from_millis(200));
    let (output, reason) = sandbox.execute(&spec).expect("execute");

    assert!(output.timed_out, "sleep must be killed by timeout");
    assert_eq!(output.exit_code, 137, "SIGKILL → 128 + 9");
    assert!(!reason.is_ok());
}

// ---------------------------------------------------------------------------
// spawn 生命周期（设计 §10：spawn / SandboxChild）
// ---------------------------------------------------------------------------

// ── 架构相关 syscall 号（与 seccomp.rs 一致）──────────────────────────────

/// mount syscall 号：x86_64=165, aarch64=40。
fn mount_nr() -> u32 {
    if cfg!(target_arch = "x86_64") {
        165
    } else if cfg!(target_arch = "aarch64") {
        40
    } else {
        panic!("unsupported target arch for mount_nr")
    }
}

/// sendmsg syscall 号：x86_64 与 aarch64 都是 46。
///
/// `send_hello` 用 sendmsg 交付 hello（D-A3）。把它加入 deny 清单会让
/// hello 永不到达父进程 → 触发 R1 错误路径（见 `spawn_setup_failure_no_leak`）。
fn sendmsg_nr() -> u32 {
    46
}

// ── pid-ns 辅助 ───────────────────────────────────────────────────────────

/// 带 PID 命名空间的 Sandbox（非 root 下 `from_config` 自动叠加 user ns）。
fn pid_sandbox() -> Sandbox {
    Sandbox::from_config(SandboxConfig::default().with_unshare_pid())
        .expect("create pid-ns sandbox")
}

/// PID ns 探测：本机 `is_pid_namespace_available()` 用裸 `unshare(CLONE_NEWPID)`
/// 探测（非 root 失败），但 userns 路径下 pid-ns 可用（namespace_test N8 同款守卫）。
fn skip_unless_pid_ns() -> bool {
    let pid_ok = namespaces::is_pid_namespace_available();
    let user_ok = namespaces::is_user_namespace_available();
    if !pid_ok && !user_ok {
        eprintln!("neither PID ns nor user ns available, skipping test");
        return true;
    }
    false
}

// ── /proc 探针辅助（轮询带超时上限防挂）────────────────────────────────────

/// 读取 `/proc/<pid>/task/<pid>/children`（直接子进程 pid 列表）。
fn proc_children(pid: u32) -> Vec<u32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).unwrap_or_default();
    s.split_whitespace()
        .filter_map(|p| p.parse().ok())
        .collect()
}

/// 读取 `/proc/<pid>/status` 的 NSpid 行 → [宿主 pid, ns 内 pid, ...]。
fn proc_nspid(pid: u32) -> Option<Vec<u32>> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:"))
        .map(|rest| {
            rest.split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect()
        })
}

/// 进程是否处于 Z（zombie）态。
fn is_zombie(pid: u32) -> bool {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let Some((_, rest)) = stat.rsplit_once(')') else {
        return false;
    };
    rest.split_whitespace().next() == Some("Z")
}

/// 轮询等待 `parent` 出现第一个直接子进程（≤`timeout`）。
fn wait_for_first_child(parent: u32, timeout: Duration) -> Option<u32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(&p) = proc_children(parent).first() {
            return Some(p);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 轮询等待进程消失（或已死 Z 态，即组杀已生效）。`true` = 已不在运行。
fn wait_for_pid_gone(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return true;
        }
        if is_zombie(pid) {
            return true; // 已死（等待 init 收割），组杀已生效
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 断言本测试进程没有遗留 Z 态（僵尸）直接子进程。
///
/// spawn_test.rs 内所有测试都在结束前同步收割（wait / wait_timeout /
/// R1 kill+waitpid），故扫描到 Z 态即视为泄漏。
fn assert_no_zombie_children() {
    let test_pid = std::process::id();
    let mut zombies = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some((_, rest)) = stat.rsplit_once(')') else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // stat 格式：pid (comm) state ppid ... → fields[0]=state, fields[1]=ppid
        if fields.len() < 2 {
            continue;
        }
        if fields[0] == "Z" && fields[1].parse::<u32>() == Ok(test_pid) {
            zombies.push(pid);
        }
    }
    assert!(
        zombies.is_empty(),
        "no zombie children should remain after R1 cleanup, found: {zombies:?}"
    );
}

// ── fd 辅助 ───────────────────────────────────────────────────────────────

/// 创建一对管道，返回 (read, write) 的 `OwnedFd`。
fn pipe2_owned() -> (OwnedFd, OwnedFd) {
    let mut fds = [0i32; 2];
    let r = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(r, 0, "pipe() failed");
    // SAFETY: fds 是 pipe(2) 刚创建的两个有效 fd；移交给 OwnedFd 由 RAII 关闭。
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    (read, write)
}

// ---------------------------------------------------------------------------
// S1: with_no_timeout — timeout None 时命令自然运行完成
// ---------------------------------------------------------------------------

#[test]
fn with_no_timeout_runs() {
    let sandbox = make_sandbox();
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "sleep 0.3"])
        .with_no_timeout(); // D-A8：默认 None，显式清除

    let mut child = sandbox.spawn(&spec, StdioConfig::Piped).expect("spawn");
    // 10s watchdog 仅防挂死；语义断言是 timeout=None → 命令自然跑完且不 timed_out。
    let es = child.wait_timeout(Duration::from_secs(10)).expect("wait");
    assert!(
        !child.timed_out(),
        "no timeout configured → must not be force-killed"
    );
    assert_eq!(es.code(), Some(0), "sleep 0.3 should exit 0");
}

// ---------------------------------------------------------------------------
// S2: try_wait / wait 幂等（CodeWhale 轮询语义）
// ---------------------------------------------------------------------------

#[test]
fn spawn_try_wait_wait_idempotent() {
    let sandbox = make_sandbox();
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "sleep 0.2"]);
    let mut child = sandbox.spawn(&spec, StdioConfig::Piped).expect("spawn");

    // 初始 try_wait：进程仍在运行 → None（WNOHANG 不阻塞）。
    assert_eq!(child.try_wait().expect("try_wait #1"), None);

    // 轮询 try_wait 到 Some（进程退出，首次 WNOHANG 收割）。固定 sleep 0.3 在重载
    // CI 下余量不足可能 flake，改为带 ≤5s 上限的轮询，再断言幂等。
    let deadline = Instant::now() + Duration::from_secs(5);
    let es1 = loop {
        if let Some(es) = child.try_wait().expect("try_wait #2") {
            break es;
        }
        assert!(
            Instant::now() < deadline,
            "child should exit within 5s (poll timeout)"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(es1.code(), Some(0));

    // 幂等：二次 try_wait 返回缓存 Some（不 ECHILD）。
    let es2 = child
        .try_wait()
        .expect("try_wait #3")
        .expect("idempotent Some");
    assert_eq!(es1, es2, "try_wait must be idempotent after reap");

    // wait() 也返回相同 ExitStatus；二次 wait 幂等（reaped 缓存，防 ECHILD）。
    let es3 = child.wait().expect("wait #1");
    let es4 = child.wait().expect("wait #2");
    assert_eq!(es1, es3);
    assert_eq!(es3, es4);
}

// ---------------------------------------------------------------------------
// S3: wait_timeout 到期组杀 + 收割
// ---------------------------------------------------------------------------

#[test]
fn wait_timeout_kills_group() {
    let sandbox = make_sandbox();
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "sleep 100"]);
    let mut child = sandbox.spawn(&spec, StdioConfig::Piped).expect("spawn");
    let id = child.id();
    assert_ne!(id, 0);

    // 等 sh 的子进程（sleep 100）出现，用于验证组杀确实波及孙进程。
    let sleep_pid =
        wait_for_first_child(id, Duration::from_secs(5)).expect("sh should spawn sleep 100");
    eprintln!("wait_timeout_kills_group: sh={id} sleep={sleep_pid}");

    // 300ms 到期 → kill(-pgid) + reap → 返回已退出状态（137）+ timed_out（D-A10）。
    let start = Instant::now();
    let es = child
        .wait_timeout(Duration::from_millis(300))
        .expect("wait_timeout");
    let elapsed = start.elapsed();
    assert!(child.timed_out(), "wait_timeout must mark timed_out");
    assert!(
        elapsed >= Duration::from_millis(300),
        "must wait until the deadline, took {elapsed:?}"
    );
    let eff = es.code().unwrap_or_else(|| 128 + es.signal().unwrap_or(0));
    assert_eq!(eff, 137, "SIGKILL 组杀 → 128 + 9");

    // 进程组被收：sh 与 sleep 孙进程都应消失。
    assert!(
        wait_for_pid_gone(id, Duration::from_secs(5)),
        "sh {id} should be gone"
    );
    assert!(
        wait_for_pid_gone(sleep_pid, Duration::from_secs(5)),
        "sleep {sleep_pid} should be gone"
    );
}

// ---------------------------------------------------------------------------
// S4: pid-ns 下 id() 是 business 宿主 pid（SCM_CREDENTIALS 正确性）
// ---------------------------------------------------------------------------

#[test]
fn pid_ns_id_is_business_host_pid() {
    if skip_unless_pid_ns() {
        return;
    }
    let sandbox = pid_sandbox();
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "sleep 30 & wait"]);
    let mut child = sandbox
        .spawn(&spec, StdioConfig::Piped)
        .expect("spawn pid-ns");

    let id = child.id();
    assert_ne!(id, 0, "business host pid must be non-zero");
    eprintln!("pid_ns_id_is_business_host_pid: id() = {id}");

    // id() 必须是 business 宿主 pid（SCM_CREDENTIALS，D-A2）：/proc/<id> 存在，
    // 且 NSpid 含两列 = [宿主 pid, ns 内 pid]，ns 内 pid == 2（reaper 是 ns PID 1）。
    // 若 SCM_CREDENTIALS 返回的是中间进程 P（宿主 ns）→ NSpid 只有 1 列 → 断言失败；
    // 若返回 reaper A → ns 内 pid == 1 → 断言失败。两条都能抓住回传 bug。
    assert!(
        Path::new(&format!("/proc/{id}")).exists(),
        "business host pid {id} must be alive in /proc"
    );
    let nspid = proc_nspid(id).expect("NSpid line in /proc/<id>/status");
    assert!(
        nspid.len() >= 2,
        "business must be inside a pid ns → NSpid ≥2 columns: {nspid:?}"
    );
    assert_eq!(
        nspid.first().copied(),
        Some(id),
        "outermost NSpid column must equal id(): {nspid:?}"
    );
    assert_eq!(
        nspid.last().copied(),
        Some(2),
        "business must be ns PID 2 (reaper is ns PID 1): {nspid:?}"
    );

    // 清理：kill 整树 + wait 收割。
    child.kill().expect("kill");
    let es = child.wait().expect("wait");
    eprintln!(
        "pid_ns_id_is_business_host_pid: cleanup exit {:?}",
        es.code()
    );
}

// ---------------------------------------------------------------------------
// S5: pid-ns 下 kill() 整树回收（business + sleep 孙进程）
// ---------------------------------------------------------------------------

#[test]
fn pid_ns_kill_group() {
    if skip_unless_pid_ns() {
        return;
    }
    let sandbox = pid_sandbox();
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "sleep 30 & wait"]);
    let mut child = sandbox
        .spawn(&spec, StdioConfig::Piped)
        .expect("spawn pid-ns");
    let id = child.id();
    assert_ne!(id, 0);

    // 找到 sleep 孙进程（business=sh 的子进程，同一进程组）。
    let sleep_pid =
        wait_for_first_child(id, Duration::from_secs(5)).expect("sh should spawn sleep 30");
    eprintln!("pid_ns_kill_group: business={id} sleep={sleep_pid}");

    // kill() → kill(-kill_pid) 组杀 B + 子孙（sleep 在 B 的进程组内）→ wait 快速返回。
    let start = Instant::now();
    child.kill().expect("kill group");
    let es = child.wait().expect("wait");
    let elapsed = start.elapsed();
    eprintln!(
        "pid_ns_kill_group: kill+wait in {elapsed:?} exit={:?}",
        es.code()
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "kill+wait must tear down the tree fast, took {elapsed:?}"
    );
    let eff = es.code().unwrap_or_else(|| 128 + es.signal().unwrap_or(0));
    assert_eq!(
        eff, 137,
        "business killed by SIGKILL → reaper 链逐层转发 137"
    );

    // 整树回收：business 与 sleep 孙进程都消失（reaper 链逐层退出）。
    assert!(
        wait_for_pid_gone(id, Duration::from_secs(5)),
        "business {id} should be gone"
    );
    assert!(
        wait_for_pid_gone(sleep_pid, Duration::from_secs(5)),
        "sleep {sleep_pid} should be gone"
    );
}

// ---------------------------------------------------------------------------
// S6: StdioConfig::Fd 预开 fd 注入（子进程 0/1/2 接到指定 fd）
// ---------------------------------------------------------------------------

#[test]
fn stdio_fd_inject() {
    let sandbox = make_sandbox();
    // 三条管道：child stdin 接读端 / stdout 接写端 / stderr 接写端。
    let (stdin_r, stdin_w) = pipe2_owned();
    let (stdout_r, stdout_w) = pipe2_owned();
    let (stderr_r, stderr_w) = pipe2_owned();

    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "read x; echo \"got:$x\" >&2; echo \"out:$x\""]);
    let mut child = sandbox
        .spawn(
            &spec,
            StdioConfig::Fd {
                stdin: stdin_r.as_raw_fd(),
                stdout: stdout_w.as_raw_fd(),
                stderr: stderr_w.as_raw_fd(),
            },
        )
        .expect("spawn fd-inject");

    // 父进程关闭子进程侧的副本（否则读端永不 EOF）。
    drop(stdin_r);
    drop(stdout_w);
    drop(stderr_w);

    // 写 stdin → 关写端（EOF）。
    let mut stdin_file = std::fs::File::from(stdin_w);
    stdin_file.write_all(b"hello\n").expect("write stdin");
    drop(stdin_file);

    // 读 stdout / stderr（子进程退出 → EOF）。
    let mut out = Vec::new();
    std::fs::File::from(stdout_r)
        .read_to_end(&mut out)
        .expect("read stdout");
    let mut err = Vec::new();
    std::fs::File::from(stderr_r)
        .read_to_end(&mut err)
        .expect("read stderr");

    let es = child.wait().expect("wait");
    assert_eq!(es.code(), Some(0), "sh should exit 0");
    assert_eq!(out, b"out:hello\n", "stdout fd must receive child stdout");
    assert_eq!(err, b"got:hello\n", "stderr fd must receive child stderr");
}

// ---------------------------------------------------------------------------
// S7: Piped + take_stdout 手动 Read（CodeWhale reader-thread 模式）
// ---------------------------------------------------------------------------

#[test]
fn take_fds_manual_read() {
    let sandbox = make_sandbox();
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "echo manual-output"]);
    let mut child = sandbox.spawn(&spec, StdioConfig::Piped).expect("spawn");

    // CodeWhale reader-thread 模式：take_stdout 手动 Read 到 EOF。
    let stdout = child.take_stdout().expect("take_stdout");
    let mut out = Vec::new();
    std::fs::File::from(stdout)
        .read_to_end(&mut out)
        .expect("read stdout");

    let stderr = child.take_stderr().expect("take_stderr");
    let mut err = Vec::new();
    std::fs::File::from(stderr)
        .read_to_end(&mut err)
        .expect("read stderr");

    let es = child.wait().expect("wait");
    assert_eq!(es.code(), Some(0));
    assert_eq!(out, b"manual-output\n");
    assert!(err.is_empty());
}

// ---------------------------------------------------------------------------
// S8: seccomp 拦截 → blocked() Some → classify_exit Denied(Seccomp)
// ---------------------------------------------------------------------------

#[test]
fn spawn_blocked_classify() {
    if !seccomp_is_available() {
        eprintln!("seccomp not available, skipping test");
        return;
    }
    let sandbox = Sandbox::from_config(SandboxConfig::default().with_seccomp_deny_nr(mount_nr()))
        .expect("create sandbox with seccomp deny");

    let mut args = vec![mount_nr().to_string()];
    args.extend(["0", "0", "0", "0", "0", "0"].map(String::from));
    let spec = CommandSpec::default()
        .with_program(env!("CARGO_BIN_EXE_syscall_probe"))
        .with_args(args);

    let mut child = sandbox
        .spawn(&spec, StdioConfig::Piped)
        .expect("spawn syscall_probe");
    let es = child.wait().expect("wait");

    // USER_NOTIF 拦截：worker 记录 (nr, arch)；reap 后必为最终值（设计 §6.2）。
    let blocked = child
        .blocked()
        .expect("blocked must be Some after interception");
    assert_eq!(
        blocked.0,
        mount_nr(),
        "intercepted syscall nr must match deny list"
    );

    let reason = sandbox.classify_exit(es.code().unwrap_or(-1), Some(blocked));
    assert!(
        matches!(
            reason,
            ExitReason::Denied {
                mechanism: DenyMechanism::Seccomp,
                ..
            }
        ),
        "classify must yield Denied(Seccomp), got {reason:?}"
    );
}

// ---------------------------------------------------------------------------
// S9: R1 spawn setup 失败错误路径清理（spawn 返回 Err + 无僵尸）
// ---------------------------------------------------------------------------

#[test]
fn spawn_setup_failure_no_leak() {
    if !seccomp_is_available() {
        eprintln!("seccomp not available, skipping test");
        return;
    }
    // deny sendmsg：child 的 send_hello 走 sendmsg，被 USER_NOTIF 拦截后阻塞
    //（worker 尚未 spawn、父进程阻塞在 recv_hello）→ poll ≤2s 超时 → R1：
    // kill + waitpid 收割 → spawn 返回 Err。覆盖 R1 错误路径清理（无僵尸/孤儿）。
    let sandbox = Sandbox::from_config(SandboxConfig::default().with_seccomp_deny_nr(sendmsg_nr()))
        .expect("create sandbox with seccomp deny");
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "true"]);

    let start = Instant::now();
    let err = match sandbox.spawn(&spec, StdioConfig::Piped) {
        Ok(_) => panic!("spawn must fail (R1: child failed during setup)"),
        Err(e) => e,
    };
    let elapsed = start.elapsed();
    eprintln!("spawn_setup_failure_no_leak: spawn Err after {elapsed:?}: {err:#}");

    assert!(
        err.to_string().contains("failed during setup"),
        "error should mark setup failure, got: {err:?}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "spawn must be bounded (≤2s poll + cleanup), took {elapsed:?}"
    );

    // 无僵尸：R1 已 kill+waitpid 收割，本测试进程的直接子进程不应有 Z 态。
    assert_no_zombie_children();
}

// ---------------------------------------------------------------------------
// S10: CLI SIGINT 转发（seabox run 收到 SIGINT → 子进程组被收 + 退出 130）
// ---------------------------------------------------------------------------

#[test]
fn cmd_run_sigint_forward() {
    let bin = env!("CARGO_BIN_EXE_seabox");
    let mut cmd = Command::new(bin);
    cmd.args(["run", "--", "sh", "-c", "sleep 100"]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    let mut seabox = cmd.spawn().expect("spawn seabox CLI");
    let seabox_pid = seabox.id();

    // 等 seabox 的子进程（sh = sandbox business，process_group 组长）出现。
    // sh 存在 ⟹ cmd_run 已完成 spawn 且 CHILD_PGID 已 store → handler 就绪。
    let sh_pid = wait_for_first_child(seabox_pid, Duration::from_secs(5))
        .expect("seabox should spawn sandbox child");
    // 等 sh 的子进程（sleep 100）出现。
    let sleep_pid =
        wait_for_first_child(sh_pid, Duration::from_secs(5)).expect("sh should spawn sleep 100");
    eprintln!("cmd_run_sigint_forward: seabox={seabox_pid} sh={sh_pid} sleep={sleep_pid}");

    // 发 SIGINT → cmd_run forward handler 转发到子进程组（kill(-pgid, SIGINT)）
    // + _exit(128 + 2 = 130)（GNU 惯例，设计 §6.5）。
    // SAFETY: seabox_pid 是刚 spawn 的有效进程。
    let r = unsafe { libc::kill(seabox_pid as i32, libc::SIGINT) };
    assert_eq!(r, 0, "kill(SIGINT) seabox should succeed");

    let status = seabox.wait().expect("wait seabox CLI");
    assert_eq!(
        status.code(),
        Some(130),
        "seabox should exit 128+SIGINT=130, got {:?}",
        status.code()
    );

    // 子进程组被收：sh 与 sleep 都应消失。
    assert!(
        wait_for_pid_gone(sh_pid, Duration::from_secs(5)),
        "sandbox child sh={sh_pid} should be gone after SIGINT forward"
    );
    assert!(
        wait_for_pid_gone(sleep_pid, Duration::from_secs(5)),
        "sleep={sleep_pid} should be gone after SIGINT forward"
    );
}
