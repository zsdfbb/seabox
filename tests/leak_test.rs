//! 资源泄漏专项测试（阶段 0，设计 §10）。
//!
//! 用公开 `Sandbox::spawn` / `SandboxChild` API 验证 spawn+wait 生命周期下
//! 无资源泄漏：fd 数、线程数稳定，子进程无僵尸，Drop 语义（deny → kill+reap+join，
//! 无 deny → 省线程）。
//!
//! fd / Threads 是**进程级**资源，`cargo test` 同文件内默认并行线程会互相污染
//! 计数，故每个测试先取全局串行锁再测量。

#![cfg(target_os = "linux")]

use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use seabox::config::SandboxConfig;
use seabox::linux::namespaces;
use seabox::linux::seccomp::is_available as seccomp_is_available;
use seabox::{CommandSpec, Sandbox, StdioConfig};

// ---------------------------------------------------------------------------
// 串行锁：进程级资源测量必须互斥
// ---------------------------------------------------------------------------

/// 全局串行锁：leak_test 内各测试共享进程级 fd / 线程资源，须串行测量，
/// 否则并行测试间互相污染计数。
static LEAK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn leak_lock() -> &'static Mutex<()> {
    LEAK_LOCK.get_or_init(|| Mutex::new(()))
}

// ---------------------------------------------------------------------------
// 资源探针
// ---------------------------------------------------------------------------

/// `/proc/self/fd` 打开 fd 数量。
fn fd_count() -> usize {
    fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .count()
}

/// `/proc/self/status` 的 `Threads:` 行（进程内线程数）。
fn thread_count() -> usize {
    let status = fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .map(|rest| rest.trim().parse().expect("parse Threads count"))
        .expect("Threads line present in /proc/self/status")
}

/// 断言本测试进程没有遗留 Z 态（僵尸）直接子进程。
fn assert_no_zombie_children() {
    let test_pid = std::process::id();
    let mut zombies = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
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
        "no zombie children should remain, found: {zombies:?}"
    );
}

// ---------------------------------------------------------------------------
// 基础辅助
// ---------------------------------------------------------------------------

/// 默认配置的 Sandbox（无 landlock / 无 ns / 无 deny）。
fn make_sandbox() -> Sandbox {
    Sandbox::from_config(SandboxConfig::default()).expect("create sandbox")
}

/// mount syscall 号：x86_64=165, aarch64=40（与 seccomp.rs 一致）。
fn mount_nr() -> u32 {
    if cfg!(target_arch = "x86_64") {
        165
    } else if cfg!(target_arch = "aarch64") {
        40
    } else {
        panic!("unsupported target arch for mount_nr")
    }
}

/// 带 seccomp deny（mount）的 Sandbox：spawn 走完整 has_deny 路径
///（USER_NOTIF worker 线程 + listener fd），用于验证这两块资源无泄漏。
fn deny_sandbox() -> Sandbox {
    Sandbox::from_config(SandboxConfig::default().with_seccomp_deny_nr(mount_nr()))
        .expect("create deny sandbox")
}

/// PID ns 探测守卫（spawn_test 同款：userns 路径下 pid-ns 可用，非 root 也成立）。
fn skip_unless_pid_ns() -> bool {
    let pid_ok = namespaces::is_pid_namespace_available();
    let user_ok = namespaces::is_user_namespace_available();
    if !pid_ok && !user_ok {
        eprintln!("neither PID ns nor user ns available, skipping test");
        return true;
    }
    false
}

/// 轮询等待 `/proc/<pid>` 消失（已完全收割）。`true` = 已消失。
fn wait_for_proc_gone(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 等待资源计数稳定：连续 5 次读数相等（间隔 10ms）后才返回。
///
/// libtest 并行测试线程是**懒启动**的（本文件实测：随测试逐个 acquire 锁，
/// 进程 Threads 数从 2 爬到 6），且测试线程在其测试完成后退场。全局锁保证
/// 本文件测试互斥执行（持锁期间无其他测试 body 跑），但启动阶段的线程爬升 /
/// 前一个测试的退场仍会瞬时扰动进程级计数——必须先 settle 再取基线/终值，
/// 否则 before/after 测量落在不同时刻的爬升窗口会误报泄漏。
fn settle<F: Fn() -> usize>(f: F) {
    let mut prev = f();
    let mut stable = 0u32;
    while stable < 5 {
        std::thread::sleep(Duration::from_millis(10));
        let cur = f();
        if cur == prev {
            stable += 1;
        } else {
            stable = 0;
        }
        prev = cur;
    }
}

// ---------------------------------------------------------------------------
// L1: fd 稳定 — spawn+wait×200（Piped + deny）前后 fd 计数相等
// ---------------------------------------------------------------------------

#[test]
fn fd_steady() {
    if !seccomp_is_available() {
        eprintln!("seccomp not available, skipping test");
        return;
    }
    let _guard = leak_lock().lock().unwrap_or_else(|e| e.into_inner());
    let sandbox = deny_sandbox();
    let spec = CommandSpec::default().with_program("true");

    settle(fd_count); // 等 libtest 线程爬升/退场的瞬时 fd 扰动稳定
    let before = fd_count();
    for _ in 0..200 {
        let mut child = sandbox.spawn(&spec, StdioConfig::Piped).expect("spawn");
        let es = child.wait().expect("wait");
        assert_eq!(es.code(), Some(0));
        // drop：join worker（关 listener fd）+ OwnedFd RAII 关 3 个 pipe 端。
        drop(child);
    }
    settle(fd_count);
    let after = fd_count();
    eprintln!("fd_steady: fd before={before} after={after}");
    assert_eq!(
        before, after,
        "fd count must be steady across spawn+wait cycles (leak?)"
    );
}

// ---------------------------------------------------------------------------
// L2: 线程稳定 — spawn+wait×100（deny，每轮 1 个 worker）前后 Threads 相等
// ---------------------------------------------------------------------------

#[test]
fn threads_steady() {
    if !seccomp_is_available() {
        eprintln!("seccomp not available, skipping test");
        return;
    }
    let _guard = leak_lock().lock().unwrap_or_else(|e| e.into_inner());
    let sandbox = deny_sandbox();
    let spec = CommandSpec::default().with_program("true");

    settle(thread_count); // 等 libtest 测试线程爬升稳定
    let before = thread_count();
    for _ in 0..100 {
        let mut child = sandbox.spawn(&spec, StdioConfig::Piped).expect("spawn");
        let es = child.wait().expect("wait");
        assert_eq!(es.code(), Some(0));
        // drop：join worker（子死 → listener POLLHUP → 确定性退出）。
        drop(child);
    }
    settle(thread_count);
    let after = thread_count();
    eprintln!("threads_steady: Threads before={before} after={after}");
    assert_eq!(
        before, after,
        "worker threads must all be joined (no thread leak)"
    );
}

// ---------------------------------------------------------------------------
// L3: 无僵尸 — spawn+wait×100 后子进程已收割（/proc/<wait_pid> 不存在）
// ---------------------------------------------------------------------------

#[test]
fn no_zombie() {
    let _guard = leak_lock().lock().unwrap_or_else(|e| e.into_inner());
    let sandbox = make_sandbox();
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "true"]);

    let mut last_id = None;
    for _ in 0..100 {
        let mut child = sandbox.spawn(&spec, StdioConfig::Piped).expect("spawn");
        let id = child.id();
        let es = child.wait().expect("wait");
        assert_eq!(es.code(), Some(0));
        last_id = Some(id);
        drop(child);
    }
    // 最后一次 wait() 已同步收割：/proc/<wait_pid>（无 pid-ns 时 = fork pid = id()）应不存在。
    let id = last_id.expect("at least one spawn");
    assert!(
        wait_for_proc_gone(id, Duration::from_secs(5)),
        "child {id} must be reaped; /proc/{id} should be gone"
    );
    // 兜底：本测试进程不应有 Z 态直接子进程。
    assert_no_zombie_children();
}

// ---------------------------------------------------------------------------
// L4: Drop 语义 — 带 deny 不 wait 直接 drop → 子进程被 SIGKILL + worker 已 join
// ---------------------------------------------------------------------------

#[test]
fn drop_kill_no_deny_reaps() {
    if !seccomp_is_available() {
        eprintln!("seccomp not available, skipping test");
        return;
    }
    let _guard = leak_lock().lock().unwrap_or_else(|e| e.into_inner());
    settle(thread_count); // 等 libtest 测试线程爬升稳定
    let before_threads = thread_count();

    let sandbox = deny_sandbox();
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "sleep 30"]);
    let child = sandbox.spawn(&spec, StdioConfig::Piped).expect("spawn");
    let id = child.id();
    assert!(
        Path::new(&format!("/proc/{id}")).exists(),
        "child {id} should be alive before drop"
    );

    // 不 wait 直接 drop：has_deny && !reaped → kill(-pgid) + wait() 阻塞收割
    // + join worker（设计 §6.4：不 kill 则子进程下次命中 deny syscall 永久阻塞）。
    drop(child);

    // 子进程已被 kill + 收割：waitpid(WNOHANG) 不再返回 0（仍在运行）。
    // 已由 Drop 的 wait() 收割时返回 -1/ECHILD，仍证明非运行态；关键否定是「不是 0」。
    let mut status: i32 = 0;
    // SAFETY: id 是刚 spawn 的直接子进程；WNOHANG 不阻塞。
    let r = unsafe { libc::waitpid(id as i32, &mut status, libc::WNOHANG) };
    assert_ne!(r, 0, "child {id} must not still be running after drop-kill");

    assert!(
        wait_for_proc_gone(id, Duration::from_secs(5)),
        "child {id} should be fully reaped after drop-kill"
    );

    // worker 已 join：线程数回到基线。
    settle(thread_count);
    let after_threads = thread_count();
    eprintln!("drop_kill_no_deny_reaps: Threads {before_threads} → {after_threads}");
    assert_eq!(
        before_threads, after_threads,
        "worker thread must be joined after drop"
    );
}

// ---------------------------------------------------------------------------
// L5: 仅 pid-ns（无 deny）— spawn 返回后无新增线程（省线程验证）
// ---------------------------------------------------------------------------

#[test]
fn pid_only_no_thread() {
    if skip_unless_pid_ns() {
        return;
    }
    let _guard = leak_lock().lock().unwrap_or_else(|e| e.into_inner());
    let sandbox = Sandbox::from_config(SandboxConfig::default().with_unshare_pid())
        .expect("create pid-ns sandbox");
    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "true"]);

    settle(thread_count); // 等 libtest 测试线程爬升稳定
    let before = thread_count();
    let mut child = sandbox
        .spawn(&spec, StdioConfig::Piped)
        .expect("spawn pid-ns");
    settle(thread_count);
    let after_spawn = thread_count();
    assert_eq!(
        before, after_spawn,
        "pid-ns without deny must not spawn a worker thread (省线程)"
    );

    let es = child.wait().expect("wait");
    assert_eq!(es.code(), Some(0));
    drop(child);
    settle(thread_count);
    let after = thread_count();
    assert_eq!(before, after);
}
