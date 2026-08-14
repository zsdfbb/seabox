//! 平台无关的 `execute` 组合逻辑（drain + 超时 + kill）。
//!
//! `run_to_output` 由 [`SandboxImpl::execute`] 的默认实现调用：
//! `self.spawn(spec, StdioConfig::Piped)?` 后委托本函数，一次性完成
//! `drain(stdout/stderr) + stdin 写入 + 超时强制 + 退出码换算`。
//!
//! 全部为单线程 drain loop（D-A12，0 额外线程）：非阻塞 pipe + poll +
//! `waitpid(WNOHANG)`，边读边 wait，防 64KB pipe 缓冲写满死锁。

use std::os::unix::io::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use anyhow::Context;

use crate::{CommandOutput, CommandSpec, SandboxChild};

/// 平台无关 execute：`drain(stdout/stderr) + stdin 写 + 超时强制 + 退出码换算` 的一次性组合。
///
/// # 流程（设计 §6.3 / D-A12）
///
/// 1. `child` 必须来自 `spawn(StdioConfig::Piped)`（否则 take_stdout 为 None，报错）。
/// 2. stdout/stderr 读端 + stdin 写端**全部置非阻塞**（stdin 不置非阻塞则 pipe 满时
///    `write(2)` 在内核内阻塞，EAGAIN→poll 逻辑变死代码，deadline 永不触发 → 死锁）。
/// 3. **单循环交错**：`drain(stdout/stderr) + stdin 非阻塞写 + try_wait + deadline`
///    在同一 loop 内交替执行，边读边 wait——先读解除子进程 stdout 反压，子进程才能继续
///    读 stdin，父进程才能继续写（防 >64KB 回显输入死锁，实测 ≥2MB 验证）。
/// 4. deadline 检查**在 loop 内可达**，不依赖 EAGAIN 触发：到点 `kill()` + `wait()`，
///    `timed_out = true`。
/// 5. 子进程死后读净两读端到 EOF；组装 `CommandOutput`；
///    `exit_code`：`ExitStatus.code()`（正常）或 `128 + signal`。
pub(crate) fn run_to_output(
    child: SandboxChild,
    spec: &CommandSpec,
) -> anyhow::Result<CommandOutput> {
    let mut child = child;

    // ── 取三个 stdio 端并全部置非阻塞（spawn 已按 Piped 创建）────────
    let stdout = child
        .take_stdout()
        .ok_or_else(|| anyhow::anyhow!("execute: stdout pipe missing (spawn must be Piped)"))?;
    let stderr = child
        .take_stderr()
        .ok_or_else(|| anyhow::anyhow!("execute: stderr pipe missing (spawn must be Piped)"))?;
    let mut stdin_w = child.take_stdin();

    // ── stdin 输入视图：None → 不写（立即关写端）；Some → 与 drain 交错写入 ──
    let stdin_data: &[u8] = spec.stdin.as_deref().unwrap_or(&[]);
    let mut stdin_pos = 0usize;
    // 空输入（None 或空串）：父进程立即 drop 写端 → 子进程读 stdin 立即见 EOF。
    // 否则保留写端，与 drain 交错非阻塞写入，写完后才关（见 loop 内 drop(stdin_w.take())）。
    let mut stdin_done = if stdin_data.is_empty() {
        drop(stdin_w.take()); // 关写端 → 子进程读 stdin 立即 EOF，不再挂起
        true
    } else {
        false
    };

    set_nonblocking(stdout.as_raw_fd())?;
    set_nonblocking(stderr.as_raw_fd())?;
    if let Some(w) = stdin_w.as_ref() {
        set_nonblocking(w.as_raw_fd())?;
    }

    let deadline = spec.timeout.map(|d| Instant::now() + d);

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut timed_out = false;
    // 循环内两条 break 路径都会赋值（try_wait 命中 / 超时 kill），仅一次写入。
    let exit_status: Option<ExitStatus>;

    // ── 单循环交错：stdout/stderr 读 + stdin 写 + wait + deadline ──────
    loop {
        // 先读，解除子进程 stdout 反压（子进程才能继续读 stdin，防回显死锁）。
        drain_available(stdout.as_raw_fd(), &mut stdout_buf)?;
        drain_available(stderr.as_raw_fd(), &mut stderr_buf)?;

        // stdin 非阻塞写：一次 loop 写一部分，与 drain 交错；
        // EAGAIN（pipe 满）→ 等 POLLOUT，下轮 drain 后再写；EPIPE/EOF → 停止（非错误）。
        if !stdin_done {
            let fd = stdin_w
                .as_ref()
                .map(|w| w.as_raw_fd())
                .expect("execute: stdin write end must be present while stdin not fully written");
            // SAFETY: write(2) 纯 syscall；fd 有效且已置非阻塞。
            let n = unsafe {
                libc::write(
                    fd,
                    stdin_data[stdin_pos..].as_ptr() as *const _,
                    stdin_data.len() - stdin_pos,
                )
            };
            if n > 0 {
                stdin_pos += n as usize;
                if stdin_pos == stdin_data.len() {
                    drop(stdin_w.take()); // 写完 → 关写端 → 子进程见 EOF
                    stdin_done = true;
                }
            } else if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // 写满（pipe 缓冲满）→ 下轮 drain 后再写。
                } else if e.raw_os_error() == Some(libc::EPIPE) {
                    drop(stdin_w.take()); // 子进程已退出/关闭读端 → 停止写入（非错误）
                    stdin_done = true;
                } else {
                    return Err(e).context("write stdin in execute");
                }
            } else {
                // n == 0：对端关闭读端。
                drop(stdin_w.take());
                stdin_done = true;
            }
        }

        if let Some(es) = child.try_wait()? {
            exit_status = Some(es);
            break;
        }

        // deadline 兜底：必须在 loop 内可达，不依赖 EAGAIN 触发。
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                child.kill()?;
                let es = child.wait()?;
                timed_out = true;
                exit_status = Some(es);
                break;
            }
        }

        // 每 tick ≈ 1×poll + 1×waitpid = 2 syscall；stdin 未写完时追加 POLLOUT。
        let mut pollfds = Vec::with_capacity(3);
        pollfds.push(libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        pollfds.push(libc::pollfd {
            fd: stderr.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        if !stdin_done {
            if let Some(fd) = stdin_w.as_ref().map(|w| w.as_raw_fd()) {
                pollfds.push(libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                });
            }
        }
        // SAFETY: poll(2) 纯 syscall；fds 均为有效 fd。
        unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 10) };
    }

    // ── 子进程已死 → 读端 EOF；读净残留缓冲 ────────────────────────────
    read_to_end(stdout.as_raw_fd(), &mut stdout_buf)?;
    read_to_end(stderr.as_raw_fd(), &mut stderr_buf)?;

    let exit_code = match exit_status {
        Some(es) => exit_code_from_status(es),
        None => -1,
    };

    Ok(CommandOutput {
        exit_code,
        blocked_syscall: child.blocked(),
        stdout: stdout_buf,
        stderr: stderr_buf,
        timed_out,
    })
}

// ---------------------------------------------------------------------------
// 私有辅助
// ---------------------------------------------------------------------------

/// `exit_code` 换算：正常退出直接取 `code()`；被信号杀死 → `128 + signal`。
fn exit_code_from_status(es: ExitStatus) -> i32 {
    match es.code() {
        Some(code) => code,
        None => 128 + es.signal().unwrap_or(0),
    }
}

/// 置 fd 为非阻塞（`fcntl(F_SETFL, O_NONBLOCK)`）。
fn set_nonblocking(fd: i32) -> anyhow::Result<()> {
    // SAFETY: fcntl(2) 纯 syscall；fd 有效。
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl(F_GETFL) failed in execute");
    }
    // SAFETY: fcntl(2) 纯 syscall。
    let r = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if r < 0 {
        return Err(std::io::Error::last_os_error())
            .context("fcntl(F_SETFL, O_NONBLOCK) failed in execute");
    }
    Ok(())
}

/// 非阻塞读净可用字节；`EAGAIN`（无更多数据）或 EOF 时返回。
fn drain_available(fd: i32, buf: &mut Vec<u8>) -> anyhow::Result<()> {
    let mut chunk = [0u8; 4096];
    loop {
        // SAFETY: read(2) 纯 syscall；fd 有效且非阻塞。
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut _, chunk.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(());
            }
            return Err(e).context("read stdout/stderr in execute");
        }
        if n == 0 {
            return Ok(()); // EOF
        }
        buf.extend_from_slice(&chunk[..n as usize]);
    }
}

/// 阻塞读至 EOF（子进程已死 → pipe EOF）。
fn read_to_end(fd: i32, buf: &mut Vec<u8>) -> anyhow::Result<()> {
    let mut chunk = [0u8; 4096];
    loop {
        // SAFETY: read(2) 纯 syscall。
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut _, chunk.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                // 子进程已死但 pipe 未空（罕见，如托孤进程仍持写端）→ 稍等再读。
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            return Err(e).context("read_to_end stdout/stderr in execute");
        }
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n as usize]);
    }
}
