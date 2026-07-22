# execute() 重构：raw fork 替代 Command::spawn

## 问题

`Command::spawn()` + `pre_exec` 受异步信号安全限制，PID ns 需要 double-fork。

## 方案

`libc::fork()` + 手动 clearenv/setenv/chdir/execvp。

## 改动

`src/linux/mod.rs` — execute() 重写
  - Command::spawn → libc::fork
  - pre_exec → if pid == 0 { libc::clearenv; setenv; chdir; ... execvp }
  - waitid → waitpid
  - PID ns: unshare + fork（少一层）
  - 错误处理: 子进程 _exit(1)，父进程检查 waitpid 返回值
