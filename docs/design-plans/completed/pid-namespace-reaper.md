# PID namespace reaper 模型

## 问题

`unshare(CLONE_NEWPID)` 不改变调用进程 PID，且业务进程直接做 PID 1 时：
- SIGTERM 等信号在无 handler 时被屏蔽
- 子进程无人收割 → 僵尸进程

## 方案

三进程模型：unshare(CLONE_NEWPID) → fork() → fork()，PID 1 做 reaper，
业务进程（PID 2）执行用户命令。

## 改动

`src/linux/mod.rs` — ns_ops 拆分 + pre_exec 闭包 double-fork
`tests/namespace_test.rs` — N8 断言 PID=2
