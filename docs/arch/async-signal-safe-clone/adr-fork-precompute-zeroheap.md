# ADR：多线程 fork 安全 — child 零堆操作

**状态**：已采纳（2026-07-26）

**背景**：seabox 同时提供 CLI 和 crate API。作为 crate 可能被多线程 agent 框架引用，其他线程在 fork() 时可能持内部锁，子进程若碰堆则死锁。

**决策**：fork 前预计算 argv/envp/cwd/exec_path，child 只调纯 syscall，零堆操作。

**具体变动**：

1. 删除 child 中 `clearenv` + `CString::new` + `setenv`（env 通过 `execve` 的 `envp` 参数传递）
2. 删除 child 中 `CString::new(cwd)`（fork 前预计算）
3. 删除 child 中 `cstring_args` + `argv` 构建（fork 前预计算）
4. `execvp` → `execve`（纯 syscall，不搜 PATH）
5. 新增 `resolve_exec_path()` 在 parent 中完成 PATH 搜索
6. 修复外部 BPF 的 `from_raw_parts` 对齐 UB

**结果**：child 在 fork 后无任何堆操作，多线程 fork 安全。

**未选方案**：

| 方案 | 原因 |
|------|------|
| 仅提供 CLI | 保留 crate API，"编译在一起"免外部依赖的价值真实存在 |
| clone() | 与 fork 的锁继承问题相同，不解决实际问题 |
| global lock 序列化 fork | 不需要——child 零堆操作后可并行调用 execute() |
| ChildContext/phase 架构 | 当前过度设计，40 行改动不值得引入裸指针 struct |
