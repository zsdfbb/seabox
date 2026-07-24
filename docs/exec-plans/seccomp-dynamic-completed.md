# 执行计划：动态 seccomp 策略

> 设计文档：`docs/design-plans/seccomp-dynamic.md`
> 状态：**待执行**

---

## 任务清单

### Task 1: 简化 seccomp.rs — 删旧增新

**type=impl**

目标文件：`src/linux/seccomp.rs`

删除：
- `SyscallCategory` 枚举 + `impl SyscallCategory { tag() }`
- `Syscall` struct 的 `category` 字段
- `BLACKLIST` 常量 + `BLACKLIST_LEN`
- `target_arch_config()` 函数
- `build_blacklist_filter()` 函数
- `syscall_by_name()` 函数

修改：
- `Syscall` struct 只保留 `name`, `nr_x86_64`, `nr_aarch64`
- `SYSCALLS` 表条目去掉 `category` 字段
- `install_user_notif_filter` 改名/调整签名，使其接受任意 `&[sock_filter]`（通用化）

新增：
- `build_deny_filter(nrs: &[u32]) -> Vec<sock_filter>` — 为给定 syscall 号构建 USER_NOTIF filter
- `install_plain_filter(filter: &[sock_filter]) -> anyhow::Result<()>` — prctl 直装 filter（无 NEW_LISTENER）
- `current_arch() -> u32` — 返回当前架构的 AUDIT_ARCH 常量（供 build_deny_filter 使用）

更新单元测试：
- 适配新的 filter 构建 API
- 保留 ioctl 编码测试
- 新增 build_deny_filter 长度/结构测试

---

### Task 2: 更新 config.rs — 新增 seccomp 配置字段

**type=impl**

目标文件：`src/config.rs`

SandboxConfig 新增字段：
```rust
pub seccomp_deny_nrs: Vec<u32>,
pub seccomp_filter_bytes: Vec<Vec<u8>>,
```

新增 builder 方法：
- `with_seccomp_deny_nr(nr: u32) -> Self`
- `with_seccomp_filter(bytes: Vec<u8>) -> Self`

更新 Default 实现（两个字段默认为空 Vec）。

---

### Task 3: 重写 mod.rs — 三条执行路径

**type=impl**

目标文件：`src/linux/mod.rs`

修改 `build_bpf_filter()`：
- 返回 `Option<Vec<seccomp::sock_filter>>`
- 当 `config.seccomp_deny_nrs` 非空时调用 `seccomp::build_deny_filter()`
- 否则返回 `None`

重写 `execute()` 的子进程部分（步骤 9-10）：
- 路径 A（有 deny-nrs）：install deny filter (NEW_LISTENER) → sendmsg → install 外部 BPF 循环 → exec
- 路径 B（仅 filter_bytes，无 deny-nrs）：install 外部 BPF 循环 → exec（无 socketpair/worker）
- 路径 C（无 seccomp）：直接 exec

父进程部分：
- 路径 A：spawn worker → recv → waitpid
- 路径 B/C：直接 waitpid

条件化 socketpair 创建：仅在路径 A 时创建。

---

### Task 4: 更新 main.rs — CLI 参数

**type=impl**

目标文件：`src/main.rs`

Cli::Run 新增：
```rust
#[arg(long)]
seccomp_deny_nr: Vec<u32>,

#[arg(long)]
seccomp_filter_fd: Vec<RawFd>,
```

cmd_run() 中：
- 从每个 fd 读取原始字节 → 存入 `config.seccomp_filter_bytes`
- 调用 `config.with_seccomp_deny_nr(nr)` 逐个添加

build_config() 传入新参数。

---

### Task 5: 更新 tests/seccomp_test.rs — 适配新 API

**type=test**

目标文件：`tests/seccomp_test.rs`

改动：
- 现有 13 个 syscall 测试需要加上 `--seccomp-deny-nr <nr>` 才能触发拦截（因为默认不再有黑名单）
- 或：改为用 `--seccomp-deny-nr` 对 mount (165) 做端到端测试
- 新增测试：`no_seccomp_args_no_block` — 无 seccomp 参数时 mount 不被拦
- 新增测试：`deny_nr_blocks_mount` — `--seccomp-deny-nr 165` 拦截 mount
- 新增测试：`deny_nr_multiple_syscalls` — 多个 --seccomp-deny-nr
- 保留 `normal_exit_does_not_hang_worker` 回归测试
- 移除 `full_access_policy_does_not_bypass_seccomp`（seccomp 现在是 opt-in）
- 更新 `verify_seccomp_active()` 探针逻辑（用 --seccomp-deny-nr 代替默认黑名单）

---

### Task 6: 更新 tests/deny_detect_test.rs — 富消息格式

**type=test**

目标文件：`tests/deny_detect_test.rs`

改动：
- `exit_159_with_block_marker_returns_rich_message` 断言去掉 `category='mount'`
- 消息格式变为：`syscall='mount' nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS`
- 其他测试保持不变

---

### Task 7: 更新文档 — linux-sandbox.md + CONTEXT.md

**type=impl**

目标文件：`docs/linux-sandbox.md`, `CONTEXT.md`

- linux-sandbox.md：更新 seccomp 章节，描述新的 CLI 接口和三条路径
- CONTEXT.md：更新 Seccomp Blacklist（不再有默认黑名单）、移除 SyscallCategory 相关词汇

---

## 依赖关系

```
Task 1 (seccomp.rs) → Task 3 (mod.rs) → Task 4 (main.rs)
                                       → Task 5 (tests)
                                       → Task 6 (tests)
Task 2 (config.rs)  → Task 3 (mod.rs)
Task 7 (docs)       → 独立
```

执行顺序：1 → 2 → 3 → 4 → 5 → 6 → 7
