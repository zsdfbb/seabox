# Execution Plan: seccomp 拒绝消息携带 syscall 名 + category

> **设计来源：** `/home/zs/.claude/plans/snug-churning-kazoo.md`（已批准，`full` 编排）
> **设计归档：** `/home/zs/Develop/seabox/docs/design-plans/feat-seccomp-deny-message.md`（由 design-plan subagent 同步产出）
> **目标格式：**
> ```
> Sandbox denial (Seccomp): blocked syscall='mount' category='mount' nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS
> ```
> **保留 fallback：** handler 未跑 / marker 缺失时仍返回旧消息 `"Blocked by seccomp filter (SIGSYS)"`。

---

## 任务总览

| 任务 ID | 类型 | 文件 | 内容 | 依赖 |
|---|---|---|---|---|
| T1-impl | impl | `src/linux/seccomp.rs` | 重写黑名单结构：黑名单 DIE→TRAP、新增 `Syscall`/`SyscallCategory`/`SYSCALLS`/`BLACKLIST`、BPF 运行时长度；模块内 5 单测改用 `SYSCALLS` | — |
| T1-test | test | `src/linux/seccomp.rs` 单元测试 (`#[cfg(test)] mod tests`) | 验证 filter 长度 = `BLACKLIST.len()+6`；黑名单 JEQ 跳偏移正确；`syscall_name`/`syscall_by_name` 解析正确 | T1-impl |
| T2-impl | impl | `src/linux/mod.rs` | SIGSYS handler + `itoa_into`/`hex_into` helpers + `parse_block_marker`；`classify_exit` 改写（保留 fallback）；`pre_exec` 装 handler | T1-impl |
| T2-test | test | `src/linux/mod.rs` 内新增 `#[cfg(test)] mod` | 验证 `parse_block_marker` 多场景（单行 / 多行取末位 / 空 / 损坏）；`classify_exit` marker 解析与 fallback | T2-impl |
| T3-impl | impl | `tests/seccomp_test.rs` + `tests/deny_detect_test.rs` | 删 `blacklist_name` 镜像表，改用 `seccomp::syscall_name`/`syscall_by_name`；`assert_syscall_blocked` 加 category 断言；新增 3 个 `classify_exit` 富消息测试 | T2-impl |
| T3-test | test | 同上 | 跑 `cargo test --test seccomp_test --test deny_detect_test` 验证全绿 | T3-impl |
| T4-impl | impl | `README.md:113` | 旧消息示例改为新格式 | T2-impl |
| T4-test | MANUAL_ACK_REQUIRED | 人工 | `grep -nR "Blocked by seccomp filter (SIGSYS)" docs/ src/ tests/ examples/` 确认无旧消息残留（README 除外） | T4-impl |
| T5-impl | impl | 全仓编译质量门 | `cargo build` + `cargo clippy -- -D warnings` + `cargo fmt --check` + `cargo test` 全套 | T1-T4 |
| T5-test | test | 全套验证 | 全测试通过 + clippy 零警告 + fmt 已格式化 | T5-impl |
| T6-impl | impl | 手动端到端 | 3 个 `syscall_probe` 验证 stderr 富消息（nr=165 mount / nr=357 bpf / nr=97 unshare） | T5-impl |
| T6-test | MANUAL_ACK_REQUIRED | 人工 | 检查 stderr 内容含 `syscall='X'` `nr=N` `arch=0x...` `signal=SIGSYS` + exit=126 | T6-impl |
| T7-impl | impl | git | `git checkout -b feat/seccomp-deny-message` + commit + push | T6-impl |
| T7-test | MANUAL_ACK_REQUIRED | 人工 | review commit 改动符合预期 + 远端分支就绪 | T7-impl |

**pairing 校验：** 7 个 impl ↔ 7 个 test，每个 impl 都有对应验证（3 个 `MANUAL_ACK_REQUIRED` 已显式标注）。sequential-workflow 合规。

---

## T1-impl：重写 `src/linux/seccomp.rs`

**改动点（diff 视角）：**

- **新增类型**
  - `enum SyscallCategory`：`MountFilesystem` / `DebugTrace` / `Boot` / `KernelModule` / `Namespace` / `BpfLoader` + `tag()` 返回 kebab-case 单字。
  - `struct Syscall { name: &'static str, category: SyscallCategory, nr_x86_64: u32, nr_aarch64: u32 }` + `nr()` 按 `cfg!(target_arch)` 取值。
- **新增静态表**
  - `pub static SYSCALLS: &[Syscall] = &[ ... ]`：13 项，顺序与 `docs/linux-sandbox.md` 对齐。
    - 0: mount (165 / 40), category=MountFilesystem
    - 1: umount2 (166 / 39), category=MountFilesystem
    - 2: pivot_root (155 / 41), category=MountFilesystem
    - 3: chroot (161 / 51), category=MountFilesystem
    - 4: ptrace (101 / 117), category=DebugTrace
    - 5: kexec_load (246 / 104), category=Boot
    - 6: kexec_file_load (320 / 294), category=Boot
    - 7: reboot (169 / 142), category=Boot
    - 8: init_module (175 / 105), category=KernelModule
    - 9: finit_module (313 / 106), category=KernelModule
    - 10: delete_module (176 / 107), category=KernelModule
    - 11: unshare (97 / 97), category=Namespace
    - 12: bpf (357 / 280), category=BpfLoader
  - `pub static BLACKLIST: &[usize] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];`
  - `pub const BLACKLIST_LEN: usize = 13;`
- **查询函数**
  - `pub fn syscall_name(nr: u32) -> Option<&'static str>`
  - `pub fn syscall_by_name(name: &str) -> Option<&'static Syscall>`
- **`build_blacklist_filter()` 改运行时长度**
  - 调用 `target_arch_config()` 取 `(arch, syscall_nrs: Vec<u32>)`。
  - `let n = syscall_nrs.len(); let total_insns = n + 6; let die_insn = total_insns - 1;`
  - 现有 BPF 指令 0/1/2/3（LD arch / JEQ arch / RET KILL_PROCESS→TRAP / LD nr）保留，循环体内 `jt` 用 `die_insn` 计算（每条黑名单 syscall 一条 `JEQ nr, 0, jt`）。
  - **DIE 动作改为 `SECCOMP_RET_TRAP`**（值为 `0x00030000`），触发 SIGSYS 而不是 KILL。
- **保留**：AUDIT_ARCH 常量、`sock_filter`/`sock_fprog`/`build_sock_fprog`/`is_available`、`SECCOMP_RET_ALLOW`。
- **模块内单测改写**
  - `filter_length`：`assert_eq!(filter.len(), BLACKLIST.len() + 6)`
  - `blacklist_jumps_target_die`：循环 `4..(BLACKLIST.len() + 4)`，`die_index = filter.len() - 1`
  - `syscall_nrs_count`：`assert_eq!(BLACKLIST.len(), BLACKLIST_LEN)`
  - `unshare_is_97`：查 `SYSCALLS.iter().find(|s| s.name == "unshare")`，断言 x86_64/aarch64 都是 97
  - `no_duplicate_syscall_nrs`：在 `SYSCALLS` 内对 `nr_x86_64` / `nr_aarch64` 各自查重
  - 新增：`syscall_name_resolves` / `syscall_by_name_resolves` / `blacklist_indices_valid` / `category_tags_are_kebab_case`

**验收标准：**
- `cargo test --lib seccomp` 全绿（含模块内单测）。
- BPF filter 长度随 `BLACKLIST.len()` 动态调整，跨 `x86_64-unknown-linux-musl` / `aarch64-unknown-linux-gnu` 编译通过。

**风险点：**
- SECCOMP_RET_TRAP 触发 SIGSYS，跨进程 SIGSYS 默认 disposition 是 KILL——子进程必须先装 handler，否则啥也来不及写。这点由 T2-impl 在 `pre_exec` 解决。
- aarch64 上某些 syscall 编号跨内核版本略有差异（如 `bpf` 在 4.14 之前不存在），但我们在 `Syscall::nr_aarch64` 表里写死，只支持 5.x+ 内核（与现有策略一致）。

**预计耗时：** 30–45 分钟（含单测）。

---

## T1-test：模块内单测

**改动点（同 T1-impl 内联单测模块）：** 见 T1-impl 第 6 项。

**验收标准：**
- `cargo test --lib seccomp::tests::test_filter_length` 通过。
- `cargo test --lib seccomp::tests::test_blacklist_jumps_target_die` 通过（JEQ 的 `jt` 必须指向 `filter.len() - 1`，否则 BPF 会跳过 TRAP 而直接 KILL）。

**风险点：**
- 单测如果直接 `assert_eq!(filter.len(), 19)`（硬编码 19）会在 `BLACKLIST` 改了之后失效——必须改成 `BLACKLIST.len() + 6`。

**预计耗时：** 15 分钟（与 T1-impl 合并执行）。

---

## T2-impl：重写 `src/linux/mod.rs`

**改动点（diff 视角）：**

- **新增模块私有 helpers**（全部 async-signal-safe，避免堆分配）
  - `fn itoa_into(buf: &mut [u8], mut pos: usize, mut v: u32) -> usize`：手写十进制。
  - `fn hex_into(buf: &mut [u8], mut pos: usize, v: u32) -> usize`：手写小写 hex（8 位补齐 32-bit）。
- **新增 SIGSYS handler**（`extern "C"` + `SA_SIGINFO`）
  - 从 `info` 拿 `nr` / `arch`（优先 `(*info).si_syscall()`，兜底 `(*info)._sifields._sigsys.{si_syscall, si_arch}`）。
  - 写紧凑 marker `BLOCKED-SYSCALL:<nr>:<arch_hex>\n` 到 fd=2，缓冲 `[u8; 64]`，最多 ~30 字节（含前缀）。
  - `libc::_exit(159)`（不能 `exit()`，会跑 atexit handlers / flush buffers）。
- **新增 `parse_block_marker(stderr: &str) -> Option<(u32, u32)>`**
  - 扫描 `stderr.lines()` 所有行，取**最后一个**匹配 `BLOCKED-SYSCALL:<nr>:<arch>` 的结果。
  - 用 `u32::from_str_radix(arch_s.trim(), 16)` 解析 hex；任何失败返回 `None`。
- **`classify_exit` 改写**
  - 检测 `exit_code == 31 || exit_code == 159`（31 = SIGSYS 默认 KILL 退出码，159 = handler 的 `_exit`）。
  - 先调 `parse_block_marker(&stderr)`：
    - 命中：format 富消息（`syscall='X' category='Y' nr=N arch=0x... reason=blacklist signal=SIGSYS`）。
    - 未命中（marker 缺失 / stderr 为空）：**fallback** 到旧消息 `"Blocked by seccomp filter (SIGSYS)"`。
  - Landlock 分支（`mod.rs:241-255`）和其他 stderr 模式分支保持不变。
- **`pre_exec` 装 handler（在 landlock 之后、SECCOMP 之前）**
  - `let mut sa: libc::sigaction = std::mem::zeroed();`
  - `sa.sa_sigaction = sigsys_handler as libc::sighandler_t;`
  - `sa.sa_flags = libc::SA_SIGINFO;`（**只这一个**，不加 `SA_RESTART`）
  - `unsafe { libc::sigemptyset(&mut sa.sa_mask); }`
  - `unsafe { libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut()) }`，失败返回 `io::Error::last_os_error()`。

**验收标准：**
- `cargo test --lib linux::tests` 全绿（见 T2-test）。
- 模块无新 `clippy::warning`（尤其 `clippy::missing_safety_doc` for `extern "C"` fn）。

**风险点：**
- handler 内调用 `libc::write` 必须是 2-arg 形式（POSIX：`ssize_t write(int, const void *, size_t)`），某些 libc 绑定是 3-arg，需要按 `libc` 版本选最稳路径。设计文档已 spec，代码评审时复核。
- `sa_flags` 不能含 `SA_RESTART`，否则 `read(2)` 之类的 syscall 在被 SIGSYS 打断后会自动重试（导致我们看不到 handler 跑过）。这点由代码评审保障。

**预计耗时：** 45–60 分钟。

---

## T2-test：`src/linux/mod.rs` 模块内单测（新增 `#[cfg(test)] mod tests`）

**改动点：** 在 `src/linux/mod.rs` 文件末尾新增：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_block_marker_finds_single_line() { ... }

    #[test]
    fn parse_block_marker_takes_last_match() { ... }

    #[test]
    fn parse_block_marker_returns_none_on_empty() { ... }

    #[test]
    fn parse_block_marker_returns_none_on_garbage() { ... }

    #[test]
    fn classify_exit_returns_rich_message_with_marker() { ... }

    #[test]
    fn classify_exit_falls_back_when_marker_missing() { ... }

    #[test]
    fn classify_exit_preserves_landlock_branch() { ... }  // smoke test
}
```

**验收标准：**
- 7 个测试全绿。
- `classify_exit_returns_rich_message_with_marker` 验证：当 `exit_code=159` 且 stderr=`"BLOCKED-SYSCALL:165:c000003e\n"` 时，返回消息包含 `syscall='mount'` / `category='mount'` / `nr=165` / `arch=0xc000003e` / `signal=SIGSYS`。
- `classify_exit_falls_back_when_marker_missing` 验证：当 `exit_code=159` 且 stderr=`""` 时，返回消息等于 `"Blocked by seccomp filter (SIGSYS)"`。

**预计耗时：** 20 分钟。

---

## T3-impl：`tests/seccomp_test.rs` + `tests/deny_detect_test.rs`

**改动点：**

`tests/seccomp_test.rs`：

- **删除** `fn blacklist_name(nr)` 镜像表（约 30 行）。
- **新增** `fn syscall_name_for_test(nr_str)` 与 `fn category_for_test(nr_str)`（调 `seabox::linux::seccomp::{syscall_name, syscall_by_name}`）。
- **`assert_syscall_blocked` 增加断言**：
  - `out.stderr.contains(&format!("syscall='{name}'"))`
  - `out.stderr.contains(&format!("nr={nr}"))`
  - `out.stderr.contains(&format!("category='{cat}'"))`
  - `out.stderr.contains("arch=0x")`
  - `out.stderr.contains("reason=blacklist")`
  - `out.stderr.contains("signal=SIGSYS")`

`tests/deny_detect_test.rs`：

- **保留** 现有 8 个测试不动（fallback 路径仍要走）。
- **新增** 3 个测试：
  - `exit_159_with_block_marker_returns_rich_message`：stderr=`BLOCKED-SYSCALL:165:c000003e\n`，验证消息含 `syscall='mount'` / `category='mount'` / `nr=165` / `arch=0xc000003e` / `signal=SIGSYS`。
  - `exit_31_with_block_marker_uses_last_line`：stderr 多行，验证取末位匹配（如 `some output\nBLOCKED-SYSCALL:97:c000003e\n` → `syscall='unshare'`）。
  - `exit_159_empty_stderr_falls_back`：stderr 空，验证返回旧消息 `"Blocked by seccomp filter (SIGSYS)"`。

**验收标准：**
- `cargo test --test seccomp_test` 全绿（13 个端到端 + 探针 + 探针跳过逻辑）。
- `cargo test --test deny_detect_test` 全绿（8 个旧 + 3 个新 = 11 个）。

**风险点：**
- `assert_syscall_blocked` 之前可能依赖 stderr 只有旧消息——新断言会让旧测试必须经过富消息路径，但我们改了 handler，一定会经过。
- `blacklist_name` 删除后如果其他测试复用，需同步更新（T1-impl 让 `syscall_name` 直接可用）。

**预计耗时：** 30 分钟。

---

## T3-test：跑集成测试

`cargo test --test seccomp_test --test deny_detect_test -- --nocapture`

**验收：** 24 个测试全绿；任何 skip 信息显式打印（"seccomp not available, skipping"）。

**预计耗时：** 2 分钟（含编译）。

---

## T4-impl：README.md:113 改消息示例

**改动点：** 单行替换：

- **旧：**
  ```
  ... 或 `Sandbox denial (Seccomp): Blocked by seccomp filter (SIGSYS)` 的诊断消息。
  ```
- **新：**
  ```
  ... 或 `Sandbox denial (Seccomp): blocked syscall='mount' category='mount' nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS` 的诊断消息。
  ```

**验收：** 唯一一处旧消息示例被替换；其他 README 章节（如果提到旧消息）也同步替换。

**风险点：** 其他文档可能也用了旧消息字符串（T4-test 用 grep 兜底）。

**预计耗时：** 5 分钟。

---

## T4-test：人工 grep 确认（MANUAL_ACK_REQUIRED）

**操作：**
```bash
grep -rn "Blocked by seccomp filter (SIGSYS)" /home/zs/Develop/seabox/
# 期望：除 README.md 历史 git 记录外，**无任何活代码/测试/示例**命中此字符串。
```

**验收：** 子 agent 报告 grep 结果清单，用户确认。

**预计耗时：** 1 分钟（用户在父会话中确认）。

---

## T5-impl：编译质量门

**操作（一气呵成）：**

```bash
cd /home/zs/Develop/seabox
cargo build --release
cargo clippy -- -D warnings
cargo fmt --check
cargo test                # 全部测试
cargo build --bin syscall_probe
```

**验收标准：**
- `cargo build --release` 成功。
- `cargo clippy -- -D warnings` 零警告。
- `cargo fmt --check` 无 diff（必要时 `cargo fmt` 后重新 commit）。
- `cargo test` 全套全绿（含 skip / 跳过均显式打印）。

**预计耗时：** 5–10 分钟（含编译）。

---

## T5-test：验证

子 agent 将 T5-impl 的输出贴回，用户确认所有质量门通过。

---

## T6-impl：手动端到端（3 个 syscall_probe 验证）

**操作：**

```bash
cd /home/zs/Develop/seabox
cargo build --release
cargo build --bin syscall_probe

# Case 1: mount (nr=165)
./target/release/seabox run --policy full-access -- \
    ./target/debug/syscall_probe 165 0 0 0 0 0 0
# 期望 stderr: "Sandbox denial (Seccomp): blocked syscall='mount' category='mount' nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS"
# 期望 exit: 126

# Case 2: bpf (nr=357)
./target/release/seabox run --policy full-access -- \
    ./target/debug/syscall_probe 357 0 0 0
# 期望: syscall='bpf' category='bpf' nr=357 arch=0xc000003e ...

# Case 3: unshare (nr=97)
./target/release/seabox run --policy full-access -- \
    ./target/debug/syscall_probe 97 0
# 期望: syscall='unshare' category='namespace' nr=97 arch=0xc000003e ...
```

**验收：** 三次 stdout/stderr 内容符合预期；exit=126（main.rs 的 `classify_exit` 把 `Denied` 映射为 126）。

**预计耗时：** 2 分钟。

---

## T6-test：人工检查（MANUAL_ACK_REQUIRED）

子 agent 报告三段 stderr 输出，用户确认。

---

## T7-impl：git 分支 + commit + push

**操作：**

```bash
cd /home/zs/Develop/seabox
git checkout -b feat/seccomp-deny-message
git add -A
git commit -m "feat(seccomp): 富诊断消息携带 syscall 名/号/架构/分类

- 新增 SyscallCategory / SYSCALLS 表查询接口
- SIGSYS handler 写 BLOCKED-SYSCALL marker
- pre_exec 装 SA_SIGINFO handler（无 SA_RESTART）
- classify_exit 解析 marker 生成富消息；marker 缺失时 fallback 到旧消息
- 调整模块内单测 + 集成测试，新增 3 个 classify_exit 富消息测试
- README 示例同步更新"
git push origin feat/seccomp-deny-message
```

**验收：** 远端分支就绪；commit message 单行 50 字符限制；改动符合预期（用户 review 后 push）。

**预计耗时：** 2 分钟。

---

## T7-test：人工 review（MANUAL_ACK_REQUIRED）

用户 review commit 后再 push；子 agent 不自动 push 由用户驱动。

---

## 全局风险与缓解

| 风险 | 缓解 |
|---|---|
| `sa_flags = SA_RESTART` 误设 | 代码评审 + T1-test 验证 handler 在触发后能跑 |
| handler 内堆分配 / 锁 | 全栈缓冲 + 手写 itoa/hex + `write(2)` + `_exit(159)`，无不安全调用 |
| `parse_block_marker` 漏匹配 | 扫描所有行取最后匹配 + 4 个单元测试覆盖（单行/多行/空/损坏） |
| aarch64 BPF 长度常量不对 | 模块内单测 `filter_length` 用 `BLACKLIST.len() + 6` 跨架构验证 |
| deny_detect_test 旧 8 个测试被破坏 | fallback 路径保留 + T2-test 覆盖 `exit_159_empty_stderr_falls_back` |
| README grep 残留旧消息 | T4-test 显式 grep 全仓兜底 |

## 改动汇总

- **重写：** `src/linux/seccomp.rs`（+120 行）
- **大改：** `src/linux/mod.rs`（+100 行，新增 `#[cfg(test)] mod`）
- **中改：** `tests/seccomp_test.rs`（-30 行 `blacklist_name`，+20 行富消息断言）
- **增量：** `tests/deny_detect_test.rs`（+50 行，3 个新测试）
- **微改：** `README.md:113`（单行替换）
- **总计：** 净增约 260 行 / 删 30 行。
