# exec-plan: Async-signal-safe fork（fork 前预计算，child 零堆操作）

## 设计上下文

ADR 0003 + `docs/arch/async-signal-safe-clone/design.md`

**核心约束**：fork 后 child 不能做任何堆操作（不调 malloc/free/realloc），否则多线程下可能死锁。

**解法**：fork 前预计算 argv/envp/cwd/exec_path，child 只调纯 syscall。

## 任务清单

### Task 1: Pre-compute + execve（核心改动）

**文件**：`src/linux/mod.rs`

**改动**：

A. 在 fork 前（`let pid = unsafe { libc::fork() };` 之前）插入预计算：

```rust
// ── 预计算 envp（fork 前堆分配，安全）──
let envp_cstrings: Vec<CString> = spec.env
    .iter()
    .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap_or_default())
    .collect();
let mut envp: Vec<*const libc::c_char> =
    envp_cstrings.iter().map(|s| s.as_ptr()).collect();
envp.push(std::ptr::null());

// ── 预计算 argv ──
let argv_cstrings: Vec<CString> = std::iter::once(spec.program.clone())
    .chain(spec.args.clone())
    .map(|a| CString::new(a).unwrap_or_default())
    .collect();
let mut argv: Vec<*const libc::c_char> =
    argv_cstrings.iter().map(|a| a.as_ptr()).collect();
argv.push(std::ptr::null());

// ── 预计算 cwd ──
let cwd_c = CString::new(cwd.to_str().unwrap_or("/")).unwrap_or_default();

// ── 预计算 exec_path（注意：优先使用 spec.env 中的 PATH）──
let exec_path = resolve_exec_path(&spec.program, &spec.env);
```

B. 新增 `resolve_exec_path` 函数（注意 review 发现的 P0 bug：必须检查 `spec.env` 中的 PATH）：

```rust
/// fork 前解析程序路径。含 '/' 直接返回；否则搜索 PATH。
/// 优先用 spec.env 中的 PATH，fallback 到父进程环境变量。
fn resolve_exec_path(program: &str, spec_env: &HashMap<String, String>) -> CString {
    if program.contains('/') {
        return CString::new(program).unwrap_or_default();
    }
    let path = spec_env
        .get("PATH")
        .map(|s| s.as_str())
        .or_else(|| std::env::var("PATH").ok().as_deref())
        .unwrap_or("/usr/bin:/bin");
    for dir in std::env::split_paths(&path) {
        let full = dir.join(program);
        if full.is_file() {
            if let Some(s) = full.to_str() {
                return CString::new(s).unwrap_or_default();
            }
        }
    }
    CString::new(program).unwrap_or_default()
}
```

C. Child 中删除：

- Lines 259-269: `clearenv()` + `setenv()` 循环（整个第 3 步）
- Lines 272-273: `CString::new(cwd_str)`（替换为使用 fork 前预计算的 `cwd_c`，chdir 调用不变）
- Lines 372-382: cstring_args + argv 构建 + `execvp()`（替换为 `execve`）

D. Child 中 chdir 和 exec 替换：

```rust
// 第 3 步：chdir（用预计算 cwd_c）
if unsafe { libc::chdir(cwd_c.as_ptr()) } != 0 {
    unsafe { libc::_exit(1); }
}
```

```rust
// 第 11 步：execve（用预计算 exec_path、argv、envp）
unsafe {
    libc::execve(exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
}
unsafe { libc::_exit(127); }
```

E. 更新模块顶部的文档注释（`//!`），把 `clearenv + setenv` 相关的行改为描述预计算行为。

F. 在 `use` 块中检查是否需要新增 `use std::collections::HashMap`（resolve_exec_path 需要）。
   当前 `HashMap` 可能已由 `CommandSpec` 引入。

**测试**：
- 现有测试应全部通过，不新增测试文件
- 手动验证：`cargo run -- run --clearenv --env FOO=bar -- sh -c 'echo $FOO'` 输出 bar
- 手动验证：`cargo run -- run --env PATH=/usr/bin -- ls` 能工作
- 手动验证：`cargo run -- run --env PATH=/nonexistent -- ls` 无 PATH 时 fallback 到 parent PATH

---

### Task 2: 外部 BPF 对齐修复

**文件**：`src/linux/mod.rs`

**改动**：

A. fork 前预对齐外部 BPF filter（在 fork 调用之前）：

```rust
// ── 预对齐外部 BPF filter（修复 from_raw_parts 对齐 UB）──
let aligned_ext_filters: Vec<Vec<seccomp::sock_filter>> = self.config.seccomp_filter_bytes
    .iter()
    .map(|bytes| {
        assert!(
            bytes.len() % mem::size_of::<seccomp::sock_filter>() == 0,
            "external BPF bytes length {} is not a multiple of sock_filter size {}",
            bytes.len(),
            mem::size_of::<seccomp::sock_filter>()
        );
        bytes
            .chunks(mem::size_of::<seccomp::sock_filter>())
            .map(|chunk| unsafe {
                std::ptr::read_unaligned(chunk.as_ptr() as *const seccomp::sock_filter)
            })
            .collect()
    })
    .collect();
```

B. child 中（原 lines 354-370）使用 `aligned_ext_filters` 替代 `ext_filter_bytes`：

```rust
// 安装外部 BPF filter（prctl 直装，无 NEW_LISTENER）
for filter in &aligned_ext_filters {
    if seccomp::install_plain_filter(filter).is_err() {
        unsafe { libc::_exit(1); }
    }
}
```

C. child 中原 `Vec<Vec<u8>>` 变体 `ext_filter_bytes` 不再需要（被 `aligned_ext_filters` 替代），删除 `ext_filter_bytes` 的 clone 和使用。

**注意**：需要 `use std::mem;` 已在文件头部 `use std::mem::{self, MaybeUninit};` 中，`mem::size_of` 可用。

**测试**：
- 现有 seccomp 测试覆盖此路径（如果使用了 `--seccomp-filter-fd`）
- `cargo test --test seccomp_test` 确认通过

---

### Task 3: 验证

```bash
cargo build
cargo test
cargo test -- --nocapture --test-threads=1

# 手动冒烟
cargo run -- run --landlock '/:ro' -- cat /etc/passwd
cargo run -- run --clearenv --env FOO=bar -- sh -c 'echo $FOO'
cargo run -- run --seccomp-deny-nr 165 -- ls
cargo run -- run --unshare-all -- ls
```
