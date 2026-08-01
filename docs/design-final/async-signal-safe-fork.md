# 多线程安全 fork — 架构设计方案

## 问题

`seabox` 作为 crate 可能被多线程的 agent 框架引用。其他线程在 `fork()` 时可能持有 malloc 锁，子进程若碰堆就会死锁。

**关键约束**：子进程从 fork 到 execve 之间必须零堆操作，只调纯 syscall。

## 候选方案对比

| 维度 | A：最小复杂度 | B：可扩展优先 | C：性能优先 |
|------|-------------|-------------|-----------|
| 代码改动量 | ~40 行，全在 mod.rs | ~200 行，新 child.rs 模块 | ~60 行，PreparedExec 结构体 |
| 新模块 | 无 | `child.rs` + `ChildSetup`/`ChildContext` | 无（PreparedExec 内联） |
| 分配优化 | 基本（Vec<CString>） | 基本 | 可选零拷贝 envp（连续 buffer） |
| 子进程代码 | 删除 unsafe 调用，保留原结构 | 提取为 phase 函数 | 与 A 类似，更关注分配次数 |
| 添加新功能成本 | 改 mod.rs | 加新 phase 即可 | 改 mod.rs |
| BPF 对齐修复 | ✅ 包含 | ✅ 包含 | ✅ 包含 |
| 可测性 | 好（原有测试不变） | 更好（phase 可独立测） | 好 |
| 风险 | 低（改动集中） | 中（提取逻辑可能引入回归） | 低 |

## 推荐方案：A（最小复杂度） + C（零拷贝 envp 可选）

### 理由

1. **改动量最小**：不需要引入新模块。所有改动都在 `src/linux/mod.rs`，约 40 行。
2. **风险最低**：不改变现有函数/模块结构，只把堆操作移到 fork 前。
3. **保留扩展路径**：未来如果需要 phase 式架构，可以在 A 的基础上提取，不影响当前。
4. **B 方案的 ChildContext 指针生命周期管理太复杂**：`*const *const c_char` 裸指针需要非常小心地确保 backing storage 存活的证明，对当前阶段过度设计。

### 改动内容

### fork 前（`execute()` 中，fork 调用之前）

```rust
// 预计算 envp
let _envp_cstrings: Vec<CString> = spec.env
    .iter()
    .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap_or_default())
    .collect();
let mut envp: Vec<*const libc::c_char> =
    _envp_cstrings.iter().map(|s| s.as_ptr()).collect();
envp.push(std::ptr::null());

// 预计算 argv
let _argv_cstrings: Vec<CString> = std::iter::once(spec.program.clone())
    .chain(spec.args.clone())
    .map(|a| CString::new(a).unwrap_or_default())
    .collect();
let mut argv: Vec<*const libc::c_char> =
    _argv_cstrings.iter().map(|a| a.as_ptr()).collect();
argv.push(std::ptr::null());

// 预计算 cwd
let cwd_c = CString::new(cwd.to_str().unwrap_or("/")).unwrap_or_default();

// 解析程序路径（execve 不搜 PATH）
let exec_path: CString = resolve_exec_path(&spec.program);

// 对齐外部 BPF（修复对齐 UB）
let aligned_ext_filters: Vec<Vec<sock_filter>> = self.config.seccomp_filter_bytes
    .iter()
    .map(|bytes| {
        assert!(bytes.len() % size_of::<sock_filter>() == 0);
        bytes.chunks(size_of::<sock_filter>())
            .map(|chunk| unsafe { ptr::read_unaligned(chunk.as_ptr() as *const sock_filter) })
            .collect()
    })
    .collect();
```

### child 中删除

- `clearenv()` + `setenv()` 循环
- `CString::new(cwd_str)`
- `cstring_args` + `argv` 构建
- `execvp()`

### child 中替换为

```rust
if libc::chdir(cwd_c.as_ptr()) != 0 { libc::_exit(1); }
// ... 中间不变 ...
libc::execve(exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
libc::_exit(127);
```

### resolve_exec_path 辅助函数

```rust
fn resolve_exec_path(program: &str) -> CString {
    if program.contains('/') {
        return CString::new(program).unwrap_or_default();
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let full = dir.join(program);
            if full.is_file() {
                if let Some(s) = full.to_str() {
                    return CString::new(s).unwrap_or_default();
                }
            }
        }
    }
    CString::new(program).unwrap_or_default()
}
```

### 外部 BPF 修复

当前 `from_raw_parts` 将 `Vec<u8>` 强转 `&[sock_filter]`（对齐 UB），改为 fork 前对齐复制。child 中用对齐后的 `&[sock_filter]`。

### 安全性说明

- child 在 fork 后**无任何堆操作**：所有 `CString::new`、`Vec::push`、`format!` 都在 fork 前
- `execve` 是纯 syscall（不搜 PATH、不碰 environ、不调用 malloc）
- 即使其他线程在 fork 时持有任意内部锁，child 也不会去碰同一把锁
- semanticaly 等价于当前行为（env 从 clearenv+setenv 变为 execve envp）

### 验证

```bash
cargo test
cargo run -- run --clearenv --env FOO=bar -- sh -c 'echo $FOO'
cargo test --test seccomp_test
cargo test --test namespace_test
cargo test --test landlock_test
```

### 未采纳方案的被否理由

| 方案 | 被否理由 |
|------|---------|
| bubblewrap 风格（parent clearenv） | 多线程下 parent clearenv 本身不是线程安全的 |
| clone() 迁移 | 不改 clone。fork 和 clone 的锁继承问题相同，clone 不解决任何问题 |
| CLONE_VM + vfork | 不可行，child 需要修改栈上数据后 exec，共享地址空间会破坏 parent |
| 全局序列化锁 | 不必要。child 零堆操作后不需要锁，可完全并行调用 |
| ChildContext + phase 架构 | 过度设计。当前改动量 40 行，扩展性好，不需要引入裸指针 struct |
