# 架构质量分析：多线程安全 fork

分析对象：`docs/arch/async-signal-safe-clone/design.md`
关注维度：全量

---

## 各维度评分

| 维度 | 评分 | 说明 |
|------|:----:|------|
| 可行性 | 🟢 绿 | 方案已经在 `posix_spawn()` 中验证，技术上无不确定性 |
| 可维护性 | 🟡 黄 | 改动集中，但有一个维护陷阱需要注意 |
| 可理解性 | 🟢 绿 | 核心概念简单，文档充分，diff 小 |
| 性能与可靠性 | 🟢 绿 | child 路径零堆操作，无性能退化；有一个 PATH 查找 bug |

---

## 可行性 🟢

- 依赖 `execve`（POSIX.1-2001）、`fork`、`unshare`、`prctl`、`seccomp`、`landlock`——都是 Linux 标准 syscall
- 预计算模式已在 `posix_spawn()` 和 bubblewrap 中验证
- `CString::new + Vec<*const c_char>` 模式是 Rust 调 `execve` 的标准做法
- 不存在依赖或技术不确定性风险
- 实现周期：一个 session

---

## 可维护性 🟡

### 好的方面

- 改动集中在 `src/linux/mod.rs`，不扩散到其他模块
- 不引入新模块/新类型/新 trait
- 约束已固化到 ADR 0003 + CONTEXT.md + CLAUDE.md

### ⚠️ 维护陷阱 1：悬垂指针风险

```rust
// 当前设计中，_envp_cstrings 和 envp 在同一栈帧
let _envp_cstrings: Vec<CString> = ...;
let mut envp: Vec<*const libc::c_char> =
    _envp_cstrings.iter().map(|s| s.as_ptr()).collect();

// 如果以后重构，把预计算提取到 helper 函数：
fn prepare_envp(env: &HashMap<...>) -> Vec<*const c_char> {
    let cstrings: Vec<CString> = ...;
    let mut ptrs: Vec<*const c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(null());
    ptrs  // ← cstrings 被 drop，ptrs 悬垂！
}
```

**建议**：直接在 `execute()` 内联，或提取时返回包含 CString 的 struct。在代码中添加注释警示此风险。

### ⚠️ 维护陷阱 2：`_` 前缀命名误导

```rust
let _envp_cstrings: Vec<CString> = ...;  // _ 前缀暗示"未使用"
```

实际上它们被使用了——它们的 Drop 是保证指针有效的关键。`_` 前缀抑制编译器警告，但语义错误。

**建议**：改为 `envp_cstrings` 加 `#![allow(unused)]` 或加注释说明。

---

## 可理解性 🟢

- 核心概念一句话：**fork 前预计算，child 只调纯 syscall**
- 改动量小（~40 行增删），diff 容易审
- ADR 和 CONTEXT.md 都有记录
- 文档中候选方案对比清晰

轻微改进机会：`align_to` 或 `ptr::read_unaligned` 的选择可以在代码注释里说明。

---

## 性能与可靠性 🟢

### 性能

- child 路径：纯 syscall，引入的开销为零
- 预计算量与 env 大小 + args 大小成正比，量级可忽略
- 可选零拷贝 envp（连续 buffer）暂不需要，有性能需求时再优化

### 可靠性

**✅ child 零堆操作保证**——核心安全属性成立。

### ⚠️ 可靠性 bug：resolve_exec_path 忽略 spec.env 中的 PATH 覆盖

```rust
fn resolve_exec_path(program: &str) -> CString {
    // ...
    let path = std::env::var("PATH").unwrap_or_default();  // 用的是 parent 的 PATH！
    // ...
}
```

问题：如果 `spec.env` 中设置了 `PATH=/custom/path`，当前设计会用 parent 的 PATH 而不是 spec 指定的 PATH 去解析。

```
实际场景：
  sandbox-runtime run --env PATH=/custom/path -- mytool

期望行为：在 /custom/path 中搜索 mytool
当前设计：在 parent 的 PATH（/usr/bin:/bin）中搜索 → 找到 /usr/bin/mytool（可能不存在或不同版本）
```

**修复**：`resolve_exec_path` 接受 `&HashMap<String, String>` 参数，优先从 spec.env 中取 PATH。

### 其他边界情况已验证

| 场景 | 行为 | 正确 |
|------|------|:----:|
| `spec.env` 为空 → envp = `{NULL}` | 空环境 | ✅ 同当前 clearenv |
| 程序名含 `/` | 直接返回 | ✅ |
| PATH 搜索失败 | 返回原始名 → execve ENOENT | ✅ 同当前 execvp |
| 参数含 NUL 字节 | CString::new Err → unwrap_or_default → 空字符串 → exec 失败 | ✅ 同当前 |

---

## 风险排序

| # | 风险 | 影响 | 可能性 | 优先级 | 类别 |
|---|------|:----:|:------:|:------:|------|
| 1 | `resolve_exec_path` 忽略 spec.env 中的 PATH 覆盖 | PATH 搜索错误 | 高 | **P0** | bug |
| 2 | 预计算提取到 helper 函数导致悬垂指针 | 内存不安全 | 中 | P1 | 维护陷阱 |
| 3 | `_` 前缀命名让人误删关键变量 | 悬垂指针 | 低 | P2 | 代码风格 |
| 4 | `is_file()` 不检查可执行位 | 与非可执行文件匹配时 execve 失败 | 低 | P3 | 边缘情况 |

---

## 改进建议

### P0 — 修复 `resolve_exec_path`（实施前必须修）

```rust
fn resolve_exec_path(program: &str, spec_env: &HashMap<String, String>) -> CString {
    if program.contains('/') {
        return CString::new(program).unwrap_or_default();
    }
    // 优先用 spec.env 中的 PATH，fallback 到 parent 的 PATH
    let path = spec_env.get("PATH").map(|s| s.as_str())
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

### P1 — 添加悬垂指针防护注释

```rust
// envp_cstrings 必须和 envp 在同一作用域，确保指针有效。
// 不要提取到 helper 函数——返回 envp 时 cstrings 会被 drop 导致悬垂指针。
let envp_cstrings: Vec<CString> = ...;
let mut envp: Vec<*const libc::c_char> = ...;
```

### P2 — 改名去掉 `_` 前缀

`_envp_cstrings` → `envp_cstrings`
`_argv_cstrings` → `argv_cstrings`

---

## 总结

设计本身是坚实的。**一个 P0 bug**（PATH 搜索忽略 spec.env）需要在实施前修复，其余都是代码风格问题。实施周期短，风险低。
