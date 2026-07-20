# ADR 002：SandboxConfig 设计 — 扁平结构 + Raw Landlock 规则

- **状态：** 已实现
- **来源：** Phase 1 初始化设计，参考 bwrap CLI 模型和 Rust crate API 兼容需求
- **影响范围：** `src/config.rs`（`SandboxConfig`、`SandboxConfigBuilder`）、`src/lib.rs`（`LandlockRule`、`LandlockPerm`）、`src/main.rs`（`expand_perm` CLI 解析）、`docs/config.md`

---

## 上下文

Phase 1 需要一种配置方式来表达沙箱策略。有两个可参考的先行者：

**bwrap（bubblewrap）**：CLI 工具，每条规则通过独立 flag 指定：

```
bwrap --ro-bind /usr /usr --bind /tmp /tmp --proc /proc --dev /dev -- <command>
```

每条路径规则单独声明，权限是隐含的（ro-bind = 只读，bind = 读写）。

**Anthropic `@anthropic-ai/sandbox-runtime`**：Node.js 库，提供高层 `FsPolicy` 枚举（`ReadOnly` / `WorkspaceWrite` / `FullAccess`），兼有 `allow_write: string[]` 数组。

本项目同时面向两种用户：

- **CLI 用户**：编写 shell 命令时需要简洁的权限表达
- **Crate API 用户**：在 Rust 代码中嵌入沙箱，需要可组合、可扩展的类型

## 决策

采用**扁平结构 + Raw Landlock 规则 + Builder 模式**：

### 配置结构

```rust
pub struct SandboxConfig {
    pub filesystem: FilesystemConfig,   // landlock: Vec<LandlockRule>
    pub network: NetworkConfig,         // enabled: bool
    pub timeout: TimeoutConfig,         // default_secs, max_secs
}

pub struct LandlockRule {
    pub path: PathBuf,
    pub perms: Vec<LandlockPerm>,
}
```

`LandlockPerm` 枚举直译内核 `AccessFs` 的 16 个个体权限位。

### CLI 层权限展开

`main.rs` 中的 `expand_perm()` 提供预设组合作为"语法糖"：

| 预设 | 展开 |
|---|---|
| `ro` / `rx` | execute + read-file + read-dir |
| `rw` | ro + write-file + remove-dir/file + make-dir/reg/sym + truncate |
| `rwx` | rw + make-sock/fifo/block/char |
| `all` | rwx + refer + ioctl-dev |

个体权限名（`execute`、`read-file`、`write-file` 等）直接通过 `FromStr` 解析为单个 `LandlockPerm`。

### 可序列化

`SandboxConfig` 通过 `serde::Serialize + Deserialize` 支持 TOML 格式。设计上兼容未来扩展更多序列化后端（JSON、YAML），但当前代码中 TOML 是唯一内建格式。

### Builder

`SandboxConfigBuilder` 提供流式 API：

```rust
SandboxConfig::builder()
    .landlock(vec![...rules])
    .network_enabled(false)
    .timeout(60, 600)
    .build()
```

## 理由

### 为什么不用高层策略枚举（如 `FsPolicy`）

1. **Landlock 是 grant-only 模型**：模糊的"只读""工作区可写"等概念需要映射到一组具体的 `LandlockPerm` 位。这种映射在 CLI 层做（`expand_perm`）比在配置层硬编码更灵活。
2. **crate 使用者需要精细控制**：库消费者可能想精确控制哪些权限位被授予，而不是被预设策略框死。
3. **预设策略是 CLI 糖衣**：未来可以加高层 CLI flag（如 `--policy read-only`），但这只是 `expand_perm` 的另一种入口方式，不需要改变底层配置结构。

### 为什么每个路径一条规则

与 Landlock 内核 API 的自然映射。`landlock_add_rule(2)` 本身就是路径 → 权限位组的原子操作。扁平列表比嵌套结构（`{ "/": "ro", "/tmp": ["rw", "refer"] }`）更直接对应底层的系统调用。

### 为什么 CLI 不直接暴露 `--landlock` 规则组合

bwrap 的每条规则用独立 flag（`--ro-bind`、`--bind`）是有道理的——它区分 bind 的语义（ro vs rw vs dev vs proc）。但 Landlock 只有一套权限位，再细分 flag 只是语法糖。`--landlock path:perm` 既简洁又完整，一个 flag 覆盖所有场景。

## 替代方案

### A：高层策略枚举（如 Anthropic `@anthropic-ai/sandbox-runtime`）

- `FsPolicy { FullAccess, ReadOnly, WorkspaceWrite }` + `allow_write: Vec<String>`
- 简单，CLI 友好
- 但 crate 使用者需求多样，预设策略无法覆盖

### B：嵌套 TOML 配置（如 `cargo deny`）

- `[filesystem.rules]` 嵌套结构
- 人类可读性好，但 Rust 类型对应复杂（需自定义 deserializer）

### C：bwrap 风格多 flag

- `--ro-bind`, `--bind`, `--dev`, `--proc` 等
- 语义清晰，但每个新的权限组合需要新增 flag

### D：扁平 Landlock 规则 + Builder + expand_perm （最终选择 ✓）

## 影响

- CLI 用户需理解 `--landlock path:perm` 语法，但不需了解 16 个权限位的细节——预设组合覆盖 90% 场景
- Crate 用户可以任意组合权限位，不受预设策略限制
- `serde` 派生让 `SandboxConfig` 天然支持 TOML/JSON/YAML 序列化
- 未来可以在 CLI 层加 `--policy read-only` 等高层 flag，只需映射到内部的 `expand_perm`，不改变底层结构

## 相关文档

- [docs/config.md](docs/config.md) — 配置使用文档
- [CONTEXT.md](CONTEXT.md) — `Landlock 权限展开`、`SandboxConfig` 词汇定义
- `src/main.rs` — `expand_perm()` 权限展开实现
- `src/lib.rs` — `LandlockRule`、`LandlockPerm` 类型定义
