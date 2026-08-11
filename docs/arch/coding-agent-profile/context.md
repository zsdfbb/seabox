# coding-agent profile — 架构上下文

## 概述

seabox 的 Phase 1/2 已完成（Landlock + seccomp + 7 namespace + mount + caps），
2026-08-06 决策（`d82d5a4`）确定了**动态授权暂缓**，下一步首要任务是
**coding-agent profile**：把 coding agent（Claude Code / CodeWhale / Cursor 等）
约 95% 静态的权限需求，打包成可复用的 profile，无需引入新机制。

> 决策原文（`docs/future-extensions.md` §1）：
> "coding agent 真实权限需求约 95% 静态（工作区 rw + /tmp rw + loopback + 默认零 cap），
> 打包现有 flag 成 TOML profile 即覆盖，无需新机制。"

**2026-08-08 形态决策**：profile = **一段 CLI flag 文本序列**（argfile 模式），
**不设计配置内容结构**（不做 serde、不做 TOML 字段映射）。
- profile 本身就是 CLI 参数，展开后拼进 argv 走**同一个 clap 解析器**，
  与手动输入的 flag 共享同一套校验、顺序（`indices_of` 保序）与合并语义。
- "内容是什么"（如 coding-agent 具体含哪些 flag）**不在本次设计范围内**，
  由使用方（用户 / 宿主框架）通过 `@file` 提供。

**2026-08-11 追加决策：不提供内置命名预设**。
- 无 `--profile NAME` flag、无 `Profile` 类型、无编译期预设表。
- flag 内容完全由使用方 `@file` 提供；crate API 只暴露 `from_flag_args([...])` 自传 flag 序列。
- 机制与内容解耦：seabox 只做 `@file` 展开机制，不为任何具体 coding agent 的内容负责。

当前代码**尚无任何 profile 概念**（CLI、config.rs、lib.rs 均无 profile/Profile）。
且 2026-07-20 曾主动**删除** `--config` CLI 参数与 `templates/` TOML 示例
（`e5a0d95`，"CLI 参数是唯一输入源，类似 bwrap"）。本次 profile 不引入
"覆盖 CLI 的配置文件"，因此与那次删除**不冲突**。

---

## 现有架构

### 模块边界

| 层 | 文件 | 职责 |
|----|------|------|
| CLI | `src/main.rs` | clap derive，`run`/`check`/`serve`（serve 是占位 stub） |
| 配置 | `src/config.rs` | `SandboxConfig` + `with_*` builder + `NamespacesConfig`/`NetworkConfig`/`MountConfig`/`CapabilityConfig`，纯数据层（无 libc 依赖） |
| 公共 API | `src/lib.rs` | `Sandbox` 包装器 + `SandboxImpl` trait + `CommandSpec`/`ExitReason` |
| Linux 实现 | `src/linux/*` | child_setup（unshare→mount→caps→seccomp→execve）、landlock、namespaces、net、seccomp、caps |

### 核心抽象

- `SandboxConfig`：扁平结构 + 链式 `with_*` 方法，是 CLI 与 crate API 的汇聚点
- `CommandSpec`：program/args/cwd/env/timeout（命令规格，与沙箱配置分离）
- `Sandbox::from_config()` → `execute(&spec)` → `(CommandOutput, ExitReason)`
- `ExitReason`：`Ok` / `Denied{mechanism, message}` / `Program(code)` / `InternalError`

### 关键数据流

```
CLI flags ──build_config()──▶ SandboxConfig ──from_config()──▶ Sandbox
                                                                │
                                             CommandSpec ────────┘ execute()
                                                                │
                                                    pre_exec 序列 + execve
```

### 外部依赖

| 依赖 | 用途 | 备注 |
|------|------|------|
| clap 4 (derive) | CLI 解析 | — |
| anyhow | CLI 错误 | — |
| dirs | `expand_tilde`（~ 展开） | — |
| libc | syscall 常量与调用 | config 层不依赖 libc |
| landlock 0.4 | Landlock ABI 封装 | Linux only |
| serde + toml | **仅 dev-dependencies**（示例/测试用） | 主库不含 serde |

**关键约束**：serde/toml 目前只是 dev-dependency。`SandboxConfig` 未派生
`Deserialize`。examples/cli_from_toml.rs 展示了"用户自定义 TOML 结构体 → 手工转换
成 SandboxConfig"的模式，说明主库刻意不做 serde 序列化。

---

## 约束

- **技术**：主库不引入 serde 依赖是当前刻意决策（dev-only）；profile 形态避开它
- **技术**：`fork()` 后零堆操作（ADR 0003）——profile 展开必须在 fork 前的父进程完成，不涉及子进程
- **技术**：每个 CLI flag 都有对应 crate 层 `with_*` 方法（CLI + Crate API 一一对应约定）——profile 的 crate 镜像为 `SandboxConfig::from_flag_args([...])`
- **演进**：`SandboxConfig` 是扁平结构（ADR 0002）；profile 展开为现有字段，而非引入并行配置结构体
- **演进**：2026-07-20 删除了 `--config`（bwrap 模式，CLI flags 唯一输入源）。profile 是"参数组预设"，只做追加、不吞用户显式 flags，与那次删除兼容
- **演进**：不引入新机制——决策明说"打包现有 flag 成 profile 即覆盖"，即 profile 只是现有能力的分组复用
- **演进**：**不设计配置内容结构**——profile 就是 flag 文本，无字段映射、无 serde、无 schema
- **组织**：单人维护，文档先行（先 context/design/ADR 再实现）

---

## 需求范围

### 范围内（本次 coding-agent profile）

- **profile 机制**：把一段 CLI flag 文本序列在 clap 解析前展开进 argv
  - CLI：`@profile.txt`（用户 flag 文本文件）
  - Crate API：`SandboxConfig::from_flag_args([...])`（调用方自传 flag 序列）
- **与用户显式 flags 合并**：追加语义（profile 在前、用户 flag 在后），
  覆盖规则由现有 CLI 代码决定，不新造合并逻辑
- **占位符**（唯一需要设计的内容级东西）：`{workspace}` → cwd、`~` → `$HOME`
  （复用/扩展已有 `expand_tilde`），在 tokenize 后、进 clap 前统一替换
- **内容（profile 里具体写什么）不在范围内**：由使用方通过 `@file` 提供
- **不提供内置命名预设**（2026-08-11 决策）：无 `--profile NAME` / `Profile` 类型 / 预设表

### 范围外（明确不做的）

- **配置内容结构设计**（TOML schema、字段映射、serde derive）
- **动态授权运行时通道**（USER_NOTIF 运行时放行、Violation Hook）：暂缓，见 future-extensions 评估结论
- `seabox::policy` 模块（`BasePolicy + PermissionRequest + merge()`）：仅在日后重评动态授权时的最小形态，本次不做
- macOS Seatbelt（Phase 3）
- IP 级网络过滤（Phase 2b）
- CodeWhale 集成 + HTTP serve（Phase 4，serve 仍为 stub）
- 恢复完整 `--config` 通用配置覆盖语义（bwrap 模式决策保持）

### 关键场景

- **场景 1（CLI 消费）**：`seabox run @coding-agent.profile -- cargo build`，
  profile 里的 flag 与手动输入的 `--` 后命令拼进同一 argv，正常解析执行
- **场景 2（Crate 消费）**：宿主框架内 `SandboxConfig::from_flag_args(["--landlock", "/:ro", ...])`，
  与现有 `with_*` 方法组合
- **场景 3（用户覆盖）**：`@file` 含 `--unshare-net`，用户追加 `--share-net` 时，
  后者按现有 CLI 语义生效（追加在后）

### 未澄清问题

- [ ] **展开时机与机制**：`@file` 的 argv 展开在 clap 解析前的哪一步？
  纯文本扫描即可识别 `@` 前缀，无需 clap 参与发现；展开先于解析。
  首遍扫描 `@` 参数 → 展开 → 重进 clap？（参照现有 `get_matches + from_arg_matches` 两步法）
- [ ] **占位符替换的输入域**：`{workspace}`/`~` 是否对 profile 文本和手动 flag 一视同仁？
  （推荐仅 profile 来源，保持手动 flag 语义不变）
- [ ] **超时与其他 CommandSpec 字段**：`@file` 是否覆盖 timeout/env，还是只管沙箱配置不管命令规格？
- [ ] **`@` 冲突**：`--` 后命令里出现 `@file` 是否误展开？（`@` 展开应只作用于选项区，不作用于命令区）

---

## 后续建议

1. **本次任务**：`arch-design` 已产出机制方案（见 `design.md` + `adr/0005-profile-argfile.md`）：
   `@file` 展开时机 + 占位符替换，**不提供内置预设、不涉及配置内容设计**
2. **之后**：Phase 3 macOS Seatbelt、Phase 4 CodeWhale 集成（HTTP serve 已暂缓，改为评估 MCP tool server）
3. 动态授权保持路线预留，**不**启动
