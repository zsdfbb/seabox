# coding-agent profile — 质量分析报告

> 分析时间：2026-08-11
> 分析对象：`docs/arch/coding-agent-profile/`（context.md + design.md + adr/0005）
> 维度：可行性 / 可维护性 / 可理解性 / 性能与可靠性

---

## 1. 分析结论总览

| 维度 | 判断 | 一句话 |
|------|------|--------|
| 可行性 | 🟢 绿 | 纯文本预处理 + 复用 clap 两步法，~130 行，无新依赖 |
| 可维护性 | 🟡 黄 | 管线下沉是唯一动现有代码点；占位符与运行时 expand_tilde 的关系需明确 |
| 可理解性 | 🟡 黄 | `@file` 惯例易懂，但叠加占位符 + `--` 边界规则后概念偏多 |
| 性能与可靠性 | 🟢 绿 | 展开 <20µs 占启动 <2%，fork 前父进程，无并发/堆约束 |

**总体：方案可行，三个实现期注意点需在设计落地时闭环。**

---

## 2. 可行性 🟢

### 2.1 技术可实现性 — 绿

- 预处理在 clap 解析前对 `Vec<OsString>` 做单遍扫描，纯文本操作，无平台差异
- 复用现有两步法 `get_matches + from_arg_matches`，`indices_of` 保序逻辑原样复用
- 无新依赖（clap 已是主依赖，serde/toml 保持 dev-only）

### 2.2 关键实现风险 — 需注意

**R-A：`--` 边界与 `trailing_var_arg` 的交互（设计 §4.4 已提，实现时最易错）**

CLI 的 command 参数是 `trailing_var_arg + allow_hyphen_values`（main.rs:304），
意味着 `--` 之后的所有 token 都归命令区。预处理扫描"首个裸 `--` 之前"时：
- ✅ `seabox run @p.txt -- cargo build` → `@p.txt` 在选项区，正确展开
- ⚠️ `seabox run @p.txt cargo build`（无 `--`）→ `@p.txt` 仍会被当 profile 展开
- ⚠️ 命令区真正需要 `@file` 时（`-- cat @list`）→ 因在 `--` 后，**不会**展开，符合预期

> 需在实现时用测试固化「无 `--` 时选项区 `@` 也展开」这个语义。

**R-B：`@` 前缀歧义（design §5 R3）**

选项区某 flag 的值恰以 `@` 开头（如 `--env TOKEN=@abc`）会被误判为 profile 文件。
罕见但存在。**建议**：预扫描只对"以 `@` 开头且后续非 `@` 开头"的独立 token 做展开，
并让 `--` 后的命令区豁免（已设计）。可接受，文档标注。

---

## 3. 可维护性 🟡

### 3.1 模块边界 — 绿

`src/profile.rs` 单职责（@file 展开 + 占位符替换），与 config/linux 解耦。
`from_flag_args` 放 config.rs 复用 clap 管线，无逻辑重复。

### 3.2 管线下沉（设计 D7）— 🟡 需评估

`build_config`/`collect_mount_actions`/`collect_cap_actions` 从 main.rs 移入 lib
是**唯一动现有代码的点**。设计意图正确（`from_flag_args` 复用同一解析器），但：
- **回归面**：main.rs 现在 `cmd_run` 约 180 行，迁移后 CLI 行为必须零变化
- **测试兜底**：现有 `tests/` 全绿 + main.rs 单测（`resolve_network_config` 等）应覆盖

> **建议**：分两步落地——第一步先做 `profile.rs` 预处理（CLI-only，`@file` 直接在
> main.rs 拼 argv），完全不动现有管线；第二步再下沉管线 + `from_flag_args`。
> 这样第一步可独立合入，回归风险最小。

### 3.3 占位符与运行时 expand_tilde 的交互 — 🟡 需明确

**已核实**：运行时已对 landlock path（`landlock.rs:162`）和 cwd（`mod.rs:135`）做
`~` 展开；mount 路径**不**展开（`mount.rs` 直接用原始字符串）。

这意味着：
- **`~` 在 profile 里展开后（绝对路径），运行时 landlock.rs:162 的 `starts_with("~")`
  不触发，二次 expand_tilde 是 no-op，无害** ✅
- **但 mount 路径（`--bind`/`--ro-bind`/`--tmpfs` 的 SRC/DST）不在运行时展开**——
  若 profile 里写 `~` 或 `{workspace}`，必须在 preprocess 展开，否则 mount 拿到的
  是字面 `~`/`{workspace}` 字符串，绑定失败

> **建议**：占位符替换必须在 preprocess 对**所有** profile token（含 bind source/target）
> 完成，不能依赖运行时二次展开；并补一条测试：`@file` 里含 `{workspace}` 的
> `--bind` 源路径正确展开。

### 3.4 错误传播 — 绿（一条注意）

`anyhow` 统一。缺文件 / 未知 profile / 环检测都是 `anyhow::Error` 上抛。
**注意**：报错信息应包含文件名（`@p.txt: No such file`），方便定位 profile 来源。

### 3.5 并发 / 资源管理 — 绿

- preprocess 在 fork 前父进程完成，不涉及 ADR 0003（fork 后零堆）
- 无锁、无共享状态、无长生命周期资源；`@file` 读取用 std fs + 立即释放
- 环检测 + depth≤8 防递归爆栈

---

## 4. 可理解性 🟡

### 4.1 概念一致性 — 黄

叠加了两套机制，概念数偏多（对比设计目标"最简"）：

| 概念 | 评价 |
|------|------|
| `@file` argfile | ✅ 业界惯例（GCC/rustc），易懂 |
| `{workspace}` / `~` 占位符 | ⚠️ 与运行时 expand_tilde 有重叠，见 §3.3，需文档解释"为什么 profile 里要写、运行时为什么不处理" |
| `--` 边界规则 | ⚠️ 叠加 trailing_var_arg 后语义微妙（§2.2 R-A） |

### 4.2 抽象层次 — 绿

单层预处理函数，无过度抽象（正确否决了 4 类型 registry/trait 方案）。

### 4.3 文档完整度 — 绿

context（需求+决策历史）+ design（方案+mermaid 图）+ ADR（D1-D8）三件套完整，
含"为什么否决预设/4 类型"的决策记录。mermaid 图辅助理解。

### 4.4 新人上手成本 — 中低

概念不多，但 `@` + 占位符 + `--` 三条规则需要一节 README/usage 说明。

---

## 5. 性能与可靠性 🟢

### 5.1 性能模型 — 绿

- 展开：读 2KB ~5µs + tokenize ~5µs + 替换 ~1µs ≈ **10-20µs**
- 占沙箱启动（fork+unshare+mount+seccomp ≈ 1-5ms）的 **<2%**
- 每进程一次，无热路径，无需 lazy/缓存

### 5.2 故障模式 — 绿（一条注意）

| 故障 | 处理 | 可靠性 |
|------|------|--------|
| `@file` 缺失 | 报错退出（含文件名） | ✅ |
| 嵌套环 | depth≤8 + 环检测报错 | ✅ |
| 嵌套深度超限 | depth 上限报错 | ✅ |
| 权限不足读 profile | std fs 错误上抛 | ✅ |
| 二进制 profile / 非法 UTF-8 | `@file` 按 UTF-8 读，非法报错 | ⚠️ 确认实现用 `read_to_string` 而非 `read` |

### 5.3 可观测性 — 绿（轻量）

preprocess 无异步、无状态，无需 tracing。CLI `--debug` 可打印展开后 argv（辅助排障），
非必需。

---

## 6. 风险排序（影响 × 可能性）

| # | 风险 | 影响 | 可能性 | 缓解 |
|---|------|------|--------|------|
| 1 | 管线下沉回归现有 CLI 行为 | 高 | 中 | 分两步落地（先 CLI-only）；现有测试兜底 |
| 2 | `--`/trailing_var_arg 边界误判（无 `--` 时选项区 `@` 展开） | 中 | 中 | 测试固化语义；文档标注 |
| 3 | mount 路径占位符未展开导致绑定失败 | 中 | 中 | §3.3 建议的 preprocess 全 token 替换 + 专项测试 |
| 4 | 选项区 flag 值以 `@` 开头误判 | 低 | 低 | 文档标注（R3） |
| 5 | 二进制/非 UTF-8 profile | 低 | 低 | 用 `read_to_string` 报清晰错误 |

## 7. 改进建议（分层）

### 易修复（实现时顺手做）

1. `@file` 用 `read_to_string`，错误信息含文件名
2. 占位符替换对**所有** profile token（含 bind source/target）执行，不依赖运行时二次展开
3. 测试固化「无 `--` 时选项区 `@` 也展开」语义

### 需讨论（合入前定）

4. **分两步落地**：先 `profile.rs` CLI-only（不动现有管线），再下沉 + `from_flag_args`——回归风险最小的路径
5. `{workspace}` 的语义定义：主进程 cwd？还是 profile 文件所在目录？（建议：**主进程 cwd**，与 `expand_tilde` 的 `$HOME` 对称；profile 文件位置与工作区无关）
6. `~` 在 profile 中是否需要支持：运行时 landlock/cwd 已展开 `~`，profile 展开后 no-op 无害；但 mount 路径需 preprocess 展开——**统一在 preprocess 处理 `~` 和 `{workspace}`**，运行时保持现状

### 架构级

7. 无。方案本身简单，未发现需要架构级调整的问题

---

## 8. 结论

**方案可行，无需架构级修改。** 三个实现期注意点：
- 管线下沉建议分两步落地（回归风险）
- 占位符替换须覆盖所有 profile token（mount 路径坑）
- `--` 边界 + trailing_var_arg 语义用测试固化

设计文档中 **D4（占位符"仅 profile 来源"）与运行时 expand_tilde 的关系**建议在
design.md 补一句说明（§3.3 的核实结论），避免实现时误以为运行时兜底。
