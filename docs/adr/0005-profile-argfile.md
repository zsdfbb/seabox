# ADR 0005: profile 机制 — argfile 预处理模式

> 日期：2026-08-08
> 状态：**提案**
> 关联：`docs/arch/coding-agent-profile/design.md` + `context.md`

---

## 背景

coding-agent profile 需求（`d82d5a4` 决策）：把 coding agent 约 95% 静态的权限需求
打包成可复用 profile。约束明确「不做配置内容结构设计」——profile 就是一段 CLI flag
文本序列。**2026-08-11 追加决策：不提供内置命名预设**，flag 内容完全由使用方提供。

关键历史：2026-07-20（`e5a0d95`）删除 `--config` CLI 参数与 TOML 模板，确立
「CLI flags 唯一输入源」的 bwrap 模式。本次 profile **不引入覆盖 CLI 的配置文件**，
与那次删除不冲突。

## 决策

profile = **一段 CLI flag 文本序列**（`@file` argfile 模式），在 clap 解析**之前**
经 `src/profile.rs` 预扫描展开进 argv，走**同一个 clap 解析器**与现有 `build_config`
管线。不提供内置命名预设、不引入 serde、不设计 TOML schema、不引新依赖。

## 具体决定

| # | 决策 | 值 |
|---|---|---|
| D1 | profile 形态 | **`@file` flag 文本文件**（argfile 模式）。展开后与用户 argv 合并，走同一 clap 解析器 |
| D2 | 展开时机 | clap 解析**之前**单遍预扫描；`--` 之后命令区不展开 |
| D3 | 合并语义 | `@file` 展开的 flag 插在 argv 原位置，用户 flag 在后的覆盖由现有 CLI 逻辑决定：`indices_of` 保序 + Vec flag 追加 + `.args_override_self(true)` 单值覆盖（`--uid`/`--chdir`/`--timeout`/`--hostname`） |
| D4 | 占位符 | `{workspace}` → **主进程 cwd**、`~` → `$HOME`（复用已有 `expand_tilde`）；**仅 `@file` 来源的所有 token**（含 `--bind`/`--ro-bind`/`--tmpfs` 的 SRC/DST）替换，手动 flag 原样。运行时 `expand_tilde` 只兜底 landlock path 与 cwd，**不兜底 mount 路径**——必须在此处完成，否则 bind 源路径拿到字面量 |
| D5 | **不提供内置预设** | 无 `--profile NAME` flag、无 `Profile` 类型、无编译期预设表。flag 内容完全由使用方 `@file` 提供；crate API 只暴露 `from_flag_args([...])` 让调用方自传 flag 序列 |
| D6 | 嵌套 | `@file` 内可再 `@other`，深度上限 8 + 环检测（防递归爆栈） |
| D7 | 管线下沉 | `build_config`/`collect_mount_actions`/`collect_cap_actions` 从 `main.rs` 移入 lib，`from_flag_args` 复用同一 clap 解析器（clap 已是主依赖） |
| D8 | 依赖 | **不引入新依赖**；serde/toml 保持 dev-dependency |

## 决策理由

1. **D1/D2 与 e5a0d95 兼容**：`@file` 不是"覆盖 CLI 的配置"，而是"参数组预设"展开成
   现有 flag——CLI flags 仍是唯一语义来源，bwrap 模式保持。展开先于解析是 clap 官方
   推荐的 argfile 模式（clap 无内建支持，issue #1693）。
2. **D3 零新增合并逻辑**：合并规则完全由现有 CLI 代码决定（`indices_of` 保序 + 追加 +
   override_self），无第二套语义。只有单值 flag（scalar）需要 `.args_override_self(true)`
   支持"用户覆盖 profile"。
3. **D4 占位符域窄**：`{workspace}` 是 profile 约定的本地惯例，手动 flag 用户自会写
   实际路径；限定 profile 来源避免污染手动 flag 语义。
4. **D5 机制与内容解耦**：不内置预设使 seabox 无需为任何具体 coding agent 的内容负责，
   内容责任完全归属使用方。省去 `--profile` CLI flag（无需 clap 帮助发现/校验名字）、
   省去 `Profile` 类型与预设表。单遍扫描只需识别 `@` 前缀，实现更简单。
5. **D7 单一解析管线**：`from_flag_args` 若复制解析逻辑会造成 CLI/crate 双语义漂移；
   下沉管线让二者走同一条路，clap 已是主依赖故无新增成本。
6. **D8 不引 serde**：内容结构不做（用户约束），天然不需要 serde；`@file` 文本解析
   只需空白切分 + 引号/注释处理，手写即可。

## 未被选择的方案

- **内置命名预设（`--profile coding-agent` / `Profile` enum / static 预设表）**：
  需求方明确否决（2026-08-11）。内容责任应由使用方承担，机制与内容解耦。
- **方案 B（4 类型抽象：`ProfileRegistry`/`ArgSource`/`ArgExpander`/`PlaceholderResolver`）**：
  对"不做内容结构"的约束过重。占位符仅 2 个、来源仅 1 种（`@file`），trait 化无实值；
  引入 4 个类型徒增概念负担。仅采纳其嵌套环检测。
- **引入 argfile crate**：需支持 `{workspace}` 占位符且避免引新依赖，自写 ~130 行足够。
- **恢复完整 `--config` 通用配置**：与 `e5a0d95` 删除决策冲突，且引入 serde schema，
  违背"不做内容结构"。
- **Trait 化占位符（`PlaceholderResolver`）**：占位符只有 `{workspace}`/`~`，枚举/匹配
  足够，不需要可注册 trait。

## 未决点与风险

- **R1 单值 flag 覆盖**：`.args_override_self(true)` 需逐一确认现有 scalar flag（`--uid`/
  `--gid`/`--chdir`/`--timeout`/`--timeout-max`/`--hostname`）均适用；`--env` 是 map 追加
  语义不受影响。
- **R2 管线下沉重构风险**：`build_config` 等移入 lib 是唯一动现有代码的点；由现有
  测试兜底保证 CLI 行为零变化。
- **R3 `@` 前缀歧义**：选项区某 flag 的值以 `@` 开头会误判为 file（罕见，文档标注）。
