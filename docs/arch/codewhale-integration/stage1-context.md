# 阶段 1（CodeWhale 同步路径 + 后端替换）— 架构上下文

> 探索时间：2026-08-14（arch-explore「考虑下一步的工作」）
> 状态：**探索完成，待决策**（4 个开工会决策未定，见 §未澄清问题）
> 前置文档：`docs/arch/codewhale-integration/design.md`（D1-D6）+ `context.md`（已定稿）+ `docs/design-final/codewhale-stage0-spawn-api.md`（已实现）

---

## 概述

阶段 1 是 Phase 4（CodeWhale 库级集成）的第二段：把 seabox 接进 CodeWhale 的**前台同步执行路径**，
替换 bwrap 包装后端，并修复 P0-1/P0-2/P1-1/P1-2/P1-3/P2-1/P2-2 共 7 项批判。
**本阶段只在 CodeWhale 仓库动代码**（seabox 侧阶段 0 已完成，本阶段零 seabox 改动）。

> 本文件是阶段 1 开工前的架构上下文，重点：核实阶段 0 完成态 + CodeWhale 工作面、
> 修正 design.md 的执行路径清单（3 → 4）、暴露阻碍开工的架构决策。

> **集成对象**：CodeWhale **个人 fork**，仓库入口 `Integration/CodeWhale`（符号链接 →
> `/home/zs/Develop/CodeWhale_seabox`，origin `zsdfbb/CodeWhale_seabox`），**非**上游 `Hmbown/CodeWhale`。

### ⚠️ 基线复核注记（2026-08-14 修正）

§现状核实 的**行号与基线基于上游 `OpenSrc/CodeWhale`（Hmbown/CodeWhale，commit `cc4e8a734`）探索**
（当时误将其当作集成对象）。实际集成对象为个人 fork `CodeWhale_seabox`（HEAD `c9b9559a7`）。
阶段 1 开工前须在个人 fork 上复核：`execute_sync_sandboxed` / `sandbox/mod.rs` / `policy.rs` 等
行号与结构是否与上游一致（fork 若已同步则大多一致，但需确认无漂移）。

---

## 现状核实（2026-08-14）

### seabox 侧：阶段 0 已完成 ✅（零代码债）

| 项 | 状态 |
|---|---|
| `Sandbox::spawn` / `SandboxChild`（try_wait/wait/wait_timeout/kill/id/take_*）/ `StdioConfig` | ✅ 已实现 |
| `CommandOutput` + stdout/stderr/timed_out；`CommandSpec` + stdin + timeout→Option | ✅ 已实现 |
| `cmd_run` 改 spawn(Inherit) 流式 + SIGINT/SIGTERM 转发 + timed_out→124 | ✅ 已实现 |
| feature 门控 `cli = ["dep:clap","dep:dirs"]`；`build --no-default-features` 可编 | ✅ |
| CLOEXEC 卫生（`3eab160`：child 侧 FD_CLOEXEC + 父侧 MSG_CMSG_CLOEXEC） | ✅ design-final §7 已知限制已解除 |
| 221 测试全绿 / clippy 零警告 / fmt 合规 | ✅ |
| `docs/development-phases.md` 阶段 0 checkbox | ❌ **文档滞后，未勾选**（可顺手收尾） |

### CodeWhale 侧：阶段 1 零开工

全仓库 `grep seabox` **零命中**。**基线为上游 `OpenSrc/CodeWhale`（commit `cc4e8a734`）探索所得，
个人 fork `CodeWhale_seabox` 需复核**（见文首「基线复核注记」）。

**执行路径清单（修正 design.md 的「三条」→ 实际 4 条）**：

| # | 路径 | 函数（shell.rs） | 现有模型 | seabox API 映射 |
|---|---|---|---|---|
| 1 | 前台同步（管道捕获） | `execute_sync_sandboxed` L1592 | Command + pipe reader 线程×2 + wait_timeout + stderr 文本启发式 | `Sandbox::execute` → `CommandOutput`（全量捕获，0 线程） |
| 2 | **前台交互（继承 stdio）** | `execute_interactive_sandboxed` L1760 | Command + `Stdio::inherit` + raw-mode 切换 + wait_timeout | `spawn(Inherit)` + `wait_timeout`（= stage 0 cmd_run 同款） |
| 3 | 后台非 tty | `spawn_background_sandboxed` L1881（非 tty 分支） | Command + piped + reader 线程 + `BackgroundShell` job table | `spawn(Piped)` + take_* + try_wait 轮询 |
| 4 | 后台 tty | `spawn_background_sandboxed` L1881（tty 分支） | portable-pty | CodeWhale openpty + `spawn(Fd{slave})` + 读 master |

> **design.md 缺口**：只列了 1/3/4，「前台交互」路径未覆盖。它是**前台同步家族**（`Stdio::inherit`，
> 映射 `spawn(Inherit)`），且 bwrap 删除（D2）会连带破坏它——**须纳入阶段 1 范围**。
> 阶段 1 = 路径 1+2（前台），阶段 2 = 路径 3+4（后台/tty）。

**已核实的关键位置**（与 context.md 调研记录一致，无漂移）：

| 位置 | 现状 |
|---|---|
| `sandbox/mod.rs` `SandboxManager::prepare` L457 | 仍是「前缀包装命令」：`ExecEnv.command: Vec<String>`（L295），`prepare_bwrap` L520 拼 bwrap argv |
| `sandbox/mod.rs` `SandboxType` L252 | `None` / `MacosSeatbelt` / `LinuxBubblewrap` / `Windows`，无 Seabox |
| `sandbox/mod.rs` `get_platform_sandbox_with_bwrap_preference` L345 | Linux：`prefer_bwrap && is_available()` 才返回 bwrap，否则 `None` → **Linux 默认零强制（P0-1）** |
| `sandbox/mod.rs` `prefer_bwrap` L395 / `PUBLIC_SANDBOX_BACKENDS` L62 | 默认 false；文案被 `web/scripts/facts-lib.mjs` L51 + `web/lib/facts-drift.ts` L173 **正则源码解析** |
| `sandbox/policy.rs` `map_safety_level_to_behavior` L435 | **死代码**（生产零调用，P0-2）；`SandboxExecutor` trait L413 未接线（P1-1） |
| `sandbox/policy.rs` `SandboxPolicy::get_writable_roots` L190 | 含 git worktree 可写根解析 L261-357 + `.codewhale`/`.deepseek` 只读子路径保护 —— **seabox landlock 映射的核心输入，可复用** |
| `sandbox/bwrap.rs` `build_bwrap_command` L87-141 | argv 顺序：`--unshare-all --share-net? --ro-bind / / --bind <roots> --ro-bind <ro-paths> --chdir <cwd> -- <prog>`；`detect_denial` L184 文本启发式 |
| `sandbox/seccomp.rs` | 休眠死代码（P1-3），未接入执行路径 |
| `shell.rs` `execute_sync_sandboxed` L1592-1757 | `Command::new(program)` + piped + reader 线程 + `wait_timeout`；退出码解析 L1682-1685；`was_denied` stderr 启发式 L1688 |
| `shell.rs` `ShellChild` L320-324 | `Process` / `Pty`，无 Seabox 变体（阶段 2 加） |
| `shell.rs` `ShellExitStatus` L639 | `{ code: Option<i64>, success: bool }`，无 denial 语义 |
| `authority.rs` `sandbox_policy_for_turn` L337-366 | turn 级策略（P2-2 三层决策），默认 `workspace_write_policy` network=true L368 |
| `config.rs` `prefer_bwrap` L2579 / `sandbox_mode` L2558 | 双旋钮（P2-1） |
| `engine.rs` `prefer_bwrap` L399/L492 + 注入 L1271-1272 | 需随 bwrap 删除移除 |
| `crates/tui/Cargo.toml` | **无 seabox 依赖**；`libc`（unix）/ `portable-pty` / `wait-timeout` |
| 沙箱测试 | mod.rs L661-1059 + bwrap.rs L197-334 **全部断言 bwrap argv 结构**，seabox 改造后需重写 |

---

## 约束

- **技术**：
  - seabox 是**全权执行模型**（fork + waitpid + 捕获），CodeWhale 是**前缀包装模型**（`ExecEnv.command` → std::process）——二者在 `prepare()` 抽象层根本冲突，这是阶段 1 最大的架构决策点。
  - CodeWhale 自带 `sandbox::CommandSpec`（L73），与 seabox 的 `CommandSpec` **同名冲突**——任一文件同时 use 即编译错，映射代码需别名/限定。
  - seabox 在 `/home/zs/Develop/seabox`，CodeWhale 个人 fork 在 `/home/zs/Develop/CodeWhale_seabox`（入口 `Integration/CodeWhale`）—— **同目录树**（`/home/zs/Develop/` 下兄弟目录），crate path 依赖用同级相对路径即可（`path = "../CodeWhale_seabox/…"` 或目录重定位，见 Q6）。
  - seabox `SandboxConfig::with_landlock` 是 **allow-list**，「root 只读 + 子目录可写」必须 `with_ro_bind` 覆盖（自动 mnt ns）——映射 `get_writable_roots` 的核心语义。
- **性能**：前台同步路径每命令一次 `Sandbox::execute`（0 额外线程，边读边 wait drain loop）；拒绝诊断从文本启发式换结构化 `ExitReason`，无额外开销。
- **演进**：bwrap 删除（D2）是**不可逆**的（删除后无回退后端）——后台/tty 路径阶段 2 才接 seabox，**删除时机与阶段 2 的衔接必须决策**。
- **组织**：跨两个仓库（seabox 本仓 + CodeWhale 个人 fork `CodeWhale_seabox`）；CodeWhale 大仓改动需遵循其 PR/CI 流程（`web/` 下 facts-drift 测试是隐式契约）。

---

## 需求范围（阶段 1）

### 范围内

- 前台同步路径（路径 1）改走 seabox：`execute_sync_sandboxed` 分叉，沙箱策略有效 → `SeaboxSandbox::execute`（构造 seabox 配置 + `Sandbox::execute` → `CommandOutput` + `ExitReason`），无沙箱 → 保留 std::process 路径。
- 前台交互路径（路径 2，**design.md 补充项**）改走 seabox：`spawn(Inherit)` + `wait_timeout`。
- 后端替换：新增 `SandboxType::Seabox`，Linux 默认返回 Seabox（修 P0-1）；删除 `bwrap.rs` + `seccomp.rs`（D2/P1-3）；移除 `prefer_bwrap`（P2-1）；收敛双旋钮。
- 拒绝检测结构化（修 P1-2）：`ExitReason` / `blocked: Option<(u32,u32)>` 直接判定，替换 stderr 文本启发式。
- 接线 `map_safety_level_to_behavior`（修 P0-2）+ **D5**（`SafetyLevel::Safe → network_access=false`）。
- 测试重写：mod.rs / bwrap.rs 的 argv 结构断言 → seabox 配置映射断言 + 同步路径集成测试。

### 范围外（阶段 2 / 明确不做）

- 后台非 tty / 后台 tty（路径 3/4）→ **阶段 2**：`ShellChild::Seabox` 变体、`spawn(Piped)` + job table、openpty + `StdioConfig::Fd`。
- persist 服务（D6：保持 DangerFullAccess 无沙箱）。
- `backend.rs` / `opensandbox.rs`（外部 HTTP 沙箱，正交路由）。
- macOS Seatbelt / Windows 路径。
- scm_creds 容器化探针（设计-final §7，阶段 3 补）。

### 关键场景

1. **前台同步 sandbox 命令**：`ReadOnly`/`WorkspaceWrite` 策略下执行命令 → `Sandbox::execute` 全量捕获 stdout/stderr → `ShellResult`（exit_code + 结构化 sandboxed/denied）。比 bwrap 路径少 2 reader 线程。
2. **只读拒绝**：写只读路径 → seabox `classify_exit` → `Denied(FileSystem)` → 结构化拒绝消息（非文本启发式）。
3. **D5 收紧**：`SafetyLevel::Safe` 命令 → `network_access=false` → 无法访问外部 IP，loopback 可达。
4. **超时强制**：timeout_ms → `CommandSpec::with_timeout` → 到期 kill(-pgid) → `ShellStatus::TimedOut`。
5. **前台交互**：交互式 shell → `spawn(Inherit)` 流式 + 信号转发（复用 stage 0 cmd_run 模式）。

---

## 未澄清问题（阶段 1 开工前需决策）

- [ ] **Q1 后端集成模型**（阻塞，最大决策）：`prepare()` → `ExecEnv.command: Vec<String>` 的前缀包装模型与 seabox 全权执行根本冲突。design D1 定「库级直连绕过 wrapper」，但 shell.rs 三个调用点都拿 `&ExecEnv`。具体形态？
  - a) `prepare()` 返回可枚举「包装 vs 全权」的 `ExecEnv`（seabox 分支携带构造好的 seabox 配置/句柄）
  - b) 直接实现 `policy.rs::SandboxExecutor` trait 的 `SeaboxSandbox` 并接线（trait 已存在未接线，P1-1）
  - c) `execute_sync_sandboxed` 内联 seabox 分支（不经过 prepare），最小侵入但破坏 `prepare` 统一抽象
  - 建议：a) 或 b)，需要 arch-design 权衡；c) 是快速但**加固 P2-2 三层决策**的返工源。
- [ ] **Q2 bwrap 删除时机**：阶段 1 删除 bwrap（D2）+ Linux 默认 Seabox，但后台/tty（路径 3/4）阶段 2 才接 seabox。删除后、阶段 2 完成前，后台 sandbox 命令走什么后端？
  - 选项 A：阶段 1 删除 bwrap 时，后台路径临时回退无沙箱（有安全空窗）
  - 选项 B：**bwrap 保留到阶段 2 完成**，阶段 1 只切前台路径（推荐——无安全空窗，D2 顺延）
  - 选项 C：阶段 1/2 合并为一个 PR（消除空窗但面大）
- [ ] **Q3 `execute_interactive_sandboxed` 归属**：路径 2 是前台家族（`Stdio::inherit` → `spawn(Inherit)`），design.md 未列。确认纳入阶段 1 范围（本上下文按此假设），避免 bwrap 删除后前台交互无后端。
- [ ] **Q4 `CommandSpec` 名称冲突**：CodeWhale `sandbox::CommandSpec` vs `seabox::CommandSpec`。映射代码统一 `use seabox::CommandSpec as SeaboxCommandSpec` 还是按模块限定？（实现细节，先定约定）
- [ ] **Q5 D5 / `map_safety_level_to_behavior` 接线路径**：该函数是死代码，`SafetyLevel` 由 `command_safety` 评估。阶段 1 需确认 SafetyLevel → SandboxPolicy 的现有路径，在 policy 层收紧网络（还是只在 seabox 映射层收紧？）——影响「SafetyLevel 在命令级生效」的语义。
- [ ] **Q6 seabox crate path 依赖**：seabox 与 CodeWhale 个人 fork **同目录树**（`/home/zs/Develop/` 下兄弟目录）。用同级相对 path（`path = "../seabox"`）？还是目录重定位 / workspace patch？（影响 CodeWhale 可发布性）
- [ ] **Q7 `PUBLIC_SANDBOX_BACKENDS` 文案消费方**：`web/scripts/facts-lib.mjs` + `web/lib/facts-drift.ts` 正则解析。改 SandboxType 文案需同步，否则 facts-drift 测试挂——是否随阶段 1 一并更新，还是后端清单保持 bwrap 文案直到阶段 2？

---

## 后续工作计划

> 记录于 2026-08-14（arch-explore「考虑下一步的工作」定案）。路线图状态见 `docs/development-phases.md`。

### P0 — 阶段 0 收尾（已完成）
- [x] `docs/development-phases.md`：勾选阶段 0 checkbox + 修正 SCM_CREDENTIALS 表述 + 执行路径清单改 4 条

### P1 — 阶段 1 开工前置决策（用 arch-design）
- [ ] **Q1 后端集成模型**（阻塞）：`prepare()`/`ExecEnv` 前缀包装 vs 接线 `SandboxExecutor` trait vs
      `execute_sync_sandboxed` 内联分支——三选一并落 ADR
- [ ] **Q2 bwrap 删除时机**：建议保留 bwrap 到阶段 2 完成（消除后台安全空窗），D2 顺延
- [ ] Q3-Q7 确认型：`execute_interactive_sandboxed` 归阶段 1（本文件已按此假设）；`CommandSpec`
      别名约定；D5 在 policy 层 vs seabox 映射层收紧；seabox crate path 依赖（同目录树，见 Q6）；
      `PUBLIC_SANDBOX_BACKENDS` 文案 + facts-drift 同步

### P2 — 阶段 1 实现（CodeWhale，P1 定案后走 exec-plan）
- [ ] `sandbox/seabox.rs` 新后端：policy → `SandboxConfig` 映射（复用 `get_writable_roots` +
      git worktree 逻辑），`SandboxType::Seabox` + Linux 默认（P0-1）
- [ ] `execute_sync_sandboxed` 分叉走 `Sandbox::execute`（路径 1）；`execute_interactive_sandboxed`
      走 `spawn(Inherit)`（路径 2）
- [ ] 拒绝检测结构化（P1-2）；`map_safety_level_to_behavior` 接线 + D5（P0-2）
- [ ] 移除 `prefer_bwrap`（P2-1）；Q2 定案后删 `bwrap.rs` / `seccomp.rs`（P1-3）
- [ ] 测试重写：mod.rs / bwrap.rs 的 bwrap argv 断言 → seabox 配置映射 + 同步路径集成测试

### P3 — 阶段 2（后续）
- [ ] 后台非 tty / 后台 tty 接 seabox（路径 3/4）；persist 保持 DangerFullAccess 无沙箱

### P4 — 阶段 3（后续）
- [ ] scm_creds 容器化探针测试；同步与后台/tty parity 测试
