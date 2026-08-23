# CodeWhale seabox 后端替换设计计划

> 日期：2026-08-22　·　编排模式：full
> 仓库：设计文档在 **seabox**（`/home/zs/Develop/seabox`）；实施目标在 **CodeWhale 个人 fork**（`/home/zs/Develop/CodeWhale_seabox`，分支 main，HEAD `c9b9559a7`）。
> 上级设计：`docs/arch/codewhale-integration/design.md`（已批准，决策 D1-D6）+ `context.md`。

## 背景

将 seabox 以 crate 依赖（库级，`default-features=false`）方式集成进 CodeWhale 个人 fork，替换并删除 bwrap 后端，覆盖**全部三条执行路径**（前台/后台非 tty/后台 tty），并修复 context.md 的 P0-1/P0-2/P1-1/P1-2/P1-3/P2-1 六项批判。

### fork 现实修正（对阵 design.md 上游假设，2026-08-22 复核）

design.md 基于上游调研，行号与调用链在 fork 上不一致，关键差异：

| design.md 假设 | fork 实测 |
|---|---|
| 前台同步 = `execute_sync_sandboxed`（§3.3） | 生产 Bash 前台 `BashTool::execute` → `execute_foreground_via_background`（`tools/shell.rs:3384`）内部以 `background=true` 塞进 **job table** 轮询；`execute_sync_sandboxed`（`shell.rs:1752`）生产**零调用**（仅单元测试触达）。全部生产 `execute_with_options_env*` 调用 `background=true` |
| 后台非 tty、tty 是独立 stage 2 | fork 的「前台」与「后台非 tty」共用 `spawn_background_sandboxed`（job table）。**要落实 P0-1（Linux 默认 Seabox）必须把 seabox 接进该路径** |
| tty 留 stage 2 | Linux 默认切 Seabox + 删 bwrap 后，tty 命令同样命中 Seabox 后端。**本计划一并实现 tty via `seabox::StdioConfig::Fd`**，否则交互 tty 会话回归成无沙箱/报错，集成不完整 |

决议（用户确认）：
- **D-A**：阶段 1 接真实前台路径 = 把 design §4.1-§4.3（`ShellChild::Seabox`、后台非 tty `Sandbox::spawn(Piped)`、tty `StdioConfig::Fd`）一并纳入本交付，使 Linux 默认 Seabox 生效。
- **D-B**：bwrap 删除（design D2）与 Linux 默认切换（P0-1）在**同一交付内一并完成**，不留空窗。

## 设计

### 整体方案

```
fork CommandSpec ──prepare──▶ seabox::SandboxConfig + seabox::CommandSpec   （sandbox/seabox.rs 翻译）
                                   │
                              ExecEnv.seabox: Option<SeaboxPlan>            （sandbox/mod.rs 扩展）
                                   │
spawn_background_sandboxed ──Sandbox::from_config + spawn ──▶ SandboxChild   （非 tty: Piped；tty: Fd(slave)）
                                   │
                        ShellChild::Seabox / reader 线程 / 完成事件           （结构化拒绝经 blocked/timed_out）
```

seabox 是全权执行（fork+waitpid），不同于 bwrap 的「命令前缀包装」。因此 `SandboxManager::prepare` 对 `SandboxType::Seabox` 不再产出包装 argv，而是产出**透明 argv**（program+args 原样）+ 携带翻译后的 `SeaboxPlan`；执行落在 `spawn_background_sandboxed` 的 seabox 分支，直接调 `seabox::Sandbox::spawn/execute`。

### 架构决策

1. **契约载体**：`ExecEnv` 增加 `pub seabox: Option<SeaboxPlan>`（`SeaboxPlan { sandbox_config: seabox::SandboxConfig, command_spec: seabox::CommandSpec }`）。`prepare()` 是唯一翻译点（语义映射集中一处，符合 design §3.1）。
2. **fail-closed**：`SandboxType::Seabox` 但 `exec_env.seabox.is_none()` 时，spawn 路径返回错误（不静默降级为无沙箱）。
3. **结构化拒绝（P1-2）**：seabox 的 `SandboxChild::blocked()` / `ClassifyExited` 取代 stderr 文本启发式。`BackgroundShell` 增 `seabox_blocked: Option<(u32,u32)>`，监控侧在 `try_wait` 后捕获；`sandbox_denied()` 对 Seabox 用结构化判定。
4. **D5 接线点（P0-2）**：`tools/shell.rs` `BashTool::execute` 在 `analyze_command`（L4041）后、构造 `policy_override`（L4070）处调用 `map_safety_level_to_behavior(safety.level, &base_policy)`；匹配 `Sandboxed(policy)` 用其中的 policy 作 override。**D5：`SafetyLevel::Safe` → `network_access=false`**（在 `policy.rs` 的 `map_safety_level_to_behavior` 内实现钳制，生产接线修复死代码）。
5. **平台门控**：`SandboxType::Seabox`、`sandbox/seabox.rs`、`shell.rs` 的 Seabox 分支一律 `#[cfg(all(target_os = "linux", not(target_env = "ohos")))]`（镜像现有 `LinuxBubblewrap`）；`seabox` 依赖可无条件声明（crate 非 Linux 可编译、运行时 bail，见 seabox `lib.rs:175`）。
6. **默认切换（P0-1）**：`get_platform_sandbox` Linux 默认返回 `Some(SandboxType::Seabox)`（seabox 无外部二进制可探测，构建即可用）。`prefer_bwrap` 字段与 `with_bwrap_preference`/`set_prefer_bwrap` 全量移除（D2/P2-1）。⚠ 默认策略 `WorkspaceWrite` 下 `should_sandbox()==true`，故**默认开沙箱会波及既有 shell 测试套件**（见 T9 测试适配）。
7. **persist（D6）**：`DangerFullAccess` → `should_sandbox()==false` → `prepare` 走 `prepare_unsandboxed`（`exec_env.seabox=None`），persist 不受影响。
8. **seccomp deny 预留**：CodeWhale 现有策略无 syscall deny 清单（`seccomp.rs` 死代码删除后，不给 deny 清单）；`seabox.rs` 预留 `with_seccomp_deny_nr` 扩展点，不在本交付启用。

### 配置映射（bwrap → seabox，`sandbox/seabox.rs` `prepare`）

| CodeWhale 策略 | seabox 配置 |
|---|---|
| `DangerFullAccess` / `ExternalSandbox` | `None`（不沙箱，`should_sandbox()` 已拦） |
| `ReadOnly` | `with_landlock("/:ro")` + `.codewhale`/`.deepseek` 例外 → `with_ro_bind`（自动 mnt ns） |
| `WorkspaceWrite { writable_roots, network_access, .. }` | `with_landlock("/:ro")` + workdir/writable_roots rw（`with_ro_bind` 或 `with_bind`） |
| `network_access` | `true` = 不 unshare net（保留宿主）；`false` = `with_unshare_net()` |
| `SafetyLevel::Safe`（D5） | 钳制 `network_access=false`（经 `map_safety_level_to_behavior`） |
| seccomp deny | 预留 `with_seccomp_deny_nr`（本交付不启用） |
| 默认隔离 | `with_unshare_user()` + `with_unshare_pid()` + `with_unshare_uts()` + `with_unshare_ipc()` + `with_unshare_cgroup()`（对应用户确认的 `--unshare-all` 子集；seabox 自动处理 user/pid 依赖） |
| timeout | `seabox::CommandSpec::with_timeout` |
| env/cwd | `seabox::CommandSpec` 透传 |

约束：翻译在 `sandbox/seabox.rs` 纯函数内完成，不做 I/O；`SeaboxPlan` 由 fork `CommandSpec`（`sandbox/mod.rs:72`，含 `program/args/cwd/env/timeout/sandbox_policy`）推导。

### 接口变更（seabox 侧零改动，已就绪）

- seabox 公开 API（`/home/zs/Develop/seabox/src/lib.rs`）已含：`Sandbox::from_config`、`Sandbox::spawn(spec, StdioConfig)`、`Sandbox::execute(spec) -> (CommandOutput, ExitReason)`、`Sandbox::classify_exit`、`CommandOutput{exit_code,blocked_syscall,stdout,stderr,timed_out}`、`ExitReason{Ok,Denied{mechanism,message},Program,InternalError}`、`SandboxChild{take_stdout/stderr/stdin,id,kill,try_wait,wait,wait_timeout,blocked,timed_out}`、`StdioConfig{Inherit,Piped,Fd{stdin,stdout,stderr}}`、`CommandSpec` builder、`SandboxConfig` builder（含 `with_process_group(bool)`）。**本交付只改 CodeWhale fork，不改 seabox。**

## 涉及文件

**实施目标 = CodeWhale fork（`/home/zs/Develop/CodeWhale_seabox`）**：

- 新增：`crates/tui/src/sandbox/seabox.rs`
- 修改：`crates/tui/Cargo.toml`、`crates/tui/src/sandbox/mod.rs`、`crates/tui/src/sandbox/policy.rs`、`crates/tui/src/tools/shell.rs`、`crates/tui/src/config.rs`、`crates/tui/src/core/engine.rs`、`crates/tui/src/acp_server.rs`、`crates/tui/src/lib.rs`、`crates/tui/src/tools/diagnostics.rs`、`crates/tui/src/tui/app/init.rs`、`crates/tui/src/tui/ui/frame.rs`、`crates/tui/src/runtime_threads.rs`（如存在）、`docs/SANDBOX.md` 等文档、web facts 引用（如有）
- 删除：`crates/tui/src/sandbox/bwrap.rs`、`crates/tui/src/sandbox/seccomp.rs`
- 范围外（勿动）：`sandbox/backend.rs`、`opensandbox.rs`、`process_hardening.rs`、`seatbelt.rs`、`windows.rs`

## 测试策略

### 测试合同（Phase 3 review 依据）

#### N1: Linux 默认后端 = Seabox
- **验收方法**: `cargo test -p codewhale-tui sandbox` 中断言 `get_platform_sandbox()` Linux 返回 `Some(SandboxType::Seabox)`；`SandboxManager::default().configured_sandbox()` 同理
- **优先级**: 必测

#### N2: 前台/后台非 tty seabox parity（Landlock）
- **验收方法**: 后台 job 以 seabox 执行——`/:ro` 下写只读文件被拒（`ExitReason::Denied`/`stderr` 报 Read-only）、`WritableRoot` 例外可写、stdout/stderr 捕获完整
- **优先级**: 必测

#### N3: tty seabox（`StdioConfig::Fd`）
- **验收方法**: openpty slave 注入 seabox，master 读写，`combined_output` 一致；无回归到 portable_pty 无沙箱路径
- **优先级**: 必测

#### N4: SafetyLevel::Safe → network_access=false（D5）
- **验收方法**: `map_safety_level_to_behavior(Safe, policy)` 返回的 policy `has_network_access()==false`（policy.rs 单测）；`BashTool` 接线后 Safe 命令在 `--unshare-net` 下无法访问外部 IP
- **优先级**: 必测

#### N5: 结构化拒绝（P1-2）
- **验收方法**: 触发被拒绝 syscall → `BackgroundShell.sandbox_denied()==true` 且基于 `blocked`/`ExitReason::Denied`（非 stderr 文本启发式）；`shell_sandbox_denied_hint` 照常带 posture
- **优先级**: 必测

#### N6: 进程组 kill
- **验收方法**: seabox child 后台长任务（含子进程）→ `kill(task_id)` 全树回收，无孤儿（`--unshare-pid` 下验证）
- **优先级**: 必测

#### N7: bwrap/seccomp 删除（D2/P1-3）
- **验收方法**: `rg -n bwrap crates/tui` 为空；`rg -n prefer_bwrap crates/tui` 为空；`cargo build --workspace` 通过（Linux）
- **优先级**: 必测

#### N8: persist 无沙箱（D6）
- **验收方法**: `DangerFullAccess` 命令 `exec_env.seabox.is_none()`、走 std::process、persist 服务跨 manager drop 存活（沿用 `exec_persistent_service.rs`）
- **优先级**: 必测

#### N9: 无回归基线
- **验收方法**: `LC_ALL=C LANG=C cargo test --workspace -- --skip dispatcher_diagnostics_are_in_process_and_read_only`——新增失败数 = 0（基线 9 个确定性失败 + 2 flaky + 1 环境挂死为 fork 现状，**不在本交付修复**）
- **优先级**: 必测

### 测试框架与命令

```bash
# fork 内执行；基线 locale 用 C 避免 i18n 文案干扰断言
cd /home/zs/Develop/CodeWhale_seabox
cargo check -p codewhale-tui
cargo test -p codewhale-tui   # 单 crate 相关用例先用过滤名跑，最后全量
LC_ALL=C LANG=C cargo test --workspace -- --skip dispatcher_diagnostics_are_in_process_and_read_only
cargo clippy -p codewhale-tui -- -D warnings
rg -n 'bwrap|prefer_bwrap' crates/tui  # 期望无命中
```

### 命中风险：默认 sandbox 开启对既有测试的影响

默认从「无沙箱」变为「Seabox」后，默认 `SandboxPolicy::default()`（WorkspaceWrite）下所有 shell 执行进入 Landlock 沙箱。既有测试若写入 `/tmp`、访问网络、或以 `sandbox_type` 断言 bwrap/None，会失败。T9 专项适配：
- 语义属「无沙箱路径」的测试（如测试 std::process 行为、persist、process-hardening）→ 显式 `SandboxPolicy::DangerFullAccess`
- 属于新默认语义（写 `/tmp` 被拒）→ 按其意图改为写 workspace/writable root，或显式加例外
- 不与 N9 基线失败混淆（reasoning-effort 等 9 个失败是 fork 现状）

## 波及文档

- `docs/arch/codewhale-integration/design.md` — 阶段 1/2 状态 → 标记实施完成（Phase 4 处理）
- `docs/arch/codewhale-integration/context.md` — 复核结论 → 补充 fork 现实修正
- fork 侧 `docs/SANDBOX.md` / `docs/ARCHITECTURE.md` / `docs/CONFIGURATION.md` — bwrap→seabox 后端描述
- `docs/development-phases.md` — Phase 4 状态至少更新为「集成库级后端实施中/完成」

## 风险与注意事项

| 风险 | 缓解 |
|---|---|
| 默认开沙箱波及大量既有测试 | T9 专项适配 + N9 基线对比；不改 9 个确定基线失败 |
| tty+seabox 边界 | 端到端 tty smoke（N3）；`StdioConfig::Fd` + master 读在 fork openpty 上已有结构 |
| pid ns kill 语义 | 复用 seabox 组杀 `kill(-kill_pid)`（seabox 已测）；N6 验证 |
| `PUBLIC_SANDBOX_BACKENDS` 被 web 正则解析 | 文案改为 seabox 前先确认 `web/scripts/facts-lib.mjs`/`facts-drift.ts`+fixture 兼容（T7 处理） |
| 结构化拒绝改动遗漏后台完成事件 | `sandbox_denied()` 只对 `SandboxType::Seabox` 走结构化分支，其余保持现状 |
| ohos/windows 编译 | 所有 Seabox 引用 target-gate；seabox 依赖编译期跨平台可编译 |
| 回滚 | 每任务独立提交，可 revert；bwrap 删除与默认切换同交付、经 N7 后生效 |