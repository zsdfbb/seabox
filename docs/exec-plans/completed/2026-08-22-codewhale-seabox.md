# CodeWhale seabox 后端替换 执行计划

> 日期：2026-08-22　·　编排模式：full　·　实施目标 = **CodeWhale fork**：`/home/zs/Develop/CodeWhale_seabox`
> 参考设计计划：`docs/design-plans/2026-08-22-codewhale-seabox.md`
> 约定：任务均在此 fork 下执行（`cd /home/zs/Develop/CodeWhale_seabox`）；测试基线用 `LC_ALL=C`。seabox crate 位于 `/home/zs/Develop/seabox`（本交付不改 seabox）。

## 任务清单

> 依赖序：T1 → T2 → T3 → T4 → T5 → T6 → T7 → T8 → T9。T9 为默认沙箱开启后的回归适配（最大）。

### Task 1: crates/tui — seabox 依赖 + 后端翻译模块 [type=impl]
- **涉及目录**: `crates/tui/`
- **涉及文件**: `crates/tui/Cargo.toml`, `crates/tui/src/sandbox/seabox.rs`(NEW), `crates/tui/src/sandbox/mod.rs`(仅加 `pub mod seabox;`)
- **描述**: 声明 `seabox = { path = "../../../seabox", default-features = false }` 到 `[dependencies]`；新建 `sandbox/seabox.rs`：定义 `SeaboxPlan { sandbox_config: seabox::SandboxConfig, command_spec: seabox::CommandSpec }` 与 `pub fn prepare(spec: &CommandSpec) -> anyhow::Result<Option<SeaboxPlan>>`，实现 design 配置映射表（ReadOnly/WorkspaceWrite → landlock `/:ro` + 例外/工作目录 rw；network_access → `with_network`/`with_unshare_net`；默认 isolation = user+pid+uts+ipc+cgroup；timeout/stdin/env/cwd 透传；`should_sandbox()` false → `Ok(None)`）。模板块 `#[cfg(all(target_os = "linux", not(target_env = "ohos")))]`。预留 `with_seccomp_deny_nr` 扩展点（不启用）。
- **关联测试任务**: T2
- **验证方法**: `cargo check -p codewhale-tui`（T1 结束时可编译；sandbox/mod.rs 仅加模块声明，不引 prepare 逻辑）

### Task 2: sandbox/seabox.rs — 映射单元测试 [type=test]
- **涉及文件**: `crates/tui/src/sandbox/seabox.rs`（`#[cfg(test)] mod tests`）
- **描述**: 覆盖：`ReadOnly` → `/:ro` + `.codewhale`/`.deepseek` ro_bind 例外；`WorkspaceWrite` → 工作目录 rw；`network_access=true/false` → 是否 unshare net；`DangerFullAccess`/`ExternalSandbox` → `None`；timeout 透传；`SeaboxPlan.command_spec` 的 program/args/env/cwd 与 fork spec 一致。
- **验证方法**: `cargo test -p codewhale-tui sandbox::seabox -- --nocapture` — 期望 passed
- **关联 impl**: T1

### Task 3: sandbox/mod.rs + policy.rs — 后端分发接 Seabox、D5、删 bwrap/seccomp [type=impl]
- **涉及目录**: `crates/tui/src/sandbox/`
- **涉及文件**: `crates/tui/src/sandbox/mod.rs`, `crates/tui/src/sandbox/policy.rs`, 删除 `crates/tui/src/sandbox/bwrap.rs`, 删除 `crates/tui/src/sandbox/seccomp.rs`
- **描述**:
  1. `SandboxType::Seabox`（cfg linux not ohos）+ `Display` → `"seabox"`。
  2. `get_platform_sandbox` Linux 默认返回 `Some(SandboxType::Seabox)`（不复用 bwrap 探测）；移除 `get_platform_sandbox_with_bwrap_preference` 与外层 `with_bwrap_preference`。
  3. `SandboxManager` 移除 `prefer_bwrap` 字段 / `with_bwrap_preference` / `set_prefer_bwrap`。
  4. `ExecEnv` 增 `pub seabox: Option<SeaboxPlan>`；`prepare()` Seabox 臂走 `prepare_seabox`（透明 argv + `seabox::SeaboxPlan::prepare(&spec)`）。`external sandbox` 注意：`ExecuteEnv` 构造点与测试模块内直接字段初始化需同步补字段。
  5. `was_denied` / `denial_message` 加 Seabox 臂（结构化：`blocked.is_some()` 判断交由 shell.rs 结构化路径；静态函数对 Seabox 保留一个合理默认）。
  6. `PUBLIC_SANDBOX_BACKENDS` 文案 `"bubblewrap (Linux, opt-in when installed)"` → `"seabox (Linux, default)"`。
  7. `policy.rs`：`map_safety_level_to_behavior` **生产接线**（修复 P0-2）——`SafetyLevel::Safe` 分支返回的 `Sandboxed(policy)` 钳制 `network_access=false`（新增 `force_no_network` 帮助函数，仅影响 `WorkspaceWrite`/`ExternalSandbox` 的 network 字段）。
  8. 删除 `bwrap.rs`、`seccomp.rs`；移除 mod.rs 里 bwrap/seccomp 引用与**依赖 bwrap 的 `#[cfg(test)]` 用例**（`linux_bwrap_selection_requires_opt_in_and_executable`、`test_parity_manager_with_bwrap`、`bwrap_denial_is_not_inferred_from_seccomp_text` 等），一并改写为 Seabox 语义或删除。
- **关联测试任务**: T4
- **依赖**: T1
- **验证方法**: `cargo check -p codewhale-tui` + `cargo test -p codewhale-tui sandbox` 编译通过

### Task 4: sandbox — 分发测试改写为 Seabox 断言 [type=test]
- **涉及文件**: `crates/tui/src/sandbox/mod.rs`（tests）, `crates/tui/src/sandbox/policy.rs`（tests）
- **描述**: 改写默认断言：`linux_default_never_claims_an_unwired_sandbox` → Linux 默认返回 `Seabox` 且 `prepare()` 产出 `exec_env.seabox`（携带 plan）；`DangerFullAccess` → `seabox=None`；`Display(Seabox)=="seabox"`；`map_safety_level_to_behavior(Safe,..)` → policy `has_network_access()==false`；`WorkspaceWrite` 保留。
- **验证方法**: `cargo test -p codewhale-tui sandbox` — 期望 passed
- **关联 impl**: T3

### Task 5: tools/shell.rs — 三路径 seabox 化 + 结构化拒绝 + D5 hook [type=impl]
- **涉及目录**: `crates/tui/src/tools/`
- **涉及文件**: `crates/tui/src/tools/shell.rs`
- **描述**:
  1. `ShellChild` 增 `#[cfg(all(target_os="linux", not(target_env="ohos")))] Seabox(seabox::SandboxChild)` 变体；`process_id()` → `child.id()`、`try_wait()`/`kill()` 委托（kill 走 seabox 组杀）。
  2. `spawn_background_sandboxed`：当 `exec_env.seabox.is_some()`：
     - 非 tty → `seabox::Sandbox::from_config(plan.sandbox_config.clone())?.spawn(&plan.command_spec, StdioConfig::Piped)`；`take_stdout/take_stderr` 接现有 `spawn_reader_thread`；`take_stdin` → `StdinWriter::Fd`。复用现有 stdout/stderr buffer + job table。
     - tty → openpty 保持；`StdioConfig::Fd { stdin: slave, stdout: slave, stderr: slave }`，读 master。无沙箱 tty 保留 portable_pty 路径。
     - `seabox.is_none()` 但 `sandbox_type==Seabox` → 返回错误（fail-closed），不降级。
  3. `BackgroundShell` 增 `seabox_blocked: Option<(u32,u32)>`；后台监控在 `child.try_wait()` 完成后捕获 `child.blocked()`，超时经 `timed_out()`；完成事件 `ShellResult.sandbox_denied` 对 `SandboxType::Seabox` 用 `seabox_blocked.is_some()`（结构化，替代 stderr 启发式）。同步/其它路径保持 `was_denied` 现状。
  4. `BashTool::execute`：`analyze_command` 后构造 `policy_override` 处，调用 `map_safety_level_to_behavior(safety.level, &context.elevated_sandbox_policy)`，`Sandboxed(policy)` → 用该 policy 作 override（D5 生效）；`RequiresApproval`/`Dangerous` → 维持现状语义。
  5. `execute_sync_sandboxed`（background=false 的外部/测试调用）也走 seabox（`seabox::Sandbox::execute`）——设计 §3.3 保留。
- **关联测试任务**: T6
- **依赖**: T3（ExecEnv.seabox 就绪）
- **验证方法**: `cargo check -p codewhale-tui`

### Task 6: shell — seabox parity + 结构化拒绝 + tty smoke [type=test]
- **涉及文件**: `crates/tui/src/tools/shell/tests.rs`（新增用例）
- **描述**: N2/N3/N5/N6 验收：后台 job 以 seabox 执行、Landlock 只读拒绝 + 例外可写、stdout/stderr 捕获；触发被拒 syscall → `sandbox_denied==true`（结构化）；tty smoke（`StdioConfig::Fd`）；进程组 `kill`。用例对 blob 用 `SandboxPolicy` 显式指定（避免依赖默认翻转）。
- **验证方法**: `cargo test -p codewhale-tui tools::shell -- --nocapture` + 过滤新增用例名 — 期望 passed
- **关联 impl**: T5

### Task 7: 全仓 prefer_bwrap / bwrap 引用清理 [type=impl]
- **涉及文件**: `crates/tui/src/config.rs`, `crates/tui/src/core/engine.rs`, `crates/tui/src/acp_server.rs`, `crates/tui/src/lib.rs`, `crates/tui/src/tui/app/init.rs`, `crates/tui/src/tui/ui/frame.rs`, `crates/tui/src/runtime_threads.rs`, `crates/tui/src/tools/diagnostics.rs`, web facts（若 `PUBLIC_SANDBOX_BACKENDS` 文案被正则消费）
- **描述**: 移除 `prefer_bwrap` 字段、merge 行、`EngineConfig.prefer_bwrap`、诊断读点（lib.rs 3491/3871/4933/6502 等）、`acp_server.rs` setter 调用；`diagnostics.rs` 移除 bwrap 探针；若 `PUBLIC_SANDBOX_BACKENDS` 变化则同步 `web/scripts/facts-lib.mjs`/`web/lib/facts-drift.ts` 与 fixture。
- **关联测试任务**: T8
- **依赖**: T3
- **验证方法**: `cargo check -p codewhale-tui`

### Task 8: 清理验证 [type=test]
- **涉及文件**: 上述文件相关测试 + `crates/tui/src/tools/diagnostics.rs` 测试
- **描述**: `rg -n prefer_bwrap crates/tui` → 空；`rg -n bwrap crates/tui` → 空（N7）；`diagnostics.rs` bwrap 探针测试改写/删除；web facts 相关测试通过。
- **验证方法**: `rg` 命令 + `cargo test -p codewhale-tui diagnostics`
- **关联 impl**: T7

### Task 9: 默认沙箱开启后的回归适配 + 全量基线 [type=test]
- **涉及目录**: `crates/tui/tests/`, `crates/tui/src/tools/shell/tests.rs`, 及各受影响测试
- **描述**: Linux 默认 Seabox 后跑 `cargo test -p codewhale-tui`，triage 失败：语义属「无沙箱路径」→ 显式 `DangerFullAccess`；属新默认语义（Landlock 拒绝 /tmp/网络）→ 按其意图改策略或加例外；其余为真实回归 → 修复。不与 N9 基线失败（reasoning-effort 9 个 + flaky + 1 环境挂死）混淆。
- **验证方法**: `LC_ALL=C LANG=C cargo test --workspace -- --skip dispatcher_diagnostics_are_in_process_and_read_only` — 失败集 ⊆ 基线（9 确定 + ≤2 flaky + 1 env），无新增
- **关联 impl**: T3/T5/T7
- **MANUAL_ACK_REQUIRED**: 无

## 验证清单
- [ ] N1-N9 全部通过
- [ ] `rg -n 'bwrap|prefer_bwrap' crates/tui` 为空
- [ ] `cargo build --workspace`（Linux）+ `cargo clippy -p codewhale-tui -- -D warnings`
- [ ] 基线失败集 ⊆ 9 确定性 + 2 flaky + 1 环境挂死（LC_ALL=C）