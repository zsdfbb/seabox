# CodeWhale seabox 后端替换 — 实施报告

> 日期：2026-08-22　·　编排：sequential-workflow **full**　·　实施目标 = CodeWhale 个人 fork `/home/zs/Develop/CodeWhale_seabox`（HEAD `c9b9559a7`）
> 参考：`docs/design-plans/2026-08-22-codewhale-seabox.md`、`docs/exec-plans/2026-08-22-codewhale-seabox.md`

## 概要

将 seabox 以 crate 依赖（`default-features=false`）集成进 CodeWhale 个人 fork，**替换并删除 bwrap 后端**，覆盖三条执行路径（前台/后台非 tty/后台 tty），落实 Linux 默认沙箱（P0-1）与 6 项批判修复。seabox 侧零改动（阶段 0 已就绪）。

**fork 现实修正**（设计文档上游假设 vs fork）：生产 Bash 前台实际经 `execute_foreground_via_background` → job table（`background=true`）执行，`execute_sync_sandboxed`（`shell.rs:1752`）生产零调用。故阶段 1 的 seabox 执行落于 `spawn_background_sandboxed`，tty 一并纳入（非如上游假设"同步=execute_sync_sandboxed、tty 属阶段 2"）。

## 交付物

| 项 | 状态 |
|---|---|
| seabox 依赖（`Cargo.toml`，path 上三级，`default-features=false`，仅拉 anyhow+libc+landlock） | ✅ |
| `sandbox/seabox.rs`（NEW）：`SeaboxPlan{SandboxConfig,CommandSpec}` + `prepare()` 策略→配置翻译（landlock `/:ro`+rw 根+ro_bind 例外 / netns / 默认隔离 user+pid+uts+ipc+cgroup / timeout/env 透传）| ✅，含 12 单测 |
| `SandboxType::Seabox`（cfg linux not ohos）取代 `LinuxBubblewrap`；`get_platform_sandbox` Linux 默认 Seabox | ✅ |
| `ExecEnv.seabox: Option<SeaboxPlan>`，`prepare` Seabox 臂透明 argv + plan 携带；fail-closed（Seabox 无 plan → Err）| ✅ |
| `ShellChild::Seabox` + `StdinWriter::Fd`；`spawn_background_sandboxed` 非 tty `Piped`+reader 线程 / tty `StdioConfig::Fd{slave×3}`+master 读（deviation：portable-pty 0.9 不暴露 slave raw fd → `libc::openpty`）| ✅ |
| `execute_sync_sandboxed` seabox 分支（`Sandbox::execute`，供 background=false 调用/测试）| ✅ |
| 结构化拒绝：`BackgroundShell.seabox_blocked` + `sandbox_denied()` = `blocked() || was_denied(stderr 兜底)`；`was_denied(Seabox)` 实现保守 landlock errno 启发式（parity）| ✅ |
| `map_safety_level_to_behavior` 生产接线（P0-2）+ **D5 Safe→network_access=false**（`force_no_network`）| ✅ |
| 删除 `sandbox/bwrap.rs` + `sandbox/seccomp.rs`；`prefer_bwrap` 全仓移除（`rg` 为空）；web facts 制品/杯具同步 | ✅ |
| 文档更新：seabox design.md §9、context.md 注记、development-phases.md Phase 4；fork docs/SANDBOX.md、CONFIGURATION.md、ARCHITECTURE.md、config.example.toml、web docs-map.ts | ✅ |

## 测试结果（对照验证合同 N1-N9）

| 合同 | 验证 | 结果 |
|---|---|---|
| N1 前端=Seabox | `get_platform_sandbox()`/`configured_sandbox()` | ✅ 用例绿 |
| N2 前台/后台非 tty parity | landlock 只读拒绝+例外可写+双流捕获 | ✅ `seabox_background_*` 用例 |
| N3 tty seabox | `StdioConfig::Fd`+master 读 smoke | ✅ `seabox_background_tty_injects_openpty_slave_and_captures_marker` |
| N4 Safe→no-network | `map_safety_level_to_behavior(Safe,..)` | ✅ `safe_level_clamps_network_access` |
| N5 结构化拒绝 | `blocked()||启发式`，端到端 | ✅ `*_sandbox_denied` 用例 |
| N6 进程组 kill | 双探针（leader+group ESRCH），真失败验证 | ✅ `seabox_background_kill_terminates_descendant_process_group` |
| N7 bwrap/seccomp 删除 | `rg 'bwrap\|prefer_bwrap' crates/tui` 空 + build 绿 | ✅ |
| N8 persist 无沙箱 | DangerFullAccess → std::process | ✅ 用例 |
| N9 无新回归 | 见下 | ✅ 收敛到基线 |

**tui lib 套件**：`LC_ALL=C cargo test -p codewhale-tui --lib`
- 首次：10385 过 / **16 失败**（9 基线 + 6 默认翻转 + 1 onboarding flaky）
- 适配后：10391 过 / **10 失败** = **基线 9（reasoning-effort 8 + unicode 1，fork main 现状）** + **1 并行 env flake**（`wl_paste_helper`，隔离跑通过）→ **⊆ 基线包络** ✅
- 新增 seabox/sandbox/shell 用例全绿（`--lib seabox` 25 过、`sandbox` 50/24 过、`diagnostics` 过）

**tui 集成/pty/cucumber**：
- cucumber 14 ✅；integration **268/1**（`failed_exec_kills_pending_service_and_exits_nonzero` → 已 stash 二分证明 **HEAD 同样超时**，基线环境挂）；pty **75/1**（`qa_pty::legacy_work_ctrl_t...` → **HEAD 同样失败**，基线 TUI 时序）

**构建/质量**：`cargo check -p codewhale-tui` 绿；`cargo check --workspace` 绿。`clippy -D warnings` 被 5 个**既有** crate 级错误阻断（`client/chat.rs`、`config.rs`、`structcopy.rs`、`latex_render.rs`、`overlays.rs`），非本次引入。

## 任务状态（T1-T9，每 impl 配独立 review）

| 任务 | 内容 | impl | review |
|---|---|---|---|
| T1 | seabox 依赖 + 后端翻译模块 | ✅ | ✅ 通过（M1 env parity/M2 `/` 排除后补）|
| T2 | seabox.rs 映射单测（TDD 落地 M1/M2）| ✅ | ✅ 通过（重派 1 次后定稿）|
| T3 | mod.rs/policy.rs 分发接 Seabox + D5 + 删 bwrap/seccomp | ✅ | ✅ 通过 |
| T4 | sandbox 分发测试改写 | ✅ | ✅ 通过 |
| T5+T5b | shell.rs 三路径 seabox 化 + 结构化拒绝 + D5 hook + landlock 拒绝 parity | ✅ | ✅ 通过（3 条非阻塞建议：master_fd 泄漏 LOW 已记录、测试判别力留 T6）|
| T6+T6b | shell seabox parity + tty smoke + kill 双探针 | ✅ | ✅ 通过（N6 判别力修复重派）|
| T7+T7b | prefer_bwrap 清理 + web facts 制品同步 | ✅ | ✅ 通过（P1 facts.generated.ts 补交）|
| T8 | 清理验证 | ✅ | 主 agent 亲验（rg 空、check-facts OK、diagnostics 绿）|
| T9 | 默认沙箱回归适配 + 全量基线 | ✅ | 6 个 shell 用例 DangerFullAccess 适配（断言零削弱）+ 收敛验证 |
| T10/T10b/T10c | **二进制实测发现的静默无沙箱缺口**（Phase 5 验证）：`run_sandbox_command`（`codewhale-tui sandbox run`）与 `execute_interactive_sandboxed`（交互 Bash 路径）仍走 wrapper 模型忽略 `exec_env.seabox` → 修复为消费 seabox 计划（`Sandbox::execute`/`StdioConfig::Inherit`）+ 全处 fail-closed guard + 穷尽审计（仅此二处，其余消费点均 seabox-aware）| ✅ | ✅ |

## 实测（真实二进制 `codewhale-tui sandbox run`）

- 默认 `workspace-write`：`echo ok` → 成功；**注意 `/tmp`/`$TMPDIR` 是策略声明的可写根**（`get_writable_roots` 默认含），非绕过。
- `--exclude-slash-tmp --exclude-tmpdir` 下写 `/tmp` → **landlock 拒绝**（`Permission denied` / 文件未创建 / 非零退出）——排除 tmp 后是判别性证明。
- `--writable-root <T>` 内写 → 成功（rw 规则生效）。
- `--policy danger-full-access` → 无沙箱（std::process 保留，D6）。
- 修复前：`sandbox run` 写 `/tmp` 成功（即使排除 tmp 也写）＝wrapper 静默绕过；修复后两条路径均受沙箱。

## 残留 / 已知项

- **基线失败保留（非本次引入）**：tui lib 9 个确定性（reasoning-effort 8 + unicode 1，fork main 现状）；integration/pty 各 1 个 HEAD 环境挂。
- **并行 env flake**：onboarding `explicit_codewhale_home_marker...`、clipboard `wl_paste_helper...`（隔离跑均过）。
- **deviation**：tty 用 `libc::openpty`（portable-pty 0.9 无 slave raw fd）；`seabox` 无 Landlock 能力探针（pre-5.13 内核运行时才失败，需后续补）。
- **LOW**：seabox tty spawn 失败路径 pty master fd 罕见泄漏（未修，已记录）。
- **次级文档**：fork `docs/INSTALL.md`、`TERMUX.md`、`HarmonyOS.md` 仍描述"opt-in bubblewrap"（未在本轮范围，建议随下轮更新）。
- **未提交**：全部改动在 fork 工作区（未 commit），供 review 后提交。

## 涉及文件（fork，非 `bwrap`/`seccomp` 均未提交）

新增 `crates/tui/src/sandbox/seabox.rs`；删除 `sandbox/bwrap.rs`、`seccomp.rs`；修改 Cargo.toml、sandbox/mod.rs、policy.rs、tools/shell.rs(+tests)、config.rs、engine.rs、acp_server.rs、lib.rs、runtime_threads.rs、diagnostics.rs、tui/{app.rs,app/init.rs,ui/frame.rs,underwater.rs}、workspace_trust.rs、commands/groups/config/status.rs、sandbox/{backend.rs,process_hardening.rs}、web/lib/{facts.generated.ts,facts-drift.test.ts,check-facts.test.ts,docs-map.ts}、Cargo.lock；文档 SANDBOX.md/CONFIGURATION.md/ARCHITECTURE.md/config.example.toml。

seabox 侧零代码改动；docs 更新：`docs/arch/codewhale-integration/design.md`(§9)、`context.md`、`docs/development-phases.md`。