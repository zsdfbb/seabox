# 执行计划: capability 权限管理

> 设计: `docs/design-plans/cap-management.md` + `docs/arch/cap-management/design.md`
> ADR: `docs/adr/0004-capability-management.md`
> 模式: full（Write → Execute(impl→review) → Finalize → Check）

每个任务 = 实现 subagent（写码→写测试→跑测试）→ 独立 review subagent（通过/不通过，最多 3 轮）。任务串行执行。

---

## 任务列表

### Task 1 (impl+test): config.rs — Capability 类型 + CapOp + CapabilityConfig + with_* 方法

**文件**: `src/config.rs`

**改动**:
1. `Capability(u16)` 新类型 + 41 个 ABI 常量（`CHOWN=0` … `CHECKPOINT_RESTORE=40`，从 `uapi/linux/capability.h` 翻译，注释来源）+ `from_name(&str) -> Option<Capability>`。**不 import libc**（与 MS_* 常量并列，config 层纯数据）。
2. `CapOp` 枚举：`Add(Capability)` / `Drop(Capability)` / `AddAll` / `DropAll` + `from_cli(name, is_add)`（`ALL` 特判）。
3. `CapabilityConfig { ops: Vec<CapOp>, inherit_base: bool }` + `Default`。
4. `SandboxConfig` 加 `pub capabilities: CapabilityConfig` + `Default` 补 `capabilities: CapabilityConfig::default()`。
5. `with_cap_add` / `with_cap_drop`（返回 `anyhow::Result<Self>`，仿 `with_landlock`）；`with_cap_add_all` / `with_cap_drop_all` / `with_cap_inherit`（返回 `Self`）。
6. 单元测试：`from_name` 命中/未知、`with_cap_add/drop` 位操作、`CapabilityConfig::default`。

**测试**: 本任务内置单测 + `tests/config_test.rs` 跑通。

---

### Task 2 (impl+test): src/linux/caps.rs — 三条原语 + resolve_caps + read_bounding_set

**新文件**: `src/linux/caps.rs`

**改动**:
1. 常量（从 `uapi/linux/capability.h` / `prctl.h` 翻译，注释来源）：`PR_CAPBSET_DROP=24`、`PR_CAP_AMBIENT=47`、`PR_CAP_AMBIENT_RAISE=2`、`_LINUX_CAPABILITY_VERSION_3=0x20080522`、`CAP_SETPCAP=8`、`CAP_LAST_CAP=40`。
2. `#[repr(C)]` V3 结构体：`CapHeader { version: u32, pid: i32 }`、`CapData { effective: u32, permitted: u32, inheritable: u32 }`（仿 seccomp.rs `sock_filter` 风格）。
3. `pub const CAP_F_NEED_CAPSET: u8 = 1` / `CAP_F_NEED_BOUNDING: u8 = 2` / `CAP_F_NEED_AMBIENT: u8 = 4`。
4. `pub unsafe fn apply_caps(requested: u64, flags: u8)`：child，零堆，三条原语按序（capset→bounding→ambient），失败 `_exit(1)`，EPERM best-effort 吞掉（bwrap 语义）。只遍历置位 bit（`trailing_zeros`）。
5. `pub fn resolve_caps(cfg, is_root, userns_active) -> ResolvedCaps { requested, flags }`：父进程，纯逻辑可单测。
6. `pub fn read_bounding_set() -> u64`：父进程从 `/proc/self/status` 的 `CapBnd` 解析（供 root bounding 分支用）。

**测试**: `resolve_caps` 纯逻辑单测（各场景 flags 判定）；`apply_caps` 编译级验证（真实行为由 Task 5 集成测试覆盖）。

---

### Task 3 (impl+test): child_setup.rs + linux/mod.rs — 插入点 + 接线

**文件**: `src/linux/child_setup.rs`、`src/linux/mod.rs`

**改动**:
1. `child_setup.rs`：`enter_child` 签名加按值标量 `caps_requested: u64, caps_flags: u8`；在 landlock 块（约 L220）之后、seccomp 块（约 L222）之前插入 `apply_caps(requested, flags)`（flags 非 0 才进）；更新模块 doc 步骤清单与 Safety 注释。
2. `linux/mod.rs`：`execute()` 中 fork 前调 `resolve_caps`（用最终 `effective_user` 决定 `userns_active`）；`enter_child(...)` 调用追加两实参；`effective_user` 计算加 `|| has_cap_add`（`!config.capabilities.ops.is_empty()`）。

**测试**: `cargo build` + 全量现有测试不破（重点 `mount_test` / `namespace_test`）。

---

### Task 4 (impl+test): lib.rs + main.rs — CLI + crate API 接线

**文件**: `src/lib.rs`、`src/main.rs`

**改动**:
1. `lib.rs`：`from_config` 的 `effective_user` 加 `|| !config.capabilities.ops.is_empty()`；L15 后 re-export `pub use config::{Capability, CapabilityConfig, CapOp};`。`SandboxImpl` trait 零改动。
2. `main.rs`：
   - clap flag：`--cap-add <CAP>`（可重复）、`--cap-drop <CAP>`（可重复）、`--cap-inherit`（bool）。
   - `CapAction` enum（Add/Drop/AddAll/DropAll）+ `collect_cap_actions(run_matches, cap_add, cap_drop)`（`indices_of` 保序，仿 `collect_mount_actions`）。
   - `main` 解构 / `cmd_run` 签名 / `build_config` 调用三处同步加参；`cmd_run` 中 `build_config` 后循环 `with_cap_*`（仿 mount_actions 循环）。
   - `build_config` 的 `effective_user` 加 `|| has_cap_add`。
   - 未知 cap 名报错（`with_cap_add` 的 Result 上抛）。

**测试**: `cargo build` + `--help` 显示三个新 flag + 现有 CLI 测试不破。

---

### Task 5 (test): tests/capability_test.rs — 探针 + 集成测试

**新文件**: `tests/capability_test.rs`（仿 mount_test.rs 骨架：`bin()`/`run_cli`/skip 守卫/OnceLock 探针）

**内容**:
1. 探针 P1（F2）：`capset` 清零后重提应 EPERM（经 CLI 验证）。
2. 探针 P2（F5）：写非零 uid_map 后 permitted 是否保留；不成立 → 非 root `--cap-add` 测试 skip。
3. 集成测试：T1 root 无 userns 收零 `CapEff=0`（`geteuid()!=0` skip）；T2 `--cap-drop ALL --cap-add CHOWN` 终态只含 CHOWN；T3 `--uid 0 --cap-add ALL` ns-root 全量；T5 未知 cap 名 exit 非零；T6 `--cap-add` 自动叠加 userns。
4. `/proc/self/status` 的 `CapEff`/`CapBnd` 解析辅助函数。

**测试**: `cargo test --test capability_test` 全过（探针失败 skip 而非 fail）。

---

### Task 6 (impl): examples/crate_api.rs — 示范 with_cap_drop_all

**文件**: `examples/crate_api.rs`

**改动**: 链式加 `.with_cap_drop_all()?` 或 `.with_cap_drop_all()`（按方法签名），示范默认收零。

**测试**: `cargo build --examples` 编译通过。

---

## 收尾验证

- `cargo test`（全量）
- `cargo clippy --all-targets -- -D warnings`
- `cargo fmt --check`
- 手动（unsandboxed）：`--cap-drop ALL --cap-add CHOWN` 终态 `CapEff=0x1`；非 root 默认 `CapEff=0`
