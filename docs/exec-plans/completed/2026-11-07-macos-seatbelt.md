# 执行计划: macOS Seatbelt 后端

> 设计: `docs/arch/macos-seatbelt/design.md`（权威设计稿，14 章 + 附录 A）
> 上下文: `docs/arch/macos-seatbelt/context.md`（实测语义基线）
> 审查: `docs/arch/macos-seatbelt/review.md`（4 P0 + 6 P1，已全部落实）
> 设计计划: `docs/design-plans/macos-seatbelt.md`
> 模板: `docs/exec-plans/mount-namespace.md`

**目标**：让 macOS 成为一等目标平台（Seatbelt + `sandbox-exec`），同时 **Linux 行为零变化**（221 测试基线不动）。
**硬约束**：mac 与 linux 代码彻底拆分——`src/linux/**` 不得出现 `macos`，`src/macos/**` 不得出现 `crate::linux`（N13）。
**任务规模**：单任务 ≤5 文件；每个 `impl` 任务都有配对的 `test` 任务。

## 任务列表

---

### Task 1: Cargo.toml 依赖门控 + syscall_probe 分支 main

**类型**: `impl`
**依赖**: 无
**涉及文件**: `Cargo.toml`、`src/bin/syscall_probe.rs`

**改动**:
1. `Cargo.toml`：把 `landlock = "0.4"` 从 `[dependencies]` 移到 `[target.'cfg(target_os = "linux")'.dependencies]`；`libc = "0.2"` 保持无条件（macOS 侧需要 `fcntl`/`F_GETFD`/`FD_CLOEXEC`/`setpgid`/`dup2`）
2. `Cargo.toml`：第 15 行 feature 注释「anyhow/libc/landlock 恒为核心依赖」改为「anyhow/libc 恒为核心依赖；landlock 仅 Linux」
3. `src/bin/syscall_probe.rs`：**不要**用文件级 `#![cfg]`（实测 E0601 `main` function not found，因 `[[bin]]` 无条件声明）
4. `src/bin/syscall_probe.rs:36` 的 `fn main()` 改为统一入口 + 内部分支：`#[cfg(target_os="linux")] { linux_main() }` / `#[cfg(not(target_os="linux"))] { eprintln!("syscall_probe is Linux-only"); std::process::ExitCode::from(77) }`
5. 把原 `main` 体搬进 `#[cfg(target_os = "linux")] fn linux_main() -> std::process::ExitCode`
6. 对 `parse_i64`、`dispatch_syscall`、`use std::env`、`use std::process::ExitCode` **逐个**加 `#[cfg(target_os = "linux")]`（选 `77` 而非 `1`，避免与「预期拒绝」退出码混淆）

---

### Task 2: tests 门控批次 A

**类型**: `impl`
**依赖**: Task 1
**涉及文件**: `tests/capability_test.rs`、`tests/concurrent_fork_test.rs`、`tests/config_test.rs`、`tests/deny_detect_test.rs`

**改动**:
1. 每个文件**第一行**（`//!` 文档注释之前）加 `#![cfg(target_os = "linux")]`
2. 不改动任何测试函数体，不加其它 `#[cfg]`

---

### Task 3: tests 门控批次 B

**类型**: `impl`
**依赖**: Task 1
**涉及文件**: `tests/landlock_test.rs`、`tests/leak_test.rs`、`tests/mount_test.rs`、`tests/namespace_test.rs`

**改动**:
1. 每个文件第一行加 `#![cfg(target_os = "linux")]`
2. 不改动任何测试函数体

---

### Task 4: tests 门控批次 C

**类型**: `impl`
**依赖**: Task 1
**涉及文件**: `tests/network_test.rs`、`tests/profile_test.rs`、`tests/seccomp_test.rs`、`tests/spawn_test.rs`

**改动**:
1. 每个文件第一行加 `#![cfg(target_os = "linux")]`
2. 不改动任何测试函数体

---

### Task 5: 编译门禁验证（N1 / N2）

**类型**: `test`（配对 Task 1-4）
**依赖**: Task 1、Task 2、Task 3、Task 4
**涉及文件**: `Cargo.toml`、`src/bin/syscall_probe.rs`、`tests/*.rs`（仅构建与读取，不修改）

**改动**:
1. macOS 上跑 `cargo build --lib`（N1），再跑 `cargo build --lib --no-default-features`
2. macOS 上跑 `cargo build --bins --tests`（N2）
3. macOS 上跑 `cargo build --bin syscall_probe && ./target/debug/syscall_probe` ⇒ 退出码 **77**
4. 断言构建输出零新增 warning
5. 记录三条命令的结论到 PR 描述（这是设计 §3.1「已实测」结论的回归守卫）

---

### Task 6: src/macos/config.rs — 数据类型 + resolve() + is_configured() + validate()

**类型**: `impl`
**依赖**: 无（纯数据类型 + 纯逻辑，不依赖任何 macOS 平台 API）
**涉及文件**: `src/macos/config.rs`（新增）、`src/macos/mod.rs`（新增）、`src/lib.rs`（交叉点 1：加 `pub mod macos;`，1 行）

**改动**:
1. 新建 `src/macos/mod.rs`：`pub mod config; pub mod sbpl;` + `#[cfg(target_os = "macos")] mod imp;`（`imp` 由 Task 10 落地）
2. 新建 `src/macos/config.rs`（**无条件编译**）：`MacOsConfig`（9 字段，`preset: Option<MacPreset>` / `write: Vec<PathBuf>` / `deny_write: Vec<PathBuf>` / `tmp_writable: Option<bool>` / `read: Option<MacReadMode>` / `deny_read: Vec<PathBuf>` / `no_credential_deny: Option<bool>` / `allow_git_write: Option<bool>` / `net: Option<MacNetConfig>`）+ `#[derive(Clone, Debug, Default)]`
3. 定义 `MacReadMode { #[default] All, Only(Vec<PathBuf>) }`、`MacPreset { ReadOnly, WorkspaceWrite, FullAccess }`、`MacNetConfig { outbound: NetAccess, inbound_loopback: bool }`、`NetAccess { #[default] Deny, Loopback, Ports(Vec<u16>), All }`，各配 `Default`/`PartialEq`
4. 定义内部类型 `ResolvedPolicy`（8 字段，无 `Option`，`pub(crate)`）
5. `MacPreset::defaults()` 与 `MacPreset::baseline()`：按设计 §4.2 表格（ReadOnly/WorkspaceWrite/FullAccess 的 `tmp_writable=Some(true)`、`allow_git_write=Some(true)`、`Write` 分别为空/`[cwd]`/全盘；baseline 的 `tmp_writable=Some(false)`、`allow_git_write=Some(true)`）
6. `MacOsConfig::resolve()`：预设展开为基线 → `Option` 字段 `Some` 覆盖 / `None` 跟随；`Vec` 字段预设值在前 + 用户追加（去重保序）；`net` 与预设正交，`None` ⇒ `NetAccess::Deny`。**幂等纯函数**，除 `write` 的 workspace 展开外不碰文件系统
7. `MacOsConfig::is_configured()`：逐字段显式检查 9 个字段，全「未设置」⇒ `false`。`net` 用 `Option::is_some()` 判断，**不比对值**（A2：`--mac-net deny` 必须为 `true`）
8. `MacOsConfig::validate()`：**双向硬错误**。macOS 侧检查 `landlock`/`seccomp_deny_nrs`/`seccomp_filter_bytes`/`capabilities`/`mount.specs`/`namespaces.{user,ipc,mnt,pid,uts,cgroup}` 非默认 ⇒ `bail!("<field> is not supported on macOS")`；Linux 侧检查 `macos.is_configured()` ⇒ `bail!("--mac-* only applies on macOS")`。`timeout_*` / `process_group` / `StdioConfig` 不校验
9. 加 `with_mac_*` crate API（AGENTS.md 约定：每个 CLI flag 都要有对应 `with_*`）：语义化快捷方法 `with_mac_no_tmp_writable()` / `with_mac_no_git_write()` / `with_mac_no_credential_deny()` / `with_mac_read_all()`，底层完整签名 `with_mac_tmp_writable(Option<bool>)` / `with_mac_git_write(Option<bool>)` / `with_mac_credential_deny(Option<bool>)` / `with_mac_read_mode(Option<MacReadMode>)` / `with_mac_preset` / `with_mac_write` / `with_mac_deny_write` / `with_mac_workspace` / `with_mac_read` / `with_mac_deny_read` / `with_mac_net` / `with_mac_net_inbound`
10. **纪律**：本文件不得 `use` 任何 macOS-only 符号（`/dev/fd`、`sandbox-exec` 路径常量、Darwin-only `libc` item）；若某逻辑必须碰平台 API，移到 `imp` 侧

---

### Task 7: config 层单测（N3 / A1-A10）

**类型**: `test`（配对 Task 6）
**依赖**: Task 6
**涉及文件**: `src/macos/config.rs`（追加内联 `#[cfg(test)] mod tests`）

**改动**:
1. N3：`MacOsConfig::default()` 的 6 个 `Option` 字段全 `None`、3 个 `Vec` 全空；`MacReadMode::default() == All`；`NetAccess::default() == Deny`
2. A1：9 个字段各自单独设置 ⇒ `is_configured()==true`（逐字段 loop 或逐条 assert）
3. A2：`net = Some(MacNetConfig { outbound: Deny, .. })` ⇒ `is_configured()==true`（防 `PartialEq` 陷阱回归）
4. A3：`MacOsConfig::default()` ⇒ `is_configured()==false`
5. A4：`ReadOnly` + `tmp_writable=Some(false)` ⇒ `resolve().tmp_writable == false`
6. A5：预设 + 无字段 ⇒ `resolve()` 等于该预设 `defaults()`
7. A6：用户 `deny_read` 追加不冲掉内置凭据清单（含预设清单条目）
8. A7：`read` 为 `Some(Only(..))` / `Some(All)` 的切换
9. A8：`FullAccess` + 显式 `deny_read` ⇒ 用户 deny 仍保留；A9：纯预设 / 纯字段 / 预设+字段三形态均不 panic；A10：`resolve()` 连调两次结果相同（幂等）
10. 本文件测试**全平台可跑**，Linux CI 必跑

---

### Task 8: src/macos/sbpl.rs — SBPL 生成器

**类型**: `impl`
**依赖**: Task 6（需要 `ResolvedPolicy`）
**涉及文件**: `src/macos/sbpl.rs`（新增）、`src/macos/mod.rs`（`pub mod sbpl;`，已在 Task 6 登记则跳过）

**改动**:
1. 新建 `src/macos/sbpl.rs`（**无条件编译**）：`pub struct Plan { profile: String, params: Vec<(String, String)> }`
2. `pub fn build(policy: &ResolvedPolicy) -> anyhow::Result<Plan>`，固定 7 段顺序写死、不可配置、用户输入不影响段落位置：`(version 1)` → `(deny default)`|`(allow default)` → floor → 预设写白名单 → TMP 可写 → `deny_read`（凭据 + 用户追加，**最后一条 file 规则**） → network（最末）
3. floor：硬性地板（`(allow process*)` / `(allow sysctl-read)` / `(allow ipc-posix-shm)` / `(allow mach-lookup)` / `(allow file-read-metadata)` / 隐式写点 `/dev/null` `/dev/dtty` `/dev/stdout` `/dev/stderr` `/dev/dtracehelper` / `(literal "/")`）+ 系统地板（仅 `MacReadMode::Only`：`/usr` `/System` `/Library` `/private/var/db` `/private/etc` `/bin` `/sbin` `/var` `/dev` + 符号链接 `(literal "/etc")` `(literal "/tmp")`）
4. 写白名单：`WorkspaceWrite` 用 `subpath WS`；`allow_git_write=false` 时用 `(require-all (subpath WS) (require-not (subpath WS/.git)))`；`ReadOnly` 不产生写白名单；`FullAccess` 不产生（靠 `allow default`）
5. `pub(crate) fn norm(p: &Path) -> anyhow::Result<PathBuf>`：`~` 展开 + `fs::canonicalize`（`/var`→`/private/var`、`/tmp`→`/private/tmp`、`/etc`→`/private/etc`），`canonicalize` 失败即硬错误（`-D` 传不存在路径 `sandbox-exec` 不报错，规则静默失效）
6. 只允许 `subpath` / `literal` 两种匹配符，**禁止 `prefix`**（字符串前缀会跨目录越权）
7. 所有路径走 `-D` 参数，**绝不拼进 SBPL 字符串**：`WS` / `TMP` / `W0..Wn` / `D0..Dn` 全部 `param` 化；被引用的 param 必须定义
8. 注入拒绝：路径含 `"` / `)` / `;` / `\n` ⇒ `bail!`；空 `write` 不产生 `(subpath "")`
9. 网络段与预设正交：`Deny` 不写规则；`Loopback` ⇒ `(remote ip "localhost:*)` + （`inbound_loopback` 时）`(local ip "localhost:*)` + mDNSResponder unix-socket；`Ports(p)` ⇒ 每个 `(remote ip "*:p")` + mDNSResponder；`All` ⇒ `(allow network*)`。`Ports` 之外的域名需求 ⇒ `bail!("domain/IP allowlist is not expressible in Seatbelt")`
10. `FullAccess` + `NetAccess::Deny` ⇒ 追加 `(deny network*)`（靠后写赢兜住 `allow default`）
11. **纪律**：本文件不得 `use` 任何 macOS-only 符号；`norm()` 的 `canonicalize` 是 std API，可无条件编译

---

### Task 9: SBPL 生成器单测（B1-B8）

**类型**: `test`（配对 Task 8）
**依赖**: Task 8
**涉及文件**: `src/macos/sbpl.rs`（追加内联 `#[cfg(test)] mod tests`）

**改动**:
1. B1：**段序断言** `assert_section_order(&plan.profile)`——断言 `(deny default)` 位置 < floor 起点（`(allow file-read-metadata)`）< `(param "WS")` < `(param "D0")` < `(allow network` 的相对位置；3 预设 × 4 网络 = 12 例。**只比对「规则集合相等」不足以防顺序回归**
2. B2：路径含 `"` / `)` / `;` / `\n` ⇒ `build()` 返回 `Err`
3. B3：任何预设生成结果**不含 `(prefix`**
4. B4：输出含 `(param "WS")`，且不含内联绝对路径
5. B5：空 `write` ⇒ 不产生 `(subpath "")`
6. B6：`.git` carve-out 开/关的规则差异（`require-all` + `require-not` 出现/不出现）
7. B7：`tmp_writable=false` ⇒ 无 `TMP` 写规则
8. B8：`no_credential_deny=true` ⇒ 无 `D0..Dn` 段
9. 全部断言只看字符串位置与子串，**不比对全量文本**（全量快照因 `canonicalize` 平台差异，是 macOS-only 的 C2，本轮不做），故可在 Linux CI 全跑

---

### Task 10: 实现侧 — MacSandbox / MacChild / canary / fd 清扫 / classify_output

**类型**: `impl`
**依赖**: Task 6、Task 8
**涉及文件**: `src/macos/imp.rs`（新增）、`src/macos/mod.rs`（`#[cfg(target_os = "macos")] mod imp;` 及其 `pub use`）

**改动**:
1. 新建 `src/macos/imp.rs`，文件首行 `#![cfg(target_os = "macos")]` 或由 `mod.rs` 侧 `#[cfg(target_os = "macos")] mod imp;` 门控（二者取一，全模块门控）
2. `pub(crate) struct MacSandbox { plan: Plan, leaky_fd_base: Vec<i32> }`：**构造期**（`create_sandbox_impl`）跑 `validate()` → `build()` → canary 预检，配置错误与策略失效均此时暴露
3. `impl SandboxImpl for MacSandbox`：`spawn()` = 探测 `/usr/bin/sandbox-exec` 存在性（缺失即 `bail!`，**绝不降级为无沙箱**）→ 拼 `Command::new("/usr/bin/sandbox-exec")` + 每个 param 一条 `-D k=v` + `-p <profile>` + `--` + program/args + `current_dir` + `env_clear().envs()` + `pre_exec`（`setpgid` + `dup2` + fd 清扫，零堆操作）；`execute()` 用 trait 默认实现（复用 `src/child.rs:33 run_to_output`）
4. `fn collect_leaky_fds(keep: &[i32]) -> Vec<i32>`：**fork 前**枚举 `/dev/fd`，跳过 `n <= 2`、`keep` 内、`fcntl(F_GETFD) == -1` 或 `FD_CLOEXEC` 已置位者，`sort_unstable` 后返回。**不要**用 `close(3.._SC_OPEN_MAX)`（实测 14.5ms）或 `fcntl` 探测到 `getdtablesize()`（11.5ms）——macOS 无 `close_range`
5. `pre_exec` 闭包 `move` 捕获预分配的 `Vec<i32>`，循环内**零分配**（ADR 0003）：`for &f in &leaky_fds { libc::close(f); }`
6. canary 预检（三优先级降级）：① 写探针——在策略不允许写的位置写一个临时文件，成功即 `bail!`；② `tmp_writable=false` 时走读探针；③ 两者都不可用 ⇒ `eprintln!` 显式警告但执行（不得静默）。临时文件在探针结束后立即清理，临时文件路径不得落在工程目录
7. `fn classify_output(&self, output: &CommandOutput) -> ExitReason`：按设计 §10.2 判定表——`65` + stderr 含 `sandbox-exec:` ⇒ `InternalError`；`65` 无判据 ⇒ `Program(65)`；`134` ⇒ `Denied{Seatbelt, ".. 可能 .."}`；stderr 含 `Operation not permitted` ⇒ `Denied{Seatbelt,..}`；`0` ⇒ `Ok`；其它 ⇒ `Program(code)`
8. `pub(crate) struct MacChild` + `impl SandboxChildImpl`（`try_wait`/`wait`/`wait_timeout`/`kill`/`id`/`take_std*`/`blocked`/`timed_out`）。`sandbox-exec` 是**原地 exec、pid 不变**，故 business-pid 天然为实际工作进程，无 pid 映射表；`kill(-pgid)` 杀整个进程组
9. `spawn(StdioConfig::Inherit)` 拿不到 stderr ⇒ 退化为仅退出码判据（65 一律算 `Program`），在 `execute` 文档写明这是已知能力降级
10. `StdioConfig` 文档补充：「**只有显式声明的 fd 会被传递**，其余非 CLOEXEC fd 在 `pre_exec` 被清扫」

---

### Task 11: classify_output 单测（G1-G7）

**类型**: `test`（配对 Task 10）
**依赖**: Task 10
**涉及文件**: `src/macos/imp.rs`（追加内联 `#[cfg(test)] mod tests`）

**改动**:
1. 只喂**构造的** `CommandOutput`，不 spawn 进程——故本组测试理论上全平台可跑；因 `imp.rs` 是 macOS 门控模块，实际在 macOS 上跑（Linux 侧由 Task 12 的 G7 覆盖默认委托）
2. G1：stderr 含 `sandbox-exec: ... Operation not permitted` ⇒ `Denied`；G2：rc=65 + stderr 含 `sandbox-exec:` ⇒ `InternalError`
3. G3：rc=65 **无** stderr 判据 ⇒ `Program(65)`；G4：rc=134 ⇒ `Denied` 且 message 标「可能」
4. G5：**拒绝但 rc=0**（`2>/dev/null; exit 0` 形态）⇒ 仍 `Denied`——此例解释 `classify_output` 为何存在
5. G6：`timed_out=true` 且 stderr 含拒绝判据 ⇒ `TimedOut` 优先（在 `Sandbox::execute` 层验证，Task 12 承载）
6. 断言 `Denied.mechanism == DenyMechanism::Seatbelt`

---

### Task 12: src/lib.rs 交叉点集成

**类型**: `impl`
**依赖**: Task 6、Task 10
**涉及文件**: `src/lib.rs`

**改动**:
1. 交叉点 2：`src/lib.rs:122` `DenyMechanism` 加 `Seatbelt` 变体（带文档注释「由 macOS Seatbelt（SBPL + sandbox-exec）拒绝」）
2. 交叉点 3：`src/lib.rs:169` `create_sandbox_impl` 加 `#[cfg(target_os = "macos")]` 分支 ⇒ 构造 `macos::imp::MacSandbox`（内部跑 `validate()` + `build()` + canary）；**Linux 分支一字不改**
3. 交叉点 4：`src/lib.rs:529` `SandboxImpl` trait 加带默认实现的 `fn classify_output(&self, output: &CommandOutput) -> ExitReason { self.classify_exit(output.exit_code, output.blocked_syscall) }`（约 4 行）；**不扩 `classify_exit` 签名，Linux 实现零改动**
4. 交叉点 5：`src/lib.rs:596` 改为 `let mut reason = self.inner.classify_output(&output);`；`:597` 的 `if output.timed_out` 覆盖**保持在其后**（超时优先于归因）
5. `src/lib.rs:607` 的 `Sandbox::classify_exit` 保持不变（保留给 Linux 既有调用点）
6. **Linux 分支 diff 必须为空**：除上述 1/3/4 行，`src/lib.rs` 其余部分一行不改

---

### Task 13: trait 默认委托与 timed_out 优先级测试（G6 / G7）

**类型**: `test`（配对 Task 12）
**依赖**: Task 12
**涉及文件**: `src/lib.rs`（追加内联 `#[cfg(test)] mod tests`）

**改动**:
1. G7：构造一个仅实现 `classify_exit` 的桩 `SandboxImpl`，断言 `classify_output` 默认实现**委托**给它，行为与直接调 `classify_exit` 一致（证明 Linux 侧零改动）
2. G6：桩实现 `classify_output` 恒返回 `Denied`，构造 `timed_out=true` 的 `CommandOutput` 走 `Sandbox::execute` 路径，断言最终为超时 `InternalError`（超时优先于拒绝）
3. 断言 `DenyMechanism::Seatbelt` 变体存在且可构造/比较（防以后被误删）
4. 本组测试全平台可跑（不 spawn 真进程）

---

### Task 14: src/config.rs — SandboxConfig 加 macos 字段

**类型**: `impl`
**依赖**: Task 6
**涉及文件**: `src/config.rs`

**改动**:
1. `src/config.rs:24` `SandboxConfig` 追加 `pub macos: MacOsConfig`（放在 `process_group` 之后，附文档注释「macOS Seatbelt 策略；Linux 上恒为 `Default::default()`，不参与任何逻辑」）
2. `src/config.rs:45` `impl Default` 补 `macos: MacOsConfig::default()`
3. **建议同时加 `#[non_exhaustive]`**（design §4.1 / review P0-2）：趁下游使用者少一次性付清 breaking change 成本；若采纳，本任务一并加，并在 CHANGELOG 标注
4. 既有 10 个字段、所有既有 `with_*` 方法**零改动**

---

### Task 15: src/cli.rs — 13 个 --mac-* flag + 构造

**类型**: `impl`
**依赖**: Task 14
**涉及文件**: `src/cli.rs`

**改动**:
1. `src/cli.rs:144` `Cli::Run` 新增 flags（纯新增，既有字段零改动）：`--mac-preset <PRESET>`（`read-only|workspace-write|full-access`）/ `--mac-write <PATH>`（可重复）/ `--mac-deny-write <PATH>`（可重复）/ `--mac-workspace <DIR>`（默认 cwd）/ `--mac-no-tmp-writable` / `--mac-read-all` / `--mac-read <PATH>`（可重复）/ `--mac-deny-read <PATH>`（可重复）/ `--mac-no-credential-deny` / `--mac-no-git-write` / `--mac-net <SPEC>`（`deny|loopback|all|443,80`）/ `--mac-net-inbound`
2. 每个 flag 的 doc 注释标注 `[macOS only]`；`--mac-read` 说明「出现即切到 `Only` 模式，自动附带系统地板」
3. **不加 `#[cfg]` 门控**：若 cfg 掉，clap 报 `unexpected argument '--mac-read'`，用户拿不到「请改用 `--landlock`」建议，设计 §4.6 双向硬错误与 H1/H2/H3 全失效。平台适用性由 `MacOsConfig::validate()` 在**运行期**判断
4. `src/cli.rs:596` 的 `Ok(SandboxConfig { .. })` 字面量构造补 `macos: <由 flags 解析出的 MacOsConfig>`
5. 解析函数：`--mac-net 443,80` 解析为 `NetAccess::Ports(vec![443,80])`；`--mac-read` 出现 ⇒ `with_mac_read(p)`（内部置 `Some(Only([...]))`）；CLI 层**只映射到语义化快捷方法**
6. 13 个 flag 每个都有对应 `with_*`（Task 6 已全部落地），逐条核对 AGENTS.md 的「CLI + Crate API 对应」约定

---

### Task 16: tests/macos_config_test.rs — CLI 映射 + 双向硬错误（N9 / N10 / H1-H3）

**类型**: `test`（配对 Task 14、Task 15）
**依赖**: Task 12、Task 14、Task 15
**涉及文件**: `tests/macos_config_test.rs`（新增）

**改动**:
1. 新建 `tests/macos_config_test.rs`（**全平台可跑**，不 spawn 进程，与 `tests/config_test.rs` 同级）
2. 13 个 `--mac-*` flag 逐一断言映射到对应 `MacOsConfig` 字段（可用 clap 的 try_parse_from 或直接构造 `MacOsConfig` 对比）
3. 每个 flag 断言存在同名 `with_*` 语义化方法
4. H1：macOS 上 `--landlock` ⇒ 硬错误（`#[cfg(target_os="macos")]` 门控该条）
5. H2：Linux 上 `--mac-*` ⇒ 硬错误（`#[cfg(target_os="linux")]` 门控该条）；H3：错误消息含对应 `--mac-*` 建议文案
6. N10 扩展：macOS 上 `--seccomp-deny-nr` / `--unshare-all` / `--bind` / `--cap-add` 各自 `bail!`，且消息指名冲突字段

---

### Task 17: src/lib.rs — check_capabilities macOS 分支

**类型**: `impl`
**依赖**: Task 6、Task 10
**涉及文件**: `src/lib.rs`

**改动**:
1. `src/lib.rs:189` `check_capabilities` 加 `#[cfg(target_os = "macos")]` 分支，输出五段（design §12.1）：能力矩阵（`Seatbelt (sandbox-exec)` / macOS 版本 / mDNSResponder socket / `sandbox_init` deprecated fail-open 标注）、`Not supported on macOS` 清单、`Seatbelt hard limits`（**setuid BLOCKED** 单列 + SIP 路径）、`Presets` 三行、`Read isolation`（明示当前是 `MacReadMode::All` 还是 `Only`）
2. 探测项必须是**运行时检测**，不硬编码：`Path::new("/usr/bin/sandbox-exec").exists()`、`Command::new("/usr/bin/sw_vers").arg("-productVersion")`、`Path::new("/private/var/run/mDNSResponder").exists()`、尝试执行 `/usr/bin/atq` 判断 setuid 是否 BLOCKED
3. 复用现有 `format!` 固定宽度表格风格，与 Linux 输出视觉一致
4. **Linux 分支一字不改**
5. 补 `src/lib.rs:185` 的 doc 注释：「macOS: Seatbelt 能力矩阵 + 硬限制」

---

### Task 18: check macOS 输出测试（H4）

**类型**: `test`（配对 Task 17）
**依赖**: Task 17
**涉及文件**: `tests/macos_test.rs`（新增，`#![cfg(target_os = "macos")]`）

**改动**:
1. 新建 `tests/macos_test.rs`，首行 `#![cfg(target_os = "macos")]`
2. H4：`seabox check`（或直接调 `check_capabilities()`）输出含 `Seatbelt (sandbox-exec)` 行、`setuid`/`BLOCKED` 行、`MacReadMode::All` 与 `Only` 双模式说明、三预设说明
3. 断言输出在 `sandbox-exec` 缺失时显示 missing（可用临时 PATH 或直接断言探测函数返回值的形态）
4. 能力缺失时 auto-skip（打印 `skipping`，非 fail，与 Linux 测试既有约定一致）

---

### Task 19: tests/macos_test.rs — 端到端 + 网络 + 安全闸门

**类型**: `test`（配对 Task 10 的施加侧）
**依赖**: Task 10、Task 12、Task 15
**涉及文件**: `tests/macos_test.rs`（与 Task 18 同文件，本任务扩写）

**改动**:
1. D1：ReadOnly——读通过 / TMPDIR 写通过 / workspace 写 `rc≠0`
2. D2：WorkspaceWrite——workspace 写通过 / `$HOME/Documents` 拒绝；D3：FullAccess——任意写 `rc=0`
3. D4/D5：凭据**读**拒绝（`~/.ssh/id_rsa`）与**写**拒绝（`~/.ssh/authorized_keys`）成对，缺写侧后门可绕过
4. E1：网络正交矩阵（3 预设 × {Deny, Loopback, Ports(443), All}）；E2：Loopback `localhost:PORT` 通 / 外网 `000`；E3：`Ports(443)` https 200 / `http:80` `000`（后写赢的直接证据）
5. F1：**fd 逃逸回归**——父开 host fd，子 `echo >&3` ⇒ `Bad file descriptor` 且宿主文件内容不变（写 `/tmp`，不写工程目录）；F2：CLOEXEC fd 不被误关；F3：fd 清扫耗时 < 1 ms（性能守卫，防退回 `close()` 循环）
6. F4：canary 正常策略 ⇒ 通过；F5：canary 坏策略（人为注入 `allow default`）⇒ 报错且命令不执行
7. H5：`spawn()` 的 business-pid == 实际工作进程，`try_wait`/`wait` 幂等；H6：超时杀整个进程组（含 `sandbox-exec` 与子进程）
8. 所有测试**不得写工程目录**、不需 root、不依赖真实外网（E 组用 localhost server 或能力缺失时 skip）

---

### Task 20: 交叉点审计（N13）

**类型**: `audit`（必测，覆盖全部分支的纪律约束）
**依赖**: Task 1-19 全部 `impl` 任务完成后
**涉及文件**: 只读 `src/linux/**`、`src/macos/**`、`src/lib.rs`、`src/config.rs`、`src/cli.rs`（不修改）

**改动**:
1. 跑两条命令，**都必须返回空**：
   ```bash
   grep -rn 'macos' src/linux/ && echo VIOLATION
   grep -rn 'crate::linux' src/macos/ && echo VIOLATION
   ```
2. 跑 `cargo build --lib`（Linux 与 macOS 各一次）确认双向无耦合导致的编译失败
3. 逐行核对 8 个允许交叉点是否**只**有这 8 处（`pub mod macos;` / `create_sandbox_impl` macOS 分支 / `check_capabilities` macOS 分支 / `DenyMechanism::Seatbelt` / `classify_output` 默认实现 / `SandboxConfig.macos` 字段 + `Default` / `Cli::Run` 的 `--mac-*` 字段 / `src/cli.rs:596` 字面量补 `macos:`），多出一处即违规
4. 跑 `git diff src/linux/` 必须为空
5. 确认 `src/macos/config.rs` 与 `src/macos/sbpl.rs` 无 macOS-only 符号引用（全平台编译即证据）

---

### Task 21: 文档更新

**类型**: `docs`
**依赖**: Task 20
**涉及文件**: `docs/macos-sandbox.md`、`README.md`

**改动**:
1. `docs/macos-sandbox.md`：剔除「尚未实现」；补两处已被实测推翻/补充的说明——「网络支持端口、协议、unix-socket，但语法层拒绝域名与具体 IP」、「白名单过窄 → 目标程序 abort(134) 而非报权限不足」
2. `README.md`：平台支持表（Linux / macOS 各自的机制与限制）+ macOS 快速上手（三预设示例、`--mac-read` 的 `Only` 模式说明、setuid 工具不可用的告警）
3. 若 Task 14 采纳 `#[non_exhaustive]`，README/CHANGELOG 写明 breaking change 与「改用 `..Default::default()`」的迁移方式

---

### Task 22: Linux 221 基线确认（N12 — MANUAL_ACK_REQUIRED）

**类型**: `test`（MANUAL_ACK_REQUIRED）
**依赖**: Task 20
**涉及文件**: 无（仅执行验证）

**改动**:
1. 在**具备 Linux 运行时**的机器上跑 `cargo test`，断言 221 通过 / 0 失败
2. 本机（macOS，无 `docker`/`podman`/`limactl`）**无法**执行此任务，故标 `MANUAL_ACK_REQUIRED`：不得因「本机跑不了」而视为通过
3. 本机可做的替代性保障：`git diff src/linux/` 为空（Task 20 已覆盖）、`src/lib.rs:169` / `:189` 的 Linux 分支逐字不变（review 逐行核对）
4. 交付时必须显式记录此项状态

---

## 执行顺序

### 波次划分

```
波次 1（无依赖，可并行）
├── Task 1   Cargo.toml + syscall_probe 门控
└── Task 6   src/macos/config.rs（纯逻辑，无平台 API）

波次 2（依赖 Task 1）
├── Task 2   tests 门控批次 A
├── Task 3   tests 门控批次 B
└── Task 4   tests 门控批次 C

波次 3（依赖 Task 1-4）
└── Task 5   编译门禁验证 N1/N2

波次 4（依赖 Task 6）
├── Task 7   config 层单测 A1-A10 / N3
├── Task 8   src/macos/sbpl.rs 生成器
└── Task 14  src/config.rs 加 macos 字段

波次 5（依赖 Task 8 / Task 14）
├── Task 9   sbpl 单测 B1-B8
├── Task 15  src/cli.rs --mac-* flags
└── Task 10  实现侧 MacSandbox / canary / fd 清扫   ← 依赖 Task 6+8

波次 6（依赖 Task 10 / Task 15）
├── Task 11  classify_output 单测 G1-G7
├── Task 12  src/lib.rs 交叉点集成
└── Task 17  check_capabilities macOS 分支

波次 7（依赖 Task 12 / Task 17）
├── Task 13  trait 默认委托 + timed_out 优先级测试
├── Task 16  tests/macos_config_test.rs（N9/N10/H1-H3）
└── Task 18  check 输出测试 H4

波次 8（依赖 Task 10/12/15，可与波次 7 并行）
└── Task 19  tests/macos_test.rs 端到端 D/E/F/H5/H6

波次 9（依赖全部 impl）
├── Task 20  交叉点审计 N13
└── Task 22  Linux 221 基线 N12（MANUAL_ACK_REQUIRED）

波次 10
└── Task 21  文档更新
```

### 依赖图（关键路径）

```
Task 1 ──┬── Task 2/3/4 ── Task 5
         └┐
Task 6 ──┼── Task 14 ── Task 15 ──┬── Task 16
         ├── Task 8 ── Task 10 ───┼── Task 11
         │              │         ├── Task 19
         │              └── Task 12 ── Task 13
         └── Task 7            └── Task 17 ── Task 18
                                              │
        Task 1-19 全部 ── Task 20 ──┬── Task 21
                                    └── Task 22
```

**关键路径**：`Task 6 → Task 8 → Task 10 → Task 12 → Task 19 → Task 20 → Task 22`。
**风险最高的顺序逻辑前置**：Task 8/9（段序断言）在 Linux CI 就能跑，是顺序敏感策略的唯一可靠防线；不应拖到 macOS 端到端之后。

### 串行化建议（若单线程执行）

1. Task 1 → 5（先让 macOS 能编译，后续所有任务的验证都依赖它）
2. Task 6 → 7（配置层 + 单测，纯逻辑，最快形成可跑的绿灯）
3. Task 8 → 9（生成器 + 段序断言；此处必须严格 TDD，因为它是安全边界）
4. Task 14 → 15（config 字段 → CLI flags）
5. Task 10 → 11 → 12 → 13（实现侧 → 归因 → 集成 → 委托测试）
6. Task 17 → 18（check 输出）
7. Task 16 → 19（两批集成测试）
8. Task 20 → 21 → 22（审计 + 文档 + 基线确认）
