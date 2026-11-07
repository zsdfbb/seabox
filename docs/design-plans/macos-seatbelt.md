# macOS Seatbelt 后端 — 设计计划

> 设计稿：`docs/arch/macos-seatbelt/design.md`（权威，1391 行 / 14 章 + 附录 A）
> 上下文：`docs/arch/macos-seatbelt/context.md`（实测语义基线）
> 质量报告：`docs/arch/macos-seatbelt/review.md`（4 P0 + 6 P1，已全部落实）
> 执行计划：`docs/exec-plans/macos-seatbelt.md`
> 目标平台：Linux（保持零回归） + macOS 27.0.1 / Darwin 27.0.0 / arm64
> 状态：**待实现**

---

## 1. 背景与目标

### 1.1 背景

seabox 当前是一个**只能编译在 Linux 上**的沙箱：`landlock = "0.4"` 是非 optional 依赖，`src/lib.rs:169 create_sandbox_impl()` 的 `#[cfg(not(target_os = "linux"))]` 分支直接 `bail!("seabox requires Linux")`，`src/lib.rs:189 check_capabilities()` 在非 Linux 上输出 8 行 "not available (non-Linux)"，12 个 `tests/*.rs` 全部 `use seabox::linux::…`。

Phase 3 要兑现的能力是：**让 macOS 也成为一等目标平台**，用 Apple Seatbelt（SBPL profile + `/usr/bin/sandbox-exec`）提供**文件系统**与**网络**两类策略，并保持 Linux 行为与 221 测试基线一字不变。

设计原则沿用项目的「语义诚实」：**能做的事做好，做不到的明确报错，不制造安全假象**。因此 macOS 上所有 Linux 专属 flag（`--seccomp-*` / `--unshare-*` / `--bind` / `--cap-*` / `--landlock`）一律**硬错误**，不静默降级。

### 1.2 目标

| # | 目标 | 验收 |
|---|---|---|
| G1 | macOS 上 `cargo build --lib --bins --tests` 通过 | `cargo build` 三 target 全绿 |
| G2 | `--mac-preset read-only\|workspace-write\|full-access` 三预设可用 | 端到端 D1-D3 |
| G3 | SBPL 生成器在 **Linux CI** 可单测（段序断言） | B1-B8 全平台跑 |
| G4 | 策略语义失效 **fail-closed**（canary 预检） | F4/F5 |
| G5 | 预开 fd 不能绕过文件策略（fd 清扫） | F1/F2/F3 |
| G6 | 拒绝可归因为 `DenyMechanism::Seatbelt` | G1-G7 |
| G7 | Linux 行为零变化 | N12（本机不可自动化，见 §5.3） |
| G8 | **mac 与 linux 代码彻底拆分，互不干扰** | N13（双向 grep 为空） |

### 1.3 与 Linux 后端的能力对照（不做的事见 §6）

| 维度 | Linux（现状） | macOS（本轮） |
|---|---|---|
| 文件系统 | Landlock，16 位 `AccessFs` 精确 ACL | SBPL `file-read*` / `file-write*`，粗粒度 + `subpath` |
| 读隔离 | 白名单（Landlock 天然只放行） | `MacReadMode::All`（默认，靠凭据黑名单补偿）/ `Only`（真隔离） |
| syscall 过滤 | seccomp BPF + USER_NOTIF 精确诊断 | **无等价物 → 硬错误** |
| namespace | 7 种 unshare | **无等价物 → 硬错误** |
| 网络 | netns + loopback | SBPL `network-outbound/inbound` + 端口/unix-socket（**拒绝域名与 IP**） |
| 超时 / 进程组 | `--timeout` / `process_group` | **原样生效**（平台无关路径） |
| 拒绝归因 | 结构化 `blocked_syscall: (nr, arch)` | stderr 文本 + 退出码，精度分级 Probable/Certain |

---

## 2. 设计方案摘要

### 2.1 配置面分离（决策 D1）

**不把 Seatbelt 语义挤进 Linux 形状的配置。** `--landlock` / `--unshare-net` / `NetworkConfig` 保持 Linux 语义一字不改；macOS 侧独立成 `MacOsConfig` + `--mac-*` flag + `SandboxConfig::with_mac_*`。

```
SandboxConfig
├── macos: MacOsConfig        ← 新增字段（Linux 上恒为 default，不参与逻辑）
└── (既有 10 个 Linux 字段全部不动)
```

双向硬错误在 `create_sandbox_impl` 内校验（design §4.6）：

| 平台 | 条件 | 结果 |
|---|---|---|
| macOS | `landlock` / `seccomp_*` / `capabilities` / `mount.specs` / `namespaces.{user,ipc,mnt,pid,uts,cgroup}` 任一非默认 | `bail!("<field> is not supported on macOS")` |
| Linux | `macos.preset.is_some()` 或任一 `--mac-*` 字段被设置 | `bail!("--mac-* only applies on macOS")` |
| 两平台 | `timeout_*` / `process_group` / `StdioConfig` | 原生生效，不校验 |

**CLI flags 不加 `cfg` 门控（重要取舍）**：若在 Linux 上把 `--mac-*` 字段 `#[cfg]` 掉，clap 会报 `unexpected argument '--mac-read'`，用户拿不到「请改用 `--landlock`」的建议文案，设计稿 §4.6 的双向硬错误与测试 H1/H2/H3 全部失效。因此：

- `src/cli.rs` 的 `Cli::Run` **全平台保留全部 `--mac-*` 字段**（纯新增，不改既有字段）；
- 平台适用性由 `validate()` 在**运行期**判断，而非 clap 在**解析期**拒绝；
- 代价：Linux 上 `seabox run --help` 会列出 `--mac-*`，需在 help 文案里标注 `[macOS only]`。

### 2.2 `Option<bool>` 语义（预设 vs 覆盖）

`bool` 区分不了「未设置」与「显式 false」，导致「用 ReadOnly 预设但显式关掉 TMP 可写」**无法表达**——而这正是预设机制的核心用法。因此三个开关用 `Option<bool>`、读模式用 `Option<MacReadMode>`：

```
None        → 跟随预设/基线
Some(true)  → 显式开（覆盖预设）
Some(false) → 显式关（覆盖预设）
```

为降低调用侧啰嗦度，额外提供语义化快捷方法（CLI 层只用这些）：`with_mac_no_tmp_writable()` / `with_mac_no_git_write()` / `with_mac_no_credential_deny()`；底层 `with_mac_tmp_writable(Option<bool>)` 等完整签名给需要表达 `Some(true)` 的库调用者。

### 2.3 `resolve()` 合并算法

生成器入口**必须**先跑这一步：`Option` 字段在进 SBPL 生成器之前全部定型，生成器只接受无 `Option` 的 `ResolvedPolicy`，避免生成器内满屏 `unwrap_or` 且 `bool` / `Option<bool>` 误用不报错。

```rust
struct ResolvedPolicy {
    read: MacReadMode,
    write: Vec<PathBuf>,
    deny_write: Vec<PathBuf>,
    deny_read: Vec<PathBuf>,
    tmp_writable: bool,
    allow_git_write: bool,
    credential_deny: bool,
    net: MacNetConfig,
}

impl MacOsConfig {
    fn resolve(&self) -> ResolvedPolicy {
        let base = match self.preset {
            Some(p) => p.defaults(),          // 三预设各自默认
            None    => MacPreset::baseline(), // 安全基线
        };
        // Option<T>：Some 覆盖，None 跟随基线
        // Vec<T>：预设值在前 + 用户追加（去重保序）
    }
}
```

两条容易错的规则：

| 字段类型 | 语义 | 理由 |
|---|---|---|
| `Option<T>` | 预设默认，用户**覆盖** | 单值语义，后者胜 |
| `Vec<T>` / `deny_*` / `write` | 预设默认 + 用户**追加** | 用户加限制是理性行为；静默丢弃内置凭据清单是安全回退 |

`resolve()` 必须是**幂等纯函数**、不碰文件系统（`write` 里的 workspace 展开除外），以便 Linux CI 全覆盖（A1-A10）。

**`is_configured()` 独立于 `resolve()`**：展开后的 `ResolvedPolicy` 与安全基线长得一样，无法区分「用户配了」和「没配」。因此需要逐字段显式检查 `preset` / `write` / `deny_write` / `tmp_writable` / `read` / `deny_read` / `no_credential_deny` / `allow_git_write` / `net`，全为「未设置」时 **`false` → 不进 `sandbox-exec`**。特别注意 A2：`--mac-net deny` 虽然与默认 `NetAccess::Deny` 相等，但 `is_configured()` 必须为 `true`（用 `Option<MacNetConfig>` 的 `is_some()` 判断，不比对值）。

### 2.4 SBPL 后写赢（生成器是安全边界）

**实测推翻了「deny 恒优先于 allow」的假设**：SBPL 是**后写赢**，与 specificity 无关。一次「调换两行」就能静默放开策略。因此固定段落顺序写死在 `sbpl::build()` 内，不可配置，用户无法影响：

```
1  (version 1)
2  (deny default)                    | FullAccess: (allow default)
3  floor（进程 / ipc / sysctl / 读 / 隐式写点）
4  预设写白名单（ReadOnly 无；WS: require-all + carve-out；Full 无）
5  TMP 可写
6  deny_read（凭据 + 用户追加）        ← 最后一条 file 规则
7  network（最末）
```

`deny_read` 必须在写白名单**之后**，否则被后续 allow 覆盖。配套三道防线：

1. **固定段序**（`build()` 内写死）；
2. **段序断言测试**（B1，全平台）：断言 `deny default` 行号 < floor < write 白名单 < `deny_read` < network 的相对位置——仅比对「规则集合相等」不足以防顺序回归；
3. **禁止用户控制顺序**：`--mac-write` / `--mac-deny-read` 是列表，但按固定段落聚合，用户给的先后不影响输出位置。

其他生成器硬约束：

- **禁用 `prefix` 匹配符**：`prefix` 是字符串前缀，实测 `prefix "/proj"` 允许写 `/proj-backup`（跨目录越权）。只允许 `subpath` / `literal`（B3）。
- **路径走 `-D` 参数，绝不拼进 SBPL 字符串**：`WS` / `TMP` / `W0..Wn` / `D0..Dn` 全部 `param` 化。路径含 `"` / `)` / `;` / 换行 → `bail!`（B2 注入拒绝）。
- **`norm()` 必须 `canonicalize`**：`/var` 与 `/private/var`、`/tmp` 与 `/private/tmp`、`/etc` 与 `/private/etc` 是不同字符串，`subpath` 按字面比较不解析 symlink，不规范化就**永不匹配且无提示**（实测 `cargo build` 报 `os error 1`）。`canonicalize` 失败（路径不存在）即硬错误——`-D` 传不存在路径 `sandbox-exec` **不报错**，规则静默失效。
- `subpath` 是**整棵子树**语义（含 `mkdir -p` 多级与 `unlink`，D10）。

### 2.5 施加机制：`sandbox-exec`

**决策：外部进程 `/usr/bin/sandbox-exec` 作为唯一施加机制，不用进程内 `sandbox_init()`。**

决定性理由是**失败语义**。4 种坏 profile（未知操作名 / 括号不闭合 / `(version 99)` / 缺 `(version)`）实测对比：

| 场景 | `sandbox_init()` | `sandbox-exec` |
|---|---|---|
| 4/4 坏 profile | `rc=-1`，**进程继续运行且无沙箱** | `rc=65`，**命令不执行** |

`sandbox_init` 是**失败开放**——调用方若按惯例「记警告后继续」，Agent 就得到一个看起来受限、实际完全自由的执行环境，这是沙箱工具最不可接受的失败模式。`sandbox-exec` 的 fail-closed 直接排除这一整类风险。

其他理由：**原地 exec，pid 不变**（实测 fork 后 pid 43419 == 最终 `/bin/sh` pid），故 ADR 006 的 business-pid 语义天然成立，`SandboxChildImpl`（kill / `kill(-pgid)` / wait）与 `src/child.rs:33 run_to_output()` 原样复用，无 pid 映射表；每次 +5~6ms 不可感知；profile 通过 `-p <text>` 传参不写临时文件（无清理路径、无 TOCTOU）。

```rust
Command::new("/usr/bin/sandbox-exec")
    .args(["-D", &format!("WS={}", ws)])   // 每个 param 一条
    .arg("-p").arg(&plan.profile)
    .arg("--").arg(&spec.program).args(&spec.args)
    .current_dir(cwd).env_clear().envs(env)
    .pre_exec(|| /* setpgid + dup2 + fd 清扫，零堆操作 */)
```

**`spawn` 时 `/usr/bin/sandbox-exec` 不存在 ⇒ `bail!`，绝不降级为无沙箱**（F8；design §13.2 风险 3b）。

### 2.6 两道安全闸门

§2.5 的 fail-closed 保证**只覆盖语法**。实测出两类「profile 合法、策略却未生效」的情形，`sandbox-exec` 都不报警：

**闸门一：canary 预检（语义失效检测）**。`MacSandbox` 在**构造期**（`create_sandbox_impl` 时）跑一次「应当被拒」的探针：写一个不允许写的位置，若探针**成功**则说明策略未生效，立即 `bail!` 且命令不执行（F5）。探针三优先级降级：写探针 → `tmp_writable=false` 时走读探针 → 两者都不可用则**显式警告但执行**（F6/F7，不得静默）。坏 profile 因此有两道闸门：语法错 rc=65 fail-closed，语义错 canary 捕获。

**闸门二：fd 卫生**。预开 fd 会**绕过**文件策略（实测 `exec 9>/host` → 沙箱内 `echo >&9` 写入成功，`host=[PWNED]`）。

- macOS **没有** `close_range`（Linux 5.9+ syscall）。三方案实测：`close(3.._SC_OPEN_MAX)` = **14.5ms**（`_SC_OPEN_MAX`=1048575）、`fcntl` 探测到 `getdtablesize()` = 11.5ms、**`/dev/fd` 枚举 = 0.026ms** → 采纳后者，快 500 倍。
- **只关非 `FD_CLOEXEC` 的 fd**：CLOEXEC 的 fd 在 exec 时被内核自动关；不过滤会误关 fork~exec 之间新开的合法 fd（如 canary 路径上的临时 fd）。Rust 的 `File`/`TcpStream` 默认 CLOEXEC，真正要担心的是**从外部继承**的 fd。
- **ADR 0003 合规**：`collect_leaky_fds(keep)` 在 **fork 前**完成枚举 + 过滤，得到 `Vec<i32>`；`pre_exec` 闭包 `move` 捕获它，循环中**零分配**。实测清扫后 `host=[ORIGINAL]` 且 `sh` 报 `3: Bad file descriptor`，证明 fd 确实在 exec 前被关。
- 目录 fd + `openat` 实测无法绕过，故只需覆盖普通文件 fd。
- 已知不足（需写进 `StdioConfig` 文档）：清扫会关闭用户期望继承的 fd——**这是故意的**，继承未声明 fd 本身就是漏洞。

### 2.7 `classify_output`（拒绝归因）

现有 `SandboxImpl::classify_exit`（`src/lib.rs:546`）只拿得到 `exit_code`，但**拒绝不会可靠传播为退出码**：

```
sh -c 'echo x > denied_path'                     → rc=1
sh -c 'echo x > denied_path 2>/dev/null; exit 0' → rc=0   ← 拒绝被吞掉
```

而 `Sandbox::execute`（`src/lib.rs:592`）在 `:596` 会**再调一次** `classify_exit`，`MacSandbox::execute` 内部算出 `Denied` 会被外层覆盖。

**方案：给 trait 加一个带默认实现的新方法**（Linux 实现零改动，不改任何既有签名）：

```rust
trait SandboxImpl: Send + Sync {
    // ... 既有 spawn / execute / classify_exit 不动 ...

    /// 带完整输出的分类。默认委托 `classify_exit`；
    /// 需要 stderr 判据的平台（macOS）override 它。
    fn classify_output(&self, output: &CommandOutput) -> ExitReason {
        self.classify_exit(output.exit_code, output.blocked_syscall)
    }
}
```

`Sandbox::execute` 的 `src/lib.rs:596` 改一行为 `self.inner.classify_output(&output)`。判定表（design §10.2）：

| 条件 | 结果 |
|---|---|
| `exit_code == 65` **且** stderr 含 `sandbox-exec:` | `InternalError`（SBPL profile 被拒，是我们自己的 bug） |
| `exit_code == 65`（无上述 stderr） | `Program(65)`——`65` 是 `EX_DATAERR`，目标程序自己也可能返回 |
| `exit_code == 134` | `Denied { Seatbelt, "aborted under policy; read whitelist may be too narrow" }`（标「可能」） |
| stderr 含 `Operation not permitted` | `Denied { Seatbelt, .. }` |
| `0` | `Ok` |
| 其它 | `Program(code)` |

两条铁律：**超时优先于归因**（`src/lib.rs:597` 的 `timed_out` 覆盖必须在 `classify_output` 之后，超时命令可能恰好写了 stderr，那不是策略拒绝）；`spawn(StdioConfig::Inherit)` 拿不到 stderr 时退化为仅退出码判据，需在 `execute` 文档写明这是已知能力降级。

---

## 3. 架构：mac / linux 彻底拆分

### 3.1 三层文件布局（硬约束）

设计稿把 `MacOsConfig` / `resolve()` / `sbpl` 全塞进 `src/macos/mod.rs`，而该文件同时含 macOS-only 实现（`MacSandbox` / `spawn` / canary / fd 清扫）。这会让 **Linux 构建也编译实现代码**，是干扰源。改为三层：

| 文件 | cfg 门控 | 内容 | Linux CI 可编译/测试 |
|---|---|---|---|
| `src/macos/config.rs` | **无条件** | `MacOsConfig` / `MacPreset` / `MacReadMode` / `NetAccess` / `MacNetConfig` / `ResolvedPolicy` / `resolve()` / `is_configured()` / `validate()` 双向硬错误检查 | ✅ 纯数据类型 + 纯逻辑 |
| `src/macos/sbpl.rs` | **无条件** | `Plan` / `build()` 生成器 / `norm()` | ✅ 段序断言全平台跑；文本快照 macOS only |
| `src/macos/mod.rs` | `#[cfg(target_os = "macos")]`（整个模块门控） | `MacSandbox` / `MacChild` / canary 预检 / fd 清扫 / `classify_output` / `spawn` | ❌ 仅 macOS |

`src/lib.rs` 的写法：

```rust
pub mod macos;                              // 无条件：内部自己分 cfg
// src/macos/mod.rs 里：
pub mod config;                             // 无条件
pub mod sbpl;                               // 无条件
#[cfg(target_os = "macos")]
mod imp;                                    // 或直接在 mod.rs 内 cfg 门控实现部分
```

**`src/macos/config.rs` 与 `sbpl.rs` 无条件编译 ⇒ 它们的 `use` 不得引用任何 macOS-only 符号**（`/dev/fd`、`sandbox-exec` 路径常量、`libc` 的 Darwin-only item）。若某段逻辑必须碰平台 API，归到 `mod.rs` / `imp` 侧，不留在 config/sbpl。这一约束由 N13 的编译验证兜住。

### 3.2 零交叉引用纪律

- `src/linux/**` 任何文件 **不得**出现 `use crate::macos::` 或任何 mac 类型；
- `src/macos/**` 任何文件 **不得**引用 `crate::linux::`；
- 验收命令（两条都必须返回空）：

```bash
grep -rn 'macos' src/linux/ && echo VIOLATION
grep -rn 'crate::linux' src/macos/ && echo VIOLATION
```

### 3.3 允许的交叉点（穷举，全部一行级）

| # | 文件:行 | 改动 | 规模 |
|---|---|---|---|
| 1 | `src/lib.rs` | 加 `pub mod macos;` | 1 行 |
| 2 | `src/lib.rs:169` `create_sandbox_impl` | 加 `#[cfg(target_os="macos")]` 分支；**Linux 分支一字不改** | ~4 行 |
| 3 | `src/lib.rs:189` `check_capabilities` | 加 `#[cfg(target_os="macos")]` 分支；**Linux 分支一字不改** | ~4 行 + 表格文案 |
| 4 | `src/lib.rs:122` `DenyMechanism` | 加 `Seatbelt` 变体 | 1 行 |
| 5 | `src/lib.rs:529` `SandboxImpl` trait | 加 `classify_output` 默认实现；**Linux 实现零改动** | ~4 行 |
| 6 | `src/config.rs:24` `SandboxConfig` | 加 `pub macos: MacOsConfig` 字段 + `:45` `Default` 里一行 | 2 行 |
| 7 | `src/cli.rs:144` `Cli::Run` | 加一组 `--mac-*` 字段（纯新增，不改既有字段） | 新增一段 |
| 8 | `src/cli.rs:596` | 全字段字面量构造补 `macos: ...` | 1 行（+ 解析逻辑） |

数据流：

```
SandboxConfig
├── macos: MacOsConfig ──────┐
└── (linux 字段不变)          │
                              ▼
                    macos::sbpl::build()   ← 无条件编译，Linux CI 可单测
                              │
                Plan { profile: String, params: Vec<(String, String)> }
                              │
                    MacSandbox::spawn()    ← cfg(target_os="macos")
                              │
              /usr/bin/sandbox-exec -D k=v ... -p <profile> -- <prog> <args>
                              │
                     child::run_to_output()  ← 复用，不改
```

### 3.4 编译门控（已实测，按此实现，勿用其他版本）

**`Cargo.toml`**：`landlock = "0.4"` 从 `[dependencies]` 移入

```toml
[target.'cfg(target_os = "linux")'.dependencies]
landlock = "0.4"
```

**12 个 `tests/*.rs`**：每个文件顶部加 `#![cfg(target_os = "linux")]`（✅ 实测有效）。现有 12 个文件：`capability_test.rs` `concurrent_fork_test.rs` `config_test.rs` `deny_detect_test.rs` `landlock_test.rs` `leak_test.rs` `mount_test.rs` `namespace_test.rs` `network_test.rs` `profile_test.rs` `seccomp_test.rs` `spawn_test.rs`。

**`src/bin/syscall_probe.rs`**：**不能用**文件级 `#![cfg]`——实测报

```
error[E0601]: `main` function not found in crate `syscall_probe`
```

原因：`[[bin]]` target 无条件声明，Cargo 不会因 `cfg` 跳过构建；文件级属性把整个 crate（含 `main`）裁掉，链接期找不到入口。正确写法：保留统一 `fn main() -> std::process::ExitCode`，内部分支：

```rust
fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    { linux_main() }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("syscall_probe is Linux-only");
        std::process::ExitCode::from(77)
    }
}

#[cfg(target_os = "linux")]
fn linux_main() -> std::process::ExitCode { /* 原 main 体 */ }
```

并对 `linux_main()` / `parse_i64` / `dispatch_syscall` / `use std::env` / `use std::process::ExitCode` **逐个**加 `#[cfg(target_os = "linux")]`。选 `77` 而非 `1`，避免与测试中「预期拒绝」的退出码混淆。

**结论（已实测）**：三处改完后 macOS 上 `cargo build --lib --bins --tests` 全通，零警告变更。

---

## 4. 涉及文件清单

### 4.1 新增文件

| 路径 | 说明 |
|---|---|
| `src/macos/mod.rs` | 新增。模块根：`pub mod config; pub mod sbpl;` + `#[cfg(target_os="macos")] mod imp;`。macOS 实现入口（`MacSandbox` / `MacChild` / canary / fd 清扫 / `classify_output` / `spawn`）在此或 `imp.rs` |
| `src/macos/config.rs` | 新增。**无条件编译**：`MacOsConfig` / `MacPreset` / `MacReadMode` / `NetAccess` / `MacNetConfig` / `ResolvedPolicy` / `resolve()` / `is_configured()` / `defaults()` / `baseline()` / `validate()`；纯数据类型 + 纯逻辑，无平台 API |
| `src/macos/sbpl.rs` | 新增。**无条件编译**：`Plan { profile, params }` / `build(&ResolvedPolicy) -> anyhow::Result<Plan>` / `norm(&Path)`；固定 7 段顺序、`subpath`/`literal` only、`-D` 参数化、注入拒绝 |
| `src/macos/imp.rs`（可选，由 Task 5 决定是否拆） | 新增，`#[cfg(target_os="macos")]`。`MacSandbox` / `MacChild` / `SandboxImpl` + `SandboxChildImpl` 实现 / canary 预检 / `collect_leaky_fds` / `classify_output` |
| `tests/macos_config_test.rs` | 新增。**全平台**：13 个 `--mac-*` CLI flag → `MacOsConfig` 映射、`with_*` 一一对应性、双向硬错误 H1/H2/H3 |
| `tests/macos_test.rs` | 新增。`#![cfg(target_os = "macos")]`：端到端 D1-D3、凭据 D4/D5、网络 E1-E3、闸门 F1-F5、平台边界 H4-H6 |

### 4.2 修改文件

| 路径 | 改动说明 |
|---|---|
| `Cargo.toml` | `landlock = "0.4"` 移入 `[target.'cfg(target_os = "linux")'.dependencies]`；`libc` 保持无条件（macOS 的 `fcntl` / `F_GETFD` / `FD_CLOEXEC` / `setpgid` / `dup2` 需要） |
| `src/lib.rs:122` | `DenyMechanism` 加 `Seatbelt` 变体 |
| `src/lib.rs:169` | `create_sandbox_impl` 加 `#[cfg(target_os="macos")]` 分支（构造 `MacSandbox`，内含 `validate()` + `build()` + canary）；Linux 分支一字不改 |
| `src/lib.rs:189` | `check_capabilities` 加 macOS 分支输出（能力矩阵 / 不支持清单 / setuid 硬限制 / 预设说明 / 读模式）；Linux 分支一字不改 |
| `src/lib.rs:529` | `SandboxImpl` trait 加 `classify_output` 默认实现（4 行） |
| `src/lib.rs:596` | `Sandbox::execute` 改调 `classify_output(&output)`（1 行）；`:597` 的 `timed_out` 覆盖保持在**其后** |
| `src/config.rs:24` | `SandboxConfig` 加 `pub macos: MacOsConfig`；建议同时加 `#[non_exhaustive]`（见 §5.1） |
| `src/config.rs:45` | `impl Default` 补 `macos: MacOsConfig::default()` |
| `src/cli.rs:144` | `Cli::Run` 新增 13 个 `--mac-*` 字段（`--mac-preset` / `--mac-write` / `--mac-deny-write` / `--mac-workspace` / `--mac-no-tmp-writable` / `--mac-read-all` / `--mac-read` / `--mac-deny-read` / `--mac-no-credential-deny` / `--mac-no-git-write` / `--mac-net` / `--mac-net-inbound` + help 标注 `[macOS only]`）；既有字段零改动 |
| `src/cli.rs:596` | 字面量构造补 `macos: <由 flags 解析出的 MacOsConfig>` |
| `src/bin/syscall_probe.rs` | 统一 `main` + `linux_main()` 分支，逐项 `#[cfg(target_os="linux")]`（禁止文件级 `#![cfg]`） |
| `tests/*.rs`（12 个） | 每个顶部加 `#![cfg(target_os = "linux")]` |

### 4.3 文档

| 路径 | 改动 |
|---|---|
| `docs/macos-sandbox.md` | 剔除「尚未实现」，补「网络支持端口/unix-socket 但拒绝域名与 IP」、「白名单过窄 → abort 134」两处更正 |
| `README.md` | 平台支持表 + macOS 快速上手（三预设示例） |

---

## 5. 测试策略

### 5.1 分层与文件落位（design §11.1）

| 位置 | 平台 | 内容 | 为何放这里 |
|---|---|---|---|
| `src/macos/sbpl.rs` 内联 `#[cfg(test)]`（结构组 B） | **全平台** | 段序断言 + 注入拒绝 + 参数化 + 禁 `prefix` | 纯函数，无文件系统依赖，Linux CI 每 PR 都跑 |
| `src/macos/config.rs` 内联 `#[cfg(test)]`（A 组） | **全平台** | `resolve()` / `is_configured()` / `defaults()` | 纯逻辑 |
| `src/macos/mod.rs`（或 `imp.rs`）内联（G 组） | **全平台** | `classify_output` | 纯字符串判断，不 spawn 进程 |
| `tests/macos_config_test.rs`（N9） | **全平台** | CLI flag → `MacOsConfig` 映射、`with_*` 对应性、H1-H3 双向硬错误 | 不 spawn 进程，与 `tests/config_test.rs` 同级 |
| `src/macos/sbpl.rs` 内联（C 组快照） | **macOS only** | golden 全量文本 | 依赖 `canonicalize`，`/var`→`/private/var` 在 Linux 上不存在 |
| `tests/macos_test.rs`（D/E/F/H 组） | **macOS** `#![cfg(target_os = "macos")]` | 端到端、网络、安全闸门、平台边界 | 需真 `sandbox-exec` |

**关键拆分（design §11.2）**：`sbpl.rs` 声称「无 cfg 门控、Linux CI 跑 golden」与 `norm()` 必须 `canonicalize` 冲突——`/var` `/etc` `/tmp` 的 symlink 结构在两平台不同。解法：

| 测试 | 依赖 | 平台 | 强度 |
|---|---|---|---|
| **段序断言**：`(deny default)` 位置 < floor < `(param "WS")` < `(param "D0")` < `(allow network` | 纯字符串位置 | ✅ **全平台** | **这才是安全防线**——改段落顺序的 PR 会在 Linux CI 变红 |
| 全量文本快照 | `canonicalize` | macOS only | 捕捉意图外的变化 |

### 5.2 测试合同（N1-N12）

| # | 合同 | 验收命令 / 断言 | 优先级 |
|---|---|---|---|
| N1 | 依赖改 target-specific → `cargo build --lib` macOS 通过 | `cargo build --lib`（macOS）成功；默认特性与 `--no-default-features` 均须通过 | 必测 |
| N2 | 12 测试文件 + `syscall_probe` 门控 → `cargo build --bins --tests` 通过 | `cargo build --bins --tests`（macOS）成功；`cargo build --bin syscall_probe` 在 macOS 产出可运行二进制（运行返回 77） | 必测 |
| N3 | `MacOsConfig` 等 4 类型 → 单测 Default 全为 None/空 | `MacOsConfig::default()` 的 `preset/read/tmp_writable/no_credential_deny/allow_git_write/net` 全 `None`，三个 Vec 全空；`MacReadMode::default() == All`；`NetAccess::default() == Deny`；`MacPreset` 无 Default（`Option` 承载未配置） | 必测 |
| N4 | `resolve()` / `is_configured()` → 单测 A1-A10 | A1 逐字段设置 9 字段全 true；A2 `--mac-net deny` ⇒ `is_configured()==true`；A3 无预设无字段 ⇒ `false`；A4 ReadOnly + `tmp_writable=Some(false)` ⇒ TMP 不可写；A5 预设 + 无字段 == `defaults()`；A6 Vec 追加不冲掉内置凭据清单；A7 `--mac-read` 切 `Only` / `--mac-read-all` 回 `All`；A8 FullAccess + 显式 `deny_read` 仍生效；A9 三种使用方式均不 panic；A10 `resolve()` 幂等 | 必测 |
| N5 | SBPL 生成器 → 单测 B1-B8 | B1 **段序断言** 3 预设 × 4 网络 = 12 例；B2 路径含 `"` `)` `;` `\n` ⇒ `bail!`；B3 生成结果不含 `(prefix`；B4 输出含 `(param "WS")` 且不含内联绝对路径；B5 空 `write` 不产生 `(subpath "")`；B6 `.git` carve-out 开/关规则差异；B7 `tmp_writable=false` ⇒ 无 TMPDIR 写规则；B8 `no_credential_deny=true` ⇒ 无 `D0..Dn` 段 | 必测 |
| N6 | `sandbox-exec` 施加 → 端到端 D1-D3 | D1 ReadOnly：读通过 / TMPDIR 写通过 / workspace 写 rc≠0；D2 WorkspaceWrite：workspace 写通过 / `$HOME/Documents` 拒绝；D3 FullAccess：任意写 rc=0 | 必测 |
| N7 | 两道闸门 → F1 fd 逃逸被堵、F5 坏策略被 canary 捕获 | F1 父开 host fd、子 `echo >&3` ⇒ `Bad file descriptor` 且宿主文件不变；F5 坏策略（`allow default`）⇒ `bail!` 且命令不执行 | 必测 |
| N8 | `classify_output` → G1-G7 | G1 stderr 含 `Operation not permitted` ⇒ `Denied`；G2 rc=65 + stderr 含 `sandbox-exec:` ⇒ `InternalError`；G3 rc=65 无 stderr 判据 ⇒ `Program(65)`；G4 rc=134 ⇒ `Denied`（标「可能」）；G5 拒绝但 rc=0 ⇒ 仍 `Denied`；G6 超时覆盖拒绝 ⇒ `TimedOut` 优先；G7 Linux 走默认委托 ⇒ 与基线一致 | 必测 |
| N9 | 13 个 `--mac-*` + `with_*` → `tests/macos_config_test.rs` | 13 个 flag 逐一映射到对应 `MacOsConfig` 字段；每个 flag 都有同名 `with_*`（AGENTS.md 约定）；H1 macOS 上 `--landlock` ⇒ 硬错误；H2 Linux 上 `--mac-*` ⇒ 硬错误；H3 错误消息含对应 `--mac-*` 建议文案 | 必测 |
| N10 | 双向硬错误 → H1/H2/H3 | 见 N9 后三条；额外覆盖 macOS 上 `--seccomp-deny-nr` / `--unshare-all` / `--bind` / `--cap-add` 各自 `bail!`，且消息指名冲突字段 | 必测 |
| N11 | `check` macOS 输出 → H4 | `seabox check` 输出含 `Seatbelt (sandbox-exec)` 行、setuid BLOCKED 行、`MacReadMode::All \| Only` 双模式说明、三预设说明；探测值为运行时检测（`Path::new("/usr/bin/sandbox-exec").exists()` 等），非硬编码 | 必测 |
| N12 | Linux 221 基线不变 | `cargo test` 在 Linux 上仍为 221 通过、0 失败；`git diff src/linux/` 为空；`src/lib.rs:169` / `:189` 的 Linux 分支 diff 为空 | **MANUAL_ACK_REQUIRED**（本机无 Linux 运行时，`docker`/`podman`/`limactl` 全无，无法自动化执行，须由具备 Linux 环境的执行者确认） |
| N13 | 交叉点纪律：`cargo build --lib` 后双向 grep 为空 | `grep -rn 'macos' src/linux/` 返回空 **且** `grep -rn 'crate::linux' src/macos/` 返回空；`cargo build --lib`（Linux）成功 | 必测 |

> N1-N11、N13 中标注「全平台」者可在 Linux CI 与 macOS 本机分别跑；仅 N6/N7 与 D/E/F 组需要 macOS 上真 `sandbox-exec`。

### 5.3 无法本机自动化的项

N12（Linux 221 基线）在本机**无法验证**：当前只有 macOS 运行时，无 `docker` / `podman` / `limactl`。工程上的替代性保障：

1. `git diff src/linux/` 必须为空（N13 的一部分）；
2. `src/lib.rs:169` 与 `:189` 的 Linux 分支逐字不变（review 时逐行核对）；
3. 所有 Linux 侧改动都是 `cfg` 门控 + 一条依赖声明，无代码路径变更。

即便如此，N12 仍需在具备 Linux 环境的机器上最终确认，标 `MANUAL_ACK_REQUIRED`，不因本机跑不了而视为通过。

### 5.4 优先级与规模（design §11.4）

| 优先级 | 测试 | 理由 |
|---|---|---|
| **P0（必做，22 例）** | A1-A8、B1-B3、D4、D5、F1、F5、G5、H1-H3、H7-H9 | 每条对应一个已识别的 P0 或安全边界 |
| P1（同期，26 例） | A9-A10、B4-B8、C1、D1-D3、D7、D8、E1-E3、F2-F4、G1-G4、H4-H6 | 功能正确性主干 |
| P2（可后补，12 例） | C2、D6、D9-D11、E4、E5、F6-F8、G6、G7 | 边界与诊断 |

合计 **60 个测试函数**（逐条列名可对账，无重复无遗漏）；含 B1 的 3×4 参数化与 E1 的 12 例矩阵，实际执行用例数约 **100+**。**H7 = N1/N2，H8 = 能力缺失 auto-skip，H9 = N12。**

### 5.5 用 review 的 P0 反查覆盖

| review P0 | 能抓住它的测试 |
|---|---|
| P0-1 `close_range` 在 macOS 不存在 | N1/N2 编译 + F3 性能守卫（< 1ms，防退回 `close()` 循环） |
| P0-2 `SandboxConfig` 加字段破窗 | N1（`src/cli.rs:596` 字面量构造直接编译失败） |
| P0-3 `classify_exit` 拿不到 stderr | N8 的 G5（拒绝但 rc=0） |
| P0-4 `bool` 表达不了「预设 + 显式关」 | N4 的 A4 |

---

## 6. 不做的事

### 6.1 design §14 的后续项（本轮明确不做）

| 项 | 为何不做 | 接口预留 |
|---|---|---|
| `sandbox_init` 双通道（若 `sandbox-exec` 消失） | 4/4 坏 profile 失败开放，风险高；本轮以 `sandbox-exec` 存活为假设（附带 `bail!` 硬错误，F8） | 吸收点已收敛为 `build() → Plan` + 一条 `Command`，换 `sandbox_init` 约 40 行，局限在 `MacSandbox::spawn`（design §5.3） |
| 代理式域名过滤（放通到 localhost 代理端口，外部代理做域名判断） | Seatbelt 语法层直接拒绝域名与具体 IP（`host must be * or localhost`）；代理方案是另一个子系统 | `NetAccess::ViaProxy` 变体仅预留，不实现；`Ports` 之外的需求一律 `bail!("domain/IP allowlist is not expressible in Seatbelt")`（E5） |
| `PolicyReport` 结构化输出（`check --json`） | 本轮先把策略做对；报告是调试性增强 | 字段名现在就定：`setuid_blocked: bool`、`pending_preset: Option<String>`（design §12.3） |

### 6.2 平台机制映射（design §1，硬错误而非静默忽略）

| 机制 | macOS 处置 | 理由 |
|---|---|---|
| syscall 过滤（`--seccomp-*`） | 硬错误 | Seatbelt 无 seccomp 等价物 |
| namespace 隔离（`--unshare-*`） | 硬错误 | macOS 无 user/mnt/pid/net ns |
| mount（`--bind` / `--ro-bind` / `--tmpfs`） | 硬错误 | 无对应物，不改挂载表 |
| capability（`--cap-*`） | 硬错误 | macOS 无 Linux capabilities |
| Landlock ACL（`--landlock`） | 硬错误 | D1：不把 Seatbelt 语义挤进 Linux 面 |
| CodeWhale 集成 | 移出本轮范围 | 先把 seabox 自身做对 |

### 6.3 本轮额外排除

- `--trace-denies`（`log show --last 15s` 归因，0.66s/次）：设计已论证可行，但属显式可选诊断通道，本轮不实现，`Denied` 精度只做 `Probable`。
- `PlatformConfig` 枚举重构（`enum PlatformConfig { Linux(..), MacOs(..) }`）：review 已判定本轮不做，会破坏全部既有 `with_landlock` 等 API；记录为「第三个平台出现时」的演进压力点。
- 进程信息隔离（`(deny process-info*)` 的进程可见性控制）：design §1 范围外。
- `seabox check --json`。

---

## 7. 风险与回滚

### 7.1 `DenyMechanism` 加变体的 breaking change

| 项 | 内容 |
|---|---|
| 风险 | `src/lib.rs:122` `pub enum DenyMechanism { Landlock, Seccomp, Unknown }` 加 `Seatbelt`。全库无 `match mechanism`（已核实），**仓库内无编译风险**；但它是 `pub enum` 且无 `#[non_exhaustive]`，下游若对它做穷尽 `match` 会编译失败 |
| 概率 | 中低。下游通常只 `if let Denied { mechanism, .. }` 或 `==` 比较 |
| 缓解 | ① 与 `SandboxConfig` 的 `#[non_exhaustive]` 一并加（同一 breaking change 窗口，一次付清）；② CHANGELOG 标注 breaking；③ 版本号 `0.0.2` → `0.1.0` |
| 回滚 | 单行删除变体 + 删除 macOS 分支即可；不涉及数据迁移 |

### 7.2 `SandboxConfig` 加字段的 breaking change

| 项 | 内容 |
|---|---|
| 风险 | `src/config.rs:24` 加 `pub macos: MacOsConfig`。`SandboxConfig` **无 `#[non_exhaustive]`**，所有用结构体字面量构造的下游代码编译失败 |
| 仓库内受影响点（已核实） | `src/cli.rs:596`（全字段字面量）❌ 必须改；`tests/landlock_test.rs:514`（`..Default::default()`）✅ 幸免；`examples/cli_from_toml.rs:75`（`Default` + `with_*`）✅ 幸免 |
| 缓解 | 加 `#[non_exhaustive]`；CHANGELOG + README 升级说明给出「改用 `..Default::default()`」 |
| 回滚 | 删除字段 + `src/cli.rs:596` 对应行 |

### 7.3 `sandbox-exec` 未来被移除

| 项 | 内容 |
|---|---|
| 风险 | `/usr/bin/sandbox-exec` 与 `sandbox_init` 均被 Apple 标记 deprecated，未来系统版本可能移除。稳态依赖一个外部程序，比库调用多一层系统依赖 |
| 缓解 | ① `spawn` 时探测存在性，缺失即 `bail!`，**绝不静默降级为无沙箱**（F8；重蹈 `sandbox_init` fail-open 覆车）；② `check` 输出 `Seatbelt (sandbox-exec) available|missing`；③ 施加面收敛为「`build() → Plan` + 拼一条 `Command`」，替换为 `sandbox_init` 只需在 **fork 前**把 profile `CString` 化（满足 ADR 0003 零堆约束），改动局限在 `MacSandbox::spawn`，不触及生成器与配置面；④ 届时**必须保留**返回码硬错误：`rc != 0` 立即 `_exit(1)`，绝不继续执行 |
| 回滚 | 无需回滚动作（探测即 fail-closed，行为是「报错」而非「不安全」） |

### 7.4 本机无法验证 Linux 基线（N12）

| 项 | 内容 |
|---|---|
| 风险 | 本机只有 macOS 运行时，`docker` / `podman` / `limactl` 全无，无法在本机跑 221 测试基线。「Linux 零回归」是设计的第一承诺，却缺少本机证据 |
| 缓解 | ① 所有 Linux 侧改动都是 `cfg` 门控 + 一条依赖声明，无代码路径变更；② N13 双向 grep + `git diff src/linux/` 空；③ `src/lib.rs:169` / `:189` 的 Linux 分支要求 diff 为空，review 逐行核对；④ 交付前在具备 Linux 环境的机器上跑一次 `cargo test` 并记录 |
| 回滚 | 若 Linux 回归：`git checkout src/lib.rs src/config.rs Cargo.toml`（改动集中在 3 个文件的少数行，回滚面小） |

### 7.5 其余残余风险（design §13.2）

| # | 风险 | 缓解 |
|---|---|---|
| 1 | **读侧零隔离**（预设默认 `All`）：凭据保护是黑名单，漏一个即泄漏；`--mac-write` 可反向放通 | `check` / README 写死；B8 golden 锁死清单；需真隔离时用 `MacReadMode::Only` |
| 2 | **顺序敏感**：一次「调换两行」静默放开策略 | 生成器固定顺序 + **全平台**段序断言 B1（§5.1） |
| 3 | 归因弱于 Linux（无 `(nr, arch)`） | `DenyMechanism::Seatbelt` + 精度分级（Probable/Certain） |
| 4 | 65/134 与目标程序自身退出码歧义 | 65 需 stderr 含 `sandbox-exec:` 才判 `InternalError`；134 归 `Denied` 但标「可能」（G2/G3/G4） |
| 5 | **setuid 程序不可用**（`ps`/`top`/`su`/`crontab` 5/5 全拒，任何 SBPL 规则都放不通——是 `sandbox-exec` 自身硬限制） | `check` 单列（§N11）；`execute` 检测 `execvp() failed: Operation not permitted` 时提示可能是 setuid 限制 |
| 6 | 双配置面心智负担（`--landlock` 在 macOS 报错） | `check` 输出平台可用面；错误消息给出对应 `--mac-*` 建议（H3） |
| 7 | `FullAccess` + `deny network*` 依赖后写赢 | 独立 golden 用例锁死顺序（B1 矩阵含此组合） |
| 8 | **预开 fd 绕过策略** | `pre_exec` fd 清扫，保留集合 fork 前算好（§2.6） |
| 9 | **语义失效静默通过** | canary 预检，每配置一次；无可探时显式警告（F4/F5/F6/F7） |
| 10 | 无 CI 覆盖 macOS | 生成器纯函数化 + 段序断言全平台可测（覆盖 ~70% 逻辑）+ 每版手工冒烟 |
| 11 | `NetAccess` 与 `NetworkConfig.loopback` 概念重叠 | 文档加 Linux/macOS 网络语义对照表 |
| 12 | canary 缓存跨实例失效（`Sandbox::from_config` 每次新建 `MacSandbox`） | 文档明确「同配置只跑一次」的实际生命周期，不承诺跨进程缓存（review P1 已指出） |

**实现量估算**：`config.rs` ~250 行、`sbpl.rs` ~280 行、实现侧（mod/imp）~380 行、校验 + CLI ~150 行、测试 ~350 行，合计 **~1160 行**；另加 `Cargo.toml` 一条 target 依赖、12 个测试文件的 `#![cfg]`、`syscall_probe` 的分支 `main`。**Linux 行为零变化**。
