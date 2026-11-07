# seabox macOS Seatbelt 后端设计

> 状态：设计稿（待 review）
> 前置：[context.md](context.md)（实测语义、范围界定、决策 D1）
> 目标平台：macOS 27.0.1 (Darwin 27.0.0, arm64)
> 关键技术决策摘要见[附录 A](#附录-a决策记录)；实测依据见 [context.md](context.md)

## 1. 目标与不做的事

**目标**：给 seabox 增加 macOS 后端，用 Apple Seatbelt（SBPL + `sandbox-exec`）兑现两类策略——**文件系统**与**网络**——并提供三种集中预设，使 Agent 的每条命令默认受限。

**不做**（本轮范围外，且**必须显式报错**而非静默忽略）：

| 机制 | macOS 处置 |
|---|---|
| syscall 过滤（`--seccomp-*`） | 硬错误：Seatbelt 无 seccomp 等价物 |
| namespace 隔离（`--unshare-*`） | 硬错误：macOS 无 user/mnt/pid/net ns |
| mount（`--bind` / `--ro-bind` / `--tmpfs`） | 硬错误：无对应物，不改挂载表 |
| capability（`--cap-*`） | 硬错误：macOS 无 Linux capabilities |
| Landlock ACL（`--landlock`） | 硬错误：D1 决定不把 Seatbelt 语义挤进 Linux 面 |
| 域名 / 具体 IP 白名单 | 硬错误：SBPL 语法层直接拒绝（实测） |
| CodeWhale 集成 | 移出本轮范围 |

设计原则沿用 [`docs/arch/codewhale-integration/design.md`] 的「语义诚实」：**能做的事做好，做不到的明确报错，不制造安全假象**。

## 2. 候选方案对比与选择

三个方向并行设计后收敛为：**候选 A（最小复杂度）** 为主体，吸收 B 的「生成与施加分离」和 C 的三个安全加固点。

| 维度 | 候选 A（最小复杂度） | 候选 B（可扩展优先） | 候选 C（安全/性能优先） | **采纳** |
|---|---|---|---|---|
| 新增抽象层 | 无 | 三层：`Policy`→`Capabilities`→`Plan` | 分段枚举 `Segment` | **A + C 的分段** |
| 新增文件 | 2 个 | 8+ 个（大规模重构） | 8 个（含 canary/fdhide） | **A 为主** |
| 预估代码量 | ~700 行 | ~1800 行 | ~1500 行 | **~1100 行** |
| 顺序安全 | 生成器固定顺序 | `Stage` 类型 + 单调性检查 | 封闭 `Segment::ALL` 枚举 | **C 的封闭枚举** |
| 拒绝归因 | 复用 `blocked_syscall` 哨兵 | 独立 `ViolationRecord` | `DenialEvidence` | **A + C 的 stderr+日志双通道** |
| fail-closed 闸门 | 无 | 无 | **canary 预检** | **C**（关键补充） |
| fd 卫生 | 未提及 | 未提及 | **`pre_exec` fd 清扫** | **C**（关键补充） |
| Linux 回归风险 | 零 | 高 | 零 | **A/C** |

**选择理由**：B 的 `Policy`/`Capabilities` 抽象在当前只有 macOS 一个消费者（Linux 侧已有实现，不会反向改写），三层类型是为尚不存在的 Windows 后端预付成本。`sbpl.rs` 只要是一个**无 `cfg` 门控的纯生成器**，就已满足「Linux CI 可测」这一核心价值。

**从 C 吸收的三个加固点**（均为实测确认，见 §9.1 / §9.2 / §6.5）：

1. **canary 预检**：施加后先跑一次「应当被拒」的探针，若探针成功则说明策略未生效，立即 fail-closed。这弥补了「`sandbox-exec` 只在 profile 语法错误时 fail-closed，语义错误仍可能静默放行」的缺口。
2. **fd 卫生**：预开 fd 会**绕过**文件策略（实测 `exec 9>/host` → 沙箱内 `echo >&9` 写入成功），必须在 `pre_exec` 清扫非 stdio fd。
3. **禁用 `prefix` 匹配符**：字符串前缀会跨目录越权（实测 `subpath /proj` 拒 `/proj-backup`，而 `prefix /proj` **允许**）。

## 3. 架构

```
SandboxConfig
├── macos: MacOsConfig ──────┐
└── (linux 字段不变)          │
                              ▼
                    macos::sbpl::build()   ← 全平台编译，Linux CI 可单测
                              │
                        Plan { profile: String, params: Vec<(String, String)> }
                              │
                    MacSandbox::spawn()    ← cfg(target_os="macos")
                              │
              /usr/bin/sandbox-exec -D k=v ... -p <profile> -- <prog> <args>
                              │
                     child::run_to_output()  ← 复用，不改
```

模块布局（新增 2 文件 + 3 处改动）：

```
src/macos/mod.rs   # MacOsConfig / MacPreset / NetAccess / validate() / MacSandbox / MacChild / canary
src/macos/sbpl.rs  # Plan + build()：纯生成器（无 cfg 门控）
src/lib.rs         # create_sandbox_impl 加 macOS 分支；check_capabilities 加 macOS 表；DenyMechanism::Seatbelt
Cargo.toml         # landlock 改 target-specific 依赖
```

**`sbpl.rs` 不门控**：它仅做 `canonicalize` + 字符串拼接，无平台 API，因此能在 Linux 上跑 golden test——这是顺序敏感策略的唯一可靠防线（见 §6）。

`MacSandbox` **在构造期**（`create_sandbox_impl`）调用 `build()` 并跑 canary 预检（§9.1），配置错误与策略失效均此时暴露；`spawn` 只剩 fork + fd 清扫 + exec，符合 ADR 0003。`MacChild` 与 `LinuxChild` 并列实现 `SandboxChildImpl`，`child.rs::run_to_output()` 原样复用。

### 3.1 编译可用性（已实测）

`landlock = "0.4"` 改为 target-specific 依赖后，**`cargo build --lib` 与 `--bin seabox` 在 macOS（27.0.1 / arm64）上直接通过**，耗时约 2.2s：

```toml
[target.'cfg(target_os = "linux")'.dependencies]
landlock = "0.4"
```

剩余两处需门控（`--lib` 之外仍会断）。**均已实测修法，不是推测**：

| 位置 | 问题 | 处理 |
|---|---|---|
| `src/bin/syscall_probe.rs` | `libc::syscall` 签名差异；`SYS_*` 常量缺失（实测 8 处 E0308） | **不能**用文件级 `#![cfg]`，见下方⚠️ |
| `tests/*.rs`（**12 个**） | 全部 Linux 专属（`use seabox::linux::…`） | 每文件顶部 `#![cfg(target_os = "linux")]` ✅ 实测有效 |

> ⚠️ **`syscall_probe.rs` 不能用文件级 `#![cfg(target_os = "linux")]`**。实测：加上后报
> ```
> error[E0601]: `main` function not found in crate `syscall_probe`
> ```
> 原因：`[[bin]]` target 是无条件声明的，Cargo 不会因 `cfg` 而跳过构建；属性把整个 crate 内容（含 `main`）都裁掉了，链接期自然找不到入口。
>
> **正确写法**（已实测通过）——保留统一 `main`，内部分支：
>
> ```rust
> fn main() -> std::process::ExitCode {
>     #[cfg(target_os = "linux")]
>     { linux_main() }
>     #[cfg(not(target_os = "linux"))]
>     {
>         eprintln!("syscall_probe is Linux-only");
>         std::process::ExitCode::from(77)
>     }
> }
>
> #[cfg(target_os = "linux")]
> fn linux_main() -> std::process::ExitCode { /* 原 main 体 */ }
> ```
>
> 并对 `use std::env` / `use std::process::ExitCode` / `parse_i64` / `dispatch_syscall` 全部逐个加 `#[cfg(target_os = "linux")]`。选 77 而非 1，以免与测试中「预期拒绝」的退出码混淆。

**总体验证结论**：上述三处改完后，macOS 上 `cargo build --lib --bins --tests` **全部通过**（实测 `Finished dev profile`，零警告变更）。这坐实了「Linux 行为零变化」的前提：所有改动都是 `cfg` 门控 + 一条依赖声明，无 Linux 代码路径变更。

## 4. 配置面

### 4.0 预设与自定义的关系

**预设与字段不是二选一，而是“默认值 vs 覆盖”**：

```
MacOsConfig
  preset: Some(WorkspaceWrite)   → 填一组默认值（read=All, write=[cwd], tmp=true, net=Deny）
  preset: None                    → 不填默认值，完全由字段决定
  字段（write/read/deny_*/net）→ 无论有无预设都生效，可覆盖预设值
```

展开规则：

| 场景 | 行为 |
|---|---|
| 无预设，无字段 | **不施加 Seatbelt**（直接执行，与 Linux 空 `landlock` 一致） |
| 有预设 | 用预设默认值构建 profile |
| 无预设，有字段（如只有 `--mac-write`） | 用**安全基线**构建：`read=All`、无任何其他写权、禁网；用户字段叠加 |
| 有预设 + 字段 | 预设填默认，字段覆盖/追加 |

「安全基线」定义为：floor + `(allow file-read*)` + 仅用户显式给的 `write` + 禁网 + 凭据 denylist。实测：写 `W0` 允许，写其他目录拒，https 不通。

#### 为何不用隐式默认预设

不能“你什么都不配，我就帮你选 ReadOnly”——那是静默降权，Agent 跑构建时会突然失败且原因不可见。不配就是不配，与 Linux 对称。

#### `$HOME` 告警与凭据写侧封禁

两层防护，均为 `WorkspaceWrite` 路径下的必要实现：

1. **告警**：workspace 解析结果等于 `$HOME` 时，stderr 输出「workspace 是家目录，建议指定子目录」。
2. **凭据目录补写侧 deny**（更根本）：内置凭据清单必须同时封读**和写**：

```
(allow file-write* (subpath (param "WS")))       ; workspace 子树
(deny  file-write* (subpath (param "D0")))        ; 凭据：后写赢
(deny  file-read*  (subpath (param "D0")))
```

实测该组合：写 `.ssh/authorized_keys` 被拒，而写 `WS/normal.txt` 仍可写（不误伤）。

> 早期设计只做了读侧 deny。这是真缺口：读保护挡不住「写一个后门进去再用别的方式执行」。

### 4.1 结构

```rust
// src/macos/mod.rs —— 全平台可构造（Linux 上不参与任何逻辑）
#[derive(Clone, Debug, Default)]
pub struct MacOsConfig {
    /// 可选预设。`None` = 自定义模式（仅按下方字段构建）。
    /// 预设与字段的关系：预设填默认值，字段可覆盖。见 §4.0
    pub preset: Option<MacPreset>,

    // ── 写侧（可独立配置，无需预设）──
    /// 可写目录根。递归含整棵子树，含删除权（见 §6.2b）
    pub write: Vec<PathBuf>,
    /// 写拒绝（后写赢，嵌在 write 之后）
    pub deny_write: Vec<PathBuf>,
    /// TMPDIR 可写。`None` = 跟随预设/基线；`Some(v)` = 显式覆盖
    pub tmp_writable: Option<bool>,

    // ── 读侧 ──
    /// 读模式。`None` = 跟随预设（预设均为 `All`）
    pub read: Option<MacReadMode>,
    /// 读拒绝（叠加在内置凭据清单之上）
    pub deny_read: Vec<PathBuf>,
    /// 关闭内置凭据清单。`None` = 跟随默认（开）；`Some(true)` = 关闭
    pub no_credential_deny: Option<bool>,

    // ── 其他 ──
    /// 是否放行 .git 写。`None` = 跟随预设（均为 true）；`Some(false)` = carve out
    pub allow_git_write: Option<bool>,
    /// 网络。`None` = 未配（不施加沙箱时网络全开）；`Some(v)` = 显式指定
    pub net: Option<MacNetConfig>,
}

/// 读侧模式。与早前结论不同：macOS 上读侧**可以**真正隔离（见 §4.3）
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum MacReadMode {
    /// `(allow file-read*)` —— 读全开，靠凭据 denylist 补偿。预设默认
    #[default]
    All,
    /// 只读指定根 + 内置系统地板。能真正隔离，需枚举系统路径（§4.3）
    Only(Vec<PathBuf>),
}

#### 为何三个开关用 `Option<bool>` 而非 `bool`

这是本轮 review 发现的核心语义缺口。若用 `bool`：

| 用户意图 | 用 `bool` 能否表达 |
|---|---|
| 用 ReadOnly 预设，TMP 可写（预设默认） | ✅ |
| 用 ReadOnly 预设，**但显式关掉** TMP 可写 | ❌ **无法表达** |
| 不用预设，TMP 不可写 | ✅ |
| 不用预设，TMP 可写 | ✅ |

第二行正是 §4.0 的核心设计目标（「预设填默认，字段可覆盖」），而 `bool` 区分不了「未设置」与「显式 false」。**`Option<bool>` 的三个取值直接对应三种语义**：

```
None        → 跟随预设/基线
Some(true)  → 显式开（覆盖预设）
Some(false) → 显式关（覆盖预设）
```

`read` 同理用 `Option<MacReadMode>`：`None` = 跟随预设（预设全为 `All`），`Some(Only([...]))` = 显式要求读隔离。这样 `--mac-read` 出现即 `Some(Only(..))`，与 §4.5 的「模式开关」描述一致。

代价：`with_mac_*` 签名从 `bool` 变成 `Option<bool>`，调用侧略啰嗦。因此额外提供语义化快捷方法：

```rust
pub fn with_mac_no_tmp_writable(self) -> Self { self.with_mac_tmp_writable(Some(false)) }
pub fn with_mac_no_git_write(self) -> Self   { self.with_mac_git_write(Some(false)) }
```

> 现有代码库无 `Option<bool>` 先例（`grep Option<bool> src/` 无结果），但这是语义必需的引入，不是风格偏好。备选是加一个 `explicit: u8` 位标记——那本质上是手写的 `Option`，可读性更差。

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacPreset { ReadOnly, WorkspaceWrite, FullAccess }

#[derive(Clone, Debug, Default)]
pub struct MacNetConfig {
    pub outbound: NetAccess,      // 默认 Deny
    pub inbound_loopback: bool,   // 默认 false
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum NetAccess {
    #[default]
    Deny,
    Loopback,
    Ports(Vec<u16>),
    All,
}
```

`SandboxConfig` 增加一个字段：

```rust
pub struct SandboxConfig {
    // ... 既有字段全部不动 ...
    pub macos: MacOsConfig,   // Default::default() = 未配置
}
```

> ⚠️ **这是破坏性变更，不是「零改动」**。`SandboxConfig` 没有 `#[non_exhaustive]`，因此加字段会使所有用**结构体字面量**构造的下游代码编译失败。本仓库内已核实的受影响点：
> 
> | 位置 | 构造方式 | 影响 |
> |---|---|---|
> | `src/cli.rs:596` | 全字段字面量 | ❌ 需补 `macos: Default::default()` |
> | `tests/landlock_test.rs:514` | `{ landlock: rules, ..Default::default() }` | ✅ 用 `..` 幸免 |
> | `examples/cli_from_toml.rs:75` | `SandboxConfig::default()` + `with_*` | ✅ 幸免 |
>
> 仓库外：`seabox` 是 lib + bin 双形态 crate，`SandboxConfig` 是 `pub use` 的公开 API，下游若用字面量构造即升级失败。
>
> **处理建议**：本阶段（Phase 3 / 0.x）宜同时加上 `#[non_exhaustive]`——趁下游使用者少一次性付清成本。代价是下游只能用 `..Default::default()` 构造，但那本来就是推荐写法。需在 CHANGELOG 标注 breaking change。

### 4.2 三种预设的语义

| 预设 | `read` | `write` | `tmp_writable` | `allow_git_write` | 凭据保护 | 典型场景 |
|---|---|---|---|---|---|---|
| `ReadOnly` | `All` | `[]` | `Some(true)` | `Some(true)` | ✅ 读+写 deny | 审查代码、跑只读命令 |
| `WorkspaceWrite` | `All` | `[cwd]` | `Some(true)` | `Some(true)` | ✅ 读+写 deny | Agent 日常开发 |
| `FullAccess` | `All` | 全盘（`allow default`） | `Some(true)` | `Some(true)` | ❌ 忽略 | 明确信任的任务 |
| *无预设（安全基线）* | `All` | 用户字段 | `Some(false)` | `Some(true)` | ✅ 默认开 | 需要真读隔离 |

> 预设只填**上表列出的字段**（内部生成 `MacOsConfig` 的值）；用户显式给的同名字段总是覆盖预设值。
> 这就是 `Option<bool>` 的意义：`None` 能区分「没配」（跟随预设）与「配了 false」（覆盖预设）。

#### 合并算法（生成器入口必须先跑这一步）

`Option` 字段在进 SBPL 生成器之前必须全部**解析定**。否则生成器内會满屏 `unwrap_or`，而 `bool` 与 `Option<bool>` 的误用不会报错。

```rust
/// 内部类型：已定型、无 Option。生成器只接受它。
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
        // 1) 预设先展开为基线；无预设时用「安全基线」
        let base = match self.preset {
            Some(p) => p.defaults(),       // 上表前三行
            None    => MacPreset::baseline(), // 上表最后一行
        };
        // 2) Option 字段：Some 覆盖，None 跟随基线
        ResolvedPolicy {
            read:            self.read.clone().unwrap_or(base.read),
            tmp_writable:    self.tmp_writable.unwrap_or(base.tmp_writable),
            allow_git_write: self.allow_git_write.unwrap_or(base.allow_git_write),
            credential_deny: self.no_credential_deny
                                 .map(|no_deny| !no_deny)
                                 .unwrap_or(base.credential_deny),
            // 3) Vec 字段：追加而非覆盖（用户策略总是叠加）
            write:      extend_unique(base.write, &self.write),
            deny_write: [base.deny_write, self.deny_write.clone()].concat(),
            deny_read:  [base.deny_read,  self.deny_read.clone()].concat(),
            net:        self.net.clone().unwrap_or_default(),   // 与预设正交（§8）：默认 Deny
        }
    }
}
```

两条容易错的规则：

| 字段类型 | 语义 | 理由 |
|---|---|---|
| `Option<T>` | 预设默认，用户**覆盖** | 单值语义，后者胜 |
| `Vec<T>` / `deny_*` / `write` | 预设默认 + 用户**追加** | 用户在预设基础上加限制是理性行为，静默丢弃内置凭据清单会是安全回退 |

> `write` 的追加需去重并**保留预设值在前**（§6.1：后写赢，但同属白名单段，顺序不影响结果；去重只为输出稳定）。

`resolve()` 应当是**幂等纯函数**、不碰文件系统（除了 `write` 里的 `workspace` 展开），以便 Linux CI 单测全覆盖。

#### 直通判断在 `resolve()` 之前

“无预设且无任何字段 = 不限制”不能靠 `resolve()` 表达——展开后的 `ResolvedPolicy` 长得很像安全基线。因此需要独立的**配置存在性判断**，且必须**逐字段显式检查**：

```rust
impl MacOsConfig {
    /// 是否用户真的配了 macOS 策略。false → 不进 sandbox-exec
    pub fn is_configured(&self) -> bool {
        self.preset.is_some()
            || !self.write.is_empty()
            || !self.deny_write.is_empty()
            || self.tmp_writable.is_some()
            || self.read.is_some()
            || !self.deny_read.is_empty()
            || self.no_credential_deny.is_some()
            || self.allow_git_write.is_some()
            || self.net.is_some()
    }
}
```

> **为何不用 `self != &Default::default()`（已否决）**：值相等不等于“未配”。`--mac-net deny` 恰好等于 `MacNetConfig` 的默认值 Deny，一旦用 `PartialEq` 判，用户显式要的禁网会被当成未配，结果**沙箱不施加、网络全开**——静默失败开放，恰好是本设计最想避免的失效模式。这也是为何 `net` 必须用 `Option<MacNetConfig>` 而非 `MacNetConfig`。
>
> 代价：`is_configured()` 需在新增字段时同步（容易漏）。**防护**：单测遍历一个字段列表断言“只改这个字段 ⇒ `is_configured()` 为真”。

> **无预设且无任何字段 = 不限制**：直接执行，与 Linux 空 `landlock` 直通一致。有字段时走「安全基线」构建。

### 4.3 读隔离：早前结论已被推翻

设计初期认为"窄读白名单不可行，必须读全开"。**这是错的**——真因是 floor 缺了三个关键项，不是白名单不可行。

#### 破案过程

| 补上什么 | 效果 |
|---|---|
| `(allow file-read* (literal "/"))` | 避免 abort(134) |
| `(allow file-read* (subpath "/dev"))` | **关键**：`git` 的 `could not open '/dev/null'` 消失 |
| `(allow ipc-posix-shm)` | **关键**：`apple.shm.notification_center` 拒绝消失 |
| `(allow file-read-metadata)` | 目录遍历正常 |
| 符号链接 `literal "/etc"` | `/etc` 是 `→private/etc` 链接，只放 `/private/etc` **不生效** |

补齐后实测（`read=Only([R0])` + 系统地板）：

| 检查 | 结果 |
|---|---|
| 读 R0 内文件 | ✅ 允许 |
| 读 `/etc/passwd`（不在白名单） | ❌ 拒 |
| 读 `$HOME`（不在白名单） | ❌ 拒 |
| `git` / `cat` / `ls` / `sh` / `whoami` / `cargo` | ✅ 全部可用 |

#### 结论

`MacReadMode::Only` 是**真的隔离**，但代价不小：

1. **必须枚举系统地板**：`/usr` `/System` `/Library` `/private/var/db` `/private/etc` `/bin` `/sbin` `/var` `/dev` + 符号链接 `/etc` `/tmp`。
2. **仍依赖用户环境**：`$HOME` 是否要加由用户决定（不加则 `~/.gitconfig`、`~/.cargo` 均不可读，工具会失败）。
3. **失败模式恶劣**：漏一个路径就是 `Operation not permitted` 或 abort(134)，且错误信息不指向缺失的规则——需靠 `log stream` 定位（实测有效）。

因此：**预设默认用 `All`（零维护），但 `Only` 作为一等公民提供**，供需要真隔离的用户显式选择。不再声称“不可能”。

各预设的完整字段映射见 §4.2。

### 4.4 内置凭据拒绝清单

默认同时 deny **读与写**：`~/.ssh`、`~/.aws`、`~/.gnupg`、`~/.kube`、`~/.netrc`、`~/.npmrc`、`~/.config/gh`、`~/.docker/config.json`。

这是 `MacReadMode::All` 的补偿项。实测：全局 `(allow file-read*)` 之后追加 `(deny file-read* (subpath "~/.ssh"))` **确实生效**，且同时挡住 `stat`（元数据不泄漏）。
写侧 deny 同样必要（见 §4.0）：只封读挡不住「写一个后门进去」。生成顺序：WS allow → 凭据写 deny → 凭据读 deny，靠后写赢。

> 用 `MacReadMode::Only` 时凭据目录通常已在白名单外，但默认仍加 denylist——防用户把 `~` 整个加进读白名单。

> ⚠️ 风险声明：这是一份**黑名单**，漏一个目录就是真泄漏。`check` 与 README 必须写死这一点（§12 风险 1）。

### 4.5 CLI

```
# 预设（可选，一键填默认值）
--mac-preset read-only|workspace-write|full-access

# 写侧（可独立用，无需预设）
--mac-write PATH                 (可重复)
--mac-deny-write PATH            (可重复)
--mac-workspace DIR              (workspace-write 预设的写根，默认 cwd)
--mac-no-tmp-writable

# 读侧（可选，自定义时生效）
--mac-read-all                   (默认)
--mac-read PATH                  (可重复；出现即切到 Only 模式)
--mac-deny-read PATH             (可重复，叠加)
--mac-no-credential-deny

# 其他
--mac-no-git-write
--mac-net deny|loopback|all|443,80
--mac-net-inbound
```

#### 三种使用方式（均合法）

```bash
# ① 纯预设
seabox run --mac-preset workspace-write -- cargo build

# ② 纯自定义（无预设）：安全基线 + 只给指定写权
seabox run --mac-write ./target --mac-write ~/.cargo -- cargo build

# ③ 预设 + 覆盖
seabox run --mac-preset workspace-write --mac-write ~/.cargo -- cargo build
```

#### `--mac-read` 是模式开关

出现任何一个 `--mac-read` 就切到 `MacReadMode::Only`，不再发 `(allow file-read*)`。这意味着 **用户必须自己补齐系统路径**（或依赖内置地板）。这是有意设计：选择真隔离就要承担配置成本。

为避免“选了 `Only` 但漏了 `/usr` 导致什么都跑不了”，`--mac-read` 自动附带系统地板（`/usr` `/System` `/Library` `/private/*` `/bin` `/sbin` `/var` `/dev` + 符号链接），用户只需给业务路径。

#### crate API 对应（AGENTS.md 要求）

| CLI | lib |
|---|---|
| `--mac-preset X` | `with_mac_preset(MacPreset::X)` |
| `--mac-write P` | `with_mac_write(P)` |
| `--mac-deny-write P` | `with_mac_deny_write(P)` |
| `--mac-workspace D` | `with_mac_workspace(D)` |
| `--mac-read P` | `with_mac_read(P)` （内部置 `Some(Only([...]))`） |
| `--mac-read-all` | `with_mac_read_all()` （置 `Some(All)`） |
| `--mac-deny-read P` | `with_mac_deny_read(P)` |
| `--mac-no-credential-deny` | `with_mac_no_credential_deny()` |
| `--mac-no-git-write` | `with_mac_no_git_write()` |
| `--mac-no-tmp-writable` | `with_mac_no_tmp_writable()` |
| `--mac-net N` | `with_mac_net(NetAccess::…)` |
| `--mac-net-inbound` | `with_mac_net_inbound(true)` |

底层完整签名（带 `Option`，供需要表达「显式开」的调用者）：

```rust
pub fn with_mac_tmp_writable(mut self, v: Option<bool>) -> Self
pub fn with_mac_git_write(mut self, v: Option<bool>) -> Self
pub fn with_mac_credential_deny(mut self, v: Option<bool>) -> Self
pub fn with_mac_read_mode(mut self, v: Option<MacReadMode>) -> Self
```

CLI 层只映射到语义化快捷方法（用户不需要表达 `Some(true)`）；库调用者两者均可用。

### 4.6 双向硬错误

在 `create_sandbox_impl`（以及 `Sandbox::from_config`）内校验：

- **macOS 上**：`seccomp_deny_nrs`/`seccomp_filter_bytes`/`capabilities`/`mount.specs`/`namespaces.{user,ipc,mnt,pid,uts,cgroup}`/`landlock` 任一非默认 → `bail!("<field> is not supported on macOS")`。
- **Linux 上**：`macos.preset.is_some()` 或任一 `--mac-*` 被设置 → `bail!("--mac-* only applies on macOS")`。
- `timeout_*`、`process_group`、`StdioConfig` 原生生效，不校验。

**注意**：macOS 上“无预设但给了 `--mac-write`”**不报错**，走安全基线（§4.0）。只有既不预设也无任何 `--mac-*` 字段时才不施加沙箱。

## 5. 施加机制：`sandbox-exec`

**决策：采用外部进程 `/usr/bin/sandbox-exec` 作为唯一施加机制，不用进程内 `sandbox_init()`。**

两条路径都被 Apple 标记 deprecated、都无公开规范，因此选择完全基于实测语义而非文档。

### 5.1 决定性理由：失败语义

| 场景 | `sandbox_init()` | `sandbox-exec` |
|---|---|---|
| 未知操作名 | `rc=-1`，**进程无沙箱，宿主可写** | `rc=65`，**命令不执行** |
| 括号不闭合 | `rc=-1`，**宿主可写** | `rc=65`，命令不执行 |
| `(version 99)` | `rc=-1`，**宿主可写** | `rc=65`，命令不执行 |
| 缺 `(version)` | `rc=-1`，**宿主可写** | `rc=65`，命令不执行 |

4/4 坏 profile 在 `sandbox_init` 下**全部失败开放**：调用返回错误码，但进程继续运行时**没有任何沙箱**。若调用方按惯例「记录警告后继续」，Agent 就得到一个看起来受限、实际完全自由的执行环境——这正是沙箱工具最不可接受的失败模式。

`sandbox-exec` 的 fail-closed（rc=65，副作用探针文件未生成）直接排除这一整类风险。

### 5.2 其他理由

| 维度 | 说明 |
|---|---|
| 可重入 | `sandbox_init` 在已沙箱进程内再调 → `EPERM`，嵌套场景会强制走失败开放路径 |
| 进程模型 | **原地 exec，pid 不变**（实测 fork 后 pid 43419 == 最终 `/bin/sh` pid）。ADR 006 的 business-pid 语义天然成立，`SandboxChildImpl`（kill / `kill(-pgid)` / wait）与 `child::run_to_output()` 原样复用，无额外进程、无 pid 映射表 |
| 开销 | 20 次调用 0.119s vs 裸 `true` 0.010s ≈ **+5~6ms/次**。Agent 单条命令耗时数十毫秒到数秒，不可感知 |
| 可调试 | profile 原文可贴进 shell 复现问题 |

**profile 通过 `-p <text>` 传递**，不写临时文件：无清理路径、无 fd 泄漏、无 TOCTOU 窗口。实测 279 KB / 5000 条规则下正常（`ARG_MAX` 1 MB），远超实际需求。

```rust
Command::new("/usr/bin/sandbox-exec")
    .args(["-D", &format!("WS={}", ws)])   // 每个 param 一条
    // ...
    .arg("-p").arg(&plan.profile)
    .arg("--").arg(&spec.program).args(&spec.args)
    .current_dir(cwd)
    .env_clear().envs(env)
    .pre_exec(|| /* setpgid + dup2 + fd 清扫，零堆操作 */)
```

### 5.3 后果与回退

**正面**：坏 profile 一律 fail-closed；零额外进程，pid 语义与 Linux 一致；profile 生成（`sbpl::build()`）与施加分离，生成器可全平台单测。

**负面**：依赖 `/usr/bin/sandbox-exec` 的存在性（`check` 必须探测）；每次 +6ms；稳态依赖一个外部程序，比库调用多一层系统依赖。

**回退路径**（若 Apple 移除 `sandbox-exec`）：吸收点已收敛为「`build() → Plan` + 拼一条 `Command`」，替换为 `sandbox_init` 只需在 **fork 前**把 profile `CString` 化（满足 ADR 0003 的零堆约束），改动局限在 `MacSandbox::spawn`，不触及生成器与配置面。届时**必须保留**对返回码的硬错误处理——`rc != 0` 立即 `_exit(1)`，绝不继续执行，否则重演失败开放。

## 6. SBPL 生成器

### 6.1 为什么生成器是安全边界

#### 实测：「后写赢」，与 specificity 无关

设计初期基于「deny 恒优先于 allow」的常见假设做规划——按这个假设，规则集合语义与书写顺序无关，生成器可以自由组织规则。**实测推翻了这个假设。**

目标文件 `outer/inner/f.txt`：

| 规则序列 | 结果 |
|---|---|
| `deny outer` → `allow outer/inner` | **可读**（后写 allow 赢） |
| `allow outer/inner` → `deny outer` | **拒**（后写 deny 赢） |
| `deny f` → `allow f` | 可读 |
| `allow f` → `deny f` | 拒 |
| `allow outer` → `deny outer/inner` | **拒** |

最后一行的解读需小心：deny-恒优先与 specificity-优先两种模型都能预测它。真正区分两者的是前两行——**同一对规则，仅仅交换顺序，结果就反转**。

**结论：后写的规则覆盖先写的，与路径具体度无关，与 allow/deny 无关。**

#### 后果（真实风险）

**任何一次「顺手调换两行」都能静默放开策略，不产生任何错误或警告。** 生成器必须成为唯一的安全边界。

三道防线：

1. **固定段落顺序**（`sbpl::build()` 内写死，不可配置）：

```
1  (version 1)
2  (deny default)                    | FullAccess: (allow default)
3  floor（进程 / ipc / sysctl / 读 / 隐式写点）
4  预设写白名单（ReadOnly 无；WS: require-all + carve-out；Full 无）
5  TMP 可写
6  deny_read（凭据 + 用户追加）        ← 最后一条 file 规则
7  network（最末）
```

`deny_read` 必须在写白名单**之后**，否则会被后续 allow 覆盖。

2. **顺序断言测试**：golden file 比较完整字符串（天然含顺序），并**额外断言** `deny default` 的行号 < floor < write 白名单 < deny_read < network 的相对位置。仅比对「规则集合相等」的测试**不足以**防止顺序回归。

3. **禁止用户控制顺序**：`--mac-write` / `--mac-deny-read` 是列表，但生成时按固定段落聚合，用户给的先后不影响输出位置。原始 SBPL 逃生舱（若未来引入）必须强制落在最后一段。

此外，固定的段落顺序使**三段式策略**成为可能（扩展能力而非仅防御）：

- `(allow file-read*)` → `(deny file-read* "~/.ssh")` → `(allow file-read* "$WS")`，表达「读全开 + 凭据保护 + workspace 例外」
- `FullAccess` 用 `(allow default)` + `(deny network*)` 实现「全放行但禁网」

两道兼得的安全裕度：坏 profile 会 fail-closed（得益于 §5 选 `sandbox-exec`），语法/顺序 bug 不会静默降级为「无沙箱」，而是 rc=65 拒绝执行。

#### 被否决

- **依赖 specificity 排序**（按路径长度/具体度排序，期望更具体的规则胜出）：实测证明假设不成立，若依赖它，策略行为将不可预测。
- **交由用户控制顺序**（暴露原始 SBPL 文本）：把顺序正确性推给用户，而用户无法从错误信息诊断顺序问题（拒绝与否只体现为 EPERM）。逃生舱仅作为最后一段存在。

### 6.2 路径规范化（两个实测坑）

`sbpl::norm()` 是唯一的路径入口：

1. **必须 `fs::canonicalize`**：`/var` 与 `/private/var` 是两个不同字符串，`subpath` 按字面比较，**不解析 symlink**。`/tmp` → `/private/tmp`、`$TMPDIR` 的 `/var/folders/...` → `/private/var/folders/...`。两个方向都 DENY（实测）。不解析就**永不匹配**且无提示（实测：`cargo build` 报 `os error 1`）。
   > 更正：早期版本将 `$TMPDIR` 失败归因于「尾斜杠」——**错误**。实测 `WS=/p/ws`、`/p/ws/`、`/p/ws//` 行为完全一致，尾斜杠无害。真因就是 `/var` 未解析。仍建议归一化，但属整洁性而非正确性。
2. **必须自己校验存在性**：`-D` 传不存在的路径 `sandbox-exec` **不报错**，规则静默失效。`canonicalize` 失败即硬错误。

### 6.2b `subpath` 的递归语义（`--mac-write` 的直接后果）

`(subpath dir)` 授予的是**整棵子树**，不是单层目录。实测（`WS=/p/rec/ws`）：

| 操作 | 结果 |
|---|---|
| 写 `WS/f.txt` | ✅ |
| 写 `WS/a/b/c.txt`（多级） | ✅ |
| `mkdir -p WS/new/deep` | ✅ |
| 新建目录后再写入 | ✅ |
| `unlink WS` 内已有文件 | ✅ |
| 写 `WS` 父目录 / 兄弟目录 | ❌ |
| 写 `WS-notmine/f`（形近名） | ❌（组件级匹配） |

**四条推论**：

1. **`--mac-write DIR` 等价于 `chmod -R` 的效果**，包括删除。给一个目录就等于给出其下所有内容的创建/修改/删除权。
2. **`WS/.git` carve-out 必须压在 `WS` 之后写**（后写赢），否则子树的 allow 会覆盖它——这正是 §7.3 模板把 `require-not` 嵌进同一条规则而非另起一行的原因。
3. **symlink 不会逃逸**：在 WS 内建 `ln -s /outside escape`，写 `WS/escape/x` 被 **拒**——内核按真实路径判定。读则放行（因读本就全开）。
4. **硬链接不可建**：在 WS 内 `ln /outside/secret WS/hard` 被拒（`Operation not permitted`）。若已存在（如预先建好），则可写——但建不了，风险有限。

因此 `--mac-write ~/.cargo` 这类用法是安全的（只影响缓存目录子树），而 `--mac-write ~` 等于把整个家目录交出去，**包括 `~/.ssh` 的写权**（读仍受凭据清单拦）。

### 6.3 `.git` carve-out：默认关闭（重要修正）

候选方案均建议默认保护 `.git` 只读。实测该默认**破坏正常开发**：

| 命令 | `.git` 只读时 |
|---|---|
| `git status` | ✅ |
| `git diff` | ✅ |
| `git add` | ❌ `Unable to create '.git/index.lock'` |
| `git commit` | ❌ 同上 |

Agent 的核心工作流包含提交，默认让 `git add` 失败会立即引发绕过沙箱的压力。**决定：`allow_git_write` 默认 `true`**（不 carve out），需要防 hook 篡改时显式 `--mac-no-git-write`。这与 Codex CLI 的默认相反，理由是我们的用户是 Agent 而 Codex 面向人类审阅。

> 注意：这与用户此前的「`.git` carve-out 实测可用」结论不冲突——语法可用（已复测 `require-all`+`require-not` 生效），但**默认值**应取可用性优先。

### 6.4 禁用 `prefix` 匹配符

`prefix` 是**字符串**前缀，会跨目录越权。实测 `subpath "/proj"` 正确拒绝 `/proj-backup`，而 `prefix "/proj"` **允许**写 `/proj-backup`。生成器只允许 `subpath` / `literal` 两种匹配符。

### 6.5 参数命名

`WS`、`TMP`、`W0..Wn`（`--mac-write`）、`D0..Dn`（deny read）。所有路径走 `-D`，**绝不拼进 SBPL 字符串**（防注入：路径含 `"`/`\`/换行会破坏 profile）。

引用未定义的 param → rc=65（实测），因此每个被引用的 param 必须定义——这一点由 golden test 保证。

## 7. 三种预设的完整模板

### 7.1 共用 floor

floor 分两块：**硬性地板**（任何模式都必含）与**系统地板**（仅 `MacReadMode::Only` 需要）。

#### 硬性地板（所有模式）

```
(version 1)
(deny default) | (allow default)   ; 按预设

; --- 进程 / ipc / sysctl ---
(allow process*)
(allow sysctl-read)
(allow mach-lookup)
(allow ipc-posix-sem)
(allow ipc-posix-shm)          ; ← 实测必需：缺它 git/cargo 报 ipc-posix-shm-read-data
(allow pseudo-tty)
(allow user-preference-read)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
(allow file-read-metadata)

; --- /dev 读：缺它 git 报 "could not open '/dev/null' for reading" ---
(allow file-read* (subpath "/dev"))

; --- 隐式写点：整族放通 ---
(allow file-write*
  (literal "/dev/null")
  (literal "/dev/tty")
  (literal "/dev/dtracehelper")
  (literal "/dev/stdout")
  (literal "/dev/stderr"))
(allow file-ioctl (literal "/dev/dtracehelper"))

; --- 读侧按模式 ---
(allow file-read*)                          ; MacReadMode::All
; 或（Only 模式）
(allow file-read* (literal "/"))            ; 防 abort(134)
(allow file-read* (subpath "<每个 --mac-read>"))
```

三个“实测必需”项都是后期调试出来的，掉进去的代价是工具莫名失败且错误信息不指向根因：

| 缺失 | 症状 |
|---|---|
| `file-read* (subpath "/dev")` | `git: could not open '/dev/null' for reading and writing` |
| `ipc-posix-shm` | `deny(1) ipc-posix-shm-read-data apple.shm.notification_center` |
| `file-ioctl /dev/dtracehelper` | 拒绝日志被 `deny(1) file-ioctl` 噪声污染，干扰归因 |

#### 系统地板（仅 `MacReadMode::Only`）

选 `Only` 时自动附带（用户不需手写）：

```
(allow file-read* (literal "/"))
(allow file-read* (subpath "/usr")) (subpath "/System") (subpath "/Library")
(allow file-read* (subpath "/private/var/db")) (subpath "/private/etc")
(allow file-read* (subpath "/bin")) (subpath "/sbin") (subpath "/var")
; 符号链接本身：/etc 与 /tmp 是链接，只放 /private/* 不生效
(allow file-read* (literal "/etc")) (literal "/tmp")
```

是否纳入 `$HOME` **不自动**——由用户用 `--mac-read ~` 显式决定（否则 `~/.gitconfig`、`~/.cargo` 不可读，`git`/`cargo` 会失败）。

### 7.2 ReadOnly


```
<floor>
(allow file-write* (subpath (param "TMP")))      ; tmp_writable 时
(deny file-read* (subpath (param "D0")))         ; 凭据，最后写
(deny file-read* (subpath (param "D1")))
...
```

参数：`TMP`、`D0..Dn`。无 workspace 写权限——`git init`、`cargo build`（写 `Cargo.lock`）、`cc -o` 到 workspace 均失败（实测），符合只读语义。

### 7.3 WorkspaceWrite

```
<floor>
(allow file-write*
  (subpath (param "WS"))
  (subpath (param "TMP"))
  (subpath (param "W0"))       ; --mac-write 追加项
  ...)
(deny file-read* (subpath (param "D0")))         ; 凭据，最后写
...
```

`allow_git_write = false` 时，`WS` 那条替换为：

```
(allow file-write*
  (require-all
    (subpath (param "WS"))
    (require-not (subpath (param "GIT"))))
  ...)
```

实测：`cargo build --offline` 在 WorkspaceWrite 下成功产出 `target/debug/...`；写 workspace 外被拒；`~/.ssh` 被拒。

### 7.4 FullAccess

```
(version 1)
(allow default)
```

网络为 `Deny` 时追加（后写赢，兜得住 `allow default`）：

```
(deny network*)
```

FullAccess 忽略 `deny_read` 与凭据清单——全放语义，不设半吊子状态。

## 8. 网络（与预设正交）

SBPL 支持端口级、IP 通配、unix-socket、inbound/outbound 分离；**硬拒域名与具体 IP**（`host must be * or localhost`）。

```
; Deny      → 不写任何规则（deny default 已覆盖）
; Loopback  →
(allow network-outbound (remote ip "localhost:*"))
(allow network-inbound  (local ip "localhost:*"))        ; 仅 inbound_loopback=true
(allow network-outbound (remote unix-socket (path "/private/var/run/mDNSResponder")))

; Ports(443) →
(allow network-outbound (remote ip "*:443"))
(allow network-outbound (remote unix-socket (path "/private/var/run/mDNSResponder")))

; All       →
(allow network*)
```

`Ports`/`Loopback` 恒定附带 mDNSResponder socket——漏掉时 `curl` 报 `Could not resolve host`（rc=6）。

实测正交性矩阵（全部符合预期）：

| 预设 | 网络 | https | http:80 |
|---|---|---|---|
| ReadOnly | Deny | 000 | 000 |
| ReadOnly | All | 200 | — |
| WorkspaceWrite | Ports(443) | 200 | **000** |
| FullAccess | (default) | 200 | 200 |

`NetAccess::Ports` 之外的域名需求 → `bail!("domain/IP allowlist is not expressible in Seatbelt")`，不做静默近似。

## 9. 施加期的两道安全闸门

§5 选 `sandbox-exec` 的理由是 fail-closed，但那个保证**只覆盖语法**。设计过程中实测出两类「profile 合法、策略却未生效」的情形，`sandbox-exec` 都不会报警：

1. **语义写错**：profile 语法完全正确，但规则写宽了（`deny default` 误写成 `allow default`，或写白名单路径算错导致覆盖面过大）。进程正常启动、命令正常执行、退出码正常——沙箱形同虚设。
2. **预开 fd 绕过**：策略对「新 open」生效，但对**已持有的 fd** 不生效。

这是沙箱工具最危险的失败模式：**看起来在工作，实际没工作**。两道闸门分别堵住这两类。

### 9.1 canary 预检（语义生效验证）

在施加真实命令**之前**，用**同一个 Plan** 跑一个「应当被拒」的探针：

```
1. 构造一个沙箱内不存在的写目标（如 $TMPDIR/.seabox-canary-<rand>）
2. 用同一 Plan 执行：sandbox-exec ... /bin/sh -c 'echo C > <canary>'
3. 若【成功写入】→ 策略未生效 → 立即 bail!（fail-closed）
4. 若被拒 → 策略生效 → 清理后执行真实命令
```

实测**两向对照均成立**：真策略下写 canary 被拒；`(allow default)` 下写 canary 成功——后者正是失效时应出现的信号。

**代价**：每沙箱 +1 次进程（~6ms）。因 `MacSandbox` 在构造期生成 `Plan`，canary 可与构造合并，**同一配置只跑一次**，可缓存。

**反过来推**：canary 的必要性也来自 `sandbox_init` 的教训——它在 4/4 坏 profile 下返回 -1 却让进程无沙箱运行（§5.1）。这说明「API 返回值」与「策略真的生效」是两件事，canary 是唯一能直接观测后者的手段。

**何时无法探（已实测两种替代方案）**：

canary 默认用「写 `$TMPDIR/.seabox-canary-*` 应被拒」作为探针，但它依赖 `tmp_writable`。当 `tmp_writable = Some(false)` 时按优先级降级：

| 优先级 | 探针形式 | 适用 | 实测结果 |
|---|---|---|---|
| 1 | 写 `$TMPDIR/.seabox-canary-<rand>`，期望被拒 | `tmp_writable != Some(false)` | ✅ 真策略下拒，`allow default` 下成功 |
| 2 | 读一个已由 `deny_read`/凭据清单封禁的路径，期望被拒 | 存在至少一条 read-deny | ✅ 真策略下 `Operation not permitted`；无 deny 的 profile 下成功（两向可区分） |
| 3 | 若两者都不可用（无写权且无 deny），**跳过并记录警告** | 极端配置 | — |

优先级 2 的关键实测：探针目标需要用 **realpath**（`/tmp` → `/private/tmp`），否则 deny 规则永远不匹配而探针会假阳性失败（实测踩到）。

优先级 3 的降级必须**显式警告**而不是静默，否则用户会以为 canary 在保护。

### 9.2 fd 卫生（预开 fd 会绕过文件策略）

Seatbelt 的安全语义是 **fd 快照**：策略施加前已打开的 fd **不受约束**。实测逃逸：

```
父 shell: exec 9>/tmp/sbxp/host_fd.txt        # 策略前 open
         exec sandbox-exec -f nofd.sb /bin/sh -c 'echo PWNED >&9'
结果: host_fd.txt = [PWNED]                   # 写入成功，完全绕过沙箱
```

同一 profile 下，沙箱内**新** open 同一路径被拒（`Operation not permitted`）——差别只在 fd 是否已存在。且跨 exec 同样成立（`exec 3>hostfile` → `echo >&3` 成功），因此「`sandbox-exec` 是原地 exec」这个优点不能自动消解该问题。

**缓解**：`pre_exec` 中关闭所有非显式保留的 fd。

- `StdioConfig::Inherit` → 保留 0/1/2
- `StdioConfig::Piped` → 保留 0/1/2
- `StdioConfig::Fd{n}` → 保留 0/1/2 与 n

保留集合**在 fork 前算好**，传给 `pre_exec` 后只做最小工作——**零堆分配**，满足 ADR 0003。

#### 清扫方案：`/dev/fd` 枚举（已实测，非 `close_range`）

**关键事实：macOS 没有 `close_range`。** 它是 Linux 5.9+ 的 syscall，macOS 从未提供（`unistd.h` 中也无 `closefrom`）。实测编译：

```
error: call to undeclared function 'close_range'; ISO C99 and later
       do not support implicit function declarations
```

因此必须选一条 macOS 可用的路径。三种方案实测对比（macOS 27.0.1 / arm64）：

| 方案 | 耗时 | 可行性 |
|---|---|---|
| `close(3.._SC_OPEN_MAX)` | **~14.5 ms** | ❌ 太慢（`_SC_OPEN_MAX` = 1048575） |
| `fcntl(F_GETFD)` 探测到 `getdtablesize()` | ~11.5 ms | ❌ 太慢（`getdtablesize()` = 92160） |
| **`/dev/fd` 枚举** | **~0.026 ms** | ✅ **采纳** |

`/dev/fd` 枚举快 500 倍，因为它只看真实存在的 fd（典型进程 3~10 个），而前两者要遍历 9 万~100 万个空槽。

实测五组，两个信息：

| 观察 | 结论 |
|---|---|
| 不清扫 → 逃逸成功（`host=[PWNED]`） | 验证了漏洞真实存在 |
| 枚举 + 清扫 → `host=[ORIGINAL]`，sh 报 `3: Bad file descriptor` | **逃逸被堵**，且证明 fd 确实在 exec 前被关 |
| `/dev/fd` 里同时看得到 CLOEXEC 与非 CLOEXEC 的 fd | 不能只看目录，必须看 `FD_CLOEXEC` |
| 枚举 200 次均 ~0.026 ms | 开销可忽略，不吃 +6ms 预算 |

#### 只关非 CLOEXEC 的 fd

`FD_CLOEXEC` 的 fd 会在 `exec` 时被内核**自动**关闭，无需扫。不过滤的后果不止是多做无用功——它会关掉在 fork 与 exec **之间**新开且合法持有的 fd（例如 canary 路径上的临时 fd）。

因为 Rust 的 `File`/`TcpStream` 默认是 CLOEXEC，**真正需要担心的是从外部继承的 fd**（shell 的 `exec 9>host`、或 `StdioConfig::Fd` 显式传来但未声明要保留的）——恰好就是威胁模型里那一条。

#### 实现结构

```rust
// fork 前（不受零堆约束）：枚举 + 过滤，得到 stable 列表
fn collect_leaky_fds(keep: &[i32]) -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/dev/fd") else { return out };
    for e in rd.flatten() {
        let Some(n) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok())
            else { continue };
        if n <= 2 || keep.contains(&n) { continue }
        let flags = unsafe { libc::fcntl(n, libc::F_GETFD) };
        if flags == -1 || flags & libc::FD_CLOEXEC != 0 { continue }
        out.push(n);
    }
    out.sort_unstable();
    out
}

// fork 后（零堆）：只遍历预分配好的列表
unsafe {
    cmd.pre_exec(move || {
        for &f in &leaky_fds { libc::close(f); }
        Ok(())
    });
}
```

关键：`Vec` 在 fork **前**就建好，`pre_exec` 闭包只捕获它（move），循环中**无任何分配**。若需严格避免迭代器的 `Iterator` 开销，可存为 `Box<[i32]>` 并拿 `as_ptr` + `len` 手写循环（非必需）。

#### 取舍与已知不足

- 目录 fd + `openat` **无法**绕过（实测 DENIED），因此只需覆盖普通文件 fd，不必额外处理目录 fd。
- 这与 Linux 侧行为**不一致**：Landlock 约束的是 inode 权限，已打开的 fd 同样不受限——两边都有此边界，但 macOS 上用户更容易持有宿主 fd（`Inherit` 模式下继承终端 fd）。需在文档中写明。
- 清扫会关闭用户期望继承的 fd。这是**故意的**——继承未声明 fd 本身就是安全漏洞。需在 `StdioConfig` 文档中写明「只有显式声明的 fd 会被传递」。
- **残余风险**：`/dev/fd` 枚举与 `pre_exec` 之间，若其他线程打开了新的非 CLOEXEC fd，它不在列表里。`pre_exec` 运行于 fork 后的子进程，其他线程已不存在，但**父进程的其他线程**在 fork 后仍可继续开 fd——而子进程继承的是 fork 时刻的快照，后续父进程新开的 fd 不会传给子进程。所以实际上无竞态。

**被否决的做法**：

- **`close_range`**：macOS 不存在（已实测编译失败）。
- **`close(3..getdtablesize())`**：可用但 ~14.5 ms，直接吃掉全预算。
- **不设 canary，只信 `sandbox-exec` 的 rc**：无法覆盖语义错误，与 fail-closed 目标不符（fail-closed 应覆盖「策略没生效」，不只是「profile 解析失败」）。
- **只在文档里警告 fd 风险**：fd 继承是默认行为（`Inherit` 模式下终端 fd 天然被继承），要求用户自己注意等同没有防护。
- **对 fd 做白名单式放行而非默认清扫**：等价于反向默认，需要枚举「所有合法 fd」，与 §4 否定的「宽白名单」思路同样不可封闭。

两道闸门相互**独立**：任一道失效，另一道仍提供部分保护。

## 10. 拒绝归因

macOS 无结构化拒绝通道，采用三级判据：

| 判据 | 精度 | 实现 |
|---|---|---|
| stderr 含 `Operation not permitted` | Probable | 必做 |
| `log show --last 15s --predicate 'sender == "Sandbox"'` | **Certain**（含 `deny(1) file-write-create /path`） | 可选（`--trace-denies`） |
| exit 134 (SIGABRT) | Guess | 白名单过窄的启发式 |

### 10.1 接口契约（关键：现有签名容不下 stderr）

现有 `SandboxImpl::classify_exit` 签名（`src/lib.rs:546`）只拿得到退出码：

```rust
fn classify_exit(&self, exit_code: i32, blocked: Option<(u32, u32)>) -> ExitReason;
```

但**拒绝不会可靠传播为 exit code**（实测）：

```
sh -c 'echo x > denied_path'                     → rc=1
sh -c 'echo x > denied_path 2>/dev/null; exit 0' → rc=0   ← 拒绝被吞掉
```

因此必须扫 stderr，而 stderr 只在 `execute` 路径上可得。§9 之前的设计说「`MacSandbox` override `execute()`」，但这**不够**——外层 `Sandbox::execute` 会再调一次 `classify_exit`：

```rust
// src/lib.rs（现有）
pub fn execute(&self, spec: &CommandSpec) -> anyhow::Result<(CommandOutput, ExitReason)> {
    let output = self.inner.execute(spec)?;
    let mut reason = self.inner.classify_exit(output.exit_code, output.blocked_syscall);
    if output.timed_out { reason = ExitReason::InternalError(...); }
    Ok((output, reason))
}
```

`MacSandbox::execute` 内部算出 `Denied` 后，会被外层这次调用**覆盖**。

**采用方案：给 trait 加一个带默认实现的新方法。**

```rust
// src/lib.rs，SandboxImpl trait 内新增
trait SandboxImpl: Send + Sync {
    // ... 既有 spawn / execute / classify_exit 不动 ...

    /// 带完整输出的分类。默认委托 `classify_exit`，
    /// 需要 stderr 判据的平台（macOS）override 它。
    fn classify_output(&self, output: &CommandOutput) -> ExitReason {
        self.classify_exit(output.exit_code, output.blocked_syscall)
    }
}

// Sandbox::execute 改一行：改用 classify_output
let mut reason = self.inner.classify_output(&output);
```

为什么选这个方案（而非扩 `classify_exit` 签名）：

| 方案 | 影响 |
|---|---|
| 扩 `classify_exit(code, blocked, stderr)` | 改 Linux 实现 + 所有测试调用点，与「Linux 零改动」冲突 |
| 在 `Sandbox::execute` 里为 `Denied` 加短路 | 把平台差异泄漏进公共层 |
| **新增 `classify_output`（默认委托）** | **Linux 实现零改动**；macOS 只需 override 这一个方法 |

注意：`Sandbox::execute` 也不能无条件用 `classify_output` 覆盖 `timed_out`。超时优先于归因——超时的命令可能恰好写了 stderr，那不是策略拒绝。

### 10.2 退出码判据（65 的歧义要处理）

| 条件 | 结果 |
|---|---|
| `exit_code == 65` **且 stderr 含 `sandbox-exec:`** | `InternalError`：SBPL profile 被拒（我们自己的 bug） |
| `exit_code == 65`（无上述 stderr） | `Program(65)`：目标程序自己返回 65 |
| `exit_code == 134` | `Denied { Seatbelt, "aborted under policy; read whitelist may be too narrow" }` |
| stderr 含 `Operation not permitted` | `Denied { Seatbelt, .. }` |
| `0` | `Ok` |
| 其它 | `Program(code)` |

`65` 是 `EX_DATAERR`，目标程序自己也可能返回它。仅凭退出码断言「这是 seabox 的 bug」会误报，所以必须用 stderr 前缀区分。`134`（SIGABRT）同理有歧义，但归为 `Denied` 并在 message 里标「可能」是更安全的默认——宁可误报拒绝，不可误报成功。

`spawn(StdioConfig::Inherit)` 路径拿不到 stderr，退化为仅退出码判据（即上表第二行生效，65 一律算 `Program`）。这是已知的能力降级，需在 `execute` 文档里写明。

`log show` 归因已实测可行：非 root（uid 501）可读，`--last 15s` 扫描耗时 0.66s，输出精确到 `deny(1) file-write-create /private/tmp/.../deny_me.txt`。但**必须过滤噪声**——未放 `/dev/dtracehelper` 的 ioctl 时日志混入 `deny(1) file-ioctl path:/dev/dtracehelper`，故 §7.1 floor 补上了 `file-ioctl`。日志按**进程名**（`sh(52233)`）而非 pid 区分，同名进程并发时归因会混淆，故精度标 `Certain` 仅在单进程场景成立。

**触发时机与降级**（本院轮定）：`--trace-denies` 是显式 flag，不在每条命令后自动跑（0.66s 不可忽略）。检测到多个同名进程并发时，降级为 Probable 并在输出里标注「进程名冲突，归因可能不准」。

## 11. 测试策略

### 11.1 分层与文件落位

现有 **12 个**测试文件全部是 Linux 后端，macOS 新增**四类**测试位置，按「是否能脱离 macOS 运行」切分：

| 位置 | 平台 | 内容 | 为何放这里 |
|---|---|---|---|
| `src/macos/sbpl.rs` 内联 `#[cfg(test)]`（结构） | **全平台** | 段序断言 + 注入拒绝 + 参数化 + 禁 `prefix` | 纯函数，无文件系统依赖，Linux CI 每 PR 都跑 |
| `src/macos/mod.rs` 内联 `#[cfg(test)]` | **全平台** | `resolve()` / `is_configured()` / 双向硬错误 / `classify_output` | 纯逻辑，同上 |
| `tests/macos_config_test.rs` | **全平台** | CLI flag → `MacOsConfig` 映射、`with_*` 对应性 | 不 spawn 进程，与 `tests/config_test.rs` 同级 |
| `src/macos/sbpl.rs` 内联（快照） | **macOS only** | golden 全量文本 | 依赖 `canonicalize` |
| `tests/macos_test.rs` | **macOS**（`#![cfg(target_os = "macos")]`） | 端到端、网络、闸门 | 需真 `sandbox-exec` |

> **Linux CI 覆盖面**：前三行合起来覆盖 `resolve()` + `is_configured()` + 生成器全部**逻辑分支**，即 §3 承诺的「~70% 代码可脱平台测试」。生成器唯一的平台差异是 `norm()` 的 `canonicalize` 结果，那部分由 macOS 快照兜住。
>
> 注：`classify_output`（清单 G 组）是 `MacOsConfig` 无关的纯字符串判断，放 `src/macos/mod.rs` 单测即可全平台覆盖。

### 11.2 段序断言 vs 文本快照（关键拆分）

§3 声称 `sbpl.rs` 无 `cfg` 门控、能在 Linux CI 跑 golden test——但 §6.2 又要求 `norm()` 必须 `fs::canonicalize`。两者冲突：`/var` `/etc` `/tmp` 的 symlink 结构在 Linux 与 macOS 上不同，`canonicalize` 输出不一致。

| 测试 | 依赖 | 平台 | 强度 |
|---|---|---|---|
| **段序断言**：`deny default` 行号 < floor < write 白名单 < deny_read < network | 纯字符串位置 | ✅ 全平台 | **这才是安全防线** |
| 全量文本快照 | `canonicalize` | macOS only | 捕捉意图外的变化 |

段序断言不依赖路径解析，因此能完整留在 Linux CI。§6.1 的「顺序敏感」风险由此有真正的 CI 保护：改段落顺序的 PR 会在 Linux CI 上变红。

```rust
/// 段序断言模板：不比对文本，只比对相对位置
fn assert_section_order(sbpl: &str) {
    let pos = |needle: &str| sbpl.find(needle)
        .unwrap_or_else(|| panic!("missing section: {needle}"));
    let order = [
        "(deny default)",
        "(allow file-read-metadata)",     // floor 起点
        "(param \"WS\")",                 // write 白名单段
        "(param \"D0\")",                 // 凭据 deny 段
        "(allow network",                 // 网络段
    ];
    let positions: Vec<usize> = order.iter().map(|n| pos(n)).collect();
    for w in positions.windows(2) {
        assert!(w[0] < w[1], "section out of order: {order:?} => {positions:?}");
    }
}
```

### 11.3 功能测试全清单

#### A. 纯函数层（全平台，Linux CI 必须全跑）

| # | 测试 | 断言 |
|---|---|---|
| A1 | `is_configured()` 逐字段 | 9 个字段各自单独设置 ⇒ 全为 `true` |
| A2 | **`--mac-net deny` ≠ 未配置** | 显式 Deny 必须 `is_configured()==true`（防 `PartialEq` 陷阱回归，见 §4.2） |
| A3 | 无预设 + 无字段 | `is_configured()==false` ⇒ 不进 `sandbox-exec` |
| A4 | 预设 + `Some(false)` 覆盖 | ReadOnly + `tmp_writable=Some(false)` ⇒ TMPDIR 不可写 |
| A5 | 预设 + 无字段 | 结果 == 预设 `defaults()` |
| A6 | **`Vec` 追加而非覆盖** | 用户 `deny_read` 不冲掉内置凭据清单 |
| A7 | `--mac-read` 模式切换 | 出现即 `Only`；`--mac-read-all` 回 `All` |
| A8 | FullAccess + 显式 `deny_read` | 内置清单关，用户显式 deny 仍生效 |
| A9 | 三种使用方式 | 纯预设 / 纯字段 / 预设+字段，均不 panic |
| A10 | `resolve()` 幂等 | 连调两次结果相同 |

#### B. SBPL 生成器——结构（全平台）

| # | 测试 | 平台 |
|---|---|---|
| B1 | **段序断言**，3 预设 × 4 网络 = 12 例 | 全平台 |
| B2 | **注入拒绝**：路径含 `"` `)` `;` `\n` ⇒ `bail!` | 全平台 |
| B3 | **`prefix` 匹配符禁用**：生成结果不含 `(prefix` | 全平台 |
| B4 | 参数化：输出含 `(param "WS")`，不含内联绝对路径 | 全平台 |
| B5 | 空 `write` ⇒ 不产生 `(subpath "")` | 全平台 |
| B6 | `.git` carve-out 开/关规则差异 | 全平台 |
| B7 | `tmp_writable=false` ⇒ 无不含 `TMPDIR` 字样的写规则 | 全平台 |
| B8 | 凭据清单：`no_credential_deny=true` ⇒ 无 `D0..Dn` 段 | 全平台 |

#### C. SBPL 生成器——平台相关（macOS only）

| # | 测试 |
|---|---|
| C1 | 路径规范化 `/var`→`/private/var`、`/tmp`→`/private/tmp`、`/etc`→`/private/etc` |
| C2 | golden 全量文本快照（三预设 × 网络组合） |

#### D. 端到端文件系统（macOS）

| # | 测试 | 期望 |
|---|---|---|
| D1 | ReadOnly：读通过 / TMPDIR 写通过 / workspace 写拒绝 | rc≠0 |
| D2 | WorkspaceWrite：workspace 写通过 / `$HOME/Documents` 拒绝 | 同上 |
| D3 | FullAccess：任意写通过 | rc=0 |
| D4 | **凭据读拒绝**（3 预设 × `~/.ssh/id_rsa` 等） | `Operation not permitted` |
| D5 | **凭据写拒绝**（`~/.ssh/authorized_keys`） | 同上；与 D4 成对，缺它后门可绕过 |
| D6 | `--mac-write` 自定义根生效，表外拒绝 | — |
| D7 | `MacReadMode::Only`：白名单外拒绝 | 真读隔离 |
| D8 | `Only` 系统地板可读（`/usr/lib` `/System` `/dev` `/etc`） | 早期 bug 回归 |
| D9 | `.git` carve-out：`--mac-no-git-write` 下 `git add` 失败于 `index.lock` | — |
| D10 | 删除权：subpath 内 `rm` 成功 | 递归含删除语义（§6.2b） |
| D11 | workspace == `$HOME` ⇒ stderr 告警 | — |

#### E. 网络（macOS，与预设正交）

| # | 测试 |
|---|---|
| E1 | 正交矩阵 3 预设 × {Deny, Loopback, Ports(443), All} |
| E2 | Loopback：`localhost:PORT` 通 / 外网 `000` |
| E3 | `Ports(443)`：https 200 / `http:80` `000`（后写赢的直接证据） |
| E4 | **mDNSResponder socket 缺失 ⇒ DNS 失败**（`curl` rc=6 回归） |
| E5 | 域名 allowlist ⇒ `bail!("not expressible in Seatbelt")`，不静默近似 |

#### F. 安全闸门（macOS）

| # | 测试 | 期望 |
|---|---|---|
| F1 | **fd 逃逸回归**：父开 host fd，子 `echo >&3` | 拒绝（`Bad file descriptor`），宿主文件不变 |
| F2 | CLOEXEC fd 不被误关 | 子命令正常使用自己的 fd |
| F3 | fd 清扫耗时 < 1 ms | 性能守卫，防退回 `close()` 循环（§9.2） |
| F4 | canary 正常策略 ⇒ 通过 | — |
| F5 | **canary 坏策略**（`allow default`）⇒ 报错且命令不执行 | 语义失效检测 |
| F6 | `tmp_writable=false` ⇒ 走读探针路径 | 降级链一条（§9.1） |
| F7 | 两种探针都不可用 ⇒ 显式警告但执行 | 不得静默 |
| F8 | **`sandbox-exec` 不存在** ⇒ `bail!`，不降级为无沙箱 | §13.2 风险 3b |

#### G. 拒绝归因（`classify_output`，全平台可测）

| # | 输入 | 期望 |
|---|---|---|
| G1 | stderr 含 `sandbox-exec: … Operation not permitted` | `Denied` |
| G2 | rc=65 + stderr 含 `sandbox-exec:` | `InternalError` |
| G3 | rc=65 **无** stderr 判据 | `Program(65)` |
| G4 | rc=134 | `Denied`（标「可能」） |
| G5 | **拒绝但 rc=0**（`2>/dev/null; exit 0`） | 仍 `Denied`——此例解释 `classify_output` 为何存在（§10.1） |
| G6 | 超时覆盖拒绝 | `TimedOut` 优先 |
| G7 | Linux 实现走默认委托 ⇒ 行为与基线一致 | 零改动验证 |

> G1-G6 只喂构造的 `CommandOutput`，不 spawn 进程，故全平台可测。

#### H. 集成与平台边界

| # | 测试 |
|---|---|
| H1 | macOS 上 `--landlock` ⇒ 硬错误 |
| H2 | Linux 上 `--mac-*` ⇒ 硬错误 |
| H3 | 错误消息含对应 `--mac-*` 建议 |
| H4 | `seabox check` macOS 输出三态（含 `MacReadMode` 双模式、setuid 告警） |
| H5 | `spawn()` business-pid = 实际工作进程；`try_wait`/`wait` 幂等 |
| H6 | 超时杀整个进程组（含 `sandbox-exec` 与子进程） |
| H7 | **Linux CI：`cargo build` 通过**（`src/macos/` 无 `cfg` 门控） |
| H8 | 能力缺失 auto-skip（打印 skipping，非 fail） |
| H9 | **Linux 221 基线不变** |

### 11.4 优先级与规模

| 优先级 | 测试 | 理由 |
|---|---|---|
| **P0（必做，22 例）** | A1-A8、B1-B3、D4、D5、F1、F5、G5、H1-H3、H7-H9 | 每条都对应一个已识别的 P0 或安全边界 |
| P1（同期，26 例） | A9-A10、B4-B8、C1、D1-D3、D7、D8、E1-E3、F2-F4、G1-G4、H4-H6 | 功能正确性主干 |
| P2（可后补，12 例） | C2、D6、D9-D11、E4、E5、F6-F8、G6、G7 | 边界与诊断 |

合计 **60 个测试**（逐条列名可对账，无重复无遗漏）。

> 若含 golden 快照的 12 个参数化展开（B1 的 3×4）与 E1 的矩阵（12 例），实际执行用例数约 **100+**；上表按**测试函数**计数。

### 11.5 用 review 的 P0 反查覆盖

| review P0 | 能抓住它的测试 | 说明 |
|---|---|---|
| P0-1 `close_range` 在 macOS 不存在 | H7 编译 + F3 性能守卫 | 编译失败最直接；F3 防后续退回慢实现 |
| P0-2 `SandboxConfig` 加字段破窗 | H7 | 加字段后 `src/cli.rs:596` 字面量构造直接编译失败 |
| P0-3 `classify_exit` 拿不到 stderr | G5 | rc=0 仍判 `Denied` 是唯一能暴露该缺陷的用例 |
| P0-4 `bool` 表达不了「预设+显式关」 | A4 + A2 | A4 覆盖显式关；A2 覆盖「默认值恰等于未配置」的静默失效 |

> 这张表是设计自检：**若某条 P0 找不到能抓住它的测试，说明该修复是纸面的**。

### 11.6 通用约定

- 能力缺失时**自动 skip**（`eprintln!("... skipping test")`），与现有 12 个文件一致，不是 fail。
- 真机探针用 `OnceLock` 缓存，整个 session 只跑一次。
- **不写宿主**：所有写入落 tempdir 或 `/tmp` 子目录，测试后清理（复用 `tests/landlock_test.rs` 的 `unique_path` / `cleanup_path` 模式）。
- **不联网**：网络用例只打 `localhost`，或直接断言 `000`；DNS 回归用可控 hostname。
- 每个「应被拒绝」的用例都必须同时有一个「应被允许」的对照组，否则无法区分「策略生效」与「命令本来就失败」。这条是现有 `landlock_test.rs` 已经在用的模式。

## 12. `seabox check` 的 macOS 输出

`check_capabilities()` 当前是固定表格（`src/lib.rs:189`）。macOS 分支需输出三层信息：**能力矩阵**、**硬限制**、**当前平台面差异**。

### 12.1 目标输出

```
$ seabox check

Capability                    Status
----------------------------- ------------------------------
Seatbelt (sandbox-exec)       available (/usr/bin/sandbox-exec)
macOS version                 27.0.1 (Darwin 27.0.0)
mDNSResponder socket          available (/private/var/run/mDNSResponder)
sandbox_init                  available (deprecated, fail-open: not used)

Not supported on macOS
----------------------------- ------------------------------
syscall filtering             no equivalent (--seccomp-* will error)
namespace isolation           no equivalent (--unshare-* will error)
mount operations              no equivalent (--bind/--tmpfs will error)
capabilities                  no equivalent (--cap-* will error)
Landlock ACL                  use --mac-preset / --mac-read instead
file read isolation           MacReadMode::All (default) | Only(paths) — see below
network domain allowlist      syntax-level rejection; ports/unix-sockets only

Seatbelt hard limits (not bypassable by any profile)
----------------------------- ------------------------------
setuid binaries               BLOCKED (ps, top, su, atq, crontab, newgrp)
write to SIP paths            BLOCKED (/etc, /System, ...)

Presets
----------------------------- ------------------------------
(no --mac-preset)             no sandbox applied (unless --mac-* fields given)
read-only                     read all; write TMPDIR only
workspace-write               read all; write workspace + TMPDIR
full-access                   unrestricted (except the hard limits above)

Read isolation
----------------------------- ------------------------------
(all forms above)             MacReadMode::All — reads global, credential denylist only
--mac-read <path>             MacReadMode::Only — real isolation; system floor auto-added
tunables                      --mac-write / --mac-deny-write / --mac-deny-read
                              --mac-no-git-write / --mac-no-tmp-writable / --mac-no-credential-deny
```

> 输出必须让用户看出**当前是哪种读模式**——这是本后端最容易产生安全错觉的地方（预设默认零读隔离）。

### 12.2 为何 setuid 必须单独列出

这是最容易让用户迷惑的一条：**即使 `full-access` 也不是真“全放通”**。

实测：`(allow default)` 下 `ps` `top` `su` `atq` `crontab` `newgrp` **5/5 全部被拒**，而 `whoami` `cat` `true` 等非 setuid 程序全部正常。错误形态：

```
sandbox-exec: execvp() of '/usr/bin/atq' failed: Operation not permitted
```

且**任何 SBPL 规则都无法放通**（实测加了 `(allow process*)` / `(allow process-exec)` / `(allow mach*)` / `(allow file-read*)` 均无效）——它是 `sandbox-exec` 自身的硬限制。

**实际影响**：Agent 用 `ps aux` 排查进程、`top` 看负载、`crontab` 查询定时任务时，会得到 `Operation not permitted` 而非“命令不存在”，极易误判为沙箱策略写错而浪费时间。

因此 `check` 必须显式列出这条，并建议替代方案（如用 `sysctl` 或 `/proc` 等价的 `proc_pidlistpids` 需 root，故实际只建议 Agent 避开这类工具）。

### 12.3 实现要点

- 复用现有 `format!` 固定宽度表格风格，保持与 Linux 输出视觉一致。
- 探测项应为**运行时检测**而非硬编码：`Path::new("/usr/bin/sandbox-exec").exists()`、`std::process::Command::new("/usr/bin/sw_vers").arg("-productVersion")`、`Path::new("/private/var/run/mDNSResponder").exists()`。
- `setuid` 行可加**运行时验证**：尝试执行 `/usr/bin/atq`（无副作用、无参数情退 0），失败则输出 BLOCKED。这样即使未来 macOS 放开该限制，输出也会自动跟上。
- `--json` 输出作为后续项（§14），但字段名建议现在就定：`setuid_blocked: bool`、`pending_preset: Option<String>`。

## 13. 风险与代价

### 13.1 已在本轮解决的（曾为阻塞项）

| 原风险 | 结论 |
|---|---|
| `close_range` 在 macOS 不存在，`close()` 循环吃光预算 | ✅ 改 `/dev/fd` 枚举（~0.026ms），已实测逃逸被堵（§9.2） |
| `SandboxConfig` 加字段是破坏性变更 | ✅ 已改正表述，建议同时加 `#[non_exhaustive]`（§4.1） |
| `classify_exit` 拿不到 stderr | ✅ 新增 `classify_output`（默认委托），Linux 零改动（§10.1） |
| `bool` 无法表达「预设 + 显式关」 | ✅ 改 `Option<bool>` / `Option<MacReadMode>`（§4.1） |
| canary 在 `tmp_writable=false` 时无可用探针 | ✅ 三优先级降级，读探针已实测可行（§9.1） |
| golden test 与 `canonicalize` 冲突 | ✅ 拆「段序断言（全平台）」+「快照（macOS）」（§11） |
| **macOS 上无法编译**（`landlock` 为无条件依赖） | ✅ 实测：改 target 依赖 + 12 个测试文件 `#![cfg]` + `syscall_probe` 分支 `main`，`cargo build --lib --bins --tests` 全通（§3.1） |
| `syscall_probe` 文件级 `#![cfg]` 导致 `main` 缺失 | ✅ 实测 E0601，改为统一 `main` + `linux_main()` 分支（§3.1） |

### 13.2 残余风险

| # | 风险 | 缓解 |
|---|---|---|
| 1 | **读侧零隔离（预设默认 `All`）**：凭据保护是黑名单，漏一个即泄漏；`--mac-write` 可反向放通 | `check`/README 写死；golden test 锁死清单；需真隔离时用 `MacReadMode::Only` |
| 2 | **顺序敏感**：一次「调换两行」静默放开策略 | 生成器固定顺序 + **全平台**段序断言测试（§11） |
| 3 | **`sandbox-exec` 被废弃**：Apple 迟早移除 | 施加收敛为 `build() + 一行 Command`；`check` 探测存在性；换 `sandbox_init` 约 40 行（需先在 fork 前 `CString` 化） |
| 3b | **`sandbox-exec` 运行时消失**（更新后移除） | `spawn` 时硬错误 `bail!`，**绝不静默降级为无沙箱**（重蹈 `sandbox_init` fail-open 覆车） |
| 4 | 归因弱于 Linux（无 `(nr, arch)`） | `DenyMechanism::Seatbelt` + 精度分级（Probable/Certain）；`--trace-denies` 显式触发 |
| 5 | 65/134 与目标程序自身退出码歧义 | 65 需 stderr 含 `sandbox-exec:` 才判 `InternalError`，否则 `Program(65)`；134 归 `Denied` 但标「可能」 |
| 5b | **setuid 程序不可用**（`ps`/`top`/`su`/`crontab`…），任何 profile 都无法放通 | `check` 单列（§12）；`execute()` 检测 `execvp() failed: Operation not permitted` 时提示可能是 setuid 限制 |
| 6 | 双配置面心智负担（`--landlock` 在 macOS 报错） | `check` 输出平台可用面；错误消息给出对应 `--mac-*` 建议（需定稿文案） |
| 7 | `FullAccess` + `deny network*` 依赖后写赢 | 独立 golden 用例锁死顺序 |
| 8 | **预开 fd 绕过策略** | `pre_exec` fd 清扫（§9.2），保留集合 fork 前算好 |
| 9 | **语义失效静默通过** | canary 预检（§9.1），每配置一次；无可探时显式警告 |
| 10 | 无 CI 覆盖 macOS | 生成器纯函数化 + 段序断言全平台可测（覆盖 ~70% 逻辑）+ 每版手工冒烟 |
| 11 | `NetAccess` 与 `NetworkConfig` 的 loopback 概念重叠 | 文档加 Linux/macOS 网络语义对照表 |

**实现量估算**：`sbpl.rs` ~280 行、`mod.rs` ~380 行（含 canary + fd 清扫）、校验 + CLI ~150 行、测试 ~350 行（对应 §11.3 的 60 个测试函数），合计 **~1160 行**；加上 `Cargo.toml` 一条 target 依赖与 **12 个**测试文件的 `#![cfg]`。**Linux 行为零变化**（221 测试基线不动）。

> §3.1 的编译前提已验证：三处 `cfg` 改完后 macOS 上 `cargo build --lib --bins --tests` 全通。

## 14. 后续（不在本轮）

- `sandbox_init` 双通道（若 `sandbox-exec` 消失）
- 代理式域名过滤：Seatbelt 只放通到 localhost 代理端口，外部代理做域名判断（业界两家的共同做法）。接口预留 `NetAccess::ViaProxy`，不实现
- `PolicyReport` 结构化输出（`check --json`）

## 附录 A：决策记录

本设计四个关键技术决策及其理由摘要。完整的实测过程已收入上文对应章节，此处只保留结论与依据线索。

### A.1 用 `sandbox-exec` 而非 `sandbox_init`

**决策**：外部进程 `sandbox-exec` 作为唯一施加机制。
**决定因**：**失败语义**。坏 profile 下 `sandbox_init()` fail-open（rc=-1 但进程无沙箱、宿主可写，4/4 实测），`sandbox-exec` fail-closed（rc=65，命令不执行）。沙箱工具最不可接受的失败模式就是失败开放。
**代价**：+6ms/次；依赖外部二进制存在。
**回退**：若 Apple 移除，换 `sandbox_init` 约 40 行（需 fork 前 `CString` 化，满足 ADR 0003），且必须硬检查返回码。
详见 §5。

### A.2 文件系统策略：读双模式 + 写白名单 + 凭据黑名单

**决策**：读侧提供 `All`（预设默认）与 `Only([roots])` 两种模式；写侧永远白名单；凭据清单永远黑名单且**同时封读与写**。
**理由**：写侧是主要破坏面（Agent 会写坏文件、写凭据目录），读泄漏需外传而网络默认关。`Only` 技术可行（早期「不可行」结论已推翻），但需枚举系统地板、失败模式恶劣，故不做预设默认。
**业界对照**：Anthropic sandbox-runtime 与 OpenAI Codex CLI 均收敛到「读宽写窄 + `denyRead` 补偿」。
详见 §4.2 / §4.3 / §4.4。

### A.3 规则顺序即安全边界

**决策**：生成器固定段落顺序；golden test 断言相对顺序；用户无法控制输出顺序。
**理由**：实测**后写赢**，与 specificity、与 allow/deny 均无关。同一对规则交换顺序结果就反转——因此「顺手调换两行」能静默放开策略且无任何警告。
**副产品**：三段式策略（全局放通 → 定点拒绝 → 精细放回）成为可能，`FullAccess` + `deny network*` 也依赖它。
详见 §6.1。

### A.4 两道施加期闸门

**决策**：canary 预检 + `pre_exec` fd 清扫。
**理由**：`sandbox-exec` 的 fail-closed 只覆盖**语法**，不覆盖语义。两类实测失效：① profile 合法但规则写宽了（形同虚设）；② 预开 fd 不受策略约束（`exec 9>host` → `echo >&9` 写入成功）。
**代价**：canary +6ms（同配置只跑一次可缓存）；fd 清扫会关闭用户未声明的 fd（故意的）。
详见 §9。

### A.5 fd 清扫用 `/dev/fd` 枚举（review 后修正）

**决策**：fork 前枚举 `/dev/fd` + 过捤 `FD_CLOEXEC`，得到精确的 leaky-fd 列表；`pre_exec` 只遍历这个列表。
**决定因**：**macOS 没有 `close_range`**（Linux 5.9+ syscall，编译实测失败）。备选方案实测对比：`close(3.._SC_OPEN_MAX)` = 14.5ms、`fcntl` 探测到 `getdtablesize()` = 11.5ms、**`/dev/fd` 枚举 = 0.026ms**。前两者直接吃光全预算。
**验证**：不清扫时 `host=[PWNED]`（逃逸成功）；清扫后 `host=[ORIGINAL]` 且 sh 报 `3: Bad file descriptor`。
**为何过捤 CLOEXEC**：CLOEXEC 的 fd 会在 exec 时被内核自动关；不过捤会误关 fork~exec 之间新开的合法 fd。Rust 的 `File`/`TcpStream` 默认 CLOEXEC，真正需要担心的是从外部继承的 fd。
详见 §9.2。

### A.6 三个开关用 `Option<bool>`（review 后修正）

**决策**：`tmp_writable` / `allow_git_write` / `no_credential_deny` 用 `Option<bool>`，`read` 用 `Option<MacReadMode>`。
**理由**：`bool` 区分不了「未设置」与「显式 false」，导致「用预设但显式关掉某一项」**无法表达**——而那正是 §4.0 声明的核心用法。
**代价**：`with_*` 签名变啰嗦，故额外提供 `with_mac_no_tmp_writable()` 这类语义化快捷方法；CLI 层只用快捷方法。
详见 §4.1。

### A.7 归因走 `classify_output`（review 后修正）

**决策**：`SandboxImpl` trait 新增带默认实现的 `classify_output(&self, output: &CommandOutput) -> ExitReason`，默认委托 `classify_exit`；macOS override。
**理由**：拒绝不传播为 exit code（`2>/dev/null; exit 0` → rc=0），必须扫 stderr；但现有 `classify_exit(exit_code, blocked)` 拿不到 stderr，且外层 `Sandbox::execute` 会二次分类并覆盖结果。
**为何不扩签名**：会改 Linux 实现与所有测试调用点，与「Linux 零改动」冲突。默认委托法让 Linux 实现一行不改。
详见 §10.1。
