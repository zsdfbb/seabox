# macOS Seatbelt 后端 — 架构质量分析报告

> **处理状态（2026-11-07 更新）**：本报告提出的 4 个 P0 与 6 个 P1 已全部落实到 `design.md`。下文保留原始发现供追溯，逐项处置见文末[「整改回顾」](#整改回顾)。

## 分析范围

- **对象**：设计方案（`design.md`，875 行）
- **维度**：全量（可行性 / 可维护性 / 可理解性 / 性能与可靠性）
- **来源**：`design.md` + `context.md` + **实际源码核对**（`src/lib.rs`、`src/config.rs`、`src/cli.rs`、`src/linux/mod.rs`）+ macOS 平台实测

本次 review 的一个特点：设计稿里凡是写「实测」的结论，本次都按可信处理（context.md 有完整实验记录）；凡是描述**现有代码契约**的部分，本次都逐条对照了源码。后者发现了若干问题——这正是本报告的主要产出。

## 各维度判断

| 维度 | 判断 | 关键发现 |
|------|------|----------|
| 1.1 技术可实现性 | 🟢 | 核心机制全部实测验证，无未经验证假设 |
| 1.2 依赖成熟度 | 🟡 | `sandbox-exec` 已 deprecated；回退路径已设计 |
| 1.3 实现周期 | 🟡 | 估算 ~1150 行，但未拆分可独立验证的里程碑 |
| 2.1 模块边界 | 🟢 | `sbpl.rs` 纯生成器 / `mod.rs` 施加，分层干净 |
| 2.2 接口稳定性 | 🔴 | `SandboxConfig` 加字段破坏下游结构体字面量；"下游零改动"不成立 |
| 2.3 错误处理 | 🟡 | 双向硬错误设计完整；但 `classify_exit` 签名拿不到 stderr、65/134 语义冲突 |
| 2.4 并发安全 | 🟢 | 构造期算好不可变状态，无共享可变状态 |
| 2.5 资源管理 | 🟡 | fd 清扫正确方向，但 `close_range` 在 macOS 不存在；canary 临时文件清理未定义 |
| 3.1 概念一致性 | 🟡 | 核心概念清晰；`tmp_writable` 默认值二义、`NetAccess` 与既有 `NetworkConfig` 并存 |
| 3.2 上手成本 | 🟡 | 文档质量高但跨 macOS/Linux 双面心智负担真实存在 |
| 4.1 性能模型 | 🟢 | +6ms 有实测，可忽略 |
| 4.2 故障模式 | 🟡 | fail-closed 与 canary 覆盖到位；"看起来在工作"的残余窗口仍在 |
| 4.3 可观测性 | 🟡 | `--trace-denies` 依赖手工 `log show`；`PolicyReport` 被引用但未定义 |

---

## 一、可行性分析 🟢

### 🟢 通过项

**1. 核心机制全部经过实测，不是纸面推演。** 这是本设计最强的部分。`context.md` 311 行记录了 9 类实测语义，每条都带具体命令与输出：规则顺序「后写赢」用 5 组对照证明、`subpath` 递归性用 7 种操作验证、预开 fd 逃逸用 `exec 9>host` 复现、`sandbox_init` fail-open 用 4/4 坏 profile 对照。设计里没有「显然」「只需」「简单」这类危险措辞——恰恰相反，有三处明确记录了**自己推翻自己**的过程（读白名单可行性、`$TMPDIR` 失败归因、`.git` carve-out 默认值）。

**2. 失败语义的论证质量高。** 选 `sandbox-exec` 而非 `sandbox_init` 的理由是 fail-open vs fail-closed，这是沙箱工具最本质的判据。4/4 坏 profile 的对照实验设计得很到位——它证明的不是"某个 profile 坏了会怎样"，而是"整类失败模式的性质"。

**3. 平台能力边界诚实。** §1 的「不做」清单里 6 项全是硬错误而非静默降级，setuid 硬限制（`check` 单列）、域名白名单不可表达（语法层直接拒）都明确写出。没有制造安全假象。

**4. 编译可行性已验证。** §3.1 实测确认 `landlock` 改 target-specific 依赖后 `cargo build --lib/--bin` 在 macOS 通过，剩余 2 处门控点也已定位到具体文件。

### 🟡 需验证项

**1. `sbpl.rs`「全平台编译、Linux CI 可测」与 `canonicalize` 存在冲突（未知领域，不在设计承诺范围内）。**

§3 与 §11 反复强调 `sbpl.rs` 无 `cfg` 门控，因此能在 Linux CI 跑 golden test——这是**顺序敏感策略的唯一可靠防线**，是设计的重要支柱。但 §6.2 又要求 `norm()` 必须 `fs::canonicalize`。

这在 macOS 上没问题，但 golden test 若真的在 Linux 上跑，`/var` `/etc` `/tmp` 的 symlink 结构完全不同，`canonicalize` 的输出与 macOS 预期值不一致。设计没有说明 golden test 如何处理这个差异。

需要区分两种测试：

| 测试类型 | 依赖 | 能否 Linux 跑 |
|---|---|---|
| 段序断言（`deny default` < floor < write < deny_read < network） | 纯字符串位置 | ✅ 完全可以 |
| golden 全量文本比对 | `canonicalize` 结果 | ❌ 平台相关 |

**建议**：把 golden test 拆成「结构断言（全平台）」+「文本快照（macOS only）」。段序断言才是安全防线，它恰好不依赖 `canonicalize`。这样 §3 的承诺可以完整兑现，且防线的强度不降。

**2. §14 遗留项 `PolicyReport` 被前文当作已有能力引用（🔴 事实错误）。** 详见面「二、可维护性 §2.3」。

### 🟡 依赖成熟度

**1. `sandbox-exec` 已 deprecated。** 这是已知风险，§13 风险 3 已记录，且回退路径具体（~40 行，局限在 `MacSandbox::spawn`）。可接受——但回退路径里「必须在 fork 前 `CString` 化」这个约束值得单独做一个小验证，因为 ADR 0003 的零堆约束在这里是硬边界。

**2. `libc = "0.2"` 已够用。** 无新增第三方依赖，这是明显的优点。

### 🟡 实现周期

~1150 行估算合理（`sbpl.rs` 280 + `mod.rs` 380 + 校验/CLI 150 + 测试 350）。但**没有拆分可独立验证的里程碑**。考虑到这是纯新增（Linux 零改动），建议按此顺序落地，每步都可独立验证：

1. `sbpl.rs` + 段序 golden test（**全平台可测**，无平台依赖，先做）
2. 双向校验 + `macos` 字段接入 `SandboxConfig`（全平台可测）
3. `MacSandbox::spawn` 最小可跑（macOS）
4. canary + fd 清扫（macOS）
5. `check` 输出 + `classify_exit` 分支（全平台可测部分先做）

第 1、2 步占 ~40% 工作量且能在 Linux CI 上完整验证——把风险最高的顺序敏感逻辑前置，是这类移植项目的合理排期。

---

## 二、可维护性分析

### 🟢 模块边界

分层是干净的，且**依赖方向正确**：

```
SandboxConfig ──► sbpl::build() ──► Plan ──► MacSandbox::spawn()
   (配置)          (纯函数)        (数据)      (平台代码)
```

- `sbpl.rs`：纯函数，`SandboxConfig → Plan`，无平台 API
- `mod.rs`：`Plan → 进程`，全部平台相关逻辑收敛于此
- `Plan` 是不可变中间表示，让生成与施加可以独立测试

`MacChild` 与 `LinuxChild` 并列实现 `SandboxChildImpl`，复用 `child::run_to_output()`——与既有架构同构，没有引入新的抽象层次。§2 否决候选 B（三层 `Policy`/`Capabilities`/`Plan`）的理由也站得住：当前只有 macOS 一个消费者，为不存在的 Windows 后端预付抽象成本是错的。

### 🔴 接口稳定性

**这是本次 review 发现的最严重问题。**

§4.1 原文：

> `SandboxConfig` 增加一个字段，类型不变，下游零改动

**这句话不成立。** `SandboxConfig` 没有 `#[non_exhaustive]`（已核实 `grep non_exhaustive src/` 无结果），因此给结构体加字段是**破坏性变更**——所有用结构体字面量构造 `SandboxConfig` 的地方都会编译失败：

| 位置 | 构造方式 | 影响 |
|---|---|---|
| `src/cli.rs:596` | `Ok(SandboxConfig { ... })` 全字段字面量 | ❌ 编译失败 |
| `tests/landlock_test.rs:514` | `SandboxConfig { landlock: rules, ..Default::default() }` | ✅ 用 `..Default` 幸免 |
| `examples/cli_from_toml.rs:75` | `SandboxConfig::default()` + `with_*` | ✅ 幸免 |

`src/cli.rs:596` 是 crate 内部代码，改起来不难——但它是 **CLI 的配置装配点，正是 macOS 字段需要接入的地方**，改动是必然的，只是设计稿把它描述成"零改动"会误导实现者低估工作量。

**更值得注意的是外部影响**：`seabox` 是 lib + bin 双形态 crate（`pub use config::{..., SandboxConfig}`），`SandboxConfig` 是公开 API。任何下游 crate 只要用了结构体字面量构造，升级即编译失败。

这不是要否决加字段（那是最合理的方案），而是要求：
1. 删除「下游零改动」的表述，改为准确描述
2. 明确本变更属于**破坏性变更**，需要在 CHANGELOG 标注；或本次就加 `#[non_exhaustive]`（但那本身也是破坏性变更，且会禁止下游用 `..Default::default()` 之外的字面量——需权衡）

**次要问题**：`MacOsConfig` 缺 `impl Default`。§4.1 只写了 `#[derive(Clone, Debug)]`，但 §4.2 表格声明「自定义 `tmp_writable: false`、`allow_git_write: true`」——这些默认值必须有 `Default` 实现承载。`MacReadMode` 同样缺 `#[default]` 标注（且它带 `Only(Vec<PathBuf>)` 变体，derive `Default` 需要显式 `#[default]` 落在 `All` 上）。

### 🟡 错误处理

**🟢 做得好的部分**：双向硬错误（§4.6）设计完整——macOS 上 Linux 字段非默认即 `bail!`，Linux 上 `--mac-*` 非空即 `bail!`。这个「双向」是关键的：单向校验会让用户在 Linux 上误以为 `--mac-write` 生效了。

**🟡 问题 1：`classify_exit` 拿不到 stderr，但 §10 要求扫描 stderr。**

已核实 trait 签名（`src/lib.rs:546`）：

```rust
fn classify_exit(&self, exit_code: i32, blocked: Option<(u32, u32)>) -> ExitReason;
```

§10 的设计是：

> 因此**不能只靠 exit code 分类**，必须同时扫描 stderr。这也是 `MacSandbox` 必须 override `execute()`（只有它能拿到 stderr）的原因；`spawn(StdioConfig::Inherit)` 路径退化为仅 exit code 判据。

设计的自我意识是对的（它知道 `classify_exit` 拿不到 stderr，所以去 override `execute()`），但**没说明 override 之后与 `Sandbox::execute` 的关系**。看现有实现（`src/lib.rs`）：

```rust
pub fn execute(&self, spec: &CommandSpec) -> anyhow::Result<(CommandOutput, ExitReason)> {
    let output = self.inner.execute(spec)?;
    let mut reason = self.inner.classify_exit(output.exit_code, output.blocked_syscall);
    if output.timed_out { reason = ExitReason::InternalError(...); }
    Ok((output, reason))
}
```

`Sandbox::execute` 在拿到 `CommandOutput` 后**又调用了 `classify_exit`**，且 `timed_out` 分支会覆盖结果。如果 `MacSandbox::execute` 内部已经用 stderr 算出 `Denied`，外层 `Sandbox::execute` 会再算一次并可能覆盖——除非 `MacSandbox` 把 stderr 判据编码进 `blocked` 字段（但那语义是 `(syscall_nr, arch)`）。

**这是真实的接口设计缺口**，需要明确：要么扩 `classify_exit` 签名（影响 Linux 实现与所有测试），要么让 `detailed_classify` 成为 trait 的新方法，要么在 `Sandbox::execute` 里为 `Denied` 加短路。**建议在实现前先定这个契约**，否则会在实现中途返工。

**🟡 问题 2：exit code 65 与 134 的语义冲突（区分度问题）。**

§10 规定：

| 条件 | 结果 |
|---|---|
| `exit_code == 65` | `InternalError`：SBPL profile 被拒（我们自己的 bug） |
| `exit_code == 134` | `Denied { Seatbelt, "read whitelist may be too narrow" }` |

问题：`65` 是 `EX_DATAERR`，**目标程序自己也可能返回 65**。同样 `134` 是 SIGABRT，程序自身崩溃也会 134。设计在风险表 §13-5 承认了 134 的歧义，但 65 的同样的歧义**没有记录**。

更麻烦的是：`sandbox-exec` 自身失败时返回 65，但**目标程序正常退出时也可能返回 65**。仅凭 exit code 无法区分。§10 说「内部错误（我们自己的 bug）」是过强的断言——若用户跑的程序恰好 `exit 65`，会被误报成 seabox 的 bug。

**建议**：65 的归类降级为 `Denied` 或 `Program(65)`，仅在 stderr 同时含 `sandbox-exec:` 前缀时判为 `InternalError`。这与 134 的处理逻辑应当一致。

**🟡 问题 3：canary 失败时的清理路径未定义。**

§9.1 的流程第 4 步是「被拒 → 策略生效 → 清理后执行真实命令」，但没说清理什么、失败如何处理。canary 文件在 `$TMPDIR`，正常路径下写不进去（被拒），所以其实**没有文件要清理**——但探针进程本身若意外成功创建了文件，清理逻辑必须存在且必须在 `bail!` 之前。这需要写清楚，否则会留下 `$TMPDIR/.seabox-canary-*` 垃圾，且失败时可能残留。

### 🟢 并发安全

设计里没有共享可变状态——`MacOsConfig` 在构造期定死，`Plan` 不可变，`spawn` 只读。`pre_exec` 的零堆约束（ADR 0003）已明确要求保留集合 fork 前算好。

一个值得肯定的细节：§3 明确「`MacSandbox` **在构造期**调用 `build()` 并跑 canary」，把昂贵操作移出 `spawn` 路径，同时让配置错误尽早暴露。这是正确的设计选择。

### 🟡 资源管理

**🟡 问题 1：`close_range(3, ~0, 0)` 在 macOS 上不存在（已实测验证）。**

§9.2 写道：

> `pre_exec` 内只循环 `close(2)` 或单次 `close_range(3, ~0, 0)`——**零堆分配**

实测编译（macOS 27.0.1 / Xcode CommandLineTools SDK）：

```
error: call to undeclared function 'close_range'; ISO C99 and later
       do not support implicit function declarations
```

`close_range` 是 **Linux 5.9+ 的 syscall**，macOS 从未提供（`unistd.h` 中也无 `closefrom`）。因此在 macOS 上这一半的方案不可用，**只剩 `close(2)` 循环**。

后果：循环上界是 `_SC_OPEN_MAX`。实测本机 `sysconf(_SC_OPEN_MAX) = 1048575`、`getdtablesize() = 92160`。无论用哪个，在 `pre_exec` 里循环 9 万~100 万次 `close()` 都不可接受——这会显著拖慢每次 spawn。

`getdtablesize()` 是 macOS 可用的 POSIX 接口，返回 92160。9 万次 `close()` 系统调用在 `close()` 对无效 fd 走快速返回的情况下，量级仍是毫秒级——**可能吃掉 +6ms 预算的几倍**。

**建议**：改用 `/dev/fd` 目录枚举实际打开的 fd（`open("/dev/fd")` + `readdir`），只关闭真实存在的。但 `readdir` 在 `pre_exec` 里涉及分配……更实际的做法是：**在 fork 前用一次 `getdtablesize()` 上限，但配合 `fcntl(F_GETFD)` 先探测**，或者接受「按 `StdioConfig` 只保留声明的 fd，其余用较小上界（如 1024）循环」。

这个问题设计稿完全没意识到——它按 Linux 的 `close_range` 写，但那在目标平台上不存在。**必须在实现前解决**，且需要在 macOS 上实测循环耗时才定方案。

**🟡 问题 2：canary 缓存的生命周期未定义。**

§9.1 说「同一配置只跑一次，可缓存」。但缓存在哪里？`MacSandbox` 是一个对象，`Sandbox::from_config` 每次都会新建——所以缓存实际只能跨「同一 `MacSandbox` 实例的多次 `execute`」，而这场景下用户通常只跑一两条命令。真正的缓存价值（同配置多次执行）需要更长的生命周期。这不是错误，但「可缓存」的说法给了过多承诺。

---

## 三、可理解性分析

### 🟡 概念一致性

**🟢 核心概念区分度高**：`read`/`write`/`deny_read`/`deny_write` 四个维度正交，`preset` 与字段是「默认值 vs 覆盖」关系（§4.0 讲得很清楚），这个模型一致且好理解。

**🟡 问题 1：`tmp_writable` 的默认值在 §4.1 与 §4.2 之间二义。**

- §4.1 字段注释：`/// TMPDIR 可写（预设默认 true；自定义默认 false）`
- §4.2 表格：`ReadOnly`/`WorkspaceWrite`/`FullAccess` 都是 `true`，自定义是 `false`

在 `preset = Some(X)` 时，「预设填默认值」与「字段默认值」冲突——`MacOsConfig::default()` 给的 `tmp_writable: false`，但 `preset = Some(ReadOnly)` 会填 `true`。**用户怎么写「用 ReadOnly 但不要 TMP 可写」？** 现有字段无法表达（没说 `--mac-no-tmp-writable` 是"覆盖预设"还是"仅自定义时生效"）。

§4.5 CLI 有 `--mac-no-tmp-writable`，但 §4.2 的表格注释「预设只填上表列出的字段；用户显式给的同名字段总是覆盖预设值」——问题在于 `tmp_writable: bool` 无法区分「用户显式设了 false」与「用户没设，取默认 false」。**这是经典的 bool vs Option\<bool\> 问题**，设计里 `Option<bool>` 一个都没用（实测 `grep Option<bool> src/` 无结果，说明现有代码也没这个模式）。

同样的二义性存在于 `allow_git_write`（预设 `true`，但 `--mac-no-git-write` 要能覆盖）和 `no_credential_deny`。

**建议**：三个 bool 字段改成 `Option<bool>`，`None` = 未设置（跟随预设），`Some(v)` = 显式覆盖。或者引入一个显式的 `configured: bool` 标记。否则「用预设但微调某一项」这个核心用法无法表达——而 §4.0 明确说这就是设计目标。

**🟡 问题 2：`NetAccess` 与既有 `NetworkConfig` 概念重叠但语义不同。**

现有 `NetworkConfig` 只有一个字段 `loopback: bool`，且注释明确「仅在 `namespaces.net == true` 时生效」——它是 **netns 内的 loopback 控制**，语义是「隔离后是否放通回环」。

新增 `NetAccess { Deny, Loopback, Ports, All }` 是**出站访问控制**，语义完全不同。两者都叫 "network"，且都有 loopback 概念。用户面对 `--allow-network`（Linux，控制 ns 内 loopback）与 `--mac-net loopback`（macOS，控制出站回环）时会困惑。

这不是命名错误（`NetAccess` 已经明确叫 Access），但需要在文档里显式对照说明。§8 讲网络时没有提 Linux 侧 `--allow-network` 的语义差异。

### 🟢 抽象层次 / 🟡 上手成本

文档质量很高：实测记录带命令与输出、错误结论有「更正」标注、被否决方案记录理由。`context.md` + `design.md` 的分工清晰（前者语义基线，后者设计决策），四个关键技术决策收在附录 A，新人可以先读附录 A 再按需深入。

**🟡 上手成本问题**：双配置面（`--landlock` vs `--mac-*`）的心智负担是真实的。§13 风险 6 已识别，缓解措施是「`check` 输出当前平台可用面 + 错误消息给出对应 `--mac-*` 建议」。这个缓解方向对，但错误消息的具体形态没设计——**「建议」是产品体验的关键，建议在设计里给出 2~3 个真实错误消息样例**，否则实现者只能自由发挥。

### 🟡 文档内部不一致

以下三处需要修正（细节见「改进建议」）：

1. `§11:750` 提到「双向 `ForeignField` 硬错误」，但 `ForeignField` 在全文其他地方**从未定义或出现**（已核实 `grep ForeignField` 只有这一处）。§4.6 描述的是「双向硬错误」，没有这个类型名。要么补定义，要么删掉这个术语。
2. `§13:824` 与 §4.4 提到 `PolicyReport` 作为缓解措施，但 `PolicyReport` **在 §14 被列为「后续（不在本轮）」**。已核实代码中不存在该类型。这是「用未来能力缓解当前风险」的循环论证。
3. `§12.1:781` 的 `check` 输出写着 `file read isolation — reads are global; only credential denylist`，但 §4.3 已经推翻「读必须全开」并引入 `MacReadMode::Only`。这行输出已过时。

---

## 四、性能与可靠性分析

### 🟢 性能模型

+6ms/次有实测依据（20 次 0.119s vs 裸 0.010s）。对 Agent 单条命令（数十毫秒到数秒）不可感知。canary 再加一次进程，同配置可缓存。

唯一的性能疑问就是上面说的 `close()` 循环——若 `_SC_OPEN_MAX` 是 1048575，即使 `close()` 走快速失败路径，10 万次系统调用也会到**毫秒级甚至十毫秒级**，直接吃掉整个预算。**这是本设计里唯一可能颠覆性能结论的点**，必须在实现前实测。

### 🟡 故障模式

**🟢 fail-closed 链条完整**：坏 profile → rc=65 不执行（§5）；策略语义失效 → canary 拦截（§9.1）；预开 fd → pre_exec 清扫（§9.2）。三层覆盖了绝大多数失效模式。

**🟡 残余窗口：canary 探针与真实命令之间的 TOCTOU。** canary 验证的是「这个 profile 在探针时刻有效」。探针跑完到真实命令启动之间，理论上策略不会变（同一 Plan），所以这个窗口实际很小。可接受，但值得在文档里注明「canary 验证的是 profile 语义，不是运行环境」。

**🟡 单点依赖：`/usr/bin/sandbox-exec`。** `check` 探测存在性，但**若运行时消失（Apple 更新后移除），行为是什么？** 设计没定义。应当是 `spawn` 时硬错误，而不是静默降级为无沙箱执行——考虑到 `sandbox_init` fail-open 的教训，这里必须显式 `bail!`。

**🟢 降级策略明确**：无预设且无字段 = 不施加（与 Linux 空 landlock 对称）；`Only` 模式失败时用户可退回 `All`。没有半吊子状态。

### 🟡 可观测性

**🟡 `--trace-denies` 的实现细节缺失。** §10 提到用 `log show --last 15s --predicate 'sender == "Sandbox"'`，实测可读（uid 501）、耗时 0.66s、能精确到 `deny(1) file-write-create /path`。但：

- 调用时机？`execute` 失败后自动调，还是用户显式加 flag？
- 0.66s 的延迟对每条命令都做是否可接受？
- 日志按**进程名**（`sh(52233)`）而非 pid 区分，同名并发进程会混淆——§10 自己标注了「精度 `Certain` 仅在单进程场景成立」，但没有给出「多进程时如何降级」的方案。

**🟡 `PolicyReport` 被当已有能力引用**（重复前面的发现）。§13-1 用它缓解「读侧零隔离」，但它在 §14 是未来项。**这是风险表里最弱的一环**：把一个不在本轮的能力当缓解措施，等于该风险当前没有缓解。

---

## 五、风险排序

| 风险 | 影响 | 可能性 | 优先级 | 建议 |
|------|------|--------|--------|------|
| `close_range` 在 macOS 不存在，`close()` 循环可能吃掉 10~100 倍性能预算 | 高（性能论证失效 / spawn 变慢） | **高**（已实测确认 API 缺失） | **P0** | 实现前实测循环耗时，改用 `getdtablesize()` 或 `/dev/fd` 枚举，重新定预算 |
| 加 `SandboxConfig` 字段是破坏性变更，与「下游零改动」表述矛盾 | 中（下游编译失败 / 工作量低估） | **高**（已确认无 `non_exhaustive`） | **P0** | 修正文档表述，决定是否加 `non_exhaustive`，CHANGELOG 标注 |
| `classify_exit` 拿不到 stderr，与 §10 的「必须扫 stderr」冲突；外层 `Sandbox::execute` 会二次分类 | 高（归因错误 / 实现返工） | 高 | **P0** | 实现前先定接口契约（扩签名 / 新 trait 方法 / 短路 `Denied`） |
| `tmp_writable` / `allow_git_write` / `no_credential_deny` 用 `bool` 无法区分「未设」与「显式 false」，预设覆盖语义不可表达 | 高（核心用法失效，§4.0 的设计目标达不到） | **高**（结构已定，逻辑必然踩到） | **P0** | 改 `Option<bool>` 或引入 `configured` 标记 |
| 65 / 134 与目标程序自身退出码无法区分，65 被判为「我们的 bug」属过强断言 | 中（误报 / 用户困惑） | 中 | P1 | 65 降级处理，仅 stderr 含 `sandbox-exec:` 时判 InternalError |
| 凭据黑名单不完备，漏一个即泄漏；风险表用未来项 `PolicyReport` 缓解 | 高（安全） | 中 | P1 | 补实测清单；把缓解措施改为当前可做的（`check` 写死 + golden 锁定） |
| golden test 依赖 `canonicalize`，与「Linux CI 可测」承诺冲突 | 中（防线强度不如预期） | 中 | P1 | 拆「段序断言（全平台）」+「文本快照（macOS）」 |
| canary 清理路径未定义，可能残留 `$TMPDIR/.seabox-canary-*` | 低 | 中 | P2 | 明确清理时机与失败路径 |
| `check` 输出中「reads are global」已过时（`Only` 模式已存在） | 低（文档误导） | 高 | P2 | 更新文案 |
| `ForeignField` 术语未定义；`PolicyReport` 状态矛盾 | 低 | 高 | P2 | 删术语或补定义；统一 `PolicyReport` 状态 |
| `sandbox-exec` 运行时消失的行为未定义 | 中 | 低 | P2 | 定为 `spawn` 时硬错误，禁止静默降级 |
| `NetAccess` 与 `NetworkConfig` 的 loopback 概念重叠 | 低（可理解性） | 中 | P2 | 文档加对照说明 |

---

## 六、改进建议

### 🔧 易修复（实施时做）

1. **删除「下游零改动」表述**（§4.1:202）。改为：「`SandboxConfig` 增加 `macos` 字段。因未加 `#[non_exhaustive]`，使用结构体字面量构造的下游代码需补 `macos: Default::default()`（本仓库内 1 处：`src/cli.rs:596`）。」
2. **给 `MacOsConfig` 加 `impl Default`，`MacReadMode` 加 `#[default] All`**（§4.1）。当前结构体声明不足以支撑 §4.2 的默认值表。
3. **更新 `check` 输出**（§12.1:781）：`file read isolation — reads are global` → `file read isolation — MacReadMode::All (default) | Only(paths)`。
4. **统一 `PolicyReport` 状态**：§13-1 与 §4.4 引用它作为缓解措施，但 §14 说不在本轮。改为当前手段（`check` 写死 + golden test 锁清单），并把 `PolicyReport` 只留在 §14。
5. **定义或删除 `ForeignField`**（§11:750）。§4.6 描述的是双向硬错误，未见此类型名。
6. **补 65 / 134 的 stderr 二次判据**（§10）：仅当 stderr 含 `sandbox-exec:` 时把 65 判为 `InternalError`，否则 `Program(65)`。
7. **明确 canary 清理时机**（§9.1）：探针若意外成功创建文件，必须在 `bail!` 前删除；正常路径无文件残留需显式说明。
8. **给 `check` 的错误建议文案定稿**（§13-6）：给出 2~3 个真实错误消息样例，如 `--landlock is not supported on macOS; use --mac-preset / --mac-read instead`。

### 💬 需讨论（需要决策）

1. **三个 bool 字段改 `Option<bool>`**（§4.1）。这是核心语义问题：`tmp_writable: bool` 无法表达「用了预设但显式关掉 TMP」，而 §4.0 明确把「预设填默认、字段覆盖」当作设计目标。三个字段（`tmp_writable`、`allow_git_write`、`no_credential_deny`）都受影响。
   - 备选：加一个 `configured_fields: u32` 位掩码，或每个字段配一个 `Option<T>` 影子字段。前者省内存但可读性差，后者直白但字段翻倍。
   - 倾向 `Option<bool>`：`None` = 未设置、跟随预设；`Some(v)` = 显式。需要确认现有代码风格是否接受（当前无 `Option<bool>` 先例）。

2. **`classify_exit` 的接口契约**（§10）。三个选项：
   - (a) 扩签名加 `stderr: &[u8]`——影响 Linux 实现 + 所有测试，但最干净
   - (b) trait 加 `fn classify_detailed(&self, output: &CommandOutput) -> ExitReason`，默认实现委托 `classify_exit`，macOS override——**侵入最小，推荐**
   - (c) 在 `Sandbox::execute` 里为 `Denied` 加短路——最省事但把平台逻辑漏进公共层

3. **golden test 的平台策略**（§11）。建议拆两层：段序断言（全平台，不依赖 `canonicalize`）+ 文本快照（macOS only）。需要确认 `sbpl.rs` 的门控方案能支持这种拆分。

4. **`SandboxConfig` 是否加 `#[non_exhaustive]`**。加了之后下游只能用 `..Default::default()` 构造，破坏性更强但长期更安全。考虑到这是 0.x 版本（Phase 3），**倾向现在就加**，趁下游使用者少。

### 🏗️ 架构级（影响面大）

1. **fd 清扫方案需要重新设计**（§9.2）。已实测 `close_range` 在 macOS 不存在，`_SC_OPEN_MAX` 高达 1048575。三条路径：
   - 按 `getdtablesize()`（本机 92160）循环 `close()`——需实测耗时是否可接受
   - `open("/dev/fd")` + 枚举——但 `pre_exec` 里读目录与零堆约束冲突
   - **fork 前先用 `fcntl(F_GETFD)` 探测有效 fd 范围，记录实际上界传给 `pre_exec`**——零堆且高效，但需要在 fork 前遍历一次（可接受，fork 前不受零堆约束）

   第三条最可行。但**必须先实测**才能定，因为它决定了 `MacSandbox::spawn` 的核心结构。这是本次 review 里唯一需要改架构的点。

2. **跨平台配置面的长期形态**。当前是「Linux 字段 + macOS 字段并列在同一个 `SandboxConfig`」，靠双向硬错误防误用。若未来加 Windows，会变成三组并列字段 + 三向校验，`SandboxConfig` 会持续膨胀。

   备选：改成 `enum PlatformConfig { Linux(LinuxConfig), MacOs(MacOsConfig) }`。但那会破坏现有 API（所有 `with_landlock` 等都得改），且与「Linux 行为零变化」的目标冲突。

   **建议本轮不做**，但记录这个演进压力点。当第三个平台出现时再重构。

---

## 总体评价

**整体健康度：良好。**

这个设计的最强项是**实证驱动**——9 类 Seatbelt 语义全部有实测记录，三处「自己推翻自己」的过程也完整保留。安全机制的核心论证（fail-closed、canary、fd 清扫、顺序敏感）都建立在实际验证之上，不是纸面推演。文档质量在同类设计稿里属上乘。

**最大风险不在设计思路，而在「设计与现有代码契约的接缝处」。** 本次 review 发现的 4 个 P0 里有 3 个属于这一类：

- `close_range` 按 Linux API 写，但目标平台没有
- 「下游零改动」不成立，因为 `SandboxConfig` 未加 `non_exhaustive`
- `classify_exit` 的签名容不下 §10 要求的 stderr 判据

这些都不是设计者的疏忽，而是跨平台移植的典型陷阱：**写「macOS 后端」时很自然地参照 Linux 实现，但 Linux 的实现细节（`close_range`、trait 签名）未必能平移**。

**推荐下一步**：

1. **先解决 4 个 P0**，其中 fd 清扫方案需要**实测**（`close()` 循环耗时、`getdtablesize()` 边界）才能定架构，建议今天就做——它可能改变 `spawn` 的结构
2. **`Option<bool>` 的决策尽快做**，它影响 §4.1 的全部结构定义，越晚改成本越高
3. **`classify_exit` 建议选方案 (b)**（trait 加 `classify_detailed`），侵入最小且不动 Linux
4. 修完 P0/P1 后，按「先是全平台可测的 `sbpl.rs` + 校验，再是 macOS 的 spawn + canary + fd」的顺序实现，把风险最高的顺序逻辑前置到 Linux CI 能覆盖的阶段

**一句话判断**：设计本身可以进入实现，但实现前需要一次「与现有代码契约的对账」——把 Linux 实现特有的假设逐条在 macOS 上验证一遍。本次已代查了 4 条，还有 `SandboxChildImpl` 的 kill/wait 语义、`StdioConfig::Fd` 在 macOS 上的 dup2 行为等值得同样对账。

---

## 整改回顾

本报告提出的问题已逐项处理，部分是**新实测**驱动的方案替换（而非文字修正）。

### P0（4 项，全部解决）

| # | 原问题 | 处置 | 位置 |
|---|---|---|---|
| 1 | `close_range` 在 macOS 不存在 | **重新实测 3 方案**：`close()` 循环 14.5ms / `fcntl` 探测 11.5ms / **`/dev/fd` 枚举 0.026ms** → 采纳后者。并验证逃逸确实被堵：不清扫 `host=[PWNED]`，清扫后 `[ORIGINAL]` 且 sh 报 `Bad file descriptor` | design §9.2 + 附录 A.5 |
| 2 | `SandboxConfig` 加字段是破坏性变更 | 删除「下游零改动」，补受影响点表格（`src/cli.rs:596` 需改，另 2 处用 `..Default` 幸免），建议同时加 `#[non_exhaustive]` | design §4.1 |
| 3 | `classify_exit` 拿不到 stderr | 新增 `classify_output(&self, output: &CommandOutput)`，默认委托 `classify_exit`；`Sandbox::execute` 改一行。Linux 实现零改动 | design §10.1 + 附录 A.7 |
| 4 | `bool` 无法表达「预设 + 显式关」 | 三个开关改 `Option<bool>`，`read` 改 `Option<MacReadMode>`；加语义化快捷方法（`with_mac_no_tmp_writable()`）。`MacOsConfig` / `MacReadMode` 补 `Default` | design §4.1 + 附录 A.6 |

### P1（6 项，全部解决）

| # | 原问题 | 处置 |
|---|---|---|
| 5 | 65/134 与程序自身退出码歧义 | 65 需 stderr 含 `sandbox-exec:` 才判 `InternalError`，否则 `Program(65)`（design §10.2） |
| 6 | 凭据黑名单风险用未来项 `PolicyReport` 缓解 | 改为当前手段（`check` 写死 + golden 锁清单）；`PolicyReport` 只留 §14 |
| 7 | golden test 与 `canonicalize` 冲突 | 拆「段序断言（全平台，**才是安全防线**）」+「文本快照（macOS）」（design §11） |
| 8 | canary 在 `tmp_writable=false` 时无探针 | 三优先级降级；**实测读探针可行**（真策略下 `Operation not permitted`，无 deny 时成功，两向可区分），并记录 realpath 坑（design §9.1） |
| 9 | `sandbox-exec` 运行时消失行为未定义 | 定为 `spawn` 时硬错误，禁止静默降级（design §13.2 风险 3b） |
| 10 | `--trace-denies` 触发时机/降级缺失 | 定为显式 flag（0.66s 不可忽略）；进程名冲突时降级 Probable 并标注（design §10.2） |

### P2（文档一致性，全部解决）

- `ForeignField` 未定义 → 从 §11 测试表删除，改用「双向硬错误」
- `check` 输出「reads are global」过时 → 改为 `MacReadMode::All (default) | Only(paths)`，并新增 Read isolation 段落
- canary 清理路径未定义 → §9.1 明确
- `NetAccess` 与 `NetworkConfig` 概念重叠 → 列入 §13.2 残余风险 11，需补对照表

### 未采纳 / 留待讨论

| 项 | 原因 |
|---|---|
| `SandboxConfig` 加 `#[non_exhaustive]` | 已给建议，但是否执行需团队决定（本阶段倾向"现在就加"） |
| 跨平台配置面长期形态（`enum PlatformConfig`） | 架构级，与「Linux 零改动」冲突，建议第三平台出现时再做 |
| 里程碑拆分 | 已写入 §「推荐下一步」的顺序建议，但未改文档结构 |

### 关键结论变更

整改过程中最有价值的不是文字修正，而是**两条原设计假设被实测推翻**：

1. **`close_range` 不可用** —— 原设计按 Linux API 写。实测编译失败，且备选方案耗时差 500 倍（14.5ms vs 0.026ms）。这不是"可以后续优化"的量级，而是直接吃掉整个 +6ms 预算。
2. **读探针可替代写探针** —— 原设计只说"或在无可用探针时跳过并记录警告"，即默认降级为无保护。实测证明读探针在真策略与无策略两向都可区分，不必降级。
