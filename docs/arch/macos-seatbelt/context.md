# macOS Seatbelt 适配 — 架构上下文

> 需求名：`macos-seatbelt`。本轮聚焦 **文件系统** 与 **网络** 两类策略，其余维度（进程、syscall、capability）只做边界界定。
> 本文档中的 Seatbelt 行为全部来自 **macOS 27.0.1（Darwin 27.0.0, arm64）实测**，标注 ✅ 者为实测确认。

## 概述

让 seabox 在 macOS 上提供与 Linux 后端（Landlock + seccomp + namespaces）**语义对齐**的沙箱：把现有 `SandboxConfig`（`--landlock path:perm` / `--unshare-net` / `--allow-network`）翻译成 Seatbelt profile（SBPL），通过 `sandbox-exec` 或进程内 `sandbox_init()` 施加。

## 现有架构

### 模块边界

```
CLI (src/cli.rs)  ──┐
                    ├──→ SandboxConfig (src/config.rs) ──→ Sandbox::from_config (src/lib.rs)
Crate API           ┘                                          │
                                                               ▼
                                          create_sandbox_impl(config)  ← 唯一平台分叉点
                                                               │
                                     ┌─────────────────────────┴──────────────────────┐
                                     ▼                                                ▼
                      linux::LinuxSandbox (impl SandboxImpl)          ⚠ 当前：bail!("requires Linux")
                      ├ child_setup.rs (pre_exec 序列)               （无 macOS 分支）
                      ├ landlock.rs / seccomp.rs / namespaces.rs …
                      └ SandboxChildImpl (src/linux/mod.rs)
```

关键观察：

- **平台分叉点只有一个**：`src/lib.rs:169 create_sandbox_impl()`，返回 `Box<dyn SandboxImpl>`；`SandboxImpl` / `SandboxChildImpl` trait 已是平台无关的（注释里明确写着"为 macOS Phase 3 提供扩展点"）。
- `src/child.rs` 的 `run_to_output()`（drain + 超时 + kill）**完全平台无关**，Piped 路径可直接复用。
- 但 **配置层是 Linux 形状的**：`SandboxConfig` 的字段名与语义（`landlock: Vec<LandlockRule>`、`namespaces`、`mount.specs`、`seccomp_deny_nrs`、`capabilities`）全部绑定 Linux 机制；`LandlockPerm` 的 16 个权限位是内核 `AccessFs` 位图的直译。
- **当前在 macOS 上根本无法编译**：`landlock = "0.4"` 是**非 optional 依赖**，在 macOS 上 `libc` 缺 `SYS_landlock_*` / `prctl` / `O_PATH`，`cargo build` 直接失败（实测 6 个 E0425/E0432）。所以"macOS 适配"的第一步必然是依赖与 cfg 门控重构。

### 核心抽象

| 抽象 | 位置 | 现状 | macOS 相关性 |
|---|---|---|---|
| `SandboxImpl`（trait） | `src/lib.rs:529` | `spawn` / `execute`(默认实现) / `classify_exit` | 可直接实现 macOS 版本 ✅ |
| `SandboxChildImpl`（trait） | `src/lib.rs:494` | `try_wait`/`wait`/`wait_timeout`/`kill`/`id`/`take_std*`/`blocked`/`timed_out` | 可直接实现 ✅ |
| `SandboxConfig` | `src/config.rs:24` | Linux 形状（见上） | **需要重新分层** |
| `LandlockRule` / `LandlockPerm` | `src/lib.rs:37,83` | 16 个内核权限位 | Seatbelt 只有 read/write/exec 粗粒度 + 若干子操作 |
| `NetworkConfig` | `src/config.rs:66` | 只有 `loopback: bool` | **严重不足**（见下） |
| `ExitReason` / `DenyMechanism` | `src/lib.rs:122,137` | `Landlock` / `Seccomp` / `Unknown` | 需要新增 `Seatbelt` 变体 |
| `CommandOutput.blocked_syscall` | `src/lib.rs:415` | seccomp USER_NOTIF 上报 | macOS 无对应机制（无结构化拒绝通道） |

### 关键数据流

1. **Linux execute**：`Sandbox::execute` → `SandboxImpl::execute`（默认实现）→ `spawn(Piped)` → `linux/mod.rs` 建 pipe + `fork` → `child_setup` pre_exec 序列（unshare → mount → landlock → seccomp → dup2 → execve）→ 父侧 `run_to_output` drain 循环 → `classify_exit(exit_code, blocked)`。
2. **macOS 预期**：`Sandbox::execute` → `MacOsSandbox::spawn` → `sandbox-exec -p <SBPL> -- prog args`（或 fork + 子进程内 `sandbox_init` + `execve`）→ 同样跑 `run_to_output` → `classify_exit`（只能靠 exit code + stderr 文本，**没有结构化 blocked 通道**）。

### 外部依赖

| 依赖 | 用途 | 版本 | 备注 |
|---|---|---|---|
| `sandbox-exec` | profile 施加 | 系统自带 `/usr/bin/sandbox-exec` | ✅ 实测存在且可用（root:wheel, 135 KB）；Apple 已标记 deprecated 但功能完好 |
| `libsystem_sandbox.dylib` | 进程内 `sandbox_init(profile, 0, &err)` | 系统自带（在 dyld shared cache 内） | ✅ 实测可直接 `extern "C"` 声明调用；SDK `sandbox.h` 标注 `API_DEPRECATED(macos 10.5–10.8)`，但 **`/usr/include/sandbox.h` 仍存在且函数可用** |
| SBPL 解析器 | profile 编译 | 内核/`libsandbox` | 无公开文档；语法事实性靠实测（见「Seatbelt 实测语义」） |
| `landlock` crate (0.4) | Landlock 封装 | 0.4.5 | **非 optional**，是 macOS 编译阻碍的根因 |

## Seatbelt 实测语义（macOS 27.0.1 实测，✅）

这一节是本轮探索最重要的产出：现有 `docs/macos-sandbox.md` 的设想与实测行为有 **3 处实质冲突**。

### ✅ 1. 规则是**「后写赢」（顺序敏感）**，不是「deny 恒赢」

> ⚠️ 本节曾误记为「deny 恒优先于 allow」。**该结论已作废**，原因是早期测试用 shell 的
> `>/dev/null` 判成败，而 profile 未允许写 `/dev/null`，导致所有结果为假阴性（实测已复现该 bug）。
> 改用「直接 `cat` + exit code」重测后结论如下。

**同一路径、同一操作名时，后写的规则胜出**（与 allow/deny、与路径具体度无关）：

| 规则顺序 | 结果 |
|---|---|
| `(deny ... outer)` → `(allow ... outer/inner)` | inner **可读**（后写 allow 赢） |
| `(allow ... outer/inner)` → `(deny ... outer)` | inner **拒**（后写 deny 赢） |
| `(deny ... f)` → `(allow ... f)` | 可读 |
| `(allow ... f)` → `(deny ... f)` | 拒 |

**与路径具体度无关**：`allow outer` + `deny outer/inner`（deny 后写）→ inner 仍被拒，
说明不是「更具体者赢」。

**对设计的含义（重要且有利）**：SBPL 是**有顺序的规则列表**，可以表达
「先全局放通、再定点拒绝、再更精细地放回」这类三段式策略，**不必**像早期结论那样
只能二选一。这与 landlock 的层级累加不同，给了翻译层更大的表达空间。
**但**：顺序敏感意味着**生成顺序本身是安全关键**，必须由生成器固定（如
「地板 allow → 预设 allow → 凭据 deny → 用户显式 allow/deny」），不可由配置顺序泄漏到输出顺序。

### ✅ 2. `subpath` 是路径组件前缀，`literal` 是精确匹配

- `subpath "/private/tmp/sbxp/sec"` **不**匹配 `/private/tmp/sbxp/secret/k.txt`（组件级，非字符串级）。
- `literal` 精确匹配单文件，同目录其他文件不受影响。
- **符号链接**：`/tmp` → `/private/tmp`。`subpath "/tmp"` 与 `subpath "/private/tmp"` 两个方向**都**DENY（实测），说明 SBPL 在 `subpath` 上按真实路径解析，`/tmp` 与 `/private/tmp` **不能互换使用**——这直接影响 `expand_tilde` 和用户输入的路径规范化（须 `realpath`）。

### ✅ 3. 白名单过窄会导致目标程序 abort（exit 134），而不是干净的错误

`(deny default)` + 只放 `file-read*` 的部分目录 → `/bin/sh` 起不来：

```
Sandbox: sh(43984) deny(1) file-read-data /
→ Abort trap: 6   (exit 134)
```

根因：**必须 `(allow file-read* (literal "/"))`**（读根目录自身）。只给 `/usr`、`/System`、`/bin`、`/System/Volumes/Preboot`、`/private/var/db`、`/dev`、`/etc` 全部不行。加上 `(literal "/")` 后立刻 rc=0。

（另注：`/private/var/select/sh` 是 `sh` 的 shell-init 读点，缺它也能起但会报非致命错。）

**结论（已修订）**：macOS 上做“纯白名单”（对标 Landlock `--landlock /etc:ro` 只给一个路径）**可行，但必须自带系统地板**。本节早前记为“几乎不可行”，那是**缺项导致**，不是白名单本身不可行——真因是 floor 少了 `(allow file-read* (literal "/"))`、`(allow file-read* (subpath "/dev"))`、`(allow ipc-posix-shm)`、`(allow file-read-metadata)`，以及 `/etc` 是符号链接（需 `literal "/etc"` **且** `subpath "/private/etc"`）。补齐后 `read=Only([R0])` 实测：读 R0 ✅、读 `/etc/passwd` ❌、读 `$HOME` ❌，而 `git`/`cargo`/`ls`/`sh` 全部可用（详见 design.md §4.3）。可用的两种形态是：

- **A. 黑名单式（推荐）**：`(allow file-read*)` 全局 + 定向 `(deny file-read* (subpath "..."))`；写侧 `(allow file-write* (subpath <白名单>))` 逐条放通。
- **B. 宽白名单**：`(allow file-read* (literal "/"))` + `/usr` + `/System` + `/bin` + `/private/etc` + `/dev` + `/Library` + `/private/var/db` + 用户路径。能跑 `ls`/`git`/`cargo`，但**容易被遗漏路径打成 exit 134**，需要维护一份"基础读集合"。

### ✅ 4. 网络不是 on/off —— 支持端口级与 unix-socket 级

现有文档写"macOS 网络只有 on/off"，**已被实测推翻**：

| 规则 | 效果（实测） |
|---|---|
| 无 `network*` allow（deny default） | curl 全失败 ✅ |
| `(allow network-outbound (remote ip "*:443"))` | 443 通，80 不通 ✅ |
| `(allow network-outbound (remote tcp "*:443"))` | 同上 ✅ |
| `(allow network-outbound (remote udp "*:53"))` | 单给 53 不放通 443 ✅ |
| `(allow network* (local ip "localhost:*"))` + `(remote ip "localhost:*")` | loopback 双向通，公网仍拒 ✅ |
| `(allow network-outbound (remote unix-socket))` | unix socket 全放 |

**loopback 的 inbound/outbound 可分离，且端口精确匹配**（实测矩阵，同一 python 进程同时 listen+connect）：

| 规则 | bind | accept | connect |
|---|---|---|---|
| 无 network 规则 | ❌ EPERM | — | ❌ EPERM |
| 只 `network-inbound (local ip "localhost:*")` | ✅ | ❌ 超时（连不进来） | ❌ EPERM |
| 只 `network-outbound (remote ip "localhost:*")` | ❌ EPERM | — | ❌ 拒绝（服务没起来） |
| inbound + outbound 各 `localhost:*` | ✅ | ✅ | ✅ |
| `localhost:9911` 两条，但进程用 9911 | ✅ | ✅ | ✅ |
| `localhost:9912` 两条，进程用 9911 | ❌ EPERM | — | ❌ EPERM |

这直接支持「Agent 起本地 dev server / MCP server」这一常见场景：可以只开 listen（inbound），不开 connect（outbound）。

**硬限制（实测报错）**：

- 主机名只接受 `*` 或 `localhost`：`(remote ip "example.com:443")` → `sandbox-exec: host must be * or localhost in network address`。**无法做域名白名单**。
- `(remote ip "1.1.1.1:*")` 同样报 `host must be * or localhost`——**无法做具体 IP 白名单**（❗ 与现有 `docs/arch/ebpf-network-filtering` 的 Linux 侧 IP 过滤设想不对称）。
- 端口和协议（tcp/udp）可指定，是**唯一的细粒度手段**。

### ✅ 5. DNS 依赖 mDNSResponder 的 unix socket

只给 `(allow network-outbound (remote ip "*:443"))` 时，`curl https://example.com` **解析失败**（`Could not resolve host`）；补一条

```
(allow network-outbound (remote unix-socket (path "/private/var/run/mDNSResponder")))
```

即恢复 200。同时 `--resolve` 直连 IP 在只放 443 时也是通的，可证明失败点在 DNS 而非 TCP。

**结论**：任何"放通出站"的策略必须**自动附带** mDNSResponder socket 放行，否则用户会看到莫名其妙的 DNS 失败。

### ✅ 6. 写权限必须整族放通，`file-write-data` 单独给不够

实测（父目录 `subpath` 放通 `file-write-data`）：

| 目标操作 | 只给 `file-write-data` | 给 `file-write*` |
|---|---|---|
| 新建文件 | ❌ DENIED | ✅ CREATED |
| 覆盖/追写已存在文件 | ❌ DENIED（连 `>>` 也拒） | ✅ APPENDED |
| `mkdir` | ❌ | ✅ MK_OK |
| `unlink` | ❌ | ✅ UNLINK_OK（deny 日志显示是 `file-write-unlink`） |
| `chmod` | ❌ | ✅ |

- `file-write-create` 单独给能创建文件，但**不能删除、不能 mkdir**（日志：`deny(1) file-write-unlink /path`）。
- 还有一批**隐式写点**被 deny default 挡住，容易造成"神秘失败"：`/dev/null`、`/dev/dtracehelper`、`/dev/tty`、`/dev/stdout`、`/dev/stderr`。实测：`file-read*` 全开 + workspace rw 时，`git status` 直接失败于 `fatal: could not open '/dev/null' for reading and writing`；补 `(allow file-write* (literal "/dev/null"))` 后 git 恢复正常。`ps` 同理（`/bin/ps` exec 被拒）。

**结论**：macOS 后端必须内置一组"运行时必需"的放行（`/dev/null`, `/dev/tty`, `/dev/dtracehelper`, `/dev/stdout`, `/dev/stderr`, 读 `/` 自身），不宜让用户逐条配。

### ✅ 7. 拒绝的观测手段只有两条

1. **程序自身 stderr**：`/bin/sh: /path: Operation not permitted`（EACCES/EPERM 化的文本），`curl` 表现为 `Could not resolve host` / `Connection refused`——**无法区分是网络策略拒绝还是真实网络故障**。
2. **内核日志**（需 root 或授权）：`log stream --predicate 'sender == "Sandbox"'` → `Sandbox: sh(7345) deny(1) file-write-unlink /path`。这是**唯一精确**的拒绝来源（含操作名与路径），但沙箱进程本身读不到。

Linux 侧 `classify_exit()` 有 `blocked_syscall: Option<(u32,u32)>` 这类结构化通道；macOS **没有等价物**，`DenyMechanism::Seatbelt` 只能基于 exit_code（134/71/1）+ stderr 文本模式匹配，歧义远高于 Linux。

### ✅ 8. 施加方式：`sandbox-exec` 是原地 exec（无额外进程），进程内 `sandbox_init` 亦可用

- `sandbox-exec` 实测**原地 exec**：fork 后子进程 pid 与最终 `/bin/sh` 的 pid 相同（`inside pid=43419 == forked child pid=43419`），不像 shell 外包一层。✅ 与 ADR 006 的 business-pid 回传兼容。
- 进程内 `sandbox_init()` 也可用：C 与 **Rust `extern "C"` 均实测成功**（`rc=0`），且 profile **跨 `execve` 生效**（子进程写宿主路径仍被拒），子进程继承（`sh → sh → sh` 三层深仍 DENY）。
- **不可重入**：已被沙箱化的进程再调 `sandbox_init` → `rc=-1, err="Operation not permitted"`（符合 `sandbox.h` 注释"if already in a sandbox, new profile ignored"）。**但**嵌套 `sandbox-exec` 仍可跑（实测 `NESTED_OK`），说明它走的是另一条路径（child 进程首次 init）。
- 启动开销：20 次 `sandbox-exec -f prof /usr/bin/true` ≈ **0.119s**（单次 ≈ 6ms），对照 20 次裸 `/usr/bin/true` ≈ 0.010s。约 **+5ms/次**，其中含 profile 解析。
- `-D key=value` + `(subpath (param "W"))` 可用 ✅ —— **这是传用户路径的最佳通道**，避免把含空格/引号的路径拼进 SBPL 字符串（SBPL 字符串转义无公开规范）。
- `-p <profile>` 支持直接传 profile 文本（含换行）✅。

### ✅ 9. 其他确认项

- 深层子进程、grandchild 均继承限制 ✅。
- 嵌套沙箱不可叠加（`sandbox_init` 返回 EPERM），故 macOS 后端**不能**像 Linux 那样"层层收窄"。
- `(deny default)` 下 `ps` / `sysctl` 一类需要 `(allow process-info*)`、`(allow sysctl-read)`；`(allow mach-lookup)` 是大多数系统服务（含 DNS 之外的）必需，但**不是网络必需**（实测去掉 mach-lookup 后 443 仍通）。

## 约束

- **技术**：Linux 侧 `landlock` crate 非 optional，macOS 上无法编译；`SandboxConfig` 是 Linux 机制形状；`LandlockPerm` 16 位与 Seatbelt 粗粒度不可一一映射；SBPL 无公开规范，只能靠实测与 Apple 历史源码行为推断；`sandbox-exec` / `sandbox_init` 均为 deprecated API（Apple 明确"不再支持"，未来版本有被移除的风险，需保留降级路径）。
- **性能**：`sandbox-exec` 每次约 +5ms 启动；若走 fork + `sandbox_init` 则近乎为零，但需在 ADR 0003 约束下（fork 后零堆操作）完成 profile 的**预编译**（`sandbox_init` 接受 C 字符串，必须在 fork 前 `CString` 化）。
- **演进**：CLI flag 已有 `--landlock` / `--unshare-net` / `--allow-network` / `--share-net`，macOS 上要么复用同名 flag（语义近似），要么引入平台专属 flag；同名复用会让 `--landlock /:ro` 在 macOS 上退化成"黑名单 + 写白名单"，需在文档/`check` 输出中明示。
- **组织**：单机开发者，无 CI 覆盖 macOS（当前测试全 Linux）。macOS 集成测试必须能在无 root 的普通用户下跑，且**不能**触发真实写宿主或网络。

## 需求范围

### 范围内

- **文件系统策略**（本轮重点）：
  - 从 `--landlock path:perm` 派生 SBPL：`ro` → 读放通/写拒；`rw` → 读写放通；`exec` → `process-exec` 放通。
  - 决定策略形态：**黑名单式**（全局 allow-read + 定向 deny + 写白名单）vs **宽白名单**（基础读集合 + 用户路径）。需实测两者在 `cargo build` / `git` / `node` 等真实 Agent 负载上的差异。
  - 路径规范化：`realpath` + `/tmp`→`/private/tmp` 处理、`~` 展开、symlink 语义。
  - 内置运行时放行集合（`/dev/null` `/dev/tty` `/dev/dtracehelper` `/dev/stdout` `/dev/stderr` `(literal "/")`）。
- **网络策略**（本轮重点）：
  - 映射 `NetworkConfig` → SBPL：`loopback` → `(local ip "localhost:*")` + `(remote ip "localhost:*")`；`enabled/false` → 全拒。
  - **新增**端口/协议级出站白名单的配置载体（Seatbelt 唯一可用的细粒度维度）。
  - 自动附带 mDNSResponder socket 放行。
  - 明确"域名白名单 / IP 白名单在 Seatbelt 上不可能"，并把 `--allow-network` 语义在 macOS 上重新定义（不要假装和 Linux 一致）。
- **施加机制**：`sandbox-exec` 子进程 vs `fork + 子进程内 sandbox_init + execve` 二选一（见未澄清问题 Q3）。
- **拒绝检测**：`DenyMechanism::Seatbelt` + exit_code(134/71/1) + stderr 文本兜底；`check` 子命令输出 macOS 能力（Seatbelt 可用性、`sandbox-exec` 存在、DNS socket 路径）。
- **构建可用性**：让 `cargo build` 在 macOS 上通过（`landlock` 依赖门控、`src/linux/*` 全模块 `#[cfg(target_os="linux")]`、`Cargo.toml` target-specific deps）。

### 范围外（明确不做的）

- **CodeWhale 集成适配**：本轮不涉及（用户明确“先把 seabox 搞定”）。
- **syscall 过滤**：Seatbelt 无 seccomp 等价物；`--seccomp-deny-nr` / `--seccomp-filter-fd` 在 macOS 上应为"明确不支持并报错"，**不静默忽略**。
- **namespace 隔离**：macOS 无 user/mount/net/pid ns；`--unshare-*` 在 macOS 上应报错或明确记为 no-op。
- **mount 语义**：`--bind` / `--ro-bind` / `--tmpfs` 无对应物（`--ro-bind` 可用 SBPL 近似只读，但不改变挂载表）。
- **capability 管理**：macOS 无 Linux capabilities。
- **进程信息隔离**：`(allow process-info*)`/`(deny process-info*)` 的进程可见性控制不在本轮。
- **IP / 域名白名单**：Seatbelt 语法层直接拒绝（见实测 §4），本轮只记录限制，不做 eBPF/NEFilter 之类旁路。
- **代码签名 / App Sandbox entitlement**：不涉及。

### 关键场景

1. **默认受限跑构建**：`seabox run --landlock '/:ro' --landlock '~/Develop/proj:rw' -- cargo build`
   → 期望：可读全盘、仅 `~/Develop/proj` 可写、`~/.ssh` `~/.aws` 不可读（若用黑名单式）、`/tmp` 可写（需显式给或内置）。
2. **禁网跑不可信脚本**：`seabox run --unshare-net -- sh script.sh`
   → 期望：任何出站连接失败；loopback 亦不可用（`--allow-network` 才能开）。
3. **只放 443 出站**：`seabox run --allow-network --allow-port 443 -- curl https://example.com`
   → 期望：443 通、80 拒、DNS 正常（隐含 mDNSResponder）。
4. **agent 前台交互 + tty**：`StdioConfig::Fd` + openpty（`sandbox-exec` 原地 exec 语义保证 pid 与 fd 传递正常）。
5. **拒绝可归因**：写越界后 `ExitReason::Denied { mechanism: Seatbelt, .. }`，用户能看懂是哪条规则。

### 异常/边界场景

- 白名单漏路径 → 目标程序 **abort(134)** 而非报"权限不足"（实测 §3）：`classify_exit` 必须把 134 归为 `Denied` 而非 `Program(134)`。
- 已被沙箱化的父进程内再初始化 → `EPERM`（不可嵌套）：macOS 后端须检测并给出清晰错误。
- `sandbox-exec` 在未来系统被移除 → 需 `check` 能诊断并回退到 `sandbox_init`（或反之）。
- 路径含空格/引号/`$` → 必须走 `-D param` 而非字符串拼接（实测 §8）。
- `--seccomp-deny-nr` 在 macOS 被误用 → 必须报错，不能静默漏过安全策略。

### 质量目标

- **语义诚实**：能做的事做好，做不到的（域名/IP 白名单、syscall 过滤）**明确报错**，不制造"看起来安全"的假象——这是本项目"策略驱动替代弹窗"的前提。
- **可用性优先于最小权限**：预设默认取“黑名单 + 写白名单”（`read=All` 零维护）；但 `MacReadMode::Only` 作为可选模式提供，能真正做读隔离（§3 已修订），并需在 `check` 里说明当前形态。
- **零额外进程**：避免多套一层 shell；`sandbox-exec` 已原地 exec，或直接 `sandbox_init`。
- **不回归 Linux**：所有改动不得改变 Linux 现有行为与测试（221 测试基线）。

## 已确认决策（用户）

- **D1 — 配置面分离**：macOS 只提供 **Seatbelt 专属选项**，且**仅在 macOS 生效**。
  不把 Seatbelt 语义挤进 `--landlock` / `--unshare-net` / `NetworkConfig` 等 Linux 形状的配置；
  平台专属面独立成 `MacOsConfig`（对应 `--mac-*` flag 与 `SandboxConfig::with_mac_*`）。
  → 由此 **Q2、Q4 自动关闭**：`--landlock` 与 `NetworkConfig` 保持 Linux 语义不被改写。

### D1 的连带结论（需在设计阶段落实）

1. **Linux 机制在 macOS 上的处置**（按“意图能否兑现”分类，不按 flag 名称）：
   | 类 | 字段 | 处置 |
   |---|---|---|
   | 意图可兑现 | `timeout_*`、`process_group` | 原样生效 |
   | 意图可兑现 | `namespaces.net`（意图=禁网） | **翻译**为“不放任何 `network*` rule”，不是关闭 |
   | 意图可兑现 | `landlock` 的**写侧** | **翻译**为 `file-write*` 白名单 |
   | 只兑现一半 | `landlock` 的**读侧** | 降级 + `PolicyReport` 报告（窄读白名单会 abort 134） |
   | 只兑现一半 | `mount.specs` 的 `ro_bind` | 借道写白名单近似，非挂载表 |
   | 无法兑现 | `namespaces.{user,ipc,pid,uts,cgroup}`、`capabilities` | 警告 + 记录（纵深防御层缺失） |
   | 无法兑现 | `seccomp_deny_nrs` / `seccomp_filter_bytes` | **默认硬错误**（静默丢弃=制造安全假象） |
   | 无法兑现 | `mount` 的 `bind`(写) / `tmpfs` | 默认硬错误 |
2. **`--mac-*` 与 Linux flag 的错配必须报错**：`--mac-*` 出现在 Linux、`--seccomp-deny-nr` 出现在 macOS，均应显式报错，不得静默忽略。
3. **CodeWhale 适配暂不在本轮范围（用户已明确）**：先把 seabox 自身的 macOS 后端做对，集成层后续再说。
   好处：**不再为了兼容下游而在“硬错误 vs 静默降级”上让步**，无法兑现的机制可以放心硬错误。
   仍建议 `PolicyReport` 存在，因为它是 seabox 自身可调试性的需要，不是为集成而加。
4. **`check` 与 `PolicyReport` 必须暴露平台适配结果**，让“哪些配置在 macOS 上没生效”对用户与排障者可见。

## 未澄清问题

> 以下问题需用户确认；未答部分已按"待用户确认"标注，文档按最保守假设落笔。

- [ ] **Q1 — 策略形态（最关键）**：macOS 上默认取哪种？
      (a) 黑名单式：`(allow file-read*)` 全局 + 定向 deny + 写白名单（贴合"读宽写窄"，实现简单，但 `--landlock '/:ro'` 语义退化为"全可读"）；
      (b) 宽白名单：内置基础读集合 + 用户路径（更接近 Landlock 语义，需维护“基础读集合”）。
      → 已实现为双模式：预设用 (a)，(b) 由 `MacReadMode::Only` 提供。早前“(b) 不可行”的结论已被实测推翻（见 §3 修订）。
- [x] ~~**Q2 — `--landlock` 在 macOS 的语义**~~ → **D1 已关闭**：`--landlock` 保持 Linux 语义，macOS 另设 `--mac-*` 面。
- [ ] **Q3 — 施加机制**：`sandbox-exec`（外部进程，deprecated 但稳定、易调试、profile 可用 `-D` 传参）vs `fork + sandbox_init + execve`（零额外进程、可精确控制、但需预编译 profile 且不可嵌套）。是否两者都支持（`sandbox-exec` 作 fallback）？
- [x] ~~**Q4 — 网络配置载体**~~ → **D1 已关闭**：细粒度网络留在 `MacNetworkConfig`（`--mac-allow-inbound/--mac-allow-outbound`），`NetworkConfig.loopback` 保持 Linux 语义。
      （仍有参考价值：inbound/outbound 实测可分离、端口精确匹配，见 §4 矩阵。）
- [ ] **Q5 — 内置放行清单**：`/dev/null` `/dev/tty` `/dev/dtracehelper` `/dev/stdout` `/dev/stderr` `(literal "/")` `/private/var/select/sh` 是否默认全部内置？还是分"最小集 / 兼容集（含 dtracehelper 等）"两档？
- [ ] **Q6 — IP/域名白名单的替代**：Seatbelt 语法硬拒（§4）。是否接受"macOS 上不支持"，还是需要旁路方案（NEFilter/自建代理进程）？若不需要，`docs/arch/ebpf-network-filtering` 要不要同步标注"仅 Linux"？
- [ ] **Q7 — 拒绝归因深度**：是否接受"exit 134/71 + stderr 文本"作为 `Denied` 判据（歧义较高）？要不要额外提供可选的 `--trace-denies`（内部起 `log stream` 抓 `Sandbox:` 日志，需权限）？
- [ ] **Q8 — 平台专属配置的落位**：`MacOsConfig` 作为 `SandboxConfig` 的一个**可选字段**（`Option<MacOsConfig>`，Linux 上为 `None`、不参与任何逻辑），还是独立的构造入口（如 `MacOsSandbox::from_mac_config()`）？
      D1 已确定“两套面分离”，但**CCrate API 形状**未定：前者让调用方写 `cfg` 判断，后者让类型系统直接隔离平台代码。
- [ ] **Q9 — 测试范围**：macOS 集成测试是否按 Linux 的方式（能力缺失自动 skip）？可在无 root、不联网条件下跑的最小用例集是什么？
- [ ] **Q10 — `sandbox-exec` 移除风险**：是否需要现在就做"双通道"（默认 `sandbox_init`，`sandbox-exec` 作为 `check` 检测到 `sandbox_init` 不可用时的回退）？

## 后续建议

- 建议用 `arch-design` 做方案设计，重点在两处真正有分叉的决策：**施加机制（Q3）**、**平台专属配置的 crate API 形状（Q8）**。
  （Q1 策略形态、Q2、Q4 已被 D1 及实测收敛或关闭。）
- 建议先写一个**一次性探针原型**（`examples/` 或 `tests/macos_probe.rs`），把 §3 的"基础读集合"跑在真实 Agent 负载上（`cargo build` / `git clone` / `npm install` / `node` server），量出宽白名单的实际完备度——这是 Q1 的唯一可靠依据。
- 建议在 `docs/macos-sandbox.md` 中**更正**两处已被实测推翻的描述：（1）"网络只有 on/off" → 支持端口/协议/unix-socket，但拒绝域名与 IP；（2）需补充"白名单过窄 → abort 134"这一关键行为。
- 建议同步更新 `docs/development-phases.md` 的 Phase 3 条目，把"跨平台 `Sandbox` enum"改为"复用既有 `SandboxImpl` trait 实现 macOS 后端"（trait 已就位，无需新 enum）。
