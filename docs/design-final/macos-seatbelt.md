# Final Design: macOS Seatbelt 后端

- **状态：** Implemented（Phase 3 完成，本机 macOS 27.0.1 / arm64 实测通过）
- **归档设计（详细）：** [`docs/arch/macos-seatbelt/design.md`](../arch/macos-seatbelt/design.md)（1391 行）
- **归档上下文（实测语义基线）：** [`docs/arch/macos-seatbelt/context.md`](../arch/macos-seatbelt/context.md)
- **归档 review：** [`docs/arch/macos-seatbelt/review.md`](../arch/macos-seatbelt/review.md)
- **目标平台：** macOS（Linux 行为零变化）
- **施加机制：** `/usr/bin/sandbox-exec`（SBPL profile 走 `-p`）

---

## 1. 概述

把 seabox 从「仅 Linux」扩展为「Linux + macOS 双后端」。macOS 侧用 **Seatbelt（SBPL + `sandbox-exec`）**
实现文件系统写白名单、凭据黑名单与端口级网络控制。

三个刻意不做的事：

1. **不追求与 Linux 能力对等**。Seatbelt 无 syscall 过滤、无 namespace、无 capability。
   强行模拟会产生「看起来有、实际没有」的保护——这正是本项目最该避免的失效模式。
2. **不做读侧白名单默认**。预设默认 `MacReadMode::All`（读全盘 + 凭据黑名单）。
   `Only` 模式存在且可用，但需要显式 `--mac-read` 启用，因为窄白名单极易触发 dyld abort(134)。
3. **不改 Linux 任何一行**。`git diff src/linux/` 必须为空（已验证）。

---

## 2. 最终架构

### 2.1 模块分层（mac 与 linux 彻底拆分的落点）

```
src/macos/
├── mod.rs      # pub mod config; pub mod sbpl;  #[cfg(macos)] pub(crate) mod imp;
├── config.rs   # 无条件编译，纯逻辑，Linux CI 可单测（969 行，16 个测试）
├── sbpl.rs     # 无条件编译，SBPL 生成器（1151 行，18 个测试）
└── imp.rs      # #[cfg(target_os = "macos")] 整模块门控（881 行，7 个测试）
```

**为什么这样切**：`config` 与 `sbpl` 是纯字符串/结构体逻辑，不该被 `libc` 和 `sandbox-exec`
拖成 macOS-only——否则 Linux CI 完全无法验证最容易出错的配置合并与 SBPL 段序。
只有真正触碰 syscall 与进程的 `imp.rs` 才门控。

**双向零引用**（N13，已验证）：
```
grep -rn 'macos' src/linux/      → 空
grep -rn 'crate::linux' src/macos/ → 空
```

### 2.2 施加链路

```
Sandbox::from_config(cfg)
  └─ create_sandbox_impl(cfg)
      └─ MacSandbox::new(&cfg.macos, cwd)      ← 构造期完成全部校验
          ├─ 1. policy.validate()               注入字符 / 空 Only 列表
          ├─ 2. policy.resolve(cwd)             预设 + 字段合并成定型策略
          ├─ 3. sbpl::build(&policy, cwd)       生成 7 段固定顺序 profile + -D 参数表
          └─ 4. canary_check(&plan, &policy)    跑一个「应当被拒」的探针

Sandbox::execute(spec)
  └─ run_to_output(spawn(Piped))               ← 平台无关，复用 src/child.rs
      └─ MacSandbox::spawn
          ├─ require_sandbox_exec()            缺失即 bail!，绝不降级为无沙箱
          ├─ sandbox-exec -D k=v ... -p <profile> -- <prog> <args>
          └─ pre_exec: setpgid(0,0) + close(每个泄漏 fd)   ← 零堆操作
```

### 2.3 三道防线

| 防线 | 位置 | 拦截的失效模式 |
|---|---|---|
| **构造期校验** | `MacSandbox::new` | 配置错误（注入字符、不存在的路径）在执行前暴露 |
| **canary 预检** | `canary_check` | 「profile 合法但策略未生效」（如误写 `allow default`）——`sandbox-exec` 不会报错 |
| **fd 清扫** | `pre_exec` | Seatbelt 是 **fd 快照语义**，施加前已打开的 fd 不受约束，可完全绕过沙箱 |

第三道最容易被忽略却最致命：父 shell `exec 9>host.txt` 后启动沙箱，
沙箱内 `echo PWNED >&9` 直接写入宿主文件。实测验证清扫后报 `9: Bad file descriptor`、
宿主文件内容不变（`tests/macos_test.rs::f1_preexisting_fd_is_swept_and_cannot_escape`）。

**fd 清扫用 `/dev/fd` 枚举**（macOS 无 `close_range`）：实测 `~0.026 ms`，
对比 `close(3.._SC_OPEN_MAX)` 的 `~14.5 ms` 快 500 倍。必须过 `FD_CLOEXEC` 过滤。

---

## 3. 关键决策（完整论证见 design.md 附录 A）

| # | 决策 | 理由 |
|---|---|---|
| 1 | **`sandbox-exec` 而非 `sandbox_init()`** | `sandbox_init` 在 4/4 坏 profile 下返回 -1 但进程无沙箱运行（fail-open）；`sandbox-exec` fail-closed rc=65。且它原地 exec，business-pid 天然成立 |
| 2 | **`Option<bool>` 而非 `bool`** | 区分「未设置」与「显式 false」，否则「用预设但显式关某项」无法表达 |
| 3 | **`net: Option<MacNetConfig>`** | `--mac-net deny` 与默认值**值相等**，用 `PartialEq` 判会静默丢失「用户显式配了」 |
| 4 | **`is_configured()` 逐字段显式检查** | 严禁 `self != &Default::default()`（同 #3 的陷阱） |
| 5 | **`Vec` 追加、`Option` 覆盖** | 静默丢弃内置凭据清单是安全回退，用户加限制是理性行为 |
| 6 | **SBPL 规则顺序 = 安全边界** | 实测「后写赢」，与 specificity 无关。固定 7 段顺序写死在生成器内，不提供按名追加的 API |
| 7 | **路径全走 `-D k=v` 参数化** | 绝不拼进 SBPL 字符串；禁止 `prefix`（字符串前缀会跨目录越权） |
| 8 | **`classify_output` 新接口（默认委托）** | `classify_exit` 拿不到 stderr，而拒绝不会可靠传播为退出码。加默认实现使 Linux 零改动 |
| 9 | **CLI flags 不加 cfg 门控** | cfg 掉会让 clap 报 "unexpected argument"，用户拿不到「请改用 `--landlock`」的建议 |
| 10 | **`--mac-workspace` 替换而非追加** | 追加会让 cwd 仍可写，结果比用户意图更宽——安全方向错误 |

---

## 4. 实现期的三处修正（设计缺口，非实现 bug）

### 4.1 内置凭据路径常态缺失

设计 §6.2 要求路径 `canonicalize` 失败即硬错误（因为 `sandbox-exec` 对不存在的 `-D`
路径不报错、规则静默失效）。但内置凭据清单 `~/.ssh` `~/.aws` `~/.gnupg` 等 8 条在
干净机器上**常态缺失**——硬错误会让沙箱在任何机器上都不可用。

**解法**：`norm()` 严格（allow 侧，失败即 bail）、`norm_deny()` 宽松（deny 侧，
canonicalize 最深已存在祖先 + 拼回尾部）。拒绝项保留，目标稍后创建时仍生效。

### 4.2 `--mac-workspace` 语义错误

初版实现为 `self.with_mac_write(path)`（追加），而 `resolve()` 在 `WorkspaceWrite`
预设下**无条件** push cwd。结果 `--mac-preset workspace-write --mac-workspace /other`
得到 `write == [cwd, /other]`，**cwd 仍可写**，用户指定的路径完全没成为「写根」。

**解法**：加 `workspace: Option<PathBuf>` 字段，`resolve()` 在 `WorkspaceWrite` 下
用 `workspace.unwrap_or(cwd)` **替换**。已实测验证：指定 `--mac-workspace /tmp/x` 后
cwd 不再可写。

### 4.3 `trait object` 看不见固有方法

`Sandbox::execute` 通过 `Box<dyn SandboxImpl>` 调用，方法解析只看得到 trait 方法。
`MacSandbox` 上的固有方法 `classify_output` 对 trait object **不可见**，不写
`impl SandboxImpl` 里的 override 就静默退回默认实现（委托 `classify_exit`），
于是「被 Seatbelt 拒绝」被误报为普通 `Program(1)`。

**解法**：在 `impl SandboxImpl for MacSandbox` 里显式 override 并转调固有方法。
这是 Rust 方法解析的经典陷阱，已加注释标记。

---

## 5. 实测验证（本机 macOS 27.0.1 / arm64）

### 5.1 端到端行为

```bash
$ seabox run --mac-preset read-only -- sh -c 'cat /etc/hosts >/dev/null && echo ok'
ok                                              # 读全盘

$ seabox run --mac-preset read-only -- sh -c 'echo x > $HOME/x.txt'
sh: /Users/zs/x.txt: Operation not permitted    # TMPDIR 外写被拒

$ seabox run --mac-preset workspace-write -- sh -c 'touch .p && rm .p && echo ok'
ok                                              # workspace 可写

$ seabox run --mac-preset full-access -- sh -c 'touch /tmp/x && echo ok'
ok                                              # 不限制（仍有 SIP/setuid 硬限制）
```

### 5.2 两道闸门

```bash
# canary：正常策略通过
$ seabox run --mac-preset read-only -- true     # 无 canary 报错

# fd 逃逸：清扫生效
$ ( exec 9>/tmp/f/host.txt; seabox run --mac-write /tmp/f -- sh -c 'echo PWNED >&9' )
sh: 9: Bad file descriptor
$ cat /tmp/f/host.txt                            # 内容不变
```

### 5.3 归因

库 API 路径（`execute`，能拿 stderr）：

```rust
let (out, reason) = sb.execute(&spec)?;
// reason == Denied { mechanism: Seatbelt, message: "Seatbelt denied ... Operation not permitted" }
```

CLI 路径（流式 `Inherit`）拿不到 stderr，降级为普通非零退出——已在 README
「已知限制」中写明。

---

## 6. 测试结果

```
cargo test（macOS 27.0.1 / arm64）
─────────────────────────────────────────────
lib 单元测试                    91 passed
tests/macos_config_test.rs      11 passed    N9 / N10 / H1-H3
tests/macos_test.rs             10 passed    N6 / N7 / H4 / H5
doc tests                        2 passed
Linux 门控测试文件（12 个）      0 passed（在 macOS 上编译为空，预期）
─────────────────────────────────────────────
合计                           114 passed, 0 failed
```

`cargo clippy --lib --bins --tests -- -D warnings` 干净；`cargo fmt --check` 干净。

### 合同 N1-N13 状态

| 编号 | 内容 | 状态 |
|---|---|---|
| N1 | 依赖改 target-specific，macOS `build --lib` 通过 | ✅ |
| N2 | 12 测试文件 + `syscall_probe` 门控，`build --bins --tests` 通过 | ✅ |
| N3 | 4 类型 Default 全为 None/空 | ✅ |
| N4 | `resolve()` / `is_configured()` 单测 A1-A10 | ✅ |
| N5 | SBPL 生成器单测 B1-B8（18 个） | ✅ |
| N6 | `sandbox-exec` 端到端 D1-D3 | ✅ |
| N7 | 两道闸门 F1 / F5 | ✅ F1 实测；F5 由 canary 实现 + 单测覆盖 |
| N8 | `classify_output` G1-G7 | ✅ G1-G5 + 2 条额外；G6/G7 由 `Sandbox::execute` 层保证 |
| N9 | 12 个 `--mac-*` + `with_*` | ✅ |
| N10 | 双向硬错误 H1/H2/H3 | ✅ |
| N11 | `check` macOS 输出 H4 | ✅ |
| N12 | Linux 221 基线不变 | ⚠️ **MANUAL_ACK_REQUIRED** |
| N13 | 双向 grep 为空 | ✅ |

**N12 说明**：本机无任何 Linux 运行时（`docker` / `podman` / `limactl` / `colima` /
`multipass` / `orb` 全无），无法自动化验证。可提供的静态证据：
`git diff <baseline> -- src/linux/` 为空；`src/lib.rs` 的 Linux 分支未改；
12 个 Linux 测试文件各只增加一行 `#![cfg(target_os = "linux")]`。
**需要具备 Linux 环境的执行者确认 `cargo test` 仍为 221 通过。**

---

## 7. 已知限制

1. **纵深防御弱于 Linux**：无 syscall 过滤、无 namespace、无 capability，读侧默认零隔离。
2. **网络不支持域名与具体 IP**：SBPL 语法层只接受 `*` 与 `localhost`，端口可精确到号。
3. **CLI 归因降级**：流式路径拿不到 stderr，需用库 API 才能获得结构化 `Denied`。
4. **setuid 程序在沙箱内不可用**：`ps` `top` `su` `atq` `crontab` `newgrp` 全被拒，
   任何 profile 都放不通。`seabox check` 单独列出此条。
5. **canary 在极端配置下无可用探针**：既无「可写但被拒」的目录、又无 `deny_read` 时，
   显式警告并继续执行（不静默）。

---

## 8. 涉及文件

| 文件 | 性质 | 行数 |
|---|---|---|
| `src/macos/config.rs` | 新增，无条件编译 | 969 |
| `src/macos/sbpl.rs` | 新增，无条件编译 | 1151 |
| `src/macos/imp.rs` | 新增，`#[cfg(macos)]` 门控 | 881 |
| `src/macos/mod.rs` | 新增 | 13 |
| `src/lib.rs` | 修改（5 处交叉点 + check 分支） | +276 |
| `src/config.rs` | 修改（`macos` 字段 + 9 个委托） | +66 |
| `src/cli.rs` | 修改（12 个 flag + 双向硬错误） | +206 |
| `src/bin/syscall_probe.rs` | 修改（非 Linux 退出 77） | +24 |
| `Cargo.toml` | 修改（landlock 移入 target-specific） | +4/-4 |
| `tests/*.rs`（12 个） | 修改（各 +1 行 `#![cfg(linux)]`） | +24 |
| `tests/macos_config_test.rs` | 新增 | — |
| `tests/macos_test.rs` | 新增 | — |
| `docs/macos-sandbox.md` | 更新（状态 + 两处实测补充） | — |
| `README.md` | 更新（平台表 + macOS 快速上手 + 已知限制） | — |
