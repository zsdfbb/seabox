# Changelog

本文件的格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.1.0] - 2026-11-07

**首个支持 macOS 的版本。** Linux 行为零变化（`git diff` 对 `src/linux/` 为空）。

### 新增

- **macOS Seatbelt 后端**（`--mac-*`）：通过 `/usr/bin/sandbox-exec` 施加 SBPL profile。
  - 三种预设：`--mac-preset read-only` / `workspace-write` / `full-access`
  - 细粒度：`--mac-write` / `--mac-deny-write` / `--mac-workspace` / `--mac-read` /
    `--mac-read-all` / `--mac-deny-read`
  - 网络：`--mac-net deny|loopback|all` + `--mac-net-inbound`
  - 开关：`--mac-no-credential-deny` / `--mac-no-git-write` / `--mac-no-tmp-writable`
  - 内置凭据拒绝清单（`~/.ssh`、`~/.aws`、钥匙串等）
  - fd 清扫：fork 后按 `/dev/fd` 枚举关闭非 `FD_CLOEXEC` 的继承 fd，
    防止宿主的已打开 fd 绕过 Seatbelt（Seatbelt 是 fd 快照语义）
- `seabox check` 在 macOS 上输出 Seatbelt 能力矩阵
- `--version` / `-V`

### 变更（**含 breaking**）

- ⚠️ **`DenyMechanism` 新增 `Seatbelt` 变体**。该枚举无 `#[non_exhaustive]`，
  下游若对它做穷尽 `match` 会编译失败。建议改用 `_ => ..` 或 `if let`。
- ⚠️ **`SandboxConfig` 新增 `pub macos: MacOsConfig` 字段**。该结构体无
  `#[non_exhaustive]`，用结构体字面量完整构造的下游代码会编译失败。
  改用 `..Default::default()` 即可。
- ⚠️ **`landlock` 依赖改为 `cfg(target_os = "linux")` 条件依赖**（此前无条件）。
  非 Linux 平台不再拉取该依赖。
- `seabox --help` 文案不再写「macOS 计划中」。

### 修复

- **发布物修复**：`Cargo.toml` 新增 `exclude`，排除 `Integration/`（指向仓库外的
  悬空软链接，会让 `cargo package` 以 os error 2 失败）、`docs/`、`tmp/` 与
  内部开发文档。此前发布物包含 71 个设计文档与一个无法归档的软链接。

### 测试

- 134 项通过（lib 91 + 集成 41 + doctest 2）
- 新增 `tests/macos_config_test.rs`（15）、`tests/macos_test.rs`（12）、
  `tests/macos_cli_e2e_test.rs`（11）、`tests/cli_meta_test.rs`（3）
- macOS CLI 端到端层此前零覆盖，本轮补齐退出码映射、参数切分、`--chdir`、
  管道与 fd 逃逸

### 已知限制

- **macOS 上 CLI 的拒绝归因只能看退出码**：CLI 走流式 `spawn(Inherit)` 拿不到
  stderr，被 Seatbelt 拒绝的命令显示为普通非零退出（`Program(1)`），而非 `126`。
  要结构化的 `Denied { mechanism: Seatbelt, .. }` 请用库 API `Sandbox::execute()`。
- macOS 网络策略只接受 `*` 与 `localhost`，不支持域名与具体 IP（端口可精确）。
- macOS 无 syscall 过滤 / namespace / capability 等价物，纵深防御弱于 Linux。

## [0.0.2] - 2026-10-30

### 新增

- `Sandbox::spawn` + `SandboxChild`（business-pid 回传，SCM_CREDENTIALS）
- mount namespace：`--unshare-mnt` / `--bind` / `--ro-bind` / `--tmpfs`
- `--allow-network` / `--share-net` 正交组合
- capability 管理：`--cap-add` / `--cap-drop` / `--cap-inherit`

## [0.0.1] - 2026-08-01

首次发布：Landlock 文件系统 ACL + seccomp BPF USER_NOTIF + CLI。
