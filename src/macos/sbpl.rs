//! SBPL（Sandbox Profile Language）文本生成器。
//!
//! **规则顺序就是安全边界。** 实测证明 SBPL 是「后写赢」：同一对规则仅交换书写顺序，
//! 结果就反转（`docs/arch/macos-seatbelt/design.md` §6.1）。任何一次「顺手调换两行」
//! 都能静默放开策略，且不产生任何错误或警告——因此段落顺序在本文件内**写死、不可配置**，
//! 用户输入（`--mac-write` / `--mac-deny-read` 等列表）只影响段内条目，绝不影响段落位置。
//!
//! 固定 7 段顺序（design §6.1）：
//!
//! ```text
//! 1  (version 1)
//! 2  (deny default)   | FullAccess: (allow default)
//! 3  floor（进程 / ipc / sysctl / 读 / 隐式写点）
//! 4  预设写白名单（ReadOnly 无；WorkspaceWrite: WS + carve-out；FullAccess 无）
//! 5  TMP 可写
//! 6  deny_write（凭据写侧）+ deny_read（凭据读侧 + 用户追加）  ← 最后一条 file 规则
//! 7  network（最末）
//! ```
//!
//! 另外三条硬约束：
//!
//! - **只用 `subpath` / `literal`**，禁用 `prefix`：`prefix` 是字符串前缀，`prefix "/proj"`
//!   会连带允许 `/proj-backup`（design §6.4）。
//! - **所有路径走 `-D` 参数化**（`param "WS"` 等），绝不拼进 SBPL 字符串，防注入（design §6.5）。
//! - **路径一律经 [`norm`]**：`~` 展开 + `fs::canonicalize`。`subpath` 按字面比较、不解析
//!   symlink，不规范化就永不匹配且无提示；`-D` 传不存在的路径 `sandbox-exec` 也不报错，
//!   规则静默失效——所以 `canonicalize` 失败必须硬错误（design §6.2）。
//!
//! **本文件无条件编译**（无 `#[cfg(target_os = "macos")]` 门控）：只依赖 `std` + `anyhow`，
//! 不含任何 macOS-only 符号（不碰 `/dev/fd`、不碰 `/usr/bin/sandbox-exec`、不碰 libc），
//! 因此 Linux CI 可完整单测其全部逻辑分支（design §3.1 / §11.1）。

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::config::{MacReadMode, NetAccess, ResolvedPolicy};

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// 一份待施加的 Seatbelt 计划：SBPL 文本 + 配套的 `-D` 参数表。
///
/// 施加侧（`imp.rs`）只需为每个参数拼一条 `-D k=v`、再 `-p <profile>`，
/// 不参与任何字符串构造，因此顺序正确性完全由 [`build`] 保证。
///
/// `params` 中的值均已规范化（[`norm`] 过），且键被引用次数 ≥ 1 ——
/// 引用未定义的 param 会让 `sandbox-exec` rc=65（design §6.5）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// 完整 SBPL 文本（可直接作为 `sandbox-exec -p` 的实参）。
    pub profile: String,
    /// `-D` 参数表：`(key, value)`。值均为绝对路径字符串。
    pub params: Vec<(String, String)>,
}

impl Plan {
    /// 取某个参数的值（测试与诊断用；未定义返回 `None`）。
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

/// 按固定段落顺序把定型策略渲染成 [`Plan`]。
///
/// 段落顺序（不可配置，见模块文档）：
///
/// 1. `(version 1)`
/// 2. `(deny default)`；[`ResolvedPolicy::full_access`] 时为 `(allow default)`
/// 3. floor：硬性地板（所有模式）+ 系统地板（仅 [`MacReadMode::Only`]）+ 读侧按模式
/// 4. 预设写白名单（`ReadOnly` / `FullAccess` 无；`WorkspaceWrite` 用 `WS`，可 carve out `.git`）
/// 5. `TMP` 可写
/// 6. 凭据写拒绝 + 读拒绝（含用户追加）——**最后一条 file 规则**
/// 7. 网络（最末）
///
/// `cwd` 只用于派生 `WorkspaceWrite` 的 `.git` carve-out 路径（`WS/.git`），
/// 本身不会被直接写入规则（`WS` 由 `policy.write` 提供）。
pub(crate) fn build(policy: &ResolvedPolicy, cwd: &Path) -> Result<Plan> {
    let mut b = Builder::new();

    // ── 1. (version 1) ──
    b.push_header();

    // ── 2. 默认动作 ──
    b.push_default_action(policy.full_access);

    // ── 3. floor ──
    b.push_floor();
    b.push_system_floor(&policy.read);
    b.push_read_mode(&policy.read)?;

    // ── 4. 预设写白名单 ──
    b.push_write_whitelist(policy, cwd)?;

    // ── 5. TMP 可写 ──
    b.push_tmp(policy.tmp_writable, policy.full_access)?;

    // ── 6. deny_write / deny_read（最后一条 file 规则）──
    b.push_deny_write(&policy.deny_write)?;
    b.push_deny_read(&policy.deny_read)?;

    // ── 7. network（最末）──
    b.push_network(policy)?;

    Ok(b.finish())
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// 段落顺序的唯一实现者：方法是私有且**调用顺序固定**在 [`build`] 内。
///
/// 刻意**不**提供「按名字追加任意段落」之类的公开入口：只要没有这样的 API，
/// 就不存在从外部改变段落顺序的途径。
struct Builder {
    out: String,
    params: Vec<(String, String)>,
    /// 已经定义过的参数键（去重：同一路径被多次引用时只发一条 `-D`）。
    defined: Vec<String>,
}

impl Builder {
    fn new() -> Self {
        Self {
            out: String::new(),
            params: Vec::new(),
            defined: Vec::new(),
        }
    }

    // ── 段 1 ──

    fn push_header(&mut self) {
        self.out.push_str("(version 1)\n");
    }

    // ── 段 2 ──

    /// `FullAccess` 用 `(allow default)`：全放语义，不设半吊子状态（design §7.4）。
    fn push_default_action(&mut self, full_access: bool) {
        if full_access {
            self.out.push_str("(allow default)\n");
        } else {
            self.out.push_str("(deny default)\n");
        }
    }

    // ── 段 3：floor ──

    /// 硬性地板：所有模式逐字相同（design §7.1）。
    ///
    /// 其中三项是后期调试出来的「实测必需」，掉进去的代价是工具莫名失败且错误信息
    /// 不指向根因：`file-read* (subpath "/dev")`、`ipc-posix-shm`、
    /// `file-ioctl (literal "/dev/dtracehelper")`。
    fn push_floor(&mut self) {
        self.out.push_str(
            r#"
; --- floor: 进程 / ipc / sysctl / 元数据（所有模式必含）---
(allow process*)
(allow sysctl-read)
(allow mach-lookup)
(allow ipc-posix-sem)
(allow ipc-posix-shm)
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
"#,
        );
    }

    /// 系统地板：仅 [`MacReadMode::Only`] 需要（design §7.1）。
    ///
    /// `(literal "/")` 是防 abort(134) 的；`/etc` 与 `/tmp` 是符号链接，
    /// 只放 `/private/*` 不生效，故两条 `literal` 必须并列存在。
    fn push_system_floor(&mut self, read: &MacReadMode) {
        if !matches!(read, MacReadMode::Only(_)) {
            return;
        }
        self.out.push_str(
            r#"
; --- 系统地板（MacReadMode::Only 自动附带）---
(allow file-read* (literal "/"))
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/Library"))
(allow file-read* (subpath "/private/var/db"))
(allow file-read* (subpath "/private/etc"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/sbin"))
(allow file-read* (subpath "/var"))
(allow file-read* (literal "/etc"))
(allow file-read* (literal "/tmp"))
"#,
        );
    }

    /// 读侧按模式：`All` ⇒ 一条 `(allow file-read*)`；`Only` ⇒ 每个 root 一条（参数化）。
    fn push_read_mode(&mut self, read: &MacReadMode) -> Result<()> {
        match read {
            MacReadMode::All => {
                self.out
                    .push_str("\n; --- 读侧：全开（凭据 denylist 在段 6 补偿）---\n");
                self.out.push_str("(allow file-read*)\n");
            }
            MacReadMode::Only(roots) => {
                if roots.is_empty() {
                    bail!("macOS read mode `Only` requires at least one path");
                }
                self.out.push_str("\n; --- 读侧：仅白名单根 ---\n");
                for (i, root) in roots.iter().enumerate() {
                    let key = format!("R{i}");
                    let value = self.def_param(&key, root)?;
                    let _ = writeln!(
                        self.out,
                        "(allow file-read* (subpath (param \"{key}\")))  ; {value}"
                    );
                }
            }
        }
        Ok(())
    }

    // ── 段 4：预设写白名单 ──

    /// 写白名单：`ReadOnly` / `FullAccess` 不产生本段（design §7.2 / §7.4）。
    ///
    /// `WorkspaceWrite` 的 `WS` 是 `policy.write[0]`（[`super::config::MacOsConfig::resolve`]
    /// 已把 cwd 填入首位），其余条目编号 `W0..Wn`。
    ///
    /// `allow_git_write == false` 时，`WS` 那条**在同一条规则内**嵌
    /// `(require-all (subpath "WS") (require-not (subpath "GIT")))`——不能另起一行写
    /// deny：后写赢，子树的 allow 会覆盖它（design §6.2b / §6.3）。
    ///
    /// `GIT` = `<workspace 根>/.git` 的规范化路径。workspace 根取 `cwd`（`WorkspaceWrite`
    /// 预设的语义就是「cwd 可写」，[`super::config::MacOsConfig::resolve`] 也把 cwd 放在 `write[0]`），
    /// 仅当 `cwd` 不在 `write` 列表里时才退回 `write[0]`——避免调用方传了与策略不一致的
    /// `cwd` 时把 carve-out 指到错误目录。
    fn push_write_whitelist(&mut self, policy: &ResolvedPolicy, cwd: &Path) -> Result<()> {
        if policy.full_access {
            return Ok(());
        }
        // 空 write 不得产生 `(subpath "")`，也不得产生空段落。
        let (first, rest) = match policy.write.split_first() {
            Some(split) => split,
            None => return Ok(()),
        };

        // WorkspaceWrite 语义下 write[0] 即 workspace 根；ReadOnly 预设的 write 恒为空，
        // 故凡有条目就按 workspace 处理（`WS` 命名，含 `.git` carve-out 语义）。
        let ws = self.def_param("WS", first)?;
        let ws_rule = if policy.allow_git_write {
            format!("  (subpath (param \"WS\"))  ; {ws}\n")
        } else {
            let git_base: &Path = if policy.write.iter().any(|p| p == cwd) {
                cwd
            } else {
                first
            };
            let git_dir = git_base.join(".git");
            let git = self.def_param("GIT", &git_dir)?;
            format!(
                "  (require-all\n    (subpath (param \"WS\"))\n    (require-not (subpath (param \"GIT\"))))  ; {ws} 除 {git}\n"
            )
        };

        let mut body = String::new();
        body.push_str(&ws_rule);
        for (i, extra) in rest.iter().enumerate() {
            let key = format!("W{i}");
            let value = self.def_param(&key, extra)?;
            let _ = writeln!(body, "  (subpath (param \"{key}\"))  ; {value}");
        }

        self.out
            .push_str("\n; --- 写白名单（workspace + --mac-write 追加）---\n");
        self.out.push_str("(allow file-write*\n");
        self.out.push_str(&body);
        self.out.push_str(")\n");
        Ok(())
    }

    // ── 段 5：TMP 可写 ──

    /// TMPDIR 可写（design §7.2 / §7.3）。
    ///
    /// `FullAccess` 下 `(allow default)` 已涵盖全部写权限，本段冗余，故不产生
    /// （design §7.4：全放语义，不设半吊子状态；少一条 param 也少一处误配面）。
    ///
    /// 走 `std::env::temp_dir()`（不引入 `dirs`：那是 `cli` feature 的可选依赖），
    /// `$TMPDIR` 的 `/var/folders/...` 经 [`norm`] 变成 `/private/var/folders/...`。
    fn push_tmp(&mut self, tmp_writable: bool, full_access: bool) -> Result<()> {
        if !tmp_writable || full_access {
            return Ok(());
        }
        let dir = std::env::temp_dir();
        let value = self.def_param("TMP", &dir)?;
        self.out.push_str("\n; --- TMP 可写 ---\n");
        let _ = writeln!(
            self.out,
            "(allow file-write* (subpath (param \"TMP\")))  ; {value}"
        );
        Ok(())
    }

    // ── 段 6：deny（最后一条 file 规则）──

    /// 凭据写侧拒绝。必须晚于写白名单（后写赢），否则被 allow 覆盖（design §4.4）。
    fn push_deny_write(&mut self, deny_write: &[PathBuf]) -> Result<()> {
        if deny_write.is_empty() {
            return Ok(());
        }
        let mut body = String::new();
        for (i, p) in deny_write.iter().enumerate() {
            let key = format!("DW{i}");
            let value = self.def_deny_param(&key, p)?;
            let _ = writeln!(body, "  (subpath (param \"{key}\"))  ; {value}");
        }
        self.out
            .push_str("\n; --- 凭据写拒绝（必须在写白名单之后）---\n");
        self.out.push_str("(deny file-write*\n");
        self.out.push_str(&body);
        self.out.push_str(")\n");
        Ok(())
    }

    /// 读侧拒绝（凭据 + 用户追加）。**必须是最后一条 file 规则**（design §6.1）。
    fn push_deny_read(&mut self, deny_read: &[PathBuf]) -> Result<()> {
        if deny_read.is_empty() {
            return Ok(());
        }
        let mut body = String::new();
        for (i, p) in deny_read.iter().enumerate() {
            let key = format!("D{i}");
            let value = self.def_deny_param(&key, p)?;
            let _ = writeln!(body, "  (subpath (param \"{key}\"))  ; {value}");
        }
        self.out
            .push_str("\n; --- 凭据读拒绝（最后一条 file 规则）---\n");
        self.out.push_str("(deny file-read*\n");
        self.out.push_str(&body);
        self.out.push_str(")\n");
        Ok(())
    }

    // ── 段 7：network（最末）──

    /// 网络段，与预设正交（design §8）。
    ///
    /// `Deny` 默认不写规则（`(deny default)` 已覆盖），但 `FullAccess` 下必须补一条
    /// `(deny network*)`——靠后写赢兜住 `(allow default)`（design §7.4）。
    ///
    /// `Loopback` / `Ports` 恒定附带 mDNSResponder unix-socket：漏掉时
    /// `curl` 报 `Could not resolve host`（rc=6）。
    fn push_network(&mut self, policy: &ResolvedPolicy) -> Result<()> {
        match &policy.net.outbound {
            NetAccess::Deny => {
                if policy.full_access {
                    self.out
                        .push_str("\n; --- network：FullAccess 下显式禁网（后写赢）---\n");
                    self.out.push_str("(deny network*)\n");
                }
                // 非 FullAccess：不写规则，(deny default) 已覆盖。
            }
            NetAccess::Loopback => {
                self.out.push_str("\n; --- network：仅 loopback ---\n");
                self.out
                    .push_str("(allow network-outbound (remote ip \"localhost:*\"))\n");
                if policy.net.inbound_loopback {
                    self.out
                        .push_str("(allow network-inbound (local ip \"localhost:*\"))\n");
                }
                self.push_mdns_socket();
            }
            NetAccess::Ports(ports) => {
                self.out
                    .push_str("\n; --- network：仅指定端口（含 DNS socket）---\n");
                for port in ports {
                    // 端口级通配：SBPL 只接受 `*` 或 `localhost` 作 host，域名/IP 白名单不可表达。
                    let _ = writeln!(
                        self.out,
                        "(allow network-outbound (remote ip \"*:{port}\"))"
                    );
                }
                self.push_mdns_socket();
            }
            NetAccess::All => {
                self.out.push_str("\n; --- network：全放 ---\n");
                self.out.push_str("(allow network*)\n");
            }
        }
        Ok(())
    }

    /// DNS 解析所需的 mDNSResponder unix socket（design §8）。
    fn push_mdns_socket(&mut self) {
        self.out.push_str(
            "(allow network-outbound (remote unix-socket (path \"/private/var/run/mDNSResponder\")))\n",
        );
    }

    // ── 参数表 ──

    /// 规范化并登记一个参数，返回规范化后的值（供注释里标注真实路径）。
    ///
    /// 同一键已被定义过时**不再**追加（键与值的映射由首次调用决定，后续同名键必须同值，
    /// 这是 [`build`] 的结构性保证：每个键只在一个位置生成）。
    fn def_param(&mut self, key: &str, path: &Path) -> Result<String> {
        self.register(key, norm(path)?)
    }

    /// deny 段专用：路径可以不存在（见 [`norm_deny`]）。
    ///
    /// 只有**授权**（allow）路径的丢失是危险的——沙箱看起来在工作、实际少了权限或多了权限；
    /// **拒绝**路径不存在则没有可保护的内容，宁可保留规则也不硬错误：内置凭据清单
    /// （`~/.aws` / `~/.kube` …）在真实机器的常态就是部分不存在，硬错误会让沙箱在任何
    /// 干净机器上直接不可用。
    fn def_deny_param(&mut self, key: &str, path: &Path) -> Result<String> {
        self.register(key, norm_deny(path)?)
    }

    /// 登记 `-D` 参数（键去重，值首次调用决定）。
    fn register(&mut self, key: &str, normalized: PathBuf) -> Result<String> {
        let value = normalized.to_string_lossy().into_owned();
        if !self.defined.iter().any(|k| k == key) {
            self.defined.push(key.to_string());
            self.params.push((key.to_string(), value.clone()));
        }
        Ok(value)
    }

    fn finish(self) -> Plan {
        Plan {
            profile: self.out,
            params: self.params,
        }
    }
}

// ---------------------------------------------------------------------------
// norm
// ---------------------------------------------------------------------------

/// 路径规范化：唯一的路径入口（design §6.2）。
///
/// 三步：`~` 展开 → 注入字符校验 → `fs::canonicalize`。
///
/// **`canonicalize` 失败即硬错误**：`-D` 传不存在的路径，`sandbox-exec` 不报错，
/// 规则静默失效——这种「看起来在工作」的失效模式必须在这里拦死。
///
/// 反斜杠不在拒绝列表内：它只出现在注释里（SBPL 无转义需求），
/// 关键字符（`"` / `)` / `;` / 换行）已全部拒绝。
pub(crate) fn norm(p: &Path) -> Result<PathBuf> {
    let expanded = expand_tilde(p);
    check_injection(&expanded)?;
    fs_canonicalize(&expanded).with_context(|| {
        format!(
            "macOS sandbox path does not exist or is not accessible: {} \
             (sandbox-exec does not report missing -D paths, so this must be an error)",
            expanded.display()
        )
    })
}

/// `~` / `~/foo` 展开为 `$HOME`。
///
/// 用 `$HOME` 而非 `dirs::home_dir()`：`dirs` 是 `cli` feature 的可选依赖，
/// 而本文件无条件编译，只能依赖 `std`（与 `src/config.rs` 的 `expand_tilde` 同策略）。
/// `$HOME` 缺失时保留 `~` 前缀，交给 `canonicalize` 报错——不静默猜测。
fn expand_tilde(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if s == "~" || s.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            let rest = s.strip_prefix('~').unwrap_or("");
            let mut out = PathBuf::from(home);
            let rest = rest.trim_start_matches('/');
            if !rest.is_empty() {
                out.push(rest);
            }
            return out;
        }
    }
    p.to_path_buf()
}

/// 拒绝含 SBPL 元字符的路径（防注入：破坏 profile 结构）。
fn check_injection(p: &Path) -> Result<()> {
    let s = p.to_string_lossy();
    for bad in ['"', ')', ';', '\n', '\r'] {
        if s.contains(bad) {
            bail!(
                "macOS sandbox path contains reserved SBPL character {:?}: {}",
                bad,
                p.display()
            );
        }
    }
    Ok(())
}

/// deny 段专用路径规范化：**允许路径不存在**（与 [`norm`] 的严格性对照）。
///
/// 语义：先做 `~` 展开 + 注入校验；`canonicalize` 成功就用结果，失败则对**最深的已存在祖先**
/// 做 `canonicalize` 再把剩余尾部拼回。
///
/// 为什么 deny 侧不能硬错误：
///
/// 1. 内置凭据清单（`~/.ssh` / `~/.aws` / `~/.docker/config.json` …）在任何真实机器上
///    都必然有若干条不存在。若硬错误，沙箱在干净机器上完全不可用（设计 §4.4 的清单
///    是**黑名单**，命中才需要保护）。
/// 2. 拒绝不存在的东西没有可保护的内容：规则要么匹配不到（等价于跳过），要么在目标稍后
///    被创建时仍然生效——后者比静默丢弃更安全，故**不丢弃**规则。
///
/// 残余风险：尾部不存在的分量无法解析 symlink。若用户给一条当前不存在、且路径前缀本身
/// 是 symlink 的拒绝项（如 `/var/log/secret`），祖先规范化已把 `/var` 解析为 `/private/var`，
/// 剩下未解析的只有不存在的部分，误匹配面为零。
pub(crate) fn norm_deny(p: &Path) -> Result<PathBuf> {
    let expanded = expand_tilde(p);
    check_injection(&expanded)?;
    if let Ok(canonical) = fs_canonicalize(&expanded) {
        return Ok(canonical);
    }

    // 逐级向上找到第一个能 canonicalize 的祖先，再把尾部拼回。
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = expanded.as_path();
    loop {
        if let Ok(canonical) = fs_canonicalize(cur) {
            let mut out = canonical;
            for name in tail.iter().rev() {
                out.push(name);
            }
            return Ok(out);
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_os_string());
                cur = parent;
            }
            _ => bail!(
                "macOS sandbox deny path cannot be resolved at all: {}",
                expanded.display()
            ),
        }
    }
}

/// `fs::canonicalize` 的薄封装（`std` API，无条件编译）。
fn fs_canonicalize(p: &Path) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(p)
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::config::{MacOsConfig, MacPreset};

    // ── 辅助 ──

    /// 把路径里所有 `"` 换成不会注入 SBPL 的样子——测试用临时目录名是安全的，
    /// 但 macOS 的 `$TMPDIR` 路径可能含任意字符，故构造策略时统一走真目录。
    fn policy_of(preset: MacPreset, net: NetAccess, cwd: &Path) -> ResolvedPolicy {
        MacOsConfig::default()
            .with_mac_preset(preset)
            .with_mac_net(net)
            .resolve(cwd)
    }

    fn build_ok(policy: &ResolvedPolicy, cwd: &Path) -> Plan {
        build(policy, cwd).unwrap_or_else(|e| panic!("build failed: {e:#}"))
    }

    /// **段序断言（B1）——这是安全防线，不是格式检查。**
    ///
    /// 只断言字符串相对位置，不比对全量文本：`canonicalize` 结果平台相关
    /// （design §11.2）。任何改段落顺序的改动都会在这里变红。
    fn assert_section_order(profile: &str) {
        let pos = |needle: &str| {
            profile
                .find(needle)
                .unwrap_or_else(|| panic!("missing section: {needle:?}"))
        };
        // 段 2 的默认动作：非 FullAccess 是 (deny default)，FullAccess 是 (allow default)。
        let default_action = if profile.contains("(deny default)") {
            "(deny default)"
        } else {
            "(allow default)"
        };
        let order = [
            "(version 1)",
            default_action,
            "(allow file-read-metadata)", // floor 起点
        ];
        let mut last = pos(order[0]);
        for needle in &order[1..] {
            let cur = pos(needle);
            assert!(
                last < cur,
                "section out of order: {needle:?} at {cur} not after {last}"
            );
            last = cur;
        }

        // floor 的隐式写点必须也在 floor 内（早于任何 user 段）。
        let dev_null = pos("(literal \"/dev/null\")");
        assert!(
            pos("(allow file-read-metadata)") < dev_null,
            "/dev/null 写点必须在 floor 内、file-read-metadata 之后"
        );

        // 其余段的位置：存在才比较，保证「越靠后越晚」。
        let tail = [
            "(param \"WS\")",  // 写白名单
            "(param \"TMP\")", // TMP 可写
            "(param \"D0\")",  // 凭据 deny_read
            "(allow network",  // 网络
        ];
        let mut last = dev_null;
        for needle in tail {
            if let Some(cur) = profile.find(needle) {
                assert!(
                    last < cur,
                    "section out of order: {needle:?} at {cur} not after {last}"
                );
                last = cur;
            }
        }
    }

    // ── B1：段序断言 ──

    #[test]
    fn b1_section_order_all_presets_and_networks() {
        let cwd = tempfile::tempdir().expect("tempdir");
        let cwd_path = cwd.path();
        let nets = [
            NetAccess::Deny,
            NetAccess::Loopback,
            NetAccess::Ports(vec![443]),
            NetAccess::All,
        ];
        for preset in [
            MacPreset::ReadOnly,
            MacPreset::WorkspaceWrite,
            MacPreset::FullAccess,
        ] {
            for net in &nets {
                let policy = policy_of(preset, net.clone(), cwd_path);
                let plan = build_ok(&policy, cwd_path);

                if policy.full_access {
                    // FullAccess：`(allow default)` 而非 `(deny default)`。
                    assert!(
                        plan.profile.starts_with("(version 1)\n(allow default)"),
                        "FullAccess 首个动作必须是 (allow default)：\n{}",
                        plan.profile
                    );
                    assert!(!plan.profile.contains("(deny default)"));
                } else {
                    assert!(
                        plan.profile.starts_with("(version 1)\n(deny default)"),
                        "首个动作必须是 (deny default)：\n{}",
                        plan.profile
                    );
                }

                assert_section_order(&plan.profile);
            }
        }
    }

    #[test]
    fn b1_write_and_tmp_precede_deny_read() {
        // 显式给一个有写权 + 有 deny_read 的配置，确认 WS < DW0 < D0 < network。
        let cwd = tempfile::tempdir().expect("tempdir");
        let user_deny = cwd.path().join("secret");
        std::fs::create_dir_all(&user_deny).expect("mkdir");

        let policy = MacOsConfig::default()
            .with_mac_preset(MacPreset::WorkspaceWrite)
            .with_mac_deny_read(user_deny)
            .with_mac_net(NetAccess::Loopback)
            .resolve(cwd.path());
        let profile = build_ok(&policy, cwd.path()).profile;

        let ws = profile.find("(param \"WS\")").expect("WS");
        let dw0 = profile.find("(param \"DW0\")").expect("DW0");
        let d0 = profile.find("(param \"D0\")").expect("D0");
        let net = profile.find("(allow network").expect("network");
        assert!(ws < dw0, "写白名单必须先于凭据写拒绝");
        assert!(dw0 < d0, "凭据写拒绝必须先于读拒绝");
        assert!(d0 < net, "读拒绝必须早于网络段");
        // deny_read 之后不得再出现任何 file 规则（network 除外）。
        let after_deny_read = &profile[profile.find("(deny file-read*").expect("deny read")..];
        assert!(
            !after_deny_read.contains("(allow file-"),
            "deny_read 之后不得出现 allow file 规则（会被后写覆盖）"
        );
    }

    // ── B2：注入拒绝 ──

    #[test]
    fn b2_rejects_injection_characters() {
        let cwd = tempfile::tempdir().expect("tempdir");
        let base = MacOsConfig::default().with_mac_preset(MacPreset::WorkspaceWrite);

        for bad in ["evil\"", "evil)", "evil;", "evil\n"] {
            // 注入字符在校验里就被拒，无需真实存在。
            let path = PathBuf::from(format!("/tmp/{bad}"));
            let policy = base.clone().with_mac_write(path).resolve(cwd.path());
            let err = build(&policy, cwd.path()).expect_err("含注入字符必须报错");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("reserved SBPL character"),
                "错误信息应指明注入字符：{msg}"
            );
        }
    }

    #[test]
    fn b2_rejects_nonexistent_path() {
        // canonicalize 失败即硬错误（-D 传不存在路径 sandbox-exec 不报错）。
        let cwd = tempfile::tempdir().expect("tempdir");
        let policy = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_write("/definitely/not/here/seabox-test")
            .resolve(cwd.path());
        let err = build(&policy, cwd.path()).expect_err("不存在路径必须硬错误");
        assert!(
            format!("{err:#}").contains("does not exist"),
            "错误信息应指出路径不存在：{err:#}"
        );
    }

    // ── B3：禁用 prefix ──

    #[test]
    fn b3_never_uses_prefix() {
        let cwd = tempfile::tempdir().expect("tempdir");
        let extra = tempfile::tempdir().expect("tempdir");
        let nets = [
            NetAccess::Deny,
            NetAccess::Loopback,
            NetAccess::Ports(vec![80, 443]),
            NetAccess::All,
        ];
        for preset in [
            MacPreset::ReadOnly,
            MacPreset::WorkspaceWrite,
            MacPreset::FullAccess,
        ] {
            for net in &nets {
                let policy = MacOsConfig::default()
                    .with_mac_preset(preset)
                    .with_mac_write(extra.path())
                    .with_mac_net(net.clone())
                    .resolve(cwd.path());
                let plan = build_ok(&policy, cwd.path());
                assert!(
                    !plan.profile.contains("(prefix"),
                    "禁用 prefix 匹配符（字符串前缀会跨目录越权）：\n{}",
                    plan.profile
                );
            }
        }
    }

    // ── B4：参数化 ──

    #[test]
    fn b4_workspace_is_parameterized() {
        let cwd = tempfile::tempdir().expect("tempdir");
        let policy = MacOsConfig::default()
            .with_mac_preset(MacPreset::WorkspaceWrite)
            .resolve(cwd.path());
        let plan = build_ok(&policy, cwd.path());

        assert!(plan.profile.contains("(param \"WS\")"));
        // 参数表里有 WS，且值等于规范化后的 cwd。
        let ws = plan.param("WS").expect("WS 参数必须定义");
        assert_eq!(
            ws,
            norm(cwd.path()).unwrap().to_string_lossy(),
            "WS 必须是规范化后的 cwd"
        );
        // 规则体里不得内联该绝对路径（只在注释里出现）。
        let body: Vec<&str> = plan
            .profile
            .lines()
            .filter(|l| !l.trim_start().starts_with(';'))
            .filter(|l| {
                // 行内注释去掉后再检查
                let code = match l.find(';') {
                    Some(i) => &l[..i],
                    None => *l,
                };
                code.contains(ws)
            })
            .collect();
        assert!(body.is_empty(), "路径不得内联进 SBPL 规则：{body:?}");
    }

    #[test]
    fn b4_all_referenced_params_are_defined() {
        // §6.5：引用未定义的 param ⇒ rc=65，因此每个 param 引用必须有 -D。
        let cwd = tempfile::tempdir().expect("tempdir");
        let extra = tempfile::tempdir().expect("tempdir");
        let deny = tempfile::tempdir().expect("tempdir");
        let policy = MacOsConfig::default()
            .with_mac_preset(MacPreset::WorkspaceWrite)
            .with_mac_write(extra.path())
            .with_mac_deny_read(deny.path())
            .with_mac_net(NetAccess::Loopback)
            .resolve(cwd.path());
        let plan = build_ok(&policy, cwd.path());

        let mut referenced = Vec::new();
        let mut rest = plan.profile.as_str();
        while let Some(i) = rest.find("(param \"") {
            rest = &rest[i + "(param \"".len()..];
            let end = rest.find('"').expect("param 名未闭合");
            referenced.push(rest[..end].to_string());
        }
        assert!(!referenced.is_empty(), "应当有被引用的 param");
        for key in &referenced {
            assert!(
                plan.param(key).is_some(),
                "param {key} 被引用但未定义（会导致 sandbox-exec rc=65）\n{}",
                plan.profile
            );
        }
    }

    #[test]
    fn b4_read_only_mode_parameterizes_roots() {
        let cwd = tempfile::tempdir().expect("tempdir");
        let root = tempfile::tempdir().expect("tempdir");
        let policy = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_read(root.path())
            .resolve(cwd.path());
        let plan = build_ok(&policy, cwd.path());

        assert!(!plan.profile.contains("(allow file-read*)\n"));
        assert!(plan.profile.contains("(param \"R0\")"));
        assert_eq!(
            plan.param("R0"),
            Some(norm(root.path()).unwrap().to_string_lossy().as_ref())
        );
        // 系统地板必须存在（Only 模式）。
        for needle in [
            "(allow file-read* (literal \"/\"))",
            "(allow file-read* (subpath \"/usr\"))",
            "(allow file-read* (subpath \"/System\"))",
            "(allow file-read* (literal \"/etc\"))",
            "(allow file-read* (literal \"/tmp\"))",
        ] {
            assert!(plan.profile.contains(needle), "缺少系统地板项：{needle}");
        }
    }

    #[test]
    fn b4_read_all_has_no_system_floor() {
        let cwd = tempfile::tempdir().expect("tempdir");
        let policy = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_read_all()
            .resolve(cwd.path());
        let plan = build_ok(&policy, cwd.path());
        assert!(plan.profile.contains("(allow file-read*)\n"));
        assert!(!plan.profile.contains("(subpath \"/System\")"));
        assert!(!plan.profile.contains("(param \"R0\")"));
    }

    // ── B5：空 write ──

    #[test]
    fn b5_empty_write_has_no_empty_subpath() {
        let cwd = tempfile::tempdir().expect("tempdir");
        for preset in [MacPreset::ReadOnly, MacPreset::FullAccess] {
            let policy = policy_of(preset, NetAccess::Deny, cwd.path());
            let plan = build_ok(&policy, cwd.path());
            assert!(
                !plan.profile.contains("(subpath \"\")"),
                "{preset:?} 不得产生 (subpath \"\")"
            );
            assert!(!plan.profile.contains("(param \"WS\")"));
            assert!(plan.param("WS").is_none());
        }
    }

    // ── B6：.git carve-out ──

    #[test]
    fn b6_git_carve_out_toggle() {
        let cwd = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(cwd.path().join(".git")).expect("mkdir .git");

        let on = MacOsConfig::default()
            .with_mac_preset(MacPreset::WorkspaceWrite)
            .with_mac_git_write(Some(true))
            .resolve(cwd.path());
        let plan = build_ok(&on, cwd.path());
        assert!(!plan.profile.contains("require-all"));
        assert!(!plan.profile.contains("require-not"));
        assert!(plan.param("GIT").is_none());

        let off = MacOsConfig::default()
            .with_mac_preset(MacPreset::WorkspaceWrite)
            .with_mac_no_git_write()
            .resolve(cwd.path());
        let plan = build_ok(&off, cwd.path());
        assert!(plan.profile.contains("require-all"));
        assert!(plan.profile.contains("require-not"));
        // carve-out 必须在同一条规则里（另起 deny 会被子树的 allow 覆盖）。
        assert!(plan.param("GIT").is_some());
        assert_eq!(
            plan.param("GIT"),
            Some(
                norm(&cwd.path().join(".git"))
                    .unwrap()
                    .to_string_lossy()
                    .as_ref()
            )
        );
        // require-all 出现在 (allow file-write* 段落内、deny 之前。
        let allow_write = plan
            .profile
            .find("(allow file-write*")
            .expect("allow write");
        let require_all = plan.profile.find("require-all").expect("require-all");
        let deny_read = plan.profile.find("(deny file-read*").expect("deny read");
        assert!(allow_write < require_all && require_all < deny_read);
        // 同一段内只能有一条 (subpath (param "WS"))
        assert_eq!(plan.profile.matches("(subpath (param \"WS\"))").count(), 1);
    }

    // ── B7：TMP 可写开关 ──

    #[test]
    fn b7_tmp_writable_toggle() {
        let cwd = tempfile::tempdir().expect("tempdir");

        let on = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_tmp_writable(Some(true))
            .resolve(cwd.path());
        let plan = build_ok(&on, cwd.path());
        assert!(plan.profile.contains("(subpath (param \"TMP\"))"));
        assert!(plan.param("TMP").is_some());

        let off = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_no_tmp_writable()
            .resolve(cwd.path());
        let plan = build_ok(&off, cwd.path());
        assert!(!plan.profile.contains("(param \"TMP\")"));
        assert!(plan.param("TMP").is_none());
        assert!(!plan.profile.contains("(allow file-write* (subpath"));
    }

    // ── B8：凭据清单关闭 ──

    #[test]
    fn b8_no_credential_deny_removes_d_section() {
        let cwd = tempfile::tempdir().expect("tempdir");

        let with_cred = MacOsConfig::default()
            .with_mac_preset(MacPreset::WorkspaceWrite)
            .resolve(cwd.path());
        let plan = build_ok(&with_cred, cwd.path());
        assert!(plan.profile.contains("(param \"D0\")"));
        assert!(plan.param("D0").is_some());
        assert!(plan.profile.contains("(deny file-read*"));

        let no_cred = MacOsConfig::default()
            .with_mac_preset(MacPreset::WorkspaceWrite)
            .with_mac_no_credential_deny()
            .resolve(cwd.path());
        let plan = build_ok(&no_cred, cwd.path());
        assert!(!plan.profile.contains("(param \"D0\")"));
        assert!(!plan.profile.contains("(param \"DW0\")"));
        assert!(!plan.profile.contains("(deny file-read*"));
        assert!(!plan.profile.contains("(deny file-write*"));
    }

    #[test]
    fn b8_full_access_skips_credentials_but_keeps_user_deny() {
        let cwd = tempfile::tempdir().expect("tempdir");
        let user_deny = tempfile::tempdir().expect("tempdir");
        let policy = MacOsConfig::default()
            .with_mac_preset(MacPreset::FullAccess)
            .with_mac_deny_read(user_deny.path())
            .with_mac_net(NetAccess::Deny)
            .resolve(cwd.path());
        let plan = build_ok(&policy, cwd.path());
        // FullAccess：无内置凭据 deny、无写白名单、无 TMP，只有用户 deny + (deny network*)。
        assert!(plan.profile.contains("(param \"D0\")"));
        assert_eq!(plan.params.len(), 1, "只应剩用户 deny 一个参数");
        assert!(plan.profile.contains("(deny network*)"));
        assert_section_order(&plan.profile);
    }

    // ── 网络段细节 ──

    #[test]
    fn network_loopback_and_ports() {
        let cwd = tempfile::tempdir().expect("tempdir");

        let lb = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_net(NetAccess::Loopback)
            .with_mac_net_inbound(true)
            .resolve(cwd.path());
        let p = build_ok(&lb, cwd.path()).profile;
        assert!(p.contains("(allow network-outbound (remote ip \"localhost:*\"))"));
        assert!(p.contains("(allow network-inbound (local ip \"localhost:*\"))"));
        assert!(
            p.contains("(remote unix-socket (path \"/private/var/run/mDNSResponder\"))"),
            "Loopback 必须附带 mDNSResponder socket（否则 curl rc=6）"
        );

        let ports = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_net(NetAccess::Ports(vec![443, 8443]))
            .resolve(cwd.path());
        let p = build_ok(&ports, cwd.path()).profile;
        assert!(p.contains("(allow network-outbound (remote ip \"*:443\"))"));
        assert!(p.contains("(allow network-outbound (remote ip \"*:8443\"))"));
        assert!(!p.contains("localhost:*"));
        assert!(
            p.contains("(remote unix-socket (path \"/private/var/run/mDNSResponder\"))"),
            "Ports 必须附带 mDNSResponder socket"
        );

        let all = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_net(NetAccess::All)
            .resolve(cwd.path());
        let p = build_ok(&all, cwd.path()).profile;
        assert!(p.trim_end().ends_with("(allow network*)"));

        // Deny：非 FullAccess 下整段不出现。
        let deny = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_net(NetAccess::Deny)
            .resolve(cwd.path());
        let p = build_ok(&deny, cwd.path()).profile;
        assert!(!p.contains("(allow network"));
        assert!(!p.contains("(deny network"));
    }

    #[test]
    fn network_is_orthogonal_to_preset() {
        // 同一网络配置在三种预设下的网络段完全一致（suffix 比较）。
        let cwd = tempfile::tempdir().expect("tempdir");
        let net_of = |p: &str| match p.find("; --- network") {
            Some(i) => p[i..].to_string(),
            None => String::new(),
        };
        let mut seen = Vec::new();
        for preset in [
            MacPreset::ReadOnly,
            MacPreset::WorkspaceWrite,
            MacPreset::FullAccess,
        ] {
            let policy = MacOsConfig::default()
                .with_mac_preset(preset)
                .with_mac_net(NetAccess::Ports(vec![443]))
                .resolve(cwd.path());
            seen.push(net_of(&build_ok(&policy, cwd.path()).profile));
        }
        // FullAccess 的 (deny network*) 情形另测；此处 All/Ports 完全一致。
        assert_eq!(seen[0], seen[1], "Ports 段应与预设正交");
        assert_eq!(seen[1], seen[2], "Ports 段应与预设正交");
    }

    // ── floor 内容 ──

    #[test]
    fn floor_contains_measured_essentials() {
        let cwd = tempfile::tempdir().expect("tempdir");
        let policy = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .resolve(cwd.path());
        let p = build_ok(&policy, cwd.path()).profile;
        for needle in [
            "(allow process*)",
            "(allow sysctl-read)",
            "(allow mach-lookup)",
            "(allow ipc-posix-sem)",
            "(allow ipc-posix-shm)",
            "(allow pseudo-tty)",
            "(allow user-preference-read)",
            "(allow process-info* (target same-sandbox))",
            "(allow signal (target same-sandbox))",
            "(allow file-read-metadata)",
            "(allow file-read* (subpath \"/dev\"))",
            "(literal \"/dev/null\")",
            "(literal \"/dev/tty\")",
            "(literal \"/dev/dtracehelper\")",
            "(literal \"/dev/stdout\")",
            "(literal \"/dev/stderr\")",
            "(allow file-ioctl (literal \"/dev/dtracehelper\"))",
        ] {
            assert!(p.contains(needle), "floor 缺少：{needle}");
        }
    }

    // ── norm ──

    #[test]
    fn norm_expands_tilde_and_rejects_missing() {
        // `~` 展开后仍应报「不存在」而不是把字面 `~` 一路带下去。
        let err = norm(Path::new("~/definitely-not-here-seabox")).expect_err("应报错");
        assert!(format!("{err:#}").contains("does not exist"));
        assert!(!format!("{err:#}").contains("~/"), "~ 应已展开：{err:#}");

        // 已存在路径 ⇒ 绝对路径。
        let abs = norm(Path::new("/usr")).expect("/usr 应可规范化");
        assert!(abs.is_absolute());
    }
}
