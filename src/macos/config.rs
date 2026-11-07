//! macOS Seatbelt 配置面：数据类型 + `resolve()` + `is_configured()` + `validate()`。
//!
//! **本文件无条件编译**（无 `#[cfg(target_os = "macos")]` 门控）：纯数据类型 + 纯逻辑，
//! 不含任何 macOS-only 平台 API（不碰 `/dev/fd`、不碰 `/usr/bin/sandbox-exec`、
//! 不碰 `Command`），因此 Linux CI 可完整单测（见 `docs/design-plans/macos-seatbelt.md` §3.1）。
//!
//! 权威定义：`docs/arch/macos-seatbelt/design.md` §4.0 / §4.1 / §4.2 / §4.4 / §4.6。
//!
//! 配置的形状是「预设 + 覆盖」：
//!
//! ```text
//! preset: Some(WorkspaceWrite)  → 先填一组预设默认值
//! preset: None                  → 用安全基线（baseline）
//! 各字段                         → 无论有无预设都生效，Option 覆盖 / Vec 追加
//! ```
//!
//! 三个开关用 [`Option<bool>`] 而非 `bool`：`bool` 区分不了「未设置」与「显式 false」，
//! 而「用 ReadOnly 预设但显式关掉 TMP 可写」正是预设机制的核心用法（design §4.1）。

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// 内置凭据拒绝清单（design §4.4）
// ---------------------------------------------------------------------------

/// 内置凭据目录/文件清单（design §4.4）。
///
/// `MacReadMode::All`（读全开）时这是唯一的补偿项，因此默认**同时** deny 读与写：
/// 只封读挡不住「写一个后门进去再用别的方式执行」（design §4.0）。
///
/// 条目保留 `~` 前缀，由 SBPL 生成器的 `norm()` 负责 `~` 展开与 `canonicalize`；
/// 本文件不做任何文件系统访问，保持 `resolve()` 为纯函数。
///
/// ⚠️ 这是一份**黑名单**，漏一个目录就是真泄漏（`seabox check` 与 README 必须写明）。
///
/// 注意：[`MacOsConfig::resolve`] 已把本清单**物化**进 [`ResolvedPolicy::deny_read`] /
/// [`ResolvedPolicy::deny_write`]，生成器**不应**再自行追加一份。
pub const CREDENTIAL_PATHS: [&str; 8] = [
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.kube",
    "~/.netrc",
    "~/.npmrc",
    "~/.config/gh",
    "~/.docker/config.json",
];

/// 内置凭据清单的 [`PathBuf`] 形式。
///
/// 与 [`CREDENTIAL_PATHS`] 等价，供需要 owned 值的调用方使用。
pub fn credential_paths() -> Vec<PathBuf> {
    CREDENTIAL_PATHS.iter().map(PathBuf::from).collect()
}

/// 判断一个路径是否属于内置凭据清单（精确字面比较，不做 `~` 展开）。
fn is_credential_path(p: &Path) -> bool {
    CREDENTIAL_PATHS.iter().any(|c| Path::new(c) == p)
}

// ---------------------------------------------------------------------------
// MacOsConfig
// ---------------------------------------------------------------------------

/// macOS 沙箱配置（`--mac-*` flag / `SandboxConfig::with_mac_*` 的载体）。
///
/// 在 Linux 上恒为 [`Default::default()`]，不参与任何逻辑；真伪由
/// [`MacOsConfig::is_configured`] 判断（**不**用 `PartialEq` 比对默认值，见该方法文档）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MacOsConfig {
    /// 可选预设。`None` = 自定义模式（仅按下方字段构建，底线是安全基线）。
    ///
    /// 预设与字段的关系：预设填默认值，字段可覆盖（`Option`）或追加（`Vec`）。见 design §4.0。
    pub preset: Option<MacPreset>,

    // ── 写侧（可独立配置，无需预设）──
    /// 可写目录根。递归含整棵子树，含删除权（design §6.2b）。
    pub write: Vec<PathBuf>,
    /// workspace 写根（`--mac-workspace`）。
    ///
    /// **替换**而非追加 `WorkspaceWrite` 预设的默认写根（cwd）。
    /// 若实现为追加，cwd 仍可写，结果比用户意图更宽——安全方向错误。
    /// 非 `WorkspaceWrite` 预设下，本字段作为普通可写目录追加。
    pub workspace: Option<PathBuf>,
    /// 写拒绝（在 `write` 之后生效：SBPL 后写赢）。
    pub deny_write: Vec<PathBuf>,
    /// TMPDIR 可写。`None` = 跟随预设/基线；`Some(v)` = 显式覆盖。
    pub tmp_writable: Option<bool>,

    // ── 读侧 ──
    /// 读模式。`None` = 跟随预设（预设均为 [`MacReadMode::All`]）。
    pub read: Option<MacReadMode>,
    /// 读拒绝（叠加在内置凭据清单之上）。
    pub deny_read: Vec<PathBuf>,
    /// 关闭内置凭据清单。`None` = 跟随默认（开）；`Some(true)` = 关闭。
    pub no_credential_deny: Option<bool>,

    // ── 其他 ──
    /// 是否放行 `.git` 写。`None` = 跟随预设（均为 `true`）；`Some(false)` = carve out。
    pub allow_git_write: Option<bool>,
    /// 网络。`None` = 未配（不施加沙箱时网络全开）；`Some(v)` = 显式指定。
    ///
    /// 必须是 `Option<MacNetConfig>` 而非 `MacNetConfig`：`--mac-net deny` 与
    /// 默认值 `NetAccess::Deny` 相等，若归一化就会丢失「用户显式配了」这一信息。
    pub net: Option<MacNetConfig>,
}

// ---------------------------------------------------------------------------
// MacReadMode
// ---------------------------------------------------------------------------

/// 读侧模式。
///
/// 与早期结论不同：macOS 上读侧**可以**真正隔离（design §4.3），代价是必须枚举系统地板。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum MacReadMode {
    /// `(allow file-read*)` —— 读全开，靠凭据 denylist 补偿。预设默认。
    #[default]
    All,
    /// 只读指定根 + 内置系统地板。能真正隔离，但漏一个路径就是 `Operation not permitted`。
    Only(Vec<PathBuf>),
}

// ---------------------------------------------------------------------------
// MacPreset
// ---------------------------------------------------------------------------

/// 三种内置预设（design §4.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacPreset {
    /// 读全开、无写权（除 TMP）。适合审查代码、跑只读命令。
    ReadOnly,
    /// 读全开、cwd 可写（`resolve()` 传入的 cwd）。Agent 日常开发。
    WorkspaceWrite,
    /// 读全开、全盘可写（`(allow default)`）、忽略凭据保护。明确信任的任务。
    FullAccess,
}

impl MacPreset {
    /// 预设展开出的默认策略（design §4.2 表格前三行）。
    ///
    /// [`MacPreset::WorkspaceWrite`] 的写根是 cwd，本方法拿不到 cwd，故 `write` 返回空，
    /// 由 [`MacOsConfig::resolve`] 填入。
    pub(crate) fn defaults(&self) -> ResolvedPolicy {
        let credentials = credential_paths();
        match self {
            MacPreset::ReadOnly => ResolvedPolicy {
                read: MacReadMode::All,
                write: vec![],
                deny_write: credentials.clone(),
                deny_read: credentials,
                tmp_writable: true,
                allow_git_write: true,
                credential_deny: true,
                net: MacNetConfig::default(),
                full_access: false,
            },
            MacPreset::WorkspaceWrite => ResolvedPolicy {
                read: MacReadMode::All,
                write: vec![], // 由 resolve(cwd) 填入
                deny_write: credentials.clone(),
                deny_read: credentials,
                tmp_writable: true,
                allow_git_write: true,
                credential_deny: true,
                net: MacNetConfig::default(),
                full_access: false,
            },
            MacPreset::FullAccess => ResolvedPolicy {
                read: MacReadMode::All,
                write: vec![],
                deny_write: vec![],
                deny_read: vec![], // FullAccess 忽略凭据保护（credential_deny = false）
                tmp_writable: true,
                allow_git_write: true,
                credential_deny: false,
                net: MacNetConfig::default(),
                full_access: true,
            },
        }
    }

    /// 无预设时的**安全基线**（design §4.2 表格最后一行）。
    ///
    /// 语义：floor + `(allow file-read*)` + 仅用户显式给的 `write` + 禁网 + 凭据 denylist。
    /// 与三预设的关键差异：`tmp_writable = false`（不配就是不放）。
    pub(crate) fn baseline() -> ResolvedPolicy {
        let credentials = credential_paths();
        ResolvedPolicy {
            read: MacReadMode::All,
            write: vec![],
            deny_write: credentials.clone(),
            deny_read: credentials,
            tmp_writable: false,
            allow_git_write: true,
            credential_deny: true,
            net: MacNetConfig::default(),
            full_access: false,
        }
    }
}

// ---------------------------------------------------------------------------
// MacNetConfig / NetAccess
// ---------------------------------------------------------------------------

/// 网络配置（与预设**正交**：design §8）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacNetConfig {
    /// 出站访问。
    pub outbound: NetAccess,
    /// 放通 loopback 入站（`(local ip "localhost:*)`）。
    pub inbound_loopback: bool,
}

/// 出站网络访问级别。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NetAccess {
    /// 禁网（默认）。
    #[default]
    Deny,
    /// 仅 loopback。
    Loopback,
    /// 仅指定 TCP 端口。
    Ports(Vec<u16>),
    /// 全放通。
    All,
}

// ---------------------------------------------------------------------------
// ResolvedPolicy
// ---------------------------------------------------------------------------

/// 已定型的策略：**无 `Option`**，SBPL 生成器只接受它。
///
/// `Option` 字段若留到生成器里再 `unwrap_or`，`bool` 与 `Option<bool>` 的误用不会报错，
/// 因此 [`MacOsConfig::resolve`] 必须在入口处把一切定型（design §4.2）。
///
/// 内部定型类型：不进入 crate 公开 API（`sbpl` / `imp` 同 crate 可见）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedPolicy {
    /// 读模式。
    pub(crate) read: MacReadMode,
    /// 可写目录根（预设值在前，用户追加，去重保序）。
    pub(crate) write: Vec<PathBuf>,
    /// 写拒绝（预设值在前，用户追加）。
    pub(crate) deny_write: Vec<PathBuf>,
    /// 读拒绝（内置凭据清单在前，用户追加）。**必须是最后一条 file 规则**。
    pub(crate) deny_read: Vec<PathBuf>,
    /// TMPDIR 可写。
    pub(crate) tmp_writable: bool,
    /// 放行 `.git` 写（`false` = `require-all` + `require-not` carve out）。
    pub(crate) allow_git_write: bool,
    /// 是否施加内置凭据保护。已物化进 `deny_read` / `deny_write`，本字段供生成器
    /// 区分凭据段与用户段（例如决定是否输出凭据相关的诊断/参数命名）。
    pub(crate) credential_deny: bool,
    /// 网络配置（默认 [`NetAccess::Deny`]）。
    pub(crate) net: MacNetConfig,
    /// `FullAccess` 预设标记：生成器写 `(allow default)` 而非 `(deny default)`，
    /// 且不产生预设写白名单。用户字段仍在其后生效（后写赢）。
    pub(crate) full_access: bool,
}

// ---------------------------------------------------------------------------
// MacOsConfig：解析 / 判断 / 校验
// ---------------------------------------------------------------------------

impl MacOsConfig {
    /// 把「预设 + 字段」合并成定型策略（design §4.2 合并算法）。
    ///
    /// 规则：
    /// - `Option<T>` 字段：`Some` 覆盖，`None` 跟随预设/基线；
    /// - `Vec` 字段：预设值在前、用户值追加（`write` 去重保序）——用户加限制是理性行为，
    ///   静默丢弃内置凭据清单则是安全回退；
    /// - `net` 与预设正交：`None` ⇒ [`NetAccess::Deny`]；
    /// - `WorkspaceWrite` 预设的写根填 `cwd`；
    /// - `no_credential_deny = Some(true)` 或 `FullAccess` 时，内置凭据条目从
    ///   `deny_read` / `deny_write` 中移除（用户显式给的同名条目保留）。
    ///
    /// **幂等纯函数**：除 `cwd` 参数外不碰文件系统、不读环境变量，连调两次结果相同
    /// （故 Linux CI 可全覆盖单测）。
    pub(crate) fn resolve(&self, cwd: &Path) -> ResolvedPolicy {
        let mut base = match self.preset {
            Some(p) => p.defaults(),
            None => MacPreset::baseline(),
        };

        // WorkspaceWrite 的写根是 cwd（`defaults()` 拿不到 cwd，故在此填入）。
        // `--mac-workspace` 显式指定时**替换** cwd（而非追加），否则 cwd 仍可写，
        // 结果比用户意图更宽——安全方向错误。
        if self.preset == Some(MacPreset::WorkspaceWrite) {
            let root = self.workspace.clone().unwrap_or_else(|| cwd.to_path_buf());
            base.write.push(root);
        } else if let Some(ws) = &self.workspace {
            // 非 WorkspaceWrite 预设下：`--mac-workspace` 作为普通可写目录追加。
            base.write.push(ws.clone());
        }

        // 凭据保护：`no_credential_deny = Some(true)` ⇒ 关闭；否则跟随预设/基线。
        let credential_deny = self
            .no_credential_deny
            .map(|no_deny| !no_deny)
            .unwrap_or(base.credential_deny);
        if credential_deny {
            // 显式要求开启（含 `FullAccess` 下强制开启）时，若预设没带清单，
            // 补回内置凭据清单——否则 `credential_deny == true` 但列表为空，
            // 保护形同虚设（静默 no-op）。
            let credentials = credential_paths();
            for c in &credentials {
                if !base.deny_read.iter().any(|p| p == c) {
                    base.deny_read.push(c.clone());
                }
                if !base.deny_write.iter().any(|p| p == c) {
                    base.deny_write.push(c.clone());
                }
            }
        } else {
            base.deny_read.retain(|p| !is_credential_path(p));
            base.deny_write.retain(|p| !is_credential_path(p));
        }

        ResolvedPolicy {
            read: self.read.clone().unwrap_or(base.read),
            write: extend_unique(base.write, &self.write),
            deny_write: [base.deny_write, self.deny_write.clone()].concat(),
            deny_read: [base.deny_read, self.deny_read.clone()].concat(),
            tmp_writable: self.tmp_writable.unwrap_or(base.tmp_writable),
            allow_git_write: self.allow_git_write.unwrap_or(base.allow_git_write),
            credential_deny,
            net: self.net.clone().unwrap_or_default(),
            full_access: base.full_access,
        }
    }

    /// 用户是否**真的**配了 macOS 策略。`false` ⇒ 不进 `sandbox-exec`（直接执行）。
    ///
    /// **逐字段显式检查，严禁 `self != &Self::default()`**：值相等不等于「未配」。
    /// `--mac-net deny` 恰好等于 [`MacNetConfig`] 的默认值 `Deny`，若用 `PartialEq` 判定，
    /// 用户显式要的禁网会被当成未配置 ⇒ 沙箱不施加、网络全开——静默失败开放，
    /// 恰好是本设计最想避免的失效模式（design §4.2）。因此 `net` 只判 `is_some()`，不比值。
    ///
    /// 覆盖的 9 个字段：`preset` / `write` / `deny_write` / `tmp_writable` / `read` /
    /// `deny_read` / `no_credential_deny` / `allow_git_write` / `net`。
    pub fn is_configured(&self) -> bool {
        self.preset.is_some()
            || !self.write.is_empty()
            || self.workspace.is_some()
            || !self.deny_write.is_empty()
            || self.tmp_writable.is_some()
            || self.read.is_some()
            || !self.deny_read.is_empty()
            || self.no_credential_deny.is_some()
            || self.allow_git_write.is_some()
            || self.net.is_some()
    }

    /// 校验 macOS 侧配置是否可安全送进 SBPL 生成器。
    ///
    /// 本轮检查（硬错误，`bail!`）：
    /// - 任意路径含 SBPL 注入字符 `"` / `)` / `;` / `\n` / `\r`；
    /// - [`MacReadMode::Only`] 携带空列表（`--mac-read` 出现却无路径 ⇒ 会发出零读白名单）。
    ///
    /// 与 Linux 字段的双向互斥检查（macOS 上不得有 `landlock` / `seccomp` / `namespaces` …）
    /// 由 `src/lib.rs` 的 `create_sandbox_impl` 负责，**不在本文件**（design §4.6）。
    pub fn validate(&self) -> anyhow::Result<()> {
        for p in self
            .write
            .iter()
            .chain(self.workspace.iter())
            .chain(self.deny_write.iter())
            .chain(self.deny_read.iter())
        {
            check_path(p)?;
        }
        match &self.read {
            Some(MacReadMode::Only(paths)) if paths.is_empty() => anyhow::bail!(
                "macOS read mode `Only` requires at least one path (`--mac-read PATH`)"
            ),
            Some(MacReadMode::Only(paths)) => {
                for p in paths {
                    check_path(p)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// 拒绝含 SBPL 注入字符的路径。
fn check_path(p: &Path) -> anyhow::Result<()> {
    let s = p.to_string_lossy();
    for bad in ['"', ')', ';', '\n', '\r'] {
        if s.contains(bad) {
            anyhow::bail!(
                "macOS sandbox path contains reserved SBPL character {:?}: {}",
                bad,
                p.display()
            );
        }
    }
    Ok(())
}

/// 追加去重（保留 `base` 在前的顺序，输出稳定）。
fn extend_unique(mut base: Vec<PathBuf>, extra: &[PathBuf]) -> Vec<PathBuf> {
    for p in extra {
        if !base.contains(p) {
            base.push(p.clone());
        }
    }
    base
}

// ---------------------------------------------------------------------------
// MacOsConfig：with_* 链式 API（AGENTS.md：每个 CLI flag 都要有对应方法）
// ---------------------------------------------------------------------------

impl MacOsConfig {
    /// 设置预设（等价于 `--mac-preset`）。
    pub fn with_mac_preset(mut self, preset: MacPreset) -> Self {
        self.preset = Some(preset);
        self
    }

    /// 追加一个可写目录根（等价于 `--mac-write PATH`）。
    pub fn with_mac_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.write.push(path.into());
        self
    }

    /// 追加一条写拒绝（等价于 `--mac-deny-write PATH`）。
    pub fn with_mac_deny_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.deny_write.push(path.into());
        self
    }

    /// 指定 workspace 写根（等价于 `--mac-workspace DIR`）。
    ///
    /// 与 [`Self::with_mac_write`] 等价：结果是「预设值在前 + 本路径追加」。
    /// 设置 workspace-write 的**写根**（`--mac-workspace`）。
    ///
    /// 语义是**替换**而非追加：`WorkspaceWrite` 预设默认把 cwd 当写根，
    /// 用户显式指定时才是真的「收窄/改指写根」。若实现为追加，cwd 仍可写，
    /// 结果比用户意图更宽——安全方向错误。
    ///
    /// 放在 `write` 字段里承载，但通过 [`Self::workspace`] 让 `resolve()`
    /// 知道要**替换**预设的 cwd 而非追加它。
    pub fn with_mac_workspace(mut self, path: impl Into<PathBuf>) -> Self {
        self.workspace = Some(path.into());
        self
    }

    /// 追加一个读白名单根（等价于 `--mac-read PATH`，出现即切到 [`MacReadMode::Only`]）。
    ///
    /// 首次调用置 `Some(Only(vec![p]))`，后续追加。若当前是
    /// [`MacReadMode::All`]（`with_mac_read_all` 设过），同样切换到 `Only` 并只保留本路径。
    pub fn with_mac_read(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.read = Some(match self.read.take() {
            Some(MacReadMode::Only(mut paths)) => {
                paths.push(path);
                MacReadMode::Only(paths)
            }
            _ => MacReadMode::Only(vec![path]),
        });
        self
    }

    /// 读全开（等价于 `--mac-read-all`，预设默认值）。
    pub fn with_mac_read_all(mut self) -> Self {
        self.read = Some(MacReadMode::All);
        self
    }

    /// 直接指定读模式（底层完整签名，供需要显式表达 `None` 的调用者）。
    pub fn with_mac_read_mode(mut self, mode: Option<MacReadMode>) -> Self {
        self.read = mode;
        self
    }

    /// 追加一条读拒绝（等价于 `--mac-deny-read PATH`）。
    pub fn with_mac_deny_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.deny_read.push(path.into());
        self
    }

    /// 关闭内置凭据拒绝清单（等价于 `--mac-no-credential-deny`）。
    pub fn with_mac_no_credential_deny(self) -> Self {
        self.with_mac_credential_deny(Some(false))
    }

    /// 直接设置凭据保护开关（底层完整签名）。
    ///
    /// `Some(true)` = 施加凭据保护；`Some(false)` = 关闭；`None` = 跟随预设/基线。
    pub fn with_mac_credential_deny(mut self, enabled: Option<bool>) -> Self {
        self.no_credential_deny = enabled.map(|on| !on);
        self
    }

    /// 禁止写 `.git`（等价于 `--mac-no-git-write`）。
    pub fn with_mac_no_git_write(self) -> Self {
        self.with_mac_git_write(Some(false))
    }

    /// 直接设置 `.git` 写开关（底层完整签名）。
    pub fn with_mac_git_write(mut self, enabled: Option<bool>) -> Self {
        self.allow_git_write = enabled;
        self
    }

    /// 关闭 TMPDIR 可写（等价于 `--mac-no-tmp-writable`）。
    pub fn with_mac_no_tmp_writable(self) -> Self {
        self.with_mac_tmp_writable(Some(false))
    }

    /// 直接设置 TMPDIR 可写开关（底层完整签名）。
    pub fn with_mac_tmp_writable(mut self, enabled: Option<bool>) -> Self {
        self.tmp_writable = enabled;
        self
    }

    /// 设置出站网络级别（等价于 `--mac-net ...`），保留已设的入站 loopback 开关。
    pub fn with_mac_net(mut self, access: NetAccess) -> Self {
        let inbound_loopback = self
            .net
            .as_ref()
            .map(|n| n.inbound_loopback)
            .unwrap_or(false);
        self.net = Some(MacNetConfig {
            outbound: access,
            inbound_loopback,
        });
        self
    }

    /// 设置是否放通 loopback 入站（等价于 `--mac-net-inbound`），保留已设的出站级别。
    pub fn with_mac_net_inbound(mut self, enabled: bool) -> Self {
        let outbound = self
            .net
            .as_ref()
            .map(|n| n.outbound.clone())
            .unwrap_or_default();
        self.net = Some(MacNetConfig {
            outbound,
            inbound_loopback: enabled,
        });
        self
    }
}

// ---------------------------------------------------------------------------
// 测试（Task 7 会扩充为 N3 / A1-A10 全集）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_not_configured() {
        assert!(!MacOsConfig::default().is_configured());
        // 默认值本身也要对：6 个 Option 全 None、3 个 Vec 全空。
        let c = MacOsConfig::default();
        assert_eq!(c.preset, None);
        assert!(c.write.is_empty());
        assert!(c.deny_write.is_empty());
        assert_eq!(c.tmp_writable, None);
        assert_eq!(c.read, None);
        assert!(c.deny_read.is_empty());
        assert_eq!(c.no_credential_deny, None);
        assert_eq!(c.allow_git_write, None);
        assert_eq!(c.net, None);
        assert_eq!(MacReadMode::default(), MacReadMode::All);
        assert_eq!(NetAccess::default(), NetAccess::Deny);
    }

    /// P0 回归防线：`--mac-net deny` 与默认值**值相等**，但必须算「已配置」，
    /// 否则沙箱不施加、网络全开（静默失败开放）。
    #[test]
    fn explicit_net_deny_counts_as_configured() {
        let c = MacOsConfig::default().with_mac_net(NetAccess::Deny);
        assert_eq!(c.net, Some(MacNetConfig::default())); // 值等于默认
        assert!(c.is_configured());
    }

    #[test]
    fn preset_with_explicit_tmp_override() {
        let c = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_no_tmp_writable();
        let p = c.resolve(Path::new("/work"));
        assert!(!p.tmp_writable);
        // 其余跟随预设
        assert_eq!(p.read, MacReadMode::All);
        assert!(p.allow_git_write);
        assert!(p.credential_deny);
        assert_eq!(p.net.outbound, NetAccess::Deny);
    }

    #[test]
    fn resolve_is_idempotent() {
        let c = MacOsConfig::default()
            .with_mac_preset(MacPreset::WorkspaceWrite)
            .with_mac_write("/extra")
            .with_mac_deny_read("/secret")
            .with_mac_net(NetAccess::Loopback);
        let cwd = Path::new("/work");
        assert_eq!(c.resolve(cwd), c.resolve(cwd));
        // WorkspaceWrite 的写根由 resolve 填入
        assert!(c.resolve(cwd).write.contains(&PathBuf::from("/work")));
    }

    #[test]
    fn validate_rejects_injection_and_empty_read_only() {
        assert!(MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .validate()
            .is_ok());
        assert!(MacOsConfig::default()
            .with_mac_write("/tmp/a\"b")
            .validate()
            .is_err());
        assert!(MacOsConfig::default()
            .with_mac_read_mode(Some(MacReadMode::Only(vec![])))
            .validate()
            .is_err());
    }

    // -----------------------------------------------------------------------
    // 以下为 Task 7 追加的 N3 / A1-A10 编号测试（design §4.2 测试合同）
    //
    // 全部**全平台可跑**：`resolve()` / `is_configured()` / `validate()` 都是纯函数，
    // 不碰文件系统、不读环境变量（`cwd` 只是被塞进 `write` 的 `PathBuf`，
    // 不要求真实存在，也不需要 `tempfile`）。故 Linux CI 可完整覆盖。
    // -----------------------------------------------------------------------

    /// N3：4 个类型的默认值 —— 6 个 `Option` 全 `None`、3 个 `Vec` 全空、
    /// `MacReadMode::default()==All`、`NetAccess::default()==Deny`。
    ///
    /// 注：合同里的「`MacPreset` 无 `Default`」是**编译期**属性（结构体未 `derive`
    /// `Default`），Rust 里无法用运行时断言表达存在的反面；此处靠「`Option` 承载未配置」
    /// 这一设计事实兜住，`MacPreset::default()` 一旦出现即编译失败。
    #[test]
    fn n3_default_values_are_unset() {
        let c = MacOsConfig::default();

        // 6 个 Option 字段：未设置即 None（不是「设为默认值」）。
        assert_eq!(c.preset, None, "preset 默认应为 None");
        assert_eq!(c.tmp_writable, None, "tmp_writable 默认应为 None");
        assert_eq!(c.read, None, "read 默认应为 None");
        assert_eq!(c.no_credential_deny, None);
        assert_eq!(c.allow_git_write, None);
        assert_eq!(c.net, None, "net 默认应为 None 而非 Some(Deny)");

        // 3 个 Vec 字段：全空。
        assert!(c.write.is_empty());
        assert!(c.deny_write.is_empty());
        assert!(c.deny_read.is_empty());

        // 两个枚举的 Default 必须落在安全侧。
        assert_eq!(MacReadMode::default(), MacReadMode::All);
        assert_eq!(NetAccess::default(), NetAccess::Deny);

        // 嵌套类型默认值：出站 Deny、不放通入站 loopback。
        let net = MacNetConfig::default();
        assert_eq!(net.outbound, NetAccess::Deny);
        assert!(!net.inbound_loopback);
    }

    /// A1：9 个字段各自**单独**设置 ⇒ `is_configured()==true`。
    ///
    /// 逐个字段独立构造（而非一次全设），否则任一字段被漏检也看不出来。
    #[test]
    fn a1_each_field_alone_counts_as_configured() {
        // 先确认起点：默认配置不算「已配置」（A3 的同义断言，此处作为对照）。
        assert!(!MacOsConfig::default().is_configured());

        let cases: [(&str, MacOsConfig); 9] = [
            (
                "preset",
                MacOsConfig::default().with_mac_preset(MacPreset::ReadOnly),
            ),
            ("write", MacOsConfig::default().with_mac_write("/w")),
            (
                "deny_write",
                MacOsConfig::default().with_mac_deny_write("/dw"),
            ),
            (
                "tmp_writable",
                MacOsConfig::default().with_mac_tmp_writable(Some(true)),
            ),
            ("read", MacOsConfig::default().with_mac_read("/r")),
            (
                "deny_read",
                MacOsConfig::default().with_mac_deny_read("/dr"),
            ),
            (
                "no_credential_deny",
                MacOsConfig::default().with_mac_credential_deny(Some(true)),
            ),
            (
                "allow_git_write",
                MacOsConfig::default().with_mac_git_write(Some(false)),
            ),
            (
                "net",
                MacOsConfig::default().with_mac_net(NetAccess::Loopback),
            ),
        ];

        for (name, cfg) in &cases {
            assert!(
                cfg.is_configured(),
                "字段 `{name}` 单独设置后 is_configured() 应为 true"
            );
            // 同时确认该字段确实被写入了（没写进某个「隐形」副本）。
            assert_ne!(cfg, &MacOsConfig::default(), "字段 `{name}` 未真正写入配置");
        }
    }

    /// A2：`net = Some(MacNetConfig { outbound: Deny, .. })` ⇒ `is_configured()==true`。
    ///
    /// 这是 `PartialEq` 陷阱的回归防线：值恰好等于默认值，但「显式要求禁网」必须算配置。
    /// 与既有的 `explicit_net_deny_counts_as_configured` 并存（断言角度不同：此处直接构造
    /// 结构体字面量，绕过 builder，确保 `is_configured()` 只判 `is_some()`）。
    #[test]
    fn a2_explicit_net_deny_literal_is_configured() {
        let cfg = MacOsConfig {
            net: Some(MacNetConfig {
                outbound: NetAccess::Deny,
                ..Default::default()
            }),
            ..Default::default()
        };
        // 值层面与默认等价，语义层面却是「用户显式配了」。
        assert_eq!(cfg.net, Some(MacNetConfig::default()));
        assert!(cfg.is_configured());
        // resolve 后网络仍是 Deny（不能被「未配」路径改写为全开）。
        assert_eq!(
            cfg.resolve(Path::new("/work")).net.outbound,
            NetAccess::Deny
        );
    }

    /// A3：无预设、无任何字段 ⇒ `is_configured()==false`（不施加沙箱）。
    #[test]
    fn a3_bare_default_is_not_configured() {
        assert!(!MacOsConfig::default().is_configured());
        // 全字段显式置 None / 空 Vec 也仍是「未配置」。
        let explicit = MacOsConfig {
            preset: None,
            write: Vec::new(),
            workspace: None,
            deny_write: Vec::new(),
            tmp_writable: None,
            read: None,
            deny_read: Vec::new(),
            no_credential_deny: None,
            allow_git_write: None,
            net: None,
        };
        assert!(!explicit.is_configured());
    }

    /// A4：`ReadOnly` + `tmp_writable = Some(false)` ⇒ `resolve().tmp_writable == false`。
    ///
    /// 「预设给默认值、字段可覆盖」的核心用法：预设的 `tmp_writable` 是 `true`，
    /// 显式 `Some(false)` 必须赢。
    #[test]
    fn a4_read_only_with_tmp_writable_disabled() {
        let cwd = Path::new("/work");

        // 只看预设：TMP 可写。
        let base = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .resolve(cwd);
        assert!(base.tmp_writable, "ReadOnly 预设默认 TMP 可写");

        // 显式覆盖。
        let overridden = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_tmp_writable(Some(false))
            .resolve(cwd);
        assert!(!overridden.tmp_writable);
        // 其余字段仍跟随预设，未被覆盖。
        assert_eq!(overridden.read, MacReadMode::All);
        assert!(overridden.allow_git_write);
        assert!(overridden.credential_deny);
        assert_eq!(overridden.net.outbound, NetAccess::Deny);
        assert!(!overridden.full_access);
    }

    /// A5：预设 + 无字段 ⇒ `resolve()` 等于该预设的 `defaults()`。
    ///
    /// 唯一例外是 `WorkspaceWrite`：它的写根是 `cwd`，`defaults()` 拿不到，
    /// 由 `resolve(cwd)` 填入——故期望值是 `defaults()` 的 `write` 替换成 `[cwd]`。
    #[test]
    fn a5_preset_alone_equals_defaults() {
        let cwd = Path::new("/work");

        for preset in [
            MacPreset::ReadOnly,
            MacPreset::WorkspaceWrite,
            MacPreset::FullAccess,
        ] {
            let cfg = MacOsConfig::default().with_mac_preset(preset);
            let mut expected = preset.defaults();
            if preset == MacPreset::WorkspaceWrite {
                expected.write = vec![cwd.to_path_buf()];
            }
            assert_eq!(
                cfg.resolve(cwd),
                expected,
                "预设 {preset:?} 在无字段时 resolve() 应等于 defaults()"
            );
        }

        // WorkspaceWrite 的写根确实来自 cwd（换个 cwd 就跟着变）。
        let ww = MacOsConfig::default().with_mac_preset(MacPreset::WorkspaceWrite);
        let other = ww.resolve(Path::new("/elsewhere"));
        assert_eq!(other.write, vec![PathBuf::from("/elsewhere")]);
    }

    /// A6：用户 `deny_read` **追加**，不冲掉内置凭据清单（含预设清单条目）。
    ///
    /// 静默丢弃凭据清单 = 安全回退，因此 Vec 字段的合并语义是「内置在前 + 用户追加」。
    #[test]
    fn a6_user_deny_read_appends_to_credential_list() {
        let cwd = Path::new("/work");
        let creds = credential_paths();
        assert_eq!(creds.len(), CREDENTIAL_PATHS.len());
        let user = PathBuf::from("/secret");

        // 无预设（安全基线）：凭据清单在最前，用户条目在最后。
        let baseline = MacOsConfig::default()
            .with_mac_deny_read(user.clone())
            .resolve(cwd);
        assert_eq!(baseline.deny_read.len(), CREDENTIAL_PATHS.len() + 1);
        assert_eq!(&baseline.deny_read[..CREDENTIAL_PATHS.len()], &creds[..]);
        assert_eq!(baseline.deny_read.last(), Some(&user));

        // 带预设：预设清单条目（凭据）一条不少。
        let with_preset = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_deny_read(user.clone())
            .resolve(cwd);
        assert_eq!(with_preset.deny_read.len(), CREDENTIAL_PATHS.len() + 1);
        for cred in CREDENTIAL_PATHS {
            assert!(
                with_preset.deny_read.iter().any(|p| p == Path::new(cred)),
                "内置凭据条目 {cred} 被用户 deny_read 冲掉"
            );
        }

        // `deny_write` 同样是「追加」而非「替换」。
        let dw = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_deny_write("/secret-w")
            .resolve(cwd);
        assert_eq!(dw.deny_write.len(), CREDENTIAL_PATHS.len() + 1);
        assert_eq!(dw.deny_write.last(), Some(&PathBuf::from("/secret-w")));
    }

    /// A7：`read` 在 `Some(Only(..))` 与 `Some(All)` 之间切换。
    #[test]
    fn a7_read_mode_switches_between_only_and_all() {
        let cwd = Path::new("/work");
        let a = PathBuf::from("/a");
        let b = PathBuf::from("/b");

        // `--mac-read /a` ⇒ 首次即切到 Only。
        let one = MacOsConfig::default().with_mac_read(a.clone());
        assert_eq!(one.read, Some(MacReadMode::Only(vec![a.clone()])));
        assert!(one.is_configured());
        assert_eq!(one.resolve(cwd).read, MacReadMode::Only(vec![a.clone()]));

        // 再加一条 ⇒ 继续追加（仍在 Only）。
        let two = one.with_mac_read(b.clone());
        assert_eq!(
            two.read,
            Some(MacReadMode::Only(vec![a.clone(), b.clone()]))
        );

        // `--mac-read-all` ⇒ 回 All（覆盖掉 Only 列表）。
        let all = two.with_mac_read_all();
        assert_eq!(all.read, Some(MacReadMode::All));
        assert_eq!(all.resolve(cwd).read, MacReadMode::All);

        // All 之后再来 `--mac-read` ⇒ 重新变成 Only，只保留新路径。
        let back = all.with_mac_read(PathBuf::from("/c"));
        assert_eq!(
            back.read,
            Some(MacReadMode::Only(vec![PathBuf::from("/c")]))
        );
        assert_eq!(
            back.resolve(cwd).read,
            MacReadMode::Only(vec![PathBuf::from("/c")])
        );
    }

    /// A8：`FullAccess` + 显式 `deny_read` ⇒ 用户 deny 仍保留。
    ///
    /// `FullAccess` 自身不产生凭据清单（`credential_deny == false`），但**用户显式**
    /// 给出的拒绝必须生效——`(allow default)` 之后写 `(deny file-read*)` 才能兜住。
    #[test]
    fn a8_full_access_keeps_user_deny_read() {
        let cwd = Path::new("/work");
        let user = PathBuf::from("/secret");

        let p = MacOsConfig::default()
            .with_mac_preset(MacPreset::FullAccess)
            .with_mac_deny_read(user.clone())
            .with_mac_deny_write(PathBuf::from("/secret-w"))
            .resolve(cwd);
        assert!(p.full_access);
        assert!(!p.credential_deny, "FullAccess 忽略内置凭据保护");
        assert_eq!(p.deny_read, vec![user.clone()]);
        assert_eq!(p.deny_write, vec![PathBuf::from("/secret-w")]);

        // 关闭凭据保护时，用户「手写」的内置同名条目仍要保留（retain 只删自动注入的那份）。
        let manual = MacOsConfig::default()
            .with_mac_preset(MacPreset::ReadOnly)
            .with_mac_credential_deny(Some(false))
            .with_mac_deny_read("~/.ssh")
            .resolve(cwd);
        assert!(!manual.credential_deny);
        assert_eq!(manual.deny_read, vec![PathBuf::from("~/.ssh")]);
        // 自动注入的其余凭据条目已被移除。
        assert!(!manual.deny_write.iter().any(|p| p.starts_with("~")));
    }

    /// A9：纯预设 / 纯字段 / 预设+字段三种使用形态均不 panic，且 `validate()` 通过。
    #[test]
    fn a9_three_config_shapes_do_not_panic() {
        let cwd = Path::new("/work");

        // 形态一：纯预设。
        for preset in [
            MacPreset::ReadOnly,
            MacPreset::WorkspaceWrite,
            MacPreset::FullAccess,
        ] {
            let cfg = MacOsConfig::default().with_mac_preset(preset);
            assert!(cfg.validate().is_ok());
            let p = cfg.resolve(cwd);
            assert_eq!(p.read, MacReadMode::All);
            assert_eq!(p.full_access, preset == MacPreset::FullAccess);
        }

        // 形态二：纯字段（无预设 ⇒ 安全基线）。
        let fields_only = MacOsConfig::default()
            .with_mac_write("/w")
            .with_mac_deny_write("/dw")
            .with_mac_deny_read("/dr")
            .with_mac_tmp_writable(Some(true));
        assert!(fields_only.validate().is_ok());
        let p = fields_only.resolve(cwd);
        assert_eq!(p.write, vec![PathBuf::from("/w")]);
        assert!(p.tmp_writable, "基线 tmp_writable=false，显式 true 覆盖");
        assert!(!p.full_access);
        assert_eq!(p.deny_read.len(), CREDENTIAL_PATHS.len() + 1);

        // 形态三：预设 + 字段。
        let combined = MacOsConfig::default()
            .with_mac_preset(MacPreset::WorkspaceWrite)
            .with_mac_write("/extra")
            .with_mac_no_git_write()
            .with_mac_net(NetAccess::Ports(vec![443]))
            .with_mac_net_inbound(true);
        assert!(combined.validate().is_ok());
        let p = combined.resolve(cwd);
        // 预设值在前（cwd），用户值追加。
        assert_eq!(
            p.write,
            vec![PathBuf::from("/work"), PathBuf::from("/extra")]
        );
        assert!(!p.allow_git_write);
        assert_eq!(p.net.outbound, NetAccess::Ports(vec![443]));
        assert!(p.net.inbound_loopback);
    }

    /// A10：`resolve()` 连调两次结果相同（幂等），三种预设 + 基线各测一遍。
    ///
    /// 除 `cwd` 外不碰文件系统、不读环境变量，故两次结果必须逐字段相等。
    #[test]
    fn a10_resolve_is_idempotent_for_all_shapes() {
        let cwd = Path::new("/work");
        let cases = [
            MacOsConfig::default(),
            MacOsConfig::default().with_mac_preset(MacPreset::ReadOnly),
            MacOsConfig::default().with_mac_preset(MacPreset::WorkspaceWrite),
            MacOsConfig::default().with_mac_preset(MacPreset::FullAccess),
            MacOsConfig::default()
                .with_mac_preset(MacPreset::WorkspaceWrite)
                .with_mac_write("/extra")
                .with_mac_deny_read("/secret")
                .with_mac_no_credential_deny()
                .with_mac_net(NetAccess::Loopback),
        ];
        for cfg in &cases {
            assert_eq!(cfg.resolve(cwd), cfg.resolve(cwd));
        }
        // 换 cwd 只影响 WorkspaceWrite 的写根，不影响幂等性本身。
        let ww = MacOsConfig::default().with_mac_preset(MacPreset::WorkspaceWrite);
        assert_eq!(ww.resolve(Path::new("/a")), ww.resolve(Path::new("/a")));
    }
}
