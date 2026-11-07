//! macOS Seatbelt 后端。
//!
//! 分层（mac 与 linux 彻底拆分，见 docs/design-plans/macos-seatbelt.md §3.1）：
//! - `config`: 配置类型与解析，**无条件编译**，Linux CI 可单测
//! - `sbpl`:   SBPL 生成器，**无条件编译**，Linux CI 可单测
//! - `imp`:    实现侧（MacSandbox / MacChild / canary / fd 清扫），
//!   `#[cfg(target_os = "macos")]` 整模块门控（依赖 `libc` 与 `sandbox-exec`）
//!
//! 三者对 Linux 侧模块**零引用**；`src/linux/` 对 macOS 侧亦然（N13 双向审计）。

pub mod config;
pub mod sbpl;

#[cfg(target_os = "macos")]
pub(crate) mod imp;
