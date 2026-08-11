//! `@file` argfile 预处理。
//!
//! 在 clap 解析之前展开 `@file` flag 文本进 argv，使 profile 复用同一个
//! clap 解析器。不提供内置命名预设——flag 内容完全由使用方通过 `@file` 提供。
//!
//! 占位符：`{workspace}` → 主进程 cwd、`~` → `$HOME`。仅 `@file` 来源 token
//! 替换，手动 flag 原样。

use std::ffi::{OsStr, OsString};
use std::path::Path;

/// 嵌套 `@file` 展开深度上限（防递归爆栈）。
const MAX_DEPTH: usize = 8;

/// 预处理 argv：展开 `@file` flag 文本，替换占位符。
///
/// 只处理选项区（首个裸 `--` 之前）；`--` 之后命令区 `@x` 原样保留。
/// 无 `--` 时整个 argv 都是选项区（`@` 也展开）。
pub fn preprocess(
    argv: impl IntoIterator<Item = impl AsRef<OsStr>>,
    cwd: &Path,
    home: Option<&Path>,
) -> anyhow::Result<Vec<OsString>> {
    let mut out: Vec<OsString> = Vec::new();
    // 当前展开栈（环检测）：记录正在展开的文件真实路径。
    let mut stack: Vec<std::path::PathBuf> = Vec::new();
    // 选项区状态：首个裸 `--` 之前为选项区（可展开 @），之后进入命令区。
    let mut in_option_zone = true;

    for arg in argv {
        let arg = arg.as_ref().to_os_string();

        // 选项区边界：首个裸 `--` 之后进入命令区，原样保留。
        if in_option_zone && arg == OsStr::new("--") {
            in_option_zone = false;
            out.push(arg);
            continue;
        }

        // 选项区内的 `@path` token 展开。
        if in_option_zone {
            if let Some(s) = arg.to_str() {
                if let Some(path) = s.strip_prefix('@') {
                    let file = std::path::PathBuf::from(path);
                    expand_file(&file, cwd, home, 0, &mut stack, &mut out)?;
                    continue;
                }
            }
        }

        out.push(arg);
    }

    Ok(out)
}

/// 展开单个 `@file`：读文件 → 切分 → 占位符替换 → 插入 `out`。
///
/// 支持嵌套（切分出的 token 若是 `@other` 递归展开），`depth` 递增，
/// `stack` 用于环检测（记录正在展开的文件路径集合）。
fn expand_file(
    path: &Path,
    cwd: &Path,
    home: Option<&Path>,
    depth: usize,
    stack: &mut Vec<std::path::PathBuf>,
    out: &mut Vec<OsString>,
) -> anyhow::Result<()> {
    if depth > MAX_DEPTH {
        anyhow::bail!(
            "profile nesting too deep (max depth {MAX_DEPTH}): {}",
            path.display()
        );
    }

    // 环检测：用 canonicalize 归一化路径。文件不存在时 canonicalize 报错，
    // 正好覆盖"缺文件"场景（错误含路径）。
    let canon =
        std::fs::canonicalize(path).map_err(|e| anyhow::anyhow!("@{}: {e}", path.display()))?;
    if stack.contains(&canon) {
        let mut chain: Vec<String> = stack.iter().map(|p| format!("@{}", p.display())).collect();
        chain.push(format!("@{}", path.display()));
        anyhow::bail!("circular profile reference: {}", chain.join(" -> "));
    }
    stack.push(canon.clone());

    let content =
        std::fs::read_to_string(&canon).map_err(|e| anyhow::anyhow!("@{}: {e}", path.display()))?;

    for token in tokenize(&content) {
        // 嵌套展开：切分出的 token 若以 @ 开头继续展开。
        if let Some(nested_path) = token.strip_prefix('@') {
            let nested = std::path::PathBuf::from(nested_path);
            expand_file(&nested, cwd, home, depth + 1, stack, out)?;
        } else {
            out.push(OsString::from(replace_placeholders(&token, cwd, home)));
        }
    }

    stack.pop();
    Ok(())
}

/// 替换占位符：`{workspace}` → cwd、`~`/`~/`/`~:` → home。
///
/// 仅对 `@file` 来源 token 调用（手动 flag 原样）。运行时
/// `config.rs::expand_tilde` 只兜底 landlock path 与 cwd，**不兜底 mount 路径**，
/// 所以这里必须对所有 token 完成替换。
///
/// `~` 前缀替换：token 开头为 `~` 且后随 `/`/`:`/结束 时，替换为 home 前缀
///（覆盖 `~`、`~/x`、`~:ro` 三种形式）。
fn replace_placeholders(token: &str, cwd: &Path, home: Option<&Path>) -> String {
    let expanded = token.replace("{workspace}", &cwd.to_string_lossy());
    let Some(home) = home else {
        return expanded;
    };
    let home = home.to_string_lossy();

    // `~` 前缀替换：`~`、`~/x`、`~:ro` → `<home>`、`<home>/x`、`<home>:ro`。
    if expanded == "~" {
        return home.into_owned();
    }
    if let Some(rest) = expanded.strip_prefix("~/") {
        return format!("{home}/{rest}");
    }
    if let Some(rest) = expanded.strip_prefix("~:") {
        return format!("{home}:{rest}");
    }
    expanded
}

/// 空白切分 `@file` 内容，支持引号、反斜杠转义、`#` 注释。
///
/// 参照 GCC response-file 惯例：空白分隔 token；单/双引号成组；
/// 反斜杠转义下一个字符；`#` 到行尾是注释。
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut chars = input.chars().peekable();
    let mut in_token = false;

    while let Some(c) = chars.next() {
        match c {
            '"' | '\'' => {
                in_token = true;
                let quote = c;
                // 引号内不转义（保留字面），遇同名引号关闭。
                for inner in chars.by_ref() {
                    if inner == quote {
                        break;
                    }
                    cur.push(inner);
                }
            }
            '\\' => {
                in_token = true;
                match chars.next() {
                    // 行尾续行（`\` + 换行）：丢弃两者。
                    Some('\n') => {}
                    // 转义下一个字符（含空格：`a\ b` → `a b`）。
                    Some(next) => cur.push(next),
                    // 行尾孤立反斜杠：忽略。
                    None => {}
                }
            }
            '#' => {
                // 注释：先 flush 当前 token（`a#comment` → `a`），再跳到行尾。
                if in_token {
                    tokens.push(std::mem::take(&mut cur));
                    in_token = false;
                }
                for inner in chars.by_ref() {
                    if inner == '\n' {
                        break;
                    }
                }
            }
            c if c.is_whitespace() => {
                if in_token {
                    tokens.push(std::mem::take(&mut cur));
                    in_token = false;
                }
            }
            c => {
                in_token = true;
                cur.push(c);
            }
        }
    }
    if in_token {
        tokens.push(cur);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    /// 便捷：对给定 argv 字符串列表运行 preprocess，返回展开后的字符串列表。
    fn run(args: &[&str], cwd: &Path) -> Vec<String> {
        let out = preprocess(
            args.iter().map(OsString::from),
            cwd,
            Some(Path::new("/home/testuser")),
        )
        .expect("preprocess should succeed");
        out.into_iter()
            .map(|o| o.to_string_lossy().into_owned())
            .collect()
    }

    /// 便捷：建临时文件，内容为 `content`，返回 `@路径` 形式的 argv token。
    fn temp_file(content: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("profile.txt");
        std::fs::write(&path, content).expect("write temp profile");
        let s = format!("@{}", path.to_string_lossy());
        (dir, s)
    }

    #[test]
    fn test_preprocess_plain_args_passthrough() {
        let out = run(
            &["run", "--landlock", "/:ro", "--", "echo", "hi"],
            Path::new("/w"),
        );
        assert_eq!(out, vec!["run", "--landlock", "/:ro", "--", "echo", "hi"]);
    }

    #[test]
    fn test_preprocess_expands_argfile_in_place() {
        let (_dir, path) = temp_file("--unshare-net --allow-network");
        let out = run(&["run", &path, "--", "ls"], Path::new("/w"));
        assert_eq!(
            out,
            vec!["run", "--unshare-net", "--allow-network", "--", "ls"]
        );
    }

    #[test]
    fn test_preprocess_no_double_dash_expands_too() {
        // 无 `--` 时整个 argv 是选项区，@ 也展开。
        let (_dir, path) = temp_file("--unshare-net");
        let out = run(&["run", &path, "cargo"], Path::new("/w"));
        assert_eq!(out, vec!["run", "--unshare-net", "cargo"]);
    }

    #[test]
    fn test_preprocess_command_zone_at_not_expanded() {
        // `--` 之后命令区 @x 原样。
        let out = run(&["run", "--", "echo", "@not-a-profile"], Path::new("/w"));
        assert_eq!(out, vec!["run", "--", "echo", "@not-a-profile"]);
    }

    #[test]
    fn test_preprocess_workspace_placeholder() {
        let (_dir, path) = temp_file("--bind {workspace}/src {workspace}/dst");
        let out = run(&["run", &path, "--", "ls"], Path::new("/my/workspace"));
        assert_eq!(
            out,
            vec![
                "run",
                "--bind",
                "/my/workspace/src",
                "/my/workspace/dst",
                "--",
                "ls"
            ]
        );
    }

    #[test]
    fn test_preprocess_tilde_placeholder() {
        let (_dir, path) = temp_file("--bind ~/src /dst");
        let out = run(&["run", &path, "--", "ls"], Path::new("/w"));
        assert_eq!(
            out,
            vec!["run", "--bind", "/home/testuser/src", "/dst", "--", "ls"]
        );
    }

    #[test]
    fn test_preprocess_tilde_only_placeholder() {
        let (_dir, path) = temp_file("--landlock ~:ro");
        let out = run(&["run", &path], Path::new("/w"));
        assert_eq!(out, vec!["run", "--landlock", "/home/testuser:ro"]);
    }

    #[test]
    fn test_preprocess_quotes_and_comments() {
        let (_dir, path) =
            temp_file("# 这是注释\n--env 'FOO=bar baz' --env \"A=B C\" \\\n--landlock /tmp:rw");
        let out = run(&["run", &path, "--", "env"], Path::new("/w"));
        assert_eq!(
            out,
            vec![
                "run",
                "--env",
                "FOO=bar baz",
                "--env",
                "A=B C",
                "--landlock",
                "/tmp:rw",
                "--",
                "env"
            ]
        );
    }

    #[test]
    fn test_preprocess_nested_argfile() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&b, "--unshare-net").unwrap();
        std::fs::write(&a, format!("@{}", b.to_string_lossy())).unwrap();
        let a_token = format!("@{}", a.to_string_lossy());
        let out = run(&["run", &a_token], Path::new("/w"));
        assert_eq!(out, vec!["run", "--unshare-net"]);
    }

    #[test]
    fn test_preprocess_circular_reference_detected() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, format!("@{}", b.to_string_lossy())).unwrap();
        std::fs::write(&b, format!("@{}", a.to_string_lossy())).unwrap();

        let argv: Vec<OsString> = vec![
            OsString::from("run"),
            OsString::from(&format!("@{}", a.to_string_lossy())),
        ];
        let err = preprocess(argv.iter(), Path::new("/w"), None).unwrap_err();
        assert!(
            err.to_string().contains("circular"),
            "expected circular error, got: {err}"
        );
    }

    #[test]
    fn test_preprocess_depth_limit() {
        let dir = tempfile::tempdir().unwrap();
        // 生成 MAX_DEPTH+1 层嵌套，最后一个是叶子。
        let mut files = Vec::new();
        for i in 0..=MAX_DEPTH + 1 {
            let f = dir.path().join(format!("f{i}.txt"));
            if i == MAX_DEPTH + 1 {
                std::fs::write(&f, "--unshare-net").unwrap();
            } else {
                let next = dir.path().join(format!("f{}.txt", i + 1));
                std::fs::write(&f, format!("@{}", next.to_string_lossy())).unwrap();
            }
            files.push(f);
        }
        let argv: Vec<OsString> = vec![
            OsString::from("run"),
            OsString::from(&format!("@{}", files[0].to_string_lossy())),
        ];
        let err = preprocess(argv.iter(), Path::new("/w"), None).unwrap_err();
        assert!(
            err.to_string().contains("too deep"),
            "expected depth error, got: {err}"
        );
    }

    #[test]
    fn test_preprocess_missing_file_error_has_name() {
        let argv: Vec<OsString> = vec![
            OsString::from("run"),
            OsString::from("@/nonexistent/x.profile"),
        ];
        let err = preprocess(argv.iter(), Path::new("/w"), None).unwrap_err();
        assert!(
            err.to_string().contains("x.profile"),
            "error should include filename, got: {err}"
        );
    }

    #[test]
    fn test_preprocess_empty_argfile() {
        let (_dir, path) = temp_file("   \n# comment only\n");
        let out = run(&["run", &path, "--", "ls"], Path::new("/w"));
        assert_eq!(out, vec!["run", "--", "ls"]);
    }

    #[test]
    fn test_tokenize_basic() {
        assert_eq!(tokenize("a b  c"), vec!["a", "b", "c"]);
        assert_eq!(tokenize("  leading spaces  "), vec!["leading", "spaces"]);
    }

    #[test]
    fn test_tokenize_quotes() {
        assert_eq!(
            tokenize("'single word' double"),
            vec!["single word", "double"]
        );
        assert_eq!(tokenize("a\"b c\"d"), vec!["ab cd"]);
    }

    #[test]
    fn test_tokenize_escape() {
        assert_eq!(tokenize("a\\ b c"), vec!["a b", "c"]);
        assert_eq!(tokenize("a\\\\b"), vec!["a\\b"]);
    }

    #[test]
    fn test_tokenize_comments() {
        assert_eq!(tokenize("a # comment\nb"), vec!["a", "b"]);
        assert_eq!(tokenize("a#no-space\nb"), vec!["a", "b"]);
    }

    #[test]
    fn test_replace_placeholders_untouched() {
        let out = replace_placeholders("--landlock", Path::new("/w"), Some(Path::new("/home/u")));
        assert_eq!(out, "--landlock");
    }
}
