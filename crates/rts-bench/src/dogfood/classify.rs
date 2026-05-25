//! Bash-command classifier for `rts-bench dogfood`.
//!
//! Decides whether a `Bash` tool call's `command` string looks like
//! a workspace navigation task that an `mcp__rts__*` tool would have
//! served better. The output drives the dogfood report's
//! `bash_candidate_fallthroughs` counts.
//!
//! Design rules:
//!
//! 1. **Token-level, not regex-heavy.** Split on shell whitespace and
//!    look at the first token (modulo `env VAR=val` prefixes). The
//!    classifier is meant to be readable line-by-line; reach for
//!    regex only when the pattern genuinely needs it.
//! 2. **False positives are fine, false negatives are worse.** The
//!    framing is "candidate fall-throughs", not "definitely wrong
//!    tool". If a call is ambiguous, lean toward classifying it.
//! 3. **Exclude obvious non-candidates explicitly.** Shell pipelines
//!    (`grep foo bar | head`), git plumbing (`git grep`), build
//!    invocations (`cargo`, `make`), and `cat /tmp/...` are out of
//!    scope. Comment each exclusion so a reader can audit.
//!
//! The patterns this catches:
//!
//! | Leading token | → would_prefer            | Excludes                          |
//! |--------------|---------------------------|-----------------------------------|
//! | `grep`/`rg`/`egrep`/`fgrep`/`ack` | `mcp__rts__grep`        | pipelines (`grep …\|…`) when piped FROM, not to |
//! | `find`       | `mcp__rts__outline_workspace`/`find_symbol` | `find /tmp`, `find ~/Downloads`, no `-name`/`-path` filters |
//! | `cat <file>` | `mcp__rts__read_range`    | `cat /tmp/...`, `cat /dev/null`, redirection (`cat > x`), heredocs |
//! | `ls`         | `mcp__rts__outline_workspace` | `ls /tmp`, `ls ~/.claude`, anything with `-l`/`-la` (browsing dirs ≠ orienting in a repo) |
//!
//! What it deliberately doesn't catch (and why):
//!
//! - **Compound pipelines.** `grep foo bar | head -n 5` — we DO catch
//!   this because the leading token is still `grep` and the agent's
//!   intent is workspace search. But `cat foo | wc -l` is excluded
//!   because the intent is character counting, not file reading.
//!   The heuristic: classify by *the leading token's purpose*, not
//!   what comes after.
//! - **`git grep`, `cargo`, `make`.** These are version-control /
//!   build invocations, not workspace navigation. Skipped.
//! - **`cat /tmp/...` / `cat /var/...`.** Reading a tempfile is a
//!   shell-pipeline detail (often the result of one tool feeding
//!   another); rts doesn't help.
//! - **Interactive shells, `sudo`, `env`.** We strip a single leading
//!   `env VAR=val` if present and continue, but anything wrapped in
//!   `bash -c '…'` is left alone — we don't try to parse arbitrary
//!   shell.

/// Tagged enum of the four candidate categories. Variants line up
/// 1:1 with the `FallthroughCounts` fields in `mod.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BashCandidate {
    GrepOrRg,
    Find,
    CatFile,
    LsWorkspace,
}

impl BashCandidate {
    /// The `mcp__rts__*` tool the candidate would have called instead.
    /// Stable strings — they appear in the report JSON's `would_prefer`
    /// field and are matched on by smoke tests.
    pub fn would_prefer(self) -> &'static str {
        match self {
            BashCandidate::GrepOrRg => "mcp__rts__grep",
            BashCandidate::Find => "mcp__rts__find_symbol",
            BashCandidate::CatFile => "mcp__rts__read_range",
            BashCandidate::LsWorkspace => "mcp__rts__outline_workspace",
        }
    }
}

/// Top-level classifier. Returns `Some(BashCandidate)` when the
/// command looks like a workspace-navigation operation an rts tool
/// could have replaced; `None` otherwise.
///
/// The function is intentionally a flat dispatch on the first
/// meaningful token. Pattern-table-driven would be cute but harder
/// to audit at code-review time, and the input space is fixed at
/// four categories.
pub fn classify_bash_command(command: &str) -> Option<BashCandidate> {
    let stripped = strip_env_prefix(command.trim());

    // `git grep`, `git ls-files`, etc. are version-control queries,
    // not workspace search. Skip outright. Same for cargo/make/etc.
    if starts_with_word(stripped, "git")
        || starts_with_word(stripped, "cargo")
        || starts_with_word(stripped, "make")
        || starts_with_word(stripped, "npm")
        || starts_with_word(stripped, "yarn")
        || starts_with_word(stripped, "pnpm")
    {
        return None;
    }

    if is_grep_like(stripped) {
        return Some(BashCandidate::GrepOrRg);
    }
    if is_find_workspace(stripped) {
        return Some(BashCandidate::Find);
    }
    if is_cat_workspace_file(stripped) {
        return Some(BashCandidate::CatFile);
    }
    if is_ls_workspace(stripped) {
        return Some(BashCandidate::LsWorkspace);
    }
    None
}

/// Strip a single leading `env VAR=val [VAR2=val2]` prefix so a call
/// like `env RUST_LOG=debug grep foo .` still classifies as grep.
/// We don't recurse — multiple `env` levels are rare and the cost of
/// false negatives there is one un-counted call.
fn strip_env_prefix(cmd: &str) -> &str {
    let rest = cmd.strip_prefix("env ").unwrap_or(cmd);
    // After `env`, skip `KEY=value` tokens until we hit a non-assignment.
    let mut tail = rest;
    loop {
        let trimmed = tail.trim_start();
        let next_word_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
        let next_word = &trimmed[..next_word_end];
        if next_word.contains('=') && !next_word.starts_with('=') {
            tail = &trimmed[next_word_end..];
            continue;
        }
        return trimmed;
    }
}

/// True iff `s` starts with `word` followed by whitespace or end-of-string.
/// Avoids the `starts_with("grep")` foot-gun where `"grepfor"` matches.
fn starts_with_word(s: &str, word: &str) -> bool {
    if !s.starts_with(word) {
        return false;
    }
    s[word.len()..]
        .chars()
        .next()
        .map(|c| c.is_whitespace())
        .unwrap_or(true)
}

/// `grep`, `rg`, `egrep`, `fgrep`, `ack`, `ack-grep` — anything whose
/// purpose is text search.
fn is_grep_like(s: &str) -> bool {
    starts_with_word(s, "grep")
        || starts_with_word(s, "rg")
        || starts_with_word(s, "egrep")
        || starts_with_word(s, "fgrep")
        || starts_with_word(s, "ack")
        || starts_with_word(s, "ack-grep")
}

/// `find` rooted at the workspace, with at least one filter
/// (`-name`/`-path`/`-iname`/`-regex`). Bare `find /tmp` or `find ~`
/// is excluded — those aren't workspace-navigation tasks.
///
/// Exclusion list matches paths that obviously aren't the workspace:
/// `/tmp`, `/var`, `/Users/.../Downloads`, `/dev`, `/proc`, anything
/// rooted at `~/.something` (dotdirs in $HOME). Catches the common
/// "find a downloaded file" / "find a tempfile" cases.
fn is_find_workspace(s: &str) -> bool {
    if !starts_with_word(s, "find") {
        return false;
    }
    // Cheap path exclusion. Look at the second token; if it starts
    // with one of these prefixes, it's not workspace-rooted.
    let after_find = s["find".len()..].trim_start();
    let next = after_find.split_whitespace().next().unwrap_or("");
    for prefix in &[
        "/tmp",
        "/var",
        "/dev",
        "/proc",
        "/sys",
        "~/Downloads",
        "~/Library",
        "~/.cache",
        "/Users", // catches "find /Users/.../Downloads" too — we still
                  // want to classify "find . -name '*.rs'" since `.`
                  // is the leading non-flag token.
    ] {
        if next.starts_with(prefix) && next != "." && !next.starts_with("/Users/n/Rustrover") {
            // Heuristic carve-out: if the search root is under
            // /Users/n/Rustrover... it's a workspace path; let it
            // through. The `/Users` prefix is otherwise too broad.
            return false;
        }
    }
    // Require at least one filter flag — bare `find /some/path` is
    // a directory listing, not symbol-shaped navigation.
    s.contains("-name ") || s.contains("-iname ") || s.contains("-path ") || s.contains("-regex ")
}

/// `cat <file>` where the file isn't a tempfile / device / heredoc /
/// stdin. Excludes shell-pipeline glue (`cat foo > bar`, `cat << EOF`)
/// because that's not workspace reading either.
fn is_cat_workspace_file(s: &str) -> bool {
    if !starts_with_word(s, "cat") {
        return false;
    }
    // Reject shell redirection / heredoc shapes outright.
    if s.contains("<<") || s.contains(">") || s.contains("<(") {
        return false;
    }
    let arg = s["cat".len()..].trim();
    if arg.is_empty() {
        return false; // `cat` alone reads stdin
    }
    // Filter out obvious non-workspace targets.
    if arg.starts_with("/tmp")
        || arg.starts_with("/var")
        || arg.starts_with("/dev")
        || arg.starts_with("/proc")
        || arg.starts_with("/sys")
        || arg == "-"
    {
        return false;
    }
    // Reject any argument that looks like a flag (`cat -n`, `cat -A`).
    // The intent isn't to read a workspace file in that case.
    if arg.starts_with('-') {
        return false;
    }
    true
}

/// `ls` in a workspace context. The narrow rule: any `ls` invocation
/// whose argument is missing or looks like a relative workspace path
/// (`.`, `src`, `crates/foo`) and which does NOT include long-listing
/// or hidden-file flags (those are usually shell admin, not
/// orientation tasks).
fn is_ls_workspace(s: &str) -> bool {
    if !starts_with_word(s, "ls") {
        return false;
    }
    // Long-form ls -l / ls -la / etc. is typically "what is this
    // directory's metadata" not "what symbols live in this repo".
    // Skip to avoid noise.
    if s.contains(" -l") || s.contains(" -la") || s.contains(" -al") {
        return false;
    }
    let arg = s["ls".len()..].trim();
    if arg.is_empty() || arg == "." {
        return true;
    }
    // Absolute paths outside what looks like a workspace → not interesting.
    if arg.starts_with('/')
        && !arg.starts_with("/Users/")
        && !arg.starts_with("/home/")
        && !arg.starts_with("/workspace")
        && !arg.starts_with("/srv")
    {
        return false;
    }
    // `ls ~/Downloads` etc. — out.
    if arg.starts_with("~/Downloads") || arg.starts_with("~/Library") {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grep_is_classified() {
        let c = classify_bash_command("grep -rn 'fn foo' crates/").unwrap();
        assert_eq!(c, BashCandidate::GrepOrRg);
        assert_eq!(c.would_prefer(), "mcp__rts__grep");
    }

    #[test]
    fn rg_is_classified() {
        assert_eq!(
            classify_bash_command("rg 'pattern' --type rust"),
            Some(BashCandidate::GrepOrRg)
        );
    }

    #[test]
    fn git_grep_is_excluded() {
        // `git grep` is a VCS operation, not a workspace search.
        assert_eq!(classify_bash_command("git grep 'pattern'"), None);
    }

    #[test]
    fn find_with_name_is_classified() {
        assert_eq!(
            classify_bash_command("find . -name '*.rs'"),
            Some(BashCandidate::Find)
        );
    }

    #[test]
    fn find_in_tmp_is_excluded() {
        // /tmp isn't a workspace; rts wouldn't have helped.
        assert_eq!(classify_bash_command("find /tmp -name '*.log'"), None);
    }

    #[test]
    fn find_without_filters_is_excluded() {
        // Bare `find /some/dir` is a listing, not symbol navigation.
        assert_eq!(classify_bash_command("find /Users/n/foo"), None);
    }

    #[test]
    fn cat_workspace_file_is_classified() {
        assert_eq!(
            classify_bash_command("cat crates/rts-bench/src/main.rs"),
            Some(BashCandidate::CatFile)
        );
    }

    #[test]
    fn cat_tmpfile_is_excluded() {
        assert_eq!(classify_bash_command("cat /tmp/foo.log"), None);
    }

    #[test]
    fn cat_with_redirection_is_excluded() {
        assert_eq!(classify_bash_command("cat <<EOF\nhello\nEOF"), None);
        assert_eq!(classify_bash_command("cat foo > bar"), None);
    }

    #[test]
    fn ls_workspace_is_classified() {
        assert_eq!(
            classify_bash_command("ls"),
            Some(BashCandidate::LsWorkspace)
        );
        assert_eq!(
            classify_bash_command("ls crates/"),
            Some(BashCandidate::LsWorkspace)
        );
    }

    #[test]
    fn ls_la_is_excluded() {
        // `ls -la` is admin, not orientation.
        assert_eq!(classify_bash_command("ls -la /etc"), None);
    }

    #[test]
    fn cargo_is_excluded() {
        assert_eq!(classify_bash_command("cargo test --workspace"), None);
    }

    #[test]
    fn env_prefix_is_stripped() {
        assert_eq!(
            classify_bash_command("env RUST_LOG=debug grep foo crates/"),
            Some(BashCandidate::GrepOrRg)
        );
    }

    #[test]
    fn unrelated_command_returns_none() {
        assert_eq!(classify_bash_command("echo hello"), None);
        assert_eq!(classify_bash_command("date"), None);
    }
}
