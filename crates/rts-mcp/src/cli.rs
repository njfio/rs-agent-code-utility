//! Shared CLI implementation for the `rts` human-facing binary.
//!
//! The binary entry point is `src/bin/rts.rs`; this module holds the
//! reusable surface (workspace resolution, daemon RPC wrappers,
//! renderers, exit codes) so it can be unit-tested without spawning a
//! process. Per the human-CLI plan (`docs/plans/2026-05-19-002-…`).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::connection::{ConnectionError, ConnectionManager, ResilienceConfig};
use crate::daemon_client::DaemonClient;
use crate::socket;

/// Documented exit-code contract for the `rts` binary.
///
/// 0 — success with results.
/// 1 — success with zero results (matches `rg`'s convention).
/// 2 — clap-handled invalid argument (clap exits this itself).
/// 3 — daemon-level error (JSON-RPC error envelope).
/// 4 — request timeout.
/// 5 — workspace resolution error (no marker found, path missing, etc.).
pub mod exit {
    pub const OK: i32 = 0;
    pub const NO_RESULTS: i32 = 1;
    pub const DAEMON_ERROR: i32 = 3;
    pub const TIMEOUT: i32 = 4;
    pub const WORKSPACE_ERROR: i32 = 5;
}

/// Workspace-marker files we look for when `--workspace` is omitted.
/// Ordered by specificity / frequency. Mirrors `rts-bench`'s
/// `detect_workspace_from` so users who already use `rts-bench query`
/// get identical behavior on the new CLI.
const MARKERS: &[&str] = &[
    "Cargo.toml",       // Rust
    "package.json",     // JS / TS
    "go.mod",           // Go
    "pyproject.toml",   // Python (modern)
    "setup.py",         // Python (legacy)
    "pom.xml",          // Java / Maven
    "build.gradle",     // Java / Kotlin (Gradle Groovy DSL)
    "build.gradle.kts", // Kotlin (Gradle KTS)
    "Gemfile",          // Ruby
    "composer.json",    // PHP
    "Package.swift",    // Swift
    ".git",             // generic VCS fallback
];

/// Walk upward from `start` looking for any workspace marker.
/// Returns `None` if no marker is found — the caller decides whether to
/// fall back to `start` itself (CLI does) or error out.
pub fn detect_workspace_from(start: &Path) -> Option<PathBuf> {
    let mut dir: Option<&Path> = Some(start);
    while let Some(d) = dir {
        for marker in MARKERS {
            if d.join(marker).exists() {
                return Some(d.to_path_buf());
            }
        }
        dir = d.parent();
    }
    None
}

/// Resolve the workspace path. `override_path` takes precedence; otherwise
/// walk up from `$PWD` and fall back to `$PWD` itself if no marker exists.
/// Errors only when the resolved path doesn't exist on disk — the
/// "couldn't find a marker, used $PWD" case is silent and matches the
/// existing `rts-bench query` behavior.
pub fn resolve_workspace(override_path: Option<&Path>) -> anyhow::Result<PathBuf> {
    let raw = match override_path {
        Some(p) => p.to_path_buf(),
        None => {
            let cwd = std::env::current_dir()?;
            detect_workspace_from(&cwd).unwrap_or(cwd)
        }
    };
    if !raw.exists() {
        anyhow::bail!("workspace path does not exist: {}", raw.display());
    }
    let canon = std::fs::canonicalize(&raw)
        .map_err(|e| anyhow::anyhow!("canonicalize {}: {e}", raw.display()))?;
    Ok(canon)
}

/// ANSI color helper. When `enabled == false`, every method returns the
/// raw text unchanged — call sites stay branch-free.
pub struct Style {
    pub enabled: bool,
}

impl Style {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Detect whether colored output should be emitted.
    /// `--no-color` and `NO_COLOR` env (any non-empty value per
    /// <https://no-color.org/>) both suppress; otherwise colors are
    /// emitted only when stdout is a TTY.
    pub fn auto(no_color_flag: bool) -> Self {
        if no_color_flag {
            return Self { enabled: false };
        }
        // `NO_COLOR` should be honored when set to ANY non-empty value
        // — per the spec, even `NO_COLOR=0` disables color. The
        // is-terminal check then gates emission on actual TTY-ness so
        // piping `rts find Foo | cat` doesn't smuggle escapes through.
        if std::env::var_os("NO_COLOR")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
            return Self { enabled: false };
        }
        use is_terminal::IsTerminal;
        Self {
            enabled: std::io::stdout().is_terminal(),
        }
    }

    fn wrap(&self, code: &str, s: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    pub fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }
    pub fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }
    pub fn cyan(&self, s: &str) -> String {
        self.wrap("36", s)
    }
    pub fn magenta(&self, s: &str) -> String {
        self.wrap("35", s)
    }
}

/// Connect to the daemon for `workspace`, auto-spawning if necessary.
/// `RTS_NO_AUTOSPAWN=1` disables the spawn — if the socket isn't there,
/// we error out instead of starting a daemon (useful in CI / sandboxed
/// environments where the user wants to manage the daemon lifecycle).
///
/// v0.6+: returns a [`ConnectionManager`] (Plan 004) rather than a bare
/// [`DaemonClient`]. The manager owns the socket and exposes the same
/// `call()` API the MCP shim uses; background heartbeat is *disabled*
/// for the CLI (single-shot — no point spawning a task we'll abort
/// 50 ms later) but the foreground reconnect-on-transport-error path
/// still fires, so a CLI invocation that races a daemon restart
/// transparently auto-spawns a fresh daemon instead of bailing.
///
/// Cross-binary parity: same code path the MCP shim's `main.rs` uses,
/// minus the background heartbeat. The structured `DAEMON_UNAVAILABLE`
/// / `DAEMON_DOWN` errors surface via the manager and get mapped to
/// the documented CLI exit codes by [`render_connection_error`].
pub async fn connect(workspace: &Path) -> anyhow::Result<ConnectionManager> {
    let daemon_bin = socket::resolve_daemon_bin()?;

    let no_autospawn = std::env::var_os("RTS_NO_AUTOSPAWN")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);

    let stream = if no_autospawn {
        // Direct connect-or-fail — never spawn. The per-workspace socket
        // path matches the auto-spawn flow's canonicalization so users
        // who started `rts-daemon --workspace PATH` manually land on
        // the same socket.
        let canon = workspace
            .canonicalize()
            .map_err(|e| anyhow::anyhow!("canonicalize {}: {e}", workspace.display()))?;
        let sock_path = socket::workspace_socket_path(&canon)?;
        socket::try_connect(&sock_path).await.ok_or_else(|| {
            anyhow::anyhow!(
                "no rts-daemon socket at {} and RTS_NO_AUTOSPAWN is set. \
                 Start the daemon manually or unset RTS_NO_AUTOSPAWN.",
                sock_path.display()
            )
        })?
    } else {
        // Auto-spawn flow: same code path rts-mcp uses. If the daemon
        // binary isn't on PATH the error message includes install
        // guidance.
        socket::connect_with_auto_spawn(&daemon_bin, Some(workspace))
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "could not connect to rts-daemon: {e:#}\n\n\
                     If rts-daemon isn't installed, install via:\n  \
                     brew install njfio/rts/rts\n\
                     or build from source:\n  \
                     cargo build --release --workspace",
                )
            })?
    };

    let client = DaemonClient::new(stream, daemon_bin.clone(), workspace.to_path_buf());
    Ok(ConnectionManager::new(
        client,
        daemon_bin,
        workspace.to_path_buf(),
        ResilienceConfig::from_env(),
        /* start_background_tasks */ false,
    ))
}

/// Mount + one RPC. Every CLI invocation is a single-shot — the
/// connection manager handles Mount lazily on the first call, so this
/// function is now a thin alias over `ConnectionManager::call`. The
/// `workspace` parameter is unused by the manager (it tracks the path
/// internally) and kept in the signature for source-compatibility
/// with the pre-resilience CLI; future cleanups may drop it.
pub async fn call_method(
    client: &ConnectionManager,
    _workspace: &Path,
    method: &str,
    params: Value,
) -> Result<Value, ConnectionError> {
    client.call(method, params).await
}

/// Map a `ConnectionError` to a user-friendly stderr message and an
/// exit code. Pre-resilience this took a bare `DaemonError`; the
/// signature now accepts a `ConnectionError` so it can render the
/// new `DAEMON_UNAVAILABLE` / `DAEMON_DOWN` shapes with their
/// `retry_after_ms` hints.
///
/// Both transient (`DAEMON_UNAVAILABLE`) and sustained (`DAEMON_DOWN`)
/// disconnections map to exit code `3` (`DAEMON_ERROR`); a future
/// release could split these but the CLI contract today is "any
/// daemon-side problem returns 3."
pub fn render_connection_error(e: &ConnectionError, style: &Style) -> i32 {
    eprintln!(
        "{}: {} ({})",
        style.red("rts error"),
        e.message(),
        style.dim(e.code())
    );
    match e {
        ConnectionError::Daemon(de) if de.code == "DEADLINE_EXCEEDED" => exit::TIMEOUT,
        _ => exit::DAEMON_ERROR,
    }
}

// ── Renderers ─────────────────────────────────────────────────────────

/// Render `Index.FindSymbol` results as a table.
/// `kind | name | path:line | container`.
///
/// Returns the number of matches rendered (used by callers to set the
/// process exit code per the rg-style 0/1 convention).
pub fn render_find_table<W: Write>(
    body: &Value,
    w: &mut W,
    style: &Style,
) -> std::io::Result<usize> {
    let matches = body
        .get("matches")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if matches.is_empty() {
        return Ok(0);
    }

    // Header. `dim` applies subtle gray so the data lines pop.
    let header = format!(
        "{:<10}  {:<32}  {:<40}  {}",
        "KIND", "NAME", "PATH:LINE", "CONTAINER",
    );
    writeln!(w, "{}", style.dim(&header))?;
    for m in &matches {
        let kind = m
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let name = m
            .get("qualified_name")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let file = m
            .get("file")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let line = m
            .get("range")
            .and_then(|r| r.get("start_line"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0);
        let container = m
            .get("container")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();
        let loc = format!("{file}:{line}");
        writeln!(
            w,
            "{:<10}  {:<32}  {:<40}  {}",
            style.cyan(&truncate(&kind, 10)),
            style.bold(&truncate(&name, 32)),
            style.green(&truncate(&loc, 40)),
            style.dim(&container),
        )?;
    }
    Ok(matches.len())
}

/// Render `Index.Grep` results in ripgrep-compatible
/// `relpath:line:col:content` shape. Match span is colored when
/// `style.enabled`. Returns the match count.
pub fn render_grep_lines<W: Write>(
    body: &Value,
    pattern: &str,
    w: &mut W,
    style: &Style,
) -> std::io::Result<usize> {
    let matches = body
        .get("matches")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for m in &matches {
        let file = m.get("file").and_then(|v| v.as_str()).unwrap_or("?");
        let range = m.get("range");
        let mut line = range
            .and_then(|r| r.get("start_line"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0);
        // Daemon `range` is byte-relative, not column-relative. We
        // approximate "col" as the 1-indexed byte offset of the
        // literal inside the line by string-searching for the
        // pattern; falls back to col=1 when not found (rare — the
        // daemon already confirmed a match on this line).
        let line_text = m
            .get("line_text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim_end_matches('\n');
        // Structural-query matches carry no `line_text`; they expose the
        // captured node(s) under `captures`. Render the first capture and
        // take its line *and* column so the emitted `path:line:col`
        // coordinate points at the content we display — the displayed
        // capture may start on a different line than the match range.
        let (col, content) = if line_text.is_empty() {
            match structural_capture(m) {
                Some((cap_line, cap_col, text)) => {
                    line = cap_line;
                    (cap_col, highlight_match(&text, pattern, style))
                }
                None => (compute_col(line_text, pattern), String::new()),
            }
        } else {
            (
                compute_col(line_text, pattern),
                highlight_match(line_text, pattern, style),
            )
        };
        writeln!(
            w,
            "{}:{}:{}:{}",
            style.magenta(file),
            style.green(&line.to_string()),
            col,
            content
        )?;
    }
    Ok(matches.len())
}

/// Extract a structural-query match's first capture as a
/// `(line, 1-indexed col, first-line-of-text)` triple. Structural
/// matches expose captured nodes under `captures.<name>[]` (each with
/// `text` and a 0-indexed `start.{line,col}`) instead of the `line_text`
/// that literal/regex matches carry. Returning the capture's own line
/// (not the enclosing match `range`) keeps the emitted `path:line:col`
/// pointing at the rendered content.
fn structural_capture(m: &Value) -> Option<(u64, usize, String)> {
    let caps = m.get("captures")?.as_object()?;
    let first = caps
        .values()
        .find_map(|arr| arr.as_array().and_then(|a| a.first()))?;
    let start = first.get("start");
    let line = start
        .and_then(|s| s.get("line"))
        .and_then(|n| n.as_u64())
        .unwrap_or(0);
    let col = start
        .and_then(|s| s.get("col"))
        .and_then(|c| c.as_u64())
        .map(|c| c as usize + 1)
        .unwrap_or(1);
    let text = first
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    Some((line, col, text))
}

/// Compute the 1-indexed column (byte offset) of the first
/// case-insensitive substring match of `pattern` inside `line`. Falls
/// back to 1 when not found.
fn compute_col(line: &str, pattern: &str) -> usize {
    if pattern.is_empty() {
        return 1;
    }
    let lower_line = line.to_lowercase();
    let lower_pat = pattern.to_lowercase();
    lower_line.find(&lower_pat).map(|i| i + 1).unwrap_or(1)
}

/// Wrap the first case-insensitive occurrence of `pattern` inside `line`
/// in ANSI red. When `style.enabled == false` returns `line` unchanged.
fn highlight_match(line: &str, pattern: &str, style: &Style) -> String {
    if !style.enabled || pattern.is_empty() {
        return line.to_string();
    }
    let lower_line = line.to_lowercase();
    let lower_pat = pattern.to_lowercase();
    if let Some(idx) = lower_line.find(&lower_pat) {
        // Use char-boundary-safe slicing by mapping the byte index
        // through char_indices. lowercase mapping in `regex` crate
        // territory can be tricky but for ASCII (the common case) the
        // byte offset matches the char offset.
        if line.is_char_boundary(idx) && line.is_char_boundary(idx + pattern.len()) {
            let prefix = &line[..idx];
            let m = &line[idx..idx + pattern.len()];
            let suffix = &line[idx + pattern.len()..];
            return format!("{}{}{}", prefix, style.red(m), suffix);
        }
    }
    line.to_string()
}

/// Render `Index.FindCallers` results tree-grouped by file.
pub fn render_callers_tree<W: Write>(
    body: &Value,
    w: &mut W,
    style: &Style,
) -> std::io::Result<usize> {
    let callers = body
        .get("callers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if callers.is_empty() {
        return Ok(0);
    }
    // Group by file. BTreeMap → stable lexical ordering of file headers.
    let mut grouped: std::collections::BTreeMap<&str, Vec<&Value>> =
        std::collections::BTreeMap::new();
    for c in &callers {
        let file = c.get("file").and_then(|v| v.as_str()).unwrap_or("?");
        grouped.entry(file).or_default().push(c);
    }
    for (file, entries) in grouped {
        writeln!(w, "{}", style.magenta(file))?;
        for c in entries {
            let line = c
                .get("range")
                .and_then(|r| r.get("start_line"))
                .and_then(|n| n.as_u64())
                .unwrap_or(0);
            let enclosing = c
                .get("enclosing_qualified_name")
                .and_then(|v| v.as_str())
                .unwrap_or("<file-scope>");
            let kind = c.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
            writeln!(
                w,
                "  {}:{}  {} {}",
                style.dim("L"),
                style.green(&line.to_string()),
                style.bold(enclosing),
                style.cyan(&format!("({kind})")),
            )?;
        }
    }
    Ok(callers.len())
}

/// Render an `Index.VerifyImpact` verdict: a one-line headline
/// (`would_break` / `safe` / `not_found`) followed by the affected
/// callers grouped by file (mirrors `render_callers_tree`). Returns the
/// number of affected callers so the binary can pick an exit code.
pub fn render_impact_verdict<W: Write>(
    body: &Value,
    w: &mut W,
    style: &Style,
) -> std::io::Result<usize> {
    let resolution = body
        .get("resolution")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let symbol = body.get("symbol").and_then(|v| v.as_str()).unwrap_or("?");
    let change = body.get("change").and_then(|v| v.as_str()).unwrap_or("?");

    // Miss: not_found + did-you-mean candidates, no verdict.
    if resolution == "not_found" {
        writeln!(
            w,
            "{} {} ({})",
            style.red("not found"),
            style.bold(symbol),
            change
        )?;
        let cands = body
            .get("candidates")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if !cands.is_empty() {
            writeln!(w, "{}", style.dim("did you mean:"))?;
            for c in &cands {
                let qn = c
                    .get("qualified_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                writeln!(w, "  {}", style.cyan(qn))?;
            }
        }
        return Ok(0);
    }

    let verdict = body.get("verdict").and_then(|v| v.as_str()).unwrap_or("?");
    let count = body
        .get("affected_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let headline = if verdict == "would_break" {
        style.red("WOULD BREAK")
    } else {
        style.green("SAFE")
    };
    let mut line = format!("{headline} {} ({change})", style.bold(symbol));
    if resolution == "indeterminate" {
        let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        line.push_str(&format!(
            " {}",
            style.dim(&format!("[indeterminate: {reason}]"))
        ));
    }
    writeln!(w, "{line}")?;
    let truncated = body
        .get("truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let count_note = if truncated {
        format!("{count}+ affected caller(s) (truncated — lower bound)")
    } else {
        format!("{count} affected caller(s)")
    };
    writeln!(w, "{}", style.dim(&count_note))?;

    let callers = body
        .get("affected_callers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut grouped: std::collections::BTreeMap<&str, Vec<&Value>> =
        std::collections::BTreeMap::new();
    for c in &callers {
        let file = c.get("file").and_then(|v| v.as_str()).unwrap_or("?");
        grouped.entry(file).or_default().push(c);
    }
    for (file, entries) in grouped {
        writeln!(w, "{}", style.magenta(file))?;
        for c in entries {
            let cline = c.get("line").and_then(|v| v.as_u64()).unwrap_or(0);
            let enclosing = c
                .get("enclosing")
                .and_then(|v| v.as_str())
                .unwrap_or("<file-scope>");
            let reason = c.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            writeln!(
                w,
                "  {}:{}  {} {}",
                style.dim("L"),
                style.green(&cline.to_string()),
                style.bold(enclosing),
                style.cyan(&format!("({reason})")),
            )?;
        }
    }
    Ok(callers.len())
}

/// Render an `Index.VerifyEdit` response: a one-line verdict headline
/// (`PASS` / `WARN` / `FAIL`) with the critical/warning/info summary, then
/// one line per finding in `SEVERITY  kind  symbol  site  — detail` shape,
/// sorted most-severe first. Returns the number of findings rendered.
///
/// The `site` is `file:enclosing` when both are present (the broken
/// caller's location). `files_skipped` (over-cap partial results) is noted
/// so a CI reader knows the analysis was incomplete.
pub fn render_edit_verdict<W: Write>(
    body: &Value,
    w: &mut W,
    style: &Style,
) -> std::io::Result<usize> {
    let verdict = body.get("verdict").and_then(|v| v.as_str()).unwrap_or("?");
    let summary = body.get("summary");
    let crit = summary
        .and_then(|s| s.get("critical"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let warn = summary
        .and_then(|s| s.get("warning"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let info = summary
        .and_then(|s| s.get("info"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let headline = match verdict {
        "pass" => style.green("PASS"),
        "warn" => style.yellow("WARN"),
        _ => style.red("FAIL"),
    };
    writeln!(
        w,
        "{headline} {}",
        style.dim(&format!("({crit} critical, {warn} warning, {info} info)"))
    )?;

    // Partial-result note: over-cap edits leave some files unanalyzed.
    let skipped = body
        .get("files_skipped")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    if skipped > 0 {
        writeln!(
            w,
            "{}",
            style.yellow(&format!(
                "  {skipped} file(s) skipped (over the analysis cap — partial result)"
            ))
        )?;
    }

    let findings = body
        .get("findings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Sort most-severe first (critical → warning → info), then by kind for
    // a stable order.
    let sev_rank = |s: &str| match s {
        "critical" => 0,
        "warning" => 1,
        "info" => 2,
        _ => 3,
    };
    let mut ordered: Vec<&Value> = findings.iter().collect();
    ordered.sort_by(|a, b| {
        let sa = a.get("severity").and_then(|v| v.as_str()).unwrap_or("");
        let sb = b.get("severity").and_then(|v| v.as_str()).unwrap_or("");
        sev_rank(sa).cmp(&sev_rank(sb)).then_with(|| {
            let ka = a.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let kb = b.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            ka.cmp(kb)
        })
    });

    for f in &ordered {
        let severity = f.get("severity").and_then(|v| v.as_str()).unwrap_or("?");
        let kind = f.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
        let symbol = f.get("symbol").and_then(|v| v.as_str()).unwrap_or("");
        let detail = f.get("detail").and_then(|v| v.as_str()).unwrap_or("");
        let site = f.get("site");
        let site_str = site
            .map(|s| {
                let file = s.get("file").and_then(|v| v.as_str()).unwrap_or("");
                let enclosing = s.get("enclosing").and_then(|v| v.as_str());
                match enclosing {
                    Some(e) if !e.is_empty() => format!("{file}:{e}"),
                    _ => file.to_string(),
                }
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_default();

        let sev_colored = match severity {
            "critical" => style.red("CRITICAL"),
            "warning" => style.yellow("WARNING"),
            "info" => style.dim("INFO"),
            other => other.to_string(),
        };
        let mut line = format!(
            "  {sev_colored}  {}  {}",
            style.cyan(kind),
            style.bold(symbol)
        );
        if !site_str.is_empty() {
            line.push_str(&format!("  {}", style.magenta(&site_str)));
        }
        if !detail.is_empty() {
            line.push_str(&format!("  {} {detail}", style.dim("—")));
        }
        writeln!(w, "{line}")?;
    }
    Ok(ordered.len())
}

/// Render the daemon's `outline_text` directly. The daemon already
/// produces a dotted-indent tree-style hierarchy (protocol-v0 §7.5);
/// we just pass it through (with a header) so the CLI shape stays
/// consistent with `rts-bench query --output lines outline`.
pub fn render_outline<W: Write>(body: &Value, w: &mut W, style: &Style) -> std::io::Result<usize> {
    let text = body
        .get("outline_text")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if text.is_empty() {
        return Ok(0);
    }
    let files = body
        .get("files_included")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    writeln!(w, "{}", style.dim(&format!("# {files} file(s) included")))?;
    w.write_all(text.as_bytes())?;
    if !text.ends_with('\n') {
        writeln!(w)?;
    }
    Ok(files as usize)
}

/// Render `Index.ReadSymbol` (or `Index.ReadSymbolAt`) source body
/// with a syntax-highlighted header. The header carries the
/// qualified name + file:line so a reader knows the provenance
/// before scanning the body.
pub fn render_read<W: Write>(body: &Value, w: &mut W, style: &Style) -> std::io::Result<usize> {
    let text = body
        .get("text")
        .or_else(|| body.get("body"))
        .or_else(|| body.get("signature"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if text.is_empty() {
        return Ok(0);
    }
    let qname = body
        .get("qualified_name")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let file = body.get("file").and_then(|v| v.as_str()).unwrap_or("?");
    let line = body
        .get("range")
        .and_then(|r| r.get("start_line"))
        .and_then(|n| n.as_u64())
        .unwrap_or(0);
    writeln!(
        w,
        "{} {} {}",
        style.bold(qname),
        style.dim("@"),
        style.green(&format!("{file}:{line}"))
    )?;
    writeln!(w, "{}", style.dim(&"─".repeat(60)))?;
    w.write_all(text.as_bytes())?;
    if !text.ends_with('\n') {
        writeln!(w)?;
    }
    Ok(1)
}

/// Render `Daemon.Stats` as a per-method table.
pub fn render_stats<W: Write>(body: &Value, w: &mut W, style: &Style) -> std::io::Result<usize> {
    let uptime_ms = body.get("uptime_ms").and_then(|v| v.as_u64()).unwrap_or(0);
    let total = body
        .get("total_calls")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let version = body.get("version").and_then(|v| v.as_str()).unwrap_or("?");
    writeln!(
        w,
        "{} {}",
        style.bold("daemon"),
        style.dim(&format!("v{version}"))
    )?;
    writeln!(w, "  uptime: {} ms", style.green(&uptime_ms.to_string()))?;
    writeln!(w, "  total:  {} calls", style.green(&total.to_string()))?;
    let calls = body
        .get("calls")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let mut pairs: Vec<(String, u64)> = calls
        .into_iter()
        .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
        .collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    writeln!(w, "{}", style.dim(&"─".repeat(40)))?;
    for (method, n) in &pairs {
        writeln!(
            w,
            "  {:<32}  {}",
            style.cyan(method),
            style.green(&n.to_string())
        )?;
    }
    // Always return non-zero so the "stats" command never exits with 1
    // (no-results) — stats with all-zero counters is still a successful
    // query, not an empty result set.
    Ok(pairs.len().max(1))
}

// ── verify (file-reference check) ─────────────────────────────────────

/// One hallucinated reference discovered by `rts verify`: a decidable
/// symbol/import reference whose `resolution == "not_found"`.
#[derive(Debug, Clone, PartialEq)]
pub struct Hallucination {
    /// The referenced name (final segment for qualified refs / imports).
    pub name: String,
    /// 1-based line of the reference in the verified file.
    pub line: usize,
    /// The top "did you mean" candidate's qualified name, if any.
    pub did_you_mean: Option<String>,
}

/// Route one reference to its verify method + params, mirroring the
/// routing in `rts-bench`'s `verify_metrics.rs`:
/// - `Import` → `Index.VerifyImport { path }`
/// - `Call` / `Type` / `Path` → `Index.VerifySymbol { name }`
///
/// Returns `(method, params, name)` where `name` is the human-facing
/// label for the reference. Kept a tight local helper (not shared with
/// the bench crate) on purpose.
pub fn verify_route(r: &rust_tree_sitter::Reference) -> (&'static str, Value, String) {
    use rust_tree_sitter::RefKind;
    match r.kind {
        RefKind::Import => {
            let path = r.qualified.as_deref().unwrap_or(&r.name).to_string();
            (
                "Index.VerifyImport",
                serde_json::json!({ "path": path }),
                r.name.clone(),
            )
        }
        RefKind::Call | RefKind::Type | RefKind::Path => (
            "Index.VerifySymbol",
            serde_json::json!({ "name": r.name }),
            r.name.clone(),
        ),
    }
}

/// Pull the top candidate's `qualified_name` from a verify response
/// body's `candidates[0]`, when present.
pub fn top_candidate(body: &Value) -> Option<String> {
    body.get("candidates")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("qualified_name"))
        .and_then(|q| q.as_str())
        .map(|s| s.to_string())
}

/// Render the collected hallucinations as `<file>:<line>  <name>
/// (did you mean: <top candidate>?)` lines. Returns the number of
/// lines written (== hallucination count). `rel` is the file label
/// (typically the path as the user passed it).
pub fn render_verify<W: Write>(
    rel: &str,
    halls: &[Hallucination],
    w: &mut W,
    style: &Style,
) -> std::io::Result<usize> {
    for h in halls {
        let loc = format!("{rel}:{}", h.line);
        match &h.did_you_mean {
            Some(cand) => writeln!(
                w,
                "{}  {}  {}",
                style.magenta(&loc),
                style.yellow(&h.name),
                style.dim(&format!("(did you mean: {cand}?)")),
            )?,
            None => writeln!(w, "{}  {}", style.magenta(&loc), style.yellow(&h.name),)?,
        }
    }
    Ok(halls.len())
}

/// Truncate a string to `max` characters, suffixing `…` when the
/// original was longer. Operates on chars, not bytes, so multi-byte
/// identifiers don't split mid-codepoint.
fn truncate(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn truncate_keeps_short_strings_intact() {
        assert_eq!(truncate("foo", 10), "foo");
        assert_eq!(truncate("abcdefghij", 10), "abcdefghij");
        assert_eq!(truncate("abcdefghijk", 10), "abcdefghi…");
    }

    #[test]
    fn style_disabled_emits_no_escapes() {
        // Crucial for `NO_COLOR=1` / `--no-color` correctness: every
        // helper must be a no-op identity transform when disabled.
        let s = Style::new(false);
        assert!(!s.red("err").contains('\x1b'));
        assert!(!s.green("ok").contains('\x1b'));
        assert!(!s.bold("title").contains('\x1b'));
        assert!(!s.dim("muted").contains('\x1b'));
        assert_eq!(s.red("err"), "err");
    }

    #[test]
    fn style_enabled_wraps_with_ansi() {
        let s = Style::new(true);
        assert!(s.red("err").contains('\x1b'));
        assert!(s.red("err").starts_with("\x1b["));
        assert!(s.red("err").ends_with("\x1b[0m"));
    }

    #[test]
    fn find_table_renders_no_results_as_zero() {
        let body = json!({ "matches": [] });
        let mut buf = Vec::new();
        let n = render_find_table(&body, &mut buf, &Style::new(false)).unwrap();
        assert_eq!(n, 0);
        assert!(buf.is_empty(), "no matches → no output");
    }

    #[test]
    fn find_table_renders_kind_name_path_line() {
        let body = json!({
            "matches": [{
                "kind": "fn",
                "qualified_name": "foo::bar",
                "file": "src/lib.rs",
                "range": { "start_line": 42 },
                "container": "foo",
            }]
        });
        let mut buf = Vec::new();
        let n = render_find_table(&body, &mut buf, &Style::new(false)).unwrap();
        assert_eq!(n, 1);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("fn"));
        assert!(s.contains("foo::bar"));
        assert!(s.contains("src/lib.rs:42"));
    }

    #[test]
    fn grep_lines_uses_rg_shape() {
        let body = json!({
            "matches": [{
                "file": "src/lib.rs",
                "range": { "start_line": 7 },
                "line_text": "    // TODO: simplify",
            }]
        });
        let mut buf = Vec::new();
        let n = render_grep_lines(&body, "TODO", &mut buf, &Style::new(false)).unwrap();
        assert_eq!(n, 1);
        let s = String::from_utf8(buf).unwrap();
        // Shape: path:line:col:content with col = byte offset (1-indexed)
        // of TODO inside "    // TODO: simplify" which is byte 8 → col 8.
        assert!(s.starts_with("src/lib.rs:7:8:"), "got {s:?}");
    }

    #[test]
    fn grep_lines_no_color_emits_no_escapes() {
        let body = json!({
            "matches": [{
                "file": "f.rs",
                "range": { "start_line": 1 },
                "line_text": "fn TODO_marker() {}",
            }]
        });
        let mut buf = Vec::new();
        let _ = render_grep_lines(&body, "TODO", &mut buf, &Style::new(false)).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            !s.contains('\x1b'),
            "no_color must suppress ANSI; got {s:?}"
        );
    }

    #[test]
    fn edit_verdict_renders_headline_and_findings_sorted() {
        let body = json!({
            "verdict": "fail",
            "summary": { "critical": 1, "warning": 0, "info": 1 },
            "findings": [
                { "severity": "info", "kind": "new_symbol", "symbol": "brand_new",
                  "site": { "file": "hub.rs" }, "detail": "added" },
                { "severity": "critical", "kind": "broken_caller", "symbol": "target",
                  "site": { "file": "caller_a.rs", "enclosing": "caller_a" },
                  "detail": "callee removed" },
            ],
        });
        let mut buf = Vec::new();
        let n = render_edit_verdict(&body, &mut buf, &Style::new(false)).unwrap();
        assert_eq!(n, 2);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("FAIL"), "headline missing: {s:?}");
        assert!(s.contains("1 critical"), "summary missing: {s:?}");
        // Critical sorts before info.
        let crit_idx = s.find("CRITICAL").expect("critical line");
        let info_idx = s.find("INFO").expect("info line");
        assert!(crit_idx < info_idx, "critical must sort first: {s:?}");
        // The broken caller names symbol + site.
        assert!(s.contains("broken_caller"), "{s:?}");
        assert!(s.contains("target"), "{s:?}");
        assert!(s.contains("caller_a.rs:caller_a"), "site: {s:?}");
        assert!(s.contains("callee removed"), "detail: {s:?}");
    }

    #[test]
    fn edit_verdict_pass_has_no_findings_and_green_headline() {
        let body = json!({
            "verdict": "pass",
            "summary": { "critical": 0, "warning": 0, "info": 0 },
            "findings": [],
        });
        let mut buf = Vec::new();
        let n = render_edit_verdict(&body, &mut buf, &Style::new(false)).unwrap();
        assert_eq!(n, 0);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("PASS"), "{s:?}");
        assert!(!s.contains('\x1b'), "no_color must suppress ANSI: {s:?}");
    }

    #[test]
    fn detect_workspace_finds_marker() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]\n").unwrap();
        let sub = tmp.path().join("crates/foo");
        std::fs::create_dir_all(&sub).unwrap();
        let found = detect_workspace_from(&sub).unwrap();
        // Resolve symlinks because tempfile on macOS lives under
        // /var → /private/var.
        assert_eq!(
            std::fs::canonicalize(&found).unwrap(),
            std::fs::canonicalize(tmp.path()).unwrap()
        );
    }

    #[test]
    fn detect_workspace_returns_none_outside_any_project() {
        // `/` has no marker (typically) → None. We use a tempdir as the
        // root and walk from a sub-path; without a marker, detection
        // walks up to / and returns None.
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("a/b/c");
        std::fs::create_dir_all(&sub).unwrap();
        // Don't write any marker — detection from `sub` should walk
        // up tmp (no marker), then up to its parent (also no marker
        // for this isolated tempdir tree). The walk may eventually
        // hit a real marker in `/` ancestors on dev machines, so
        // we only assert behavior on a controlled subtree: detection
        // from a directory below a non-marker tempdir does not return
        // the tempdir itself.
        let found = detect_workspace_from(&sub);
        if let Some(p) = &found {
            assert_ne!(p, tmp.path(), "tempdir without marker must not match");
        }
    }
}
