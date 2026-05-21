//! `rts` — human-facing CLI wrapper over the daemon's JSON-RPC surface.
//!
//! Each subcommand maps to one MCP tool / daemon method. The binary
//! Mounts the workspace (idempotent on the daemon), issues the RPC,
//! renders the response, and exits with one of the documented codes:
//!
//!   0 — success with results
//!   1 — success with zero results (matches `rg`'s convention)
//!   2 — clap-handled invalid argument (clap exits this itself)
//!   3 — daemon-level error (JSON-RPC error envelope)
//!   4 — request timeout
//!   5 — workspace resolution error (no marker found, path missing)
//!
//! See `docs/cli.md` for per-subcommand reference and
//! `docs/plans/2026-05-19-002-feat-human-cli-subcommand-plan.md` for
//! the design rationale.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use serde_json::{Value, json};

use rts_mcp::cli::{self, Style, exit};

#[derive(Parser, Debug)]
#[command(
    name = "rts",
    version,
    about = "Human-facing CLI for the rts code-retrieval daemon",
    long_about = "rts wraps the same JSON-RPC surface that the MCP server exposes to agents. \
                  Use it to query symbols, grep workspace bytes, find callers, outline a repo, \
                  read symbol source, or inspect daemon stats from the terminal."
)]
struct Cli {
    /// Workspace root (default: walk up from $PWD for a marker file).
    #[arg(long, global = true)]
    workspace: Option<PathBuf>,

    /// Emit JSON instead of human-formatted output. Composes with `jq`.
    #[arg(long, global = true)]
    json: bool,

    /// Disable ANSI colors. `NO_COLOR` env var has the same effect.
    #[arg(long, global = true)]
    no_color: bool,

    /// Request timeout in milliseconds. Default 30000.
    #[arg(long, global = true, default_value_t = 30_000)]
    timeout: u64,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Mount a workspace (default: $PWD). Daemon makes Mount idempotent,
    /// so calling this on an already-mounted workspace is cheap.
    Mount {
        /// Workspace path (overrides `--workspace`).
        path: Option<PathBuf>,
    },
    /// Find symbol by exact name.
    Find {
        /// Symbol name (exact match) or glob pattern when `--pattern`.
        name: String,
        /// Treat `NAME` as a glob (e.g. `make_*`, `*_target`).
        #[arg(long)]
        pattern: bool,
        /// Optional `kind` filter: fn, struct, enum, type, trait, …
        #[arg(long)]
        kind: Option<String>,
        /// Optional workspace-relative file filter.
        #[arg(long)]
        file: Option<String>,
        /// Maximum number of results. Default 256.
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Search workspace for a pattern (ripgrep-compatible output).
    Grep {
        /// Pattern to search for. Default: literal substring,
        /// case-insensitive. Pass `--regex` for the `regex` crate
        /// syntax, `--case-sensitive` for exact case.
        pattern: String,
        /// Treat PATTERN as a regex.
        #[arg(long)]
        regex: bool,
        /// Case-sensitive matching (default is case-insensitive).
        #[arg(long)]
        case_sensitive: bool,
        /// File-path glob to scope the search (e.g. `*.rs`).
        #[arg(long)]
        glob: Option<String>,
        /// Maximum number of matches.
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Show direct callers of a symbol.
    Callers {
        /// Exact symbol name.
        name: String,
        /// Optional `kind` filter (filters the enclosing def).
        #[arg(long)]
        kind: Option<String>,
        /// Optional workspace-relative file filter.
        #[arg(long)]
        file: Option<String>,
    },
    /// Print the workspace outline (token-budgeted tree).
    Outline {
        /// Optional glob to restrict the outline.
        #[arg(long)]
        glob: Option<String>,
        /// Token budget for the outline.
        #[arg(long)]
        token_budget: Option<u64>,
    },
    /// Read a symbol's source.
    Read {
        /// Symbol name.
        name: String,
        /// `signature` (declaration only) or `body` (default).
        #[arg(long)]
        shape: Option<String>,
        /// Optional file filter to disambiguate.
        #[arg(long)]
        file: Option<String>,
        /// Optional kind filter to disambiguate.
        #[arg(long)]
        kind: Option<String>,
    },
    /// Print daemon stats (per-method call counts).
    Stats,
    /// Run the rts-bench health-check (delegates to the rts-bench binary).
    Doctor {
        /// Forwarded to rts-bench doctor as `--output`.
        #[arg(long)]
        output: Option<String>,
    },
    /// Emit shell completions to stdout. Pipe into your shell's
    /// completion-loading mechanism (bash: `> /etc/bash_completion.d/rts`,
    /// zsh: `> "${fpath[1]}/_rts"`, fish: `> ~/.config/fish/completions/rts.fish`).
    Completions {
        /// Target shell. One of: bash, zsh, fish, powershell, elvish.
        shell: Shell,
    },
    /// Manage anonymous opt-in telemetry. See `docs/telemetry.md` for
    /// the full schema, retention policy, and privacy boundaries.
    /// Default is OFF; nothing is sent unless you explicitly enable.
    Telemetry {
        #[command(subcommand)]
        action: TelemetryCmd,
    },
}

#[derive(Subcommand, Debug)]
enum TelemetryCmd {
    /// Print whether telemetry is enabled, the schema version, the
    /// endpoint, and the local install-id (if any).
    Status,
    /// Print the exact JSON payload that would be sent on the next
    /// flush. Auditable: this is byte-equivalent to what `flush`
    /// uploads. Works regardless of opt-in state — it's a local
    /// dry-run, never a network call.
    Preview,
    /// Generate a local random install-id and enable telemetry. The
    /// daemon's ticker (or `rts telemetry flush`) will start sending
    /// once-per-day pings. Idempotent.
    Enable,
    /// Delete the install-id file and disable telemetry. After this,
    /// no pings are sent and no install-id remains on disk.
    Disable,
    /// Send the current payload immediately and update the
    /// `last_ping_unix_ms` timestamp on success. Errors if telemetry
    /// is disabled or if the binary was built without `--features
    /// telemetry`.
    Flush,
}

fn main() -> ExitCode {
    // tracing → stderr, opt-in via RTS_LOG. Quiet by default so the CLI
    // matches `rg`'s "no chatter on stderr unless something went wrong"
    // expectation.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RTS_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let cli = Cli::parse();
    let style = Style::auto(cli.no_color);

    // Top-level commands that don't talk to the daemon — handle before
    // we spin up a Tokio runtime.
    if let Cmd::Completions { shell } = &cli.cmd {
        emit_completions(*shell);
        return ExitCode::from(exit::OK as u8);
    }
    if let Cmd::Doctor { output } = &cli.cmd {
        return run_doctor(output.as_deref());
    }
    if let Cmd::Telemetry { action } = &cli.cmd {
        // Telemetry: status / preview / enable / disable do not need
        // a daemon connection. `flush` opens a short-lived daemon
        // connection (best-effort) for fresh stats but still
        // gracefully degrades to "all-zero counters" if the daemon
        // isn't reachable. Either way the command runs synchronously
        // without spinning up a workspace runtime.
        return run_telemetry(action, &style, cli.json, cli.workspace.as_deref());
    }

    // Resolve workspace before we open a runtime — workspace errors are
    // synchronous and don't need the daemon to land an exit code 5.
    let workspace = match cli::resolve_workspace(cli.workspace.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "{}: {}",
                style.red("rts workspace error"),
                e.to_string().trim_end()
            );
            return ExitCode::from(exit::WORKSPACE_ERROR as u8);
        }
    };

    // Daemon-talking commands run on a current-thread Tokio runtime
    // (the JSON-RPC stream is inherently sequential per connection).
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{}: {e}", style.red("rts internal error"));
            return ExitCode::from(exit::DAEMON_ERROR as u8);
        }
    };

    let timeout = std::time::Duration::from_millis(cli.timeout);
    let result = rt.block_on(async {
        match tokio::time::timeout(timeout, run_command(&cli, &workspace, &style)).await {
            Ok(r) => r,
            Err(_) => Err(CmdError::Timeout(timeout)),
        }
    });

    match result {
        Ok(exit_code) => ExitCode::from(exit_code as u8),
        Err(CmdError::Timeout(d)) => {
            eprintln!(
                "{}: request exceeded {}ms",
                style.red("rts timeout"),
                d.as_millis()
            );
            ExitCode::from(exit::TIMEOUT as u8)
        }
        Err(CmdError::Setup(e)) => {
            eprintln!("{}: {e:#}", style.red("rts setup error"));
            ExitCode::from(exit::DAEMON_ERROR as u8)
        }
    }
}

/// Internal command-dispatch error type. Daemon-side errors (from a
/// `DaemonError`) are handled in-line and converted to exit codes
/// directly — they don't reach this enum, which is reserved for
/// transport-layer failures (Setup) and the wall-clock timeout
/// (Timeout) wrapped around the whole RPC.
enum CmdError {
    Setup(anyhow::Error),
    Timeout(std::time::Duration),
}

impl From<anyhow::Error> for CmdError {
    fn from(e: anyhow::Error) -> Self {
        CmdError::Setup(e)
    }
}

async fn run_command(
    cli: &Cli,
    workspace: &std::path::Path,
    style: &Style,
) -> Result<i32, CmdError> {
    let client = cli::connect(workspace).await?;

    match &cli.cmd {
        Cmd::Mount { path } => {
            // The connect() + first-call lazy-Mount handle the mount
            // implicitly. A CLI user typing `rts mount` deserves
            // explicit confirmation, so we still issue an explicit
            // `Workspace.Mount` here (daemon makes it idempotent).
            let target = path
                .as_deref()
                .map(|p| {
                    std::fs::canonicalize(p)
                        .map_err(|e| anyhow::anyhow!("canonicalize {}: {e}", p.display()))
                })
                .transpose()?
                .unwrap_or_else(|| workspace.to_path_buf());
            match client
                .call("Workspace.Mount", json!({ "root": target }))
                .await
            {
                Ok(v) => {
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                    } else {
                        let id = v
                            .get("workspace_id")
                            .and_then(|s| s.as_str())
                            .unwrap_or("<unknown>");
                        println!(
                            "{} {} ({})",
                            style.green("mounted"),
                            style.bold(&target.display().to_string()),
                            style.dim(id),
                        );
                    }
                    Ok(exit::OK)
                }
                Err(e) => Ok(cli::render_connection_error(&e, style)),
            }
        }
        Cmd::Find {
            name,
            pattern,
            kind,
            file,
            limit,
        } => {
            let mut params = serde_json::Map::new();
            if *pattern {
                params.insert("pattern".into(), Value::String(name.clone()));
            } else {
                params.insert("name".into(), Value::String(name.clone()));
            }
            if let Some(k) = kind {
                params.insert("kind".into(), Value::String(k.clone()));
            }
            if let Some(f) = file {
                params.insert("file".into(), Value::String(f.clone()));
            }
            if let Some(n) = limit {
                params.insert("limit".into(), Value::Number((*n).into()));
            }
            let body = match cli::call_method(
                &client,
                workspace,
                "Index.FindSymbol",
                Value::Object(params),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return Ok(cli::render_connection_error(&e, style)),
            };
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&body).unwrap_or_default()
                );
                let n = body
                    .get("matches")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                return Ok(if n == 0 { exit::NO_RESULTS } else { exit::OK });
            }
            let mut stdout = std::io::stdout().lock();
            let n = cli::render_find_table(&body, &mut stdout, style).map_err(io_to_anyhow)?;
            stdout.flush().map_err(io_to_anyhow)?;
            Ok(if n == 0 { exit::NO_RESULTS } else { exit::OK })
        }
        Cmd::Grep {
            pattern,
            regex,
            case_sensitive,
            glob,
            limit,
        } => {
            let mut params = serde_json::Map::new();
            params.insert("text".into(), Value::String(pattern.clone()));
            if *regex {
                params.insert("regex".into(), Value::Bool(true));
            }
            if *case_sensitive {
                params.insert("case_insensitive".into(), Value::Bool(false));
            }
            if let Some(g) = glob {
                params.insert("file_glob".into(), Value::String(g.clone()));
            }
            if let Some(n) = limit {
                params.insert("limit".into(), Value::Number((*n).into()));
            }
            let body =
                match cli::call_method(&client, workspace, "Index.Grep", Value::Object(params))
                    .await
                {
                    Ok(v) => v,
                    Err(e) => return Ok(cli::render_connection_error(&e, style)),
                };
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&body).unwrap_or_default()
                );
                let n = body
                    .get("matches")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                return Ok(if n == 0 { exit::NO_RESULTS } else { exit::OK });
            }
            let mut stdout = std::io::stdout().lock();
            let n =
                cli::render_grep_lines(&body, pattern, &mut stdout, style).map_err(io_to_anyhow)?;
            stdout.flush().map_err(io_to_anyhow)?;
            Ok(if n == 0 { exit::NO_RESULTS } else { exit::OK })
        }
        Cmd::Callers { name, kind, file } => {
            let mut params = serde_json::Map::new();
            params.insert("name".into(), Value::String(name.clone()));
            if let Some(k) = kind {
                params.insert("kind".into(), Value::String(k.clone()));
            }
            if let Some(f) = file {
                params.insert("file".into(), Value::String(f.clone()));
            }
            let body = match cli::call_method(
                &client,
                workspace,
                "Index.FindCallers",
                Value::Object(params),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return Ok(cli::render_connection_error(&e, style)),
            };
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&body).unwrap_or_default()
                );
                let n = body
                    .get("callers")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                return Ok(if n == 0 { exit::NO_RESULTS } else { exit::OK });
            }
            let mut stdout = std::io::stdout().lock();
            let n = cli::render_callers_tree(&body, &mut stdout, style).map_err(io_to_anyhow)?;
            stdout.flush().map_err(io_to_anyhow)?;
            Ok(if n == 0 { exit::NO_RESULTS } else { exit::OK })
        }
        Cmd::Outline { glob, token_budget } => {
            let mut params = serde_json::Map::new();
            if let Some(g) = glob {
                params.insert("glob".into(), Value::String(g.clone()));
            }
            if let Some(b) = token_budget {
                params.insert("token_budget".into(), Value::Number((*b).into()));
            }
            let body =
                match cli::call_method(&client, workspace, "Index.Outline", Value::Object(params))
                    .await
                {
                    Ok(v) => v,
                    Err(e) => return Ok(cli::render_connection_error(&e, style)),
                };
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&body).unwrap_or_default()
                );
                return Ok(exit::OK);
            }
            let mut stdout = std::io::stdout().lock();
            let n = cli::render_outline(&body, &mut stdout, style).map_err(io_to_anyhow)?;
            stdout.flush().map_err(io_to_anyhow)?;
            Ok(if n == 0 { exit::NO_RESULTS } else { exit::OK })
        }
        Cmd::Read {
            name,
            shape,
            file,
            kind,
        } => {
            let mut params = serde_json::Map::new();
            params.insert("name".into(), Value::String(name.clone()));
            if let Some(s) = shape {
                params.insert("shape".into(), Value::String(s.clone()));
            }
            if let Some(f) = file {
                params.insert("file".into(), Value::String(f.clone()));
            }
            if let Some(k) = kind {
                params.insert("kind".into(), Value::String(k.clone()));
            }
            let body = match cli::call_method(
                &client,
                workspace,
                "Index.ReadSymbol",
                Value::Object(params),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return Ok(cli::render_connection_error(&e, style)),
            };
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&body).unwrap_or_default()
                );
                return Ok(exit::OK);
            }
            let mut stdout = std::io::stdout().lock();
            let n = cli::render_read(&body, &mut stdout, style).map_err(io_to_anyhow)?;
            stdout.flush().map_err(io_to_anyhow)?;
            Ok(if n == 0 { exit::NO_RESULTS } else { exit::OK })
        }
        Cmd::Stats => {
            let body = match cli::call_method(&client, workspace, "Daemon.Stats", json!({})).await {
                Ok(v) => v,
                Err(e) => return Ok(cli::render_connection_error(&e, style)),
            };
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&body).unwrap_or_default()
                );
                return Ok(exit::OK);
            }
            let mut stdout = std::io::stdout().lock();
            cli::render_stats(&body, &mut stdout, style).map_err(io_to_anyhow)?;
            stdout.flush().map_err(io_to_anyhow)?;
            Ok(exit::OK)
        }
        // Handled before reaching here.
        Cmd::Doctor { .. } | Cmd::Completions { .. } | Cmd::Telemetry { .. } => Ok(exit::OK),
    }
}

fn io_to_anyhow(e: std::io::Error) -> CmdError {
    CmdError::Setup(anyhow::anyhow!("stdout write: {e}"))
}

/// `rts telemetry {status,preview,enable,disable,flush}` dispatch.
///
/// All variants are synchronous and never spin up a workspace
/// runtime — telemetry is local-state-only by design. `flush` is
/// the one exception: it does open a network connection (when
/// compiled with `--features telemetry`), but that runs on the
/// `ureq` blocking client, not Tokio.
fn run_telemetry(
    action: &TelemetryCmd,
    style: &Style,
    json: bool,
    workspace_override: Option<&std::path::Path>,
) -> ExitCode {
    use rts_mcp::telemetry as tlm;

    // Resolve the user's actual config dir up front. Honors
    // $XDG_CONFIG_HOME and falls back to $HOME/.config/rts. If
    // neither is set we error visibly rather than silently writing
    // to a surprise location.
    let dir = match tlm::config_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{}: {e}", style.red("rts telemetry error"));
            return ExitCode::from(exit::DAEMON_ERROR as u8);
        }
    };

    match action {
        TelemetryCmd::Status => {
            let cfg = tlm::read_config_in(&dir).unwrap_or_default();
            let id = tlm::read_install_id_in(&dir).unwrap_or(None);
            if json {
                let body = serde_json::json!({
                    "enabled": cfg.enabled && id.is_some(),
                    "schema_version": tlm::SCHEMA_VERSION,
                    "endpoint": tlm::endpoint(),
                    "install_id": id,
                    "last_ping_unix_ms": cfg.last_ping_unix_ms,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&body).unwrap_or_default()
                );
            } else {
                println!("{}", tlm::render_status(&cfg, id.as_deref()));
            }
            ExitCode::from(exit::OK as u8)
        }
        TelemetryCmd::Preview => {
            // Use whatever install-id is on disk if any; otherwise a
            // synthetic placeholder so the preview is meaningful
            // pre-enable. The placeholder is clearly fake (all-zero
            // UUID) so an auditor can tell it's not a real id.
            let id = tlm::read_install_id_in(&dir)
                .unwrap_or(None)
                .unwrap_or_else(|| "00000000-0000-4000-8000-000000000000".into());
            let inputs = collect_payload_inputs_best_effort(workspace_override);
            let payload = tlm::build_payload(&id, &inputs);
            println!("{}", tlm::payload_to_pretty_json(&payload));
            ExitCode::from(exit::OK as u8)
        }
        TelemetryCmd::Enable => match tlm::enable_in(&dir) {
            Ok(id) => {
                if json {
                    let body = serde_json::json!({
                        "enabled": true,
                        "install_id": id,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&body).unwrap_or_default()
                    );
                } else {
                    println!(
                        "{} {}",
                        style.green("telemetry enabled"),
                        style.dim(&format!("install_id={id}"))
                    );
                    println!("  Run `rts telemetry preview` to see what gets sent.");
                    println!("  Run `rts telemetry disable` to opt out (deletes install-id).");
                }
                ExitCode::from(exit::OK as u8)
            }
            Err(e) => {
                eprintln!("{}: {e:#}", style.red("rts telemetry enable error"));
                ExitCode::from(exit::DAEMON_ERROR as u8)
            }
        },
        TelemetryCmd::Disable => match tlm::disable_in(&dir) {
            Ok(()) => {
                if json {
                    println!("{}", serde_json::json!({ "enabled": false }));
                } else {
                    println!(
                        "{} {}",
                        style.green("telemetry disabled"),
                        style.dim("(install-id deleted)")
                    );
                }
                ExitCode::from(exit::OK as u8)
            }
            Err(e) => {
                eprintln!("{}: {e:#}", style.red("rts telemetry disable error"));
                ExitCode::from(exit::DAEMON_ERROR as u8)
            }
        },
        TelemetryCmd::Flush => run_telemetry_flush(&dir, style, json, workspace_override),
    }
}

/// Collect inputs for the telemetry payload.
///
/// Best-effort: if a workspace marker is reachable and a daemon
/// socket exists for that workspace, we fire one `Daemon.Telemetry`
/// RPC (without auto-spawning a daemon — see
/// [`fetch_daemon_telemetry`]) to pull the live collector snapshot.
/// If anything in that chain fails (no workspace marker, no daemon
/// running, RPC errors, malformed response) we fall back to the
/// default zero-shaped inputs.
///
/// Why this matters: `rts telemetry preview` and `rts telemetry
/// flush` both call this, and an unsuspecting user running `preview`
/// before having mounted anything still sees a sensible "all zeros"
/// payload — never a startup error.
///
/// Privacy: the daemon RPC's response is already bounded-enum keyed
/// (`Daemon.Telemetry` constructs its map keys from closed enums in
/// the daemon binary). The receiver-side `build_payload` runs the
/// same allowlist filter a second time, so even a hypothetical
/// daemon-side enum-allowlist regression cannot leak through.
fn collect_payload_inputs_best_effort(
    workspace_override: Option<&std::path::Path>,
) -> rts_mcp::telemetry::PayloadInputs {
    let workspace = match rts_mcp::cli::resolve_workspace(workspace_override) {
        Ok(p) => p,
        Err(_) => return rts_mcp::telemetry::PayloadInputs::default(),
    };
    fetch_daemon_telemetry(&workspace).unwrap_or_default()
}

/// Try to fetch `Daemon.Telemetry` from a daemon running for
/// `workspace`. Returns `None` (not an error) on every failure
/// mode — the caller falls back to zero-shaped inputs and the user
/// sees a clean preview rather than a stack trace.
///
/// Auto-spawn is intentionally disabled: telemetry preview should
/// never spin up a daemon as a side effect. Users who want fresh
/// counters can `rts mount` first.
fn fetch_daemon_telemetry(
    workspace: &std::path::Path,
) -> Option<rts_mcp::telemetry::PayloadInputs> {
    use rts_mcp::socket;
    // Build a single-threaded runtime for the one-shot RPC.
    // Telemetry preview is a CLI command; latency matters more than
    // throughput.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    rt.block_on(async {
        let canon = workspace.canonicalize().ok()?;
        let sock_path = socket::workspace_socket_path(&canon).ok()?;
        let stream = socket::try_connect(&sock_path).await?;
        let daemon_bin = socket::resolve_daemon_bin().ok()?;
        let mut client =
            rts_mcp::daemon_client::DaemonClient::new(stream, daemon_bin, canon.clone());
        // Bound the call: telemetry preview must never hang the CLI
        // on a slow / hung daemon. 2s is generous — the RPC is
        // synthetic (no disk I/O beyond one redb read-only iter).
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.call("Daemon.Telemetry", serde_json::json!({})),
        )
        .await
        .ok()?
        .ok()?;
        parse_daemon_telemetry(&resp)
    })
}

/// Parse the `Daemon.Telemetry` response into a `PayloadInputs`.
/// Returns `None` if the response is missing required shape — the
/// caller falls back to defaults.
///
/// The privacy boundary is enforced TWICE: the daemon constructs
/// its response from closed-enum strings; the receiver's
/// `build_payload` filters again through `METHOD_NAMES` /
/// `ERROR_CODES` / `LANGUAGE_NAMES`. This function does not
/// itself filter — it's a raw shape adaptor.
fn parse_daemon_telemetry(resp: &serde_json::Value) -> Option<rts_mcp::telemetry::PayloadInputs> {
    let obj = resp.as_object()?;
    let uptime_secs = obj.get("uptime_secs").and_then(|v| v.as_u64()).unwrap_or(0);

    let languages_raw: Vec<String> = obj
        .get("languages_indexed")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let to_u64_map = |v: Option<&serde_json::Value>| -> std::collections::BTreeMap<String, u64> {
        let mut out = std::collections::BTreeMap::new();
        if let Some(obj) = v.and_then(|x| x.as_object()) {
            for (k, val) in obj {
                if let Some(n) = val.as_u64() {
                    out.insert(k.clone(), n);
                }
            }
        }
        out
    };
    let method_counts_raw = to_u64_map(obj.get("method_counts"));
    let method_latency_p50_raw = to_u64_map(obj.get("method_latency_p50_ms"));
    let method_latency_p99_raw = to_u64_map(obj.get("method_latency_p99_ms"));
    let error_counts_raw = to_u64_map(obj.get("error_counts"));

    let cache_hit_rate = obj
        .get("cache_hit_rate")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let cold_walk_ms_p50 = obj
        .get("cold_walk_ms_p50")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let workspace_files = obj
        .get("workspace_files")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    Some(rts_mcp::telemetry::PayloadInputs {
        uptime_secs,
        languages_raw,
        method_counts_raw,
        method_latency_p50_raw,
        method_latency_p99_raw,
        error_counts_raw,
        cache_hit_rate,
        cold_walk_ms_p50,
        workspace_files,
    })
}

#[cfg(feature = "telemetry")]
fn run_telemetry_flush(
    dir: &std::path::Path,
    style: &Style,
    json: bool,
    workspace_override: Option<&std::path::Path>,
) -> ExitCode {
    use rts_mcp::telemetry as tlm;
    // Hard opt-in gate. Read both files; if either is missing or the
    // flag is false, refuse to send.
    let cfg = match tlm::read_config_in(dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", style.red("rts telemetry flush error"));
            return ExitCode::from(exit::DAEMON_ERROR as u8);
        }
    };
    let install_id = match tlm::read_install_id_in(dir) {
        Ok(Some(id)) => id,
        Ok(None) => {
            eprintln!(
                "{}: telemetry is not enabled (no install-id on disk). \
                 Run `rts telemetry enable` first.",
                style.red("rts telemetry flush")
            );
            return ExitCode::from(exit::DAEMON_ERROR as u8);
        }
        Err(e) => {
            eprintln!("{}: {e}", style.red("rts telemetry flush error"));
            return ExitCode::from(exit::DAEMON_ERROR as u8);
        }
    };
    if !cfg.enabled {
        eprintln!(
            "{}: telemetry is disabled. Run `rts telemetry enable` first.",
            style.red("rts telemetry flush")
        );
        return ExitCode::from(exit::DAEMON_ERROR as u8);
    }

    let inputs = collect_payload_inputs_best_effort(workspace_override);
    let payload = tlm::build_payload(&install_id, &inputs);
    let body = tlm::payload_to_compact_json(&payload);

    let endpoint = tlm::endpoint();
    let ua = format!("{}{}", tlm::USER_AGENT_PREFIX, env!("CARGO_PKG_VERSION"));
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .user_agent(&ua)
        .build();
    let resp = agent
        .post(&endpoint)
        .set("Content-Type", "application/json")
        .send_string(&body);

    match resp {
        Ok(_) => {
            // Update last-ping timestamp on success.
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let mut cfg = cfg;
            cfg.last_ping_unix_ms = Some(now_ms);
            let _ = tlm::write_config_in(dir, &cfg);
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "sent": true, "endpoint": endpoint })
                );
            } else {
                println!(
                    "{} {}",
                    style.green("telemetry sent"),
                    style.dim(&format!("→ {endpoint}"))
                );
            }
            ExitCode::from(exit::OK as u8)
        }
        Err(e) => {
            // Silent at trace level on the *daemon* path; the CLI
            // surfaces the error because the user explicitly asked.
            eprintln!(
                "{}: POST to {endpoint} failed: {e}",
                style.red("rts telemetry flush")
            );
            ExitCode::from(exit::DAEMON_ERROR as u8)
        }
    }
}

#[cfg(not(feature = "telemetry"))]
fn run_telemetry_flush(
    _dir: &std::path::Path,
    style: &Style,
    _json: bool,
    _workspace_override: Option<&std::path::Path>,
) -> ExitCode {
    eprintln!(
        "{}: this binary was built without `--features telemetry`. \
         `flush` requires the HTTP client; rebuild with \
         `cargo build --features telemetry` (or use a packaged release).",
        style.red("rts telemetry flush")
    );
    ExitCode::from(exit::DAEMON_ERROR as u8)
}

/// Emit shell completions to stdout. clap_complete handles all five
/// supported shells; we just route the binary name.
fn emit_completions(shell: Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "rts", &mut std::io::stdout());
}

/// `rts doctor` → delegate to the `rts-bench` binary's `doctor`
/// subcommand. We don't re-implement doctor inside `rts` because it
/// already lives in rts-bench and the contract is a stable public API.
fn run_doctor(output: Option<&str>) -> ExitCode {
    // Resolve rts-bench: env override wins, otherwise sibling of the
    // current executable, otherwise $PATH.
    let bench_bin: PathBuf = std::env::var_os("RTS_BENCH_BIN")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("rts-bench")))
                .filter(|p| p.is_file())
        })
        .unwrap_or_else(|| PathBuf::from("rts-bench"));
    let mut cmd = std::process::Command::new(&bench_bin);
    cmd.arg("doctor");
    if let Some(fmt) = output {
        cmd.arg("--output").arg(fmt);
    }
    match cmd.status() {
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!("rts doctor: could not invoke {}: {e}", bench_bin.display());
            eprintln!(
                "  install rts (which ships rts-bench) via: brew install njfio/rts/rts\n  \
                 or set RTS_BENCH_BIN to the rts-bench binary path."
            );
            ExitCode::from(exit::DAEMON_ERROR as u8)
        }
    }
}
