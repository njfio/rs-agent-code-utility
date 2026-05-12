//! Path-level filtering for the watcher and the initial workspace walk.
//!
//! Implements `docs/protocol-v0.md` §6 (path safety / `.gitignore` honour) and
//! §13 (default secrets blocklist + code-extension allowlist).
//!
//! The filter is *deterministic and cheap*: it never opens the file. Content
//! scanning (high-entropy / known-token regexes — §13.2) happens at index time
//! in a later P6 phase, not here.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;

/// Decision returned for every path the watcher / initial walk produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    /// Index this file. Body reads (`Index.ReadSymbol`/`Index.ReadRange`) are
    /// allowed because the extension matches the §13.4 allowlist.
    IndexFull,
    /// Index this file's structure (symbols, ranges) but never return its
    /// body. Used for files whose extension isn't in the §13.4 allowlist —
    /// the file might be code-adjacent (e.g. CSV, log) but isn't safe to
    /// return verbatim to an agent.
    IndexSignatureOnly,
    /// Skip entirely. Reason carried for telemetry / debugging.
    Skip(SkipReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// `.gitignore` / `.rtsignore` / global ignore excludes this path.
    Gitignore,
    /// Filename matches the default secrets blocklist (§13.1).
    SecretsBlocklist,
    /// File extension is outside both the body-allowlist and the
    /// signature-allowlist. Includes binaries, archives, images.
    UnsupportedExtension,
    /// Editor swap / temp file (`*.swp`, `___jb_tmp___`, etc.). These come
    /// through the watcher in storms; filtering pre-debouncer is a hot-path
    /// concern.
    EditorSwap,
    /// File is symlinked outside the workspace root. Reserved for the
    /// content-scanner path that would enforce §6.2's per-read prefix check
    /// at index time — the watcher currently doesn't stat to detect this,
    /// since the prefix check happens in the file-reader path later.
    #[allow(dead_code)]
    Symlink,
}

/// Default secrets blocklist regex per protocol-v0 §13.1.
///
/// Matches against the path's UTF-8 string representation. The regex is
/// compiled once via `OnceLock`; allocation is on first call.
fn secrets_blocklist_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // (?x): allow whitespace + comments. (?i): case-insensitive for filename
        // segments — e.g. `.AWS/credentials` should match too.
        Regex::new(
            r"(?ix)
              (^|/)\.env(\..*)?$                                # .env, .env.production
            | (^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$          # SSH keys
            | \.(pem|p12|pfx|key|kdbx|jks|crt|cer)$             # Certs / keystores
            | .*credentials.*\.json$                            # gcloud/aws-style
            | (^|/)\.aws/(credentials|config)$
            | (^|/)\.npmrc$
            | (^|/)\.pypirc$
            | (^|/)\.htpasswd$
            ",
        )
        .expect("secrets blocklist regex compiles")
    })
}

/// Editor swap / temp / lock file regex. Matches the *whole path* — anchored
/// names live there because some patterns (vim's `4913`) are bare basenames.
fn editor_swap_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?x)
              # Vim
              (^|/)\.[^/]+\.sw[a-p]$
            | (^|/)4913$
            | ~$                                        # vim/emacs backup
              # Emacs
            | (^|/)\.\#[^/]+$                            # lock symlink
            | (^|/)\#[^/]+\#$                            # autosave
              # JetBrains (RustRover/IntelliJ/etc.)
            | ___jb_(tmp|old|bak)___$
            | (^|/)\.idea/.*\.(tmp|xml\.tmp)$
              # VS Code
            | (^|/)\.vscode/.*\.tmp$
            | \.code-workspace\.tmp$
              # Generic
            | \.tmp(\.\d+)?$
            | \.swp$
            | \.part$
            | \.crdownload$
            ",
        )
        .expect("editor swap regex compiles")
    })
}

/// Per protocol-v0 §13.4: extensions whose body content may be returned to an
/// agent. Other indexed files get `IndexSignatureOnly`.
pub const BODY_ALLOWED_EXTENSIONS: &[&str] = &[
    // Code
    "rs", "py", "ts", "tsx", "js", "jsx", "go", "java", "c", "h", "cpp", "hpp", "cc", "cs", "php",
    "rb", "swift", "kt", // Code-adjacent (config, prose)
    "md", "toml", "yaml", "yml", "json", "xml",
];

/// Extensions we *index* (structure / symbols) but never return body for.
/// Empty for v0 — anything outside the body-allowlist is skipped entirely. A
/// later phase may add signature-only indexing for HTML, CSS, etc.
const SIGNATURE_ONLY_EXTENSIONS: &[&str] = &[];

/// Compose all filters into one decision. The cost order matters under burst:
/// 1. editor-swap regex (cheapest, most common skip)
/// 2. extension allowlist (cheap; eliminates binaries fast)
/// 3. secrets blocklist regex (cheap; rarely matches)
/// 4. gitignore matcher (callers provide the prebuilt matcher; we don't
///    rebuild per-call).
pub fn classify(path: &Path, gitignore: &PrebuiltGitignore) -> FilterDecision {
    // We do *not* call `symlink_metadata` here — the watcher can race with
    // deletes and a stat-on-every-event is too expensive under burst. Callers
    // can short-circuit symlinked-target paths separately.

    let display = path.to_string_lossy();
    let display_ref: &str = &display;

    if editor_swap_regex().is_match(display_ref) {
        return FilterDecision::Skip(SkipReason::EditorSwap);
    }

    if secrets_blocklist_regex().is_match(display_ref) {
        return FilterDecision::Skip(SkipReason::SecretsBlocklist);
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    let in_body = matches!(ext.as_deref(), Some(e) if BODY_ALLOWED_EXTENSIONS.contains(&e));
    let in_sig = matches!(ext.as_deref(), Some(e) if SIGNATURE_ONLY_EXTENSIONS.contains(&e));

    if !in_body && !in_sig {
        return FilterDecision::Skip(SkipReason::UnsupportedExtension);
    }

    // gitignore check last: it's the only filter that allocates a Vec for
    // path-component traversal.
    if gitignore.is_ignored(path) {
        return FilterDecision::Skip(SkipReason::Gitignore);
    }

    if in_body {
        FilterDecision::IndexFull
    } else {
        FilterDecision::IndexSignatureOnly
    }
}

/// A prebuilt gitignore matcher anchored at a specific workspace root. Cheap
/// to construct (one walk of `.gitignore` + `.rtsignore` + global gitignore)
/// and reusable across millions of `classify` calls.
pub struct PrebuiltGitignore {
    /// Workspace root the matcher is anchored at.
    pub root: PathBuf,
    matcher: ignore::gitignore::Gitignore,
}

impl PrebuiltGitignore {
    /// Build the matcher for `workspace_root`. Always honours the workspace's
    /// `.gitignore`, the global gitignore (`$XDG_CONFIG_HOME/git/ignore`), and
    /// a project-local `.rtsignore` (additive — cannot un-ignore).
    pub fn build(workspace_root: &Path) -> std::io::Result<Self> {
        let mut builder = ignore::gitignore::GitignoreBuilder::new(workspace_root);

        // Local `.gitignore` is honoured by `ignore::WalkBuilder` automatically,
        // but `GitignoreBuilder` needs it added explicitly when we use it as a
        // standalone matcher (which is the case for watcher events that don't
        // come from the walker).
        let local = workspace_root.join(".gitignore");
        if local.exists() {
            if let Some(err) = builder.add(&local) {
                return Err(std::io::Error::other(format!("parse .gitignore: {err}")));
            }
        }
        let rts = workspace_root.join(".rtsignore");
        if rts.exists() {
            if let Some(err) = builder.add(&rts) {
                return Err(std::io::Error::other(format!("parse .rtsignore: {err}")));
            }
        }

        // Hardcoded fallbacks: directories every project usually wants
        // ignored, even if the user forgot to put them in `.gitignore`.
        // These are *additive* — a project can override by un-ignoring in
        // their own `.gitignore` (since the file we add explicitly above is
        // processed in declaration order).
        for pat in [
            "target/",
            "node_modules/",
            ".git/",
            ".hg/",
            ".svn/",
            "build/",
            "dist/",
            ".next/",
            ".cache/",
        ] {
            let _ = builder.add_line(None, pat);
        }

        let matcher = builder
            .build()
            .map_err(|e| std::io::Error::other(format!("build gitignore matcher: {e}")))?;

        Ok(Self {
            root: workspace_root.to_path_buf(),
            matcher,
        })
    }

    /// Returns true if `path` is ignored by any of the bound rules.
    ///
    /// If `path` isn't under the matcher's `root`, returns `false` rather
    /// than panicking. (`ignore::gitignore::Gitignore::matched_path_or_any_parents`
    /// panics on out-of-root paths; that combines badly with macOS's
    /// `/var → /private/var` structural symlink, where notify can report
    /// events under either prefix depending on the event source.)
    pub fn is_ignored(&self, path: &Path) -> bool {
        if !path.starts_with(&self.root) {
            return false;
        }
        let is_dir = path.is_dir();
        self.matcher
            .matched_path_or_any_parents(path, is_dir)
            .is_ignore()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_gitignore() -> PrebuiltGitignore {
        let tmp = tempfile::tempdir().unwrap();
        let pgi = PrebuiltGitignore::build(tmp.path()).unwrap();
        // Leak the tempdir so the matcher's root path stays valid for the test.
        // We never write to the dir; nothing leaks beyond the test process.
        std::mem::forget(tmp);
        pgi
    }

    #[test]
    fn body_allowed_extensions_return_index_full() {
        let g = empty_gitignore();
        let p = g.root.join("src").join("main.rs");
        assert_eq!(classify(&p, &g), FilterDecision::IndexFull);
    }

    #[test]
    fn unsupported_extensions_skip() {
        let g = empty_gitignore();
        let p = g.root.join("app").join("logo.png");
        assert_eq!(
            classify(&p, &g),
            FilterDecision::Skip(SkipReason::UnsupportedExtension)
        );
    }

    #[test]
    fn no_extension_skip() {
        let g = empty_gitignore();
        let p = g.root.join("Makefile");
        assert_eq!(
            classify(&p, &g),
            FilterDecision::Skip(SkipReason::UnsupportedExtension)
        );
    }

    #[test]
    fn secrets_blocklist_filenames() {
        let g = empty_gitignore();
        for bad in [
            ".env",
            ".env.production",
            "id_rsa",
            "id_ed25519.pub",
            "secret.pem",
            "creds.p12",
            "aws-credentials.json",
            ".aws/credentials",
            ".npmrc",
            ".htpasswd",
        ] {
            let p = g.root.join(bad);
            assert_eq!(
                classify(&p, &g),
                FilterDecision::Skip(SkipReason::SecretsBlocklist),
                "{bad} should be in the secrets blocklist"
            );
        }
    }

    #[test]
    fn editor_swap_filenames() {
        let g = empty_gitignore();
        for ugly in [
            ".main.rs.swp",
            "4913",
            "main.rs~",
            ".#main.rs",
            "#main.rs#",
            "main.rs___jb_tmp___",
            ".vscode/scratch.tmp",
            "main.rs.tmp",
            "main.rs.tmp.42",
            "main.rs.swp",
            "download.crdownload",
        ] {
            let p = g.root.join(ugly);
            assert_eq!(
                classify(&p, &g),
                FilterDecision::Skip(SkipReason::EditorSwap),
                "{ugly} should match the editor-swap filter"
            );
        }
    }

    #[test]
    fn gitignore_excludes_target_dir() {
        // PrebuiltGitignore adds `target/` as a fallback pattern. We use a
        // file with a code extension so the test exercises the gitignore
        // check rather than short-circuiting on UnsupportedExtension.
        let g = empty_gitignore();
        let p = g.root.join("target").join("debug").join("foo.rs");
        assert_eq!(
            classify(&p, &g),
            FilterDecision::Skip(SkipReason::Gitignore)
        );
    }

    #[test]
    fn gitignore_excludes_node_modules() {
        let g = empty_gitignore();
        let p = g.root.join("node_modules").join("react").join("index.js");
        assert_eq!(
            classify(&p, &g),
            FilterDecision::Skip(SkipReason::Gitignore)
        );
    }

    #[test]
    fn rtsignore_file_is_honoured() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".rtsignore"), "*.private.rs\n").unwrap();
        let g = PrebuiltGitignore::build(tmp.path()).unwrap();
        let p = tmp.path().join("secret.private.rs");
        assert_eq!(
            classify(&p, &g),
            FilterDecision::Skip(SkipReason::Gitignore),
            ".rtsignore should add to the ignore set"
        );
    }
}
