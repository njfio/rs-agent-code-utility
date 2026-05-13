//! Workspace-relative path validation. The single defense-in-depth
//! gate that every file-read in the daemon should pass through.
//!
//! Prior to alpha.29 this lived as `methods::index::resolve_workspace_path`,
//! a private fn. The alpha.27 security audit (M1) flagged that
//! `closure.rs` reads dep file contents directly via
//! `workspace_root.join(&def.file)` without going through this gate.
//! Currently safe (the writer stores workspace-relative paths and the
//! mount-time canonicalization refuses symlinked roots), but the audit
//! correctly noted that defense-in-depth wants every file read on the
//! same code path.
//!
//! ### Alpha.29 hardening
//!
//! Beyond the lexical checks (no `..`, must stay under root) this slice
//! adds **symlink rejection** (M2): after resolving the path, we
//! `symlink_metadata` it and reject if the resolved entry is a symlink.
//! The walker already runs with `follow_links(false)` so the indexer
//! never sees symlinked content; agents driving the read handlers can
//! still try to ask for an indexed-or-not symlinked path, and per the
//! trust model (`docs/protocol-v0.md` §1: "agents are not trusted") we
//! refuse.
//!
//! ### What "symlink" means here
//!
//! `symlink_metadata` returns the metadata of the link itself, not its
//! target. So `file_type().is_symlink() == true` means "the last
//! component of the path is a symlink". We don't validate every
//! intermediate component — that would be expensive and the walker's
//! `follow_links(false)` already prevents symlinked directories from
//! being indexed in the first place. The leaf-symlink check is the
//! narrow, cheap gate that covers the documented attack: agent supplies
//! a file path inside the workspace that's actually a symlink to
//! e.g. `/etc/passwd`.

use std::path::{Component, Path, PathBuf};

use crate::error::{ErrorCode, ProtocolError};

/// Resolve a workspace-relative `file` argument to an absolute path
/// inside `root`. Enforces protocol-v0 §6.2 (per-read prefix check) +
/// §6.3 (no `..`) + alpha.29 leaf-symlink rejection.
///
/// Absolute paths are accepted only if they already start with `root`
/// (the MCP server may forward absolute paths from agent-side editors);
/// anything else surfaces as `OUT_OF_ROOT`.
///
/// Returns `(absolute_path, workspace_relative_string)`. The relative
/// string is what the daemon's index keys by (`Store::find_symbol`
/// returns `FoundSymbol.file` as workspace-relative).
///
/// Errors are typed per the wire protocol:
/// - `InvalidParams` — empty path
/// - `PathTraversal` — any `..` component
/// - `OutOfRoot` — absolute path outside workspace, OR resolved path
///   is a symlink (per alpha.29 M2)
pub(crate) fn resolve_workspace_path(
    root: &Path,
    raw: &str,
) -> Result<(PathBuf, String), ProtocolError> {
    if raw.is_empty() {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`file` must be non-empty",
        ));
    }
    let p = Path::new(raw);
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(ProtocolError::new(
            ErrorCode::PathTraversal,
            "`..` segment in path",
        ));
    }
    let abs = if p.is_absolute() {
        if !p.starts_with(root) {
            return Err(ProtocolError::new(
                ErrorCode::OutOfRoot,
                "absolute path is outside workspace root",
            ));
        }
        p.to_path_buf()
    } else {
        root.join(p)
    };
    let rel = match abs.strip_prefix(root) {
        Ok(r) => r.to_string_lossy().into_owned(),
        Err(_) => {
            return Err(ProtocolError::new(
                ErrorCode::OutOfRoot,
                "resolved path is outside workspace root",
            ));
        }
    };
    // alpha.29 M2: refuse leaf symlinks. The walker uses
    // `follow_links(false)` so symlinked files aren't in the index;
    // this catches an agent driving a read at a workspace-internal
    // symlink anyway. `symlink_metadata` is one stat syscall; the
    // read that follows is much more expensive.
    //
    // We skip the check when the leaf doesn't exist — read handlers
    // already surface `FileNotIndexed` / `IoMissing` for those, and
    // calling `symlink_metadata` on a non-existent path returns an
    // io::Error we'd have to absorb anyway.
    if let Ok(meta) = std::fs::symlink_metadata(&abs) {
        if meta.file_type().is_symlink() {
            return Err(ProtocolError::new(
                ErrorCode::OutOfRoot,
                "path resolves to a symlink; refused per protocol-v0 §6.2",
            ));
        }
    }
    Ok((abs, rel))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn rejects_empty() {
        let err = resolve_workspace_path(Path::new("/tmp/ws"), "").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidParams);
    }

    #[test]
    fn rejects_parent_dir() {
        let err = resolve_workspace_path(Path::new("/tmp/ws"), "../etc/passwd").unwrap_err();
        assert_eq!(err.code, ErrorCode::PathTraversal);
    }

    #[test]
    fn rejects_outside_absolute() {
        let err = resolve_workspace_path(Path::new("/tmp/ws"), "/etc/passwd").unwrap_err();
        assert_eq!(err.code, ErrorCode::OutOfRoot);
    }

    #[test]
    fn joins_relative_when_leaf_does_not_exist() {
        // No symlink_metadata call on a non-existent path; happy path.
        let (abs, rel) = resolve_workspace_path(Path::new("/tmp/ws"), "src/lib.rs").unwrap();
        assert_eq!(abs, Path::new("/tmp/ws/src/lib.rs"));
        assert_eq!(rel, "src/lib.rs");
    }

    #[test]
    fn rejects_leaf_symlink_inside_workspace() {
        // Create a real symlink inside a tempdir and verify it's
        // refused. This is the M2 attack the alpha.27 security audit
        // flagged: an agent driving a read at a workspace-internal
        // symlink to /etc/passwd (or any allowed-extension file
        // outside the workspace).
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("real.rs");
        std::fs::write(&target, "fn x() {}").unwrap();
        let link = tmp.path().join("link.rs");
        symlink(&target, &link).unwrap();
        let err = resolve_workspace_path(tmp.path(), "link.rs").unwrap_err();
        assert_eq!(err.code, ErrorCode::OutOfRoot);
        assert!(
            err.message.contains("symlink"),
            "error message should explain the rejection; got {:?}",
            err.message
        );
    }

    #[test]
    fn accepts_regular_file_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("real.rs"), "fn x() {}").unwrap();
        let (abs, rel) = resolve_workspace_path(tmp.path(), "real.rs").unwrap();
        assert_eq!(abs, tmp.path().join("real.rs"));
        assert_eq!(rel, "real.rs");
    }
}
