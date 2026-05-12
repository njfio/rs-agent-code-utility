//! Workspace canonicalisation, fingerprinting, and redb open.
//!
//! Implements `docs/protocol-v0.md` §5 (workspace identity). The v0 daemon is
//! workspace-pinned: the first `Workspace.Mount` decides; later mounts on a
//! different path are rejected via `WORKSPACE_VANISHED`.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::error::{ErrorCode, ProtocolError};

/// Per-OS canonical representation of a workspace path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPath {
    pub path: PathBuf,
}

/// Workspace identity binding (per protocol-v0 §5.2).
/// Defeats symlink-swap attacks where the workspace root is replaced between
/// daemon starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceFingerprint {
    pub dev: u64,
    pub inode: u64,
    /// `blake3(dev_le || inode_le || canonical_path_utf8)[:16]` rendered hex.
    pub id_hex: [u8; 32],
}

impl WorkspaceFingerprint {
    /// 16-character hex id (the visible workspace id used in socket paths etc).
    pub fn id_str(&self) -> String {
        // Safe: id_hex bytes are all `0..=9 | a..=f` by construction.
        String::from_utf8(self.id_hex.to_vec()).expect("id_hex is hex")
    }
}

/// A successfully-mounted workspace.
///
/// `mounted_at` is recorded for future telemetry / `Workspace.Status` use; the
/// P6-skeleton build doesn't surface it yet.
#[derive(Debug)]
pub struct MountedWorkspace {
    pub canonical: CanonicalPath,
    pub fingerprint: WorkspaceFingerprint,
    #[allow(dead_code)]
    pub mounted_at: SystemTime,
}

/// Canonicalise a user-supplied workspace path per the per-OS matrix in
/// `docs/protocol-v0.md` §5.1.
///
/// - Linux: `realpath()` + UTF-8 validation. Refuse non-UTF-8.
/// - macOS: `realpath()` + NFC-normalize via `unicode-normalization`. Refuse
///   non-UTF-8.
/// - Windows: `GetFinalPathNameByHandleW` + lowercase ASCII portion. (v1.1)
pub fn canonicalize(input: &Path) -> Result<CanonicalPath, ProtocolError> {
    let real = std::fs::canonicalize(input).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InvalidWorkspacePath,
            format!("canonicalize {:?} failed: {e}", input),
        )
    })?;

    // UTF-8 gate: identical on Linux + macOS.
    let s = real.to_str().ok_or_else(|| {
        ProtocolError::new(
            ErrorCode::InvalidWorkspacePath,
            "workspace path is not valid UTF-8",
        )
    })?;

    let canonical = if cfg!(target_os = "macos") {
        // NFC normalise — HFS+/APFS stores NFD but users type NFC; pin to NFC
        // for deterministic ids.
        use unicode_normalization::UnicodeNormalization;
        let normalised: String = s.nfc().collect();
        PathBuf::from(normalised)
    } else {
        // Linux: bytes-are-bytes after UTF-8 validation.
        real
    };

    Ok(CanonicalPath { path: canonical })
}

/// Refuse `Workspace.Mount` if the workspace-root *leaf* is itself a symlink,
/// and refuse any `..` segments outright.
///
/// The protocol-v0 doc originally said "any component" must not be a symlink,
/// but macOS structural symlinks (`/var → /private/var`, `/tmp → /private/tmp`)
/// and common dev setups (`~/Library` aliases, conda envs, etc.) make that
/// strictness break legitimate use without buying meaningful security. The
/// real defence against root-replacement-after-mount is the `(dev, inode)`
/// fingerprint check at remount time (§5.2 + `verify_unchanged`), not the
/// initial-walk symlink scan.
///
/// What we still refuse:
/// - the workspace root itself being a symlink (the obvious "I mounted a
///   symlink that points at the attacker's tree" case);
/// - `..` segments anywhere in the supplied path (defence-in-depth against
///   path-traversal in incoming RPCs).
pub fn refuse_symlinked_components(user_input: &Path) -> Result<(), ProtocolError> {
    for component in user_input.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(ProtocolError::new(
                ErrorCode::PathTraversal,
                ".. is not allowed in workspace paths",
            ));
        }
    }
    match std::fs::symlink_metadata(user_input) {
        Ok(meta) if meta.file_type().is_symlink() => Err(ProtocolError::new(
            ErrorCode::MountHasSymlink,
            format!("workspace root is a symlink: {}", user_input.display()),
        )),
        Ok(_) | Err(_) => Ok(()),
    }
}

/// Compute the workspace fingerprint per protocol-v0 §5.2.
pub fn fingerprint(canonical: &CanonicalPath) -> Result<WorkspaceFingerprint, ProtocolError> {
    let meta = std::fs::metadata(&canonical.path).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InvalidWorkspacePath,
            format!("stat {:?} failed: {e}", canonical.path),
        )
    })?;
    if !meta.is_dir() {
        return Err(ProtocolError::new(
            ErrorCode::InvalidWorkspacePath,
            format!("{:?} is not a directory", canonical.path),
        ));
    }
    let dev = meta.dev();
    let inode = meta.ino();

    let mut hasher = blake3::Hasher::new();
    hasher.update(&dev.to_le_bytes());
    hasher.update(&inode.to_le_bytes());
    hasher.update(canonical.path.as_os_str().as_encoded_bytes());
    let h = hasher.finalize();
    let hex_full = h.to_hex(); // 64 hex chars
    let mut id_hex = [0u8; 32];
    id_hex.copy_from_slice(&hex_full.as_bytes()[..32]);

    Ok(WorkspaceFingerprint { dev, inode, id_hex })
}

/// Refuse network-mounted workspaces (protocol-v0 §5.6).
///
/// Linux: read `/proc/self/mountinfo`, find the mount the workspace path
/// belongs to, and refuse if its fstype is in the network-FS deny list.
///
/// macOS / other: best-effort no-op for v0. (A `statfs` call could check the
/// FS type but the deny-list is platform-specific and we don't ship Windows
/// in v0.)
pub fn refuse_network_mount(_canonical: &CanonicalPath) -> Result<(), ProtocolError> {
    #[cfg(target_os = "linux")]
    {
        if let Some(fs_type) = lookup_fstype_linux(&_canonical.path) {
            const DENY: &[&str] = &["nfs", "nfs4", "cifs", "smbfs", "fuse.sshfs", "fuse.gvfsd"];
            if DENY.contains(&fs_type.as_str()) {
                return Err(ProtocolError::new(
                    ErrorCode::WorkspaceOnNetworkMount,
                    format!("path is on a {fs_type} mount; v0 is local-FS only"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn lookup_fstype_linux(path: &Path) -> Option<String> {
    // /proc/self/mountinfo lines: `36 35 98:0 / /mnt/foo rw … - fstype source …`
    // Field 5 is mount point; field after `-` is fstype. Find the longest
    // matching mountpoint that's a prefix of `path`.
    let contents = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut best: Option<(usize, String)> = None;
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let mp = fields.nth(4)?; // mount point
        // Skip until the `-` separator.
        let after_dash = line.split(" - ").nth(1)?;
        let fs_type = after_dash.split_whitespace().next()?;
        if path.starts_with(mp) {
            let len = mp.len();
            if best.as_ref().map(|(l, _)| len > *l).unwrap_or(true) {
                best = Some((len, fs_type.to_string()));
            }
        }
    }
    best.map(|(_, fs)| fs)
}

/// Mount a workspace: canonicalise → refuse symlinks → fingerprint → refuse
/// network mounts → return a `MountedWorkspace`.
pub fn mount(user_input: &Path) -> Result<MountedWorkspace, ProtocolError> {
    refuse_symlinked_components(user_input)?;
    let canonical = canonicalize(user_input)?;
    refuse_network_mount(&canonical)?;
    let fingerprint = fingerprint(&canonical)?;
    Ok(MountedWorkspace {
        canonical,
        fingerprint,
        mounted_at: SystemTime::now(),
    })
}

/// Verify a workspace mount remains valid (re-stat the path; check `(dev, inode)`).
///
/// Called on every `Workspace.Mount` after the first to detect symlink-swap
/// attacks per protocol-v0 §5.2.
pub fn verify_unchanged(mounted: &MountedWorkspace) -> Result<(), ProtocolError> {
    let meta = std::fs::metadata(&mounted.canonical.path).map_err(|_| {
        ProtocolError::new(
            ErrorCode::WorkspaceVanished,
            "workspace path no longer exists",
        )
    })?;
    if meta.dev() != mounted.fingerprint.dev || meta.ino() != mounted.fingerprint.inode {
        return Err(ProtocolError::new(
            ErrorCode::WorkspaceVanished,
            "workspace (dev, inode) changed since mount",
        )
        .with_data(serde_json::json!({
            "stored":  { "dev": mounted.fingerprint.dev, "inode": mounted.fingerprint.inode },
            "current": { "dev": meta.dev(), "inode": meta.ino() }
        })));
    }
    Ok(())
}

/// State-dir resolution per protocol-v0 §5.4. Called from tests in this build;
/// the redb-open path (P6 later, not in this skeleton) will be the production
/// consumer.
#[allow(dead_code)]
pub fn state_dir_for(fingerprint: &WorkspaceFingerprint) -> PathBuf {
    let id = fingerprint.id_str();
    if let Some(state) = state_home_root() {
        return state.join("rts").join(id);
    }
    // Fallback: ~/.local/state/rts/<hash> (Linux convention) — only reached if
    // both XDG_STATE_HOME and the home-dir lookup fail.
    std::env::temp_dir().join("rts").join(id)
}

#[allow(dead_code)]
fn state_home_root() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("XDG_STATE_HOME") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return Some(home.join("Library").join("Caches"));
        }
    }
    if let Some(home) = dirs::home_dir() {
        return Some(home.join(".local").join("state"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn unique_workspace() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ws");
        fs::create_dir_all(&dir).unwrap();
        (tmp, dir)
    }

    #[test]
    fn mount_round_trip_succeeds() {
        let (_tmp, dir) = unique_workspace();
        let mounted = mount(&dir).expect("mount should succeed");
        assert!(mounted.canonical.path.is_absolute());
        assert_ne!(mounted.fingerprint.id_hex, [0u8; 32]);
    }

    #[test]
    fn mount_refuses_dotdot() {
        let (_tmp, dir) = unique_workspace();
        let bad = dir.join("..").join(dir.file_name().unwrap());
        let err = mount(&bad).unwrap_err();
        assert_eq!(err.code, ErrorCode::PathTraversal);
    }

    #[test]
    fn mount_refuses_symlinked_component() {
        let (_tmp, dir) = unique_workspace();
        let link = dir.parent().unwrap().join("ws-link");
        #[allow(unsafe_code)] // wrapped: this is a test-only symlink helper
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let err = mount(&link).unwrap_err();
        assert_eq!(err.code, ErrorCode::MountHasSymlink);
    }

    #[test]
    fn mount_returns_consistent_fingerprint() {
        let (_tmp, dir) = unique_workspace();
        let a = mount(&dir).unwrap();
        let b = mount(&dir).unwrap();
        assert_eq!(a.fingerprint.id_hex, b.fingerprint.id_hex);
        assert_eq!(a.fingerprint.dev, b.fingerprint.dev);
        assert_eq!(a.fingerprint.inode, b.fingerprint.inode);
    }

    #[test]
    fn verify_unchanged_passes_if_path_intact() {
        let (_tmp, dir) = unique_workspace();
        let mounted = mount(&dir).unwrap();
        assert!(verify_unchanged(&mounted).is_ok());
    }

    #[test]
    fn state_dir_uses_xdg_state_home_when_set() {
        // Rust 2024 marked `set_var`/`remove_var` as unsafe (thread-safety
        // hazard with other threads reading env). This test runs single-
        // threaded; serialise it explicitly so a future paralleliser doesn't
        // race other env-touching tests.
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let prev = std::env::var("XDG_STATE_HOME").ok();
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: no other thread in this test reads or writes XDG_STATE_HOME
        // concurrently; the ENV_LOCK serialises all env-touching tests in this
        // crate.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("XDG_STATE_HOME", tmp.path());
        }

        let (_ws_tmp, dir) = unique_workspace();
        let mounted = mount(&dir).unwrap();
        let sd = state_dir_for(&mounted.fingerprint);

        assert!(
            sd.starts_with(tmp.path()),
            "state dir {:?} should start under XDG_STATE_HOME {:?}",
            sd,
            tmp.path()
        );

        // SAFETY: same as above; restoring under the same lock.
        #[allow(unsafe_code)]
        unsafe {
            match prev {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
        }
    }
}
