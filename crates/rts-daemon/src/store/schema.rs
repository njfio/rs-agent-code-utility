//! redb table definitions + value-type schemas.
//!
//! Postcard encodes the value payloads. Keys stay simple (`u32`, `&str`) so
//! redb's built-in encoders apply. Per the P0.2 spike, this layout hit p50
//! lookups around 0.7 µs (shared-txn) on macOS arm64.

use redb::{MultimapTableDefinition, TableDefinition};
use serde::{Deserialize, Serialize};

// ---------- Tables ----------

/// `file_id (u32)` → postcard(`FileMeta`).
pub const FILES: TableDefinition<u32, &[u8]> = TableDefinition::new("files");
/// `workspace-relative path (&str)` → `file_id (u32)`.
pub const PATH_TO_FID: TableDefinition<&str, u32> = TableDefinition::new("path_to_fid");
/// `file_id (u32)` → `workspace-relative path (&str)`.
pub const FID_TO_PATH: TableDefinition<u32, &str> = TableDefinition::new("fid_to_path");
/// `symbol name (&str)` → `symbol_id (u32)` intern table.
pub const NAME_TO_SID: TableDefinition<&str, u32> = TableDefinition::new("name_to_sid");
/// Inverse: `symbol_id (u32)` → `symbol name (&str)`.
pub const SID_TO_NAME: TableDefinition<u32, &str> = TableDefinition::new("sid_to_name");
/// Multimap `symbol_id (u32)` → postcard(`DefSite`). Each `(name, file)` pair
/// produces one row.
pub const DEFS: MultimapTableDefinition<u32, &[u8]> = MultimapTableDefinition::new("defs");
/// Inverse fan-out for cheap per-file invalidation: `file_id` → set of `sid`s
/// it defines.
pub const FID_DEFS: MultimapTableDefinition<u32, u32> = MultimapTableDefinition::new("fid_defs");

// ---------- v0.3 reference-graph tables (SCHEMA_VERSION=2; U1 of v0.3 plan) ----------
//
// Three tables form the call-graph half of the index. v0.2 computed
// references at query time and threw them away; v0.3 persists them so
// `Index.FindCallers`, `Index.ImpactOf`, and symbol-level PageRank
// (`rank_score`) become O(1) lookups instead of O(workspace) scans.
//
// Shape rationale (see v0.3 plan §"Architecture" + deepening §B1):
//   * Multimap blob-of-postcard for REFS mirrors DEFS. Bytes-equal
//     entries dedupe; the secondary B-tree handles per-key fan-out
//     without rewriting the whole vec on each update.
//   * FID_REFS gives O(1) per-file ref invalidation symmetric to
//     FID_DEFS — `drop_file_entries` extends naturally.
//   * SID_REFS_OUT gives the *outgoing* direction ("what does X
//     reference?") cheaply. Without it, the closure walker would
//     have to scan all REFS to find rows where caller_sid == X.
//     Landed in U1 (not U4) to avoid a second SCHEMA_VERSION bump.

/// Multimap `callee_sid (u32)` → postcard(`RefSite`). One entry per
/// individual call site, so `REFS[X]` answers "who calls X, and
/// where?" with one lookup. Used by `Index.FindCallers` (v0.3 U2').
pub const REFS: MultimapTableDefinition<u32, &[u8]> = MultimapTableDefinition::new("refs");

/// Multimap `file_id (u32)` → set of `callee_sid (u32)`s referenced
/// in that file. Used by `outline::compute` to enumerate outgoing
/// refs per file (replacing the at-query-time parse loop). Also the
/// invalidation key for `drop_file_entries`: when a file is removed,
/// FID_REFS[fid] enumerates which REFS rows need a filter-by-fid
/// rewrite.
///
/// Multimap dedupes — if file F references callee C three times,
/// only one row `(F → C)` is stored. The three individual call
/// sites all live in REFS[C].
pub const FID_REFS: MultimapTableDefinition<u32, u32> = MultimapTableDefinition::new("fid_refs");

/// Multimap `caller_sid (u32)` → set of `callee_sid (u32)`s the
/// caller references. Used by `closure::compute` (v0.3 U3) to answer
/// "what does symbol X call?" without re-parsing the anchor file.
/// File-scope refs (callsites not inside any def) are excluded —
/// they have no caller_sid to key on.
pub const SID_REFS_OUT: MultimapTableDefinition<u32, u32> =
    MultimapTableDefinition::new("sid_refs_out");

/// Small key-value table for daemon-internal metadata (schema_version,
/// next_fid, next_sid, workspace_fingerprint, …).
pub const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

// ---------- Value types ----------

/// Whether the parser succeeded, partially succeeded, or errored on the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ParseStatus {
    Ok = 0,
    Partial = 1,
    Failed = 2,
}

/// Per-file metadata row.
///
/// `lang` is a small numeric tag the writer is the source of truth for
/// (see `writer.rs::lang_tag`); we don't serialise the `Language` enum
/// directly because that would couple the on-disk format to rts-core's
/// internal enum order.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FileMeta {
    pub content_hash: [u8; 32],
    pub mtime_ns: i64,
    pub lang: u8,
    pub parse_status: ParseStatus,
    pub oversize: bool,
}

/// A single definition site: which file, byte/line range, kind, visibility.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DefSite {
    pub fid: u32,
    pub start: u32,
    pub end: u32,
    pub start_line: u32,
    pub end_line: u32,
    pub visibility: Visibility,
    pub kind: SymbolKind,
}

/// A single reference site: where one symbol is called from. Used as
/// the value type for the `REFS` multimap, keyed by `callee_sid`.
///
/// `caller_sid` is the SID of the smallest enclosing def whose range
/// covers `start`. `None` when the call site is outside any def
/// (e.g. a top-level expression statement, a static initializer at
/// module scope, or a JavaScript top-level call).
///
/// Postcard varint-encodes u32s, so a typical RefSite serializes to
/// ~12 bytes (5 u32s in the 1-2 byte range + 1-byte enum tag for
/// caller_sid `Option`). Worst case is 26 bytes when every field is
/// > 2^28. The redb B-tree sorts by *key* (callee_sid), not by
/// blob bytes; insertion order within a multimap key is arbitrary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RefSite {
    pub fid: u32,
    pub start: u32,
    pub end: u32,
    pub start_line: u32,
    pub end_line: u32,
    pub caller_sid: Option<u32>,
}

/// Cross-language symbol kind. Coarse-grained on purpose; per-language
/// kinds (Rust impl-block vs Python decorator etc.) will live in a
/// `subkind` byte introduced when a real consumer needs the distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SymbolKind {
    Function = 1,
    Method = 2,
    Class = 3,
    Struct = 4,
    Enum = 5,
    Trait = 6,
    Type = 7,
    Const = 8,
    Static = 9,
    Module = 10,
    Other = 255,
}

impl SymbolKind {
    /// Convert from the loose `String` `kind` field that `rts_core::Symbol`
    /// emits today. (P8's per-language SignatureRenderer work will tighten
    /// this on the producer side.)
    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "fn" | "function" | "func" | "def" => SymbolKind::Function,
            "method" => SymbolKind::Method,
            "class" => SymbolKind::Class,
            "struct" | "record" => SymbolKind::Struct,
            "enum" | "enum_class" => SymbolKind::Enum,
            "trait" | "interface" | "protocol" => SymbolKind::Trait,
            "type" | "type_alias" | "typealias" => SymbolKind::Type,
            "const" | "constant" => SymbolKind::Const,
            "static" => SymbolKind::Static,
            "module" | "namespace" => SymbolKind::Module,
            _ => SymbolKind::Other,
        }
    }

    pub fn as_wire_str(self) -> &'static str {
        match self {
            SymbolKind::Function => "fn",
            SymbolKind::Method => "method",
            SymbolKind::Class => "class",
            SymbolKind::Struct => "struct",
            SymbolKind::Enum => "enum",
            SymbolKind::Trait => "trait",
            SymbolKind::Type => "type",
            SymbolKind::Const => "const",
            SymbolKind::Static => "static",
            SymbolKind::Module => "module",
            SymbolKind::Other => "other",
        }
    }
}

/// Symbol visibility — loosely classified from the producer's string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum Visibility {
    Public = 0,
    Private = 1,
    Crate = 2,
    Protected = 3,
    Unknown = 255,
}

impl Visibility {
    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "public" | "pub" => Visibility::Public,
            "private" | "priv" => Visibility::Private,
            "crate" | "pub(crate)" => Visibility::Crate,
            "protected" => Visibility::Protected,
            _ => Visibility::Unknown,
        }
    }

    pub fn as_wire_str(self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Private => "private",
            Visibility::Crate => "crate",
            Visibility::Protected => "protected",
            Visibility::Unknown => "unknown",
        }
    }
}

/// Compact newtype for a file id stored in `FILES` keys. Type-only convenience
/// for callers; redb still sees plain `u32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileId(pub u32);

/// Same for symbol ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymbolId(pub u32);
