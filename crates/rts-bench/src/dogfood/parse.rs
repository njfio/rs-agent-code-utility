//! JSONL session-transcript parser for `rts-bench dogfood`.
//!
//! Claude Code session files live at
//! `~/.claude/projects/<encoded-cwd>/<uuid>.jsonl`. Each line is one
//! JSON event. The events we care about have:
//!
//! ```jsonc
//! {
//!   "type": "assistant",
//!   "timestamp": "2026-05-19T14:32:11.123Z",
//!   "message": {
//!     "role": "assistant",
//!     "content": [
//!       { "type": "tool_use", "id": "toolu_...", "name": "Bash",
//!         "input": { "command": "grep -rn pattern .", "description": "..." } }
//!     ]
//!   }
//! }
//! ```
//!
//! A single assistant line can carry multiple tool_uses (Claude can
//! batch tool calls in a turn). Non-tool content blocks (`"text"`,
//! `"thinking"`) and non-assistant lines (`user`, `tool_result`,
//! `summary`, `queue-operation`, …) are ignored.
//!
//! Parse contract: best-effort, fail-loud-on-format-corruption,
//! quiet-on-individual-event-skips. A line that isn't valid JSON
//! returns `Err` (the file is corrupt); a line that's valid JSON but
//! has none of the expected fields is skipped silently (forward-compat
//! with new Claude Code event types).

use std::io::BufRead;

use anyhow::{Context, Result};
use serde_json::Value;

/// One agent-emitted tool invocation. The parser flattens
/// multi-tool-use assistant turns into N events, one per tool_use
/// block, preserving the outer line's timestamp on each.
#[derive(Debug, Clone)]
pub struct ToolUseEvent {
    /// Tool name verbatim, e.g. `"Bash"`, `"Read"`, `"mcp__rts__grep"`.
    pub name: String,
    /// ISO-8601 UTC timestamp from the outer event line, when present.
    /// `None` for lines that omit it (rare; the dogfood report
    /// degrades to `duration_ms: None` instead of failing).
    pub timestamp: Option<String>,
    /// The full `input` object as it appeared in the JSONL. Kept
    /// untyped because tool-input shapes vary by tool (Bash has
    /// `command`, Edit has `file_path` + `new_string`, etc.).
    pub input: Value,
}

impl ToolUseEvent {
    /// Convenience for the `Bash` case: pull `input.command` as `&str`.
    /// Returns `None` for non-Bash events or when the field is missing
    /// or not a string. Tool calls without a command can't be
    /// classified, so the classifier short-circuits via this returning
    /// `None`.
    pub fn command(&self) -> Option<&str> {
        self.input.get("command")?.as_str()
    }
}

/// Parse a session JSONL into a flat vector of `ToolUseEvent`s in
/// source order. One outer JSONL line can emit zero or many events
/// depending on how many tool_use blocks it carries.
///
/// Returns `Err` on any line that isn't valid JSON; partial output is
/// not surfaced — the maintainer fixes the JSONL or filters it.
/// Lines that are valid JSON but uninteresting (user messages, tool
/// results, queue ops) yield zero events.
pub fn parse_session<R: BufRead>(reader: R) -> Result<Vec<ToolUseEvent>> {
    let mut out = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("reading JSONL line {}", idx + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(trimmed)
            .with_context(|| format!("parsing JSONL line {}: not valid JSON", idx + 1))?;
        extract_tool_uses(&v, &mut out);
    }
    Ok(out)
}

/// Drain `tool_use` blocks from a single JSONL line's parsed JSON
/// into `out`. Tolerates the four shapes we've observed in real
/// Claude Code transcripts:
///
/// - `{"type":"assistant", "message":{"content":[…]}}` — the modern
///   shape, what every recent session emits.
/// - `{"type":"user", "message":{"content":[…]}}` — user turns can
///   theoretically carry tool_use too (sidechain), so we accept them.
/// - Lines without a `message.content[]` array (queue ops, summaries,
///   `tool_result` blocks at the top level) → silently skipped.
///
/// We do NOT try to walk arbitrarily-nested structures; the official
/// content-block shape is always at `message.content[]`.
fn extract_tool_uses(line: &Value, out: &mut Vec<ToolUseEvent>) {
    let timestamp = line
        .get("timestamp")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let Some(content) = line
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_array())
    else {
        return;
    };

    for block in content {
        let Some(obj) = block.as_object() else {
            continue;
        };
        let Some(ty) = obj.get("type").and_then(|t| t.as_str()) else {
            continue;
        };
        if ty != "tool_use" {
            continue;
        }
        let name = obj
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            // Defensive: a tool_use block without a name is malformed
            // upstream. Skip rather than panic.
            continue;
        }
        let input = obj
            .get("input")
            .cloned()
            .unwrap_or(Value::Object(serde_json::Map::new()));
        out.push(ToolUseEvent {
            name,
            timestamp: timestamp.clone(),
            input,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_assistant_with_single_tool_use() {
        let line = r#"{"type":"assistant","timestamp":"2026-05-19T14:32:11.000Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}}]}}"#;
        let evts = parse_session(line.as_bytes()).unwrap();
        assert_eq!(evts.len(), 1);
        assert_eq!(evts[0].name, "Bash");
        assert_eq!(evts[0].command(), Some("ls"));
        assert_eq!(
            evts[0].timestamp.as_deref(),
            Some("2026-05-19T14:32:11.000Z")
        );
    }

    #[test]
    fn flattens_multi_tool_use_into_multiple_events() {
        let line = r#"{"type":"assistant","timestamp":"2026-05-19T14:32:11.000Z","message":{"content":[{"type":"tool_use","id":"a","name":"Bash","input":{"command":"ls"}},{"type":"tool_use","id":"b","name":"Read","input":{"file_path":"/x"}}]}}"#;
        let evts = parse_session(line.as_bytes()).unwrap();
        assert_eq!(evts.len(), 2);
        assert_eq!(evts[0].name, "Bash");
        assert_eq!(evts[1].name, "Read");
    }

    #[test]
    fn skips_text_blocks_and_non_assistant_lines() {
        let jsonl = concat!(
            r#"{"type":"queue-operation","timestamp":"2026-05-19T14:32:00.000Z"}"#,
            "\n",
            r#"{"type":"user","timestamp":"2026-05-19T14:32:05.000Z","message":{"role":"user","content":"hello"}}"#,
            "\n",
            r#"{"type":"assistant","timestamp":"2026-05-19T14:32:11.000Z","message":{"content":[{"type":"text","text":"thinking..."}]}}"#,
            "\n",
            r#"{"type":"assistant","timestamp":"2026-05-19T14:32:12.000Z","message":{"content":[{"type":"tool_use","id":"t","name":"Bash","input":{"command":"ls"}}]}}"#,
            "\n",
        );
        let evts = parse_session(jsonl.as_bytes()).unwrap();
        assert_eq!(evts.len(), 1);
        assert_eq!(evts[0].name, "Bash");
    }

    #[test]
    fn malformed_json_line_is_an_error() {
        let jsonl = "{this is not json}\n";
        assert!(parse_session(jsonl.as_bytes()).is_err());
    }

    #[test]
    fn empty_lines_are_skipped() {
        let jsonl = "\n\n\n";
        let evts = parse_session(jsonl.as_bytes()).unwrap();
        assert!(evts.is_empty());
    }
}
