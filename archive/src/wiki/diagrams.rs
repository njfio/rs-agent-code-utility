// Skeleton for Phase 1; functions will be moved incrementally.
// Implementations will extend WikiGenerator with diagram helpers.

use std::fmt::Write as _;
use std::path::Path;

impl super::WikiGenerator {
    pub(super) fn file_has_branching(file: &crate::analyzer::FileInfo) -> bool {
        use crate::analysis_common::FileAnalyzer;
        if let Ok(content) = std::fs::read_to_string(&file.path) {
            if let Ok(tree) = FileAnalyzer::parse_file_content(&content, &file.language) {
                let t = &tree;
                let kinds = [
                    "if_expression",
                    "match_expression",
                    "while_expression",
                    "while_let_expression",
                    "for_expression",
                    "loop_expression", // rust
                    "if_statement",
                    "switch_statement",
                    "conditional_expression", // js/ts/c/cpp/go
                    "for_statement",
                    "while_statement",
                    "do_statement",
                ];
                return kinds.iter().any(|k| !t.find_nodes_by_kind(k).is_empty());
            }
        }
        false
    }

    pub(super) fn build_sequence_diagram(
        file: &crate::analyzer::FileInfo,
        root_path: &Path,
    ) -> String {
        // Participants from function symbols
        let funcs: Vec<_> = file
            .symbols
            .iter()
            .filter(|s| s.kind.contains("fn") || s.kind.contains("function"))
            .collect();

        let mut out = String::new();

        // Add participants
        for f in &funcs {
            let _ = writeln!(
                &mut out,
                "  participant {}",
                super::util::safe_ident(&f.name)
            );
        }

        // Try building call list via CFG
        let calls_from_cfg: Option<Vec<String>> = (|| {
            use crate::analysis_common::FileAnalyzer;
            let abs = if file.path.is_absolute() {
                file.path.clone()
            } else {
                root_path.join(&file.path)
            };
            let content = std::fs::read_to_string(abs).ok()?;
            let tree = FileAnalyzer::parse_file_content(&content, &file.language).ok()?;
            let builder = crate::control_flow::CfgBuilder::new(&file.language);
            let cfg = builder.build_cfg(&tree).ok()?;
            let calls = cfg.call_sequence();
            if !calls.is_empty() {
                Some(calls)
            } else {
                None
            }
        })();

        // Simple heuristic fallback for basic calls - look for patterns in the file
        let simple_calls: Option<Vec<(String, String)>> = (|| {
            use crate::analysis_common::FileAnalyzer;
            if file.path.exists() {
                let content = std::fs::read_to_string(&file.path).ok()?;
                let tree = FileAnalyzer::parse_file_content(&content, &file.language).ok()?;

                let mut calls = Vec::new();
                // Simple heuristic: look for function calls in the syntax tree
                super::util::walk_tree_for_calls(&tree, tree.inner().root_node(), &mut calls);
                if !calls.is_empty() {
                    Some(calls)
                } else {
                    None
                }
            } else {
                None
            }
        })();

        if let Some(calls) = calls_from_cfg {
            // Use CFG calls
            if let Some(caller) = funcs.first() {
                let caller_id = super::util::safe_ident(&caller.name);
                for callee in calls {
                    let _ = writeln!(
                        &mut out,
                        "  {}->>{}: call",
                        caller_id,
                        super::util::safe_ident(&callee)
                    );
                }
            }
        } else if let Some(simple_calls_data) = simple_calls {
            // Use simple calls
            for (caller_name, callee_name) in simple_calls_data {
                if funcs.iter().any(|f| f.name == caller_name)
                    && funcs.iter().any(|f| f.name == callee_name)
                {
                    let _ = writeln!(
                        &mut out,
                        "  {}->>{}: call",
                        super::util::safe_ident(&caller_name),
                        super::util::safe_ident(&callee_name)
                    );
                }
            }
        } else if funcs.len() >= 2 {
            // Fallback: adjacent functions
            for w in funcs.windows(2) {
                let a = super::util::safe_ident(&w[0].name);
                let b = super::util::safe_ident(&w[1].name);
                let _ = writeln!(&mut out, "  {}->>{}: call", a, b);
            }
        }
        out
    }

    pub(super) fn build_control_flow(file: &crate::analyzer::FileInfo) -> String {
        // Heuristic control flow based on symbol list
        let mut out = String::new();
        let _ = writeln!(&mut out, "  start([Start])\n  end([End])\n  start --> F0");
        for (i, s) in file.symbols.iter().enumerate() {
            let id = format!("F{}", i);
            let _ = writeln!(
                &mut out,
                "  {}([{}])",
                id,
                super::util::html_escape(&s.name)
            );
            if i + 1 < file.symbols.len() {
                let next = format!("F{}", i + 1);
                let _ = writeln!(&mut out, "  {} --> {}", id, next);
            } else {
                let _ = writeln!(&mut out, "  {} --> end", id);
            }
        }

        out
    }

    pub(super) fn build_sequence_or_flow_blocks(
        file: &crate::analyzer::FileInfo,
        rels: &str,
        root_path: &Path,
    ) -> String {
        // Build CFG once; use it to decide branching and to render flow if available
        let (flow_from_cfg, has_branch) = (|| {
            use crate::analysis_common::FileAnalyzer;
            let abs_path = if file.path.is_absolute() {
                file.path.clone()
            } else {
                root_path.join(&file.path)
            };
            let content = std::fs::read_to_string(&abs_path).ok()?;
            let tree = FileAnalyzer::parse_file_content(&content, &file.language).ok()?;
            let builder = crate::control_flow::CfgBuilder::new(&file.language);
            let cfg = builder.build_cfg(&tree).ok()?;
            // Determine branching from CFG
            let has_branch = !cfg.decision_points().is_empty();
            // Render a simple flowchart including Branch and Call nodes
            let mut out = String::new();
            use std::fmt::Write as _;
            // Helpers: sanitize labels and shorten branch kinds for Mermaid reliability
            fn sanitize_label(s: &str) -> String {
                let mut t = String::with_capacity(s.len());
                for ch in s.chars() {
                    match ch {
                        'a'..='z' | 'A'..='Z' | '0'..='9' | ' ' | '_' | '-' => t.push(ch),
                        ':' | '.' | '/' | '\\' => t.push('_'),
                        _ => {}
                    }
                }
                if t.is_empty() {
                    "node".to_string()
                } else {
                    t
                }
            }
            fn short_branch(kind: &str) -> String {
                let k = kind.to_lowercase();
                if k.contains("if") {
                    "if".to_string()
                } else if k.contains("match") {
                    "match".to_string()
                } else if k.contains("switch") {
                    "switch".to_string()
                } else if k.contains("for") {
                    "for".to_string()
                } else if k.contains("while_let") {
                    "while let".to_string()
                } else if k.contains("while") {
                    "while".to_string()
                } else if k.contains("loop") {
                    "loop".to_string()
                } else {
                    sanitize_label(kind)
                }
            }
            let _ = writeln!(&mut out, "  S([Start])\n  E([End])\n  S --> N0");
            let mut idx = 0usize;
            for n in cfg.graph.node_indices() {
                match &cfg.graph[n] {
                    crate::control_flow::CfgNodeType::Branch { node_type, .. } => {
                        let label = short_branch(node_type);
                        let _ = writeln!(&mut out, "  N{}([{}])", idx, label);
                        // Include original node_type as a Mermaid comment to aid tests/search
                        let _ = writeln!(&mut out, "  %% node_type: {}", node_type);
                        if label == "if" || label == "match" || label == "switch" {
                            if idx > 0 {
                                let _ = writeln!(&mut out, "  N{} -->|true| N{}", idx - 1, idx);
                                let _ = writeln!(&mut out, "  N{} -->|false| N{}", idx - 1, idx);
                            } else {
                                // First branch after Start: show labeled edges from S to N0
                                let _ = writeln!(&mut out, "  S -->|true| N0");
                                let _ = writeln!(&mut out, "  S -->|false| N0");
                            }
                        } else if idx > 0 {
                            let _ = writeln!(&mut out, "  N{} --> N{}", idx - 1, idx);
                        }
                        idx += 1;
                    }
                    crate::control_flow::CfgNodeType::Call { function_name, .. } => {
                        let _ = writeln!(
                            &mut out,
                            "  N{}([call {}])",
                            idx,
                            sanitize_label(function_name)
                        );
                        if idx > 0 {
                            let _ = writeln!(&mut out, "  N{} --> N{}", idx - 1, idx);
                        }
                        idx += 1;
                    }
                    _ => {}
                }
            }
            if idx > 0 {
                let _ = writeln!(&mut out, "  N{} --> E", idx - 1);
            } else {
                let _ = writeln!(&mut out, "  N0 --> E");
            }
            Some((out, has_branch))
        })()
        .unzip();

        let flow_opt: Option<String> = flow_from_cfg; // first of tuple
        let has_branch = has_branch.unwrap_or_else(|| Self::file_has_branching(file));
        let multi_funcs = file
            .symbols
            .iter()
            .filter(|s| s.kind.contains("fn") || s.kind.contains("function"))
            .count()
            >= 2;
        // Short helper snippets explaining how to read diagrams
        let help_cf = "<div class=\"diagram-help\"><strong>How to read Control Flow:</strong> boxes are Branch/Call nodes; arrows show execution; <code>true/false</code> edge labels indicate decision outcomes; <code>repeat</code> labels mark loop back edges; Start/End denote entry/exit.</div>";
        let help_seq = "<div class=\"diagram-help\"><strong>How to read Call Sequence:</strong> participants are functions; <code>A-&gt;&gt;B</code> means A calls B; events appear top-to-bottom in call order; the \"call\" label is a generic action description.</div>";

        match (has_branch, multi_funcs) {
            (true, true) => format!(
                "<details class=\"card\" id=\"control-flow\"><summary>Control Flow</summary>{help_cf}<div class=\"mermaid\">flowchart TB\n{flow}\n</div></details>\n\
                 <details class=\"card\" id=\"call-sequence\"><summary>Call Sequence</summary>{help_seq}<div class=\"mermaid\">sequenceDiagram\n{seq}\n</div></details>",
                help_cf = help_cf,
                help_seq = help_seq,
                flow = flow_opt.unwrap_or_else(|| Self::build_control_flow(file)),
                seq = Self::build_sequence_diagram(file, root_path),
            ),
            (true, false) => {
                let flow = flow_opt.unwrap_or_else(|| Self::build_control_flow(file));
                format!(
                    "<details class=\"card\" id=\"control-flow\"><summary>Control Flow</summary>{help_cf}<div class=\"mermaid\">flowchart TB\n{flow}\n</div></details>",
                    help_cf = help_cf,
                    flow = flow,
                )
            }
            (false, true) => format!(
                "<details class=\"card\" id=\"call-sequence\"><summary>Call Sequence</summary>{help_seq}<div class=\"mermaid\">sequenceDiagram\n{seq}\n</div></details>\n\
                 <details class=\"card\" id=\"class-diagram\"><summary>Class/Module Diagram</summary><div class=\"mermaid\">classDiagram\n{rels}\n</div></details>",
                help_seq = help_seq,
                seq = Self::build_sequence_diagram(file, root_path),
                rels = rels,
            ),
            (false, false) => format!(
                "<details class=\"card\" id=\"class-diagram\"><summary>Class/Module Diagram</summary><div class=\"mermaid\">classDiagram\n{rels}\n</div></details>",
                rels = rels,
            ),
        }
    }
}
