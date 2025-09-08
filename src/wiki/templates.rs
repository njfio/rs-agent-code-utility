// Phase 1: HTML template writers moved from mod.rs with minimal churn.

use crate::analyzer::AnalysisResult;
use std::fmt::Write as _;
use std::path::Path;

impl super::WikiGenerator {
    pub(super) fn build_nav(
        &self,
        files: &[crate::analyzer::FileInfo],
        link_prefix: &str,
    ) -> String {
        use std::collections::BTreeMap;
        #[derive(Default)]
        struct Node {
            dirs: BTreeMap<String, Node>,
            files: Vec<(String, String)>,
        }

        fn insert_path(node: &mut Node, parts: &[String], display: &str, href: &str) {
            if parts.is_empty() {
                node.files.push((display.to_string(), href.to_string()));
                return;
            }
            if parts.len() == 1 {
                node.files.push((display.to_string(), href.to_string()));
                return;
            }
            let head = parts[0].clone();
            let child = node.dirs.entry(head).or_default();
            insert_path(child, &parts[1..], display, href);
        }

        let mut root = Node::default();
        for f in files {
            let display = f.path.display().to_string();
            let href = format!(
                "{}{}.html",
                link_prefix,
                super::util::sanitize_filename(&f.path)
            );
            let parts: Vec<String> = f
                .path
                .components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect();
            insert_path(&mut root, &parts, &display, &href);
        }

        fn render(node: &Node, name: Option<&str>, out: &mut String) {
            if let Some(n) = name {
                let _ = writeln!(
                    out,
                    "<details><summary class=\"folder\">{}</summary>",
                    super::util::html_escape(n)
                );
            }
            for (dname, child) in &node.dirs {
                render(child, Some(dname), out);
            }
            for (disp, href) in &node.files {
                let _ = writeln!(
                    out,
                    "<a href=\"{}\">{}</a>",
                    href,
                    super::util::html_escape(disp)
                );
            }
            if name.is_some() {
                let _ = writeln!(out, "</details>");
            }
        }

        let mut out = String::new();
        for (dname, child) in &root.dirs {
            render(child, Some(dname), &mut out);
        }
        for (disp, href) in &root.files {
            let _ = writeln!(
                &mut out,
                "<a href=\"{}\">{}</a>",
                href,
                super::util::html_escape(disp)
            );
        }
        out
    }

    /// Build sidebar HTML with search input, filters, and links
    pub(super) fn build_sidebar_with_search(
        &self,
        analysis: &AnalysisResult,
        security_analysis: &Option<super::security_enhancements::SecurityAnalysisResult>,
        link_prefix: &str,
    ) -> String {
        let mut nav_content = String::new();
        let root_prefix = if link_prefix.is_empty() { "../" } else { "" };
        // Search input + clear button row
        let _ = writeln!(
            &mut nav_content,
            "<div style=\"display:flex;gap:.4rem;align-items:center\"><input class=\"search\" id=\"q\" type=\"search\" placeholder=\"Search...\" /><button id=\"clearSearch\" class=\"theme-toggle\" title=\"Clear search\">Clear</button></div>"
        );
        // Language filter (populated by search.js)
        let _ = writeln!(
            &mut nav_content,
            "<label for=\"langFilter\" style=\"display:block;margin-top:.5rem;color:#9aa4b2;font-size:.85em\">Language</label>"
        );
        let _ = writeln!(
            &mut nav_content,
            "<select id=\"langFilter\" style=\"width:100%;background:#0a1220;color:#e6e9ef;border:1px solid #1f2937;border-radius:6px;padding:.25rem .5rem\"><option value=\"\">All</option></select>"
        );
        // Kind filter (populated by search.js)
        let _ = writeln!(&mut nav_content, "<label for=\"kindFilter\" style=\"display:block;margin-top:.5rem;color:#9aa4b2;font-size:.85em\">Symbol Kind</label>");
        let _ = writeln!(
            &mut nav_content,
            "<select id=\"kindFilter\" style=\"width:100%;background:#0a1220;color:#e6e9ef;border:1px solid #1f2937;border-radius:6px;padding:.25rem .5rem\"><option value=\"\">All</option></select>"
        );
        // Vulnerability filter
        let _ = writeln!(&mut nav_content, "<label style=\"display:flex;align-items:center;gap:.5rem;margin-top:.5rem;color:#9aa4b2;font-size:.9em\"><input id=\"vulnOnly\" type=\"checkbox\"> Vulnerable only</label>");
        // Live results container + meta
        let _ = writeln!(
            &mut nav_content,
            "<div id=\"resultMeta\" style=\"color:#9aa4b2;font-size:.85em;margin:.25rem 0\"></div>"
        );
        let _ = writeln!(
            &mut nav_content,
            "<ul id=\"results\" style=\"margin:.5rem 0; padding-left:1rem;\"></ul>"
        );

        // File links
        let _ = writeln!(
            &mut nav_content,
            "<hr style=\"border-color: #334155; margin: .75rem 0;\"/>"
        );
        let _ = writeln!(&mut nav_content, "<h4>Files</h4>");
        let _ = writeln!(
            &mut nav_content,
            "{}",
            self.build_nav(&analysis.files, link_prefix)
        );

        // Security links if available
        if let Some(_security) = security_analysis {
            let _ = writeln!(
                &mut nav_content,
                "<hr style=\"border-color: #334155; margin: 1rem 0;\"/>"
            );
            let _ = writeln!(&mut nav_content, "<h4>Security</h4>");
            let _ = writeln!(
                &mut nav_content,
                "<a href=\"{root}security.html\">Security Overview</a>",
                root = root_prefix
            );
            let _ = writeln!(
                &mut nav_content,
                "<a href=\"{root}security_hotspots.html\">Security Hotspots</a>",
                root = root_prefix
            );
        }

        nav_content
    }

    pub(super) fn write_index_html(
        &self,
        out: &Path,
        analysis: &AnalysisResult,
        security_analysis: &Option<super::security_enhancements::SecurityAnalysisResult>,
        nav_content: &str,
    ) -> super::Result<()> {
        let ai_block = if self.config.ai_enabled {
            self.generate_project_ai_block(analysis)
                .unwrap_or_else(|_| "<div class=\"card ai\"><h3>AI Commentary</h3><p>AI generation failed. Showing defaults.</p></div>".to_string())
        } else {
            "<div class=\"card ai\"><h3>AI Commentary</h3><p>Enable AI to generate rich documentation.</p></div>".to_string()
        };

        let security_block = if let Some(ref security) = security_analysis {
            let inner = self.generate_security_overview_block(security);
            format!("<details class=\"card\" id=\"security-overview\"><summary>Security Overview</summary>{}</details>", inner)
        } else {
            String::new()
        };

        let ai_summary_top = format!(
            "<div class=\"card ai\" id=\"ai-summary\"><h3>AI Summary</h3>\n<p><strong>Project Root:</strong> {root}<br><strong>Total Files:</strong> {files}<br><strong>Total Lines:</strong> {lines}</p></div>",
            root = super::util::html_escape(&analysis.root_path.display().to_string()),
            files = analysis.total_files,
            lines = analysis.total_lines,
        );

        let mut toc_items: Vec<String> = Vec::new();
        toc_items.push("<li><a href=\\\"#ai-commentary\\\">AI Commentary</a></li>".to_string());
        toc_items
            .push("<li><a href=\\\"#project-snapshot\\\">Project Snapshot</a></li>".to_string());
        toc_items.push(
            "<li><a href=\\\"#dependency-overview\\\">Dependency Overview</a></li>".to_string(),
        );
        if security_analysis.is_some() {
            toc_items.push(
                "<li><a href=\\\"#security-overview\\\">Security Overview</a></li>".to_string(),
            );
        }
        toc_items
            .push("<li><a href=\\\"#docs-insights\\\">Documentation Insights</a></li>".to_string());
        let toc_html = format!(
            "<div class=\\\"card toc\\\"><h3>Contents</h3><ul>{}</ul></div>",
            toc_items.join("\n")
        );

        let content = format!(
            r#"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="assets/style.css">
<link rel="stylesheet" href="assets/hljs.css">
<script src="assets/search_index.js"></script>
<script src="assets/search.js"></script>
<script src="assets/mermaid.js"></script>
<script src="assets/hljs.js"></script>
<script src="assets/main.js"></script>
</head>
<body>
<header><h1>{title}</h1><div style="display:flex;gap:.5rem;align-items:center"><button id="sidebarToggle" class="sidebar-toggle">Sidebar</button><button id="themeToggle" class="theme-toggle"></button></div></header>
<main>
<nav>
{nav}
</nav>
<section class="article">
{ai_summary_top}
{toc}
<details class="card" id="ai-commentary"><summary>AI Commentary</summary>
{ai_block}
</details>
<details class="card" id="project-snapshot"><summary>Project Snapshot</summary>
{project_snapshot}
</details>
<details class="card" id="dependency-overview"><summary>Dependency Overview</summary>
<div class="mermaid">graph LR
{dep}
</div>
</details>
{security_block}
<details class="card" id="docs-insights"><summary>Documentation Insights</summary>
<p>Automatic summaries are generated from symbols and structure. Public functions and modules include heuristic descriptions and cross-references.</p>
</details>
</section>
</main>
</body>
</html>"#,
            title = self.config.site_title,
            nav = nav_content,
            ai_summary_top = ai_summary_top,
            toc = toc_html,
            project_snapshot =
                super::util::markdown_to_html(&super::WikiGenerator::project_snapshot_md(analysis)),
            dep = super::util::build_simple_dependency_graph(analysis),
            security_block = security_block,
            ai_block = ai_block,
        );
        std::fs::write(out.join("index.html"), content).map_err(|e| e.into())
    }

    pub(super) fn write_global_symbols(
        &self,
        out: &Path,
        files: &[crate::analyzer::FileInfo],
    ) -> super::Result<()> {
        let mut items = String::new();
        for f in files {
            let page = format!("pages/{}.html", super::util::sanitize_filename(&f.path));
            for s in &f.symbols {
                let _ = writeln!(
                    &mut items,
                    "<li><a href=\"{page}#symbol-{anchor}\"><code>{name}</code></a> <small>{file}</small></li>",
                    page = page,
                    anchor = super::util::anchorize(&s.name),
                    name = super::util::html_escape(&s.name),
                    file = super::util::html_escape(&f.path.display().to_string()),
                );
            }
        }
        let content = format!(
            r#"<!doctype html>
<html>
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Symbols - {title}</title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body>
<header><h1>Symbols</h1></header>
<main>
<section class="article">
<ul>
{items}
</ul>
</section>
</main>
</body>
</html>"#,
            title = super::util::html_escape(&self.config.site_title),
            items = items,
        );
        std::fs::write(out.join("symbols.html"), content).map_err(|e| e.into())
    }

    pub(super) fn write_security_overview_page(
        &self,
        out: &Path,
        security: &super::security_enhancements::SecurityAnalysisResult,
    ) -> super::Result<()> {
        let mut content = String::new();
        let _ = writeln!(&mut content, "<!doctype html>\n<html>\n<head>");
        let _ = writeln!(&mut content, "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        let _ = writeln!(
            &mut content,
            "<title>Security Overview - {}</title>",
            super::util::html_escape(&self.config.site_title)
        );
        let _ = writeln!(&mut content, "<link rel=\\\"stylesheet\\\" href=\\\"assets/style.css\\\">\n<script src=\\\"assets/mermaid.js\\\"></script>\n<script src=\\\"assets/main.js\\\"></script>\n</head>\n<body>");
        let _ = writeln!(&mut content, "<header><h1>Security Overview</h1><button id=\\\"themeToggle\\\" class=\\\"theme-toggle\\\"></button></header>");
        let _ = writeln!(&mut content, "<main><section class=\"article\">");

        // Security score card
        let _ = writeln!(
            &mut content,
            "<div class=\"card\"><h2>Security Score: {}/100</h2>",
            security.security_result.security_score
        );
        let security_rating = if security.security_result.security_score >= 80 {
            "Excellent"
        } else if security.security_result.security_score >= 60 {
            "Good"
        } else if security.security_result.security_score >= 40 {
            "Needs Improvement"
        } else {
            "Critical Issues"
        };
        let _ = writeln!(
            &mut content,
            "<p>Rating: <strong>{}</strong></p></div>",
            security_rating
        );

        // Vulnerabilities summary
        let _ = writeln!(
            &mut content,
            "<div class=\"card\"><h3>Vulnerability Summary</h3>"
        );
        let _ = writeln!(
            &mut content,
            "<p>Total Vulnerabilities: <strong>{}</strong></p>",
            security.security_result.total_vulnerabilities
        );
        let mut vuln_by_severity = String::new();
        for (severity, count) in &security.security_result.vulnerabilities_by_severity {
            let _ = writeln!(&mut vuln_by_severity, "<li>{:?}: {}</li>", severity, count);
        }
        let _ = writeln!(&mut content, "<ul>{}</ul></div>", vuln_by_severity);

        // Security traces
        if !security.security_traces.is_empty() {
            let _ = writeln!(&mut content, "<div class=\"card\"><h3>Security Traces</h3>");
            for trace in &security.security_traces {
                let _ = writeln!(
                    &mut content,
                    "<h4>Vulnerability: {}</h4>",
                    super::util::html_escape(&trace.source.title)
                );
                let _ = writeln!(&mut content, "<p>Severity: {:?}</p>", trace.source.severity);
                let _ = writeln!(
                    &mut content,
                    "<div class=\"mermaid\">{}</div>",
                    super::security_enhancements::SecurityWikiGenerator::new()?
                        .generate_trace_diagram(trace)
                );
            }
            let _ = writeln!(&mut content, "</div>");
        }

        let _ = writeln!(&mut content, "</section></main></body></html>");
        std::fs::write(out.join("security.html"), content).map_err(|e| e.into())
    }

    pub(super) fn write_security_hotspots_page(
        &self,
        out: &Path,
        security: &super::security_enhancements::SecurityAnalysisResult,
    ) -> super::Result<()> {
        let mut content = String::new();
        let _ = writeln!(&mut content, "<!doctype html>\n<html>\n<head>");
        let _ = writeln!(&mut content, "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        let _ = writeln!(
            &mut content,
            "<title>Security Hotspots - {}</title>",
            super::util::html_escape(&self.config.site_title)
        );
        let _ = writeln!(&mut content, "<link rel=\\\"stylesheet\\\" href=\\\"assets/style.css\\\">\n<script src=\\\"assets/mermaid.js\\\"></script>\n<script src=\\\"assets/main.js\\\"></script>\n</head>\n<body>");
        let _ = writeln!(&mut content, "<header><h1>Security Hotspots</h1><button id=\\\"themeToggle\\\" class=\\\"theme-toggle\\\"></button></header>");
        let _ = writeln!(&mut content, "<main><section class=\"article\">");

        if !security.security_hotspots.is_empty() {
            let _ = writeln!(
                &mut content,
                "<div class=\"card\"><h2>Security Hotspots Visualization</h2>"
            );
            let _ = writeln!(
                &mut content,
                "<div class=\"mermaid\">{}</div>",
                super::security_enhancements::SecurityWikiGenerator::new()?
                    .generate_hotspot_diagram(&security.security_hotspots)
            );
            let _ = writeln!(&mut content, "</div>");

            let _ = writeln!(
                &mut content,
                "<div class=\"card\"><h3>Detailed Hotspots</h3><ul>"
            );
            for hotspot in &security.security_hotspots {
                let _ = writeln!(&mut content, "<li><strong>{}</strong><br>Risk Score: {:.1}<br>Vulnerabilities: {} ({:?})<br>Description: {}</li>", super::util::html_escape(&hotspot.location.file.display().to_string()), hotspot.risk_score, hotspot.vulnerability_count, hotspot.severity, super::util::html_escape(&hotspot.description));
            }
            let _ = writeln!(&mut content, "</ul></div>");
        } else {
            let _ = writeln!(&mut content, "<div class=\"card\"><h3>No Security Hotspots Found</h3><p>Your codebase appears to be secure based on current analysis.</p></div>");
        }

        let _ = writeln!(&mut content, "</section></main></body></html>");
        std::fs::write(out.join("security_hotspots.html"), content).map_err(|e| e.into())
    }

    pub(super) fn generate_security_overview_block(
        &self,
        security: &super::security_enhancements::SecurityAnalysisResult,
    ) -> String {
        let mut block = String::new();
        let _ = writeln!(&mut block, "<div class=\"card\"><h2>Security Analysis</h2>");
        let _ = writeln!(
            &mut block,
            "<p><strong>Security Score:</strong> {} / 100</p>",
            security.security_result.security_score
        );
        let _ = writeln!(
            &mut block,
            "<p><strong>Total Vulnerabilities:</strong> {}</p>",
            security.security_result.total_vulnerabilities
        );
        if !security.security_hotspots.is_empty() {
            let _ = writeln!(
                &mut block,
                "<p><strong>High-Risk Files:</strong> {}</p>",
                security.security_hotspots.len()
            );
        }
        let _ = writeln!(
            &mut block,
            "<div class=\"mermaid\">{}</div>",
            super::security_enhancements::SecurityWikiGenerator::new()
                .unwrap()
                .generate_hotspot_diagram(
                    &security
                        .security_hotspots
                        .iter()
                        .take(5)
                        .cloned()
                        .collect::<Vec<_>>()
                )
        );
        let _ = writeln!(&mut block, "</div>");
        block
    }

    pub(super) fn write_file_page(
        &self,
        page_path: &Path,
        title: &str,
        description: &str,
        file: &crate::analyzer::FileInfo,
        root_path: &Path,
        security_block: &str,
        nav_content: &str,
        ai_block_html: &str,
    ) -> super::Result<()> {
        let mut rels = String::new();
        for sym in &file.symbols {
            let _ = writeln!(&mut rels, "  class {} {{}}", sym.name.replace(':', "_"));
        }

        let full_path = root_path.join(&file.path);
        let source = std::fs::read_to_string(&full_path).unwrap_or_default();
        let src_lines: Vec<&str> = source.lines().collect();

        let mut functions_html = String::new();
        let mut variables_html = String::new();
        let mut types_html = String::new();
        let mut count_functions = 0usize;
        let mut count_variables = 0usize;
        let mut count_types = 0usize;

        for sym in &file.symbols {
            let start = sym.start_line.saturating_sub(1);
            let end = sym.end_line.min(src_lines.len());
            let snippet = if start < end && end <= src_lines.len() {
                super::util::html_escape(&src_lines[start..end].join("\n"))
            } else {
                String::new()
            };

            let code_id = format!(
                "code-{}-{}",
                super::util::safe_ident(&sym.name),
                sym.start_line
            );
            let mut gutter = String::new();
            if start < end {
                for ln in sym.start_line..=sym.end_line {
                    let _ = writeln!(&mut gutter, "{}", ln);
                }
            }
            let abs_path = {
                let p = root_path.join(&file.path);
                std::fs::canonicalize(&p).unwrap_or(p)
            };
            let vscode_href = format!(
                "vscode://file/{}:{}",
                super::util::url_encode_path(&abs_path),
                sym.start_line
            );

            let item_html = format!(
                "<li id=\"symbol-{id}\"><code>{name}</code> <small>{kind}</small>{details}</li>",
                id = super::util::anchorize(&sym.name),
                name = super::util::html_escape(&sym.name),
                kind = super::util::html_escape(&sym.kind),
                details = if !snippet.is_empty() {
                    format!(
                        "\n<details><summary>View code ({start}-{end})</summary>\n<div class=\"codeblock\">\n  <div class=\"codeblock-header\">\n    <button class=\"copy-btn\" data-target=\"{code_id}\">Copy</button>\n    <a class=\"open-in-editor\" href=\"{vscode}\" title=\"Open in VS Code\">Open in VS Code</a>\n  </div>\n  <div class=\"codeblock-body\">\n    <pre class=\"gutter\">{gutter}</pre>\n    <pre><code id=\"{code_id}\" class=\"lang-{lang} hljs\">{snippet}</code></pre>\n  </div>\n</div>\n</details>",
                        start = sym.start_line,
                        end = sym.end_line,
                        lang = super::util::html_escape(&file.language.to_lowercase()),
                        snippet = snippet,
                        code_id = super::util::html_escape(&code_id),
                        gutter = super::util::html_escape(&gutter),
                        vscode = super::util::html_escape(&vscode_href),
                    )
                } else {
                    String::new()
                }
            );

            let kind_lower = sym.kind.to_lowercase();
            if kind_lower.contains("function")
                || kind_lower.contains("fn")
                || kind_lower.contains("method")
            {
                count_functions += 1;
                let _ = writeln!(&mut functions_html, "{}", item_html);
            } else if kind_lower.contains("variable")
                || kind_lower.contains("const")
                || kind_lower == "let"
            {
                count_variables += 1;
                let _ = writeln!(&mut variables_html, "{}", item_html);
            } else {
                count_types += 1;
                let _ = writeln!(&mut types_html, "{}", item_html);
            }
        }

        let mut sym_list = String::new();
        let _ = writeln!(&mut sym_list, "<details><summary><strong>Functions</strong> <small>({})</small></summary><ul>{}</ul></details>", count_functions, functions_html);
        let _ = writeln!(&mut sym_list, "<details><summary><strong>Variables</strong> <small>({})</small></summary><ul>{}</ul></details>", count_variables, variables_html);
        let _ = writeln!(&mut sym_list, "<details><summary><strong>Types & Structures</strong> <small>({})</small></summary><ul>{}</ul></details>", count_types, types_html);
        let diag_blocks = Self::build_sequence_or_flow_blocks(file, &rels, root_path);

        let ai_summary = format!(
            "<div class=\"card ai\" id=\"ai-summary\"><h3>AI Summary</h3>\n<p><strong>File:</strong> {file_path}<br><strong>Language:</strong> {lang}<br><strong>Lines:</strong> {lines}<br><strong>Symbols:</strong> {syms}<br><strong>Vulnerabilities:</strong> {vulns}</p></div>",
            file_path = super::util::html_escape(&file.path.display().to_string()),
            lang = super::util::html_escape(&file.language),
            lines = file.lines,
            syms = file.symbols.len(),
            vulns = file.security_vulnerabilities.len(),
        );

        let ai_commentary = if !ai_block_html.trim().is_empty() {
            format!("<details class=\\\"card\\\" id=\\\"ai-commentary\\\"><summary>AI Commentary</summary>{}</details>", ai_block_html)
        } else {
            String::new()
        };

        let has_cf = diag_blocks.contains("id=\"control-flow\"");
        let has_seq = diag_blocks.contains("id=\"call-sequence\"");
        let has_class = diag_blocks.contains("id=\"class-diagram\"");
        let symbols_block = format!("<details class=\\\"card\\\" id=\\\"symbols\\\"><summary>Symbols</summary>\n{}\n</details>", sym_list);
        let security_section = if !security_block.trim().is_empty() {
            format!("<details class=\\\"card\\\" id=\\\"security-analysis\\\"><summary>Security Analysis</summary>{}</details>", security_block)
        } else {
            String::new()
        };

        let mut toc_items: Vec<String> = Vec::new();
        toc_items.push("<li><a href=\\\"#ai-summary\\\">AI Summary</a></li>".to_string());
        if !ai_commentary.is_empty() {
            toc_items.push("<li><a href=\\\"#ai-commentary\\\">AI Commentary</a></li>".to_string());
        }
        if has_cf {
            toc_items.push("<li><a href=\\\"#control-flow\\\">Control Flow</a></li>".to_string());
        }
        if has_seq {
            toc_items.push("<li><a href=\\\"#call-sequence\\\">Call Sequence</a></li>".to_string());
        }
        if has_class {
            toc_items.push(
                "<li><a href=\\\"#class-diagram\\\">Class/Module Diagram</a></li>".to_string(),
            );
        }
        toc_items.push("<li><a href=\\\"#symbols\\\">Symbols</a></li>".to_string());
        if !security_section.is_empty() {
            toc_items.push(
                "<li><a href=\\\"#security-analysis\\\">Security Analysis</a></li>".to_string(),
            );
        }
        let toc_html = format!(
            "<div class=\\\"card\\\"><h3>Contents</h3><ul>{}</ul></div>",
            toc_items.join("\n")
        );

        // Breadcrumbs + editor link - simplified for debugging
        let abs_file_path = {
            let p = root_path.join(&file.path);
            std::fs::canonicalize(&p).unwrap_or(p)
        };
        let vscode_file_href = format!(
            "vscode://file/{}",
            super::util::url_encode_path(&abs_file_path)
        );

        // Simple breadcrumbs generation
        let breadcrumbs_html = {
            let mut br = String::new();
            let _ = write!(&mut br, "<nav class=\"breadcrumbs\">");
            let _ = write!(&mut br, "<a href=\"../index.html\">Home</a>");

            // Add file path components
            let parts: Vec<String> = file
                .path
                .components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect();

            if !parts.is_empty() {
                for (i, part) in parts.iter().enumerate() {
                    let _ = write!(&mut br, " <span class=\"sep\">/</span> ");
                    if i + 1 == parts.len() {
                        let _ = write!(
                            &mut br,
                            "<strong>{}</strong>",
                            super::util::html_escape(part)
                        );
                    } else {
                        let _ = write!(&mut br, "<span>{}</span>", super::util::html_escape(part));
                    }
                }
            }

            let _ = write!(&mut br, " <a class=\"open-in-editor right\" href=\"{}\" title=\"Open file in VS Code\">Open in VS Code</a>", super::util::html_escape(&vscode_file_href));
            let _ = write!(&mut br, "</nav>");

            br
        };

        // Build the HTML content by concatenating parts to avoid quote conflicts
        let mut content = String::new();
        content.push_str("<!doctype html>\n<html>\n<head>\n");
        content.push_str("<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
        content.push_str(&format!(
            "<title>{}</title>\n",
            super::util::html_escape(title)
        ));
        content.push_str("<link rel=\"stylesheet\" href=\"../assets/style.css\">\n");
        content.push_str("<link rel=\"stylesheet\" href=\"../assets/hljs.css\">\n");
        content.push_str("<script src=\"../assets/search_index.js\"></script>\n");
        content.push_str("<script src=\"../assets/search.js\"></script>\n");
        content.push_str("<script src=\"../assets/mermaid.js\"></script>\n");
        content.push_str("<script src=\"../assets/hljs.js\"></script>\n");
        content.push_str("<script src=\"../assets/main.js\"></script>\n");
        content.push_str("</head>\n<body>\n");
        content.push_str(&format!("<header><h1>{}</h1><div style=\"display:flex;gap:.5rem;align-items:center\"><button id=\"sidebarToggle\" class=\"sidebar-toggle\">Sidebar</button><button id=\"themeToggle\" class=\"theme-toggle\"></button></div></header>\n", super::util::html_escape(title)));
        content.push_str("<main>\n<nav>\n");
        // Escape nav_content to prevent HTML injection issues
        let escaped_nav = nav_content
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
        content.push_str(&escaped_nav);
        content.push_str("\n</nav>\n<section class=\"article\">\n");

        content.push_str(&breadcrumbs_html);
        content.push_str(&format!(
            "\n<p>{}</p>\n",
            super::util::html_escape(description)
        ));
        content.push_str(&ai_summary);
        content.push_str(&toc_html);
        content.push_str(&ai_commentary);
        content.push_str(&diag_blocks);
        content.push_str(&symbols_block);
        content.push_str(&security_section);
        content.push_str("\n</section>\n</main>\n</body>\n</html>");

        std::fs::write(page_path, content).map_err(|e| e.into())
    }
}
