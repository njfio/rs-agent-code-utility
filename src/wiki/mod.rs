//! Wiki site generator
//!
//! Generates a static, navigable documentation website from a codebase
//! using tree-sitter analysis results. It includes:
//! - AI-like documentation insights based on deterministic heuristics
//! - Mermaid diagrams (flowchart, class relationships, dependency overview)
//! - Search index and client-side search
//! - Cross-references between modules/files
//! - Security trace analysis and vulnerability visualization
//! - OWASP recommendations and security hotspot identification
//!
//! The API follows Result<T,E> patterns with comprehensive error handling
//! and uses a builder for configuration.

mod ai_integration;
mod ai_schema;
mod assets;
mod diagrams;
mod search;
pub mod security_enhancements;
mod templates;
mod util;

use self::search::SearchEntry;
use self::util::{html_escape, markdown_to_html, sanitize_filename};
use crate::analyzer::{AnalysisConfig, AnalysisDepth, AnalysisResult};
use crate::{CodebaseAnalyzer, Result};
use security_enhancements::SecurityWikiGenerator;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::{Path, PathBuf};

/// Configuration for wiki generation
#[derive(Debug, Clone)]
pub struct WikiConfig {
    /// Title for the site
    pub site_title: String,
    /// Output directory for generated site
    pub output_dir: PathBuf,
    /// Include API docs (per-file symbol listings)
    pub include_api_docs: bool,
    /// Include example snippets where available
    pub include_examples: bool,
    /// Enable AI-generated documentation
    pub ai_enabled: bool,
    /// Use mock AI providers (no network) for deterministic tests
    pub ai_use_mock: bool,
    /// Optional path to AI config file
    pub ai_config_path: Option<PathBuf>,
    /// Enable enhanced AI context and advanced documentation
    pub enhanced_ai_enabled: bool,
    /// Enable rich function documentation
    pub function_enhancement_enabled: bool,
    /// Enable security vulnerability explanations
    pub security_insights_enabled: bool,
    /// Enable refactoring suggestions
    pub refactoring_hints_enabled: bool,
    /// Enable diagram annotations
    pub diagram_annotations_enabled: bool,
    /// Enable performance analysis (placeholder for future implementation)
    pub performance_analysis_enabled: bool,
    /// AI provider to use for enhancement
    pub ai_provider: Option<String>,
    /// Request AI in JSON mode and render via schema
    pub ai_json_mode: bool,
    /// Maximum search results to display in UI
    pub search_max_results: usize,
    /// Cap number of symbols per file in search index
    pub max_index_symbols_per_file: Option<usize>,
    /// Optional external templates directory (reserved for future)
    pub templates_dir: Option<PathBuf>,
}

impl WikiConfig {
    /// Create a new builder
    pub fn builder() -> WikiConfigBuilder {
        WikiConfigBuilder::new()
    }
}

    /// Builder for WikiConfig (builder pattern)
#[derive(Debug, Default, Clone)]
pub struct WikiConfigBuilder {
    site_title: Option<String>,
    output_dir: Option<PathBuf>,
    include_api_docs: bool,
    include_examples: bool,
    ai_enabled: bool,
    ai_use_mock: bool,
    ai_config_path: Option<PathBuf>,
    enhanced_ai_enabled: bool,
    function_enhancement_enabled: bool,
    security_insights_enabled: bool,
    refactoring_hints_enabled: bool,
    diagram_annotations_enabled: bool,
    performance_analysis_enabled: bool,
    ai_provider: Option<String>,
    ai_json_mode: bool,
    search_max_results: Option<usize>,
    max_index_symbols_per_file: Option<usize>,
    templates_dir: Option<PathBuf>,
}

impl WikiConfigBuilder {
    /// Start a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set site title
    pub fn with_site_title(mut self, title: &str) -> Self {
        self.site_title = Some(title.to_string());
        self
    }
    /// Set output directory
    pub fn with_output_dir<P: AsRef<Path>>(mut self, out: P) -> Self {
        self.output_dir = Some(out.as_ref().to_path_buf());
        self
    }
    /// Toggle API docs
    pub fn include_api_docs(mut self, yes: bool) -> Self {
        self.include_api_docs = yes;
        self
    }
    /// Toggle examples
    pub fn include_examples(mut self, yes: bool) -> Self {
        self.include_examples = yes;
        self
    }
    /// Enable AI-generated content
    pub fn with_ai_enabled(mut self, yes: bool) -> Self {
        self.ai_enabled = yes;
        self
    }
    /// Use mock AI providers (offline)
    pub fn with_ai_mock(mut self, yes: bool) -> Self {
        self.ai_use_mock = yes;
        self
    }
    /// Path to AI config file
    pub fn with_ai_config_path<P: AsRef<Path>>(mut self, p: P) -> Self {
        self.ai_config_path = Some(p.as_ref().to_path_buf());
        self
    }

    /// Enable enhanced AI context and advanced documentation
    pub fn with_enhanced_ai(mut self, yes: bool) -> Self {
        self.enhanced_ai_enabled = yes;
        self
    }
    /// Enable rich function documentation
    pub fn with_function_enhancement(mut self, yes: bool) -> Self {
        self.function_enhancement_enabled = yes;
        self
    }
    /// Enable security vulnerability explanations
    pub fn with_security_insights(mut self, yes: bool) -> Self {
        self.security_insights_enabled = yes;
        self
    }
    /// Enable refactoring suggestions
    pub fn with_refactoring_hints(mut self, yes: bool) -> Self {
        self.refactoring_hints_enabled = yes;
        self
    }
    /// Enable diagram annotations
    pub fn with_diagram_annotations(mut self, yes: bool) -> Self {
        self.diagram_annotations_enabled = yes;
        self
    }
    /// Set AI provider for enhancement
    pub fn with_ai_provider(mut self, provider: &str) -> Self {
        self.ai_provider = Some(provider.to_string());
        self
    }
    /// Enable AI JSON mode (Groq/OpenAI JSON responses)
    pub fn with_ai_json(mut self, yes: bool) -> Self {
        self.ai_json_mode = yes;
        self
    }

    /// Set maximum search results shown in UI (default: 200)
    pub fn with_search_max_results(mut self, n: usize) -> Self {
        self.search_max_results = Some(n);
        self
    }
    /// Cap number of indexed symbols per file for search index
    pub fn with_max_index_symbols(mut self, n: usize) -> Self {
        self.max_index_symbols_per_file = Some(n);
        self
    }
    /// Provide an external templates directory (reserved)
    pub fn with_templates_dir<P: AsRef<Path>>(mut self, p: P) -> Self {
        self.templates_dir = Some(p.as_ref().to_path_buf());
        self
    }

    /// Enable performance analysis
    pub fn with_performance_analysis(mut self, yes: bool) -> Self {
        self.performance_analysis_enabled = yes;
        self
    }

    /// Build final config
    pub fn build(self) -> Result<WikiConfig> {
        Ok(WikiConfig {
            site_title: self.site_title.unwrap_or_else(|| "Code Wiki".to_string()),
            output_dir: self
                .output_dir
                .ok_or_else(|| crate::error::Error::InvalidInput {
                    details: crate::error::InvalidInputDetails {
                        input_type: "WikiConfig".to_string(),
                        expected: "output_dir set".to_string(),
                        actual: "None".to_string(),
                        suggestion: Some("Provide a writable output directory".to_string()),
                    },
                })?,
            include_api_docs: self.include_api_docs,
            include_examples: self.include_examples,
            ai_enabled: self.ai_enabled,
            ai_use_mock: self.ai_use_mock,
            ai_config_path: self.ai_config_path,
            enhanced_ai_enabled: self.enhanced_ai_enabled,
            function_enhancement_enabled: self.function_enhancement_enabled,
            security_insights_enabled: self.security_insights_enabled,
            refactoring_hints_enabled: self.refactoring_hints_enabled,
            diagram_annotations_enabled: self.diagram_annotations_enabled,
            performance_analysis_enabled: self.performance_analysis_enabled,
            ai_provider: self.ai_provider,
            ai_json_mode: self.ai_json_mode,
            search_max_results: self.search_max_results.unwrap_or(200),
            max_index_symbols_per_file: self.max_index_symbols_per_file,
            templates_dir: self.templates_dir,
        })
    }
}

/// Result summary for wiki generation
#[derive(Debug, Clone, Default)]
pub struct WikiGenerationResult {
    /// Number of pages generated
    pub pages: usize,
}

#[derive(serde::Serialize)]
struct SearchEntry {
    title: String,
    path: String,
    description: String,
    symbols: Vec<String>,
    language: String,
    file_type: String,
    security_level: String,
}

/// Wiki site generator
pub struct WikiGenerator {
    config: WikiConfig,
    ai_rt: std::cell::RefCell<Option<tokio::runtime::Runtime>>,
    ai_service: std::cell::RefCell<Option<crate::ai::service::AIService>>,
}

impl Clone for WikiGenerator {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            ai_rt: std::cell::RefCell::new(None),
            ai_service: std::cell::RefCell::new(None),
        }
    }
}

impl WikiGenerator {
    fn project_snapshot_md(analysis: &AnalysisResult) -> String {
        use std::collections::HashMap;
        // Language distribution
        let mut langs: Vec<(String, usize)> = analysis
            .languages
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        langs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        // Directory breakdown (top-level folder counts)
        let mut dirs: HashMap<String, usize> = HashMap::new();
        let root = &analysis.root_path;
        for f in &analysis.files {
            let rel = if f.path.is_absolute() {
                f.path.strip_prefix(root).unwrap_or(&f.path)
            } else {
                &f.path
            };
            let top = rel
                .components()
                .next()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .unwrap_or_else(|| ".".to_string());
            *dirs.entry(top).or_insert(0) += 1;
        }
        let mut dirs_vec: Vec<(String, usize)> = dirs.into_iter().collect();
        dirs_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let examples_count = dirs_vec
            .iter()
            .find(|(d, _)| d == "examples")
            .map(|x| x.1)
            .unwrap_or(0);
        let src_count = dirs_vec
            .iter()
            .find(|(d, _)| d == "src")
            .map(|x| x.1)
            .unwrap_or(0);

        let mut md = String::new();
        use std::fmt::Write as _;
        let _ = writeln!(&mut md, "- Files: {}", analysis.total_files);
        let _ = writeln!(&mut md, "- Lines: {}", analysis.total_lines);
        if !langs.is_empty() {
            let parts: Vec<String> = langs
                .iter()
                .map(|(l, c)| format!("{} ({} files)", l, c))
                .collect();
            let _ = writeln!(&mut md, "- Languages: {}", parts.join(", "));
        }

        // Top directories table
        if !dirs_vec.is_empty() {
            let _ = writeln!(&mut md, "\n| Directory | Files |\n|---|---|");
            for (d, c) in dirs_vec.iter().take(10) {
                let _ = writeln!(&mut md, "| {} | {} |", d, c);
            }
        }

        // Entry points
        let has_main = analysis.files.iter().any(|f| {
            let s = f.path.display().to_string();
            s.ends_with("src/main.rs") || s.contains("/bin/")
        });
        let _ = writeln!(
            &mut md,
            "\n- Entry points: {}",
            if has_main {
                "src/main.rs or src/bin/*"
            } else {
                "Not detected from analyzed files"
            }
        );

        // Examples vs src context for clarity without speculation
        let _ = writeln!(
            &mut md,
            "- Content distribution: src={} files, examples={} files",
            src_count, examples_count
        );

        md
    }

    // parse_ai_json moved to ai_integration.rs
    /// Create a new generator
    pub fn new(config: WikiConfig) -> Self {
        Self {
            config,
            ai_rt: std::cell::RefCell::new(None),
            ai_service: std::cell::RefCell::new(None),
        }
    }

    /// Ensure a single AI runtime and service are built and available
    fn ensure_ai(&self) -> Result<()> {
        // Initialize runtime once
        if self.ai_rt.borrow().is_none() {
            let rt = tokio::runtime::Runtime::new().map_err(|e| crate::error::Error::Internal {
                component: "wiki".to_string(),
                message: format!("tokio: {}", e),
                context: None,
            })?;
            *self.ai_rt.borrow_mut() = Some(rt);
        }
        // Initialize service once using the runtime
        if self.ai_service.borrow().is_none() {
            let builder = self.make_ai_builder();
            let service = self
                .ai_rt
                .borrow()
                .as_ref()
                .expect("runtime just initialized")
                .block_on(async { builder.build().await })
                .map_err(|e| crate::error::Error::Internal {
                    component: "wiki".to_string(),
                    message: format!("ai build: {}", e),
                    context: None,
                })?;
            *self.ai_service.borrow_mut() = Some(service);
        }
        Ok(())
    }

    /// Generate the wiki site from a path (file or directory)
    pub fn generate_from_path<P: AsRef<Path>>(&self, path: P) -> Result<WikiGenerationResult> {
        let root = path.as_ref();
        let analysis = self.analyze(root)?;
        self.generate_site(&analysis)
    }

    fn analyze(&self, root: &Path) -> Result<AnalysisResult> {
        // Build analysis config and exclude generated wiki directories to avoid self-scanning
        let mut cfg = AnalysisConfig {
            depth: AnalysisDepth::Full,
            ..AnalysisConfig::default()
        };
        // Always exclude the configured output directory name
        if let Some(name) = self.config.output_dir.file_name().and_then(|s| s.to_str()) {
            cfg.exclude_dirs.push(name.to_string());
        }
        // Also exclude any sibling directories under root that look like previous wiki outputs (wiki_site*)
        if root.is_dir() {
            if let Ok(entries) = std::fs::read_dir(root) {
                for e in entries.flatten() {
                    if let Some(fname) = e.file_name().to_str() {
                        if fname.starts_with("wiki_site") {
                            cfg.exclude_dirs.push(fname.to_string());
                        }
                    }
                }
            }
        }
        let mut analyzer = CodebaseAnalyzer::with_config(cfg)?;
        analyzer.analyze_directory(root)
    }

    fn generate_site(&self, analysis: &AnalysisResult) -> Result<WikiGenerationResult> {
        // Ensure directories
        let out = &self.config.output_dir;
        let assets = out.join("assets");
        let pages = out.join("pages");
        fs::create_dir_all(&assets)?;
        fs::create_dir_all(&pages)?;

        // Assets
        self.write_style_css_impl(&assets.join("style.css"))?;
        self.write_search_js_impl(&assets.join("search.js"))?;
        // Bundle local syntax highlighting assets (with graceful fallback)
        self.write_highlight_assets_impl(&assets)?;
        // Provide local Mermaid asset (attempt network fetch; fallback to stub)
        self.write_mermaid_asset_impl(&assets)?;
        // Provide main page behavior JS
        self.write_main_js_impl(&assets.join("main.js"))?;

        // Initialize AI enhancer placeholder - to be implemented when enhanced AI module is ready
        let ai_enhancer: Option<String> = if self.config.enhanced_ai_enabled {
            Some("enhanced_ai_enabled".to_string())
        } else {
            None
        };
        // For now, use simple heuristics for AI enhancement

        // Initialize security analysis if enabled
        let security_analysis = if self.config.security_insights_enabled {
            // Create security wiki generator
            let security_config = crate::wiki::security_enhancements::SecurityWikiConfig {
                enable_trace_analysis: true,
                enable_propagation_diagrams: self.config.diagram_annotations_enabled,
                enable_owasp_recommendations: true,
                enable_hotspot_visualization: true,
                min_hotspot_severity: crate::advanced_security::SecuritySeverity::Medium,
            };

            let security_generator = SecurityWikiGenerator::new_with_config(security_config)?;
            Some(security_generator.analyze_security(analysis)?)
        } else {
            None
        };

        // Generate AI-enhanced relationship map across all files
        let relationship_map = self.generate_relationship_map_simple(analysis);

        // Performance analysis placeholder - to be implemented when performance_analysis module is available
        let _performance_analysis_enabled = self.config.performance_analysis_enabled;

        // Pages and search index
        let mut page_count = 0usize;
        let mut index_entries: Vec<SearchEntry> = Vec::new();

        // Build sidebar content with correct link prefixes for index and file pages
        let nav_index = self.build_sidebar_with_search(analysis, &security_analysis, "pages/");
        let nav_pages = self.build_sidebar_with_search(analysis, &security_analysis, "");

        // Index.html
        self.write_index_html(out, analysis, &security_analysis, &nav_index)?;
        page_count += 1;

        // Security overview page if security analysis is enabled
        if let Some(ref security) = security_analysis {
            self.write_security_overview_page(out, security)?;
            page_count += 1;
        }

        // Per-file pages
        for file in &analysis.files {
            let safe_name = sanitize_filename(&file.path);
            let page_path = pages.join(format!("{}.html", safe_name));

            let title = format!("{}", file.path.display());
            let desc = format!("{} symbols, {} lines", file.symbols.len(), file.lines);

            // Generate security enhancements for this file if enabled
            let security_block = if let Some(ref security) = security_analysis {
                // Find this file in security hotspots
                let file_hotspots: Vec<_> = security
                    .security_hotspots
                    .iter()
                    .filter(|h| h.location.file == file.path)
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };

            // Determine additional fields for search filters
            let language = file.language.clone();
            let file_type = file.path.extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("file")
                .to_string();
            let security_level = if file_hotspots.is_empty() {
                "low".to_string()
            } else if file_hotspots.iter().any(|h| h.severity == crate::advanced_security::SecuritySeverity::Critical) {
                "critical".to_string()
            } else if file_hotspots.iter().any(|h| h.severity == crate::advanced_security::SecuritySeverity::High) {
                "high".to_string()
            } else {
                "medium".to_string()
            };

            // Generate security enhancements for this file if enabled
            let security_block = if let Some(ref security) = security_analysis {
                // Generate OWASP recommendations for this file
                let owasp_rec = if self.config.security_insights_enabled {
                    let temp_generator = SecurityWikiGenerator::new()?;
                    temp_generator.generate_owasp_recommendations(file)
                } else {
                    String::new()
                };

                // Create security block
                self.generate_file_security_block(file, &file_hotspots, &owasp_rec)
            } else {
                String::new()
            };

            // Generate AI block early so we can also capture tags for search index
            let (ai_block_html, ai_tags) = if self.config.ai_enabled {
                self.generate_file_ai_block_and_tags(file)
            } else {
                (String::new(), Vec::new())
            };

            self.write_file_page(
                &page_path,
                &title,
                &desc,
                file,
                &analysis.root_path,
                &security_block,
                &nav_pages,
                &ai_block_html,
            )?;
            page_count += 1;

            // Add to search index (with anchors for first symbol if present)
            let anchor = file
                .symbols
                .get(0)
                .map(|s| format!("#symbol-{}", Self::anchorize(&s.name)))
                .unwrap_or_default();
            let mut tags = vec![file.language.clone()];
            if !file.security_vulnerabilities.is_empty() {
                tags.push("vulnerable".to_string());
            }
            for t in ai_tags {
                if !t.is_empty() {
                    tags.push(t);
                }
            }
            // Apply per-file symbol indexing cap if configured
            let symbol_cap = self
                .config
                .max_index_symbols_per_file
                .unwrap_or_else(|| file.symbols.len());
            index_entries.push(SearchEntry {
                title: title.clone(),
                path: format!("pages/{}.html{}", safe_name, anchor),
                description: desc,
                symbols: file
                    .symbols
                    .iter()
                    .take(symbol_cap)
                    .map(|s| s.name.clone())
                    .collect(),
                language: file.language.clone(),
                kinds: file
                    .symbols
                    .iter()
                    .take(symbol_cap)
                    .map(|s| s.kind.clone())
                    .collect(),
                tags,
            });
        }

        // Global symbols page
        self.write_global_symbols(out, &analysis.files)?;
        page_count += 1;

        // Security hotspots page if security analysis is enabled
        if let Some(ref security) = security_analysis {
            self.write_security_hotspots_page(out, security)?;
            page_count += 1;
        }

        // Write search index JSON
        self.write_search_index(&assets.join("search_index.json"), &index_entries)?;

        // Post-process generated HTML to replace any residual CDN references in display-only code
        self.postprocess_cdn_refs_impl(out)?;

        Ok(WikiGenerationResult { pages: page_count })
    }

    // Add other methods here as needed...
    /* legacy asset writers removed (moved to assets.rs)
        fn write_style_css(&self, path: &Path) -> Result<()> {
            let css = r#":root{--bg:#0b0f17;--fg:#e6e9ef;--muted:#9aa4b2;--accent:#7aa2f7;--card:#111826;--security-critical:#ef4444;--security-high:#f97316;--security-medium:#eab308;--security-low:#22c55e;--security-info:#6b7280}
    html{scroll-behavior:smooth}
    body{background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;margin:0;line-height:1.55;font-size:15px}
    /* Improve readability for general text */
p{margin:.6rem 0}
    /* Add comfortable spacing for lists in article content */
.article ul,.article ol{margin:.5rem 0 .75rem 1.25rem;padding-left:1.25rem}
.article li{margin:.35rem 0}
    /* Ensure consecutive list items have breathing room even without margins */
.article li+li{margin-top:.35rem}
header{background:#0d1320;border-bottom:1px solid #1f2937;padding:.75rem 1.25rem;position:sticky;top:0;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:1rem}
[data-theme=light] header{background:#ffffff;border-bottom:1px solid #e2e8f0}
main{display:flex}
nav{width:260px;height:100vh;overflow:auto;background:#0d1524;border-right:1px solid #1f2937;padding:1rem;position:sticky;top:0}
[data-theme=light] nav{background:#f1f5f9;border-right:1px solid #e2e8f0}
nav a{display:block;color:#e6e9ef;text-decoration:none;padding:.35rem 0;border-radius:4px;transition:all 0.2s ease;line-height:1.35}
nav a:hover{color:#ffffff;background:#1e2530;text-decoration:underline}
[data-theme=light] nav a{color:#0f172a}
[data-theme=light] nav a:hover{color:#111827;background:#e5e7eb}
nav a:focus{outline:2px solid #334155}
    /* Global link styling for readability on dark bg */
a{color:#e6e9ef;text-decoration:underline}
a:hover{color:#ffffff}
.article a{color:#e6e9ef;text-decoration:underline;border-radius:3px;transition:all 0.2s ease}
.article a:hover{color:#ffffff;background:#1e2530;padding:0.1rem 0.3rem}
[data-theme=light] a,[data-theme=light] .article a,[data-theme=light] pre a,[data-theme=light] code a{color:#0f172a}
[data-theme=light] a:hover,[data-theme=light] .article a:hover{color:#111827;background:#e5e7eb}
pre a,code a{color:#e6e9ef;text-decoration:none;border-radius:2px}
pre a:hover,code a:hover{color:#9aa4b2;background:rgba(122,162,247,0.1);padding:0 2px}
    /* Ensure visited links remain readable */
nav a:visited{color:#e6e9ef}
.article a:visited{color:#e6e9ef}
pre a:visited,code a:visited{color:#e6e9ef}
nav hr{border-color:#334155;margin:1rem 0}
nav h4{margin:.5rem 0;margin-top:1rem;font-size:.9em;color:var(--accent)}
.article{flex:1;padding:1.5rem;max-width:1100px}
.article h1,.article h2,.article h3{margin:.2rem 0 .6rem}
.card{background:var(--card);border:1px solid #1f2937;border-radius:10px;padding:1rem 1.1rem;margin:.85rem 0;box-shadow:0 1px 2px rgba(0,0,0,0.25)}
    /* AI insights card styling */
.card.ai{border-color:rgba(122,162,247,0.6);box-shadow:0 0 0 1px rgba(122,162,247,0.15) inset, 0 6px 24px rgba(0,0,0,0.25)}
.card.ai h3{color:var(--accent);margin-top:0}
    /* Collapsible sections */
details.card{border-radius:10px}
details.card>summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:.5rem;font-weight:600}
details.card>summary::-webkit-details-marker{display:none}
details.card[open]{box-shadow:0 1px 2px rgba(0,0,0,0.25)}

    /* Sidebar collapse */
.sidebar-toggle{margin-left:auto;background:#1e2530;color:#e6e9ef;border:1px solid #334155;border-radius:6px;padding:.35rem .6rem;cursor:pointer}
[data-theme=light] .sidebar-toggle{background:#e5e7eb;color:#0f172a;border-color:#cbd5e1}
.sidebar-collapsed nav{display:none}
.sidebar-collapsed .article{max-width:min(1300px,95vw)}

    /* Sidebar tree */
nav details{margin:.25rem 0}
nav details>summary{cursor:pointer;color:#9aa4b2}
nav details a{padding-left:.75rem}
nav .folder{font-weight:600;color:#9aa4b2}
pre{background:#0a1220;border:1px solid #1f2937;border-radius:8px;padding:.8rem;overflow:auto}
.mermaid{background:#0a1220;border:1px solid #1f2937;border-radius:8px;padding:.6rem;margin:.75rem 0;overflow:auto}
[data-theme=light] pre,[data-theme=light] .mermaid{background:#f8fafc;border-color:#e2e8f0}
    /* Small helper text above diagrams */
.diagram-help{font-size:.9em;color:var(--muted);margin:.25rem 0 .5rem}
.diagram-help code{background:transparent;color:var(--muted);padding:0}
input.search{width:100%;padding:.5rem .75rem;border-radius:6px;border:1px solid #334155;background:#0a1220;color:var(--fg)}
[data-theme=light] input.search{background:#ffffff;border-color:#e2e8f0}
#results li{margin:.3rem 0}
#results a{display:block}

    /* Theme toggle button */
.theme-toggle{background:#1e2530;color:#e6e9ef;border:1px solid #334155;border-radius:8px;padding:.3rem .6rem;font-size:.85em;cursor:pointer}
.theme-toggle:hover{background:#2a3340}
[data-theme=light] .theme-toggle{background:#e5e7eb;color:#111827;border-color:#cbd5e1}

    /* Codeblock with gutter and actions */
.codeblock{background:#0a1220;border:1px solid #1f2937;border-radius:8px;margin:.6rem 0}
.codeblock-header{display:flex;gap:.5rem;align-items:center;justify-content:flex-end;border-bottom:1px solid #1f2937;padding:.25rem .5rem}
.copy-btn{background:#1e2530;color:#e6e9ef;border:1px solid #334155;border-radius:6px;font-size:.85em;padding:.25rem .6rem;cursor:pointer}
.copy-btn:hover{background:#2a3340}
.open-in-editor{font-size:.85em;color:var(--accent)}
.codeblock-body{display:grid;grid-template-columns:auto 1fr}
pre.gutter{margin:0;padding:.75rem .5rem;border-right:1px solid #1f2937;color:#9aa4b2;text-align:right;min-width:3ch}
.codeblock-body pre{margin:0;padding:.75rem}

    /* Security-specific styles */
.security-score{color:var(--accent);font-size:2em;font-weight:bold}
.security-critical{color:var(--security-critical)}
.security-high{color:var(--security-high)}
.security-medium{color:var(--security-medium)}
.security-low{color:var(--security-low)}
.security-info{color:var(--security-info)}

.security-vulnerability{background:#1f1826;border-left:4px solid var(--security-critical);padding:1rem;margin:.5rem 0}
.security-hotspot{background:#1e2530;border-left:4px solid var(--security-high);padding:1rem;margin:.5rem 0}

.vulnerability-count{background:#dc2626;color:white;padding:.25rem .5rem;border-radius:4px;font-size:.8em}
.risk-score{background:#ea580c;color:white;padding:.25rem .5rem;border-radius:4px;font-size:.8em}

.owasp-category{background:#2563eb;color:white;padding:.25rem .5rem;border-radius:4px;display:inline-block;margin:.25rem}
.owasp-a01{background:#7c2d12;color:white}
.owasp-a02{background:#dc2626;color:white}
.owasp-a03{background:#ea580c;color:white}
.owasp-a04{background:#ca8a04;color:white}
.owasp-a05{background:#65a30d;color:white}

.trace-path{background:#181a25;border:1px solid #374151;border-radius:6px;padding:.75rem;margin:.5rem 0}
.trace-node{background:#2d3748;color:#fbbf24;border:1px solid #4b5563;padding:.25rem .5rem;border-radius:4px;display:inline-block;margin:.1rem}

.security-hotspot-diagram-node{stroke:#f97316;fill:#f97316}
.security-trace-flow{stroke:#ef4444;stroke-width:3}
"#;

        let mut enhanced_css = css.to_string();

        // Add dynamic CSS for security hotspot severity colors
        if self.config.security_insights_enabled {
            enhanced_css.push_str(
                r#"
    /* Dynamic security styles */
.severity-critical{background:#dc2626;color:white;padding:.2rem .5rem;border-radius:4px}
.severity-high{background:#ea580c;color:white;padding:.2rem .5rem;border-radius:4px}
.severity-medium{background:#eab308;color:#1f2937;padding:.2rem .5rem;border-radius:4px}
.severity-low{background:#22c55e;color:white;padding:.2rem .5rem;border-radius:4px}
.severity-info{background:#6b7280;color:white;padding:.2rem .5rem;border-radius:4px}"#
            );
        }

        // Typography and layout enhancements (overrides)
        enhanced_css.push_str(
            r#"
    /* Typography enhancements */
body{font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
.article h1{font-size:1.875rem;line-height:1.2;margin:.5rem 0 .8rem}
.article h2{font-size:1.35rem;line-height:1.3;margin:.75rem 0 .6rem}
.article h3{font-size:1.1rem;line-height:1.3;margin:.6rem 0 .4rem;color:#cbd5e1}
.article h4{font-size:1rem;margin:.4rem 0 .3rem;color:#a8b1c5}
.card h3{margin-top:0}
.toc{margin:.6rem 0}
.toc ul{margin:.25rem 0 .25rem 1rem}
.toc li{margin:.25rem 0}
nav{width:270px}
"#
        );

        fs::write(path, enhanced_css).map_err(|e| e.into())
    }

    fn postprocess_cdn_refs(&self, out: &Path) -> Result<()> {
        fn process_dir(dir: &Path) -> std::io::Result<()> {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() { process_dir(&path)?; continue; }
                if let Some(ext) = path.extension() { if ext == "html" {
                    if let Ok(mut content) = std::fs::read_to_string(&path) {
    let mut replaced = content.replace("https: //cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js", "assets/mermaid.js");
                        replaced = replaced.replace("https://cdn.jsdelivr.net/npm/mermaid", "assets/mermaid.js");
                        replaced = replaced.replace("https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js", "assets/hljs.js");
                        replaced = replaced.replace("https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css", "assets/hljs.css");
                        replaced = replaced.replace("https://cdnjs.cloudflare.com/ajax/libs/highlight.js/", "assets/");
                        if replaced != content { let _ = std::fs::write(&path, replaced); }
                    }
                }}
            }
            Ok(())
        }
        process_dir(out).map_err(|e| e.into())
    }

    fn write_search_js(&self, path: &Path) -> Result<()> {
        let js = r#"function runSearch(){
  // Use embedded search index if present to avoid file:// CORS
  let idx = (typeof window !== 'undefined' && window.SEARCH_INDEX) ? window.SEARCH_INDEX : [];
  // Resolve asset base path relative to current page
  const isFile = (typeof location !== 'undefined' && location.protocol === 'file:');
  const base = (typeof location !== 'undefined' && location.pathname && location.pathname.indexOf('/pages/') !== -1) ? '../assets' : 'assets';
  const jsonUrl = base + '/search_index.json';
  // Fallback: attempt to fetch JSON if embedded index missing (best effort)
  async function tryLoadJson(){
    try {
      if (!idx || idx.length === 0) {
        if (!isFile) {
          const r = await fetch(jsonUrl);
          if (r.ok) { idx = await r.json(); }
        }
      }
    } catch (_) { /* ignore for file:// and fetch errors */ }
  }
  const q = document.getElementById('q');
  const list = document.getElementById('results');
  const langFilter = document.getElementById('langFilter');
  const kindFilter = document.getElementById('kindFilter');
  const vulnOnly = document.getElementById('vulnOnly');

  // Populate language filter
  if (langFilter && langFilter.options.length <= 1) {
    const langs = Array.from(new Set(idx.map(it => it.language))).sort();
    for (const l of langs) { const o=document.createElement('option'); o.value=l; o.textContent=l; langFilter.appendChild(o); }
  }
  // Populate kind filter
  if (kindFilter && kindFilter.options.length <= 1) {
    const kinds = Array.from(new Set(idx.flatMap(it => it.kinds))).sort();
    for (const k of kinds) { const o=document.createElement('option'); o.value=k; o.textContent=k; kindFilter.appendChild(o); }
  }

  function scoreItem(it, term){
    if (!term) return 0;
    const t = term.toLowerCase();
    let s = 0;
    if (it.title.toLowerCase().includes(t)) s += 3;
    if (it.description.toLowerCase().includes(t)) s += 1;
    if (it.symbols.some(sym => sym.toLowerCase().includes(t))) s += 2;
    return s;
  }

  function passFilters(it){
    const lang = langFilter ? langFilter.value : '';
    if (lang && it.language !== lang) return false;
    const kind = kindFilter ? kindFilter.value : '';
    if (kind && !it.kinds.includes(kind)) return false;
    if (vulnOnly && vulnOnly.checked && !(it.tags||[]).includes('vulnerable')) return false;
    return true;
  }

  function render(items){
    if (!list) return;
    list.innerHTML='';
    for (const it of items){
      const li=document.createElement('li');
      const a=document.createElement('a');
      const pageBase = (typeof location !== 'undefined' && location.pathname && location.pathname.indexOf('/pages/') !== -1) ? '../' : '';
      a.href = pageBase + it.path; a.textContent=it.title; li.appendChild(a);
      const small=document.createElement('small'); small.style.display='block'; small.style.color='#9aa4b2'; small.textContent=`${it.language} • ${it.symbols.length} symbols`; li.appendChild(small);
      list.appendChild(li);
    }
  }

  async function update(){
    await tryLoadJson();
    const term = q ? q.value.trim() : '';
    let items = idx.filter(passFilters);
    if (term){ items = items.map(it => ({it, sc: scoreItem(it, term)})).filter(x => x.sc>0).sort((a,b)=>b.sc-a.sc).map(x=>x.it); }
    render(items.slice(0, 200));
  }

  if (q) q.addEventListener('input', update);
  if (langFilter) langFilter.addEventListener('change', update);
  if (kindFilter) kindFilter.addEventListener('change', update);
  if (vulnOnly) vulnOnly.addEventListener('change', update);
  update();
}

function render(items){ list.innerHTML=''; items.forEach(it=>{ const li=document.createElement('li'); const a=document.createElement('a'); a.href=it.path; a.textContent=it.title; li.appendChild(a); list.appendChild(li); }); }

// Populate filter options
function populateFilters() {
if (!languageFilter || !fileTypeFilter || !securityLevelFilter) return;

const languages = getUniqueValues('language');
const fileTypes = getUniqueValues('file_type');
const securityLevels = getUniqueValues('security_level');

// Clear existing options except "All"
const clearOptions = (select, addOptions) => {
  while (select.options.length > 0) { select.options.remove(0); }
  const allOption = new Option('All', '');
  select.appendChild(allOption);
  addOptions.forEach(val => select.appendChild(new Option(val, val)));
};

clearOptions(languageFilter, languages);
clearOptions(fileTypeFilter, fileTypes);
clearOptions(securityLevelFilter, securityLevels);
}

function updateSearch() {
const term = q.value.toLowerCase();
const filters = getFilterValues();
let items = idx.filter(it=> it.title.toLowerCase().includes(term) || it.description.toLowerCase().includes(term) || it.symbols.some(s=>s.toLowerCase().includes(term)) );
items = filterItems(items, filters);
render(items);
}

q.addEventListener('input', updateSearch);
if (languageFilter) languageFilter.addEventListener('change', updateSearch);
if (fileTypeFilter) fileTypeFilter.addEventListener('change', updateSearch);
if (securityLevelFilter) securityLevelFilter.addEventListener('change', updateSearch);

window.addEventListener('DOMContentLoaded', () => {
populateFilters();
updateSearch();
});
}"#;
        fs::write(path, js).map_err(|e| e.into())
    }

    fn write_highlight_assets(&self, assets_dir: &Path) -> Result<()> {
        let js_path = assets_dir.join("hljs.js");
        let css_path = assets_dir.join("hljs.css");

    // Always ensure we have at least a minimal stub to avoid 404s
        let js_stub = "window.hljs = window.hljs || { highlightAll: function(){ try { document.querySelectorAll('pre code').forEach(function(el){ el.classList.add('hljs'); }); } catch(e){} } };";
        let css_stub = ".hljs{background:#0a1220;color:#e6e9ef}.hljs-keyword,.hljs-literal,.hljs-built_in{color:#7aa2f7}.hljs-string{color:#a6e3a1}.hljs-comment{color:#9aa4b2}.hljs-number{color:#f78c6c}";
        if !js_path.exists() { let _ = fs::write(&js_path, js_stub); }
        if !css_path.exists() { let _ = fs::write(&css_path, css_stub); }

    // Try to download real assets; ignore failures (offline environments)
        let js_url = "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js";
        let css_url = "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css";

    // Use tokio + reqwest if available (default features include net)
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            let fetch = async move {
                let client = reqwest::Client::new();
                let js_resp = client.get(js_url).send().await;
                if let Ok(resp) = js_resp { if resp.status().is_success() { if let Ok(text) = resp.text().await { let _ = fs::write(&js_path, text); } } }
                let css_resp = client.get(css_url).send().await;
                if let Ok(resp) = css_resp { if resp.status().is_success() { if let Ok(text) = resp.text().await { let _ = fs::write(&css_path, text); } } }
            };
            let _ = rt.block_on(fetch);
        }

        Ok(())
    }

    fn write_mermaid_asset(&self, assets_dir: &Path) -> Result<()> {
        let path = assets_dir.join("mermaid.js");
    // Minimal stub that attempts to load the real library when served over http(s)
        let stub = r#"(function(){
  function ensureRealMermaid(){
    try {
      if (window.mermaid && window.mermaid.parse && window.mermaid.initialize) return;
      if (typeof document === 'undefined') return;
      if (location && (location.protocol === 'http:' || location.protocol === 'https:')){
        var s=document.createElement('script');
        s.src='https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js';
        s.async=true; document.head.appendChild(s);
      }
    } catch(_){}
  }
  window.mermaid = window.mermaid || { initialize:function(){}, init:function(){}, parse:function(){}, render:function(){} };
  ensureRealMermaid();
})();"#;
        if !path.exists() { let _ = fs::write(&path, stub); }

    // Try to download the real library; ignore failures
        let url = "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js";
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            let fetch = async move {
                let client = reqwest::Client::new();
                if let Ok(resp) = client.get(url).send().await {
                    if resp.status().is_success() {
                        if let Ok(text) = resp.text().await { let _ = fs::write(&path, text); }
                    }
                }
            };
            let _ = rt.block_on(fetch);
        }

        Ok(())
    }

    */
    /* moved to templates.rs
        fn write_index_html(&self, out: &Path, analysis: &AnalysisResult, security_analysis: &Option<security_enhancements::SecurityAnalysisResult>, nav_content: &str) -> Result<()> {

            let ai_block = if self.config.ai_enabled {
                self.generate_project_ai_block(analysis)
                    .unwrap_or_else(|_| "<div class=\"card ai\"><h3>AI Commentary</h3><p>AI generation failed. Showing defaults.</p></div>".to_string())
            } else {
                "<div class=\"card ai\"><h3>AI Commentary</h3><p>Enable AI to generate rich documentation.</p></div>".to_string()
            };

            // Add security overview if available (collapsible)
            let security_block = if let Some(ref security) = security_analysis {
                let inner = self.generate_security_overview_block(security);
                format!("<details class=\"card\" id=\"security-overview\"><summary>Security Overview</summary>{}</details>", inner)
            } else {
                String::new()
            };

            // Project AI summary (top, not collapsed)
            let ai_summary_top = format!(
                "<div class=\"card ai\" id=\"ai-summary\"><h3>AI Summary</h3>\n<p><strong>Project Root:</strong> {root}<br><strong>Total Files:</strong> {files}<br><strong>Total Lines:</strong> {lines}</p></div>",
                root = html_escape(&analysis.root_path.display().to_string()),
                files = analysis.total_files,
                lines = analysis.total_lines,
            );

            // Index page TOC
            let mut toc_items: Vec<String> = Vec::new();
            toc_items.push("<li><a href=\\\"#ai-commentary\\\">AI Commentary</a></li>".to_string());
            toc_items.push("<li><a href=\\\"#project-snapshot\\\">Project Snapshot</a></li>".to_string());
            toc_items.push("<li><a href=\\\"#dependency-overview\\\">Dependency Overview</a></li>".to_string());
            if security_analysis.is_some() { toc_items.push("<li><a href=\\\"#security-overview\\\">Security Overview</a></li>".to_string()); }
            toc_items.push("<li><a href=\\\"#docs-insights\\\">Documentation Insights</a></li>".to_string());
            let toc_html = format!("<div class=\\\"card toc\\\"><h3>Contents</h3><ul>{}</ul></div>", toc_items.join("\n"));

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
                project_snapshot = markdown_to_html(&Self::project_snapshot_md(analysis)),
                dep = build_simple_dependency_graph(analysis),
                security_block = security_block,
            );
            fs::write(out.join("index.html"), content).map_err(|e| e.into())
        }
        */

    /* moved to templates.rs
        fn write_global_symbols(&self, out: &Path, files: &[crate::analyzer::FileInfo]) -> Result<()> {
            let mut items = String::new();
            for f in files {
                let page = format!("pages/{}.html", sanitize_filename(&f.path));
                for s in &f.symbols {
                    let _ = writeln!(
                        &mut items,
                        "<li><a href=\"{page}#symbol-{anchor}\"><code>{name}</code></a> <small>{file}</small></li>",
                        page = page,
                        anchor = Self::anchorize(&s.name),
                        name = html_escape(&s.name),
                        file = html_escape(&f.path.display().to_string()),
                    );
                }
                if idx >= node_limit { break; }
            }
            let content = format!(
                r#"<!doctype html>
    <html>
    <head>
    <meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
    <title>Symbols - {title}</title>
    <link rel=\"stylesheet\" href=\"assets/style.css\">
    </head>
    <body>
    <header><h1>Symbols</h1></header>
    <main>
    <section class=\"article\">
    <ul>
    {items}
    </ul>
    </section>
    </main>
    </body>
    </html>"#,
                title = html_escape(&self.config.site_title),
                items = items,
            );
            fs::write(out.join("symbols.html"), content).map_err(|e| e.into())
        }
        */

    fn generate_ai_insights_sync(analysis: &AnalysisResult, use_mock: bool, _cfg_path: Option<&PathBuf>) -> Result<String> {
        // Create a placeholder implementation - comprehensive AI insights for the entire repository
        let mut summary = String::new();
        use std::fmt::Write as _;
        let _ = writeln!(&mut summary, "Project Overview:");
        for f in analysis.files.iter().take(5) {
            let _ = writeln!(&mut summary, "- {} ({:} symbols)",
                           f.path.display(), f.symbols.len());
        }
        let insights = format!(
            "<div class=\"card\"><h3>AI Insights</h3>\
            <p>Project analysis shows {total_files} files with {total_symbols} symbols: {summary}</p>\
            <p><strong>Recommendations:</strong></p>\
            <ul><li>Consider modularization for files with >50 functions</li>\
            <li>Add comprehensive error handling patterns</li>\
            <li>Optimize imports and dependencies</li></ul></div>",
            total_files = analysis.total_files,
            total_symbols = analysis.files.iter().map(|f| f.symbols.len()).sum::<usize>(),
            summary = if summary.len() > 200 { &summary[..200] } else { &summary }
        );
        Ok(insights)
    }

    fn generate_file_ai_insights_sync(&self, file: &crate::analyzer::FileInfo) -> Result<String> {
        use crate::ai::types::{AIFeature, AIRequest};
        let title = format!("File: {}", file.path.display());
        let mut html = String::new();
        use std::fmt::Write as _;
        // Ensure a single AI runtime/service
        self.ensure_ai()?;
        let rt = self.ai_rt.borrow();
        let rt = rt.as_ref().expect("ai runtime initialized");
        let service = self.ai_service.borrow();
        let service = service.as_ref().expect("ai service initialized");
        if self.config.ai_json_mode {
            // Ask for structured JSON output per schema
            let mut prompt = String::new();
            let _ = writeln!(
                &mut prompt,
                "Provide structured wiki documentation for file '{}'.\nContext: language={}, lines={}, symbols={}",
                file.path.display(),
                file.language,
                file.lines,
                file.symbols.len()
            );
            let _ = writeln!(
                &mut prompt,
                "Respond with a JSON object with keys: overview, deep_dive (list of {{name,kind,summary,details}}), key_apis (list of {{name,signature,usage}}), examples (list of {{title,language,code,explanation}}), gotchas (list), security {{risks,mitigations}}, performance {{concerns,tips}}, related (list of {{path,reason}}), cross_refs (list of {{text,target}}), tags (list)."
            );

            let mut req = AIRequest::new(AIFeature::DocumentationGeneration, prompt)
                .with_temperature(0.2)
                .with_max_tokens(2000);
            req = req.with_context("response_format".to_string(), "json_object".to_string());
            let resp = rt
                .block_on(async { service.process_request(req).await })
                .map_err(|e| crate::error::Error::Internal {
                    component: "wiki".to_string(),
                    message: format!("ai: {}", e),
                    context: None,
                })?;

            if let Some(doc) =
                Self::parse_ai_json::<crate::wiki::ai_schema::AiDocFile>(&resp.content)
            {
                return Ok(self.render_ai_doc_file(file, &doc));
            }
            // Fallback to simple text card if parsing failed
            let _ = writeln!(
                &mut html,
                "<div class=\"card ai\"><h3>AI Commentary</h3>{}</div>",
                markdown_to_html(&resp.content)
            );
            Ok(html)
        } else {
            // Text-mode fallback: multiple focused prompts
            let req = AIRequest::new(
                AIFeature::DocumentationGeneration,
                format!("Module overview for {}", title),
            )
            .with_temperature(0.0)
            .with_max_tokens(200);
            let resp = rt
                .block_on(async { service.process_request(req).await })
                .map_err(|e| crate::error::Error::Internal {
                    component: "wiki".to_string(),
                    message: format!("ai: {}", e),
                    context: None,
                })?;
            let _ = writeln!(
                &mut html,
                "<div class=\"card ai\"><h3>AI Commentary</h3><h4>Module Overview</h4>{}",
                markdown_to_html(&resp.content)
            );
            let req2 = AIRequest::new(
                AIFeature::DocumentationGeneration,
                format!(
                    "Function docs for {}: {} symbols",
                    title,
                    file.symbols.len()
                ),
            )
            .with_temperature(0.0)
            .with_max_tokens(200);
            let resp2 = rt
                .block_on(async { service.process_request(req2).await })
                .map_err(|e| crate::error::Error::Internal {
                    component: "wiki".to_string(),
                    message: format!("ai: {}", e),
                    context: None,
                })?;
            let _ = writeln!(
                &mut html,
                "<h4>Function Docs</h4>{}",
                markdown_to_html(&resp2.content)
            );
            let req3 = AIRequest::new(
                AIFeature::RefactoringSuggestions,
                format!("Refactoring suggestions for {}", title),
            )
            .with_temperature(0.0)
            .with_max_tokens(200);
            let resp3 = rt
                .block_on(async { service.process_request(req3).await })
                .map_err(|e| crate::error::Error::Internal {
                    component: "wiki".to_string(),
                    message: format!("ai: {}", e),
                    context: None,
                })?;
            let _ = writeln!(
                &mut html,
                "<h4>Refactoring Suggestions</h4>{}",
                markdown_to_html(&resp3.content)
            );
            let req4 = AIRequest::new(
                AIFeature::SecurityAnalysis,
                format!("Security insights for {}", title),
            )
            .with_temperature(0.0)
            .with_max_tokens(200);
            let resp4 = rt
                .block_on(async { service.process_request(req4).await })
                .map_err(|e| crate::error::Error::Internal {
                    component: "wiki".to_string(),
                    message: format!("ai: {}", e),
                    context: None,
                })?;
            let _ = writeln!(
                &mut html,
                "<h4>Security Insights</h4>{}</div>",
                markdown_to_html(&resp4.content)
            );
            Ok(html)
        }
    }
    /// Generate AI block HTML and collect tags (prefers JSON mode when enabled)
    fn generate_file_ai_block_and_tags(
        &self,
        file: &crate::analyzer::FileInfo,
    ) -> (String, Vec<String>) {
        use crate::ai::types::{AIFeature, AIRequest};
        if !self.config.ai_enabled {
            return (String::new(), vec![]);
        }

        if self.config.ai_json_mode {
            if self.ensure_ai().is_ok() {
                let rt_b = self.ai_rt.borrow();
                let rt = rt_b.as_ref().expect("ai runtime initialized");
                let svc_b = self.ai_service.borrow();
                let service = svc_b.as_ref().expect("ai service initialized");
                use std::fmt::Write as _;
                let mut prompt = String::new();
                let _ = writeln!(
                    &mut prompt,
                    "Provide structured wiki documentation for file '{}'.",
                    file.path.display()
                );
                let _ = writeln!(
                    &mut prompt,
                    "Context: language={}, lines={}, symbols={}",
                    file.language,
                    file.lines,
                    file.symbols.len()
                );
                let _ = writeln!(&mut prompt, "Respond with a JSON object with keys: overview, deep_dive (list of {{name,kind,summary,details}}), key_apis (list of {{name,signature,usage}}), examples (list of {{title,language,code,explanation}}), gotchas (list), security {{risks,mitigations}}, performance {{concerns,tips}}, related (list of {{path,reason}}), cross_refs (list of {{text,target}}), tags (list)." );
                let mut req = AIRequest::new(AIFeature::DocumentationGeneration, prompt)
                    .with_temperature(0.2)
                    .with_max_tokens(2000);
                req = req.with_context("response_format".to_string(), "json_object".to_string());
                if let Ok(resp) = rt.block_on(async { service.process_request(req).await }) {
                    if let Some(doc) =
                        Self::parse_ai_json::<crate::wiki::ai_schema::AiDocFile>(&resp.content)
                    {
                        let html = self.render_ai_doc_file(file, &doc);
                        return (html, doc.tags.unwrap_or_default());
                    }
                }
            }
        }

        // Fallback to text-mode block without tags
        match self.generate_file_ai_insights_sync(file) {
            Ok(html) => (html, vec![]),
            Err(_) => ("<div class=\\\"card ai\\\"><h3>AI Commentary</h3><p>AI generation failed.</p></div>".to_string(), vec![]),
        }
    }

    fn anchorize(s: &str) -> String {
        // Allow only [a-z0-9-]; map other chars to '-'; collapse dashes
        let mut out = String::with_capacity(s.len());
        for ch in s.chars() {
            let c = ch.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() {
                out.push(c);
            } else if matches!(c, ' ' | '-' | '_' | ':' | '.' | '/') {
                out.push('-');
            } else {
                out.push('-');
            }
        }
        let collapsed = out
            .split('-')
            .filter(|seg| !seg.is_empty())
            .collect::<Vec<_>>()
            .join("-");
        collapsed
    }

    /* moved to templates.rs
    fn build_nav(&self, files: &[crate::analyzer::FileInfo], link_prefix: &str) -> String {
        use std::collections::BTreeMap;
        #[derive(Default)]
        struct Node { dirs: BTreeMap<String, Node>, files: Vec<(String, String)> }

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
            let href = format!("{}{}.html", link_prefix, sanitize_filename(&f.path));
            // Build components vector
            let parts: Vec<String> = f
                .path
                .components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect();
            insert_path(&mut root, &parts, &display, &href);
        }

        fn render(node: &Node, name: Option<&str>, out: &mut String) {
            use std::fmt::Write as _;
            if let Some(n) = name { let _ = writeln!(out, "<details><summary class=\"folder\">{}</summary>", html_escape(n)); }
            for (dname, child) in &node.dirs {
                render(child, Some(dname), out);
            }
            for (disp, href) in &node.files {
                let _ = writeln!(out, "<a href=\"{}\">{}</a>", href, html_escape(disp));
            }
            if name.is_some() { let _ = writeln!(out, "</details>"); }
        }

        let mut out = String::new();
        // Render top-level directories then root files
        for (dname, child) in &root.dirs {
            render(child, Some(dname), &mut out);
        }
        for (disp, href) in &root.files {
            use std::fmt::Write as _;
            let _ = writeln!(&mut out, "<a href=\"{}\">{}</a>", href, html_escape(disp));
        }
        out
    }
    */

    /// Build sidebar HTML with search input, filters, and links
    /* moved to templates.rs
    fn build_sidebar_with_search(
        &self,
        analysis: &AnalysisResult,
        security_analysis: &Option<security_enhancements::SecurityAnalysisResult>,
        link_prefix: &str,
    ) -> String {
        let mut nav_content = String::new();
        let root_prefix = if link_prefix.is_empty() { "../" } else { "" };
        let _ = writeln!(
            &mut nav_content,
            "<input class=\"search\" id=\"q\" type=\"search\" placeholder=\"Search...\" />"
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
        // Live results container
        let _ = writeln!(&mut nav_content, "<ul id=\"results\" style=\"margin:.5rem 0; padding-left:1rem;\"></ul>");

        // File links
        let _ = writeln!(&mut nav_content, "<hr style=\"border-color: #334155; margin: .75rem 0;\"/>");
        let _ = writeln!(&mut nav_content, "<h4>Files</h4>");
        let _ = writeln!(&mut nav_content, "{}", self.build_nav(&analysis.files, link_prefix));

        // Security links if available
        if let Some(_security) = security_analysis {
            let _ = writeln!(&mut nav_content, "<hr style=\"border-color: #334155; margin: 1rem 0;\"/>");
            let _ = writeln!(&mut nav_content, "<h4>Security</h4>");
            let _ = writeln!(&mut nav_content, "<a href=\"{root}security.html\">Security Overview</a>", root=root_prefix);
            let _ = writeln!(&mut nav_content, "<a href=\"{root}security_hotspots.html\">Security Hotspots</a>", root=root_prefix);
        }

        nav_content
    }
    */
    // write_search_index moved to search.rs

    /// Generate a simple relationship map for enhanced wiki features
    fn generate_relationship_map_simple(&self, analysis: &AnalysisResult) -> HashMap<String, Vec<String>> {
        let mut relationships = HashMap::new();

        for file in &analysis.files {
            let mut file_relationships = Vec::new();

            // Add related symbols within this file
            for symbol in &file.symbols {
                file_relationships.push(format!("symbol:{}:{}", symbol.name, symbol.kind));
            }

            // Add cross-file relationships based on naming patterns
            for other_file in &analysis.files {
                if other_file.path != file.path {
                    // Check for naming similarities that might indicate relationships
                    let file_name = file.path.file_stem()
                        .and_then(|stem| stem.to_str())
                        .unwrap_or("");
                    let other_file_name = other_file.path.file_stem()
                        .and_then(|stem| stem.to_str())
                        .unwrap_or("");

                    // Simple relationship detection: files with similar names or common patterns
                    if file_name.contains(other_file_name) || other_file_name.contains(file_name) {
                        file_relationships.push(format!("cross_file:{}", other_file.path.display()));
                    }

                    // Relationship via shared symbol names (potential interfaces/utilities)
                    for symbol in &file.symbols {
                        for other_symbol in &other_file.symbols {
                            if symbol.name.to_lowercase() == other_symbol.name.to_lowercase() &&
                               symbol.kind != other_symbol.kind {
                                file_relationships.push(format!("shared_symbol:{}@{}", symbol.name, other_file.path.display()));
                            }
                        }
                    }
                }
            }

            relationships.insert(
                file.path.display().to_string(),
                file_relationships
            );
        }

        // Add global relationships (files that might be entry points or main files)
        let mut global_relationships = Vec::new();

        // Identify potential main files or entry points
        for file in &analysis.files {
            if let Some(file_name) = file.path.file_name().and_then(|name| name.to_str()) {
                if file_name.contains("main") || file_name.contains("entry") ||
                   file_name.contains("app") || file_name.contains("server") {
                    global_relationships.push(format!("entry_point:{}", file.path.display()));
                }
            }
        }

        // Identify large files with high symbol counts (potential core modules)
        for file in &analysis.files {
            if file.symbols.len() > analysis.files.iter().map(|f| f.symbols.len()).max().unwrap_or(0) / 2 {
                global_relationships.push(format!("core_module:{}", file.path.display()));
            }
        }

        relationships.insert("_global_".to_string(), global_relationships);

        relationships
    }

    /// Write a security overview page
    /* moved to templates.rs
    fn write_security_overview_page(&self, out: &Path, security: &security_enhancements::SecurityAnalysisResult) -> Result<()> {
        let mut content = String::new();
        let _ = writeln!(&mut content, "<!doctype html>");
        let _ = writeln!(&mut content, "<html>");
        let _ = writeln!(&mut content, "<head>");
        let _ = writeln!(&mut content, "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        let _ = writeln!(&mut content, "<title>Security Overview - {}</title>", html_escape(&self.config.site_title));
        let _ = writeln!(&mut content, "<link rel=\\\"stylesheet\\\" href=\\\"assets/style.css\\\">");
        let _ = writeln!(&mut content, "<script src=\\\"assets/mermaid.js\\\"></script>");
        let _ = writeln!(&mut content, "<script src=\\\"assets/main.js\\\"></script>");
        let _ = writeln!(&mut content, "</head>");
        let _ = writeln!(&mut content, "<body>");
        let _ = writeln!(&mut content, "<header><h1>Security Overview</h1><button id=\\\"themeToggle\\\" class=\\\"theme-toggle\\\"></button></header>");
        let _ = writeln!(&mut content, "<main><section class=\"article\">");

        // Security score card
        let _ = writeln!(&mut content, "<div class=\"card\">");
        let _ = writeln!(&mut content, "<h2>Security Score: {}/100</h2>", security.security_result.security_score);
        let security_rating = if security.security_result.security_score >= 80 {
            "Excellent"
        } else if security.security_result.security_score >= 60 {
            "Good"
        } else if security.security_result.security_score >= 40 {
            "Needs Improvement"
        } else {
            "Critical Issues"
        };
        let _ = writeln!(&mut content, "<p>Rating: <strong>{}</strong></p>", security_rating);
        let _ = writeln!(&mut content, "</div>");

        // Vulnerabilities summary
        let _ = writeln!(&mut content, "<div class=\"card\">");
        let _ = writeln!(&mut content, "<h3>Vulnerability Summary</h3>");
        let _ = writeln!(&mut content, "<p>Total Vulnerabilities: <strong>{}</strong></p>", security.security_result.total_vulnerabilities);

        let mut vuln_by_severity = String::new();
        for (severity, count) in &security.security_result.vulnerabilities_by_severity {
            let _ = writeln!(&mut vuln_by_severity, "<li>{:?}: {}</li>", severity, count);
        }
        let _ = writeln!(&mut content, "<ul>{}</ul>", vuln_by_severity);
        let _ = writeln!(&mut content, "</div>");

        // Security traces
        if !security.security_traces.is_empty() {
            let _ = writeln!(&mut content, "<div class=\"card\">");
            let _ = writeln!(&mut content, "<h3>Security Traces</h3>");
            for trace in &security.security_traces {
                let _ = writeln!(&mut content, "<h4>Vulnerability: {}</h4>", html_escape(&trace.source.title));
                let _ = writeln!(&mut content, "<p>Severity: {:?}</p>", trace.source.severity);
                let _ = writeln!(&mut content, "<div class=\"mermaid\">{}</div>", SecurityWikiGenerator::new()?.generate_trace_diagram(trace));
            }
            let _ = writeln!(&mut content, "</div>");
        }

        // Theme handled by main.js
        let _ = writeln!(&mut content, "</section></main></body></html>");
        fs::write(out.join("security.html"), content).map_err(|e| e.into())
    }
    */

    /// Write security hotspots page
    /* moved to templates.rs
    fn write_security_hotspots_page(&self, out: &Path, security: &security_enhancements::SecurityAnalysisResult) -> Result<()> {
        let mut content = String::new();
        let _ = writeln!(&mut content, "<!doctype html>");
        let _ = writeln!(&mut content, "<html>");
        let _ = writeln!(&mut content, "<head>");
        let _ = writeln!(&mut content, "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        let _ = writeln!(&mut content, "<title>Security Hotspots - {}</title>", html_escape(&self.config.site_title));
        let _ = writeln!(&mut content, "<link rel=\\\"stylesheet\\\" href=\\\"assets/style.css\\\">");
        let _ = writeln!(&mut content, "<script src=\\\"assets/mermaid.js\\\"></script>");
        let _ = writeln!(&mut content, "<script src=\\\"assets/main.js\\\"></script>");
        let _ = writeln!(&mut content, "</head>");
        let _ = writeln!(&mut content, "<body>");
        let _ = writeln!(&mut content, "<header><h1>Security Hotspots</h1><button id=\\\"themeToggle\\\" class=\\\"theme-toggle\\\"></button></header>");
        let _ = writeln!(&mut content, "<main><section class=\"article\">");

        if !security.security_hotspots.is_empty() {
            let _ = writeln!(&mut content, "<div class=\"card\">");
            let _ = writeln!(&mut content, "<h2>Security Hotspots Visualization</h2>");
            let _ = writeln!(&mut content, "<div class=\"mermaid\">{}</div>", SecurityWikiGenerator::new()?.generate_hotspot_diagram(&security.security_hotspots));
            let _ = writeln!(&mut content, "</div>");

            let _ = writeln!(&mut content, "<div class=\"card\">");
            let _ = writeln!(&mut content, "<h3>Detailed Hotspots</h3>");
            let _ = writeln!(&mut content, "<ul>");
            for hotspot in &security.security_hotspots {
                let _ = writeln!(&mut content, "<li><strong>{}</strong>", html_escape(&hotspot.location.file.display().to_string()));
                let _ = writeln!(&mut content, "<br>Risk Score: {:.1}", hotspot.risk_score);
                let _ = writeln!(&mut content, "<br>Vulnerabilities: {} ({:?})", hotspot.vulnerability_count, hotspot.severity);
                let _ = writeln!(&mut content, "<br>Description: {}</li>", html_escape(&hotspot.description));
            }
            let _ = writeln!(&mut content, "</ul>");
            let _ = writeln!(&mut content, "</div>");
        } else {
            let _ = writeln!(&mut content, "<div class=\"card\">");
            let _ = writeln!(&mut content, "<h3>No Security Hotspots Found</h3>");
            let _ = writeln!(&mut content, "<p>Your codebase appears to be secure based on current analysis.</p>");
            let _ = writeln!(&mut content, "</div>");
        }

        // Theme handled by main.js
        let _ = writeln!(&mut content, "</section></main></body></html>");
        fs::write(out.join("security_hotspots.html"), content).map_err(|e| e.into())
    }
    */

    /// Generate security overview block for inclusion in main page
    /* moved to templates.rs
    fn generate_security_overview_block(&self, security: &security_enhancements::SecurityAnalysisResult) -> String {
        let mut block = String::new();
        let _ = writeln!(&mut block, "<div class=\"card\">");
        let _ = writeln!(&mut block, "<h2>Security Analysis</h2>");
        let _ = writeln!(&mut block, "<p><strong>Security Score:</strong> {} / 100</p>", security.security_result.security_score);
        let _ = writeln!(&mut block, "<p><strong>Total Vulnerabilities:</strong> {}</p>", security.security_result.total_vulnerabilities);
        if !security.security_hotspots.is_empty() {
            let _ = writeln!(&mut block, "<p><strong>High-Risk Files:</strong> {}</p>", security.security_hotspots.len());
        }
        let _ = writeln!(&mut block, "<div class=\"mermaid\">{}</div>", SecurityWikiGenerator::new().unwrap().generate_hotspot_diagram(&security.security_hotspots.iter().take(5).cloned().collect::<Vec<_>>()));
        let _ = writeln!(&mut block, "</div>");
        block
    }
    */

    /// Update write_file_page signature and implementation
    /* moved to templates.rs
        fn write_file_page(&self, page_path: &Path, title: &str, description: &str, file: &crate::analyzer::FileInfo, root_path: &Path, security_block: &str, nav_content: &str, ai_block_html: &str) -> Result<()> {
            let mut rels = String::new();
            for sym in &file.symbols {
                // Simple relationship lines in mermaid classDiagram
                let _ = writeln!(&mut rels, "  class {} {{}}", sym.name.replace(':', "_"));
            }
            // Prepare source content for collapsible code snippets
            let full_path = root_path.join(&file.path);
            let source = fs::read_to_string(&full_path).unwrap_or_default();
            // Absolute path for editor link (whole file)
            let abs_file = {
                let p = root_path.join(&file.path);
                std::fs::canonicalize(&p).unwrap_or(p)
            };
            let vscode_file_href = format!("vscode://file/{}", url_encode_path(&abs_file));
            let src_lines: Vec<&str> = source.lines().collect();

            // Build grouped symbol sections for better UX
            let mut functions_html = String::new();
            let mut variables_html = String::new();
            let mut types_html = String::new();

            let mut count_functions = 0usize;
            let mut count_variables = 0usize;
            let mut count_types = 0usize;

            for sym in &file.symbols {
                // Build a collapsible code snippet for this symbol
                let start = sym.start_line.saturating_sub(1);
                let end = sym.end_line.min(src_lines.len());
                let snippet = if start < end && end <= src_lines.len() {
                    let slice = &src_lines[start..end];
                    html_escape(&slice.join("\n"))
                } else {
                    String::new()
                };

                let code_id = format!("code-{}-{}", Self::safe_ident(&sym.name), sym.start_line);
                // Build line number gutter
                let mut gutter = String::new();
                if start < end {
                    for ln in sym.start_line..=sym.end_line {
                        let _ = writeln!(&mut gutter, "{}", ln);
                    }
                }
                // VS Code deep link
                let abs_path = {
                    let p = root_path.join(&file.path);
                    std::fs::canonicalize(&p).unwrap_or(p)
                };
                let vscode_href = format!(
                    "vscode://file/{}:{}",
                    url_encode_path(&abs_path),
                    sym.start_line
                );

                let item_html = format!(
                    "<li id=\"symbol-{id}\"><code>{name}</code> <small>{kind}</small>{details}</li>",
                    id = Self::anchorize(&sym.name),
                    name = html_escape(&sym.name),
                    kind = html_escape(&sym.kind),
                    details = if !snippet.is_empty() {
                        format!(
                            "\n<details><summary>View code ({start}-{end})</summary>\n<div class=\"codeblock\">\n  <div class=\"codeblock-header\">\n    <button class=\"copy-btn\" data-target=\"{code_id}\">Copy</button>\n    <a class=\"open-in-editor\" href=\"{vscode}\" title=\"Open in VS Code\">Open in VS Code</a>\n  </div>\n  <div class=\"codeblock-body\">\n    <pre class=\"gutter\">{gutter}</pre>\n    <pre><code id=\"{code_id}\" class=\"lang-{lang} hljs\">{snippet}</code></pre>\n  </div>\n</div>\n</details>",
                            start = sym.start_line,
                            end = sym.end_line,
                            lang = html_escape(&file.language.to_lowercase()),
                            snippet = snippet,
                            code_id = html_escape(&code_id),
                            gutter = html_escape(&gutter),
                            vscode = html_escape(&vscode_href),
                        )
                    } else { String::new() }
                );

                // Categorize symbol
                let kind_lower = sym.kind.to_lowercase();
                if kind_lower.contains("function") || kind_lower.contains("fn") || kind_lower.contains("method") {
                    count_functions += 1;
                    let _ = writeln!(&mut functions_html, "{}", item_html);
                } else if kind_lower.contains("variable") || kind_lower.contains("const") || kind_lower == "let" {
                    count_variables += 1;
                    let _ = writeln!(&mut variables_html, "{}", item_html);
                } else {
                    count_types += 1;
                    let _ = writeln!(&mut types_html, "{}", item_html);
                }
            }
            let mut sym_list = String::new();
            // Render grouped sections as collapsible blocks
            let _ = writeln!(
                &mut sym_list,
                "<details><summary><strong>Functions</strong> <small>({})</small></summary><ul>{}</ul></details>",
                count_functions,
                functions_html
            );
            let _ = writeln!(
                &mut sym_list,
                "<details><summary><strong>Variables</strong> <small>({})</small></summary><ul>{}</ul></details>",
                count_variables,
                variables_html
            );
            let _ = writeln!(
                &mut sym_list,
                "<details><summary><strong>Types & Structures</strong> <small>({})</small></summary><ul>{}</ul></details>",
                count_types,
                types_html
            );
            let diag_blocks = Self::build_sequence_or_flow_blocks(file, &rels, root_path);

            // Build AI summary (always visible)
            let ai_summary = format!(
                "<div class=\"card ai\" id=\"ai-summary\"><h3>AI Summary</h3>\n<p><strong>File:</strong> {file_path}<br><strong>Language:</strong> {lang}<br><strong>Lines:</strong> {lines}<br><strong>Symbols:</strong> {syms}<br><strong>Vulnerabilities:</strong> {vulns}</p></div>",
                file_path = html_escape(&file.path.display().to_string()),
                lang = html_escape(&file.language),
                lines = file.lines,
                syms = file.symbols.len(),
                vulns = file.security_vulnerabilities.len(),
            );

            // Wrap AI commentary in a collapsible section if present
            let ai_commentary = if !ai_block_html.trim().is_empty() {
                format!("<details class=\\\"card\\\" id=\\\"ai-commentary\\\"><summary>AI Commentary</summary>{}</details>", ai_block_html)
            } else { String::new() };

            // Diagrams already come wrapped as collapsible details with IDs
            let has_cf = diag_blocks.contains("id=\"control-flow\"");
            let has_seq = diag_blocks.contains("id=\"call-sequence\"");
            let has_class = diag_blocks.contains("id=\"class-diagram\"");

            // Symbols section collapsible wrapper
            let symbols_block = format!("<details class=\\\"card\\\" id=\\\"symbols\\\"><summary>Symbols</summary>\n{}\n</details>", sym_list);

            // Security section collapsible wrapper (if present)
            let security_section = if !security_block.trim().is_empty() {
                format!("<details class=\\\"card\\\" id=\\\"security-analysis\\\"><summary>Security Analysis</summary>{}</details>", security_block)
            } else { String::new() };

            // Table of contents
            let mut toc_items: Vec<String> = Vec::new();
            toc_items.push("<li><a href=\\\"#ai-summary\\\">AI Summary</a></li>".to_string());
            if !ai_commentary.is_empty() { toc_items.push("<li><a href=\\\"#ai-commentary\\\">AI Commentary</a></li>".to_string()); }
            if has_cf { toc_items.push("<li><a href=\\\"#control-flow\\\">Control Flow</a></li>".to_string()); }
            if has_seq { toc_items.push("<li><a href=\\\"#call-sequence\\\">Call Sequence</a></li>".to_string()); }
            if has_class { toc_items.push("<li><a href=\\\"#class-diagram\\\">Class/Module Diagram</a></li>".to_string()); }
            toc_items.push("<li><a href=\\\"#symbols\\\">Symbols</a></li>".to_string());
            if !security_section.is_empty() { toc_items.push("<li><a href=\\\"#security-analysis\\\">Security Analysis</a></li>".to_string()); }
            let toc_html = format!("<div class=\\\"card\\\"><h3>Contents</h3><ul>{}</ul></div>", toc_items.join("\n"));

            // Build breadcrumbs from file.path components
            let breadcrumbs_html = {
                use std::fmt::Write as _;
                let mut br = String::new();
                let _ = write!(&mut br, "<nav class=\\\"breadcrumbs\\\"><a href=\\\"../index.html\\\">Home</a>");
                let parts: Vec<String> = file
                    .path
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .collect();
                if !parts.is_empty() {
                    for (i, part) in parts.iter().enumerate() {
                        let _ = write!(&mut br, " <span class=\\\"sep\\\">/</span> ");
                        if i + 1 == parts.len() { let _ = write!(&mut br, "<strong>{}</strong>", html_escape(part)); }
                        else { let _ = write!(&mut br, "<span>{}</span>", html_escape(part)); }
                    }
                }
                let _ = write!(&mut br, "<a class=\\\"open-in-editor right\\\" href=\\\"{}\\\" title=\\\"Open file in VS Code\\\">Open in VS Code</a>", html_escape(&vscode_file_href));
                let _ = write!(&mut br, "</nav>");
                br
            };

            let content = format!(
                r#"<!doctype html>
    <html>
    <head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{title}</title>
    <link rel="stylesheet" href="../assets/style.css">
    <link rel="stylesheet" href="../assets/hljs.css">
    <script src="../assets/search_index.js"></script>
    <script src="../assets/search.js"></script>
    <script src="../assets/mermaid.js"></script>
    <script src="../assets/hljs.js"></script>
    <script src="../assets/main.js"></script>
    </head>
    <body>
    <header><h1>{title}</h1><div style="display:flex;gap:.5rem;align-items:center"><button id="sidebarToggle" class="sidebar-toggle">Sidebar</button><button id="themeToggle" class="theme-toggle"></button></div></header>
    <main>
    <nav>
    {nav}
    </nav>
    <section class="article">
    {breadcrumbs}
    <p>{description}</p>
    {ai_summary}
    {toc}
    {ai_commentary}
    {diag_blocks}
    {symbols_block}
    {security_section}
    </section>
    </main>
    </body>
    </html>"#,
                title = html_escape(title),
                description = html_escape(description),
                ai_summary = ai_summary,
                toc = toc_html,
                ai_commentary = ai_commentary,
                diag_blocks = diag_blocks,
                symbols_block = symbols_block,
                security_section = security_section,
                nav = nav_content,
                breadcrumbs = breadcrumbs_html,
            );
            fs::write(page_path, content).map_err(|e| e.into())
        }
        */

    /// Generate security enhancements block for a file
    fn generate_file_security_block(
        &self,
        _file: &crate::analyzer::FileInfo,
        hotspots: &[security_enhancements::SecurityHotspot],
        owasp_rec: &str,
    ) -> String {
        if hotspots.is_empty() && owasp_rec.is_empty() {
            return String::new();
        }

        let mut block = String::new();
        let _ = writeln!(&mut block, "<div class=\"card\">");
        let _ = writeln!(&mut block, "<h3>Security Analysis</h3>");

        if !hotspots.is_empty() {
            for hotspot in hotspots {
                let _ = writeln!(
                    &mut block,
                    "<h4>File Security: {}</h4>",
                    hotspot.location.file.display()
                );
                let _ = writeln!(&mut block, "<p>Risk Score: {:.1}</p>", hotspot.risk_score);
                let _ = writeln!(
                    &mut block,
                    "<p>Vulnerabilities: {} ({:?})</p>",
                    hotspot.vulnerability_count, hotspot.severity
                );
                let _ = writeln!(&mut block, "<p>{}</p>", html_escape(&hotspot.description));
            }
        }

        if !owasp_rec.is_empty() {
            let _ = writeln!(&mut block, "<h4>OWASP Recommendations</h4>");
            let _ = writeln!(&mut block, "{}", owasp_rec);
        }

        let _ = writeln!(&mut block, "</div>");
        block
    }

}

// SearchEntry moved to search.rs

impl WikiGenerator {
    fn generate_ai_insights_sync(
        &self,
        analysis: &AnalysisResult,
        _use_mock: bool,
        _cfg_path: Option<&PathBuf>,
    ) -> Result<String> {
        // For now, use the AI service builder with mock providers unless networking is configured.

        // We assemble a compact context of the codebase and ask for a concise summary.
        // This runs synchronously by blocking on tokio if needed for consistency with CLI usage.
        let mut summary = String::new();
        use std::fmt::Write as _;
        let _ = writeln!(&mut summary, "Project Overview:");
        for f in analysis.files.iter().take(10) {
            let _ = writeln!(
                &mut summary,
                "- {} ({} symbols, {} lines)",
                f.path.display(),
                f.symbols.len(),
                f.lines
            );
        }

        // Compose prompt content (strict: summarize only provided facts)
        // Add high-signal facts to prevent incorrect assumptions
        let mut facts = String::new();
        let _ = writeln!(
            &mut facts,
            "Stats: total_files={}, total_lines={}",
            analysis.total_files, analysis.total_lines
        );
        if !analysis.languages.is_empty() {
            let mut ls: Vec<(String, usize)> = analysis
                .languages
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            ls.sort_by(|a, b| b.1.cmp(&a.1));
            let lang_list: Vec<String> = ls.iter().map(|(l, c)| format!("{}:{}", l, c)).collect();
            let _ = writeln!(&mut facts, "Languages: {}", lang_list.join(", "));
        }
        let content = format!(
            "You are summarizing a codebase strictly from provided FACTS.\n\
             DO NOT infer or assume beyond these facts. If unknown, say 'Unknown'.\n\
             Output concise Markdown with two sections: 'Highlights' and 'Potential Improvements'.\n\
             FACTS:\n{}\n\nFILE LIST (sample):\n{}",
            facts,
            summary
        );

        let req = crate::ai::types::AIRequest::new(
            crate::ai::types::AIFeature::DocumentationGeneration,
            content,
        )
        .with_temperature(0.2)
        .with_max_tokens(400);

        self.ensure_ai()?;
        let rt_b = self.ai_rt.borrow();
        let rt = rt_b.as_ref().expect("ai runtime initialized");
        let svc_b = self.ai_service.borrow();
        let service = svc_b.as_ref().expect("ai service initialized");

        let resp = rt
            .block_on(async { service.process_request(req).await })
            .map_err(|e| crate::error::Error::Internal {
                component: "wiki".to_string(),
                message: format!("ai: {}", e),
                context: None,
            })?;

        let html = format!(
            "<div class=\"card ai\"><h3>AI Commentary</h3>{}</div>",
            markdown_to_html(&resp.content)
        );
        Ok(html)
    }

/// Much simpler implementation that works around tree-sitter API issues
impl WikiGenerator {
    fn generate_project_ai_block(&self, analysis: &AnalysisResult) -> Result<String> {
        if self.config.ai_json_mode {
            self.ensure_ai()?;
            let rt_b = self.ai_rt.borrow();
            let rt = rt_b.as_ref().expect("ai runtime initialized");
            let svc_b = self.ai_service.borrow();
            let service = svc_b.as_ref().expect("ai service initialized");

            // Prompt for structured JSON
            use std::fmt::Write as _;
            let mut facts = String::new();
            let _ = writeln!(
                &mut facts,
                "Files={}, Lines={}",
                analysis.total_files, analysis.total_lines
            );
            if !analysis.languages.is_empty() {
                let mut ls: Vec<(String, usize)> = analysis
                    .languages
                    .iter()
                    .map(|(k, v)| (k.clone(), *v))
                    .collect();
                ls.sort_by(|a, b| b.1.cmp(&a.1));
                let lang_list: Vec<String> =
                    ls.iter().map(|(l, c)| format!("{}:{}", l, c)).collect();
                let _ = writeln!(&mut facts, "Languages: {}", lang_list.join(", "));
            }
            let prompt = format!(
                "Provide a concise project overview as JSON with keys: overview (markdown), highlights (list), improvements (list), tags (list). Use only the FACTS provided.\nFACTS:\n{}",
                facts
            );
            let mut req = crate::ai::types::AIRequest::new(
                crate::ai::types::AIFeature::DocumentationGeneration,
                prompt,
            )
            .with_temperature(0.2)
            .with_max_tokens(600);
            req = req.with_context("response_format".to_string(), "json_object".to_string());
            let resp = rt
                .block_on(async { service.process_request(req).await })
                .map_err(|e| crate::error::Error::Internal {
                    component: "wiki".to_string(),
                    message: format!("ai: {}", e),
                    context: None,
                })?;
            if let Some(doc) =
                Self::parse_ai_json::<crate::wiki::ai_schema::AiDocProject>(&resp.content)
            {
                return Ok(self.render_ai_project_doc(&doc));
            }
            // Fallback to plain text rendering if JSON parse fails
            return Ok(format!(
                "<div class=\"card ai\"><h3>AI Commentary</h3>{}</div>",
                markdown_to_html(&resp.content)
            ));
        }
        // Non-JSON mode: reuse existing summary flow
        self.generate_ai_insights_sync(
            analysis,
            self.config.ai_use_mock,
            self.config.ai_config_path.as_ref(),
        )
    }

    // render_ai_project_doc moved to ai_integration.rs
}
