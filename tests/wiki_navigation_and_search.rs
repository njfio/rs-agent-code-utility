use rust_tree_sitter::wiki::{WikiConfig, WikiConfigBuilder, WikiGenerator};
use rust_tree_sitter::Result;
use tempfile::TempDir;
use std::fs;

fn create_project() -> Result<(TempDir, std::path::PathBuf)> {
    let tmp = TempDir::new()?;
    let root = tmp.path().to_path_buf();
    let src = root.join("src");
    fs::create_dir_all(&src)?;
    fs::write(src.join("lib.rs"), r#"
pub fn alpha() {}
pub fn beta() {}
"#)?;
    Ok((tmp, root))
}

#[test]
fn wiki_contains_breadcrumbs_and_active_support() -> Result<()> {
    let (_tmp, root) = create_project()?;
    let out = TempDir::new()?;
    let cfg: WikiConfig = WikiConfigBuilder::new()
        .with_site_title("NAV-TEST")
        .with_output_dir(out.path())
        .include_api_docs(true)
        .build()?;
    WikiGenerator::new(cfg).generate_from_path(&root)?;

    // Locate a generated file page
    let pages = out.path().join("pages");
    let mut found = None;
    for e in fs::read_dir(&pages)? { let p = e?.path(); if p.extension().and_then(|e| e.to_str())==Some("html") { found = Some(p); break; } }
    let file_page = found.expect("expected at least one file page");
    let content = fs::read_to_string(&file_page)?;

    // Breadcrumb markup and editor link present
    assert!(content.contains("<nav class=\"breadcrumbs\">"), "breadcrumbs should be present in file page. got: {}", &content[..content.len().min(800)]);
    assert!(content.to_lowercase().contains("open in vs code"), "editor link should be present");

    // Active-link support is provided by assets: CSS + JS
    let css = fs::read_to_string(out.path().join("assets").join("style.css"))?;
    assert!(css.contains("nav a.active"), "style should include active link rule");
    let js = fs::read_to_string(out.path().join("assets").join("main.js"))?;
    assert!(js.contains("initActiveLink"), "main.js should include initActiveLink");
    assert!(js.contains("classList.add('active')"), "main.js should add 'active' class");

    Ok(())
}

#[test]
fn search_js_has_shortcuts_and_result_meta() -> Result<()> {
    let (_tmp, root) = create_project()?;
    let out = TempDir::new()?;
    let cfg: WikiConfig = WikiConfigBuilder::new()
        .with_site_title("SEARCH-TEST")
        .with_output_dir(out.path())
        .include_api_docs(true)
        .with_search_max_results(123)
        .build()?;
    WikiGenerator::new(cfg).generate_from_path(&root)?;

    let js = fs::read_to_string(out.path().join("assets").join("search.js"))?;
    // Result meta and clear button wiring
    assert!(js.contains("resultMeta"), "search.js should manage result meta (count/time)");
    assert!(js.contains("clearSearch"), "search.js should provide a clear button");
    // Keyboard shortcuts
    assert!(js.contains("'/'") || js.contains("\"/\""), "/ focuses the search input");
    assert!(js.contains("Escape"), "Escape clears search");
    assert!(js.contains("ArrowDown") && js.contains("ArrowUp"), "Arrow keys navigate results");
    // Highlighting
    assert!(js.contains("<mark>"), "search.js should inject <mark> tags for highlights");
    // Configured max results is embedded
    assert!(js.contains("slice(0, 123)") || js.contains("slice(0,123)"), "search.js should reflect configured max results");
    Ok(())
}
