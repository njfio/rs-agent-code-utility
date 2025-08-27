use rust_tree_sitter::wiki::{WikiConfig, WikiConfigBuilder, WikiGenerator};
use rust_tree_sitter::Result;
use tempfile::TempDir;
use std::fs;
use std::path::PathBuf;

fn write_rs(dir: &PathBuf, rel: &str, content: &str) -> Result<()> {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() { fs::create_dir_all(parent)?; }
    fs::write(p, content)?;
    Ok(())
}

fn project_with_branching() -> Result<(TempDir, PathBuf)> {
    let tmp = TempDir::new()?;
    let root = tmp.path().to_path_buf();
    let src = root.join("src");
    fs::create_dir_all(&src)?;
    write_rs(&root, "src/lib.rs", r#"pub fn branched(x:i32)->i32{ if x>0 {x*2} else {x-1} }"#)?;
    Ok((tmp, root))
}

fn project_linear_two_funcs() -> Result<(TempDir, PathBuf)> {
    let tmp = TempDir::new()?;
    let root = tmp.path().to_path_buf();
    let src = root.join("src");
    fs::create_dir_all(&src)?;
    write_rs(&root, "src/lib.rs", r#"pub fn a()->i32{42} pub fn b()->i32{a()}"#)?;
    Ok((tmp, root))
}

#[test]
fn selects_flowchart_for_branching() -> Result<()> {
    let (_t, root) = project_with_branching()?;
    let out = TempDir::new()?;
    let cfg: WikiConfig = WikiConfigBuilder::new()
        .with_site_title("Phase2")
        .with_output_dir(out.path())
        .include_api_docs(true)
        .build()?;
    WikiGenerator::new(cfg).generate_from_path(&root)?;

    // Expect flowchart diagram on the module page
    let pages = out.path().join("pages");
    let mut found_flow = false;
    for e in fs::read_dir(&pages)? { let e = e?; let c = fs::read_to_string(e.path())?; if c.contains("flowchart TB") { found_flow = true; break; } }
    assert!(found_flow, "should include flowchart TB for branching file");
    Ok(())
}

#[test]
fn selects_sequence_for_linear_multi_funcs() -> Result<()> {
    let (_t, root) = project_linear_two_funcs()?;
    let out = TempDir::new()?;
    let cfg: WikiConfig = WikiConfigBuilder::new()
        .with_site_title("Phase2")
        .with_output_dir(out.path())
        .include_api_docs(true)
        .build()?;
    WikiGenerator::new(cfg).generate_from_path(&root)?;

    // Expect sequenceDiagram on the module page
    let pages = out.path().join("pages");
    let mut found_seq = false;
    for e in fs::read_dir(&pages)? { let e = e?; let c = fs::read_to_string(e.path())?; if c.contains("sequenceDiagram") { found_seq = true; break; } }
    assert!(found_seq, "should include sequenceDiagram for linear multi-function file");
    Ok(())
}

#[test]
fn generates_global_symbols_and_anchors() -> Result<()> {
    let (_t, root) = project_linear_two_funcs()?;
    let out = TempDir::new()?;
    let cfg: WikiConfig = WikiConfigBuilder::new()
        .with_site_title("Phase2")
        .with_output_dir(out.path())
        .include_api_docs(true)
        .build()?;
    WikiGenerator::new(cfg).generate_from_path(&root)?;

    let symbols = out.path().join("symbols.html");
    assert!(symbols.exists(), "symbols.html should exist");

    // Anchors exist on pages
    let pages = out.path().join("pages");
    let mut found_anchor = false;
    for e in fs::read_dir(&pages)? { let e = e?; let c = fs::read_to_string(e.path())?; if c.contains("id=\"symbol-") { found_anchor = true; break; } }
    assert!(found_anchor, "should include symbol anchors");

    // Search index includes anchor link
    let search_idx = fs::read_to_string(out.path().join("assets").join("search_index.json"))?;
    assert!(search_idx.contains("#symbol-"), "search index should include anchor links");
    Ok(())
}

