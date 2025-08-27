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

fn project_with_if_else() -> Result<(TempDir, PathBuf)> {
    let tmp = TempDir::new()?;
    let root = tmp.path().to_path_buf();
    let src = root.join("src");
    fs::create_dir_all(&src)?;
    write_rs(&root, "src/lib.rs", r#"pub fn demo(x:i32)->i32{ if x>1 { x+1 } else { x-1 } }"#)?;
    Ok((tmp, root))
}

fn project_with_for_loop() -> Result<(TempDir, PathBuf)> {
    let tmp = TempDir::new()?;
    let root = tmp.path().to_path_buf();
    let src = root.join("src");
    fs::create_dir_all(&src)?;
    write_rs(&root, "src/lib.rs", r#"pub fn sum(n:i32)->i32{ let mut s=0; for i in 0..n { s+=i; } s }"#)?;
    Ok((tmp, root))
}

#[test]
fn flowchart_contains_branch_nodes_for_if_else() -> Result<()> {
    let (_t, root) = project_with_if_else()?;
    let out = TempDir::new()?;
    let cfg: WikiConfig = WikiConfigBuilder::new()
        .with_site_title("CFG")
        .with_output_dir(out.path())
        .include_api_docs(true)
        .build()?;
    WikiGenerator::new(cfg).generate_from_path(&root)?;

    let pages = out.path().join("pages");
    let mut content = String::new();
    for e in fs::read_dir(&pages)? { let e = e?; content = fs::read_to_string(e.path())?; if content.contains("flowchart TB") { break; } }
    assert!(content.contains("flowchart TB"), "should include flowchart container");
    // CFG rendering lists Branch nodes as node_type strings; for Rust if it's if_expression
    assert!(content.contains("if_expression") || content.contains("match_expression"), "should render branch node type");
    Ok(())
}

#[test]
fn flowchart_contains_loop_backedge_node() -> Result<()> {
    let (_t, root) = project_with_for_loop()?;
    let out = TempDir::new()?;
    let cfg: WikiConfig = WikiConfigBuilder::new()
        .with_site_title("CFG2")
        .with_output_dir(out.path())
        .include_api_docs(true)
        .build()?;
    WikiGenerator::new(cfg).generate_from_path(&root)?;

    let pages = out.path().join("pages");
    let mut content = String::new();
    for e in fs::read_dir(&pages)? { let e = e?; content = fs::read_to_string(e.path())?; if content.contains("flowchart TB") { break; } }
    assert!(content.contains("flowchart TB"), "should include flowchart container");
    // For Rust for loop, node kind in our CFG is for_expression
    assert!(content.contains("for_expression") || content.contains("loop_expression") || content.contains("while_expression"), "should render loop node type");
    Ok(())
}

