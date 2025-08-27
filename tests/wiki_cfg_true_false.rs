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

#[test]
fn flowchart_shows_true_false_edges_for_if_else() -> Result<()> {
    let tmp = TempDir::new()?;
    let root = tmp.path().to_path_buf();
    fs::create_dir_all(root.join("src"))?;
    write_rs(&root, "src/lib.rs", r#"pub fn pick(x:i32)->i32{ if x>0 { 1 } else { -1 } }"#)?;

    let out = TempDir::new()?;
    let cfg: WikiConfig = WikiConfigBuilder::new()
        .with_site_title("CFG-TF")
        .with_output_dir(out.path())
        .include_api_docs(true)
        .build()?;
    WikiGenerator::new(cfg).generate_from_path(&root)?;

    let pages = out.path().join("pages");
    let mut content = String::new();
    for e in fs::read_dir(&pages)? { let e = e?; content = fs::read_to_string(e.path())?; if content.contains("flowchart TB") { break; } }
    assert!(content.contains("flowchart TB"));
    assert!(content.contains("-->|true|") || content.contains("-->|false|"), "should show labeled true/false edges");
    Ok(())
}

