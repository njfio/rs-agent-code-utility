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

fn project_simple_calls() -> Result<(TempDir, PathBuf)> {
    let tmp = TempDir::new()?;
    let root = tmp.path().to_path_buf();
    let src = root.join("src");
    fs::create_dir_all(&src)?;
    write_rs(&root, "src/lib.rs", r#"
        pub fn a(){ b(); c(); }
        pub fn b(){}
        pub fn c(){}
    "#)?;
    Ok((tmp, root))
}

#[test]
fn sequence_diagram_has_calls() -> Result<()> {
    let (_t, root) = project_simple_calls()?;
    let out = TempDir::new()?;
    let cfg: WikiConfig = WikiConfigBuilder::new()
        .with_site_title("SEQ")
        .with_output_dir(out.path())
        .include_api_docs(true)
        .build()?;
    WikiGenerator::new(cfg).generate_from_path(&root)?;

    let pages = out.path().join("pages");
    let mut content = String::new();
    for e in fs::read_dir(&pages)? { let e = e?; content = fs::read_to_string(e.path())?; if content.contains("sequenceDiagram") { break; } }
    assert!(content.contains("sequenceDiagram"));
    assert!(content.contains("a->>b: call"));
    assert!(content.contains("a->>c: call"));
    Ok(())
}

