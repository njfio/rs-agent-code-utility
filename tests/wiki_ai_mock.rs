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

fn project_simple() -> Result<(TempDir, PathBuf)> {
    let tmp = TempDir::new()?;
    let root = tmp.path().to_path_buf();
    let src = root.join("src");
    fs::create_dir_all(&src)?;
    write_rs(&root, "src/lib.rs", r#"pub fn hello(){ }"#)?;
    Ok((tmp, root))
}

#[test]
fn index_and_file_pages_include_ai_mock_sections() -> Result<()> {
    let (_t, root) = project_simple()?;
    let out = TempDir::new()?;
    let cfg: WikiConfig = WikiConfigBuilder::new()
        .with_site_title("AI")
        .with_output_dir(out.path())
        .include_api_docs(true)
        .with_ai_enabled(true)
        .with_ai_mock(true)
        .build()?;
    WikiGenerator::new(cfg).generate_from_path(&root)?;

    // index.html contains an AI block
    let index = fs::read_to_string(out.path().join("index.html"))?;
    assert!(index.contains("AI Insights"), "Index should include AI insights header");

    // a file page contains specific AI subsections
    let pages = out.path().join("pages");
    let mut found = None;
    for e in fs::read_dir(&pages)? {
        let e = e?;
        let c = fs::read_to_string(e.path())?;
        if c.contains("AI Insights") && c.contains("Module Overview") && c.contains("Function Docs") && c.contains("Refactoring Suggestions") && c.contains("Security Insights") {
            found = Some(c);
            break;
        }
    }
    assert!(found.is_some(), "File page should include all AI insight sections");
    Ok(())
}

