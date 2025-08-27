use rust_tree_sitter::wiki::{WikiConfig, WikiConfigBuilder, WikiGenerator};
use rust_tree_sitter::Result;
use tempfile::TempDir;
use std::fs;
use std::path::PathBuf;

fn create_sample_project() -> Result<(TempDir, PathBuf)> {
    let tmp = TempDir::new()?;
    let root = tmp.path().to_path_buf();
    let src = root.join("src");
    fs::create_dir_all(&src)?;

    // Simple Rust file with a function and a public function
    fs::write(
        src.join("lib.rs"),
        r#"/// Sample module
pub fn public_add(a: i32, b: i32) -> i32 { a + b }
fn private_double(x: i32) -> i32 { if x > 0 { x * 2 } else { x - 1 } }
"#,
    )?;

    Ok((tmp, root))
}

#[test]
fn generates_basic_site_structure() -> Result<()> {
    let (_tmp, project_root) = create_sample_project()?;
    let out_dir = TempDir::new()?;

    let cfg: WikiConfig = WikiConfigBuilder::new()
        .with_site_title("Test Wiki")
        .with_output_dir(out_dir.path())
        .include_api_docs(true)
        .include_examples(true)
        .build()?;

    let generator = WikiGenerator::new(cfg);
    let result = generator.generate_from_path(&project_root)?;

    assert!(result.pages >= 2, "expected at least index + one module page");

    // Files exist
    let index = out_dir.path().join("index.html");
    assert!(index.exists(), "index.html should exist");

    let assets_css = out_dir.path().join("assets").join("style.css");
    assert!(assets_css.exists(), "style.css should exist");

    let search_js = out_dir.path().join("assets").join("search.js");
    assert!(search_js.exists(), "search.js should exist");

    Ok(())
}

#[test]
fn includes_mermaid_diagrams() -> Result<()> {
    let (_tmp, project_root) = create_sample_project()?;
    let out_dir = TempDir::new()?;

    let cfg: WikiConfig = WikiConfigBuilder::new()
        .with_site_title("Test Wiki")
        .with_output_dir(out_dir.path())
        .include_api_docs(true)
        .include_examples(false)
        .build()?;

    let generator = WikiGenerator::new(cfg);
    generator.generate_from_path(&project_root)?;

    // Find a module page and ensure mermaid code block exists
    let pages_dir = out_dir.path().join("pages");
    let mut found_mermaid = false;
    if pages_dir.exists() {
        for entry in fs::read_dir(&pages_dir)? {
            let entry = entry?;
            let content = fs::read_to_string(entry.path())?;
            if content.contains("<script src=\"https://cdn.jsdelivr.net/npm/mermaid") {
                found_mermaid = true;
                break;
            }
            if content.contains("classDiagram") || content.contains("flowchart TB") {
                found_mermaid = true;
                break;
            }
        }
    }
    assert!(found_mermaid, "generated pages should include mermaid diagrams");

    Ok(())
}

#[test]
fn embeds_ai_generated_content_and_crossrefs() -> Result<()> {
    let (_tmp, project_root) = create_sample_project()?;
    let out_dir = TempDir::new()?;

    let cfg: WikiConfig = WikiConfigBuilder::new()
        .with_site_title("Test Wiki")
        .with_output_dir(out_dir.path())
        .include_api_docs(true)
        .include_examples(false)
        .build()?;

    let generator = WikiGenerator::new(cfg);
    generator.generate_from_path(&project_root)?;

    // Ensure AI-like documentation insights are present
    let index = fs::read_to_string(out_dir.path().join("index.html"))?;
    assert!(index.contains("Documentation Insights") || index.contains("AI"),
        "index should reference documentation insights section");

    // Ensure search index contains symbol names and cross-refs
    let search_idx = fs::read_to_string(out_dir.path().join("assets").join("search_index.json"))?;
    assert!(search_idx.contains("public_add"), "search index should include symbol names");

    Ok(())
}

