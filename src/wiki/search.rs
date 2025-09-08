use std::path::Path;

use crate::Result;

#[derive(serde::Serialize)]
pub(super) struct SearchEntry {
    pub(super) title: String,
    pub(super) path: String,
    pub(super) description: String,
    pub(super) symbols: Vec<String>,
    pub(super) language: String,
    pub(super) kinds: Vec<String>,
    pub(super) tags: Vec<String>,
}

impl super::WikiGenerator {
    pub(super) fn write_search_index(&self, path: &Path, entries: &[SearchEntry]) -> Result<()> {
        let json = serde_json::to_string(entries).map_err(|e| crate::error::Error::Internal {
            component: "wiki".to_string(),
            message: format!("serde error: {}", e),
            context: None,
        })?;
        std::fs::write(path, &json)?;
        // Also emit a JS file to avoid file:// fetch/CORS issues
        let js_path = path.with_file_name("search_index.js");
        let js_content = format!("window.SEARCH_INDEX = {};", json);
        std::fs::write(js_path, js_content).map_err(|e| e.into())
    }
}
