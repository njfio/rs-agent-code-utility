//! CycloneDX SBOM serializer (minimal JSON)
//! Converts DependencyAnalysisResult into a CycloneDX-like JSON structure.

use serde::Serialize;

#[derive(Serialize)]
struct Bom<'a> {
    #[serde(rename = "bomFormat")] bom_format: &'static str,
    #[serde(rename = "specVersion")] spec_version: &'static str,
    version: u32,
    components: Vec<Component<'a>>,
}

#[derive(Serialize)]
struct Component<'a> {
    #[serde(rename = "type")] ctype: &'static str,
    name: &'a str,
    version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")] purl: Option<String>,
}

fn purl_for(manager: &crate::dependency_analysis::PackageManager, name: &str, version: &str) -> Option<String> {
    match manager {
        crate::dependency_analysis::PackageManager::Cargo => Some(format!("pkg:cargo/{name}@{version}")),
        crate::dependency_analysis::PackageManager::Npm | crate::dependency_analysis::PackageManager::Yarn => Some(format!("pkg:npm/{name}@{version}")),
        crate::dependency_analysis::PackageManager::Pip | crate::dependency_analysis::PackageManager::Poetry | crate::dependency_analysis::PackageManager::Pipenv => Some(format!("pkg:pypi/{name}@{version}")),
        crate::dependency_analysis::PackageManager::GoMod => Some(format!("pkg:golang/{name}@{version}")),
    }
}

pub fn to_cyclonedx(deps: &'_ crate::DependencyAnalysisResult) -> String {
    let components: Vec<_> = deps.dependencies.iter().map(|d| Component {
        ctype: "library",
        name: d.name.as_str(),
        version: d.version.as_str(),
        purl: purl_for(&d.manager, &d.name, &d.version),
    }).collect();

    let bom = Bom { bom_format: "CycloneDX", spec_version: "1.4", version: 1, components };
    serde_json::to_string_pretty(&bom).unwrap_or_else(|_| "{}".to_string())
}

