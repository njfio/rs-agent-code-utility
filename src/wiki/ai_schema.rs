use serde::Deserialize;

// JSON schema for AI-generated wiki content per file
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AiDocFile {
    pub overview: Option<String>,
    pub deep_dive: Option<Vec<DeepDiveItem>>, // name, kind, summary, details
    pub key_apis: Option<Vec<KeyApi>>,        // name, signature, usage
    pub examples: Option<Vec<Example>>,       // title, language, code, explanation
    pub gotchas: Option<Vec<String>>,
    pub security: Option<SecuritySection>, // risks, mitigations
    pub performance: Option<PerformanceSection>, // concerns, tips
    pub related: Option<Vec<RelatedItem>>, // path, reason
    pub cross_refs: Option<Vec<CrossRef>>, // text, target
    pub tags: Option<Vec<String>>,
}

// JSON schema for AI-generated project overview (index page)
#[derive(Debug, Deserialize)]
pub struct AiDocProject {
    pub overview: Option<String>,
    pub highlights: Option<Vec<String>>, // bullet points of key aspects
    pub improvements: Option<Vec<String>>, // improvement suggestions
    pub tags: Option<Vec<String>>,       // optional tags
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DeepDiveItem {
    pub name: Option<String>,
    pub kind: Option<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct KeyApi {
    pub name: Option<String>,
    pub signature: Option<String>,
    pub usage: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Example {
    pub title: Option<String>,
    pub language: Option<String>,
    pub code: Option<String>,
    pub explanation: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SecuritySection {
    pub risks: Option<Vec<String>>,
    pub mitigations: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct PerformanceSection {
    pub concerns: Option<Vec<String>>,
    pub tips: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct RelatedItem {
    pub path: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct CrossRef {
    pub text: Option<String>,
    pub target: Option<String>,
}
