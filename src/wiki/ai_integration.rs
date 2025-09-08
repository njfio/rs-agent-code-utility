// Phase 2: AI integration helpers moved incrementally from mod.rs

// (no external imports needed here)

impl super::WikiGenerator {
    /// Parse JSON (or ```json fenced) into a target type
    pub(super) fn parse_ai_json<T: for<'de> serde::Deserialize<'de>>(raw: &str) -> Option<T> {
        let s = raw.trim();
        let s = s
            .strip_prefix("```json")
            .and_then(|x| x.strip_suffix("```"))
            .map(|x| x.trim())
            .unwrap_or(s);
        serde_json::from_str::<T>(s).ok()
    }

    /// Create an AI builder configured from env + config (no runtime side-effects)
    pub(super) fn make_ai_builder(&self) -> crate::ai::service::AIServiceBuilder {
        use crate::ai::service::AIServiceBuilder;
        use crate::ai::config::{ProviderConfig, ModelConfig, RateLimitConfig, RetryConfig};

        let mut builder = AIServiceBuilder::new();
        let use_groq = std::env::var("AI_GROQ_API_KEY").is_ok() || std::env::var("GROQ_API_KEY").is_ok();
        if use_groq {
            let api_key = std::env::var("AI_GROQ_API_KEY").or_else(|_| std::env::var("GROQ_API_KEY")).ok();
            let groq_cfg = ProviderConfig {
                enabled: true,
                api_key,
                base_url: Some("https://api.groq.com/openai/v1".to_string()),
                organization: None,
                models: vec![ModelConfig {
                    name: "openai/gpt-oss-120b".to_string(),
                    context_length: 8192,
                    max_tokens: 8001,
                    supports_streaming: false,
                    cost_per_token: None,
                    supported_features: vec![
                        crate::ai::types::AIFeature::DocumentationGeneration,
                        crate::ai::types::AIFeature::CodeExplanation,
                        crate::ai::types::AIFeature::SecurityAnalysis,
                        crate::ai::types::AIFeature::RefactoringSuggestions,
                        crate::ai::types::AIFeature::QualityAssessment,
                    ],
                }],
                default_model: "openai/gpt-oss-120b".to_string(),
                timeout: std::time::Duration::from_secs(30),
                rate_limit: RateLimitConfig::default(),
                retry: RetryConfig::default(),
            };
            builder = builder
                .with_provider(crate::ai::types::AIProvider::Groq, groq_cfg)
                .with_default_provider(crate::ai::types::AIProvider::Groq);
        } else {
            builder = builder.with_default_provider(crate::ai::types::AIProvider::OpenAI);
        }
        let use_groq = std::env::var("AI_GROQ_API_KEY").is_ok() || std::env::var("GROQ_API_KEY").is_ok();
        let builder = if self.config.ai_use_mock
            || (!use_groq
                && std::env::var("OPENAI_API_KEY").is_err()
                && std::env::var("AI_OPENAI_API_KEY").is_err())
        {
            builder.with_mock_providers(true)
        } else {
            builder
        };
        builder
    }

    pub(super) fn render_ai_doc_file(&self, _file: &crate::analyzer::FileInfo, doc: &crate::wiki::ai_schema::AiDocFile) -> String {
        // Minimal HTML rendering for AI JSON doc
        let mut out = String::new();
        use std::fmt::Write as _;
        let _ = writeln!(&mut out, "<div class=\"card ai\"><h3>AI Commentary</h3>");
        if let Some(ov) = &doc.overview {
            let _ = writeln!(&mut out, "<h4>Overview</h4>{}", super::util::markdown_to_html(ov));
        }
        if let Some(items) = &doc.deep_dive { if !items.is_empty() { let _ = writeln!(&mut out, "<h4>Deep Dive</h4><ul>");
            for i in items {
                let name = i.name.as_deref().unwrap_or("");
                let kind = i.kind.as_deref().unwrap_or("");
                let sum = i.summary.as_deref().unwrap_or("");
                if !name.is_empty() {
                    let anchor = format!("#symbol-{}", super::util::anchorize(name));
                    let _ = writeln!(&mut out, "<li><strong>{}</strong> <a href=\"{}\">{}</a><br>{}</li>", super::util::html_escape(kind), super::util::html_escape(&anchor), super::util::html_escape(name), super::util::html_escape(sum));
                } else {
                    let _ = writeln!(&mut out, "<li><strong>{}</strong><br>{}</li>", super::util::html_escape(kind), super::util::html_escape(sum));
                }
            }
            let _ = writeln!(&mut out, "</ul>"); }}
        if let Some(apis) = &doc.key_apis { if !apis.is_empty() { let _ = writeln!(&mut out, "<h4>Key APIs</h4><ul>");
            for a in apis {
                let sig = a.signature.as_deref().unwrap_or("");
                let useg = a.usage.as_deref().unwrap_or("");
                let _ = writeln!(&mut out, "<li><code>{}</code><br><small>{}</small></li>", super::util::html_escape(sig), super::util::html_escape(useg));
            }
            let _ = writeln!(&mut out, "</ul>"); }}
        if let Some(exs) = &doc.examples { if !exs.is_empty() { let _ = writeln!(&mut out, "<h4>Examples</h4>");
            for e in exs {
                let lang = e.language.as_deref().unwrap_or("text");
                let code = e.code.as_deref().unwrap_or("");
                let expl = e.explanation.as_deref().unwrap_or("");
                let title = e.title.as_deref().unwrap_or("");
                if !title.is_empty() { let _ = writeln!(&mut out, "<h5>{}</h5>", super::util::html_escape(title)); }
                let _ = writeln!(&mut out, "<div class=\"card\"><pre><code class=\"lang-{}\">{}</code></pre>{}</div>", super::util::html_escape(lang), super::util::html_escape(code), super::util::markdown_to_html(expl));
            }
        }}
        if let Some(sec) = &doc.security { if sec.risks.as_ref().map(|v| !v.is_empty()).unwrap_or(false) || sec.mitigations.as_ref().map(|v| !v.is_empty()).unwrap_or(false) {
            let _ = writeln!(&mut out, "<h4>Security</h4>");
            if let Some(risks) = &sec.risks { let _ = writeln!(&mut out, "<strong>Risks</strong><ul>"); for r in risks { let _ = writeln!(&mut out, "<li>{}</li>", super::util::html_escape(r)); } let _ = writeln!(&mut out, "</ul>"); }
            if let Some(mit) = &sec.mitigations { let _ = writeln!(&mut out, "<strong>Mitigations</strong><ul>"); for m in mit { let _ = writeln!(&mut out, "<li>{}</li>", super::util::html_escape(m)); } let _ = writeln!(&mut out, "</ul>"); }
        }}
        if let Some(perf) = &doc.performance { if perf.concerns.as_ref().map(|v| !v.is_empty()).unwrap_or(false) || perf.tips.as_ref().map(|v| !v.is_empty()).unwrap_or(false) {
            let _ = writeln!(&mut out, "<h4>Performance</h4>");
            if let Some(cs) = &perf.concerns { let _ = writeln!(&mut out, "<strong>Concerns</strong><ul>"); for c in cs { let _ = writeln!(&mut out, "<li>{}</li>", super::util::html_escape(c)); } let _ = writeln!(&mut out, "</ul>"); }
            if let Some(ts) = &perf.tips { let _ = writeln!(&mut out, "<strong>Tips</strong><ul>"); for t in ts { let _ = writeln!(&mut out, "<li>{}</li>", super::util::html_escape(t)); } let _ = writeln!(&mut out, "</ul>"); }
        }}
        if let Some(tags) = &doc.tags { if !tags.is_empty() { let _ = writeln!(&mut out, "<h4>Tags</h4><p>{}</p>", super::util::html_escape(&tags.join(", "))); }}
        if let Some(rel) = &doc.related { if !rel.is_empty() { let _ = writeln!(&mut out, "<h4>Related</h4><ul>"); for r in rel { let p=r.path.as_deref().unwrap_or(""); let reason=r.reason.as_deref().unwrap_or("");
            if !p.is_empty() { let link = format!("pages/{}.html", super::util::sanitize_filename(&std::path::PathBuf::from(p))); let _ = writeln!(&mut out, "<li><a href=\"{}\">{}</a> - {}</li>", super::util::html_escape(&link), super::util::html_escape(p), super::util::html_escape(reason)); }
            else { let _ = writeln!(&mut out, "<li>{}</li>", super::util::html_escape(reason)); }
        } let _ = writeln!(&mut out, "</ul>"); }}
        let _ = writeln!(&mut out, "</div>");
        out
    }

    pub(super) fn render_ai_project_doc(&self, doc: &crate::wiki::ai_schema::AiDocProject) -> String {
        let mut out = String::new();
        use std::fmt::Write as _;
        let _ = writeln!(&mut out, "<div class=\"card ai\"><h3>AI Commentary</h3>");
        if let Some(ov) = &doc.overview { let _ = writeln!(&mut out, "{}", super::util::markdown_to_html(ov)); }
        if let Some(hi) = &doc.highlights { if !hi.is_empty() { let _ = writeln!(&mut out, "<h4>Highlights</h4><ul>"); for h in hi { let _ = writeln!(&mut out, "<li>{}</li>", super::util::html_escape(h)); } let _ = writeln!(&mut out, "</ul>"); }}
        if let Some(im) = &doc.improvements { if !im.is_empty() { let _ = writeln!(&mut out, "<h4>Potential Improvements</h4><ul>"); for i in im { let _ = writeln!(&mut out, "<li>{}</li>", super::util::html_escape(i)); } let _ = writeln!(&mut out, "</ul>"); }}
        if let Some(tags) = &doc.tags { if !tags.is_empty() { let _ = writeln!(&mut out, "<p><small>Tags: {}</small></p>", super::util::html_escape(&tags.join(", "))); }}
        let _ = writeln!(&mut out, "</div>");
        out
    }
}
