use std::fs;
use std::path::Path;

use crate::Result;

impl super::WikiGenerator {
    pub(super) fn write_style_css_impl(&self, path: &Path) -> Result<()> {
        let css = r#":root{--bg:#0b0f17;--fg:#e6e9ef;--muted:#9aa4b2;--accent:#7aa2f7;--card:#111826;--security-critical:#ef4444;--security-high:#f97316;--security-medium:#eab308;--security-low:#22c55e;--security-info:#6b7280}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;margin:0;line-height:1.55;font-size:15px}
/* Improve readability for general text */
p{margin:.6rem 0}
/* Add comfortable spacing for lists in article content */
.article ul,.article ol{margin:.5rem 0 .75rem 1.25rem;padding-left:1.25rem}
.article li{margin:.35rem 0}
/* Ensure consecutive list items have breathing room even without margins */
.article li+li{margin-top:.35rem}
header{background:#0d1320;border-bottom:1px solid #1f2937;padding:.75rem 1.25rem;position:sticky;top:0;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:1rem}
[data-theme=light] header{background:#ffffff;border-bottom:1px solid #e2e8f0}
main{display:flex}
nav{width:260px;height:100vh;overflow:auto;background:#0d1524;border-right:1px solid #1f2937;padding:1rem;position:sticky;top:0}
[data-theme=light] nav{background:#f1f5f9;border-right:1px solid #e2e8f0}
nav a{display:block;color:#e6e9ef;text-decoration:none;padding:.35rem 0;border-radius:4px;transition:all 0.2s ease;line-height:1.35}
nav a:hover{color:#ffffff;background:#1e2530;text-decoration:underline}
[data-theme=light] nav a{color:#0f172a}
[data-theme=light] nav a:hover{color:#111827;background:#e5e7eb}
nav a:focus{outline:2px solid #334155}
/* Active link highlighting */
nav a.active{background:#1e2530;color:#ffffff;border-left:3px solid var(--accent);padding-left:.5rem}
[data-theme=light] nav a.active{background:#e5e7eb;color:#111827;border-left-color:var(--accent)}
/* Global link styling for readability on dark bg */
a{color:#e6e9ef;text-decoration:underline}
a:hover{color:#ffffff}
.article a{color:#e6e9ef;text-decoration:underline;border-radius:3px;transition:all 0.2s ease}
.article a:hover{color:#ffffff;background:#1e2530;padding:0.1rem 0.3rem}
[data-theme=light] a,[data-theme=light] .article a,[data-theme=light] pre a,[data-theme=light] code a{color:#0f172a}
[data-theme=light] a:hover,[data-theme=light] .article a:hover{color:#111827;background:#e5e7eb}
pre a,code a{color:#e6e9ef;text-decoration:none;border-radius:2px}
pre a:hover,code a:hover{color:#9aa4b2;background:rgba(122,162,247,0.1);padding:0 2px}
/* Ensure visited links remain readable */
nav a:visited{color:#e6e9ef}
.article a:visited{color:#e6e9ef}
pre a:visited,code a:visited{color:#e6e9ef}
nav hr{border-color:#334155;margin:1rem 0}
nav h4{margin:.5rem 0;margin-top:1rem;font-size:.9em;color:var(--accent)}
.article{flex:1;padding:1.5rem;max-width:1100px}
.article h1,.article h2,.article h3{margin:.2rem 0 .6rem}
.card{background:var(--card);border:1px solid #1f2937;border-radius:10px;padding:1rem 1.1rem;margin:.85rem 0;box-shadow:0 1px 2px rgba(0,0,0,0.25)}
/* AI insights card styling */
.card.ai{border-color:rgba(122,162,247,0.6);box-shadow:0 0 0 1px rgba(122,162,247,0.15) inset, 0 6px 24px rgba(0,0,0,0.25)}
.card.ai h3{color:var(--accent);margin-top:0}
/* Collapsible sections */
details.card{border-radius:10px}
details.card>summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:.5rem;font-weight:600}
details.card>summary::-webkit-details-marker{display:none}
details.card[open]{box-shadow:0 1px 2px rgba(0,0,0,0.25)}

/* Sidebar collapse */
.sidebar-toggle{margin-left:auto;background:#1e2530;color:#e6e9ef;border:1px solid #334155;border-radius:6px;padding:.35rem .6rem;cursor:pointer}
[data-theme=light] .sidebar-toggle{background:#e5e7eb;color:#0f172a;border-color:#cbd5e1}
.sidebar-collapsed nav{display:none}
.sidebar-collapsed .article{max-width:min(1300px,95vw)}

/* Sidebar tree */
nav details{margin:.25rem 0}
nav details>summary{cursor:pointer;color:#9aa4b2}
nav details a{padding-left:.75rem}
nav .folder{font-weight:600;color:#9aa4b2}
pre{background:#0a1220;border:1px solid #1f2937;border-radius:8px;padding:.8rem;overflow:auto}
.mermaid{background:#0a1220;border:1px solid #1f2937;border-radius:8px;padding:.6rem;margin:.75rem 0;overflow:auto}
[data-theme=light] pre,[data-theme=light] .mermaid{background:#f8fafc;border-color:#e2e8f0}
/* Small helper text above diagrams */
.diagram-help{font-size:.9em;color:var(--muted);margin:.25rem 0 .5rem}
.diagram-help code{background:transparent;color:var(--muted);padding:0}
input.search{width:100%;padding:.5rem .75rem;border-radius:6px;border:1px solid #334155;background:#0a1220;color:var(--fg)}
[data-theme=light] input.search{background:#ffffff;border-color:#e2e8f0}
#results li{margin:.3rem 0}
#results a{display:block}
/* Selected search result */
#results li.selected a{background:#1e2530}
[data-theme=light] #results li.selected a{background:#e5e7eb}

/* Breadcrumbs */
.breadcrumbs{display:flex;flex-wrap:wrap;gap:.35rem;align-items:center;color:var(--muted);font-size:.9em;margin:.25rem 0 1rem}
.breadcrumbs a{color:inherit;text-decoration:underline}
.breadcrumbs .sep{opacity:.6}
.breadcrumbs .right{margin-left:auto}
.breadcrumbs .open-in-editor{font-size:.9em;background:#1e2530;color:#e6e9ef;border:1px solid #334155;border-radius:6px;padding:.25rem .5rem;text-decoration:none}
[data-theme=light] .breadcrumbs .open-in-editor{background:#e5e7eb;color:#0f172a;border-color:#cbd5e1}

/* Theme toggle button */
.theme-toggle{background:#1e2530;color:#e6e9ef;border:1px solid #334155;border-radius:8px;padding:.3rem .6rem;font-size:.85em;cursor:pointer}
.theme-toggle:hover{background:#2a3340}
[data-theme=light] .theme-toggle{background:#e5e7eb;color:#111827;border-color:#cbd5e1}

/* Codeblock with gutter and actions */
.codeblock{background:#0a1220;border:1px solid #1f2937;border-radius:8px;margin:.6rem 0}
.codeblock-header{display:flex;gap:.5rem;align-items:center;justify-content:flex-end;border-bottom:1px solid #1f2937;padding:.25rem .5rem}
.copy-btn{background:#1e2530;color:#e6e9ef;border:1px solid #334155;border-radius:6px;font-size:.85em;padding:.25rem .6rem;cursor:pointer}
.copy-btn:hover{background:#2a3340}
.open-in-editor{font-size:.85em;color:var(--accent)}
.codeblock-body{display:grid;grid-template-columns:auto 1fr}
pre.gutter{margin:0;padding:.75rem .5rem;border-right:1px solid #1f2937;color:#9aa4b2;text-align:right;min-width:3ch}
.codeblock-body pre{margin:0;padding:.75rem}

/* Security-specific styles */
.security-score{color:var(--accent);font-size:2em;font-weight:bold}
.security-critical{color:var(--security-critical)}
.security-high{color:var(--security-high)}
.security-medium{color:var(--security-medium)}
.security-low{color:var(--security-low)}
.security-info{color:var(--security-info)}

.security-vulnerability{background:#1f1826;border-left:4px solid var(--security-critical);padding:1rem;margin:.5rem 0}
.security-hotspot{background:#1e2530;border-left:4px solid var(--security-high);padding:1rem;margin:.5rem 0}

.vulnerability-count{background:#dc2626;color:white;padding:.25rem .5rem;border-radius:4px;font-size:.8em}
.risk-score{background:#ea580c;color:white;padding:.25rem .5rem;border-radius:4px;font-size:.8em}

.owasp-category{background:#2563eb;color:white;padding:.25rem .5rem;border-radius:4px;display:inline-block;margin:.25rem}
.owasp-a01{background:#7c2d12;color:white}
.owasp-a02{background:#dc2626;color:white}
.owasp-a03{background:#ea580c;color:white}
.owasp-a04{background:#ca8a04;color:white}
.owasp-a05{background:#16a34a;color:white}
.owasp-a06{background:#0ea5e9;color:white}
.owasp-a07{background:#a855f7;color:white}
.owasp-a08{background:#f59e0b;color:white}
.owasp-a09{background:#ef4444;color:white}
.owasp-a10{background:#64748b;color:white}

/* Security overview cards */
.security-card{background:var(--card);border:1px solid #334155;border-radius:8px;padding:1rem;margin:.5rem 0}
.security-card h3{margin-top:0}
.hotspot-item{display:flex;justify-content:space-between;align-items:center;padding:.4rem 0;border-bottom:1px dashed #334155}
.hotspot-item:last-child{border-bottom:none}
.hotspot-score{font-weight:bold}

.toc ul{margin:.25rem 0 .25rem 1rem}
.toc li{margin:.25rem 0}
nav{width:270px}
"#;

        // Apply small enhancements
        let enhanced_css = css.to_string();
        fs::write(path, enhanced_css).map_err(|e| e.into())
    }

    pub(super) fn postprocess_cdn_refs_impl(&self, out: &Path) -> Result<()> {
        fn process_dir(dir: &Path) -> std::io::Result<()> {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() { process_dir(&path)?; continue; }
                if let Some(ext) = path.extension() { if ext == "html" {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        let mut replaced = content.replace("https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js", "assets/mermaid.js");
                        replaced = replaced.replace("https://cdn.jsdelivr.net/npm/mermaid", "assets/mermaid.js");
                        replaced = replaced.replace("https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js", "assets/hljs.js");
                        replaced = replaced.replace("https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css", "assets/hljs.css");
                        replaced = replaced.replace("https://cdnjs.cloudflare.com/ajax/libs/highlight.js/", "assets/");
                        if replaced != content { let _ = std::fs::write(&path, replaced); }
                    }
                }}
            }
            Ok(())
        }
        process_dir(out).map_err(|e| e.into())
    }

    pub(super) fn write_search_js_impl(&self, path: &Path) -> Result<()> {
        let max_results = self.config.search_max_results;
        let js = format!(r#"function runSearch(){{
  let idx = (typeof window !== 'undefined' && window.SEARCH_INDEX) ? window.SEARCH_INDEX : [];
  const isFile = (typeof location !== 'undefined' && location.protocol === 'file:');
  const base = (typeof location !== 'undefined' && location.pathname && location.pathname.indexOf('/pages/') !== -1) ? '../assets' : 'assets';
  const jsonUrl = base + '/search_index.json';
  async function tryLoadJson(){{
    try {{
      if (!idx || idx.length === 0) {{
        if (!isFile) {{ const r = await fetch(jsonUrl); if (r.ok) {{ idx = await r.json(); }} }}
      }}
    }} catch (_) {{ }}
  }}
  const q = document.getElementById('q');
  const list = document.getElementById('results');
  const langFilter = document.getElementById('langFilter');
  const kindFilter = document.getElementById('kindFilter');
  const vulnOnly = document.getElementById('vulnOnly');
  const clearBtn = document.getElementById('clearSearch');
  const meta = document.getElementById('resultMeta');

  if (langFilter && langFilter.options.length <= 1) {{
    const langs = Array.from(new Set(idx.map(it => it.language))).sort();
    for (const l of langs) {{ const o=document.createElement('option'); o.value=l; o.textContent=l; langFilter.appendChild(o); }}
  }}
  if (kindFilter && kindFilter.options.length <= 1) {{
    const kinds = Array.from(new Set(idx.flatMap(it => it.kinds))).sort();
    for (const k of kinds) {{ const o=document.createElement('option'); o.value=k; o.textContent=k; kindFilter.appendChild(o); }}
  }}

  function scoreItem(it, term){{
    if (!term) return 0;
    const t = term.toLowerCase();
    let s = 0;
    if (it.title.toLowerCase().includes(t)) s += 3;
    if (it.description.toLowerCase().includes(t)) s += 1;
    if (it.symbols.some(sym => sym.toLowerCase().includes(t))) s += 2;
    return s;
  }}

  function passFilters(it){{
    const lang = langFilter ? langFilter.value : '';
    if (lang && it.language !== lang) return false;
    const kind = kindFilter ? kindFilter.value : '';
    if (kind && !it.kinds.includes(kind)) return false;
    if (vulnOnly && vulnOnly.checked && !(it.tags||[]).includes('vulnerable')) return false;
    return true;
  }}

  function highlight(text, term){{
    if (!term) return text;
    try {{ const re = new RegExp(term.replace(/[.*+?^${{}}()|[\]\\]/g,'\\$&'), 'gi'); return text.replace(re, m => '<mark>'+m+'</mark>'); }} catch(e) {{ return text; }}
  }}

  let selectedIndex = -1;

  function render(items, term){{
    if (!list) return;
    list.innerHTML='';
    items.forEach((it, idx) => {{
      const li=document.createElement('li'); li.setAttribute('role','option'); li.setAttribute('aria-selected','false');
      const a=document.createElement('a');
      const pageBase = (typeof location !== 'undefined' && location.pathname && location.pathname.indexOf('/pages/') !== -1) ? '../' : '';
      a.href = pageBase + it.path; a.innerHTML=highlight(it.title, term); li.appendChild(a);
      const small=document.createElement('small'); small.style.display='block'; small.style.color='#9aa4b2'; small.innerHTML=`${{it.language}} • ${{it.symbols.length}} symbols`;
      const path=document.createElement('div'); path.style.color='#9aa4b2'; path.style.fontSize='.85em'; path.textContent = it.title;
      li.appendChild(small); li.appendChild(path);
      list.appendChild(li);
    }});
  }}

  async function update(){{
    const start = (typeof performance !== 'undefined' && performance.now) ? performance.now() : 0;
    await tryLoadJson();
    const term = q ? q.value.trim() : '';
    let items = idx.filter(passFilters);
    if (term){{ items = items.map(it => ({{it, sc: scoreItem(it, term)}})).filter(x => x.sc>0).sort((a,b)=>b.sc-a.sc).map(x=>x.it); }}
    const limited = items.slice(0, {max_results});
    render(limited, term);
    if (meta) {{ const end = (typeof performance !== 'undefined' && performance.now) ? performance.now() : 0; const ms = end && start ? Math.round(end - start) : 0; meta.textContent = `${{limited.length}} result(s)` + (ms?` • ${{ms}} ms`:'' ); }}
    selectedIndex = -1;
  }}

  if (q) q.addEventListener('input', update);
  if (langFilter) langFilter.addEventListener('change', update);
  if (kindFilter) kindFilter.addEventListener('change', update);
  if (vulnOnly) vulnOnly.addEventListener('change', update);
  if (clearBtn && q) clearBtn.addEventListener('click', function(){{ q.value=''; update(); q.focus(); }});

  document.addEventListener('keydown', function(e){{
    if (!e) return; const tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : '';
    if (e.key === '/' && tag !== 'input' && tag !== 'textarea') {{ e.preventDefault(); try{{ q && q.focus(); }}catch(_ ){{}} }}
    if (e.key === 'Escape' && q) {{ q.value=''; update(); }}
    if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && list) {{
      const L = list.querySelectorAll('li'); if (!L || L.length===0) return; e.preventDefault();
      if (e.key === 'ArrowDown') selectedIndex = Math.min(selectedIndex+1, L.length-1);
      if (e.key === 'ArrowUp') selectedIndex = Math.max(selectedIndex-1, 0);
      L.forEach((li,i)=>{{ li.classList.toggle('selected', i===selectedIndex); li.setAttribute('aria-selected', i===selectedIndex?'true':'false'); }});
      const sel = L[selectedIndex]; if (sel) sel.scrollIntoView({{ block: 'nearest' }});
    }}
    if (e.key === 'Enter' && list && selectedIndex>=0) {{ const L = list.querySelectorAll('li'); if (!L || !L[selectedIndex]) return; const a = L[selectedIndex].querySelector('a[href]'); if (a) {{ location.href = a.href; }} }}
  }});
  update();
}}
window.addEventListener('DOMContentLoaded', runSearch);"#, max_results=max_results);
        fs::write(path, js).map_err(|e| e.into())
    }

    pub(super) fn write_highlight_assets_impl(&self, assets_dir: &Path) -> Result<()> {
        let js_path = assets_dir.join("hljs.js");
        let css_path = assets_dir.join("hljs.css");

        // Always ensure we have at least a minimal stub to avoid 404s
        let js_stub = "window.hljs = window.hljs || { highlightAll: function(){ try { document.querySelectorAll('pre code').forEach(function(el){ el.classList.add('hljs'); }); } catch(e){} } };";
        let css_stub = ".hljs{background:#0a1220;color:#e6e9ef}.hljs-keyword,.hljs-literal,.hljs-built_in{color:#7aa2f7}.hljs-string{color:#a6e3a1}.hljs-comment{color:#9aa4b2}.hljs-number{color:#f78c6c}";
        if !js_path.exists() { let _ = fs::write(&js_path, js_stub); }
        if !css_path.exists() { let _ = fs::write(&css_path, css_stub); }

        // Try to download real assets; ignore failures (offline environments)
        let js_url = "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js";
        let css_url = "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css";

        // Use tokio + reqwest if available (default features include net)
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            let fetch = async move {
                use std::time::Duration;
                let client = reqwest::Client::builder().timeout(Duration::from_secs(2)).build().unwrap_or_else(|_| reqwest::Client::new());
                let js_resp = client.get(js_url).send().await;
                if let Ok(resp) = js_resp { if resp.status().is_success() { if let Ok(text) = resp.text().await { let _ = fs::write(&js_path, text); } } }
                let css_resp = client.get(css_url).send().await;
                if let Ok(resp) = css_resp { if resp.status().is_success() { if let Ok(text) = resp.text().await { let _ = fs::write(&css_path, text); } } }
            };
            let _ = rt.block_on(fetch);
        }

        Ok(())
    }

    pub(super) fn write_mermaid_asset_impl(&self, assets_dir: &Path) -> Result<()> {
        let path = assets_dir.join("mermaid.js");
        // Minimal stub that attempts to load the real library when served over http(s)
        let stub = r#"(function(){
  function ensureRealMermaid(){
    try {
      if (window.mermaid && window.mermaid.parse && window.mermaid.initialize) return;
      if (typeof document === 'undefined') return;
      if (location && (location.protocol === 'http:' || location.protocol === 'https:')){
        var s=document.createElement('script');
        s.src='https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js';
        s.async=true; document.head.appendChild(s);
      }
    } catch(_){}
  }
  window.mermaid = window.mermaid || { initialize:function(){}, init:function(){}, parse:function(){}, render:function(){} };
  ensureRealMermaid();
})();"#;
        if !path.exists() { let _ = fs::write(&path, stub); }

        // Try to download the real library; ignore failures
        let url = "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js";
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            let fetch = async move {
                use std::time::Duration;
                let client = reqwest::Client::builder().timeout(Duration::from_secs(2)).build().unwrap_or_else(|_| reqwest::Client::new());
                if let Ok(resp) = client.get(url).send().await {
                    if resp.status().is_success() {
                        if let Ok(text) = resp.text().await { let _ = fs::write(&path, text); }
                    }
                }
            };
            let _ = rt.block_on(fetch);
        }

        Ok(())
    }

    pub(super) fn write_main_js_impl(&self, path: &Path) -> Result<()> {
        let js = r#"(function(){
// Initialize Mermaid when available; retry briefly
function initMermaid(){
  function ready(){ try { if (window.mermaid && window.mermaid.initialize && window.mermaid.parse) { mermaid.initialize({ startOnLoad: true, theme: 'dark' }); return true; } } catch(e){} return false; }
  if (!ready()) { let i=0; const t=setInterval(() => { if (ready() || ++i > 50) clearInterval(t); }, 120); }
}

// Highlight code blocks if highlight.js is present
function initHighlight(){ try { if (window.hljs) { hljs.highlightAll(); } } catch(e){}
}

// Validate Mermaid blocks early and fallback to <pre>
function preparseMermaid(){ try {
  if (window.mermaid && mermaid.parse) {
    document.querySelectorAll('.mermaid').forEach(function(el){
      try { mermaid.parse(el.textContent); } catch(e) {
        var pre=document.createElement('pre'); pre.textContent=el.textContent; el.replaceWith(pre);
      }
    });
  }
} catch(e){} }

// Theme toggle with persistence
function initTheme(){ try {
  const key='wiki_theme';
  const root=document.documentElement; const btn=document.getElementById('themeToggle');
  function apply(t){ root.setAttribute('data-theme', t); if(btn) btn.textContent=(t==='light'?'Dark':'Light')+' Mode'; localStorage.setItem(key,t); }
  const saved=localStorage.getItem(key)||'dark'; apply(saved);
  if (btn) btn.addEventListener('click', ()=>{ const next=(root.getAttribute('data-theme')==='light'?'dark':'light'); apply(next); });
} catch(e){} }

// Sidebar collapse toggle with persistence
function initSidebar(){ try {
  const key='wiki_sidebar';
  const body=document.body; const btn=document.getElementById('sidebarToggle');
  function apply(state){ if(state==='collapsed'){ body.classList.add('sidebar-collapsed'); } else { body.classList.remove('sidebar-collapsed'); } localStorage.setItem(key,state); if (btn) btn.textContent = (state==='collapsed' ? 'Show Sidebar' : 'Hide Sidebar'); }
  const saved=localStorage.getItem(key)||'expanded'; apply(saved);
  if (btn) btn.addEventListener('click', function(){ const next = body.classList.contains('sidebar-collapsed') ? 'expanded' : 'collapsed'; apply(next); });
} catch(e){} }

// Copy buttons for code blocks
function initCopyButtons(){ try {
  document.querySelectorAll('.copy-btn').forEach(function(btn){
    btn.addEventListener('click', function(){
      var id = btn.getAttribute('data-target'); var el = document.getElementById(id); if(!el) return; var text = el.innerText;
      if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text); }
      else { var ta=document.createElement('textarea'); ta.value=text; document.body.appendChild(ta); ta.select(); try{document.execCommand('copy');}catch(e){} document.body.removeChild(ta); }
      btn.textContent='Copied'; setTimeout(function(){ btn.textContent='Copy'; },1200);
    });
  });
} catch(e){} }

// Highlight current page link in sidebar
function initActiveLink(){ try {
  var path = (typeof location !== 'undefined' && location.pathname) ? location.pathname : '';
  var current = path.split('/').pop();
  if (!current) return;
  var links = document.querySelectorAll('nav a[href]');
  var matched;
  links.forEach(function(a){
    var href = a.getAttribute('href')||'';
    if (href.split('/').pop() === current) { a.classList.add('active'); matched = a; }
  });
  // Ensure parent folders are open for visibility
  if (matched) {
    var el = matched.parentElement;
    while (el) { if (el.tagName && el.tagName.toLowerCase()==='details') { el.open = true; } el = el.parentElement; }
  }
} catch(e){} }

// Persist folder <details> open states keyed by breadcrumb-like path
function initFolderState(){ try {
  function keyFor(details){
    var parts = [];
    var el = details;
    while (el && el.tagName) {
      if (el.tagName.toLowerCase()==='details') {
        var sum = el.querySelector(':scope > summary');
        if (sum) parts.unshift((sum.textContent||'').trim());
      }
      if (el.parentElement && el.parentElement.tagName && el.parentElement.tagName.toLowerCase()==='nav') break;
      el = el.parentElement;
    }
    return 'wiki_folder:'+parts.join('/');
  }
  document.querySelectorAll('nav details').forEach(function(d){
    var key = keyFor(d);
    var v = localStorage.getItem(key);
    if (v==='1') d.open = true; if (v==='0') d.open = false;
    d.addEventListener('toggle', function(){ try { localStorage.setItem(key, d.open ? '1' : '0'); } catch(e){} });
  });
} catch(e){} }

// Boot
initMermaid();
initHighlight();
preparseMermaid();
if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', function(){ initTheme(); initSidebar(); initCopyButtons(); initActiveLink(); initFolderState(); }); }
else { initTheme(); initSidebar(); initCopyButtons(); initActiveLink(); initFolderState(); }
})();"#;
        fs::write(path, js).map_err(|e| e.into())
    }
}
