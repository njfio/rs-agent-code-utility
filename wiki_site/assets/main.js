(function(){
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
})();