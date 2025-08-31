function runSearch(){
  // Use embedded search index if present to avoid file:// CORS
  let idx = (typeof window !== 'undefined' && window.SEARCH_INDEX) ? window.SEARCH_INDEX : [];
  // Resolve asset base path relative to current page
  const isFile = (typeof location !== 'undefined' && location.protocol === 'file:');
  const base = (typeof location !== 'undefined' && location.pathname && location.pathname.indexOf('/pages/') !== -1) ? '../assets' : 'assets';
  const jsonUrl = base + '/search_index.json';
  // Fallback: attempt to fetch JSON if embedded index missing (best effort)
  async function tryLoadJson(){
    try {
      if (!idx || idx.length === 0) {
        if (!isFile) {
          const r = await fetch(jsonUrl);
          if (r.ok) { idx = await r.json(); }
        }
      }
    } catch (_) { /* ignore for file:// and fetch errors */ }
  }
  const q = document.getElementById('q');
  const list = document.getElementById('results');
  const langFilter = document.getElementById('langFilter');
  const kindFilter = document.getElementById('kindFilter');
  const vulnOnly = document.getElementById('vulnOnly');

  // Populate language filter
  if (langFilter && langFilter.options.length <= 1) {
    const langs = Array.from(new Set(idx.map(it => it.language))).sort();
    for (const l of langs) { const o=document.createElement('option'); o.value=l; o.textContent=l; langFilter.appendChild(o); }
  }
  // Populate kind filter
  if (kindFilter && kindFilter.options.length <= 1) {
    const kinds = Array.from(new Set(idx.flatMap(it => it.kinds))).sort();
    for (const k of kinds) { const o=document.createElement('option'); o.value=k; o.textContent=k; kindFilter.appendChild(o); }
  }

  function scoreItem(it, term){
    if (!term) return 0;
    const t = term.toLowerCase();
    let s = 0;
    if (it.title.toLowerCase().includes(t)) s += 3;
    if (it.description.toLowerCase().includes(t)) s += 1;
    if (it.symbols.some(sym => sym.toLowerCase().includes(t))) s += 2;
    return s;
  }

  function passFilters(it){
    const lang = langFilter ? langFilter.value : '';
    if (lang && it.language !== lang) return false;
    const kind = kindFilter ? kindFilter.value : '';
    if (kind && !it.kinds.includes(kind)) return false;
    if (vulnOnly && vulnOnly.checked && !(it.tags||[]).includes('vulnerable')) return false;
    return true;
  }

  function render(items){
    if (!list) return;
    list.innerHTML='';
    for (const it of items){
      const li=document.createElement('li');
      const a=document.createElement('a');
      const pageBase = (typeof location !== 'undefined' && location.pathname && location.pathname.indexOf('/pages/') !== -1) ? '../' : '';
      a.href = pageBase + it.path; a.textContent=it.title; li.appendChild(a);
      const small=document.createElement('small'); small.style.display='block'; small.style.color='#9aa4b2'; small.textContent=`${it.language} • ${it.symbols.length} symbols`; li.appendChild(small);
      list.appendChild(li);
    }
  }

  async function update(){
    await tryLoadJson();
    const term = q ? q.value.trim() : '';
    let items = idx.filter(passFilters);
    if (term){ items = items.map(it => ({it, sc: scoreItem(it, term)})).filter(x => x.sc>0).sort((a,b)=>b.sc-a.sc).map(x=>x.it); }
    render(items.slice(0, 200));
  }

  if (q) q.addEventListener('input', update);
  if (langFilter) langFilter.addEventListener('change', update);
  if (kindFilter) kindFilter.addEventListener('change', update);
  if (vulnOnly) vulnOnly.addEventListener('change', update);
  update();
}
window.addEventListener('DOMContentLoaded', runSearch);