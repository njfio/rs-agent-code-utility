function runSearch(){
  let idx = (typeof window !== 'undefined' && window.SEARCH_INDEX) ? window.SEARCH_INDEX : [];
  const isFile = (typeof location !== 'undefined' && location.protocol === 'file:');
  const base = (typeof location !== 'undefined' && location.pathname && location.pathname.indexOf('/pages/') !== -1) ? '../assets' : 'assets';
  const jsonUrl = base + '/search_index.json';
  async function tryLoadJson(){
    try {
      if (!idx || idx.length === 0) {
        if (!isFile) { const r = await fetch(jsonUrl); if (r.ok) { idx = await r.json(); } }
      }
    } catch (_) { }
  }
  const q = document.getElementById('q');
  const list = document.getElementById('results');
  const langFilter = document.getElementById('langFilter');
  const kindFilter = document.getElementById('kindFilter');
  const vulnOnly = document.getElementById('vulnOnly');
  const clearBtn = document.getElementById('clearSearch');
  const meta = document.getElementById('resultMeta');

  if (langFilter && langFilter.options.length <= 1) {
    const langs = Array.from(new Set(idx.map(it => it.language))).sort();
    for (const l of langs) { const o=document.createElement('option'); o.value=l; o.textContent=l; langFilter.appendChild(o); }
  }
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

  function highlight(text, term){
    if (!term) return text;
    try { const re = new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'), 'gi'); return text.replace(re, m => '<mark>'+m+'</mark>'); } catch(e) { return text; }
  }

  let selectedIndex = -1;

  function render(items, term){
    if (!list) return;
    list.innerHTML='';
    items.forEach((it, idx) => {
      const li=document.createElement('li'); li.setAttribute('role','option'); li.setAttribute('aria-selected','false');
      const a=document.createElement('a');
      const pageBase = (typeof location !== 'undefined' && location.pathname && location.pathname.indexOf('/pages/') !== -1) ? '../' : '';
      a.href = pageBase + it.path; a.innerHTML=highlight(it.title, term); li.appendChild(a);
      const small=document.createElement('small'); small.style.display='block'; small.style.color='#9aa4b2'; small.innerHTML=`${it.language} • ${it.symbols.length} symbols`;
      const path=document.createElement('div'); path.style.color='#9aa4b2'; path.style.fontSize='.85em'; path.textContent = it.title;
      li.appendChild(small); li.appendChild(path);
      list.appendChild(li);
    });
  }

  async function update(){
    const start = (typeof performance !== 'undefined' && performance.now) ? performance.now() : 0;
    await tryLoadJson();
    const term = q ? q.value.trim() : '';
    let items = idx.filter(passFilters);
    if (term){ items = items.map(it => ({it, sc: scoreItem(it, term)})).filter(x => x.sc>0).sort((a,b)=>b.sc-a.sc).map(x=>x.it); }
    const limited = items.slice(0, 200);
    render(limited, term);
    if (meta) { const end = (typeof performance !== 'undefined' && performance.now) ? performance.now() : 0; const ms = end && start ? Math.round(end - start) : 0; meta.textContent = `${limited.length} result(s)` + (ms?` • ${ms} ms`:'' ); }
    selectedIndex = -1;
  }

  if (q) q.addEventListener('input', update);
  if (langFilter) langFilter.addEventListener('change', update);
  if (kindFilter) kindFilter.addEventListener('change', update);
  if (vulnOnly) vulnOnly.addEventListener('change', update);
  if (clearBtn && q) clearBtn.addEventListener('click', function(){ q.value=''; update(); q.focus(); });

  document.addEventListener('keydown', function(e){
    if (!e) return; const tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : '';
    if (e.key === '/' && tag !== 'input' && tag !== 'textarea') { e.preventDefault(); try{ q && q.focus(); }catch(_ ){} }
    if (e.key === 'Escape' && q) { q.value=''; update(); }
    if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && list) {
      const L = list.querySelectorAll('li'); if (!L || L.length===0) return; e.preventDefault();
      if (e.key === 'ArrowDown') selectedIndex = Math.min(selectedIndex+1, L.length-1);
      if (e.key === 'ArrowUp') selectedIndex = Math.max(selectedIndex-1, 0);
      L.forEach((li,i)=>{ li.classList.toggle('selected', i===selectedIndex); li.setAttribute('aria-selected', i===selectedIndex?'true':'false'); });
      const sel = L[selectedIndex]; if (sel) sel.scrollIntoView({ block: 'nearest' });
    }
    if (e.key === 'Enter' && list && selectedIndex>=0) { const L = list.querySelectorAll('li'); if (!L || !L[selectedIndex]) return; const a = L[selectedIndex].querySelector('a[href]'); if (a) { location.href = a.href; } }
  });
  update();
}
window.addEventListener('DOMContentLoaded', runSearch);