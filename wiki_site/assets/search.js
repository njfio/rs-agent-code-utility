async function runSearch(){
const q = document.getElementById('q');
const list = document.getElementById('results');
const idxResp = await fetch('assets/search_index.json');
const idx = await idxResp.json();
function render(items){ list.innerHTML=''; items.forEach(it=>{ const li=document.createElement('li'); const a=document.createElement('a'); a.href=it.path; a.textContent=it.title; li.appendChild(a); list.appendChild(li); }); }
q.addEventListener('input',()=>{
const term = q.value.toLowerCase();
const items = idx.filter(it=> it.title.toLowerCase().includes(term) || it.description.toLowerCase().includes(term) || it.symbols.some(s=>s.toLowerCase().includes(term)) );
render(items);
});
}
window.addEventListener('DOMContentLoaded', runSearch);