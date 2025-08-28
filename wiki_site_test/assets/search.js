async function runSearch(){
const q = document.getElementById('q');
const list = document.getElementById('results');
const languageFilter = document.getElementById('language-filter');
const fileTypeFilter = document.getElementById('file-type-filter');
const securityLevelFilter = document.getElementById('security-level-filter');
const idxResp = await fetch('assets/search_index.json');
const idx = await idxResp.json();

function getUniqueValues(field) {
return [...new Set(idx.map(it => it[field]).filter(it => it && it !== ""))].sort();
}

function getFilterValues() {
return {
language: languageFilter ? languageFilter.value : '',
fileType: fileTypeFilter ? fileTypeFilter.value : '',
securityLevel: securityLevelFilter ? securityLevelFilter.value : ''
};
}

function filterItems(items, filters) {
return items.filter(it => {
const matchesLanguage = !filters.language || it.language === filters.language;
const matchesFileType = !filters.fileType || it.file_type === filters.fileType;
const matchesSecurityLevel = !filters.securityLevel || it.security_level === filters.securityLevel;
return matchesLanguage && matchesFileType && matchesSecurityLevel;
});
}

function render(items){ list.innerHTML=''; items.forEach(it=>{ const li=document.createElement('li'); const a=document.createElement('a'); a.href=it.path; a.textContent=it.title; li.appendChild(a); list.appendChild(li); }); }

// Populate filter options
function populateFilters() {
if (!languageFilter || !fileTypeFilter || !securityLevelFilter) return;

const languages = getUniqueValues('language');
const fileTypes = getUniqueValues('file_type');
const securityLevels = getUniqueValues('security_level');

// Clear existing options except "All"
const clearOptions = (select, addOptions) => {
  while (select.options.length > 0) { select.options.remove(0); }
  const allOption = new Option('All', '');
  select.appendChild(allOption);
  addOptions.forEach(val => select.appendChild(new Option(val, val)));
};

clearOptions(languageFilter, languages);
clearOptions(fileTypeFilter, fileTypes);
clearOptions(securityLevelFilter, securityLevels);
}

function updateSearch() {
const term = q.value.toLowerCase();
const filters = getFilterValues();
let items = idx.filter(it=> it.title.toLowerCase().includes(term) || it.description.toLowerCase().includes(term) || it.symbols.some(s=>s.toLowerCase().includes(term)) );
items = filterItems(items, filters);
render(items);
}

q.addEventListener('input', updateSearch);
if (languageFilter) languageFilter.addEventListener('change', updateSearch);
if (fileTypeFilter) fileTypeFilter.addEventListener('change', updateSearch);
if (securityLevelFilter) securityLevelFilter.addEventListener('change', updateSearch);

window.addEventListener('DOMContentLoaded', () => {
populateFilters();
updateSearch();
});
}