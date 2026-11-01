const $ = id => document.getElementById(id);
let page = 1, busy = false;
const cell = (tr, value) => {const td = document.createElement('td'); td.textContent = value; tr.append(td); return td;};
const date = ts => new Date(ts * 1000).toISOString().slice(0, 10);
async function load() {
  const args = new URLSearchParams({domain: $('domain').value, start: $('start').value, end: $('end').value, failures: $('failures').checked ? '1' : '0', page});
  try {
    const response = await fetch('api/dashboard?' + args);
    if (!response.ok) throw Error('Dashboard request failed: ' + response.status);
    const data = await response.json();
    const selected = $('domain').value;
    $('domain').replaceChildren(new Option('All domains', ''), ...data.domains.map(d => new Option(d, d)));
    $('domain').value = selected;
    $('stats').replaceChildren();
    const s = data.stats;
    for (const [label, value] of [['Observed messages', s.total], ['DMARC pass', s.passed], ['DMARC fail', s.failed], ['Pass rate', s.total ? (100*s.passed/s.total).toFixed(1)+'%' : '—'], ['Reported quarantine', s.quarantined], ['Reported reject', s.rejected], ['Reports', s.reports]]) {
      const card = document.createElement('article'); const n = document.createElement('strong'); n.textContent = value.toLocaleString(); const labelEl = document.createElement('span'); labelEl.textContent = label; card.append(n, labelEl); $('stats').append(card);
    }
    $('groups').replaceChildren();
    for (const g of data.groups) {const tr = document.createElement('tr'); [g.domain, g.total.toLocaleString(), g.failed.toLocaleString(), ((g.total-g.failed)/g.total*100).toFixed(1)+'%'].forEach(x => cell(tr, x)); $('groups').append(tr);}
    $('rows').replaceChildren();
    for (const row of data.rows) {
      const tr = document.createElement('tr');
      [row.domain+' / '+row.reporter, date(row.begin)+' – '+date(row.end), row.ip, row.count.toLocaleString(), row.passed ? 'PASS' : 'FAIL', row.dkim, row.spf, row.disposition].forEach(x => cell(tr, x));
      const button = document.createElement('button'); button.textContent = 'Inspect';
      button.onclick = async () => { try {const r = await fetch('api/report/'+row.report); if(!r.ok) throw Error('Could not load report'); const report = await r.json(); $('detailtext').textContent = JSON.stringify({record:row, report}, null, 2); $('detail').showModal();} catch(e) {$('status').textContent=e.message;} };
      cell(tr, '').append(button); $('rows').append(tr);
    }
    $('page').textContent = `Page ${page} · ${data.row_count} matching source records`;
    $('prev').disabled = page <= 1; $('next').disabled = page*100 >= data.row_count;
  } catch(e) {$('status').textContent=e.message;}
}
async function upload(files) {
  if (busy || !files.length) return;
  busy = true; $('choose').disabled = true; $('status').textContent = 'Importing…';
  const lines=[];
  try {
    // Send one file per request to isolate upload limits and errors.
    for (const file of files) {
      const form = new FormData(); form.append('files', file);
      const r = await fetch('api/import', {method:'POST', headers:{'X-CSRF-Token':document.querySelector('meta[name="csrf-token"]').content}, body:form});
      if(!r.ok) {lines.push(file.name+': HTTP '+r.status); continue;}
      const data = await r.json();
      for(const result of data.results) lines.push(result.file+': '+(result.error || `${result.imported} imported, ${result.duplicates} duplicates skipped`));
    }
    $('status').textContent = lines.join('\n'); page=1; await load();
  } catch(e) {$('status').textContent=lines.join('\n')+'\n'+e.message;}
  finally {busy=false; $('choose').disabled=false; $('files').value='';}
}
$('choose').onclick = e => {e.stopPropagation(); $('files').click();};
$('files').onchange = e => upload([...e.target.files]);
$('drop').onclick = e => {if(e.target !== $('files') && e.target !== $('choose')) $('files').click();};
$('drop').onkeydown = e => {if(e.target === $('drop') && ['Enter',' '].includes(e.key)){e.preventDefault(); $('files').click();}};
for(const name of ['dragenter','dragover']) $('drop').addEventListener(name, e => {e.preventDefault(); $('drop').classList.add('over');});
$('drop').ondragleave = () => $('drop').classList.remove('over');
$('drop').ondrop = e => {e.preventDefault(); $('drop').classList.remove('over'); upload([...e.dataTransfer.files]);};
window.addEventListener('dragover', e => e.preventDefault()); window.addEventListener('drop', e => e.preventDefault());
$('refresh').onclick = () => {page=1; load();};
$('prev').onclick = () => {page--; load();}; $('next').onclick = () => {page++; load();};
$('close').onclick = () => $('detail').close();

// Default to the past calendar year through today, using UTC.
const today = new Date();
const yearAgo = new Date(today);

yearAgo.setUTCFullYear(today.getUTCFullYear() - 1);

// Clamp February 29 to February 28 if the previous year wasn't a leap year.
if (yearAgo.getUTCMonth() !== today.getUTCMonth()) {
  yearAgo.setUTCDate(0);
}

$('start').value = yearAgo.toISOString().slice(0, 10);
$('end').value = today.toISOString().slice(0, 10);

load();
