(()=>{
const $=id=>document.getElementById(id), table=$('checks').querySelector('tbody'),rows=Array.from(table.rows);
const keys=['result','evaluation','mode','transport','seed','case','outcome'],controls=keys.map($);let page=1,matching=[];
function filter(resetPage=true){if(resetPage)page=1;const query=$('search').value.trim().toLowerCase();
matching=rows.filter(row=>keys.every(key=>$(key).value==='all'||row.dataset[key]===$(key).value)&&[...keys.map(key=>row.dataset[key]),row.dataset.tools].join(' ').toLowerCase().includes(query));
const sort=$('sort').value;matching.sort((a,b)=>sort==='failures'?(a.dataset.result===b.dataset.result?+a.dataset.index-+b.dataset.index:a.dataset.result==='fail'?-1:1):sort==='case'?a.dataset.case.localeCompare(b.dataset.case):sort==='seed'?(a.dataset.seed===''?Infinity:+a.dataset.seed)-(b.dataset.seed===''?Infinity:+b.dataset.seed):+a.dataset.index-+b.dataset.index);
const size=$('page-size').value==='all'?Math.max(1,matching.length):+$('page-size').value,pages=Math.max(1,Math.ceil(matching.length/size));page=Math.min(page,pages);
rows.forEach(row=>row.hidden=true);matching.forEach((row,index)=>{table.append(row);row.hidden=index<(page-1)*size||index>=page*size;});
$('visible').textContent=matching.length+' of '+rows.length+' checks match · '+matching.filter(row=>row.dataset.result==='fail').length+' failed assertions';
$('empty').hidden=matching.length!==0;$('page-label').textContent='Page '+page+' of '+pages;$('previous').disabled=page===1;$('next').disabled=page===pages;
}
function reset(){controls.forEach(control=>control.value='all');$('search').value='';$('sort').value='original';filter();}
controls.forEach(control=>control.addEventListener('change',()=>filter()));$('search').addEventListener('input',()=>filter());$('sort').addEventListener('change',()=>filter());$('page-size').addEventListener('change',()=>filter());$('reset').addEventListener('click',reset);
$('previous').addEventListener('click',()=>{page--;filter(false);});$('next').addEventListener('click',()=>{page++;filter(false);});
$('failures-shortcut').addEventListener('click',()=>{reset();$('result').value='fail';filter();location.hash='evidence';$('result').focus({preventScroll:true});});
document.querySelectorAll('.case-jump').forEach(link=>link.addEventListener('click',()=>{reset();$('evaluation').value='llm';$('case').value=link.dataset.case;$('transport').value=link.dataset.transport;filter();}));
let inspectedRow=null;
function inspect(row){inspectedRow=row;$('inspector').classList.remove('wide');$('inspector-nav').hidden=false;
  $('inspector-body').replaceChildren($('evidence-'+row.dataset.index).content.cloneNode(true));
  const index=matching.indexOf(row);$('inspect-previous').disabled=index<=0;$('inspect-next').disabled=index<0||index===matching.length-1;
  if(!$('inspector').open)$('inspector').showModal();$('inspector').scrollTop=0;}
document.querySelectorAll('.inspect').forEach(button=>button.addEventListener('click',()=>inspect(button.closest('tr'))));
$('inspect-previous').addEventListener('click',()=>{const index=matching.indexOf(inspectedRow);if(index>0){inspect(matching[index-1]);($('inspect-previous').disabled?$('inspect-next'):$('inspect-previous')).focus();}});
$('inspect-next').addEventListener('click',()=>{const index=matching.indexOf(inspectedRow);if(index>=0&&index<matching.length-1){inspect(matching[index+1]);($('inspect-next').disabled?$('inspect-previous'):$('inspect-next')).focus();}});
$('export-filtered').addEventListener('click',()=>{const cell=SimlabData.csvCell;
const csv=[['case','evaluation','transport','server','seed','task_outcome','result'],...matching.map(row=>Array.from(row.cells).slice(0,7).map(td=>td.textContent.trim()))].map(row=>row.map(cell).join(',')).join('\r\n');
const url=URL.createObjectURL(new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'})),link=document.createElement('a');link.href=url;link.download='filtered-checks.csv';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});

// Pins span filters and pages; only explicit pin selections enter the comparison.
const pins=new Set();
function refreshPins(message=''){
  document.querySelectorAll('.pin-check').forEach(button=>{const selected=pins.has(button.dataset.index);button.setAttribute('aria-pressed',String(selected));button.textContent=selected?'Pinned':'Pin';});
  $('pin-status').textContent=message||pins.size+' of 2 checks pinned';$('compare-pins').disabled=pins.size!==2;
}
document.querySelectorAll('.pin-check').forEach(button=>button.addEventListener('click',()=>{
  const id=button.dataset.index;if(pins.has(id))pins.delete(id);else if(pins.size<2)pins.add(id);else{refreshPins('Two checks are pinned. Unpin one before adding another.');return;}refreshPins();
}));
$('clear-pins').addEventListener('click',()=>{pins.clear();refreshPins();});
$('compare-pins').addEventListener('click',()=>{if(pins.size!==2)return;
  const columns=document.createElement('div');columns.className='pinned-comparison';
  for(const id of pins){const article=document.createElement('article');article.append($('evidence-'+id).content.cloneNode(true));columns.append(article);}
  $('inspector-body').replaceChildren(columns);$('inspector-nav').hidden=true;$('inspector').classList.add('wide');$('inspector').showModal();$('inspector').scrollTop=0;
});

// Save only filter preferences, scoped to this report's content fingerprint.
const storageKey='simlab-views-'+document.body.dataset.runKey;let savedViews=[],persistent=true;
try{const stored=localStorage.getItem(storageKey);if(stored&&stored.length<200000){const parsed=JSON.parse(stored);if(Array.isArray(parsed))savedViews=parsed.filter(view=>view&&typeof view.name==='string'&&typeof view.id==='string'&&view.state&&typeof view.state==='object').slice(0,20);}}
catch{persistent=false;}
function viewsMessage(message){$('views-status').textContent=message+' · '+(persistent?'Saved on this browser for this report.':'Available for this tab; browser storage is unavailable.');}
function renderViews(selected=''){$('saved-views').replaceChildren(new Option('Choose a saved view',''));for(const view of savedViews)$('saved-views').add(new Option(view.name.slice(0,80),view.id));$('saved-views').value=selected;}
function persistViews(){try{localStorage.setItem(storageKey,JSON.stringify(savedViews));}catch{persistent=false;}}
function captureView(){return Object.fromEntries([...keys,'search','sort','page-size'].map(key=>[key,$(key).value]));}
$('save-view').addEventListener('click',()=>{const name=$('view-name').value.trim();if(!name){viewsMessage('Enter a view name first.');return;}
  let view=savedViews.find(item=>item.name===name);if(!view&&savedViews.length>=20){viewsMessage('20 views are saved. Delete one before saving another.');return;}
  if(!view){view={id:Date.now().toString(36)+'-'+Math.random().toString(36).slice(2,8),name,state:{}};savedViews.push(view);}view.state=captureView();persistViews();renderViews(view.id);viewsMessage('Saved view: '+name);
});
$('load-view').addEventListener('click',()=>{const view=savedViews.find(item=>item.id===$('saved-views').value);if(!view){viewsMessage('Choose a saved view first.');return;}
  for(const key of [...keys,'sort','page-size']){const control=$(key),value=view.state[key];if(typeof value==='string'&&Array.from(control.options).some(option=>option.value===value))control.value=value;}
  $('search').value=typeof view.state.search==='string'?view.state.search.slice(0,500):'';$('view-name').value=view.name;filter();viewsMessage('Applied view: '+view.name);
});
$('delete-view').addEventListener('click',()=>{const id=$('saved-views').value,view=savedViews.find(item=>item.id===id);if(!view){viewsMessage('Choose a saved view first.');return;}savedViews=savedViews.filter(item=>item.id!==id);persistViews();renderViews();viewsMessage('Deleted view: '+view.name);});
renderViews();viewsMessage(savedViews.length+' saved views');

// Imported reports remain local and are rendered exclusively through textContent.
const currentReport=JSON.parse($('run-data').textContent);let runComparison=null;
const rateText=metric=>metric.rate===null?'Not evaluated':metric.count+'/'+metric.total+' · '+(metric.rate*100).toFixed(1)+'%';
const deltaText=(left,right)=>left===null||right===null?'Not comparable':((left-right)*100>=0?'+':'')+((left-right)*100).toFixed(1)+' pp';
function addRow(body,values){const row=document.createElement('tr');values.forEach((value,index)=>{const cell=document.createElement(index===0?'th':'td');if(index===0)cell.scope='row';cell.textContent=String(value);row.append(cell);});body.append(row);}
function clearReference(){$('reference-file').value='';$('reference-results').hidden=true;$('reference-status').textContent='No reference loaded. Choose a saved report JSON.';$('reference-status').classList.remove('error-box');$('reference-status').setAttribute('role','status');$('export-comparison').disabled=true;runComparison=null;}
$('clear-reference').addEventListener('click',clearReference);
$('reference-file').addEventListener('change',async()=>{const file=$('reference-file').files[0];if(!file)return;
  $('reference-results').hidden=true;$('export-comparison').disabled=true;runComparison=null;
  try{if(file.size>20*1024*1024)throw new Error('Choose a report smaller than 20 MB.');
    const reference=SimlabData.validateReport(JSON.parse(await file.text()));runComparison=SimlabData.compare(currentReport,reference);
    const data=runComparison;$('run-metrics').replaceChildren();
    addRow($('run-metrics'),['Checks passed',data.current.passed+'/'+data.current.checks,data.reference.passed+'/'+data.reference.checks,'Different run sizes may apply']);
    for(const [key,label] of [['baseline','Baseline exploit effects'],['hardened','Hardened bypasses'],['tasks','Hardened task completion']])addRow($('run-metrics'),[label,rateText(data.current[key]),rateText(data.reference[key]),deltaText(data.current[key].rate,data.reference[key].rate)]);
    addRow($('run-metrics'),['Live errors',data.current.errors,data.reference.errors,(data.current.errors-data.reference.errors>=0?'+':'')+(data.current.errors-data.reference.errors)]);
    $('scope-notes').textContent='Current model: '+data.currentScope.model+'\nReference model: '+data.referenceScope.model+'\n'+(data.differences.length?'Scope differences: '+data.differences.join(', ')+'. Interpret deltas in that context.':'Recorded model, case, transport, seed, and grading scopes match. Independent model runs can still vary.')+'\n'+data.groups.filter(group=>group.current.total&&group.reference.total).length+' case/transport/arm groups have evaluated attempts in both runs. Seed pairing is not asserted.';
    $('run-case-changes').replaceChildren();for(const group of data.groups)addRow($('run-case-changes'),[group.case,group.transport,group.mode,rateText(group.current)+' · '+group.current.errors+' errors',rateText(group.reference)+' · '+group.reference.errors+' errors',group.delta===null?'Not comparable':(group.delta>=0?'+':'')+group.delta.toFixed(1)]);
    $('reference-status').textContent='Loaded '+file.name+' · '+reference.rows.length+' reference checks · local comparison only.';$('reference-status').classList.remove('error-box');$('reference-status').setAttribute('role','status');$('reference-results').hidden=false;$('export-comparison').disabled=false;
  }catch(error){$('reference-status').textContent='Could not load reference: '+(error instanceof SyntaxError?'The file is not valid JSON.':error.message);$('reference-status').classList.add('error-box');$('reference-status').setAttribute('role','alert');$('reference-file').value='';}
});
$('export-comparison').addEventListener('click',()=>{if(!runComparison)return;
  const csv=[['case','transport','arm','current_effects','current_evaluated','current_errors','reference_effects','reference_evaluated','reference_errors','delta_percentage_points'],...runComparison.groups.map(group=>[group.case,group.transport,group.mode,group.current.count,group.current.total,group.current.errors,group.reference.count,group.reference.total,group.reference.errors,group.delta??''])].map(row=>row.map(SimlabData.csvCell).join(',')).join('\r\n');
  const url=URL.createObjectURL(new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'})),link=document.createElement('a');link.href=url;link.download='run-comparison.csv';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
document.addEventListener('keydown',event=>{if(event.key==='/'&&!$('inspector').open&&!/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)){event.preventDefault();location.hash='evidence';$('search').focus();}});
if('IntersectionObserver' in window){const observer=new IntersectionObserver(entries=>{for(const entry of entries)if(entry.isIntersecting){document.querySelectorAll('.sidebar nav a').forEach(link=>{if(link.hash==='#'+entry.target.id)link.setAttribute('aria-current','location');else link.removeAttribute('aria-current');});}},{rootMargin:'-10% 0px -65% 0px'});document.querySelectorAll('main>section').forEach(section=>observer.observe(section));}
filter();
})();
