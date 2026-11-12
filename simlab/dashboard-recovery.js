(()=>{
let serial=0;
function element(tag,text='',className=''){const node=document.createElement(tag);node.textContent=text;if(className)node.className=className;return node;}
function mount(container){
  const recorded=container.querySelector('.recorded-result');if(!recorded)return;
  const section=element('section','','recovery-viewer');let found;
  try{if(recorded.textContent.length>32*1024*1024)throw new Error('large');found=SimlabData.collectRecoveryTraces(JSON.parse(recorded.textContent));}
  catch{section.append(element('p','The recovery viewer could not read this evidence. Full recorded evidence remains below.','helper'));container.append(section);return;}
  if(!found.traces.length)return;
  const prefix='recovery-'+(++serial)+'-',heading=element('h3','Recovery timeline');heading.id=prefix+'heading';section.setAttribute('aria-labelledby',heading.id);section.append(heading);
  section.append(element('p','Times are simulated milliseconds. Filters keep the original time scale. Select an attempt below for details.','helper'));
  const controls=element('div','','recovery-controls');
  function field(label,node,name){node.id=prefix+name;const box=element('div','','field'),caption=element('label',label);caption.htmlFor=node.id;box.append(caption,node);controls.append(box);return node;}
  const source=field('Recovery trace',element('select'),'source');
  found.traces.forEach((trace,index)=>{const option=element('option','Trace '+(index+1)+' · '+trace.record_id+' · '+(trace.kind==='timed'?'timed schedule':'recovery attempts'));option.value=String(index);source.append(option);});
  const incident=field('Find incident',element('input'),'incident');incident.type='search';incident.maxLength=128;
  const outcome=field('Attempt outcome',element('select'),'outcome');
  for(const [value,label] of [['all','All outcomes'],['succeeded','Succeeded'],['retry','Retry needed'],['exhausted','Attempts exhausted']]){const option=element('option',label);option.value=value;outcome.append(option);}
  section.append(controls);
  const summary=element('p','','helper'),status=element('p','','helper');status.setAttribute('role','status');status.setAttribute('aria-live','polite');section.append(summary,status);
  if(found.limited||found.invalid)section.append(element('p','This view contains '+found.traces.length+' unique supported traces.'+(found.limited?' Additional data exceeds the viewer limits.':'')+(found.invalid?' Some trace-shaped data was malformed.':'')+' Full evidence remains below.','helper'));
  const chart=element('div','','recovery-chart');chart.setAttribute('role','img');section.append(chart);
  const key=element('p','Succeeded · green   |   Retry needed · amber   |   Attempts exhausted · red','helper');section.append(key);
  const actions=element('div','','actions'),previous=element('button','Previous attempts'),pageLabel=element('span'),next=element('button','Next attempts'),download=element('button','Export filtered attempts CSV');
  actions.append(previous,pageLabel,next,download);section.append(actions);
  const scroll=element('div','','scroll');scroll.tabIndex=0;scroll.setAttribute('role','region');scroll.setAttribute('aria-label','Recorded recovery attempts');
  const table=element('table'),caption=element('caption','Recorded recovery attempts · simulated milliseconds'),head=element('thead'),header=element('tr');
  for(const label of ['Incident / attempt','Phase','Worker','Start','End','Outcome']){const cell=element('th',label);cell.scope='col';header.append(cell);}head.append(header);
  const body=element('tbody');table.append(caption,head,body);scroll.append(table);section.append(scroll);
  const detail=element('div','','recovery-detail');detail.setAttribute('aria-live','polite');section.append(detail);
  let page=1,filtered=[],selected=null;
  const trace=()=>found.traces[Number(source.value)];
  function selectEvent(event){
    selected=event?.index??null;detail.replaceChildren();
    if(!event){detail.append(element('p',trace().events.length?'No matching attempts.':'No attempts were recorded in this trace.','helper'));return;}
    detail.append(element('h4',event.record_id+' · attempt '+event.attempt));const list=element('dl');
    for(const [label,value] of [['Phase',event.status],['Worker',event.worker],['Expected version',event.expected_version],['Time',event.start_ms+'–'+event.end_ms+' simulated ms'],['Outcome',event.outcome],['Reason',event.reason]]){
      const item=element('div');item.append(element('dt',label),element('dd',String(value)));list.append(item);
    }detail.append(list);
    for(const button of body.querySelectorAll('button'))button.setAttribute('aria-pressed',String(Number(button.dataset.event)===selected));
  }
  function drawPage(){
    const pages=Math.max(1,Math.ceil(filtered.length/25));page=Math.min(page,pages);body.replaceChildren();
    for(const event of filtered.slice((page-1)*25,page*25)){
      const row=element('tr'),cell=element('td'),button=element('button',event.record_id+' · '+event.attempt,'recovery-event-button');button.dataset.event=String(event.index);
      button.setAttribute('aria-pressed',String(event.index===selected));button.addEventListener('click',()=>selectEvent(event));cell.append(button);row.append(cell);
      for(const value of [event.status,event.worker,event.start_ms,event.end_ms,event.outcome])row.append(element('td',String(value)));body.append(row);
    }
    pageLabel.textContent='Page '+page+' of '+pages;previous.disabled=page===1;next.disabled=page===pages;
  }
  function draw(reset=true){
    if(reset)page=1;const current=trace();filtered=SimlabData.filterRecoveryEvents(current,{incident:incident.value,outcome:outcome.value});
    summary.textContent=current.record_id+' · '+current.workers+' workers · '+current.horizon_ms+' simulated ms'+(current.completed===null?'':current.completed?' · recovery completed':' · recovery unfinished');
    status.textContent=filtered.length+' of '+current.events.length+' recorded attempts match';chart.replaceChildren();
    chart.setAttribute('aria-label','Worker timeline for '+filtered.length+' matching attempts over '+current.horizon_ms+' simulated milliseconds. The table below provides details.');
    const axis=element('div','','recovery-axis');axis.append(element('span','0 ms'),element('span',current.horizon_ms+' ms'));chart.append(axis);
    for(let worker=0;worker<current.workers;worker++){
      const lane=element('div','','recovery-lane'),label=element('span','Worker '+worker),track=element('div','','recovery-track');
      for(const event of filtered.filter(item=>item.worker===worker)){
        const bar=element('span','','recovery-bar '+event.outcome);bar.style.left=(100*event.start_ms/(current.horizon_ms||1))+'%';bar.style.width=(100*(event.end_ms-event.start_ms)/(current.horizon_ms||1))+'%';
        bar.title=event.record_id+' · '+event.status+' · attempt '+event.attempt+' · '+event.start_ms+'–'+event.end_ms+' ms · '+event.outcome;track.append(bar);
      }lane.append(label,track);chart.append(lane);
    }
    download.disabled=filtered.length===0;selectEvent(filtered[0]);drawPage();
  }
  source.addEventListener('change',()=>{incident.value='';outcome.value='all';draw();});incident.addEventListener('input',()=>draw());outcome.addEventListener('change',()=>draw());
  previous.addEventListener('click',()=>{page--;drawPage();});next.addEventListener('click',()=>{page++;drawPage();});
  download.addEventListener('click',()=>{const url=URL.createObjectURL(new Blob(['\ufeff'+SimlabData.recoveryCsv(trace(),filtered)],{type:'text/csv;charset=utf-8'})),link=element('a');link.href=url;link.download='recovery-attempts.csv';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  const anchor=container.querySelector('.recovery-resource-summary')??container.querySelector('.evidence-links');container.insertBefore(section,anchor?.nextSibling??recorded.closest('details'));draw();
}
globalThis.SimlabRecovery={mount};
})();
