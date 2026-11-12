/* Pure report comparison helpers, also exercised by the Node test runner. */
(function(root){
'use strict';
function validateReport(value){
  if(!value||typeof value!=='object'||Array.isArray(value)||!Array.isArray(value.rows)||value.rows.length>40000)
    throw new Error('Choose a simulation report JSON containing at most 40,000 rows.');
  if(![1,2].includes(value.schema_version))throw new Error('Unsupported report schema. Choose a schema 1 or 2 simulation report.');
  for(const row of value.rows){
    if(!row||typeof row!=='object'||typeof row.passed!=='boolean'||!['protocol','llm'].includes(row.evaluation)||typeof row.case!=='string'
       ||(row.exploit_observed!==undefined&&typeof row.exploit_observed!=='boolean')
       ||(row.task!==undefined&&(!row.task||typeof row.task!=='object'||typeof row.task.completed!=='boolean')))
      throw new Error('The selected report contains an invalid result row.');
  }
  return value;
}
function stats(rows){
  const live=rows.filter(row=>row.evaluation==='llm');
  const rate=(arm,key)=>{const items=live.filter(row=>row.mode===arm&&(key==='exploit_observed'?typeof row[key]==='boolean':typeof row.task?.completed==='boolean'));
    const count=items.filter(row=>key==='exploit_observed'?row[key]:row.task.completed).length;
    return {count,total:items.length,rate:items.length?count/items.length:null};};
  return {checks:rows.length,passed:rows.filter(row=>row.passed).length,errors:live.filter(row=>Object.hasOwn(row,'error')).length,
    baseline:rate('vulnerable','exploit_observed'),hardened:rate('hardened','exploit_observed'),tasks:rate('hardened','task')};
}
function scope(report){
  const live=report.rows.filter(row=>row.evaluation==='llm');
  const distinct=key=>[...new Set(live.filter(row=>row[key]!==undefined).map(row=>String(row[key])))].sort();
  return {model:typeof report.model?.model==='string'?report.model.model:'Not recorded',
    cases:distinct('case'),transports:distinct('transport'),seeds:distinct('seed'),
    unrecordedSeeds:live.some(row=>row.seed===undefined),strict:report.experiment?.require_task_success??null};
}
function compare(current,reference){
  validateReport(current);validateReport(reference);
  const leftScope=scope(current),rightScope=scope(reference),differences=[];
  for(const key of ['model','cases','transports','seeds','strict'])if(JSON.stringify(leftScope[key])!==JSON.stringify(rightScope[key]))differences.push(key);
  if(leftScope.unrecordedSeeds||rightScope.unrecordedSeeds)differences.push('unrecorded seeds');
  const key=row=>JSON.stringify([row.case,row.transport??'',row.mode??'']);
  const group=report=>{const groups=new Map();for(const row of report.rows.filter(row=>row.evaluation==='llm')){
    const id=key(row);if(!groups.has(id))groups.set(id,[]);groups.get(id).push(row);}return groups;};
  const a=group(current),b=group(reference),groups=[];
  for(const id of [...new Set([...a.keys(),...b.keys()])].sort()){
    const [caseId,transport,mode]=JSON.parse(id);
    const metric=items=>{const evaluated=items.filter(row=>typeof row.exploit_observed==='boolean'),count=evaluated.filter(row=>row.exploit_observed).length;
      return {count,total:evaluated.length,rate:evaluated.length?count/evaluated.length:null,errors:items.filter(row=>Object.hasOwn(row,'error')).length};};
    const left=metric(a.get(id)??[]),right=metric(b.get(id)??[]);
    groups.push({case:caseId,transport,mode,current:left,reference:right,delta:left.rate===null||right.rate===null?null:(left.rate-right.rate)*100});
  }
  return {current:stats(current.rows),reference:stats(reference.rows),currentScope:leftScope,referenceScope:rightScope,differences,groups};
}
function parseQuery(query){
  const tokens=[];let token='',quoted=false;
  for(const character of query.trim()){
    if(character==='"'){quoted=!quoted;token+=character;}
    else if(/\s/.test(character)&&!quoted){if(token){tokens.push(token);token='';}}
    else token+=character;
  }
  if(quoted)throw new Error('Close the quotation mark to finish your search.');
  if(token)tokens.push(token);
  const allowed=['case','tool','seed','transport','mode','result','evaluation','outcome','review','note'];
  return tokens.map(raw=>{
    const exclude=raw.startsWith('-');if(exclude)raw=raw.slice(1);
    const colon=raw.indexOf(':');let field=null;
    if(colon>0){field=raw.slice(0,colon).toLowerCase();raw=raw.slice(colon+1);if(!allowed.includes(field))throw new Error('Unknown search field: '+field);}
    if(raw.startsWith('"')&&raw.endsWith('"'))raw=raw.slice(1,-1);
    if(!raw||raw.includes('"'))throw new Error('Use a word or a quoted phrase after each search field.');
    return {field,value:raw.toLowerCase(),exclude};
  });
}
function matchesQuery(fields,terms){
  const exact=new Set(['seed','transport','mode','result','evaluation','outcome','review']);
  return terms.every(term=>{
    const haystack=String(term.field?fields[term.field]??'':Object.values(fields).join(' ')).toLowerCase();
    const match=term.field&&exact.has(term.field)?haystack===term.value:haystack.includes(term.value);
    return term.exclude?!match:match;
  });
}
function cleanViewState(state){
  if(!state||typeof state!=='object'||Array.isArray(state))throw new Error('Invalid saved view state.');
  const clean={};for(const key of ['result','evaluation','mode','transport','seed','case','outcome','search','sort','page-size','review-filter']){
    if(Object.hasOwn(state,key)){if(typeof state[key]!=='string'||state[key].length>500)throw new Error('Invalid saved view preference.');clean[key]=state[key];}}
  return clean;
}
function validateWorkspace(value,reportKey,rowCount){
  if(!value||value.version!==1||value.reportKey!==reportKey)throw new Error('Choose a review workspace exported from this report.');
  if(!Array.isArray(value.notes)||!Array.isArray(value.views)||!Array.isArray(value.pins)||!Array.isArray(value.hiddenColumns)||value.notes.length>rowCount||value.views.length>20||value.pins.length>2)throw new Error('Invalid review workspace structure.');
  const validIndex=id=>Number.isInteger(id)&&id>=0&&id<rowCount,seen=new Set();
  const notes=value.notes.map(entry=>{if(!entry||!validIndex(entry.index)||seen.has(entry.index)||!['unreviewed','followup','resolved'].includes(entry.status)||typeof entry.note!=='string'||entry.note.length>4000)throw new Error('Invalid review note.');seen.add(entry.index);return {index:entry.index,status:entry.status,note:entry.note};});
  const ids=new Set();const views=value.views.map(view=>{if(!view||typeof view.id!=='string'||!view.id||view.id.length>80||ids.has(view.id)||typeof view.name!=='string'||!view.name.trim()||view.name.length>80)throw new Error('Invalid saved view.');ids.add(view.id);return {id:view.id,name:view.name,state:cleanViewState(view.state)};});
  if(value.pins.some(id=>!validIndex(id))||new Set(value.pins).size!==value.pins.length||value.hiddenColumns.some(index=>!Number.isInteger(index)||index<1||index>7))throw new Error('Invalid pinned checks or columns.');
  return {version:1,reportKey,notes,views,pins:[...value.pins],hiddenColumns:[...new Set(value.hiddenColumns)],state:cleanViewState(value.state)};
}
function csvCell(value){value=String(value);if(/^[=+@\-\t\r]/.test(value))value="'"+value;return '"'+value.replace(/"/g,'""')+'"';}
function collectRecoveryTraces(evidence){
  const traces=[],seen=new WeakSet(),fingerprints=new Set(),stack=[{value:evidence,depth:0}];let visited=0,limited=false,invalid=0;
  const integer=(value,min=0)=>Number.isSafeInteger(value)&&value>=min;
  const text=value=>typeof value==='string'&&value.length>0&&value.length<=128;
  while(stack.length){
    if(++visited>100000){limited=true;break;}
    const {value,depth}=stack.pop();if(!value||typeof value!=='object'||seen.has(value))continue;seen.add(value);
    if(depth>24){limited=true;continue;}
    const candidate=typeof value.record_id==='string'&&Object.hasOwn(value,'max_parallel')&&(Array.isArray(value.attempts)||Array.isArray(value.events));
    if(candidate){
      const resilience=Array.isArray(value.attempts),raw=resilience?value.attempts:value.events,horizon=resilience?value.elapsed_ms:value.makespan_ms;
      let valid=text(value.record_id)&&integer(value.max_parallel,1)&&value.max_parallel<=16&&integer(horizon)&&raw.length<=(resilience?1024:256)
        &&(!resilience||typeof value.completed==='boolean');
      const events=[];
      if(valid)for(let index=0;index<raw.length;index++){
        const item=raw[index];if(!item||typeof item!=='object'){valid=false;break;}
        const outcome=resilience?item.outcome:'succeeded',reason=resilience?item.reason:'none',attempt=resilience?item.attempt:1;
        if(!text(item.record_id)||!['investigating','resolved'].includes(item.status)||!integer(item.expected_version,1)||!integer(item.worker)
          ||item.worker>=value.max_parallel||!integer(item.start_ms)||!integer(item.end_ms)||item.end_ms<=item.start_ms||item.end_ms>horizon
          ||!integer(attempt,1)||attempt>4||!['succeeded','retry','exhausted'].includes(outcome)||!['none','injected_failure','worker_outage'].includes(reason)){valid=false;break;}
        events.push({index,record_id:item.record_id,status:item.status,expected_version:item.expected_version,worker:item.worker,
          start_ms:item.start_ms,end_ms:item.end_ms,attempt,outcome,reason});
      }
      if(!valid){invalid++;continue;}
      const trace={record_id:value.record_id,workers:value.max_parallel,horizon_ms:horizon,kind:resilience?'resilience':'timed',
        completed:resilience?value.completed:null,events};
      const fingerprint=JSON.stringify(trace);if(!fingerprints.has(fingerprint)){
        if(traces.length===48){limited=true;break;}fingerprints.add(fingerprint);traces.push(trace);
      }
      continue;
    }
    let children=Object.values(value);if(children.length>100000){children=children.slice(0,100000);limited=true;}
    for(let index=children.length-1;index>=0;index--)stack.push({value:children[index],depth:depth+1});
  }
  return {traces,limited,invalid};
}
function filterRecoveryEvents(trace,{incident='',outcome='all'}={}){
  const query=String(incident).trim().toLowerCase().slice(0,128);
  return (trace?.events??[]).filter(event=>event.record_id.toLowerCase().includes(query)&&(outcome==='all'||event.outcome===outcome))
    .slice().sort((a,b)=>a.start_ms-b.start_ms||a.worker-b.worker||a.index-b.index);
}
function recoveryCsv(trace,events=trace.events){
  const columns=['trace_record_id','trace_kind','worker','record_id','status','attempt','expected_version','start_ms','end_ms','outcome','reason'];
  return [columns,...events.map(event=>[trace.record_id,trace.kind,event.worker,event.record_id,event.status,event.attempt,event.expected_version,
    event.start_ms,event.end_ms,event.outcome,event.reason])].map(row=>row.map(csvCell).join(',')).join('\r\n');
}
const api={validateReport,stats,scope,compare,csvCell,parseQuery,matchesQuery,validateWorkspace,collectRecoveryTraces,filterRecoveryEvents,recoveryCsv};
if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.SimlabData=api;
})(globalThis);
