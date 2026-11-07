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
function csvCell(value){value=String(value);if(/^[=+@\-\t\r]/.test(value))value="'"+value;return '"'+value.replace(/"/g,'""')+'"';}
const api={validateReport,stats,scope,compare,csvCell};
if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.SimlabData=api;
})(globalThis);
