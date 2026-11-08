const test=require('node:test');
const assert=require('node:assert/strict');
const {validateReport,compare,csvCell,parseQuery,matchesQuery,validateWorkspace}=require('../simlab/dashboard-data.js');
const report=rows=>({schema_version:2,model:{model:'local'},rows});
const row=(mode,seed,effect)=>({case:'output_poison',evaluation:'llm',transport:'stdio',mode,seed,passed:true,exploit_observed:effect});

test('comparison preserves denominators and separates errors from evaluated attempts',()=>{
  const current=report([row('vulnerable',7,true),row('hardened',7,false),{case:'output_poison',evaluation:'llm',transport:'stdio',mode:'hardened',seed:11,passed:false,error:'timeout'}]);
  const reference=report([row('vulnerable',7,false),{...row('hardened',7,false),task:{completed:true}}]);
  const result=compare(current,reference);
  assert.equal(result.current.errors,1);
  assert.deepEqual(result.current.hardened,{count:0,total:1,rate:0});
  assert.equal(result.current.tasks.rate,null);
  assert.equal(result.reference.tasks.rate,1);
  assert.equal(result.groups.find(group=>group.mode==='vulnerable').delta,100);
  assert.ok(result.differences.includes('seeds'));
});

test('unmatched cases and absent task rubrics are not treated as zero-rate evaluations',()=>{
  const left=report([row('vulnerable',7,true)]),right=report([{...row('hardened',7,false),case:'different_case'}]);
  const result=compare(left,right);
  assert.equal(result.groups.length,2);
  assert.ok(result.groups.every(group=>group.delta===null));
  assert.equal(result.current.tasks.rate,null);
});

test('schema 1 reports with unrecorded seeds retain that scope limitation',()=>{
  const legacy=report([row('vulnerable',7,true)]);legacy.schema_version=1;delete legacy.rows[0].seed;
  const result=compare(report([row('vulnerable',7,true)]),legacy);
  assert.ok(result.differences.includes('unrecorded seeds'));
});

test('invalid reference inputs are rejected instead of producing misleading rates',()=>{
  for(const value of [null,[],{schema_version:9,rows:[]},{schema_version:2,rows:[{passed:'true'}]},report([{...row('vulnerable',7,true),exploit_observed:'yes'}]),report([{...row('hardened',7,false),task:{completed:'true'}}])]){
    assert.throws(()=>validateReport(value));
  }
  assert.doesNotThrow(()=>validateReport(report([])));
});

test('CSV text is quoted and spreadsheet formulas are treated as data',()=>{
  assert.equal(csvCell('=HYPERLINK("x")'),'"\'=HYPERLINK(""x"")"');
  assert.equal(csvCell('a,b'),'"a,b"');
});

test('search combines field terms, phrases, and exclusions without partial seed matches',()=>{
  const fields={case:'tool_shadow',tool:'sim_calculate',seed:'7',mode:'hardened',result:'pass',review:'followup',note:'Check arithmetic result'};
  assert.equal(matchesQuery(fields,parseQuery('mode:hardened tool:calculate note:"arithmetic result" -review:resolved')),true);
  assert.equal(matchesQuery({...fields,seed:'17'},parseQuery('seed:7')),false);
  assert.equal(matchesQuery(fields,parseQuery('-result:pass')),false);
  assert.equal(matchesQuery(fields,parseQuery('"arithmetic result"')),true);
  assert.equal(matchesQuery(fields,parseQuery('seed:7 note:missing')),false);
  assert.equal(matchesQuery(fields,parseQuery('')),true);
});

test('invalid search reports actionable syntax errors',()=>{
  for(const query of ['note:"unfinished','unknown:value','tool:','-'])assert.throws(()=>parseQuery(query));
});

const workspace=()=>({version:1,reportKey:'run-a',notes:[{index:0,status:'followup',note:'<script>literal note</script>'}],views:[{id:'a',name:'Follow-ups',state:{'review-filter':'followup',search:'tool:calculate'}}],pins:[0,1],hiddenColumns:[1,2],state:{mode:'all',search:'review:followup'}});
test('review exports round-trip preferences and literal notes only for the matching report',()=>{
  const value=workspace(),restored=validateWorkspace(JSON.parse(JSON.stringify(value)),'run-a',2);
  assert.deepEqual(restored,value);
  assert.throws(()=>validateWorkspace(value,'other-run',2));
  assert.throws(()=>validateWorkspace({...value,notes:[{index:2,status:'followup',note:'x'}]},'run-a',2));
  assert.throws(()=>validateWorkspace({...value,pins:[0,0]},'run-a',2));
});

test('malformed review data is rejected before it can replace an existing workspace',()=>{
  const value=workspace();
  for(const change of [{notes:[{index:0,status:'anything',note:'x'}]},{notes:[{index:0,status:'resolved',note:'x'.repeat(4001)}]},{hiddenColumns:[0]},{views:[{id:'a',name:'x',state:{search:123}}]},{state:[]},{pins:[0,1,2]}]){
    assert.throws(()=>validateWorkspace({...value,...change},'run-a',3));
  }
  assert.equal(value.notes[0].status,'followup');
});
