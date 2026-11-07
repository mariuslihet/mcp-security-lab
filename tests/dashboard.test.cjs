const test=require('node:test');
const assert=require('node:assert/strict');
const {validateReport,compare,csvCell}=require('../simlab/dashboard-data.js');
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
