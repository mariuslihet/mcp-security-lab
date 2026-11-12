const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {JSDOM}=require('jsdom');

function trace(count=30){return {record_id:'GR-003',max_parallel:2,elapsed_ms:count,completed:true,attempts:Array.from({length:count},(_,index)=>({
  record_id:'GR-'+String(index).padStart(3,'0'),status:'investigating',expected_version:1,attempt:1,
  worker:index%2,start_ms:index,end_ms:index+1,outcome:'succeeded',reason:'none'}))};}
function harness(){
  // No browser, URL navigation, resource loader, or report upload is involved.
  const dom=new JSDOM('<!doctype html><body><main></main>',{runScripts:'outside-only'});
  for(const name of ['dashboard-data.js','dashboard-recovery.js'])dom.window.eval(fs.readFileSync(path.join(__dirname,'../simlab',name),'utf8'));
  const {document}=dom.window;
  function mount(evidence){
    const article=document.createElement('article'),heading=document.createElement('h2'),links=document.createElement('div'),details=document.createElement('details'),pre=document.createElement('pre');
    heading.textContent='Recorded check';links.className='evidence-links';pre.className='recorded-result';pre.textContent=JSON.stringify(evidence);
    details.append(pre);article.append(heading,links,details);document.querySelector('main').append(article);dom.window.SimlabRecovery.mount(article);
    return article;
  }
  const field=(root,name)=>Array.from(root.querySelectorAll('label')).find(label=>label.textContent===name)?.control;
  const button=(root,name)=>Array.from(root.querySelectorAll('button')).find(button=>button.textContent===name);
  const change=(node,type='change')=>node.dispatchEvent(new dom.window.Event(type,{bubbles:true}));
  return {dom,document,mount,field,button,change};
}

test('viewer pagination, incident filters and empty results operate on recorded evidence',()=>{
  const h=harness();try{
    const root=h.mount({responses:[{structuredContent:trace()}]}),table=root.querySelector('.recovery-viewer table');
    assert.equal(table.tBodies[0].rows.length,25);
    h.button(root,'Next attempts').click();assert.equal(table.tBodies[0].rows.length,5);
    const incident=h.field(root,'Find incident');incident.value='GR-029';h.change(incident,'input');
    assert.equal(table.tBodies[0].rows.length,1);assert.equal(h.button(root,'Next attempts').disabled,true);
    const outcome=h.field(root,'Attempt outcome');outcome.value='retry';h.change(outcome);
    assert.equal(table.tBodies[0].rows.length,0);assert.equal(h.button(root,'Export filtered attempts CSV').disabled,true);
    assert.ok(root.textContent.includes('No matching attempts.'));
  }finally{h.dom.window.close();}
});

test('trace changes reset local filters and retain immutable source evidence',()=>{
  const h=harness();try{
    const data={responses:[{structuredContent:trace(30)},{structuredContent:trace(2)}]},root=h.mount(data);
    h.field(root,'Find incident').value='not-present';h.change(h.field(root,'Find incident'),'input');
    const selector=h.field(root,'Recovery trace');assert.equal(selector.options.length,2);selector.value='1';h.change(selector);
    assert.equal(h.field(root,'Find incident').value,'');assert.equal(root.querySelector('table').tBodies[0].rows.length,2);
    assert.equal(root.querySelector('.recorded-result').textContent,JSON.stringify(data));
  }finally{h.dom.window.close();}
});

test('attempt selection preserves focus and exposes versions and outcomes through text',()=>{
  const h=harness();try{
    const root=h.mount({trace:trace(3)}),buttons=root.querySelectorAll('.recovery-event-button'),chosen=buttons[1];
    chosen.focus();chosen.click();assert.equal(h.document.activeElement,chosen);assert.equal(chosen.getAttribute('aria-pressed'),'true');
    assert.equal(buttons[0].getAttribute('aria-pressed'),'false');
    const detail=root.querySelector('.recovery-detail');assert.ok(detail.textContent.includes('GR-001'));
    assert.ok(detail.textContent.includes('Expected version'));assert.ok(detail.textContent.includes('succeeded'));
    for(const label of root.querySelectorAll('label'))assert.ok(label.control,'each control has an associated label');
  }finally{h.dom.window.close();}
});

test('empty completed traces have no invented work or enabled CSV download',()=>{
  const h=harness();try{
    const root=h.mount({trace:trace(0)});
    assert.equal(root.querySelectorAll('.recovery-bar').length,0);
    assert.equal(h.button(root,'Export filtered attempts CSV').disabled,true);
    assert.ok(root.textContent.includes('No attempts were recorded'));
  }finally{h.dom.window.close();}
});

test('pinned-style inspector panes retain independent controls and unique labels',()=>{
  const h=harness();try{
    const left=h.mount({trace:trace(3)}),right=h.mount({trace:trace(4)});
    h.field(left,'Find incident').value='not-present';h.change(h.field(left,'Find incident'),'input');
    assert.equal(left.querySelector('table').tBodies[0].rows.length,0);assert.equal(right.querySelector('table').tBodies[0].rows.length,4);
    const ids=Array.from(h.document.querySelectorAll('label'),label=>label.htmlFor);assert.equal(new Set(ids).size,ids.length);
  }finally{h.dom.window.close();}
});

test('hostile identifiers render as text rather than creating executable elements',()=>{
  const h=harness();try{
    const value=trace(1),payload='<img src=x onerror="globalThis.injected=1">';value.record_id=payload;value.attempts[0].record_id=payload;
    const root=h.mount({trace:value});assert.equal(root.querySelector('img'),null);assert.equal(h.dom.window.injected,undefined);
    assert.ok(root.textContent.includes(payload));
  }finally{h.dom.window.close();}
});

test('CSV export includes all filtered attempts without triggering a real download',async()=>{
  const h=harness();try{
    let captured=null,clicked=null;h.dom.window.Blob=Blob;
    h.dom.window.URL.createObjectURL=blob=>{captured=blob;return 'blob:offline-test';};h.dom.window.URL.revokeObjectURL=()=>{};
    h.dom.window.HTMLAnchorElement.prototype.click=function(){clicked={name:this.download,url:this.href};};
    const root=h.mount({trace:trace(30)}),incident=h.field(root,'Find incident');incident.value='GR-00';h.change(incident,'input');
    h.button(root,'Export filtered attempts CSV').click();assert.equal(clicked.name,'recovery-attempts.csv');
    const csv=await captured.text();assert.equal(csv.split('\r\n').length,11);assert.ok(csv.includes('GR-009'));assert.ok(!csv.includes('GR-010'));
  }finally{h.dom.window.close();}
});
