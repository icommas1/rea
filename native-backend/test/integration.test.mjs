import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {join} from 'node:path';
import {analyze} from '../src/adapter.mjs';
const enabled=process.env.REA_INTEGRATION==='1';
test('official REA parses ELF object with real symbols and relocations', {skip:!enabled}, async()=>{
 const root=await mkdtemp('/tmp/rea-integration-');
 try{
  const path=join(root,'fixture.o');
  execFileSync('cc',['-c','-O0','-o',path,new URL('./fixture.c',import.meta.url).pathname]);
  const value=await analyze(path,{root,signal:AbortSignal.timeout(15000)});
  assert.equal(value.layout.format,'elf');assert.equal(value.layout.image_type,'ET_REL');
  assert.ok(value.layout.sections.length>0);assert.ok(value.layout.relocations.length>0);
  assert.ok(JSON.stringify(value.layout.symbols).includes('rea_fixture_add'));
  assert.equal(value.artifact.bytes,(await readFile(path)).length);
  assert.ok(!JSON.stringify(value).includes(root));
 }finally{await rm(root,{recursive:true,force:true})}
});
test('official REA rejects structurally malformed ELF within deadline', {skip:!enabled}, async()=>{
 const root=await mkdtemp('/tmp/rea-malformed-');
 try{const path=join(root,'invalid.elf');await writeFile(path,Buffer.from('not ELF'));await assert.rejects(analyze(path,{root,signal:AbortSignal.timeout(15000)}));}
 finally{await rm(root,{recursive:true,force:true})}
});
test('real cancellation verifies provider process cleanup after interpreter exec', {skip:!enabled}, async()=>{
 const root=await mkdtemp('/tmp/rea-cancel-');
 try {await assert.rejects(analyze('/usr/bin/true',{root,signal:AbortSignal.timeout(50)}),error=>!error.cleanupIncomplete && error.code==='AnalysisCancelledError');}
 finally{await rm(root,{recursive:true,force:true})}
});
test('real HTTP cancellation keeps service healthy and accepting requests', {skip:!enabled}, async()=>{
 const {createServer}=await import('../src/server.mjs');
 const root=await mkdtemp('/tmp/rea-http-cancel-');
 const key='TEST_ONLY_NOT_A_DEPLOYMENT_CREDENTIAL_000000000';
 const server=createServer({key,tempParent:root,analysisTimeoutMs:50});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const base=`http://127.0.0.1:${server.address().port}`;
 try {
   const r=await fetch(base+'/v1/analyze',{method:'POST',headers:{authorization:`Bearer ${key}`,'content-type':'application/octet-stream'},body:await readFile('/usr/bin/true')});
   assert.equal(r.status,504);
   assert.equal((await fetch(base+'/healthz')).status,200);
   const next=await fetch(base+'/v1/analyze',{method:'POST',headers:{authorization:`Bearer ${key}`,'content-type':'application/octet-stream'},body:Buffer.from('invalid')});
   assert.equal(next.status,422);
 }finally {await new Promise(r=>server.close(r));await rm(root,{recursive:true,force:true})}
});
