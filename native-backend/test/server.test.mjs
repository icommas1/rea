import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readdir} from 'node:fs/promises';
import {createServer} from '../src/server.mjs';
const key='TEST_ONLY_NOT_A_DEPLOYMENT_CREDENTIAL_000000000';
const head=Buffer.alloc(64); head.write('\x7fELF',0,'binary');head[4]=2;head[5]=1;head.writeUInt16LE(62,18);head.writeUInt16LE(1,16);
async function setup(t,options={}){
 const tempParent=await mkdtemp('/tmp/rea-http-test-');
 const server=createServer({key,tempParent,runAnalysis:async()=>({layout:{format:'elf'}}),...options});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 t.after(async()=>{await new Promise(r=>server.close(r));await rm(tempParent,{recursive:true,force:true});});
 const base=`http://127.0.0.1:${server.address().port}`;
 const post=(body=head,headers={})=>fetch(base+'/v1/analyze',{method:'POST',headers:{authorization:`Bearer ${key}`,'content-type':'application/octet-stream',...headers},body});
 return{base,post,tempParent};
}
test('auth missing fails closed but health is available',async t=>{const{base,post}=await setup(t,{key:undefined});assert.equal((await post()).status,503);assert.equal((await (await fetch(base+'/healthz')).json()).analysisEnabled,false)});
test('short auth key fails closed',async t=>{const{post}=await setup(t,{key:'short'});assert.equal((await post()).status,503)});
test('invalid bearer and oai headers rejected',async t=>{const{base,post}=await setup(t);assert.equal((await post(head,{authorization:'Bearer bad','oai-user-id':'admin'})).status,401);assert.equal((await fetch(base+'/v1/capabilities')).status,401)});
test('successful upload and cleanup',async t=>{const{post,tempParent}=await setup(t);const r=await post();assert.equal(r.status,200);assert.equal((await r.json()).ok,true);assert.deepEqual(await readdir(tempParent),[])});
test('unsupported bytes, architecture, encoding and paths rejected',async t=>{const{post,base}=await setup(t);assert.equal((await post(Buffer.from('not ELF'))).status,422);const arm=Buffer.from(head);arm.writeUInt16LE(183,18);assert.equal((await post(arm)).status,415);assert.equal((await post(head,{'content-encoding':'gzip'})).status,415);assert.equal((await fetch(base+'/v1/analyze?path=/etc/passwd',{method:'POST',headers:{authorization:`Bearer ${key}`}})).status,404)});
test('oversized upload rejected',async t=>{const{post}=await setup(t);assert.equal((await post(Buffer.alloc(4*1024*1024+1))).status,413)});
test('oversized output rejected completely',async t=>{const{post}=await setup(t,{runAnalysis:async()=>({data:'a'.repeat(2*1024*1024)})});assert.equal((await post()).status,422)});
test('analysis errors sanitized and files cleaned',async t=>{const{post,tempParent}=await setup(t,{runAnalysis:async()=>{throw new Error('/secret/path secret-token')}});const r=await post();assert.equal(r.status,500);assert.ok(!(await r.text()).includes('secret'));await new Promise(r=>setTimeout(r,20));assert.deepEqual(await readdir(tempParent),[])});
test('concurrency one includes upload/analysis; next request rejected',async t=>{let release,started;const ready=new Promise(r=>started=r);const gate=new Promise(r=>release=r);const{post}=await setup(t,{runAnalysis:async()=>{started();await gate;return{}}});const first=post();await ready;assert.equal((await post()).status,429);release();assert.equal((await first).status,200)});
test('analysis timeout cancels parser and cleans files',async t=>{const{post,tempParent}=await setup(t,{analysisTimeoutMs:10,runAnalysis:async(path,{signal})=>new Promise(resolve=>signal.addEventListener('abort',()=>resolve({}),{once:true}))});assert.equal((await post()).status,504);await new Promise(r=>setTimeout(r,20));assert.deepEqual(await readdir(tempParent),[])});
test('uncertain parser cleanup disables all subsequent analysis',async t=>{const{post,base}=await setup(t,{runAnalysis:async()=>{throw Object.assign(new Error('cleanup failed'),{cleanupIncomplete:true,status:503,code:'cleanup_incomplete'})}});assert.equal((await post()).status,503);const h=await fetch(base+'/healthz');assert.equal(h.status,503);assert.equal((await h.json()).analysisEnabled,false);assert.equal((await post()).status,503)});
test('uncertain parser ownership retains files until verified shutdown cleanup',async()=>{
 const tempParent=await mkdtemp('/tmp/rea-retained-');let canClose=false;
 const server=createServer({key,tempParent,runAnalysis:async()=>{throw Object.assign(new Error('owned'),{cleanupIncomplete:true,status:503,code:'cleanup_incomplete'});},cleanupAnalysis:async()=>{if(!canClose)throw Error('still owned');}});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try {
  const response=await fetch(`http://127.0.0.1:${server.address().port}/v1/analyze`,{method:'POST',headers:{authorization:`Bearer ${key}`,'content-type':'application/octet-stream'},body:head});
  assert.equal(response.status,503);assert.equal((await readdir(tempParent)).length,1);
  await assert.rejects(server.closeAnalysis());assert.equal((await readdir(tempParent)).length,1);
  canClose=true;await server.closeAnalysis();assert.deepEqual(await readdir(tempParent),[]);
 }finally{await new Promise(r=>server.close(r));await rm(tempParent,{recursive:true,force:true});}
});
test('shutdown cancellation reaches current parser',async t=>{let started;const ready=new Promise(r=>started=r);const tempParent=await mkdtemp('/tmp/rea-stop-test-');const server=createServer({key,tempParent,runAnalysis:async(path,{signal})=>new Promise(resolve=>{started();signal.addEventListener('abort',()=>resolve({}),{once:true})})});await new Promise(r=>server.listen(0,'127.0.0.1',r));try{const pending=fetch(`http://127.0.0.1:${server.address().port}/v1/analyze`,{method:'POST',headers:{authorization:`Bearer ${key}`,'content-type':'application/octet-stream'},body:head});await ready;server.cancelActive();assert.equal((await pending).status,504);assert.deepEqual(await readdir(tempParent),[]);}finally{await new Promise(r=>server.close(r));await rm(tempParent,{recursive:true,force:true})}});
