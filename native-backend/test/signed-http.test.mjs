import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {mkdtemp,rm,readdir} from 'node:fs/promises';
import {createServer} from '../src/server.mjs';
import {canonicalChallenge} from '../src/auth.mjs';
const body=Buffer.alloc(64);body.write('\x7fELF',0,'binary');body[4]=2;body[5]=1;body.writeUInt16LE(62,18);body.writeUInt16LE(1,16);
const digest=b=>createHash('sha256').update(b).digest('hex');
async function setup(t,options={}){
 const keys=generateKeyPairSync('ed25519'),tempParent=await mkdtemp('/tmp/rea-signed-test-');let clock=1000000,calls=0;
 const server=createServer({key:undefined,publicKeyPem:keys.publicKey.export({type:'spki',format:'pem'}),issuer:'https://site.example',audience:'https://backend.example',authNow:()=>clock,tempParent,runAnalysis:async()=>{calls++;return{layout:{format:'elf'}}},...options});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 t.after(async()=>{await new Promise(r=>server.close(r));await rm(tempParent,{recursive:true,force:true});});
 const base=`http://127.0.0.1:${server.address().port}`;
 const issue=async({bytes=body,method='POST',path='/v1/analyze',extra={}}={})=>{
   const r=await fetch(base+'/v1/challenge',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({method,path,bodySha256:digest(bytes),bodyBytes:bytes.length,...extra})});
   assert.equal(r.status,200);return r.json();
 };
 const header=c=>'REA-Ed25519 '+Buffer.from(JSON.stringify({kid:c.kid,nonce:c.nonce,signature:sign(null,Buffer.from(canonicalChallenge(c)),keys.privateKey).toString('base64url')})).toString('base64url');
 const post=(c,bytes=body)=>fetch(base+'/v1/analyze',{method:'POST',headers:{'content-type':'application/octet-stream',authorization:header(c)},body:bytes});
 return{base,issue,header,post,server,tempParent,get calls(){return calls},advance:ms=>clock+=ms};
}
test('public challenge followed by valid signed upload, cleanup and replay rejection',async t=>{
 const s=await setup(t),c=await s.issue();assert.equal((await s.post(c)).status,200);assert.equal(s.calls,1);assert.deepEqual(await readdir(s.tempParent),[]);assert.equal((await s.post(c)).status,401);assert.equal(s.calls,1);
});
test('unsigned bearer and malformed signed headers fail in signed-only mode',async t=>{
 const s=await setup(t);
 for(const authorization of ['', 'Bearer TEST_ONLY_NOT_A_DEPLOYMENT_CREDENTIAL_00000', 'REA-Ed25519 invalid'])assert.equal((await fetch(s.base+'/v1/analyze',{method:'POST',headers:{authorization,'content-type':'application/octet-stream'},body})).status,401);
 assert.equal(s.calls,0);
});
test('signed capabilities uses a separate exact empty-body binding and one use',async t=>{
 const s=await setup(t),c=await s.issue({bytes:Buffer.alloc(0),method:'GET',path:'/v1/capabilities'});
 assert.equal((await fetch(s.base+'/v1/capabilities',{headers:{authorization:s.header(c)}})).status,200);
 assert.equal((await fetch(s.base+'/v1/capabilities',{headers:{authorization:s.header(c)}})).status,401);
});
test('body length and hash mismatch prevent analysis and clean temporary files',async t=>{
 const s=await setup(t),c=await s.issue();let changed=Buffer.from(body);changed[63]=1;
 assert.equal((await s.post(c,changed)).status,401);assert.equal((await s.post(c,Buffer.concat([body,Buffer.from([1])]))).status,401);
 assert.equal(s.calls,0);assert.deepEqual(await readdir(s.tempParent),[]);
 assert.equal((await s.post(c)).status,200);assert.equal(s.calls,1);
});
test('expired nonce, unknown nonce after restart/clear and future timestamp rejected',async t=>{
 const s=await setup(t),c=await s.issue();s.advance(60000);assert.equal((await s.post(c)).status,401);
 const fresh=await s.issue();s.server.cancelActive();assert.equal((await s.post(fresh)).status,401);
 const rollback=await s.issue();s.advance(-1000);assert.equal((await s.post(rollback)).status,401);
});
test('nonce consumed before dispatch even when analysis is pending or fails',async t=>{
 let started,release;const ready=new Promise(r=>started=r),wait=new Promise(r=>release=r);
 const s=await setup(t,{runAnalysis:async()=>{started();await wait;throw new Error('test parser failure')}}),c=await s.issue();
 const first=s.post(c);await ready;assert.equal((await s.post(c)).status,401);release();assert.equal((await first).status,500);assert.equal((await s.post(c)).status,401);
});
test('challenge JSON size, encoding, duplicate fields, malformed JSON and rate bounded',async t=>{
 const s=await setup(t);
 const challenge=(text,headers={})=>fetch(s.base+'/v1/challenge',{method:'POST',headers:{'content-type':'application/json',...headers},body:text});
 assert.equal((await challenge(' '.repeat(1025))).status,413);
 assert.equal((await challenge('{}',{'content-encoding':'gzip'})).status,415);
 assert.equal((await challenge('{"method":"POST","method":"POST"}')).status,400);
 assert.equal((await challenge('bad')).status,400);
 for(let i=0;i<12;i++)assert.equal((await challenge('{}')).status,400);
 assert.equal((await challenge('{}')).status,429);
});
test('no keys or mixed keys keep challenge and analysis disabled',async t=>{
 const s=await setup(t,{key:'TEST_ONLY_NOT_A_DEPLOYMENT_CREDENTIAL_000000'});
 assert.equal((await (await fetch(s.base+'/healthz')).json()).analysisEnabled,false);
 assert.equal((await fetch(s.base+'/v1/challenge',{method:'POST',headers:{'content-type':'application/json'},body:'{}'})).status,503);
});
