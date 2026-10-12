import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {createAuth,canonicalChallenge,EMPTY_SHA256,AUTH_LIMITS} from '../src/auth.mjs';
const issuer='https://site.example',audience='https://backend.example';
const binding={method:'POST',path:'/v1/analyze',bodySha256:EMPTY_SHA256,bodyBytes:0};
function setup(){
 const keys=generateKeyPairSync('ed25519');
 let instant=1000000;
 const config={publicKeyPem:keys.publicKey.export({format:'pem',type:'spki'}),issuer,audience,now:()=>instant};
 const auth=createAuth(config);
 const issue=(input=binding)=>auth.admitChallenge()(input);
 const header=(c,privateKey=keys.privateKey,changes={})=>{
   const envelope={kid:c.kid,nonce:c.nonce,signature:sign(null,Buffer.from(canonicalChallenge(c)),privateKey).toString('base64url'),...changes};
   return 'REA-Ed25519 '+Buffer.from(JSON.stringify(envelope)).toString('base64url');
 };
 const req=(c,more={})=>({method:c.method,url:c.path,headers:{authorization:header(c)},...more});
 return{auth,issue,header,req,keys,config,advance:ms=>instant+=ms};
}
const rejected=fn=>assert.throws(fn,e=>e.status===401);
test('canonical bytes have exact fields/order, ASCII decimal numbers, and no final newline',()=>{
 const c={kid:'k',issuer:'i',audience:'a',nonce:'n',iat:1,exp:61,method:'POST',path:'/v1/analyze',bodySha256:'h',bodyBytes:3};
 assert.equal(canonicalChallenge(c),'REA-ED25519-V1\nk\ni\na\nn\n1\n61\nPOST\n/v1/analyze\nh\n3');
});
test('signed challenge is bound to SPKI-derived key ID and consumed once',()=>{
 const s=setup(),c=s.issue();
 assert.equal(c.protocol,'REA-ED25519-V1');assert.equal(c.exp-c.iat,60);assert.equal(c.nonce.length,43);
 assert.equal(c.kid,createHash('sha256').update(s.keys.publicKey.export({format:'der',type:'spki'})).digest('base64url'));
 const ticket=s.auth.begin(s.req(c));s.auth.finish(ticket,binding);assert.equal(s.auth.pendingCount,0);rejected(()=>s.auth.begin(s.req(c)));rejected(()=>s.auth.finish(ticket,binding));
});
test('incorrect signatures, keys, key IDs, nonce and claim substitutions rejected',()=>{
 const s=setup(),c=s.issue(),wrong=generateKeyPairSync('ed25519');
 const request=authorization=>({method:'POST',url:'/v1/analyze',headers:{authorization}});
 rejected(()=>s.auth.begin(request(s.header(c,wrong.privateKey))));
 rejected(()=>s.auth.begin(request(s.header(c,s.keys.privateKey,{kid:'x'.repeat(43)}))));
 rejected(()=>s.auth.begin(request(s.header(c,s.keys.privateKey,{nonce:'x'.repeat(43)}))));
 for(const patch of [{issuer:'https://other.example'},{audience:'https://other.example'},{iat:c.iat-1},{exp:c.exp+1},{bodyBytes:1},{bodySha256:'1'.repeat(64)}])rejected(()=>s.auth.begin(request(s.header({...c,...patch}))));
 rejected(()=>s.auth.begin(s.req(c,{method:'GET'})));rejected(()=>s.auth.begin(s.req(c,{url:'/v1/analyze?extra=1'})));
});
test('expired, future-after-clock-rollback, restart and cleared nonces fail closed',()=>{
 let s=setup(),c=s.issue();s.advance(60000);rejected(()=>s.auth.begin(s.req(c)));assert.equal(s.auth.pendingCount,0);
 s=setup();c=s.issue();s.advance(-1000);rejected(()=>s.auth.begin(s.req(c)));
 s=setup();c=s.issue();rejected(()=>createAuth(s.config).begin(s.req(c)));s.auth.clear();rejected(()=>s.auth.begin(s.req(c)));
});
test('expiry rechecked on finish and tampered body cannot consume valid authorization',()=>{
 const s=setup(),c=s.issue(),ticket=s.auth.begin(s.req(c));
 rejected(()=>s.auth.finish(ticket,{bodySha256:'1'.repeat(64),bodyBytes:0}));rejected(()=>s.auth.finish(ticket,{bodySha256:EMPTY_SHA256,bodyBytes:1}));
 s.advance(60000);rejected(()=>s.auth.finish(ticket,binding));
});
test('malformed, padded, duplicate/extra-field or duplicate-header envelopes rejected',()=>{
 const s=setup(),c=s.issue();const valid=JSON.parse(Buffer.from(s.header(c).split(' ')[1],'base64url').toString());
 const cases=['Bearer anything','REA-Ed25519 ###',s.header(c)+'=','REA-Ed25519 '+Buffer.from(JSON.stringify({...valid,extra:1})).toString('base64url'),'REA-Ed25519 '+Buffer.from('{"kid":"bad",'+JSON.stringify(valid).slice(1)).toString('base64url'),'REA-Ed25519 '+Buffer.from(JSON.stringify(valid,null,2)).toString('base64url')];
 for(const authorization of cases)rejected(()=>s.auth.begin({method:'POST',url:'/v1/analyze',headers:{authorization}}));
 rejected(()=>s.auth.begin({...s.req(c),rawHeaders:['Authorization',s.header(c),'Authorization',s.header(c)]}));
});
test('invalid/mixed/partial/non-Ed25519 configuration cannot enable a fallback',()=>{
 const s=setup();
 for(const patch of [{bearerKey:'test_only_'.repeat(5)},{issuer:undefined},{audience:'has\nnewline'},{publicKeyPem:'not PEM'},{publicKeyPem:s.keys.privateKey.export({format:'pem',type:'pkcs8'})},{publicKeyPem:generateKeyPairSync('ec',{namedCurve:'P-256'}).publicKey.export({format:'pem',type:'spki'})}])assert.equal(createAuth({...s.config,...patch}).enabled,false);
 assert.equal(createAuth({}).enabled,false);assert.equal(createAuth({bearerKey:'short'}).enabled,false);
});
test('challenge input type, hash, lengths, methods, paths and extra fields bounded',()=>{
 const s=setup();
 for(const x of [null,[],{...binding,bodyBytes:-1},{...binding,bodyBytes:4*1024*1024+1},{...binding,bodyBytes:1.1},{...binding,bodySha256:'A'.repeat(64)},{...binding,method:'DELETE'},{...binding,path:'/etc/passwd'},{...binding,method:'GET',path:'/v1/capabilities',bodyBytes:1},{...binding,extra:true}])assert.throws(()=>s.issue(x),e=>e.status===400);
});
test('challenge rate cap refills and pending state never exceeds fixed capacity',()=>{
 const s=setup();
 for(let i=0;i<AUTH_LIMITS.challengeBurst;i++)s.issue();
 assert.throws(()=>s.issue(),e=>e.status===429);s.advance(2000);s.issue();
 for(let i=0;i<200;i++){s.advance(2000);s.issue();assert.ok(s.auth.pendingCount<=AUTH_LIMITS.pendingNonces)}
});
test('pending cap enforced even for delayed admissions; each admission single-use',()=>{
 const s=setup(),admissions=[];
 for(let i=0;i<65;i++){s.advance(2000);admissions.push(s.auth.admitChallenge());}
 for(let i=0;i<64;i++)admissions[i](binding);
 assert.equal(s.auth.pendingCount,64);assert.throws(()=>admissions[64](binding),e=>e.status===429);assert.throws(()=>admissions[0](binding),e=>e.status===400);
});
test('concurrent verified tickets cannot consume the same nonce twice',()=>{
 const s=setup(),c=s.issue();const first=s.auth.begin(s.req(c)),second=s.auth.begin(s.req(c));
 s.auth.finish(first,binding);rejected(()=>s.auth.finish(second,binding));
});
test('clearing authorization invalidates unfinished challenge admissions',()=>{
 const s=setup(),issue=s.auth.admitChallenge();s.auth.clear();assert.throws(()=>issue(binding),e=>e.status===503);assert.equal(s.auth.pendingCount,0);
});
