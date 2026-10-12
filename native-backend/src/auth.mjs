import {createHash, createPublicKey, randomBytes, timingSafeEqual, verify} from 'node:crypto';

export const EMPTY_SHA256 = createHash('sha256').update('').digest('hex');
export const AUTH_LIMITS = Object.freeze({ttlSeconds:60, pendingNonces:64, challengeBodyBytes:1024, challengeBurst:16, refillMilliseconds:2000});
const MAX_UPLOAD = 4*1024*1024;
const fault=(status,code,message)=>Object.assign(new Error(message),{status,code});
const unauthorized=()=>fault(401,'unauthorized','A valid, unexpired, single-use server signature is required.');
const textClaim=value=>typeof value==='string' && /^[\x21-\x7e]{1,200}$/.test(value);
const b64url=value=>typeof value==='string' && /^[A-Za-z0-9_-]+$/.test(value);

// Identical byte protocol is implemented by the trusted Site signer.
export function canonicalChallenge(c) {
  return ['REA-ED25519-V1',c.kid,c.issuer,c.audience,c.nonce,String(c.iat),String(c.exp),c.method,c.path,c.bodySha256,String(c.bodyBytes)].join('\n');
}
function validBinding(input) {
  if (!input || typeof input!=='object' || Array.isArray(input) || Object.keys(input).sort().join(',')!=='bodyBytes,bodySha256,method,path') return false;
  if (typeof input.bodySha256!=='string' || !/^[0-9a-f]{64}$/.test(input.bodySha256) || !Number.isSafeInteger(input.bodyBytes) || input.bodyBytes<0 || input.bodyBytes>MAX_UPLOAD) return false;
  return (input.method==='POST' && input.path==='/v1/analyze') || (input.method==='GET' && input.path==='/v1/capabilities' && input.bodyBytes===0 && input.bodySha256===EMPTY_SHA256);
}
export function createAuth({bearerKey,publicKeyPem,issuer,audience,now=Date.now}={}) {
  const signedConfigured=[publicKeyPem,issuer,audience].some(v=>v!==undefined && v!=='');
  const bearerConfigured=bearerKey!==undefined && bearerKey!=='';
  let mode='disabled', publicKey;
  // Never fall back to a weaker/other mode if any supplied configuration is invalid.
  if (bearerConfigured && !signedConfigured && typeof bearerKey==='string' && Buffer.byteLength(bearerKey)>=32) mode='bearer';
  if (signedConfigured && !bearerConfigured && textClaim(issuer) && textClaim(audience) && typeof publicKeyPem==='string' && publicKeyPem.length<=1024 && publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----') && !publicKeyPem.includes('PRIVATE')) {
    try {publicKey=createPublicKey({key:publicKeyPem,format:'pem',type:'spki'});if(publicKey.asymmetricKeyType==='ed25519') mode='signed';} catch {}
  }
  const kid=publicKey?.asymmetricKeyType==='ed25519' ? createHash('sha256').update(publicKey.export({format:'der',type:'spki'})).digest('base64url') : undefined;
  const pending=new Map();
  let generation=0;
  let tokens=AUTH_LIMITS.challengeBurst,lastRefill=now();
  const prune=()=>{const current=Math.floor(now()/1000);for(const[nonce,c]of pending){if(c.exp<=current)pending.delete(nonce);}};
  const alive=c=>c && c.protocol==='REA-ED25519-V1' && c.kid===kid && c.issuer===issuer && c.audience===audience && Number.isSafeInteger(c.iat) && Number.isSafeInteger(c.exp) && c.exp-c.iat===AUTH_LIMITS.ttlSeconds && c.iat<=Math.floor(now()/1000) && c.exp>Math.floor(now()/1000);
  return {
    get enabled(){return mode!=='disabled';},
    get mode(){return mode;},
    get pendingCount(){prune();return pending.size;},
    admitChallenge() {
      if(mode!=='signed')throw fault(503,'challenge_disabled','Signed challenge authentication is not configured.');
      prune();
      const instant=now();
      tokens=Math.min(AUTH_LIMITS.challengeBurst,tokens+Math.max(0,instant-lastRefill)/AUTH_LIMITS.refillMilliseconds);lastRefill=instant;
      if(tokens<1 || pending.size>=AUTH_LIMITS.pendingNonces)throw fault(429,'challenge_limit','Challenge capacity reached. Retry later.');
      tokens-=1;
      let used=false;
      const admittedGeneration=generation;
      return (input)=>{
        if(admittedGeneration!==generation)throw fault(503,'challenge_cancelled','Challenge admission was invalidated.');
        if(used)throw fault(400,'invalid_challenge','Challenge admission already used.');
        used=true;
        if(!validBinding(input))throw fault(400,'invalid_challenge','Challenge must bind an allowed method/path, a SHA-256 hex digest, and a bounded byte length.');
        prune();
        if(pending.size>=AUTH_LIMITS.pendingNonces)throw fault(429,'challenge_limit','Challenge capacity reached. Retry later.');
        let nonce;do{nonce=randomBytes(32).toString('base64url');}while(pending.has(nonce));
        const iat=Math.floor(now()/1000);
        const c=Object.freeze({protocol:'REA-ED25519-V1',kid,nonce,issuer,audience,iat,exp:iat+AUTH_LIMITS.ttlSeconds,...input});
        pending.set(nonce,c);
        return {...c};
      };
    },
    begin(req) {
      if (req.rawHeaders && req.rawHeaders.filter((v,i)=>i%2===0 && v.toLowerCase()==='authorization').length!==1) throw unauthorized();
      if(mode==='bearer') {
        if(typeof req.headers.authorization!=='string')throw unauthorized();
        const actual=createHash('sha256').update(req.headers.authorization).digest();
        const wanted=createHash('sha256').update(`Bearer ${bearerKey}`).digest();
        if(!timingSafeEqual(actual,wanted))throw unauthorized();
        return null;
      }
      if(mode!=='signed')throw fault(503,'disabled','Authentication is disabled.');
      prune();
      const header=req.headers.authorization;
      if(typeof header!=='string' || header.length>512 || !header.startsWith('REA-Ed25519 '))throw unauthorized();
      const encoded=header.slice('REA-Ed25519 '.length);
      if(!b64url(encoded))throw unauthorized();
      let envelope;
      try {
        const decoded=Buffer.from(encoded,'base64url');
        if(decoded.toString('base64url')!==encoded)throw unauthorized();
        const json=decoded.toString('utf8');
        envelope=JSON.parse(json);
        if(JSON.stringify(envelope)!==json)throw unauthorized();
      } catch {throw unauthorized();}
      if(!envelope || typeof envelope!=='object' || Array.isArray(envelope) || Object.keys(envelope).sort().join(',')!=='kid,nonce,signature' || envelope.kid!==kid || !b64url(envelope.nonce) || envelope.nonce.length!==43 || !b64url(envelope.signature) || envelope.signature.length!==86)throw unauthorized();
      const signature=Buffer.from(envelope.signature,'base64url');
      if(signature.length!==64 || signature.toString('base64url')!==envelope.signature)throw unauthorized();
      const c=pending.get(envelope.nonce);
      if(!alive(c) || c.method!==req.method || c.path!==req.url)throw unauthorized();
      if(!verify(null,Buffer.from(canonicalChallenge(c),'utf8'),publicKey,signature))throw unauthorized();
      return c;
    },
    finish(ticket,{bodySha256,bodyBytes}) {
      if(mode==='bearer')return;
      // Synchronous map check + delete is the single-process consume transaction.
      if(mode!=='signed' || !ticket || pending.get(ticket.nonce)!==ticket || !alive(ticket) || ticket.bodySha256!==bodySha256 || ticket.bodyBytes!==bodyBytes)throw unauthorized();
      pending.delete(ticket.nonce);
    },
    clear(){generation++;pending.clear();},
  };
}
