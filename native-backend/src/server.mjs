import http from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtemp, open, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { analyze, capabilities, closeNativeProviders } from './adapter.mjs';
import { createAuth, EMPTY_SHA256, AUTH_LIMITS } from './auth.mjs';

const MAX = capabilities.limits.uploadBytes;
const fault = (status, code, message) => Object.assign(new Error(message), {status, code});
function send(res, status, value) {
  if (res.destroyed || res.writableEnded) return;
  const data = JSON.stringify(value);
  res.writeHead(status, {'Content-Type':'application/json', 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff', 'Connection':'close'});
  res.end(data);
}
function validateElf(head) {
  if (head.length < 64 || head.subarray(0,4).toString('hex') !== '7f454c46')
    throw fault(422, 'invalid_elf', 'Upload a complete ELF header.');
  if (head[4] !== 2 || head[5] !== 1 || head.readUInt16LE(18) !== 62 || ![1,2,3].includes(head.readUInt16LE(16)))
    throw fault(415, 'unsupported_target', 'Only ELF64 little-endian x86-64 EXEC/DYN/REL is supported.');
}
export function createServer({key = process.env.REA_API_KEY, publicKeyPem = process.env.REA_AUTH_PUBLIC_KEY_PEM, issuer = process.env.REA_AUTH_ISSUER, audience = process.env.REA_AUTH_AUDIENCE, authNow = Date.now, runAnalysis = analyze, cleanupAnalysis = closeNativeProviders, tempParent = join(tmpdir(),'rea-native-service'), uploadTimeoutMs = 10000, analysisTimeoutMs = capabilities.limits.analysisMilliseconds} = {}) {
  const auth = createAuth({bearerKey:key,publicKeyPem,issuer,audience,now:authNow});
  let challengeActive = 0;
  let active = false;
  let healthy = true;
  const retainedRoots = new Set();
  let cancelActive = () => {};
  const server = http.createServer(async (req,res) => {
    let root, handle, controller, timer, uploadTimer, onClose;
    let ownsSlot = false, ownsChallengeSlot = false;
    try {
      if (req.method === 'GET' && req.url === '/healthz') {
        send(res, healthy ? 200 : 503, {status: healthy ? 'ok' : 'unhealthy', analysisEnabled: auth.enabled && healthy, reaVersion: capabilities.reaVersion, serviceVersion: capabilities.version}); return;
      }
      if (!auth.enabled || !healthy) throw fault(503,'disabled','Analysis is disabled until server authentication is configured and cleanup is healthy.');
      if (req.method === 'POST' && req.url === '/v1/challenge') {
        if (challengeActive>=4) throw fault(429,'challenge_busy','Challenge request capacity reached.');
        const issue = auth.admitChallenge(); // Charge every admitted attempt, including malformed bodies.
        if (req.headers['content-type']!=='application/json' || req.headers['content-encoding']) throw fault(415,'unsupported_media_type','Challenge body must be uncompressed application/json.');
        if (req.headers['content-length']!==undefined && (!/^\d+$/.test(req.headers['content-length']) || Number(req.headers['content-length'])>AUTH_LIMITS.challengeBodyBytes)) throw fault(413,'challenge_body_limit','Challenge body limit is 1024 bytes.');
        challengeActive++; ownsChallengeSlot=true;
        uploadTimer=setTimeout(()=>req.destroy(),2000);
        const chunks=[]; let length=0;
        for await (const chunk of req) {
          length+=chunk.length;
          if(length>AUTH_LIMITS.challengeBodyBytes)throw fault(413,'challenge_body_limit','Challenge body limit is 1024 bytes.');
          chunks.push(chunk);
        }
        clearTimeout(uploadTimer);
        let binding;
        try {
          const json=Buffer.concat(chunks).toString('utf8');
          binding=JSON.parse(json);
          if(JSON.stringify(binding)!==json)throw new Error('Noncanonical JSON');
        } catch {throw fault(400,'invalid_challenge','Challenge must be compact JSON without duplicate fields.');}
        send(res,200,issue(binding)); return;
      }
      const ticket=auth.begin(req);
      if (req.method === 'GET' && req.url === '/v1/capabilities') {
        if(req.headers['transfer-encoding'] || (req.headers['content-length']!==undefined && req.headers['content-length']!=='0'))throw fault(400,'unexpected_body','Capabilities requests cannot have a body.');
        auth.finish(ticket,{bodySha256:EMPTY_SHA256,bodyBytes:0});send(res,200,capabilities);return;
      }
      if (req.method !== 'POST' || req.url !== '/v1/analyze') throw fault(404,'not_found','Unknown endpoint.');
      if (req.headers['content-type'] !== 'application/octet-stream' || req.headers['content-encoding']) throw fault(415,'unsupported_media_type','Send uncompressed application/octet-stream bytes.');
      if (req.headers['content-length'] !== undefined && (!/^\d+$/.test(req.headers['content-length']) || Number(req.headers['content-length']) > MAX)) throw fault(413,'upload_limit','Upload limit is 4 MiB.');
      if (active) throw fault(429,'busy','One analysis is already in progress. Retry later.');
      active = true; ownsSlot = true;
      controller = new AbortController();
      onClose = () => {if (!res.writableEnded) controller.abort();};
      res.once('close',onClose);
      cancelActive = () => {controller.abort(); if (!req.complete) req.destroy();};
      await mkdir(tempParent,{recursive:true,mode:0o700});
      root = await mkdtemp(join(tempParent,'job-'));
      const path = join(root,'upload.elf');
      handle = await open(path,'wx',0o600);
      let bytes=0, head=Buffer.alloc(0);
      const bodyHasher=createHash('sha256');
      uploadTimer = setTimeout(()=>req.destroy(),uploadTimeoutMs);
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > MAX) throw fault(413,'upload_limit','Upload limit is 4 MiB.');
        bodyHasher.update(chunk);
        if (head.length < 64) head = Buffer.concat([head,chunk.subarray(0,64-head.length)]);
        await handle.write(chunk);
      }
      clearTimeout(uploadTimer);
      await handle.close(); handle = null;
      auth.finish(ticket,{bodySha256:bodyHasher.digest('hex'),bodyBytes:bytes});
      validateElf(head);
      if (controller.signal.aborted || res.destroyed) throw fault(504,'analysis_cancelled','Analysis was cancelled.');
      timer = setTimeout(()=>controller.abort(),analysisTimeoutMs);
      let value;
      try {value = await runAnalysis(path,{signal:controller.signal,root});}
      finally {res.off('close',onClose);}
      if (controller.signal.aborted) throw fault(504,'analysis_timeout','Analysis exceeded its time limit or was cancelled.');
      const response={ok:true,...value};
      const encoded = JSON.stringify(response);
      if (Buffer.byteLength(encoded) > capabilities.limits.outputBytes) throw fault(422,'output_limit','Complete report exceeds the 2 MiB output limit.');
      // Do not acknowledge success until sensitive temporary files are removed.
      await rm(root,{recursive:true,force:true}); root=null;
      active=false; ownsSlot=false;
      send(res,200,response);
    } catch(error) {
      if (error.cleanupIncomplete) {
        healthy=false;
        // An unresolved parser may still own these files. Retain the server's
        // directory owner until provider cleanup has been verified on shutdown.
        if (root) { retainedRoots.add(root); root=null; }
      }
      await handle?.close().catch(()=>{}); handle=null;
      if (root) {
        try {await rm(root,{recursive:true,force:true}); root=null;}
        catch {healthy=false;}
      }
      if (ownsSlot) {active=false; ownsSlot=false;}
      send(res,error.status || 500,{ok:false,error:{code:error.code || 'analysis_failed',message:error.status ? error.message : 'Analysis failed. No partial report was returned.'}});
    } finally {
      clearTimeout(timer); clearTimeout(uploadTimer);
      if (onClose) res.off('close',onClose);
      await handle?.close().catch(()=>{});
      if (root) {
        try {await rm(root,{recursive:true,force:true});}
        catch {healthy=false; console.error('Temporary cleanup failed; further analysis disabled.');}
      }
      if (ownsSlot) active=false;
      if (ownsChallengeSlot) challengeActive--;
      if (!active) cancelActive = () => {};
    }
  });
  server.requestTimeout=12000;
  server.headersTimeout=5000;
  server.keepAliveTimeout=1000;
  server.maxConnections=16;
  server.cancelActive = () => {auth.clear();cancelActive();};
  server.closeAnalysis = async () => {
    await cleanupAnalysis();
    for (const root of retainedRoots) {
      await rm(root,{recursive:true,force:true});
      retainedRoots.delete(root);
    }
  };
  return server;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const server=createServer();
  server.listen(Number(process.env.PORT || 8080),'0.0.0.0',()=>console.log('REA native backend listening'));
  const stop=()=>{server.cancelActive(); server.close(async()=>{try {await server.closeAnalysis();process.exit(0);} catch {process.exit(1);}}); setTimeout(()=>process.exit(1),20000).unref();};
  process.on('SIGTERM',stop); process.on('SIGINT',stop);
}
