import test from 'node:test';
import assert from 'node:assert/strict';
import {inspectAndCloseProvider,closeNativeProviders} from '../src/provider-lifecycle.mjs';

test('one-shot provider closes before a successful result can be returned',async()=>{
 const calls=[];const value={ok:true,value:{layout:'unchanged'}};
 const provider={inspectAndClose:async()=>{calls.push('inspect');return value;},close:async()=>{calls.push('close');}};
 assert.equal(await inspectAndCloseProvider(provider,{path:'/fixture'},{}),value);
 assert.deepEqual(calls,['inspect','close']);
});
test('cleanup failure retains its owner for a later verified shutdown retry',async()=>{
 let attempts=0;
 const provider={inspectAndClose:async()=>({ok:true,value:{}}),close:async()=>{if(++attempts<3)throw Error('still owned');}};
 await assert.rejects(inspectAndCloseProvider(provider,{path:'/fixture'},{}),error=>error.cleanupIncomplete===true&&error.status===503);
 await assert.rejects(closeNativeProviders());
 await closeNativeProviders();
 assert.equal(attempts,3);
 await closeNativeProviders();assert.equal(attempts,3);
});
