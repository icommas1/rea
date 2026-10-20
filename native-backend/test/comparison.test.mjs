import test from 'node:test';
import assert from 'node:assert/strict';
import {compareNativeResults} from '../scripts/compare-results.mjs';
const report=()=>({profile:'static-elf-layout',artifact:{sha256:'a'.repeat(64),bytes:64},layout:{format:'elf',sections:[],segments:[],symbols:[],relocations:[]}});
test('legacy and current reports compare directly while preserving their originals',()=>{
 const before=report(),after={...report(),engine_version:'6.7.0',result_schema_version:'rea-native-layout-v1'};
 const original=JSON.stringify([before,after]);const result=compareNativeResults(before,after);
 assert.equal(result.before.engine_version,null);assert.equal(result.after.engine_version,'6.7.0');
 assert.equal(result.comparison_complete,true);assert.equal(result.observed_layout_equal,true);
 assert.equal(JSON.stringify([before,after]),original);
});
test('different artifacts and unknown schemas are rejected',()=>{
 assert.throws(()=>compareNativeResults(report(),{...report(),artifact:{sha256:'b'.repeat(64),bytes:64}}),/same artifact/);
 assert.throws(()=>compareNativeResults(report(),{...report(),result_schema_version:'unknown'}),/Unsupported/);
});
test('projected omissions remain incomplete and changed fields are reported',()=>{
 const before={...report(),projection:{complete:false,omitted:{array_items:20}}};
 const after=report();after.layout.symbols=[{name:'fixture'}];
 const result=compareNativeResults(before,after);
 assert.equal(result.comparison_complete,false);assert.equal(result.observed_layout_equal,false);
 assert.equal(result.field_comparison.find(row=>row.field==='symbols').status,'different');
});
