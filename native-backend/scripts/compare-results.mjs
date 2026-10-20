import {readFile,stat} from 'node:fs/promises';
import {isDeepStrictEqual} from 'node:util';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';

const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
function validate(value) {
  if (!object(value)||!object(value.artifact)||!object(value.layout)||
      value.profile!=='static-elf-layout'||
      !/^[a-f0-9]{64}$/.test(value.artifact.sha256??'')||
      !Number.isSafeInteger(value.artifact.bytes)||value.artifact.bytes<0||
      value.layout.format!=='elf') throw Error('Expected a native ELF layout report.');
  if (value.result_schema_version!==undefined&&value.result_schema_version!=='rea-native-layout-v1')
    throw Error('Unsupported native report schema.');
  if (value.engine_version!==undefined&&typeof value.engine_version!=='string')
    throw Error('Invalid engine version.');
}
/** Read old and new adapter reports without rewriting either original. */
export function compareNativeResults(before,after) {
  validate(before);validate(after);
  if (before.artifact.sha256!==after.artifact.sha256||before.artifact.bytes!==after.artifact.bytes)
    throw Error('Reports must describe the same artifact SHA-256 and byte length.');
  const complete=value=>value.projection===undefined||value.projection?.complete===true;
  const fields=[...new Set([...Object.keys(before.layout),...Object.keys(after.layout)])].sort();
  const counts=value=>Object.fromEntries(['sections','segments','symbols','relocations','packed_relative_relocations'].map(key=>[key,Array.isArray(value.layout[key])?value.layout[key].length:null]));
  const field_comparison=fields.map(field=>({field,status:!Object.hasOwn(before.layout,field)?'only-after':!Object.hasOwn(after.layout,field)?'only-before':isDeepStrictEqual(before.layout[field],after.layout[field])?'unchanged':'different'}));
  return {
    comparison_schema_version:1,
    artifact:{sha256:before.artifact.sha256,bytes:before.artifact.bytes},
    before:{engine_version:before.engine_version??null,reported_rows:counts(before),projection:before.projection??null},
    after:{engine_version:after.engine_version??null,reported_rows:counts(after),projection:after.projection??null},
    comparison_complete:complete(before)&&complete(after),
    observed_layout_equal:isDeepStrictEqual(before.layout,after.layout),
    field_comparison,
    notice:'Compares reported static observations, not runtime behavior or security. Missing engine versions remain unknown; omitted projected rows are not evidence of absence. Original reports are unchanged.',
  };
}
async function load(path) {
  const info=await stat(path);
  if (!info.isFile()||info.size>2*1024*1024) throw Error('Report must be a regular JSON file up to 2 MiB.');
  const bytes=await readFile(path);
  if (bytes.length>2*1024*1024) throw Error('Report exceeds 2 MiB.');
  return JSON.parse(bytes.toString('utf8'));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try{
    if(process.argv.length!==4)throw Error('Usage: node scripts/compare-results.mjs before.json after.json');
    console.log(JSON.stringify(compareNativeResults(await load(process.argv[2]),await load(process.argv[3])),null,2));
  }catch(error){console.error(error instanceof SyntaxError?'Report is not valid JSON.':error.message);process.exitCode=1;}
}
