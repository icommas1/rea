import { PwntoolsLayoutProvider } from 'rea-agents/dist/native/pwntools/PwntoolsLayoutProvider.js';
import { spawnOwnedProviderProcess } from 'rea-agents/dist/process/ProviderProcess.js';
import { PrivateRuntimeRoot } from 'rea-agents/dist/process/PrivateRuntimeRoot.js';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';

export const ANALYSIS_TIMEOUT_MS = Math.min(30000, Math.max(15000, Number(process.env.ANALYSIS_TIMEOUT_MS) || 30000));
export const capabilities = Object.freeze({
  service: 'rea-native-backend', version: '0.1.0', reaVersion: '6.4.0',
  profile: 'static-elf-layout', host: 'linux-x64',
  formats: ['ELF64 little-endian x86-64 EXEC/DYN/REL'],
  features: ['sections', 'segments', 'symbols', 'relocations', 'dependency-names', 'GOT candidates', 'static-mitigation-candidates'],
  unsupported: ['decompilation', 'general disassembly', 'reliable PLT inference', 'debugging', 'host execution', 'PE', 'Mach-O', 'ARM', 'core dumps', 'archives', 'URL fetching'],
  limits: {uploadBytes: 4*1024*1024, outputBytes: 2*1024*1024, analysisMilliseconds: ANALYSIS_TIMEOUT_MS, concurrency: 1},
  limitations: ['Not a malware sandbox or security verdict.', 'Unicorn may emulate selected instructions for static PLT inference; uploaded programs are never launched as host processes.', 'Symbol/relocation completeness and runtime behavior remain unknown.', 'The small-memory profile can prevent Unicorn PLT inference; an empty PLT does not mean no imported functions.'],
});

export async function analyze(path, {signal, root}) {
  const python = resolve(dirname(fileURLToPath(import.meta.url)), '../scripts/limited-python');
  // Whitelist interpreter environment; no deployment secrets reach the parser.
  const environment = {
    PATH: process.env.PATH, HOME: root, TMPDIR: root, LANG: 'C.UTF-8',
    REA_PWNTOOLS_PYTHON: python, PYTHONDONTWRITEBYTECODE: '1',
    PWNLIB_NOTERM: '1', OPENBLAS_NUM_THREADS: '1', OMP_NUM_THREADS: '1',
  };
  const provider = new PwntoolsLayoutProvider(environment, (options) => spawnOwnedProviderProcess({...options, expectedCommand:null}), () => PrivateRuntimeRoot.create({parent: root, prefix: 'decoder-'}));
  const result = await provider.inspect({path}, {signal});
  if (!result.ok) {
    const tag = result.error?._tag || 'AnalysisError';
    const error = new Error('The ELF adapter could not produce a complete result within this service profile.');
    error.code = tag;
    error.cleanupIncomplete = result.error?.cleanupIncomplete === true;
    if (error.cleanupIncomplete) {error.status=503; error.code='cleanup_incomplete'; throw error;}
    error.status = /CapabilityUnavailable/.test(tag) ? 503 : /Timeout|Cancelled/.test(tag) ? 504 : /Resource|Output/.test(tag) ? 422 : 422;
    throw error;
  }
  // Return the verified provider result, not a mutated REA evidence envelope.
  // Avoid exposing internal temporary paths or unbounded process diagnostics.
  const {artifact, diagnostics, ...layout} = result.value;
  const bytes = await readFile(path);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  if (sha256 !== artifact.sha256) throw new Error('Artifact changed during analysis');
  return {profile: capabilities.profile, provider: provider.identity,
    artifact: {sha256, bytes: artifact.bytes}, layout,
    diagnostics: {
      outputPresent: Boolean(diagnostics.stdout || diagnostics.stderr),
      truncated: Boolean(diagnostics.truncated),
      warnings: [
        ...(/Could not populate PLT/.test(String(diagnostics.stderr)) ? [{code:'plt_inference_unavailable', message:'PLT inference failed under the constrained analysis profile; its inventory may be incomplete.'}] : []),
        ...(diagnostics.stdout || diagnostics.stderr ? [{code:'parser_diagnostics_present', message:'The upstream parser reported diagnostics; treat derived inventories as potentially incomplete. Raw parser text is withheld.'}] : []),
      ],
    },
    limitations: capabilities.limitations};
}
