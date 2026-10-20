// Keep owners reachable until all parser processes and temporary files retire.
const ownedProviders = new Set();

export async function inspectAndCloseProvider(provider, input, options) {
  ownedProviders.add(provider);
  let result;
  try {
    result = await provider.inspectAndClose(input, options);
  } finally {
    try {
      await provider.close();
      ownedProviders.delete(provider);
    } catch {
      throw Object.assign(new Error('Native provider cleanup remains incomplete.'), {
        cleanupIncomplete: true, status: 503, code: 'cleanup_incomplete',
      });
    }
  }
  return result;
}

/** Retry retained owners during shutdown; never discard a failed owner. */
export async function closeNativeProviders() {
  const failures = [];
  for (const provider of ownedProviders) {
    try { await provider.close(); ownedProviders.delete(provider); }
    catch (error) { failures.push(error); }
  }
  if (failures.length) throw new AggregateError(failures, 'Native cleanup remains incomplete.');
}
