import { createHmac, randomBytes } from 'node:crypto';
import { inspectBytes } from './inspect-file.js';

const CACHE_NAMESPACE = 'credential-lens:v2';

function asBuffer(bytes) {
  if (Buffer.isBuffer(bytes)) return bytes;
  if (bytes instanceof Uint8Array) return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  throw new TypeError('bytes must be a Buffer or Uint8Array');
}

export function createInspectionSession({ maxEntries = 1_000, maxResultBytes = 4 * 1024 * 1024 } = {}) {
  const secret = randomBytes(32);
  const results = new Map();
  const inFlight = new Map();
  const stats = { hits: 0, misses: 0, shared: 0, evictions: 0 };
  let disposed = false;
  const active = () => { if (disposed) throw new Error('Inspection session has been disposed'); };
  const keyFor = (data, options) => {
    const mode = options.passphrase === undefined ? 'metadata' : 'unlocked';
    const hash = createHmac('sha256', secret).update(CACHE_NAMESPACE).update('\0').update(mode).update('\0').update(data).digest('hex');
    return { mode, key: `${CACHE_NAMESPACE}:${mode}:hmac-sha256:${hash}` };
  };
  const cache = (key, result) => {
    if (maxEntries === 0 || Buffer.byteLength(JSON.stringify(result)) > maxResultBytes) return;
    results.set(key, structuredClone(result));
    while (results.size > maxEntries) { results.delete(results.keys().next().value); stats.evictions += 1; }
  };
  async function inspect(bytes, options = {}) {
    active();
    const data = asBuffer(bytes);
    const descriptor = keyFor(data, options);
    const cached = results.get(descriptor.key);
    if (cached) {
      stats.hits += 1;
      results.delete(descriptor.key); results.set(descriptor.key, cached);
      const response = structuredClone(cached);
      return { ...response, cache: { ...response.cache, hit: true } };
    }
    if (inFlight.has(descriptor.key)) { stats.shared += 1; return inFlight.get(descriptor.key); }
    stats.misses += 1;
    const pending = inspectBytes(data, options).then((result) => {
      const safe = { ...result, cache: { key: descriptor.key, algorithm: 'hmac-sha256', analysisMode: descriptor.mode, scope: 'session', hit: false } };
      if (!disposed) cache(descriptor.key, safe);
      return safe;
    }).finally(() => inFlight.delete(descriptor.key));
    inFlight.set(descriptor.key, pending);
    return pending;
  }
  return Object.freeze({
    inspectBytes: inspect,
    cacheStats: () => ({ ...stats, entries: results.size, inFlight: inFlight.size }),
    dispose: () => { if (!disposed) { disposed = true; results.clear(); inFlight.clear(); secret.fill(0); } }
  });
}
