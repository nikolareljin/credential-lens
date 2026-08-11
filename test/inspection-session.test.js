import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createInspectionSession, inspectBytes, inspectFile } from '../src/index.js';

function fakeJwt() {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return Buffer.from([encode({ alg: 'none' }), encode({ sub: 'synthetic-user', exp: 1700003600 }), 'synthetic'].join('.'));
}

test('uses an opaque per-session cache key and reports a cache hit', async () => {
  const session = createInspectionSession();
  const bytes = fakeJwt();
  const first = await session.inspectBytes(bytes);
  const second = await session.inspectBytes(bytes);
  assert.match(first.cache.key, /^credential-lens:v2:metadata:hmac-sha256:[a-f0-9]{64}$/);
  assert.equal(second.cache.hit, true);
  assert.equal(JSON.stringify(second).includes(bytes.toString()), false);
  assert.equal(session.cacheStats().hits, 1);
  session.dispose();
});

test('shares concurrent work, separates modes, evicts, and disposes', async () => {
  const session = createInspectionSession({ maxEntries: 1 });
  const bytes = fakeJwt();
  const [one, two] = await Promise.all([session.inspectBytes(bytes), session.inspectBytes(bytes)]);
  assert.equal(one.cache.key, two.cache.key);
  assert.equal(session.cacheStats().shared, 1);
  const unlocked = await session.inspectBytes(bytes, { passphrase: 'synthetic-only' });
  assert.match(unlocked.cache.key, /^credential-lens:v2:unlocked:hmac-sha256:/);
  assert.ok(session.cacheStats().evictions >= 1);
  session.dispose();
  await assert.rejects(() => session.inspectBytes(bytes), /disposed/);
});

test('file and byte inspection agree without returning a source path by default', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'credential-lens-'));
  try {
    const path = join(directory, 'synthetic.jwt');
    const bytes = fakeJwt();
    await writeFile(path, bytes);
    const fromBytes = await inspectBytes(bytes);
    const fromFile = await inspectFile(path);
    assert.deepEqual(fromFile.facts, fromBytes.facts);
    assert.equal(Object.hasOwn(fromFile.input, 'source'), false);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
