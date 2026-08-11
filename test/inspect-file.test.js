import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { inspectFile } from '../src/index.js';

async function withTempDir(run) {
  const directory = await mkdtemp(join(tmpdir(), 'credential-lens-'));
  try { await run(directory); } finally { await rm(directory, { recursive: true, force: true }); }
}

// Synthetic parser fixtures only: no generated, real, or usable SSH keys.
function sshString(value) {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  return Buffer.concat([length, data]);
}

function fakePublicBlob() {
  return Buffer.concat([sshString('ssh-ed25519'), sshString(Buffer.alloc(32, 0x42))]);
}

function fakeOpenSshPrivate(encrypted = false) {
  const kdfOptions = encrypted ? Buffer.concat([sshString(Buffer.alloc(16, 0x53)), Buffer.from([0, 0, 0, 16])]) : Buffer.alloc(0);
  const count = Buffer.alloc(4);
  count.writeUInt32BE(1);
  const payload = Buffer.concat([Buffer.from('openssh-key-v1' + String.fromCharCode(0)), sshString(encrypted ? 'aes256-ctr' : 'none'), sshString(encrypted ? 'bcrypt' : 'none'), sshString(kdfOptions), count, sshString(fakePublicBlob()), Buffer.from('SYNTHETIC-NOT-A-PRIVATE-KEY')]);
  return ['-----BEGIN OPENSSH PRIVATE KEY-----', payload.toString('base64'), '-----END OPENSSH PRIVATE KEY-----', ''].join(String.fromCharCode(10));
}

function fakePublicLine(comment = '') {
  return 'ssh-ed25519 ' + fakePublicBlob().toString('base64') + (comment ? ' ' + comment : '');
}

function fakeJwt() {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return [encode({ alg: 'none', typ: 'JWT' }), encode({ sub: 'synthetic-user', iss: 'https://issuer.invalid', iat: 1700000000, exp: 1700003600, role: 'test-only' }), Buffer.from('synthetic-signature').toString('base64url')].join('.');
}


test('inspects an unencrypted OpenSSH private key without exposing its body', async () => {
  await withTempDir(async (directory) => {
    const key = join(directory, 'id_ed25519');
    await writeFile(key, fakeOpenSshPrivate());
    await writeFile(key + '.pub', fakePublicLine('fixture@example.test'));
    const report = await inspectFile(key);
    assert.equal(report.status, 'ok');
    assert.equal(report.facts.kind, 'private-key');
    assert.equal(report.facts.encryption.encrypted, false);
    assert.equal(report.facts.publicKeys[0].algorithm, 'ssh-ed25519');
    assert.match(report.facts.publicKey, /^ssh-ed25519 /);
    assert.match(report.facts.publicKeys[0].fingerprints.sha256, /^SHA256:/);
    assert.equal(report.evidence.identity.length, 0);
    assert.equal(JSON.stringify(report).includes('OPENSSH PRIVATE KEY'), false);
  });
});

test('reads encryption facts and public identity from an encrypted OpenSSH key', async () => {
  await withTempDir(async (directory) => {
    const key = join(directory, 'id_ed25519');
    await writeFile(key, fakeOpenSshPrivate(true));
    const report = await inspectFile(key);
    assert.equal(report.status, 'ok');
    assert.equal(report.facts.encryption.encrypted, true);
    assert.equal(report.facts.encryption.kdf, 'bcrypt');
    assert.equal(report.facts.publicKeys[0].bits, 256);
  });
});

test('inspects authorized_keys-style public entries and labels comments as evidence', async () => {
  await withTempDir(async (directory) => {
    const path = join(directory, 'authorized_keys');
    await writeFile(path, 'from="192.0.2.1" ' + fakePublicLine('operator@example.test') + String.fromCharCode(10));
    const report = await inspectFile(path);
    assert.equal(report.status, 'ok');
    assert.equal(report.facts.authorizedKeyOptions, 'from="192.0.2.1"');
    assert.equal(report.evidence.identity[0].confidence, 'unverified-claim');
  });
});

test('decodes a fully synthetic JWT without emitting the raw bearer token', async () => {
  await withTempDir(async (directory) => {
    const path = join(directory, 'synthetic.jwt');
    const token = fakeJwt();
    await writeFile(path, token);
    const report = await inspectFile(path);
    assert.equal(report.status, 'ok');
    assert.equal(report.facts.kind, 'jwt');
    assert.equal(report.facts.payload.sub, 'synthetic-user');
    assert.equal(report.facts.timestamps.exp, '2023-11-14T23:13:20.000Z');
    assert.equal(report.facts.signature.present, true);
    assert.equal(report.cache.scope, 'none');
    assert.equal(report.cache.key, null);
    assert.equal(report.credential.family, 'jwt');
    assert.equal(report.summary.subject, 'synthetic-user');
    assert.equal(report.summary.expiresAt, '2023-11-14T23:13:20.000Z');
    assert.ok(report.claims.some((item) => item.id === 'jwt.payload.exp'));
    assert.equal(JSON.stringify(report).includes(token), false);
    assert.equal(report.evidence.identity[0].confidence, 'unverified-jwt-claim');
  });
});


test('returns a structured result for malformed input', async () => {
  await withTempDir(async (directory) => {
    const path = join(directory, 'not-a-key');
    await writeFile(path, 'not a key');
    const report = await inspectFile(path);
    assert.equal(report.status, 'uninspectable');
    assert.equal(report.error.code, 'UNSUPPORTED_OR_MALFORMED_CREDENTIAL');
  });
});
