import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { analyzeAdditionalStaticFormats } from './static-formats.js';
import { constants, promises as fs } from 'node:fs';

const SSH_KEY_TOKEN = /^(?:ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+$/;
const CERT_TOKEN = /-cert-v01@openssh\.com$/;
const MAX_INPUT_BYTES = 1024 * 1024;

function readUInt32(buffer, offset) {
  if (offset + 4 > buffer.length) throw new Error('Truncated SSH binary data');
  return buffer.readUInt32BE(offset);
}

function readString(buffer, offset) {
  const length = readUInt32(buffer, offset);
  const start = offset + 4;
  const end = start + length;
  if (end > buffer.length) throw new Error('Truncated SSH binary string');
  return { value: buffer.subarray(start, end), offset: end };
}

function mpintBits(value) {
  let start = 0;
  while (start < value.length && value[start] === 0) start += 1;
  if (start === value.length) return 0;
  let bits = (value.length - start - 1) * 8;
  let first = value[start];
  while (first) { bits += 1; first >>>= 1; }
  return bits;
}

function parsePublicBlob(blob) {
  let part = readString(blob, 0);
  const algorithm = part.value.toString('utf8');
  const result = { algorithm, publicKey: algorithm + ' ' + blob.toString('base64'), fingerprints: { sha256: 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, ''), md5: 'MD5:' + createHash('md5').update(blob).digest('hex').match(/.{1,2}/g).join(':') } };
  if (algorithm === 'ssh-rsa') {
    part = readString(blob, part.offset);
    part = readString(blob, part.offset);
    result.bits = mpintBits(part.value);
  } else if (algorithm === 'ssh-dss') {
    part = readString(blob, part.offset);
    result.bits = mpintBits(part.value);
  } else if (algorithm.startsWith('ecdsa-sha2-')) {
    part = readString(blob, part.offset);
    const curve = part.value.toString('utf8');
    result.curve = curve;
    result.bits = Number(curve.replace(/^nistp/, '')) || undefined;
  } else if (algorithm.includes('ed25519')) {
    result.curve = 'ed25519';
    result.bits = 256;
  } else if (algorithm.includes('ed448')) {
    result.curve = 'ed448';
    result.bits = 456;
  }
  return result;
}

function parseOpenSshPrivate(buffer) {
  const magic = Buffer.from('openssh-key-v1\0');
  if (!buffer.subarray(0, magic.length).equals(magic)) throw new Error('Invalid OpenSSH private-key header');
  let offset = magic.length;
  let part = readString(buffer, offset); const cipher = part.value.toString('utf8'); offset = part.offset;
  part = readString(buffer, offset); const kdf = part.value.toString('utf8'); offset = part.offset;
  part = readString(buffer, offset); const kdfOptions = part.value; offset = part.offset;
  const keyCount = readUInt32(buffer, offset); offset += 4;
  const publicKeys = [];
  for (let index = 0; index < keyCount; index += 1) {
    part = readString(buffer, offset); offset = part.offset;
    publicKeys.push(parsePublicBlob(part.value));
  }
  const encryption = { encrypted: cipher !== 'none', cipher: cipher === 'none' ? null : cipher, kdf: kdf === 'none' ? null : kdf };
  if (kdf === 'bcrypt') {
    try {
      const salt = readString(kdfOptions, 0);
      encryption.kdfRounds = readUInt32(kdfOptions, salt.offset);
    } catch { /* Retain the usable top-level encryption facts. */ }
  }
  return { encryption, publicKeys, publicKey: publicKeys.length === 1 ? publicKeys[0].publicKey : null };
}

function parsePublicLine(line) {
  const tokens = line.trim().split(/\s+/);
  const keyIndex = tokens.findIndex((token) => SSH_KEY_TOKEN.test(token));
  if (keyIndex < 0 || !tokens[keyIndex + 1]) throw new Error('No OpenSSH public key was found');
  const algorithm = tokens[keyIndex];
  const blob = Buffer.from(tokens[keyIndex + 1], 'base64');
  if (!blob.length) throw new Error('Invalid public-key encoding');
  const key = parsePublicBlob(blob);
  return {
    publicKeys: [key],
    publicKey: `${algorithm} ${tokens[keyIndex + 1]}${tokens.slice(keyIndex + 2).length ? ` ${tokens.slice(keyIndex + 2).join(' ')}` : ''}`,
    comment: tokens.slice(keyIndex + 2).join(' ') || null,
    authorizedKeyOptions: keyIndex > 0 ? tokens.slice(0, keyIndex).join(' ') : null
  };
}

function keyObjectToPublicLine(privateKey) {
  const publicKey = createPublicKey(privateKey);
  const jwk = publicKey.export({ format: 'jwk' });
  const string = (value) => {
    const data = Buffer.isBuffer(value) ? value : Buffer.from(value);
    const length = Buffer.alloc(4); length.writeUInt32BE(data.length);
    return Buffer.concat([length, data]);
  };
  const base64url = (value) => Buffer.from(value, 'base64url');
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    const blob = Buffer.concat([string('ssh-ed25519'), string(base64url(jwk.x))]);
    return `ssh-ed25519 ${blob.toString('base64')}`;
  }
  if (jwk.kty === 'RSA') {
    const mpint = (value) => {
      let data = base64url(value);
      while (data.length > 1 && data[0] === 0) data = data.subarray(1);
      if (data[0] & 0x80) data = Buffer.concat([Buffer.from([0]), data]);
      return string(data);
    };
    const blob = Buffer.concat([string('ssh-rsa'), mpint(jwk.e), mpint(jwk.n)]);
    return `ssh-rsa ${blob.toString('base64')}`;
  }
  if (jwk.kty === 'EC') {
    const curves = { 'P-256': 'nistp256', 'P-384': 'nistp384', 'P-521': 'nistp521' };
    const curve = curves[jwk.crv];
    if (curve) {
      const blob = Buffer.concat([string(`ecdsa-sha2-${curve}`), string(curve), string(Buffer.concat([Buffer.from([4]), base64url(jwk.x), base64url(jwk.y)]))]);
      return `ecdsa-sha2-${curve} ${blob.toString('base64')}`;
    }
  }
  return null;
}


function caveats(hasCertificate) {
  const items = [
    'SSH key material does not cryptographically contain a verified owner or a key creation date.',
  ];
  if (!hasCertificate) items.push('An ordinary SSH key has no expiry date; only an SSH certificate can carry a validity window.');
  return items;
}


function inspectCertificate(sourcePath) {
  try {
    const output = execFileSync('ssh-keygen', ['-L', '-f', sourcePath], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const lines = output.split(String.fromCharCode(10));
    const field = (label) => { const line = lines.find((value) => value.trimStart().startsWith(label)); return line ? line.trimStart().slice(label.length).trim() : null; };
    const principals = [];
    const start = lines.findIndex((value) => value.trim() === 'Principals:');
    if (start >= 0) for (let index = start + 1; index < lines.length && lines[index].startsWith(' '); index += 1) principals.push(lines[index].trim());
    return { keyId: field('Key ID:'), serial: field('Serial:'), signingCa: field('Signing CA:'), validity: field('Valid:'), principals };
  } catch { return null; }
}



function parseJwt(text) {
  const compact = text.trim();
  const parts = compact.split('.');
  if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) throw new Error('Invalid compact JWT');
  const decodeJson = (part, label) => { try { return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')); } catch { throw new Error('Invalid JWT ' + label + ' JSON'); } };
  const payload = decodeJson(parts[1], 'payload');
  const timestamps = {};
  for (const name of ['iat', 'nbf', 'exp']) if (typeof payload[name] === 'number' && Number.isFinite(payload[name])) timestamps[name] = new Date(payload[name] * 1000).toISOString();
  return { kind: 'jwt', container: 'compact-jwt', header: decodeJson(parts[0], 'header'), payload, timestamps, signature: { present: parts[2].length > 0, byteLength: Buffer.from(parts[2], 'base64url').length } };
}

function jwtCaveats() {
  return ['JWT decoding does not verify its signature, issuer, audience, revocation state, or expiry.', 'JWT claims may be sensitive; reports omit the raw token and signature but show decoded header and payload.'];
}

function parsePem(text, passphrase) {
  const header = text.match(/-----BEGIN ([^-]+)-----/);
  if (!header) throw new Error('Missing PEM header');
  const encrypted = header[1] === 'ENCRYPTED PRIVATE KEY' || /Proc-Type:\s*4,ENCRYPTED/i.test(text);
  const result = { encryption: { encrypted, cipher: encrypted ? 'PEM-encrypted' : null, kdf: null }, publicKeys: [] };
  if (passphrase !== undefined || !encrypted) {
    const privateKey = createPrivateKey({ key: text, format: 'pem', passphrase });
    const publicLine = keyObjectToPublicLine(privateKey);
    if (publicLine) {
      const publicData = parsePublicLine(publicLine);
      result.publicKeys = publicData.publicKeys;
      result.publicKey = publicData.publicKey;
    }
    result.unlocked = true;
  }
  return result;
}

function claim(id, label, category, value, source = 'embedded', verification = 'unverified') {
  return { id, label, category, value, source, verification };
}

function certificateValidityTimes(validity) {
  if (typeof validity !== 'string') return { notBefore: null, expiresAt: null };
  const match = validity.match(/^from\s+(.+?)\s+to\s+(.+)$/i);
  if (!match) return { notBefore: null, expiresAt: null };
  const normalize = (value) => {
    if (/forever/i.test(value)) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toISOString();
  };
  return { notBefore: normalize(match[1]), expiresAt: normalize(match[2]) };
}


function addIntegrationContract(report, data, analysisMode) {
  const facts = report.facts;

  report.cache = { algorithm: null, key: null, analysisMode, scope: 'none', hit: false };
  report.credential = { family: facts.family || (facts.kind === 'jwt' ? 'jwt' : 'ssh'), kind: facts.kind, format: facts.container };
  report.summary = { algorithm: null, fingerprint: null, encrypted: facts.encryption?.encrypted ?? null, issuer: null, subject: null, issuedAt: null, notBefore: null, expiresAt: null };
  report.claims = [];
  if (facts.summary) { Object.assign(report.summary, facts.summary); report.claims.push(...(facts.claims || [])); report.warnings = report.caveats.map((message) => ({ code: "LIMITATION", message })); return; }
  if (facts.kind === 'jwt') {
    report.summary.issuer = typeof facts.payload.iss === 'string' ? facts.payload.iss : null;
    report.summary.subject = typeof facts.payload.sub === 'string' ? facts.payload.sub : null;
    report.summary.issuedAt = facts.timestamps.iat || null;
    report.summary.notBefore = facts.timestamps.nbf || null;
    report.summary.expiresAt = facts.timestamps.exp || null;
    for (const [name, value] of Object.entries(facts.header)) report.claims.push(claim('jwt.header.' + name, name, 'header', value));
    for (const [name, value] of Object.entries(facts.payload)) {
      const category = name === 'iss' || name === 'sub' || name === 'aud' ? 'identity' : ['iat', 'nbf', 'exp'].includes(name) ? 'lifecycle' : 'claim';
      const label = ({ iss: 'Issuer', sub: 'Subject', aud: 'Audience', iat: 'Issued at', nbf: 'Not before', exp: 'Expires at' })[name] || name;
      const normalized = facts.timestamps[name] || value;
      report.claims.push(claim('jwt.payload.' + name, label, category, normalized));
    }
  } else {
    const key = facts.publicKeys?.[0];
    report.summary.algorithm = key?.algorithm || null;
    report.summary.fingerprint = key?.fingerprints?.sha256 || null;
    report.summary.subject = facts.certificate?.principals?.[0] || facts.comment || null;
    report.summary.issuer = facts.certificate?.signingCa || null;
    const certificateTimes = certificateValidityTimes(facts.certificate?.validity);
    report.summary.notBefore = certificateTimes.notBefore;
    report.summary.expiresAt = certificateTimes.expiresAt;
    if (key?.algorithm) report.claims.push(claim('ssh.algorithm', 'Algorithm', 'cryptographic', key.algorithm));
    if (key?.bits) report.claims.push(claim('ssh.bits', 'Key size', 'cryptographic', key.bits));
    if (key?.curve) report.claims.push(claim('ssh.curve', 'Curve', 'cryptographic', key.curve));
    if (key?.fingerprints?.sha256) report.claims.push(claim('ssh.fingerprint.sha256', 'SHA-256 fingerprint', 'cryptographic', key.fingerprints.sha256));
    if (facts.encryption) report.claims.push(claim('ssh.encrypted', 'Encrypted', 'protection', facts.encryption.encrypted));
    if (facts.comment) report.claims.push(claim('ssh.comment', 'Comment', 'identity', facts.comment, 'embedded', 'unverified'));
    for (const principal of facts.certificate?.principals || []) report.claims.push(claim('ssh.certificate.principal', 'Certificate principal', 'identity', principal, 'embedded-certificate', 'unverified'));
    if (facts.certificate?.keyId) report.claims.push(claim('ssh.certificate.key-id', 'Certificate key ID', 'identity', facts.certificate.keyId, 'embedded-certificate', 'unverified'));
    if (facts.certificate?.signingCa) report.claims.push(claim('ssh.certificate.signing-ca', 'Signing CA', 'issuer', facts.certificate.signingCa, 'embedded-certificate', 'unverified'));
    if (facts.certificate?.validity) report.claims.push(claim('ssh.certificate.validity', 'Certificate validity', 'lifecycle', facts.certificate.validity, 'embedded-certificate', 'unverified'));
  }
  report.warnings = report.caveats.map((message) => ({ code: 'LIMITATION', message }));
}


/**
 * Inspect a credential file without emitting private key material or raw bearer tokens.
 * `passphrase` is retained only for the duration of this call. It is intended
 * for an interactive caller; the CLI deliberately never accepts a passphrase.
 */
function analyzeCertificateArtifact(sourcePath, text) {
  const fields = (output) => Object.fromEntries(output.split(String.fromCharCode(10)).map((line) => { const index = line.indexOf('='); return index > 0 ? [line.slice(0, index).trim(), line.slice(index + 1).trim()] : []; }).filter((entry) => entry.length));
  try {
    if (/-----BEGIN CERTIFICATE-----/.test(text)) {
      const data = fields(execFileSync('openssl', ['x509', '-in', sourcePath, '-noout', '-subject', '-issuer', '-serial', '-dates', '-fingerprint', '-sha256'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }));
      return { family: 'x509', kind: 'certificate', container: 'pem', summary: { issuer: data.issuer || null, subject: data.subject || null, notBefore: data.notBefore || null, expiresAt: data.notAfter || null, fingerprint: data['sha256 Fingerprint'] || null }, claims: Object.entries(data).map(([name, value]) => claim('x509.' + name.toLowerCase().replace(/[^a-z0-9]+/g, '-'), name, ['subject', 'issuer'].includes(name) ? 'identity' : 'cryptographic', value)), caveats: ['Certificate facts were read locally. Chain trust and revocation were not checked.'] };
    }
    if (/-----BEGIN (CERTIFICATE REQUEST|NEW CERTIFICATE REQUEST)-----/.test(text)) {
      const data = fields(execFileSync('openssl', ['req', '-in', sourcePath, '-noout', '-subject'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }));
      return { family: 'x509', kind: 'certificate-signing-request', container: 'pem', summary: { subject: data.subject || null }, claims: Object.entries(data).map(([name, value]) => claim('csr.' + name, name, 'identity', value)), caveats: ['A CSR is a request, not an issued certificate; it has no issuer or expiry date.'] };
    }
    if (sourcePath && /\.(p12|pfx)$/i.test(sourcePath)) return { family: 'x509', kind: 'pkcs12', container: 'pkcs12', summary: { encrypted: true }, claims: [claim('pkcs12.unlock-required', 'Unlock required', 'protection', true)], caveats: ['PKCS#12 contents are encrypted or password-protected and require an explicit interactive unlock flow.'] };
  } catch { return null; }
  return null;
}


async function inspectData(data, { passphrase, sourcePath = null } = {}) {
  if (data.length > MAX_INPUT_BYTES) throw new Error('Refusing to inspect a file larger than 1 MiB');
  const text = data.toString('utf8');
  const report = {
    schemaVersion: 1,
    input: { bytes: data.length },
    status: 'ok',
    facts: {},
    evidence: { identity: [] },
    caveats: []
  };
  try {
    const additional = analyzeCertificateArtifact(sourcePath, text) || analyzeAdditionalStaticFormats(text);
    if (additional) {
      report.facts = additional;
    } else if (text.trim().split('.').length === 3) {
      report.facts = parseJwt(text);
    } else if (text.includes('-----BEGIN OPENSSH PRIVATE KEY-----')) {
      const body = text.replace(/-----[^\n]+-----/g, '').replace(/\s/g, '');
      const parsed = parseOpenSshPrivate(Buffer.from(body, 'base64'));
      report.facts = { kind: 'private-key', container: 'openssh', ...parsed, unlocked: !parsed.encryption.encrypted };
    } else if (/-----BEGIN [^-]*PRIVATE KEY-----/.test(text)) {
      report.facts = { kind: 'private-key', container: 'pem', ...parsePem(text, passphrase) };
    } else {
      const firstKeyLine = text.split(/\r?\n/).find((line) => SSH_KEY_TOKEN.test(line.trim().split(/\s+/).find((token) => SSH_KEY_TOKEN.test(token)) || ''));
      if (!firstKeyLine) throw new Error('Unsupported key format');
      const parsed = parsePublicLine(firstKeyLine);
      report.facts = { kind: CERT_TOKEN.test(parsed.publicKeys[0].algorithm) ? 'certificate' : 'public-key', container: 'openssh', ...parsed };
    }
    if (report.facts.kind === 'certificate') {
      report.facts.certificate = sourcePath ? inspectCertificate(sourcePath) : null;
      for (const principal of report.facts.certificate?.principals || []) report.evidence.identity.push({ value: principal, source: 'certificate principal', confidence: 'embedded-certificate-claim' });
      if (report.facts.certificate?.keyId) report.evidence.identity.push({ value: report.facts.certificate.keyId, source: 'certificate key ID', confidence: 'embedded-certificate-claim' });
    }
    if (report.facts.kind === 'jwt' && typeof report.facts.payload.sub === 'string') report.evidence.identity.push({ value: report.facts.payload.sub, source: 'JWT subject claim', confidence: 'unverified-jwt-claim' });
    if (report.facts.comment) report.evidence.identity.push({ value: report.facts.comment, source: 'public-key comment', confidence: 'unverified-claim' });
    report.caveats = report.facts.caveats || (report.facts.kind === 'jwt' ? jwtCaveats() : caveats(report.facts.kind === 'certificate'));
    addIntegrationContract(report, data, passphrase === undefined ? 'metadata' : 'unlocked');
    return report;
  } catch (error) {
    report.status = "uninspectable";
    report.error = { code: "UNSUPPORTED_OR_MALFORMED_CREDENTIAL", message: error.message };
    report.cache = { algorithm: null, key: null, analysisMode: passphrase === undefined ? "metadata" : "unlocked", scope: "none", hit: false };
    report.credential = null;
    report.summary = null;
    report.claims = [];
    report.warnings = [];
    return report;
  }
}
export async function inspectBytes(bytes, options = {}) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) throw new TypeError("bytes must be a Buffer or Uint8Array");
  const data = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return inspectData(data, options);
}

export async function inspectFile(path, options = {}) {
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW || 0);
  const handle = await fs.open(path, flags);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error("The supplied path is not a regular file");
    if (stat.size > MAX_INPUT_BYTES) throw new Error('Refusing to inspect a file larger than 1 MiB');
    const data = await handle.readFile();
    const result = await inspectData(data, { ...options, sourcePath: path });
    if (options.includeSource === true) result.input.source = { kind: "file", path };
    return result;
  } finally {
    await handle.close();
  }
}
