import { createHash } from 'node:crypto';

function claim(id, label, category, value, source = 'embedded', verification = 'unverified') {
  return { id, label, category, value, source, verification };
}

function decodeJson(segment, label) {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    throw new Error(`Invalid ${label} JSON`);
  }
}

function tokenClassification(value) {
  const providers = [
    ['github-fine-grained-token', /^github_pat_[A-Za-z0-9_]+$/],
    ['github-classic-token', /^gh[pousr]_[A-Za-z0-9]+$/],
    ['gitlab-token', /^glpat-[A-Za-z0-9_-]+$/],
    ['slack-token', /^xox[baprs]-[A-Za-z0-9-]+$/],
    ['stripe-secret-key', /^sk_(?:live|test)_[A-Za-z0-9]+$/],
    ['aws-access-key-id', /^A(?:KIA|SIA|ROA)[A-Z0-9]{16}$/]
  ];
  const match = providers.find(([, pattern]) => pattern.test(value));
  if (!match) return null;
  return {
    family: 'api-token', kind: match[0], container: 'text',
    summary: { issuer: match[0].split('-')[0] },
    claims: [claim('api.token-type', 'Credential type', 'classification', match[0], 'format', 'unverified')],
    caveats: ['A token prefix identifies a possible provider/type; it does not establish validity, owner, scope, or expiry.']
  };
}

function analyzeGcp(value) {
  let document;
  try { document = JSON.parse(value); } catch { return null; }
  if (document?.type !== 'service_account') return null;
  return {
    family: 'cloud-credential', kind: 'gcp-service-account', container: 'json',
    summary: { issuer: document.client_email || null, subject: document.client_email || null },
    claims: [
      ['project_id', 'Project ID', 'identity'], ['client_email', 'Client email', 'identity'], ['client_id', 'Client ID', 'identity'], ['private_key_id', 'Private key ID', 'cryptographic'], ['token_uri', 'Token URI', 'endpoint']
    ].filter(([name]) => document[name] !== undefined).map(([name, label, category]) => claim(`gcp.${name}`, label, category, document[name])),
    caveats: ['Private key and token fields are intentionally omitted. Static analysis does not validate account state or credential validity.']
  };
}

function analyzeKubeConfig(value) {
  if (!/(^|\n)apiVersion:\s*v1\s*$/m.test(value) || !/(^|\n)(clusters|contexts|users):/m.test(value)) return null;
  const current = value.match(/(?:^|\n)current-context:\s*([^\n#]+)/);
  const names = (section) => [...value.matchAll(new RegExp(`(?:^|\\n)${section}:\\s*\\n(?:[\\s\\S]*?)(?=\\n[A-Za-z-]+:|$)`, 'g'))]
    .flatMap((match) => [...match[0].matchAll(/(?:^|\n)\s*-\s*name:\s*([^\n#]+)/g)].map((entry) => entry[1].trim()));
  const clusters = names('clusters');
  const contexts = names('contexts');
  return {
    family: 'cluster-configuration', kind: 'kubernetes-kubeconfig', container: 'yaml',
    summary: { subject: current?.[1].trim() || null },
    claims: [
      ...clusters.map((name) => claim('kube.cluster', 'Cluster', 'configuration', name)),
      ...contexts.map((name) => claim('kube.context', 'Context', 'configuration', name)),
      claim('kube.embedded-certificate', 'Embedded certificate present', 'protection', /certificate-authority-data:|client-certificate-data:/.test(value)),
      claim('kube.token-present', 'Token present', 'protection', /(?:^|\n)\s*token:/.test(value))
    ],
    caveats: ['Tokens, client keys, and certificate bodies are not returned. Configuration references are not resolved.']
  };
}

function analyzeWireGuard(value) {
  if (!/(^|\n)\[Interface\]\s*$/m.test(value) || !/(^|\n)\s*PrivateKey\s*=/.test(value)) return null;
  const peers = (value.match(/(^|\n)\s*\[Peer\]\s*$/g) || []).length;
  return {
    family: 'vpn-key', kind: 'wireguard-configuration', container: 'ini',
    summary: {},
    claims: [claim('wireguard.private-key-present', 'Private key present', 'protection', true), claim('wireguard.peer-count', 'Peer count', 'configuration', peers)],
    caveats: ['WireGuard private key material is not returned or derived into a public key.']
  };
}

function analyzeKnownHosts(value) {
  const line = value.split(/\r?\n/).find((item) => item && !item.startsWith('#'));
  if (!line) return null;
  const fields = line.trim().split(/\s+/);
  if (fields.length < 3 || fields[0].includes('=') || !/^(?:ssh-|ecdsa-|sk-)/.test(fields[1])) return null;
  const blob = Buffer.from(fields[2], 'base64');
  if (!blob.length) return null;
  const sha256 = createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
  return {
    family: 'host-key-record', kind: 'known-hosts-entry', container: 'openssh',
    summary: { algorithm: fields[1], fingerprint: `SHA256:${sha256}`, subject: fields[0] },
    claims: [claim('known-hosts.host-pattern', 'Host pattern', 'identity', fields[0]), claim('known-hosts.algorithm', 'Algorithm', 'cryptographic', fields[1]), claim('known-hosts.fingerprint', 'SHA-256 fingerprint', 'cryptographic', `SHA256:${sha256}`)],
    caveats: ['A known_hosts record is a host-key observation, not proof of a current host identity.']
  };
}

function analyzePgp(value) {
  const header = value.match(/-----BEGIN PGP (PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|MESSAGE)-----/);
  if (!header) return null;
  return {
    family: 'openpgp', kind: header[1].toLowerCase().replace(/ /g, '-'), container: 'ascii-armor', summary: {}, claims: [claim('openpgp.armor-type', 'Armor type', 'classification', header[1])],
    caveats: ['Only armor type is reported until packet parsing is added; armored private material is never returned.']
  };
}

export function analyzeAdditionalStaticFormats(text) {
  const compact = text.trim();
  const parts = compact.split('.');
  if (parts.length === 5 && parts.every((part) => /^[A-Za-z0-9_-]+$/.test(part))) {
    const header = decodeJson(parts[0], 'JWE protected header');
    return { family: 'jwt', kind: 'jwe', container: 'compact-jwe', protectedHeader: header, summary: { algorithm: header.alg || null, issuer: header.iss || null }, claims: Object.entries(header).map(([name, value]) => claim(`jwe.header.${name}`, name, 'header', value)), caveats: ['Compact JWE payload is encrypted and is not decrypted without a matching decryption key.'] };
  }
  return analyzeGcp(text) || analyzeKubeConfig(text) || analyzeWireGuard(text) || analyzeKnownHosts(text) || analyzePgp(text) || tokenClassification(compact);
}
