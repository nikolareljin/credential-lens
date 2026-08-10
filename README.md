# credential-lens

`credential-lens` safely inspects SSH key files and compact JWTs and produces evidence-based facts for security-review tooling.

```sh
credential-lens inspect --file /path/to/id_ed25519 --format json
credential-lens inspect --file /path/to/encrypted-key --unlock --format json
credential-lens inspect --file /path/to/token.jwt --format json
```

It accepts only a path, never a key value argument. Reports never contain private-key material or passphrases. They include format, encryption, algorithm, safe public-key facts, and clearly labelled identity claims embedded in the supplied credential.
Use --unlock only from an interactive terminal to have the local OpenSSH utility prompt for, and verify, the passphrase. The passphrase is never an argument, report field, log value, or file.
JWT output shows decoded header and payload claims, plus issued-at, not-before, and expiration timestamps converted to UTC. It never emits the raw token or signature, and decoding is not signature verification.

SSH keys do not contain a cryptographically verified owner, creation date, or ordinary-key expiry. JWT claims and OpenSSH certificates can carry issuer, subject, issued-at, and validity claims; these remain unverified until signature validation is added.

## Test-data policy

Tests use only synthetic, non-usable parser fixtures. Do not add real SSH keys, credentials, production-derived data, or generated key material to this repository.

## Documentation

- [Usage](docs/USAGE.md)
- [Integration contract and caching](docs/INTEGRATION.md)

## Library

```js
import { inspectFile } from 'credential-lens';

const report = await inspectFile('/protected/path/to/key');
```

For PEM keys, an interactive host application may pass a short-lived in-memory `passphrase` option to inspect public facts that require unlocking. The command-line tool deliberately does not accept passphrases.
