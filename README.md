# credential-lens

`credential-lens` safely inspects SSH key files and compact JWTs and produces evidence-based facts for security-review tooling.

## Author

[Nik Reljin](https://github.com/nikolareljin) · [LinkedIn](https://www.linkedin.com/in/nikolareljin)


## Install

After npm publication, install it globally to use the CLI:

```sh
npm install --global @nikolareljin/credential-lens
credential-lens inspect --file /protected/path/to/artifact --format json
```

## Run with npx

Run the published CLI without installing it globally:

```sh
npx --yes @nikolareljin/credential-lens inspect --file /protected/path/to/artifact --format json
```

Use the same file-only form for each credential; do not place credential values in shell arguments.

Or add it to another Node.js tool:

```sh
npm install @nikolareljin/credential-lens
```

```js
import { inspectFile } from '@nikolareljin/credential-lens';

const result = await inspectFile('/protected/path/to/artifact');
```

For local development before publication, install from a checkout:

```sh
npm install /path/to/credential-lens
```


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
- [Development and npm releases](docs/RELEASING.md)

## Library

```js
import { inspectFile } from '@nikolareljin/credential-lens';

const report = await inspectFile('/protected/path/to/key');
```

For PEM keys, an interactive host application may pass a short-lived in-memory `passphrase` option to inspect public facts that require unlocking. The command-line tool deliberately does not accept passphrases.
