# Usage

`credential-lens` reads only one supplied credential file. It does not inspect sibling files, repository history, local configuration, or network services.


## Install

```sh
npm install --global @nikolareljin/credential-lens
```

For a Node.js integration:


```sh
npm install @nikolareljin/credential-lens
```

Until npm publication, use a local checkout with `npm install /path/to/credential-lens`.

```sh
credential-lens inspect --file /protected/path/to/artifact --format json
credential-lens inspect --file /protected/path/to/encrypted-key --unlock --format text
credential-lens inspect --file /protected/path/to/token.jwt --format json
```

Use `--unlock` only in an interactive terminal. The passphrase is never an argument or result field.

Supported input: OpenSSH/PEM private keys, OpenSSH public keys and certificates, `authorized_keys` entries, compact JWTs and JWEs, GCP service-account JSON, Kubernetes configuration metadata, WireGuard configuration metadata, known_hosts entries, OpenPGP armor classification, common API-token prefixes, X.509 PEM certificates/CSRs, and PKCS#12 identification. All analysis is local; JWT decoding does not verify a signature or validity.

## Library

```js
import { inspectFile } from '@nikolareljin/credential-lens';

const result = await inspectFile('/protected/path/to/artifact');
```

Do not log the supplied credential content. Results omit private-key bodies, raw compact JWTs, and JWT signatures.
