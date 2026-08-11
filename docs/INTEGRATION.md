# Integration contract

Every result includes a stable display model:

- `credential`: `{ family, kind, format }`, or `null` when uninspectable.
- `summary`: `algorithm`, `fingerprint`, `encrypted`, `issuer`, `subject`, `issuedAt`, `notBefore`, and `expiresAt`.
- `claims`: table rows with `id`, `label`, `category`, `value`, `source`, and `verification`.
- `warnings`: limitations a caller should display.
- `cache`: cache metadata; it never contains a raw credential or stable content digest.

Identity and lifecycle fields are `null` unless the supplied artifact embeds them. SSH comments, certificate principals, and JWT claims are evidence, not verified ownership.

## Recommended scanner integration

Use one `createInspectionSession()` per scanner run and pass candidate bytes directly. This avoids one temporary file per finding and deduplicates repeated findings in memory.

```js
import { createInspectionSession } from '@nikolareljin/credential-lens';

const session = createInspectionSession({ maxEntries: 1_000, maxResultBytes: 4 * 1024 * 1024 });
try {
  const report = await session.inspectBytes(candidateBytes);
  // `report.cache.hit` is true when this session already inspected these bytes.
} finally {
  session.dispose();
}
```

The cache key is an HMAC-SHA-256 value derived from a random secret created for that session. It is scoped to both the exact bytes and analysis mode (`metadata` or `unlocked`), cannot be reused across sessions, and is safe for in-process lookup only. The cache stores normalized reports, never input bytes, passphrases, decrypted key material, paths, or raw tokens. It is bounded by entry count and result size; disposal clears entries and zeroes its secret.

For tools that can only invoke the CLI, use a restrictive temporary file and delete it in `finally`, bounded by a worker pool. Prefer the library API when it is available.
