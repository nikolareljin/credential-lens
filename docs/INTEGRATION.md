# Integration contract

Every result includes this stable display model:

- `credential`: `{ family, kind, format }` or `null` when uninspectable.
- `summary`: stable columns: `algorithm`, `fingerprint`, `encrypted`, `issuer`, `subject`, `issuedAt`, `notBefore`, and `expiresAt`.
- `claims`: table rows with `id`, `label`, `category`, `value`, `source`, and `verification`.
- `warnings`: limitations that a UI should show.
- `cache`: a content-addressed result key.

The `summary` identity and lifecycle fields are `null` when the credential does not embed those facts. They are never inferred. A JWT issuer/subject or SSH comment/principal is an embedded, unverified claim; an ordinary SSH key has no owner or expiration date.

## Cache and temporary files

`cache.key` has the form `credential-lens:v1:<analysis-mode>:sha256:<digest>`. The digest is calculated from the exact supplied bytes, so it remains stable when a caller creates a different temporary filename for the same credential.

For a filename-only integration:

1. Hash the detected bytes in memory and check the caller's result cache by the expected key.
2. On a cache hit, render the stored normalized result without creating a file or invoking this tool.
3. On a miss, write a single restrictive temporary file (`0600`), inspect it, store the normalized result by `cache.key`, and delete the file in `finally`.
4. Bound this workflow with a worker pool. The maximum temporary-file count is the worker count, not the number of findings.

Cache normalized results only. Never cache raw credentials, passphrases, private-key bodies, or compact JWT values. Treat the content digest as sensitive correlation metadata and expire it with the caller's scan lifecycle.
