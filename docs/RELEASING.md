# Development and release

Initialize shared scripts after cloning:

```sh
git submodule update --init --recursive
./scripts/check.sh
```

`./scripts/check.sh` delegates to `script-helpers` and runs syntax checks, the synthetic-only test suite, and `npm pack --dry-run`. CI uses the reusable Node workflow from `ci-helpers` with the same checks.

## npm publication

The public package name is `@nikolareljin/credential-lens`. Authenticate to the personal npm account that owns the `@nikolareljin` scope, then publish only from a reviewed release branch after its version is merged and tagged:

```sh
npm login
npm publish --access public
```

The repository includes a manual publish workflow for a specific existing tag. Configure `NPM_TOKEN` as a repository Actions secret before using it. The workflow verifies the package version against the tag, runs checks, and publishes with provenance. Never put a token in the repository or command arguments.
