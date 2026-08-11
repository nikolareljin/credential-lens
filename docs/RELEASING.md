# Development and release

Initialize shared scripts after cloning:

```sh
git submodule update --init --recursive
./scripts/check.sh
```

`./scripts/check.sh` delegates to `script-helpers` and runs syntax checks, the synthetic-only test suite, and `npm pack --dry-run`. CI uses the reusable Node workflow from `ci-helpers` with the same checks.

## npm publication

The public package name is `@nikolareljin/credential-lens`. For a local manual publish, authenticate to the personal npm account that owns the `@nikolareljin` scope, then publish only from a reviewed, tagged release:

```sh
npm login
npm publish --access public
```

The repository includes a manual publish workflow for a specific existing tag. Configure npm trusted publishing for the exact GitHub repository, `publish.yml` workflow filename, and `npm` environment. The workflow uses GitHub Actions OIDC and does not require an npm token. It verifies the package version against the tag, runs checks, and publishes with automatic provenance.
