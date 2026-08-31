# Releasing `zsign-wasm`

Releases are automated. Push a `vX.Y.Z` tag to run
[.github/workflows/release.yml](.github/workflows/release.yml), which
builds `dist/` and publishes to npm.

## One-time setup

The workflow authenticates with npm **trusted publishing (OIDC)** — no token.
Configure it once on npmjs.com:

1. Open <https://www.npmjs.com/package/zsign-wasm/access>.
2. Under **Trusted Publisher**, select **GitHub Actions**.
3. Set repository `gabrieldonadel/zsign-wasm`, workflow `release.yml`.

If you push the tag before this is configured, the publish step fails.
Configure it, then re-run the workflow.

## Release steps

```bash
# 1. Bump "version" in package.json (e.g. 0.0.3), then:
git commit -am "release v0.0.3"
git tag v0.0.3

# 2. Sanity-check the tarball contents:
npm pack --dry-run

# 3. Push the branch and the tag. The tag push triggers the release.
git push origin master v0.0.3
```

Watch the run with `gh run watch`. Confirm with `npm view zsign-wasm@<version>`.

## Notes

- `binary/` (the WASM output) is committed to git. CI publishes it from a
  plain checkout and does not need emscripten. After you change the C++ or
  the wasm build, run `bun run build:wasm` and commit the new `binary/` files.
- `dist/` is gitignored. CI builds it with `bun run build:dist` (plain tsc).
- The tag must match `package.json` `version`. The workflow checks this.
