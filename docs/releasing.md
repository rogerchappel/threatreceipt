# Packaging and release readiness

This project uses Stackforge's CLI/package-check conventions, with original source and a smaller dependency surface. There is no ReleaseBox bootstrap, npm publishing step or automatic GitHub release.

1. Review the source, license and changelog on a branch.
2. Run `npm ci --ignore-scripts` and `npm run release:check`.
3. Run `npm pack --ignore-scripts`; inspect `npm pack --dry-run --ignore-scripts` and the tarball contents. The CLI must run from the extracted package without runtime dependencies.
4. Confirm the exact commit passes CI on Node 22 and 24.
5. The manual `Package readiness` workflow can produce a checksummed tarball as a CI artifact. This is not a release. Review it before any later publication request.

`private: true` blocks accidental npm publication. No release tag, GitHub release, npm publication, external deployment or release credential is needed or created by this workflow. A future authorized release must record the validated commit and test evidence before publishing. Rolling back the initial project means stopping use/removing the checkout; no external application has been changed.
