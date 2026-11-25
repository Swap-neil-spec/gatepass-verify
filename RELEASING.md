# Releasing

Releases go through npm trusted publishing with staged approval. No npm token is stored in this repository.

1. Bump `version` in `package.json` and `package-lock.json`, and the version in `CITATION.cff` and `.zenodo.json`. Add a `CHANGELOG.md` entry.
2. Merge to `main` and wait for the test workflow to pass.
3. Tag the release and push the tag:

   ```sh
   git tag v0.1.1
   git push origin v0.1.1
   ```

4. The publish workflow checks that the tag matches `package.json`, runs lint and tests, and runs `npm stage publish`. npm adds provenance automatically.
5. The maintainer reviews the staged version on npmjs.com under Staged Packages, or with `npm stage list` and `npm stage view <stage-id>`, and approves it with 2FA. The version is public only after approval.
