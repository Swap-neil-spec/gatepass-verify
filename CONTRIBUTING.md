# Contributing

Open an issue or a pull request against https://github.com/Swap-neil-spec/gatepass-verify.

- Keep the package free of runtime dependencies. Use `node:crypto` for hashes and signatures.
- Add a fixture and a test for a new verdict. Update `fixtures/expected.json`.
- Say what a check does and what it does not do, in the README format table.
- Do not describe an experimental parser as certified or compliant.
- Run `npm test` and `npm run lint` before sending a change.

Questions about a bug in verification can go to security@usegatepass.com when the bug would accept a bad receipt.
