# Security

Report a vulnerability in this verifier to security@usegatepass.com.

Please include the version, the receipt format, and a minimal file that shows the problem. Do not open a public issue for an unfixed verification bypass.

This tool checks bytes you already have. It does not fetch keys, and a `valid` result only covers the checks named in that result.

A `valid` verdict means every check that ran has passed. A check with `ok: null` was skipped because the evidence was not supplied. A skip is not a pass. This tool does not keep a replay store, and it does not fetch keys from the network.
