# Receipt checks

gatepass-verify reads one local file and prints one verdict per record. It does not open a network connection, and it does not sit in front of a call.

Pass `--format` to force a parser. The default detects the format and refuses input it does not recognize. A skipped check (`ok: null`) is named in the output. A skip is not a pass.

`--evidence` prints a bundle for a dispute or an audit: what was approved, by whom, when, what ran, the verdict, and why. `--evidence --json` prints the same bundle as `gatepass-verify.evidence.v1` ([schema/evidence.v1.json](../schema/evidence.v1.json)). Sections the file does not carry are stated as missing. They are not filled in.

## AP2 mandates

Public sources:

- [Agent authorization](https://ap2-protocol.org/ap2/agent_authorization/)
- [Payment mandate](https://ap2-protocol.org/ap2/payment_mandate/)
- [Checkout mandate](https://ap2-protocol.org/ap2/checkout_mandate/)
- [SD-JWT, RFC 9901](https://www.rfc-editor.org/rfc/rfc9901)

The file is either a raw `~~` chain or a JSON object:

```json
{ "profile": "ap2-mandate", "chain": "<hop>~~<hop>", "receipt": "<optional compact JWT>" }
```

Checked:

- SD-JWT disclosures. A supplied disclosure whose digest is not referenced is rejected. Digests that are not supplied stay hidden.
- ES256 on the first hop, when you pass `--key ap2=<P-256 JWK or PEM>`.
- ES256 on each later hop, using the previous hop's `cnf.jwk`.
- `sd_hash` over the exact preceding hop bytes, after repairing the `~~~` junction that `~~` creates with a trailing tilde. `issuer_jwt_hash`, when present, is the SHA-256 of the preceding hop's issuer JWT only.
- Closed payment fields from the payment mandate schema: `transaction_id`, `payee`, `payment_amount` as an integer minor unit, and `payment_instrument`.
- `checkout_hash` as the base64url SHA-256 of `checkout_jwt`, and equality with `transaction_id` when both mandates are present.
- Claims set on an open mandate, other than `vct`, `constraints`, `cnf`, `iat`, and `exp`, must be unchanged on the closed mandate.
- These constraint types, when a closed mandate is present: `payment.amount_range`, `payment.allowed_payees`, `payment.allowed_payment_instruments`, `payment.allowed_pisps`, `payment.execution_date`, `payment.reference`, `checkout.allowed_merchants`, `checkout.line_items`.
- Unknown constraint types fail evaluation. That is a `widened` verdict, from the agent authorization rule that an unknown constraint fails.
- `exp` against the verification clock. The payment mandate page does not define a skew allowance, so the comparison is exact.
- A receipt `reference`, when a receipt is present, must be the SHA-256 of the final hop. `--key ap2-receipt=<key>` checks that receipt's ES256 signature.

Not checked, and never reported as passed:

- Issuer JWKS and `x5c` trust. There is no network. Without `--key ap2`, the first-hop signature is skipped.
- `payment.agent_recurrence` spacing and occurrence counts, and `payment.budget` cumulative spend. Those need earlier presentations. The shape is checked. A single integer amount that already exceeds an integer budget max still fails.
- `payment.amount_range` bounds that are not integers. The schema table requires integer minor units. The same page shows a decimal example. A decimal bound is malformed, not converted.
- The `checkout_jwt` payload schema. It is out of scope in the checkout mandate document. This tool reads `merchant` and `line_items` when those keys are present. A merchant signature on that JWT is not a MUST there, so it is not treated as verified.
- ISO mdoc mandates.
- Algorithms other than ES256.

`sd_hash` uses the preceding hop bytes because the delegate SD-JWT draft is cited by AP2 but does not publish a vector for the chain junction in the AP2 narrative docs. A file whose signer hashed a different serialization fails closed.

## Verifiable Intent

Public sources:

- [Credential format, v0.1 draft](https://verifiableintent.dev/spec/credential-format/)
- [Constraints](https://verifiableintent.dev/spec/constraints/)
- [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901)

The public text defines the layers. It does not define one file container. This tool reads:

```json
{
  "profile": "verifiable-intent-v0.1",
  "l1": "<SD-JWT>",
  "l2": "<KB-SD-JWT>",
  "l3a": "<optional>",
  "l3b": "<optional>"
}
```

`l1` must be the exact serialized string the layer 2 `sd_hash` was computed over, including the trailing tilde when the signer included it.

Checked:

- Layer 1 header `ES256` and `sd+jwt`, no `sd_hash`, and `_sd_alg` of `sha-256`.
- Structural claims `iss`, `sub`, `iat`, `exp`, `vct`, `cnf`, `_sd_alg`. For `vct` `https://credentials.mastercard.com/card`, also `pan_last_four` and `scheme`.
- Layer 1 ES256 when you pass `--key verifiable-intent=<P-256 JWK or PEM>`.
- Layer 2 ES256 against layer 1 `cnf.jwk`.
- Layer 2 `sd_hash` against the `l1` string.
- `typ` of `kb-sd-jwt` for immediate mode and `kb-sd-jwt+kb` for autonomous mode.
- Immediate pairing: `checkout_hash`, the SHA-256 of `checkout_jwt`, and `transaction_id` match. Immediate mandates must not carry `cnf` or `constraints`.
- Autonomous delegation: open checkout and payment mandates share one P-256 `cnf.jwk` with `kid`. `mandate.payment.reference` matches the checkout disclosure digest.
- Layer 3, when present: `kb-sd-jwt`, `kid` matches the delegated key, ES256 against that key, no `cnf`, lifetime at most one hour, and `sd_hash` over the selective layer 2 presentation (issuer JWT, the mandate disclosure, then nested disclosures, each joined by `~`, with a trailing `~`).
- Machine-checked constraints from the constraints document: `mandate.payment.amount_range`, `mandate.payment.allowed_payees`, `mandate.checkout.allowed_merchants`, `mandate.checkout.line_items`, the per-payment part of `mandate.payment.budget`, and the date window of `mandate.payment.agent_recurrence`.
- Unknown constraint types on an open mandate fail. The constraints document requires that.
- `exp` with the 300 second skew stated in the credential format. `iat` after the clock plus that skew is rejected.

Not checked, and never reported as passed:

- Issuer JWKS. The credential format says production verifiers resolve `kid` from JWKS. This tool does not fetch it.
- `checkout_jwt` merchant signature. v0.1 says the schema and the signature procedure are implementation-defined, and signature verification is not yet a MUST.
- Cumulative budget and agent-recurrence occurrence counts. Those need payment-network state.
- Merchant recurrence metadata for `mandate.payment.recurrence`. v0.1 says that metadata is implementation-defined.
- Nonce replay. This tool keeps no store.
- Profile-specific layer 1 claims for a `vct` other than the Mastercard reference profile.

Layer 3 `sd_hash` follows the selective presentation in credential format section 5.4. A file that hashes the disclosures in a different order fails closed.

## Decision records

Profile `gatepass-decision-record`. One object is one record. A bundle is:

```json
{ "profile": "gatepass-decision-record", "witness": {}, "records": [ {}, {} ] }
```

The signature covers every field except `signature`, using `alg` `Ed25519` or `ES256` and `publicKey` on the record. Canonical form is the code-point JSON used by the Keel and flight-recorder checks. `--key gatepass=<key>` pins that public key. Without a pin, the signature still has to match the key on the record, and the output says the signer was not pinned.

When both `approved` and `executed` are present, these must match or the verdict is `tampered`:

- `tool`
- `argsHash`
- `resolvedPathHash`
- `toolDefinitionHash`

A hash is lowercase SHA-256 hex. `argsHash` and `toolDefinitionHash` are the hash of the code-point canonical JSON. `resolvedPathHash` is the hash of the path string. If `materials` carries `approvedArgs`, `executedArgs`, `approvedTool`, `executedTool`, `approvedPath`, or `executedPath`, those preimages are hashed and compared with the stored digests. Missing hashes are skipped and named. A hash on only one side is malformed.

`mandate` is checked when present:

- `signature` over the mandate with `signature`, `clientDataJSON`, and `authenticatorData` removed.
- If `clientDataJSON` and `authenticatorData` are present, the signature is the passkey assertion from [WebAuthn](https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion): `authenticatorData` concatenated with SHA-256 of the client data, the challenge equals the SHA-256 of the canonical mandate, the user-present flag is set, and `rpIdHash` matches the host of `clientDataJSON.origin`. `--aud` pins that origin. This does not store a signature counter and does not check attestation.
- Without those two fields, an ES256 or Ed25519 signature over the canonical mandate is checked, and the output says it is not a passkey ceremony.
- `scopes` must contain `executed.tool`.
- `caps.amount` and `caps.count`, when the executed record has `amount` or `count`, must hold. A miss is `widened`.
- `expiresAt` before the verification clock is `expired`.

`chain.prev` and `chain.hash` link records in a bundle. `hash` is the SHA-256 of the canonical record with `signature` and `chain.hash` removed. The first record may use 64 zero hex as `prev`. A broken link is `tampered`.

`witness` is an outside checkpoint: `logId`, `headHash`, and `length`. The head must equal the last record hash, and `length` must equal the number of records in the file. A shorter file and an older head fail the same check. This catches a cut tail and a replay of an earlier head. It does not catch a missing prefix when the remaining links and the head still match. A witness URL is not contacted.

Unrecognized fields stay inside the signed bytes. The output names them and does not assign them a meaning.

## What this tool does not do

- It does not approve a call, block a call, or contact an issuer.
- It does not treat a skipped check as a pass.
- It does not keep replay state, occurrence counts, or cumulative spend.
- It does not certify a receipt as produced by a particular vendor. The parsers follow the public documents above. A published vector is used when one is in this repository. The AP2, Verifiable Intent, and decision-record fixtures were written here so the checks can be tested. They are not vendor test vectors.
