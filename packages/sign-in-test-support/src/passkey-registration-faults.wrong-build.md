# Wrong-build evidence for `passkey-registration-faults.host.e2e.test.ts`

What each case in the host file does when the code under test is wrong.

## Hook removed

Built from commit `06090180` with the `refuseUnverifiableRegistration` call removed from `second-factor-provider-plugin.ts`, so the passkey plugin answers alone. The file had 10 cases then. Node and workerd gave the same result: 7 failed and 3 passed.

| Case | Status | Assertion |
| --- | --- | --- |
| valid ceremony | 200 | passes |
| tampered challenge | 500 | fails: `expected 500 to be 400` |
| client data origin that is not the issuer | 500 | fails: `expected 500 to be 400` |
| packed self-attestation signed by a different key | 400 from the plugin (`verified: false`) | fails on the body: `expected { …(2) } to match object { error: 'invalid_request', …(1) }` |
| authData with no attested credential data | 500 | fails: `expected 500 to be 400` |
| credential public key that is not a COSE map | 500 | fails: `expected 500 to be 400` |
| storage failure after a passed verification | 5xx | passes |
| refused fault deletes no verification row | 500 | fails: `expected 500 to be 400` |
| expired challenge reaches the plugin's not-found answer | 400 `CHALLENGE_NOT_FOUND` | passes (the boundary takes no part) |
| WebCrypto failure in verification | 500, from the plugin | fails: `expected [] to deeply equal [ { …(6) } ]` (the plugin consumed the challenge) |

## Other wrong builds at `06090180`

Both hosts gave the same result each time.

- **Lookup through `findVerificationValue`, without the expiry check:** 2 of 10 failed.
  - The no-delete witness failed with `expected [ { …(6) } ] to deeply equal [ { …(6) }, { …(6) } ]`: the unrelated expired row was deleted.
  - The expired-challenge case failed with `expected { error: 'invalid_request', …(2) } to match object { code: 'CHALLENGE_NOT_FOUND' }`: the expired challenge was verified.
- **Unknown verifier failures classified as `malformed`:** 1 of 10 failed. The WebCrypto case failed with `expected 400 to be 500`.
- **The unchanged `06090180` classifier, which did not know `InvalidBackupFlags`:** the case "authData claiming a backup of a single-device credential" failed with `expected 500 to be 400`.
