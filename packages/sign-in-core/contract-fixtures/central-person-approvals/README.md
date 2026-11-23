# Central person approvals wire (C3)

Consumer copies from codex-router `main` `1ede5c1b9afbe6bd427ac742f8b63d53a225151e`, where central merged C3. The generated file and both vector files there are byte-identical to the `24dfd348` copies below. Sources, as handed to sign-in in the DEL-06 packets:

| File | Central commit | SHA-256 |
|---|---|---|
| `central-sign-in.ts` (vendored as `src/central-link/generated/central-sign-in.gen.ts`) | `24dfd348`; since DEL-07, central main `4593797b1` (see `central-sign-in-provenance.ts`; the only change is that `engineRetired.next` is required and nullable) | `1b353b3c3af466421d932014e0bf013e3327c7f27f4274e1b8dda0d1b018a3c7` at `24dfd348` |
| `contracts/approval-intent-vector.json` | `24dfd348` (unchanged since `8670195`) | `7cd5f18f05dd95c8a7d5fd098614f732448cd25c2a54d17949fc5e4180454ae7` |
| `contracts/approval-person-reply-vectors.json` | `24dfd348` | `5a9bec2fa13bc599c02a544e4557d6a70eeb5c838806da14c49687ad6f819c79` |
| `approval_person_wire.rs` | `8670195` | `4e2f47c3145171d34bf7b3008df3bf2fad3f0be7157bc475d7a12d01febd3577` |
| `signin_approval_wire_specimens_test.rs` | `8670195` | `ff1b832c948ffd630216a0c5693c7f632b1fa35974803bbb85ae598be089c515` |
| `approval-person-results.md` (result, HTTP status and writes matrix) | `24dfd348` | `ab81cae855f2efa7d39c345dc3309641b953dbdc6a2e837d88b1db8bc0e7f4e8` |

- `approval-intent-vector.json` and `approval-person-reply-vectors.json` are central's byte vectors from `contracts/`: the request body, canonical intent and digest for list, read and decide, and the canonical bytes of each reply variant. The SHA-256 values above are of the producer bytes as copied; these files use Switchboard formatting (oxfmt), and their parsed JSON equals the producer files. The canonical strings inside them are unchanged.
- `specimen-literals.json` holds the bodies central's `8670195` specimens test writes inline: one accepted last page and the malformed list bodies it refuses. Its two `factorRequired` decide literals were dropped at `24dfd348`, when the owner removed the second-factor reply from C3.
- `src/central-link/approval-person-results.ts` records, as typed constants, the HTTP status each reply variant and refusal arrives with, from `approval-person-results.md`.

`POST /organization-admin/v1/approval-{list,read,decide}` travels the private link with `Authorization: DPoP <person-fleet token>` and `DPoP: <proof>`, like the admin routes. The proof's `intent` is base64url(SHA-256(JCS(intent))) over central's `ApprovalIntent`. All three need `approval:decide`, which only the organization owner holds. Approvals need no second factor.

These fixtures define parsing and the intent only. They earn no credit for central's admission, replay or decision rules.
