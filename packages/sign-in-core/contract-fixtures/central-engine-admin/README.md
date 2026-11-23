# Central engine administration wire (DEL-07)

Consumer copies from codex-router `main` `4593797b1c6a0dd03af6bbed6d8b00a0c4cc876f` (#394, "Specify the signed engine administration route contracts"), `crates/collaboration-central-core/contracts/`:

| File | SHA-256 of the producer bytes as copied |
|---|---|
| `central-sign-in.ts` (vendored as `src/central-link/generated/central-sign-in.gen.ts`) | `8c52f41be954b008fdb5c9f519bded0777970b30bb27fb5e5d8338a65dd1d52e` |
| `engine-admin-intent-vectors.json` | `edb143b94028c1f34a5cc58651973f4eb02ac13dcf85b20270ffa2a7cafa0f54` |
| `engine-admin-reply-vectors.json` | `1b3791b4879093376dbddd6b224545aa156a9521fb00291b3945f696a8adeaf6` |
| `engine-admin-results.md` (path, permission, HTTP status and writes matrix; not copied) | `cffb2521e2385602814a8b38debce5776d739a4c5141773a2ef8dbde1c070d08` |

- The two vector files use Switchboard formatting (oxfmt); their parsed JSON equals the producer files, and the canonical strings inside them are unchanged.
- `engine-admin-intent-vectors.json` holds, per route, the request body sign-in sends, the canonical intent bytes and their base64url SHA-256: the proof's `intent` claim.
- `engine-admin-reply-vectors.json` holds the canonical bytes of each reply central gives on these routes, including every timestamp width, the empty continuation page and every typed refusal.
- `src/central-link/engine-admin-results.ts` records, as typed constants, the HTTP status each reply and refusal arrives with, from `engine-admin-results.md`.

`POST /organization-admin/v1/engine-{health,retired,retry,discard}` travels the private link with `Authorization: DPoP <person-fleet token>` and `DPoP: <proof>`, like the other admin routes. Health and retired need `organization:readAudit`; retry and discard need `organization:repairWork` and a fresh second factor (900 s). Both permissions are owner-only.

These fixtures define parsing and the intent only. They earn no credit for central's admission, receipts or engine rules.
