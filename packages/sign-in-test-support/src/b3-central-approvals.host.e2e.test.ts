import { epochMillisecondsSchema } from '@agent-collaboration/sign-in-core';
import {
	createMemoryProofKeyStore,
	fleetCliSession,
	requireFleetTarget,
	runApprovalsCommand,
	sendApprovalOperation,
	type ApprovalCommandOutcome,
	type ApprovalsCommandOptions,
	type FleetCliIo,
} from '@agent-collaboration/sign-in-owner-cli';
import { createWebSignInCapabilities } from '@agent-collaboration/sign-in-platform-web';
import { decodeJwt } from 'jose';
import { expect, it } from 'vitest';
import { z } from 'zod';

import { c3CentralProofPin } from '#sign-in-test-support/test-fixtures/b3-central-proof-pin';
import { startB3CentralTokio } from '#sign-in-test-support/test-fixtures/b3-central-tokio';
import { useControlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-node-test-clock';
import { controlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-sign-in-clock';
import { fleetCliIoFor } from '#sign-in-test-support/test-fixtures/fleet-cli-fixture';
import { startLocalAuthHarness } from '#sign-in-test-support/test-fixtures/local-auth-harness';
import { ensureLocalOwnerOrganization } from '#sign-in-test-support/test-fixtures/local-owner-organization';
import {
	peoplePost,
	signInConfirmedPeopleBrowser,
} from '#sign-in-test-support/test-fixtures/people-browser-login';
import { webSignInCrypto } from '#sign-in-test-support/test-fixtures/recording-sign-in-capabilities';

useControlledSignInClock();

/*
 * C3 live check against real central. Known gap, accepted by the Sign-in Lead (23 Nov): real
 * central lists and decides only requests a Router raised over the machine link, and the
 * machine-link client is the Mac Lead's work. So this file cannot save a decision or answer a
 * second approve alreadyDecided against real central; both stay proven against the stand-in on
 * both hosts (approval-person-relay.host.e2e.test.ts). What runs here is everything that needs no
 * raised request: list, read and decide notVisible, the retained retry, operationConflict, and a
 * member's notPermitted, and two controls of central's order: a contract-invalid body behind a bad
 * proof is 401, and a token behind the person's revision is refreshRequired.
 */

/** Central main 1ede5c1b9's native build (c3CentralProofPin), started as the Tokio pair's central. */
const centralExecutable = process.env.C3_CENTRAL_SERVE;
const tokioPair = process.env.SIGN_IN_TEST_HOST === 'node';

/** One printed line of the live record: the command and what the CLI said. */
function record(
	command: string,
	result: { readonly exitCode: number; readonly lines: readonly string[] },
): void {
	process.stdout.write(`${JSON.stringify({ event: 'c3-live-approvals', command, ...result })}\n`);
}

it.runIf(centralExecutable !== undefined && tokioPair)(
	"C3 live: the owner CLI lists, reads and decides against real central's person approval routes",
	async (): Promise<void> => {
		if (centralExecutable === undefined) throw new Error('Missing pinned Central build');
		let now = controlledSignInClock.now();
		const harness = await startLocalAuthHarness({
			host: 'node',
			turnstileSecret: 'published-test',
			authenticatorClock: { now: () => epochMillisecondsSchema.parse(now) },
			async centralLink(issuer: string) {
				const central = await startB3CentralTokio({
					executable: centralExecutable,
					issuer,
					jwksUrl: new URL('/api/auth/jwks', issuer).toString(),
					pin: c3CentralProofPin,
				});
				return { socketPath: central.socketPath, close: central.close };
			},
		});
		try {
			// Real central keeps real time: align the sign-in proof clock with the host's first.
			const clockSample = await fetch(harness.issuer);
			await clockSample.body?.cancel();
			now = epochMillisecondsSchema.parse(Date.parse(clockSample.headers.get('date') ?? ''));
			const clock = await harness.auth('/__auth-proof/set-clock', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ milliseconds: now }),
			});
			expect(clock.status).toBe(200);
			await signInConfirmedPeopleBrowser({ harness, email: 'owner@example.invalid' });
			const organizationId = await ensureLocalOwnerOrganization({
				auth: harness.auth,
				database: harness.database,
			});
			const bootstrap = await harness.auth('/api/auth/owner/bootstrap', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: '{}',
			});
			expect(bootstrap.status).toBe(200);
			await harness.settleDeferredWork();
			const ownerCookie = harness.cookie();
			const target = { ...harness.target, organizationId };
			const ids = createWebSignInCapabilities({
				now: () => epochMillisecondsSchema.parse(now),
			}).ids;

			function cli(
				io: FleetCliIo,
			): (
				args: readonly string[],
				options?: ApprovalsCommandOptions,
			) => Promise<{ readonly exitCode: number; readonly lines: readonly string[] }> {
				const store = createMemoryProofKeyStore(webSignInCrypto);
				return async (args, options = {}) => {
					const lines: string[] = [];
					const exitCode = await runApprovalsCommand({
						arguments: args,
						// The target is built in memory here; this names it in any printed repeat line.
						targetPath: 'live-c3-target.json',
						target,
						options,
						environment: {
							io,
							store: () => store,
							confirmSecondFactor: async () => {
								throw new Error('approvals never ask for a second factor');
							},
							write: (line) => lines.push(line),
						},
					});
					const result = { exitCode, lines };
					record(
						['approvals', ...args, ...Object.entries(options).flat().map(String)].join(' '),
						result,
					);
					return result;
				};
			}
			const ownerIo = fleetCliIoFor({ harness, cookie: ownerCookie, now: () => now, sent: [] });
			const owner = cli(ownerIo);

			// list: real central's first page for an organization with no raised requests.
			expect(await owner(['list'])).toEqual({ exitCode: 0, lines: ['No approval requests.'] });
			expect(await owner(['list'], { all: true })).toEqual({
				exitCode: 0,
				lines: ['No approval requests.'],
			});
			// read: an id the person may not see is notVisible.
			const unknown = ids.nextId();
			expect(await owner(['show', unknown])).toEqual({ exitCode: 2, lines: ['Not found.'] });
			expect(await owner(['approve', unknown])).toEqual({ exitCode: 2, lines: ['Not found.'] });

			// decide, signed exactly as the CLI signs it: central verifies the decide intent and
			// retains the first result under the operation id.
			const fleetTarget = requireFleetTarget(target);
			const session = await fleetCliSession({
				target: fleetTarget,
				store: createMemoryProofKeyStore(webSignInCrypto),
				io: ownerIo,
			});
			const operationId = ids.nextId();
			const decide = (
				decision: 'allow' | 'decline',
			): Promise<ApprovalCommandOutcome<'ApprovalDecide'>> =>
				sendApprovalOperation({
					target: fleetTarget,
					session,
					io: ownerIo,
					operation: {
						operation: 'ApprovalDecide',
						organization: organizationId,
						requestId: unknown,
						operationId,
						answer: { kind: 'unprovenCall', decision },
					},
				});
			const first = await decide('allow');
			const replayed = await decide('allow');
			const changed = await decide('decline');
			for (const [command, answer] of [
				['decide allow', first],
				['decide allow (same operation id)', replayed],
				['decide decline (same operation id)', changed],
			] as const)
				process.stdout.write(
					`${JSON.stringify({ event: 'c3-live-approvals', command, answer })}\n`,
				);
			expect(first).toEqual({ kind: 'replied', reply: { kind: 'notVisible' } });
			expect(replayed).toEqual(first);
			expect(changed).toEqual({ kind: 'replied', reply: { kind: 'operationConflict' } });

			// A member, who holds no approval:decide, is refused by central itself.
			const invited = await peoplePost(
				harness,
				'invite-member',
				{ organizationId, email: 'member@example.invalid', role: 'member' },
				ownerCookie,
			);
			const invitationId = z.object({ id: z.uuidv7() }).parse(await invited.json()).id;
			await signInConfirmedPeopleBrowser({ harness, email: 'member@example.invalid' });
			expect((await peoplePost(harness, 'accept-invitation', { invitationId })).status).toBe(200);
			await harness.settleDeferredWork();
			const member = cli(
				fleetCliIoFor({ harness, cookie: harness.cookie(), now: () => now, sent: [] }),
			);
			expect(await member(['list'])).toEqual({
				exitCode: 2,
				lines: [
					"Not permitted: answering approvals needs the organization owner's approval:decide.",
				],
			});

			// Central's order (approval_person_admission.rs:368-395): it reads only the address,
			// verifies the proof, then decodes the body, so a contract-invalid body behind a bad
			// proof is 401, not 400.
			const unsigned = await fetch(
				new URL('/api/auth/organization-admin/v1/approval-list', harness.issuer),
				{
					method: 'POST',
					headers: {
						'content-type': 'application/json',
						authorization: 'DPoP not-a-token',
						dpop: 'not-a-proof',
					},
					body: JSON.stringify({ organization: organizationId, filter: 'bogus' }),
				},
			);
			process.stdout.write(
				`${JSON.stringify({ event: 'c3-live-approvals', command: 'invalid body behind a bad proof', status: unsigned.status })}\n`,
			);
			expect(unsigned.status).toBe(401);

			// A token behind the person's current revision (admission.rs:168-172): the owner's role
			// changes through the production fenced adapter, which pushes the new floor to central.
			const roleChanged = await harness.auth('/__auth-proof/authorization-fence', {
				method: 'POST',
				headers: { 'content-type': 'application/json', cookie: ownerCookie },
				body: JSON.stringify({
					kind: 'update',
					model: 'member',
					where: [{ field: 'userId', value: decodeJwt(session.accessToken).sub }],
					update: { role: 'member' },
				}),
			});
			expect(roleChanged.status).toBe(200);
			await harness.settleDeferredWork();
			const stale = await sendApprovalOperation({
				target: fleetTarget,
				session,
				io: ownerIo,
				operation: {
					operation: 'ApprovalList',
					organization: organizationId,
					filter: 'waiting',
					cursor: null,
				},
			});
			process.stdout.write(
				`${JSON.stringify({ event: 'c3-live-approvals', command: 'list with the token from before the revision bump', answer: stale })}\n`,
			);
			expect(stale).toEqual({ kind: 'refused', reason: 'refreshRequired' });
		} finally {
			await harness.close();
		}
	},
);
