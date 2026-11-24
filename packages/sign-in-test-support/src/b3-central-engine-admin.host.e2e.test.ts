import { epochMillisecondsSchema, engineKindNames } from '@agent-collaboration/sign-in-core';
import {
	createMemoryProofKeyStore,
	runEngineCommand,
	type EngineCommandOptions,
	type FleetCliIo,
} from '@agent-collaboration/sign-in-owner-cli';
import { createWebSignInCapabilities } from '@agent-collaboration/sign-in-platform-web';
import { expect, it } from 'vitest';
import { z } from 'zod';

import { engineCentralProofPin } from '#sign-in-test-support/test-fixtures/b3-central-proof-pin';
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
 * DEL-07 live check against real central main 4593797b1 on the Tokio pair. A fresh organization
 * has no raised engine work, so health and the retired list need nothing raised; retry and discard
 * of an unknown attempt get central's documented refusal (`notFound`), which central retains under
 * the operation ID. Applying a real retry or discard needs a retired attempt in central's store,
 * which only central's engine raises; that stays proven against the stand-in on both hosts
 * (engine-admin-relay.host.e2e.test.ts).
 */

/** Central main 4593797b1's native build (engineCentralProofPin), started as the Tokio pair's central. */
const centralExecutable = process.env.ENGINE_CENTRAL_SERVE;
const tokioPair = process.env.SIGN_IN_TEST_HOST === 'node';

it.runIf(centralExecutable !== undefined && tokioPair)(
	"DEL-07 live: the owner CLI reads engine health and the retired list, and is refused retry and discard of an unknown attempt, by real central's engine routes",
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
					pin: engineCentralProofPin,
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
				options?: EngineCommandOptions,
			) => Promise<{ readonly exitCode: number; readonly lines: readonly string[] }> {
				const store = createMemoryProofKeyStore(webSignInCrypto);
				return async (args, options = {}) => {
					const lines: string[] = [];
					const exitCode = await runEngineCommand({
						arguments: args,
						// The target is built in memory here; this names it in any printed repeat line.
						targetPath: 'live-engine-target.json',
						target,
						options,
						environment: {
							io,
							store: () => store,
							confirmSecondFactor: async () => {
								throw new Error('the owner confirmed a factor at sign-in, inside 900 s');
							},
							write: (line) => lines.push(line),
						},
					});
					const result = { exitCode, lines };
					process.stdout.write(
						`${JSON.stringify({
							event: 'del07-live-engine',
							command: ['engine', ...args, ...Object.entries(options).flat().map(String)].join(' '),
							...result,
						})}\n`,
					);
					return result;
				};
			}
			const owner = cli(fleetCliIoFor({ harness, cookie: ownerCookie, now: () => now, sent: [] }));

			// health: every registered kind, zero counts too, in central's order.
			const health = await owner(['health']);
			expect(health.exitCode).toBe(0);
			expect(health.lines.slice(1).map((line) => line.split('  ')[0])).toEqual([
				...engineKindNames,
			]);
			expect(health.lines[0]).toMatch(/^Engine alarm: /u);

			// retired: a fresh organization's walk reaches next: null.
			expect(await owner(['retired'])).toEqual({ exitCode: 0, lines: ['No retired engine work.'] });

			// retry and discard of an unknown attempt: central's documented notFound, retained under
			// the operation ID, so the same operation replays it and another request under it conflicts.
			const unknown = ids.nextId();
			const operationId = ids.nextId();
			const notFound = `Not found: there is no retired attempt ${unknown}; nothing changed.`;
			expect(await owner(['retry', unknown], { 'operation-id': operationId })).toEqual({
				exitCode: 2,
				lines: [notFound],
			});
			expect(await owner(['retry', unknown], { 'operation-id': operationId })).toEqual({
				exitCode: 2,
				lines: [notFound],
			});
			expect(await owner(['discard', unknown], { 'operation-id': operationId })).toEqual({
				exitCode: 2,
				lines: [
					'Central answered conflict: either the authorization it admitted this discard under changed while applying it, or this operation id is already held by another request or person. Nothing was written to the attempt or its subject.',
				],
			});
			expect(await owner(['discard', ids.nextId()])).toEqual({
				exitCode: 2,
				lines: [expect.stringMatching(/^Not found: there is no retired attempt /u)],
			});

			// The relay refuses a request without DPoP before anything reaches central.
			const bearer = await fetch(
				new URL('/api/auth/organization-admin/v1/engine-health', harness.issuer),
				{
					method: 'POST',
					headers: { 'content-type': 'application/json', authorization: 'Bearer token' },
					body: JSON.stringify({ organizationId }),
				},
			);
			process.stdout.write(
				`${JSON.stringify({ event: 'del07-live-engine', command: 'engine-health relay without DPoP', status: bearer.status })}\n`,
			);
			expect(bearer.status).toBe(401);

			// A member, who holds neither organization:readAudit nor organization:repairWork.
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
			expect(await member(['health'])).toEqual({
				exitCode: 2,
				lines: [
					"Not permitted: reading engine health needs the organization owner's organization:readAudit.",
				],
			});
			expect(await member(['retry', unknown])).toEqual({
				exitCode: 2,
				lines: [
					"Not permitted: repairing engine work needs the organization owner's organization:repairWork.",
				],
			});
		} finally {
			await harness.close();
		}
	},
);
