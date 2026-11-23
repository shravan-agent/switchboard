import { writeFile } from 'node:fs/promises';
import path from 'node:path';

import { engineKindNames } from '@agent-collaboration/sign-in-core';
import {
	createMemoryProofKeyStore,
	runOwnerCli,
	type EngineCommandOptions,
	type FleetCliIo,
} from '@agent-collaboration/sign-in-owner-cli';
import { createWebSignInCapabilities } from '@agent-collaboration/sign-in-platform-web';
import { expect, it } from 'vitest';
import { z } from 'zod';

import { useControlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-node-test-clock';
import {
	fleetCliIoFor,
	initialTime,
	ownerEmail,
	setupFleetCli,
	type FleetFixture,
} from '#sign-in-test-support/test-fixtures/fleet-cli-fixture';
import {
	peoplePost,
	signInConfirmedPeopleBrowser,
} from '#sign-in-test-support/test-fixtures/people-browser-login';
import { webSignInCrypto } from '#sign-in-test-support/test-fixtures/recording-sign-in-capabilities';

// DEL-07: the owner CLI's engine commands through sign-in's DPoP relay, on both hosts, against
// the engine stand-in built from central's decision table at 4593797b1
// (controlled-central-engine.ts, which cites central's lines).

useControlledSignInClock();

const ids = createWebSignInCapabilities().ids;

/** `count` fresh UUIDv7s in ascending order: central's pager walks attempt IDs in that order. */
function ascendingIds(count: number): readonly string[] {
	return Array.from({ length: count }, () => ids.nextId()).toSorted();
}

function flagsFor(options: EngineCommandOptions): readonly string[] {
	return [
		...(options.cursor === undefined ? [] : ['--cursor', options.cursor]),
		...(options['operation-id'] === undefined ? [] : ['--operation-id', options['operation-id']]),
	];
}

/**
 * One `engine` command through the owner CLI's real entry (`runOwnerCli`: its argument parsing,
 * target file and dispatch), with this person's fleet credential, against the running sign-in
 * host and its central stand-in. `confirmSecondFactor` is the person at the browser.
 */
function engineCli(props: {
	readonly fixture: FleetFixture;
	readonly io: FleetCliIo;
	readonly confirmSecondFactor?: () => Promise<boolean>;
}): (
	args: readonly string[],
	options?: EngineCommandOptions,
) => Promise<{ readonly exitCode: number; readonly lines: readonly string[] }> {
	const store = createMemoryProofKeyStore(webSignInCrypto);
	const { harness, target } = props.fixture;
	const targetFile = path.join(
		path.dirname(harness.target.tokenCachePath),
		'engine-cli-target.json',
	);
	return async (args, options = {}) => {
		await writeFile(
			targetFile,
			JSON.stringify({ ...harness.target, organizationId: target.organizationId }),
			{ mode: 0o600 },
		);
		const lines: string[] = [];
		const exitCode = await runOwnerCli(
			['--target', targetFile, 'engine', ...args, ...flagsFor(options)],
			{
				io: props.io,
				store: () => store,
				confirmSecondFactor:
					props.confirmSecondFactor ??
					(async () => {
						throw new Error('no step-up expected');
					}),
				write: (line) => lines.push(line),
			},
		);
		return { exitCode, lines };
	};
}

it('engine health: the owner reads all seven kinds and the alarm', async () => {
	// Arrange: one retired attempt of each kind, and one still failing.
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const organizationId = target.organizationId;
		const attemptIds = ascendingIds(engineKindNames.length + 1);
		for (const [index, kind] of engineKindNames.entries())
			harness.centralEngine.seedRetired({
				organizationId,
				attemptId: attemptIds[index] ?? '',
				kind,
				firstFailedAt: '2026-11-23T08:00:01.123456Z',
			});
		harness.centralEngine.seedFailing({
			organizationId,
			attemptId: attemptIds.at(-1) ?? '',
			kind: 'direct_message',
		});
		harness.centralEngine.setAlarm({ at: '2026-11-23T08:10:03.456Z', missing: false });
		const engine = engineCli({ fixture, io: fixture.io });
		// Act
		const health = await engine(['health']);
		// Assert
		expect(health.exitCode).toBe(0);
		expect(health.lines).toEqual([
			'Engine alarm: 2026-11-23T08:10:03.456Z.',
			...engineKindNames.map(
				(kind) =>
					`${kind}  failing ${kind === 'direct_message' ? 1 : 0}  retired 1  oldest failure ${kind === 'direct_message' ? '2026-11-23T08:00:00.123456789Z' : '2026-11-23T08:00:01.123456Z'}  last failure ${kind === 'direct_message' ? 'other_store_unavailable' : 'statement_rejected'}`,
			),
		]);
		const [arrival] = harness.centralEngine.arrivals;
		expect(arrival).toMatchObject({
			route: 'EngineHealth',
			outcome: { kind: 'replied', replayed: false },
		});
		expect(arrival?.permissions).toContain('organization:readAudit');
	} finally {
		await harness.close();
	}
});

it('engine retired: the walk asks again through an empty page that carries a cursor, and ends only on next: null', async () => {
	// Arrange: 400 failing attempts fill the first scan's cap (4 x 100) with nothing visible.
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const organizationId = target.organizationId;
		const attemptIds = ascendingIds(401);
		const hidden = attemptIds.slice(0, 400);
		const visible = attemptIds[400] ?? '';
		for (const attemptId of hidden)
			harness.centralEngine.seedFailing({ organizationId, attemptId });
		const engine = engineCli({ fixture, io: fixture.io });
		// Act 1: only hidden rows. The full scan gives a cursor; the continuation, the explicit end.
		const onlyHidden = await engine(['retired']);
		// Assert 1
		expect(onlyHidden).toEqual({ exitCode: 0, lines: ['No retired engine work.'] });
		const pages = (): readonly unknown[] =>
			harness.centralEngine.arrivals
				.filter((arrival) => arrival.route === 'EngineListRetired')
				.map((arrival) =>
					arrival.outcome.kind === 'replied' ? JSON.parse(arrival.outcome.bytes) : arrival.outcome,
				);
		expect(pages()).toEqual([
			{ result: 'engineRetired', items: [], next: hidden.at(-1) },
			{ result: 'engineRetired', items: [], next: null },
		]);
		// Act 2: one retired attempt after the hidden rows.
		harness.centralEngine.seedRetired({ organizationId, attemptId: visible });
		const withVisible = await engine(['retired']);
		// Assert 2: the empty page with a cursor did not end the walk.
		expect(withVisible.exitCode).toBe(0);
		expect(withVisible.lines).toEqual([
			expect.stringMatching(new RegExp(`^${visible}  wake_timer  subject `, 'u')),
			'End of the retired list.',
		]);
		expect(pages().slice(2)).toEqual([
			{ result: 'engineRetired', items: [], next: hidden.at(-1) },
			{
				result: 'engineRetired',
				items: [expect.objectContaining({ attemptId: visible })],
				next: null,
			},
		]);
		// Act 3: --cursor continues after the cursor given.
		const continued = await engine(['retired'], { cursor: hidden.at(-1) ?? '' });
		expect(continued.lines).toEqual([
			expect.stringMatching(new RegExp(`^${visible}  `, 'u')),
			'End of the retired list.',
		]);
	} finally {
		await harness.close();
	}
});

it("engine retired: central's empty 503 for an invalid stored attempt is shown as unavailable", async () => {
	// Arrange
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const [invalid = ''] = ascendingIds(1);
		harness.centralEngine.seedInvalidState({
			organizationId: target.organizationId,
			attemptId: invalid,
		});
		const engine = engineCli({ fixture, io: fixture.io });
		// Act
		const result = await engine(['retired']);
		// Assert
		expect(result).toEqual({
			exitCode: 1,
			lines: ['Central is unavailable; nothing was read. Repeat with: engine retired.'],
		});
		expect(harness.centralEngine.arrivals.map((arrival) => arrival.outcome)).toEqual([
			{ kind: 'storage-error' },
		]);
	} finally {
		await harness.close();
	}
});

it('engine retry and discard with a fresh factor apply once; a repeat with the operation ID replays', async () => {
	// Arrange: the owner's sign-in confirmed a factor just now, inside central's 900 s.
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const organizationId = target.organizationId;
		const [retried = '', discarded = '', unsupported = '', gone = '', failing = ''] =
			ascendingIds(5);
		harness.centralEngine.seedRetired({ organizationId, attemptId: retried });
		harness.centralEngine.seedRetired({ organizationId, attemptId: discarded });
		harness.centralEngine.seedRetired({
			organizationId,
			attemptId: unsupported,
			kind: 'direct_message',
		});
		harness.centralEngine.seedRetired({ organizationId, attemptId: gone, subject: 'gone' });
		harness.centralEngine.seedFailing({ organizationId, attemptId: failing });
		const engine = engineCli({ fixture, io: fixture.io });
		const operationId = ids.nextId();
		// Act / Assert
		expect(await engine(['retry', retried], { 'operation-id': operationId })).toEqual({
			exitCode: 0,
			lines: [`Retried: attempt ${retried} is due again.`],
		});
		expect(harness.centralEngine.holdsAttempt(organizationId, retried)).toBe(false);
		expect(await engine(['discard', discarded])).toEqual({
			exitCode: 0,
			lines: [`Discarded: attempt ${discarded}'s subject is finished and the attempt removed.`],
		});
		expect(harness.centralEngine.holdsAttempt(organizationId, discarded)).toBe(false);
		// The same operation again, with a fresh proof: central's retained reply, applied once.
		expect(await engine(['retry', retried], { 'operation-id': operationId })).toEqual({
			exitCode: 0,
			lines: [`Retried: attempt ${retried} is due again.`],
		});
		// The same operation ID for a different request is a conflict.
		expect(await engine(['discard', retried], { 'operation-id': operationId })).toEqual({
			exitCode: 2,
			lines: ['This operation id was already used for a different request; nothing changed.'],
		});
		expect((await engine(['retry', ids.nextId()])).lines).toEqual([
			expect.stringMatching(/^Not found: there is no retired attempt /u),
		]);
		expect((await engine(['retry', failing])).lines).toEqual([
			`Not retired: attempt ${failing} is still failing, not retired; nothing changed.`,
		]);
		expect((await engine(['discard', unsupported])).lines).toEqual([
			`Discard is not supported for attempt ${unsupported}'s kind of work; nothing changed. Retry it instead.`,
		]);
		expect((await engine(['discard', gone])).lines).toEqual([
			`Stale: attempt ${gone}'s subject moved or is gone; nothing changed.`,
		]);
		const changes = harness.centralEngine.arrivals.filter(
			(arrival) => arrival.route === 'EngineRetry' || arrival.route === 'EngineDiscard',
		);
		expect(changes.slice(0, 4).map((arrival) => arrival.outcome)).toEqual([
			{ kind: 'replied', bytes: '{"result":"engineRetried"}', replayed: false },
			{ kind: 'replied', bytes: '{"result":"engineDiscarded"}', replayed: false },
			{ kind: 'replied', bytes: '{"result":"engineRetried"}', replayed: true },
			{ kind: 'replied', bytes: '{"result":"refused","reason":"conflict"}', replayed: false },
		]);
		expect(
			changes.every((arrival) => arrival.permissions?.includes('organization:repairWork')),
		).toBe(true);
	} finally {
		await harness.close();
	}
});

it.each(['retry', 'discard'] as const)(
	'engine %s without a fresh factor: the step-up, a same-key refresh and one resend apply once; a declined step-up sends nothing again',
	async (subcommand) => {
		// Arrange: past central's 900-second window since the owner's app confirmation.
		const fixture = await setupFleetCli();
		const { harness, target } = fixture;
		try {
			const organizationId = target.organizationId;
			const [declined = '', confirmed = ''] = ascendingIds(2);
			harness.centralEngine.seedRetired({ organizationId, attemptId: declined });
			harness.centralEngine.seedRetired({ organizationId, attemptId: confirmed });
			await fixture.setTime(initialTime + 901_000);
			const decline = engineCli({
				fixture,
				io: fixture.io,
				confirmSecondFactor: async () => false,
			});
			const confirm = engineCli({
				fixture,
				io: fixture.io,
				confirmSecondFactor: async () =>
					(await harness.totpAuthenticator.confirmApp(ownerEmail, harness.auth)).ok,
			});
			// Act
			const notConfirmed = await decline([subcommand, declined]);
			const applied = await confirm([subcommand, confirmed]);
			// Assert
			expect(notConfirmed).toEqual({
				exitCode: 2,
				lines: [`Not confirmed; the ${subcommand} was not sent again. Nothing changed.`],
			});
			expect(harness.centralEngine.holdsAttempt(organizationId, declined)).toBe(true);
			expect(applied.exitCode).toBe(0);
			expect(harness.centralEngine.holdsAttempt(organizationId, confirmed)).toBe(false);
			const arrivals = harness.centralEngine.arrivals;
			expect(arrivals.map((arrival) => arrival.outcome)).toEqual([
				{ kind: 'refused', reason: 'secondFactorRequired' },
				{ kind: 'refused', reason: 'secondFactorRequired' },
				{
					kind: 'replied',
					bytes: `{"result":"${subcommand === 'retry' ? 'engineRetried' : 'engineDiscarded'}"}`,
					replayed: false,
				},
			]);
			// The resend is the same operation and the same bytes, under a renewed token.
			const [, refused, resent] = arrivals;
			expect(resent?.operationId).toBe(z.uuidv7().parse(refused?.operationId));
			expect(resent?.bodySha256).toBe(refused?.bodySha256);
		} finally {
			await harness.close();
		}
	},
);

it('engine: a member, who holds neither organization:readAudit nor organization:repairWork, is refused by central', async () => {
	// Arrange: the owner invites a member, who signs in, accepts, and signs in to the fleet CLI.
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const organizationId = target.organizationId;
		const [attemptId = ''] = ascendingIds(1);
		harness.centralEngine.seedRetired({ organizationId, attemptId });
		const invited = await peoplePost(
			harness,
			'invite-member',
			{ organizationId, email: 'member@example.invalid', role: 'member' },
			fixture.cookie,
		);
		const invitationId = z.object({ id: z.uuidv7() }).parse(await invited.json()).id;
		const memberId = await signInConfirmedPeopleBrowser({
			harness,
			email: 'member@example.invalid',
		});
		expect((await peoplePost(harness, 'accept-invitation', { invitationId })).status).toBe(200);
		await harness.settleDeferredWork();
		const memberIo = fleetCliIoFor({
			harness,
			cookie: harness.cookie(),
			now: () => initialTime,
			sent: [],
		});
		const engine = engineCli({ fixture, io: memberIo });
		// Act / Assert
		expect(await engine(['health'])).toEqual({
			exitCode: 2,
			lines: [
				"Not permitted: reading engine health needs the organization owner's organization:readAudit.",
			],
		});
		expect(await engine(['retired'])).toMatchObject({ exitCode: 2 });
		expect(await engine(['retry', attemptId])).toEqual({
			exitCode: 2,
			lines: [
				"Not permitted: repairing engine work needs the organization owner's organization:repairWork.",
			],
		});
		const arrivals = harness.centralEngine.arrivals;
		expect(arrivals.map((arrival) => [arrival.route, arrival.outcome])).toEqual([
			['EngineHealth', { kind: 'refused', reason: 'notPermitted' }],
			['EngineListRetired', { kind: 'refused', reason: 'notPermitted' }],
			['EngineRetry', { kind: 'refused', reason: 'notPermitted' }],
		]);
		expect(arrivals.every((arrival) => arrival.personId === memberId)).toBe(true);
		expect(
			arrivals.some(
				(arrival) =>
					arrival.permissions?.includes('organization:readAudit') === true ||
					arrival.permissions?.includes('organization:repairWork') === true,
			),
		).toBe(false);
		expect(harness.centralEngine.holdsAttempt(organizationId, attemptId)).toBe(true);
	} finally {
		await harness.close();
	}
});
