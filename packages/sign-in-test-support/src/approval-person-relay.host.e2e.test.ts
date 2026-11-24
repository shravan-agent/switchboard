import { writeFile } from 'node:fs/promises';
import path from 'node:path';

import { canonicalJson } from '@agent-collaboration/sign-in-core';
import {
	createMemoryProofKeyStore,
	runOwnerCli,
	sendApprovalOperation,
	signInFleetCli,
	type ApprovalsCommandOptions,
	type FleetCliIo,
} from '@agent-collaboration/sign-in-owner-cli';
import { createWebSignInCapabilities } from '@agent-collaboration/sign-in-platform-web';
import { expect, it } from 'vitest';
import { z } from 'zod';

import { useControlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-node-test-clock';
import {
	fleetCliIoFor,
	initialTime,
	setupFleetCli,
	type FleetFixture,
} from '#sign-in-test-support/test-fixtures/fleet-cli-fixture';
import {
	peoplePost,
	signInConfirmedPeopleBrowser,
} from '#sign-in-test-support/test-fixtures/people-browser-login';
import { webSignInCrypto } from '#sign-in-test-support/test-fixtures/recording-sign-in-capabilities';

useControlledSignInClock();

const ids = createWebSignInCapabilities().ids;
const minute = 60_000;

/** The command-line flags for `options`, as a person types them. */
function flagsFor(options: ApprovalsCommandOptions): readonly string[] {
	return [
		...(options.all === true ? ['--all'] : []),
		...(options.cursor === undefined ? [] : ['--cursor', options.cursor]),
		...(options.option === undefined ? [] : ['--option', options.option]),
		...(options['operation-id'] === undefined ? [] : ['--operation-id', options['operation-id']]),
		...(options.field ?? []).flatMap((field) => ['--field', field]),
		...(options.answer === undefined ? [] : ['--answer', options.answer]),
	];
}

/**
 * One `approvals` command through the owner CLI's real entry (`runOwnerCli`: its argument
 * parsing, target file and dispatch), with this person's fleet credential, against the running
 * sign-in host and its central stand-in.
 */
function approvalsCli(props: {
	readonly fixture: FleetFixture;
	readonly io: FleetCliIo;
	readonly organizationId: string;
}): (
	args: readonly string[],
	options?: ApprovalsCommandOptions,
) => Promise<{ readonly exitCode: number; readonly lines: readonly string[] }> {
	const store = createMemoryProofKeyStore(webSignInCrypto);
	const { harness } = props.fixture;
	const targetFile = path.join(
		path.dirname(harness.target.tokenCachePath),
		'approvals-cli-target.json',
	);
	return async (args, options = {}) => {
		await writeFile(
			targetFile,
			JSON.stringify({ ...harness.target, organizationId: props.organizationId }),
			{
				mode: 0o600,
			},
		);
		const lines: string[] = [];
		const exitCode = await runOwnerCli(
			['--target', targetFile, 'approvals', ...args, ...flagsFor(options)],
			{
				io: props.io,
				store: () => store,
				confirmSecondFactor: async () => {
					throw new Error('approvals never ask for a second factor');
				},
				write: (line) => lines.push(line),
			},
		);
		return { exitCode, lines };
	};
}

it('approvals: the owner lists, reads and decides through the relay; central replies in its committed shapes', async () => {
	// Arrange: four unproven calls in the owner's organization, one raised past its deadline.
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const organizationId = target.organizationId;
		// Central orders by request id; ids minted in one millisecond differ only in random bits,
		// so they are named in id order: timedOut < first < second < third.
		const [timedOut = '', first = '', second = '', third = ''] = [
			ids.nextId(),
			ids.nextId(),
			ids.nextId(),
			ids.nextId(),
		].toSorted();
		harness.centralApprovals.seedUnprovenCall({
			organizationId,
			requestId: timedOut,
			raisedAtMillis: initialTime - 120 * minute,
		});
		for (const [index, requestId] of [first, second, third].entries())
			harness.centralApprovals.seedUnprovenCall({
				organizationId,
				requestId,
				raisedAtMillis: initialTime - (10 - index) * minute,
			});
		harness.centralApprovals.setPageSize(2);
		const approvals = approvalsCli({ fixture, io: fixture.io, organizationId });

		// Act / Assert: list pages newest first; the timed-out call is waiting no longer.
		const firstPage = await approvals(['list']);
		expect(firstPage.exitCode).toBe(0);
		expect(firstPage.lines.map((line) => line.split('  ')[0])).toEqual([
			third,
			second,
			`More: approvals list --cursor ${second}`,
		]);
		const secondPage = await approvals(['list'], { cursor: second });
		expect(secondPage.lines.map((line) => line.split('  ')[0])).toEqual([first]);
		const everything = await approvals(['list'], { all: true, cursor: first });
		expect(everything.lines).toEqual([
			expect.stringMatching(new RegExp(`^${timedOut}  unproven call  timedOut  `, 'u')),
		]);

		// read: a request this organization does not hold is notVisible.
		expect(await approvals(['show', ids.nextId()])).toEqual({ exitCode: 2, lines: ['Not found.'] });
		const shown = await approvals(['show', first]);
		expect(shown.exitCode).toBe(0);
		expect(shown.lines[0]).toBe(`${first}  unproven call  waiting`);

		// decide: saved, then a second answer is alreadyDecided, naming who and when.
		expect(await approvals(['approve', first])).toEqual({
			exitCode: 0,
			lines: ['Decision saved: allow.'],
		});
		const again = await approvals(['deny', first]);
		expect(again.exitCode).toBe(2);
		const ownerId = harness.centralApprovals.arrivals.at(-1)?.personId;
		expect(again.lines).toEqual([
			`Already decided by person ${ownerId} at ${new Date(initialTime).toISOString().replace('.000Z', 'Z')}; this answer was not saved.`,
		]);
		// tooLate: the deadline passed before an answer.
		expect(await approvals(['approve', timedOut])).toEqual({
			exitCode: 2,
			lines: ['Too late: the request timed out or was closed before an answer.'],
		});
		// operationConflict: the same operation id with a different answer.
		const operationId = ids.nextId();
		expect((await approvals(['approve', second], { 'operation-id': operationId })).exitCode).toBe(
			0,
		);
		expect(await approvals(['deny', second], { 'operation-id': operationId })).toEqual({
			exitCode: 2,
			lines: ['This operation id was already used with a different answer.'],
		});

		// Every C3 request reached central with the owner's own credential and approval:decide.
		const arrivals = harness.centralApprovals.arrivals;
		expect(arrivals.every((arrival) => arrival.outcome.kind === 'replied')).toBe(true);
		expect(new Set(arrivals.map((arrival) => arrival.personId))).toEqual(new Set([ownerId]));
		expect(arrivals.every((arrival) => arrival.permissions?.includes('approval:decide'))).toBe(
			true,
		);
	} finally {
		await harness.close();
	}
});

it('approvals: a lost decide reply is recovered by the retry with the same operation id, not decided twice', async () => {
	// Arrange
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const organizationId = target.organizationId;
		const requestId = ids.nextId();
		harness.centralApprovals.seedUnprovenCall({
			organizationId,
			requestId,
			raisedAtMillis: initialTime - minute,
		});
		harness.centralApprovals.loseNextDecideReply();
		const approvals = approvalsCli({ fixture, io: fixture.io, organizationId });
		// Act
		const result = await approvals(['approve', requestId]);
		// Assert: the first decide was applied and its reply lost; the retry got the same result.
		expect(result).toEqual({ exitCode: 0, lines: ['Decision saved: allow.'] });
		const decides = harness.centralApprovals.arrivals.filter(
			(arrival) => arrival.route === 'ApprovalDecide',
		);
		expect(decides.map((arrival) => arrival.outcome)).toEqual([
			{
				kind: 'replied',
				reply: expect.objectContaining({ kind: 'savedDecision' }),
				delivered: false,
			},
			{
				kind: 'replied',
				reply: expect.objectContaining({ kind: 'savedDecision' }),
				delivered: true,
			},
		]);
		expect(decides[0]?.operationId).toEqual(z.uuidv7().parse(decides[1]?.operationId));
		expect(decides[0]?.bodySha256).toBe(decides[1]?.bodySha256);
	} finally {
		await harness.close();
	}
});

it('approvals: a member, who holds no approval:decide, is refused by central on every route', async () => {
	// Arrange: the owner invites a member, who signs in, accepts, and signs in to the fleet CLI.
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const organizationId = target.organizationId;
		const requestId = ids.nextId();
		harness.centralApprovals.seedUnprovenCall({
			organizationId,
			requestId,
			raisedAtMillis: initialTime - minute,
		});
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
		const approvals = approvalsCli({ fixture, io: memberIo, organizationId });
		const notPermitted =
			"Not permitted: answering approvals needs the organization owner's approval:decide.";
		// Act / Assert
		expect(await approvals(['list'])).toEqual({ exitCode: 2, lines: [notPermitted] });
		expect(await approvals(['approve', requestId])).toEqual({ exitCode: 2, lines: [notPermitted] });
		const arrivals = harness.centralApprovals.arrivals;
		expect(arrivals.map((arrival) => [arrival.route, arrival.outcome])).toEqual([
			['ApprovalList', { kind: 'refused', reason: 'notPermitted' }],
			['ApprovalRead', { kind: 'refused', reason: 'notPermitted' }],
		]);
		expect(arrivals.every((arrival) => arrival.personId === memberId)).toBe(true);
		expect(arrivals.some((arrival) => arrival.permissions?.includes('approval:decide'))).toBe(
			false,
		);
	} finally {
		await harness.close();
	}
});

it('approvals: provider approvals resolve one option or refuse locally; questions take typed fields or refuse locally', async () => {
	// Arrange: two single-option approvals, one with two allow options, and a question.
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const organizationId = target.organizationId;
		const raisedAtMillis = initialTime - minute;
		const allowOnce = {
			id: 1,
			label: 'Allow once',
			effect: 'allow',
			lasts: { kind: 'thisRequest' },
		} as const;
		const decline = {
			id: 2,
			label: 'Decline',
			effect: 'decline',
			lasts: { kind: 'thisRequest' },
		} as const;
		const alwaysAllow = {
			id: 4,
			label: 'Always allow',
			effect: 'allow',
			lasts: { kind: 'keptUntilChanged', kept: 'agentSettingsFile' },
		} as const;
		const single = {
			title: 'Run the migration',
			description: null,
			subject: null,
			options: [allowOnce, decline],
		};
		const ambiguous = { ...single, options: [allowOnce, alwaysAllow, decline] };
		const [approveOne, denyOne, choose, asked] = [
			ids.nextId(),
			ids.nextId(),
			ids.nextId(),
			ids.nextId(),
		];
		const seed = { organizationId, raisedAtMillis };
		harness.centralApprovals.seedProviderApproval({
			...seed,
			requestId: approveOne,
			offer: single,
		});
		harness.centralApprovals.seedProviderApproval({ ...seed, requestId: denyOne, offer: single });
		harness.centralApprovals.seedProviderApproval({ ...seed, requestId: choose, offer: ambiguous });
		harness.centralApprovals.seedQuestion({
			...seed,
			requestId: asked,
			offer: {
				prompt: 'Why and where?',
				fields: [
					{ kind: 'text', fieldId: 1, label: 'Reason', description: null, required: true },
					{
						kind: 'singleChoice',
						fieldId: 2,
						label: 'Region',
						description: null,
						required: false,
						options: [
							{ optionId: 1, label: 'East' },
							{ optionId: 2, label: 'West' },
						],
					},
				],
			},
		});
		const approvals = approvalsCli({ fixture, io: fixture.io, organizationId });
		const decides = (): readonly unknown[] =>
			harness.centralApprovals.arrivals.filter((arrival) => arrival.route === 'ApprovalDecide');
		const ambiguousOptions = [
			'Options:',
			'  option 1  allow  this request only  Allow once',
			'  option 4  allow  kept until changed (in the agent settings file)  Always allow',
			'  option 2  decline  this request only  Decline',
		];

		// Act / Assert: the single allow and the single decline option.
		expect(await approvals(['approve', approveOne])).toEqual({
			exitCode: 0,
			lines: ['Decision saved: option 1.'],
		});
		expect(await approvals(['deny', denyOne])).toEqual({
			exitCode: 0,
			lines: ['Decision saved: option 2.'],
		});
		// show lists every option; an ambiguous approve is refused before anything is sent.
		const shown = await approvals(['show', choose]);
		expect(shown.lines.slice(1, 6)).toEqual(['Title: Run the migration', ...ambiguousOptions]);
		const decidesBefore = decides().length;
		expect(await approvals(['approve', choose])).toEqual({
			exitCode: 2,
			lines: [
				'More than one option is an allow; choose one with --option. No decision was sent.',
				...ambiguousOptions,
			],
		});
		expect(decides()).toHaveLength(decidesBefore);
		// --option names one explicitly.
		expect(await approvals(['approve', choose], { option: '4' })).toEqual({
			exitCode: 0,
			lines: ['Decision saved: option 4.'],
		});

		// A bad field is refused before anything is sent, listing the fields.
		const beforeQuestion = decides().length;
		expect(await approvals(['answer', asked], { field: ['1=latency', '2=North'] })).toEqual({
			exitCode: 2,
			lines: [
				'The value for field 2 does not fit that field. No decision was sent.',
				'Fields:',
				'  field 1  text  required  Reason',
				'  field 2  one option id  optional  Region',
				'    option 1  East',
				'    option 2  West',
			],
		});
		expect(decides()).toHaveLength(beforeQuestion);
		// Fields that fit are answered; repeated --field flags reach the answer in order.
		expect(await approvals(['answer', asked], { field: ['2=2', '1=latency'] })).toEqual({
			exitCode: 0,
			lines: ['Decision saved: answered.'],
		});

		// Central (the stand-in, with central's answer checks) received exactly these answers.
		expect(
			harness.centralApprovals.arrivals
				.filter((arrival) => arrival.route === 'ApprovalDecide')
				.map((arrival) => arrival.outcome),
		).toEqual([
			{
				kind: 'replied',
				delivered: true,
				reply: expect.objectContaining({
					kind: 'savedDecision',
					decision: expect.objectContaining({ answer: { kind: 'approval', optionId: 1 } }),
				}),
			},
			{
				kind: 'replied',
				delivered: true,
				reply: expect.objectContaining({
					kind: 'savedDecision',
					decision: expect.objectContaining({ answer: { kind: 'approval', optionId: 2 } }),
				}),
			},
			{
				kind: 'replied',
				delivered: true,
				reply: expect.objectContaining({
					kind: 'savedDecision',
					decision: expect.objectContaining({ answer: { kind: 'approval', optionId: 4 } }),
				}),
			},
			{
				kind: 'replied',
				delivered: true,
				reply: expect.objectContaining({
					kind: 'savedDecision',
					decision: expect.objectContaining({
						answer: {
							kind: 'question',
							answer: {
								kind: 'answered',
								fields: [
									{ fieldId: 2, value: { kind: 'selectedOptions', selectedOptionIds: [2] } },
									{ fieldId: 1, value: { kind: 'text', value: 'latency' } },
								],
							},
						},
					}),
				}),
			},
		]);
	} finally {
		await harness.close();
	}
});

it('approvals: a multi-choice field takes a comma list; duplicates, unknown ids and counts out of range are refused locally', async () => {
	// Arrange: a question whose one field takes one or two of three options.
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const organizationId = target.organizationId;
		const asked = ids.nextId();
		harness.centralApprovals.seedQuestion({
			organizationId,
			requestId: asked,
			raisedAtMillis: initialTime - minute,
			offer: {
				prompt: 'Which zones?',
				fields: [
					{
						kind: 'multiChoice',
						fieldId: 1,
						label: 'Zones',
						description: null,
						required: true,
						selection: {
							options: [
								{ optionId: 1, label: 'North' },
								{ optionId: 2, label: 'South' },
								{ optionId: 3, label: 'Central' },
							],
							min: 1,
							max: 2,
						},
					},
				],
			},
		});
		const approvals = approvalsCli({ fixture, io: fixture.io, organizationId });
		const fields = [
			'Fields:',
			'  field 1  option ids, comma-separated (1 to 2)  required  Zones',
			'    option 1  North',
			'    option 2  South',
			'    option 3  Central',
		];
		const decides = (): number =>
			harness.centralApprovals.arrivals.filter((arrival) => arrival.route === 'ApprovalDecide')
				.length;

		// Act / Assert: each refusal lists the field's options and sends nothing.
		for (const [value, words] of [
			['1,2,3', 'Field 1 takes 1 to 2 options, not 3. No decision was sent.'],
			['2,2', 'Field 1 lists option 2 more than once. No decision was sent.'],
			['1,7', 'Field 1 has no option "7". No decision was sent.'],
		] as const)
			expect(await approvals(['answer', asked], { field: [`1=${value}`] })).toEqual({
				exitCode: 2,
				lines: [words, ...fields],
			});
		expect(decides()).toBe(0);
		// Two offered options within the count are answered, in the order given.
		expect(await approvals(['answer', asked], { field: ['1=3,1'] })).toEqual({
			exitCode: 0,
			lines: ['Decision saved: answered.'],
		});
		expect(harness.centralApprovals.arrivals.at(-1)?.outcome).toEqual({
			kind: 'replied',
			delivered: true,
			reply: expect.objectContaining({
				kind: 'savedDecision',
				decision: expect.objectContaining({
					answer: {
						kind: 'question',
						answer: {
							kind: 'answered',
							fields: [
								{ fieldId: 1, value: { kind: 'selectedOptions', selectedOptionIds: [3, 1] } },
							],
						},
					},
				}),
			}),
		});
	} finally {
		await harness.close();
	}
});

/** The owner's role, changed through the production fenced adapter (a revision bump and push). */
async function setRole(
	fixture: FleetFixture,
	personId: string,
	role: 'owner' | 'member',
): Promise<void> {
	const changed = await fixture.harness.auth('/__auth-proof/authorization-fence', {
		method: 'POST',
		headers: { 'content-type': 'application/json', cookie: fixture.cookie },
		body: JSON.stringify({
			kind: 'update',
			model: 'member',
			where: [{ field: 'userId', value: personId }],
			update: { role },
		}),
	});
	expect(changed.status).toBe(200);
	await fixture.harness.settleDeferredWork();
}

it('approvals: after the grant is lost, a repeat with --operation-id reaches Decide with no read and gets the retained result', async () => {
	// Arrange: the owner approves an unproven call; central retains the result.
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const organizationId = target.organizationId;
		const requestId = ids.nextId();
		harness.centralApprovals.seedUnprovenCall({
			organizationId,
			requestId,
			raisedAtMillis: initialTime - minute,
		});
		const approvals = approvalsCli({ fixture, io: fixture.io, organizationId });
		expect(await approvals(['approve', requestId])).toEqual({
			exitCode: 0,
			lines: ['Decision saved: allow.'],
		});
		const first = harness.centralApprovals.arrivals.at(-1);
		const operationId = z.uuidv7().parse(first?.operationId);
		const ownerId = z.uuidv7().parse(first?.personId);
		// The owner loses approval:decide: their role becomes member (revision bumped and pushed).
		await setRole(fixture, ownerId, 'member');
		const arrivalsBefore = harness.centralApprovals.arrivals.length;
		// A plain approve now reads first, and central refuses the read.
		expect(await approvals(['approve', requestId])).toEqual({
			exitCode: 2,
			lines: ["Not permitted: answering approvals needs the organization owner's approval:decide."],
		});
		// Act: the recovery states the exact answer and goes straight to Decide.
		const recovered = await approvals(['approve', requestId], { 'operation-id': operationId });
		// Assert
		expect(recovered).toEqual({ exitCode: 0, lines: ['Decision saved: allow.'] });
		const after = harness.centralApprovals.arrivals.slice(arrivalsBefore);
		expect(after.map((arrival) => [arrival.route, arrival.outcome.kind])).toEqual([
			['ApprovalRead', 'refused'],
			['ApprovalDecide', 'replied'],
		]);
		const recovery = after[1];
		expect(recovery?.operationId).toBe(operationId);
		expect(recovery?.permissions).not.toContain('approval:decide');
		expect(recovery?.outcome).toEqual(first?.outcome);
		// A different answer under the same id is not a recovery: central refuses it.
		expect(await approvals(['deny', requestId], { 'operation-id': operationId })).toEqual({
			exitCode: 2,
			lines: ["Not permitted: answering approvals needs the organization owner's approval:decide."],
		});
	} finally {
		await harness.close();
	}
});

it("approvals: the stand-in keeps central's order: a contract-invalid body behind a bad proof is 401, and a token behind its revision is refreshRequired", async () => {
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const organizationId = target.organizationId;
		// Central reads only the address, verifies, then decodes the body: 401, not 400.
		const unsigned = await fetch(
			new URL('/api/auth/organization-admin/v1/approval-list', target.issuer),
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
		expect(unsigned.status).toBe(401);
		expect(harness.centralApprovals.arrivals.at(-1)?.outcome).toEqual({
			kind: 'refused-unauthenticated',
			failure: 'token',
		});
		// A token issued before the person's revision moved is refused refreshRequired.
		const store = createMemoryProofKeyStore(webSignInCrypto);
		const session = await signInFleetCli({ target, store, io: fixture.io });
		const list = await sendApprovalOperation({
			target,
			session,
			io: fixture.io,
			operation: {
				operation: 'ApprovalList',
				organization: organizationId,
				filter: 'waiting',
				cursor: null,
			},
		});
		expect(list).toMatchObject({ kind: 'replied' });
		const ownerId = z.uuidv7().parse(harness.centralApprovals.arrivals.at(-1)?.personId);
		// The role change bumps the person's revision past the token's; the floor check comes first.
		await setRole(fixture, ownerId, 'member');
		expect(
			await sendApprovalOperation({
				target,
				session,
				io: fixture.io,
				operation: {
					operation: 'ApprovalList',
					organization: organizationId,
					filter: 'waiting',
					cursor: null,
				},
			}),
		).toEqual({ kind: 'refused', reason: 'refreshRequired' });
	} finally {
		await harness.close();
	}
});

it("approvals: after the grant is lost, a question's repeat with --operation-id --answer gets the retained result", async () => {
	// Arrange: the owner answers a question with --field; central retains the result.
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const organizationId = target.organizationId;
		const asked = ids.nextId();
		harness.centralApprovals.seedQuestion({
			organizationId,
			requestId: asked,
			raisedAtMillis: initialTime - minute,
			offer: {
				prompt: 'Why and where?',
				fields: [
					{ kind: 'text', fieldId: 1, label: 'Reason', description: null, required: true },
					{ kind: 'number', fieldId: 2, label: 'Replicas', description: null, required: false },
				],
			},
		});
		const approvals = approvalsCli({ fixture, io: fixture.io, organizationId });
		expect(await approvals(['answer', asked], { field: ["1=it's latency", '2=3'] })).toEqual({
			exitCode: 0,
			lines: ['Decision saved: answered.'],
		});
		const first = harness.centralApprovals.arrivals.at(-1);
		const operationId = z.uuidv7().parse(first?.operationId);
		const ownerId = z.uuidv7().parse(first?.personId);
		// The exact answer, as the no-answer advice prints it: the canonical JSON of what was sent.
		const answered = {
			kind: 'answered',
			fields: [
				{ fieldId: 1, value: { kind: 'text', value: "it's latency" } },
				{ fieldId: 2, value: { kind: 'number', value: '3' } },
			],
		};
		await setRole(fixture, ownerId, 'member');
		const arrivalsBefore = harness.centralApprovals.arrivals.length;
		// Act
		const recovered = await approvals(['answer', asked], {
			'operation-id': operationId,
			answer: canonicalJson(answered),
		});
		// Assert: straight to Decide, under a token without the grant, with the retained result.
		expect(recovered).toEqual({ exitCode: 0, lines: ['Decision saved: answered.'] });
		const after = harness.centralApprovals.arrivals.slice(arrivalsBefore);
		expect(after.map((arrival) => arrival.route)).toEqual(['ApprovalDecide']);
		expect(after[0]?.permissions).not.toContain('approval:decide');
		expect(after[0]?.outcome).toEqual(first?.outcome);
	} finally {
		await harness.close();
	}
});

it('approvals: the stand-in answers like central 1ede5c1b9 for a malformed proof after a valid token, a forgotten floor, and a replay', async () => {
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const organizationId = target.organizationId;
		const approvals = approvalsCli({ fixture, io: fixture.io, organizationId });
		const session = await signInFleetCli({
			target,
			store: createMemoryProofKeyStore(webSignInCrypto),
			io: fixture.io,
		});

		// A malformed DPoP header after a valid token is refused 401 (verifier.rs:153-158), not thrown.
		const malformed = await fetch(
			new URL('/api/auth/organization-admin/v1/approval-list', target.issuer),
			{
				method: 'POST',
				headers: {
					'content-type': 'application/json',
					authorization: `DPoP ${session.accessToken}`,
					dpop: 'not-a-compact-jws',
				},
				body: JSON.stringify({ organization: organizationId, filter: 'waiting' }),
			},
		);
		expect(malformed.status).toBe(401);
		expect(harness.centralApprovals.arrivals.at(-1)?.outcome).toEqual({
			kind: 'refused-unauthenticated',
			failure: 'proof-header',
		});

		// A retained replay settles no deadline (approval_store_person_decide.rs:81-105).
		const [decided, expiring] = [ids.nextId(), ids.nextId()];
		harness.centralApprovals.seedUnprovenCall({
			organizationId,
			requestId: decided,
			raisedAtMillis: initialTime - minute,
		});
		// Its deadline falls 30 seconds after now.
		harness.centralApprovals.seedUnprovenCall({
			organizationId,
			requestId: expiring,
			raisedAtMillis: initialTime - 60 * minute + 30_000,
		});
		expect(await approvals(['approve', decided])).toEqual({
			exitCode: 0,
			lines: ['Decision saved: allow.'],
		});
		const operationId = z.uuidv7().parse(harness.centralApprovals.arrivals.at(-1)?.operationId);
		await fixture.setTime(initialTime + minute);
		expect(await approvals(['approve', decided], { 'operation-id': operationId })).toEqual({
			exitCode: 0,
			lines: ['Decision saved: allow.'],
		});
		expect(harness.centralApprovals.settlements).toEqual([]);
		// A list discovers the passed deadline and settles it.
		await approvals(['list']);
		expect(harness.centralApprovals.settlements).toEqual([
			{ requestId: expiring, route: 'ApprovalList' },
		]);

		// Once central forgets the floors, admission reads the same forgotten state.
		harness.centralProvisioning.forgetFloors();
		expect(await approvals(['list'])).toEqual({
			exitCode: 2,
			lines: ['Central refused (authorizationSyncRequired).'],
		});
		expect(harness.centralApprovals.arrivals.at(-1)?.outcome).toEqual({
			kind: 'refused',
			reason: 'authorizationSyncRequired',
		});
	} finally {
		await harness.close();
	}
});
