import {
	approvalPersonIntent,
	approvalPersonIntentDigest,
	approvalPersonOperationSchema,
	canonicalJson,
} from '@agent-collaboration/sign-in-core';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { readAuthTarget } from '#sign-in-owner-cli/auth-target';
import {
	decideReplyWords,
	runApprovalsCommand,
	type ApprovalsCommandOptions,
} from '#sign-in-owner-cli/fleet/approvals-cli-command';
import type { FleetCliEnvironment } from '#sign-in-owner-cli/fleet/fleet-cli-commands';
import {
	authTarget,
	decodeJwt,
	documentedEntrypoint,
	posixShellWords,
	scenario,
	target,
} from '#sign-in-owner-cli/fleet/fleet-cli-test-world';
import { runOwnerCli } from '#sign-in-owner-cli/owner-cli';

vi.mock('#sign-in-owner-cli/auth-target', { spy: true });

const organization = target.organizationId;
/** The `--target` file in use: a space and a quote, so the printed line must quote it. */
const targetPath = "/private/runtime/owner's fleet target.json";
const requestId = '019a3dce-2000-7000-8000-0000000000c1';
const personId = '019a3dce-2000-7000-8000-0000000000d1';
const window = { raisedAt: '2026-11-23T12:00:00.007Z', deadline: '2026-11-23T13:00:00.007Z' };
const unprovenCallView = {
	kind: 'unprovenCall',
	requestId,
	offer: {
		operation: { kind: 'endSessionForGood', sessionId: '019a3dce-2000-7000-8000-0000000000e1' },
	},
	state: { kind: 'waiting' },
	window,
};
const providerApprovalView = {
	kind: 'providerApproval',
	requestId,
	offer: {
		title: 'Run the migration',
		description: null,
		subject: null,
		options: [{ id: 1, label: 'Allow once', effect: 'allow', lasts: { kind: 'thisRequest' } }],
	},
	state: { kind: 'waiting', status: 'pending' },
	window,
};
const twoAllowsView = {
	...providerApprovalView,
	offer: {
		...providerApprovalView.offer,
		options: [
			{ id: 1, label: 'Allow once', effect: 'allow', lasts: { kind: 'thisRequest' } },
			{
				id: 4,
				label: 'Always allow',
				effect: 'allow',
				lasts: { kind: 'keptUntilChanged', kept: 'agentSettingsFile' },
			},
			{ id: 2, label: 'Decline', effect: 'decline', lasts: { kind: 'thisRequest' } },
		],
	},
};
const questionView = {
	kind: 'providerQuestion',
	requestId,
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
	state: { kind: 'waiting', status: 'pending' },
	window,
};
const readRequest = (view: object) => (): Response => Response.json({ kind: 'request', view });
const savedAnswer = (answer: object) => (): Response =>
	Response.json({ kind: 'savedDecision', decision: { by: { kind: 'person', personId }, answer } });
const saved = (decision: 'allow' | 'decline') => (): Response =>
	Response.json({
		kind: 'savedDecision',
		decision: { by: { kind: 'person', personId }, answer: { kind: 'unprovenCall', decision } },
	});
const unavailable = (): Response =>
	Response.json({ error: 'central-unavailable' }, { status: 503 });

/** One `approvals` command through the real entry: printed lines, exit code and relay calls. */
async function approvals(
	args: readonly string[],
	relayReplies: readonly (() => Response)[],
	options: ApprovalsCommandOptions = {},
): Promise<{
	readonly exitCode: number;
	readonly lines: string[];
	readonly calls: { readonly path: string; readonly body: unknown; readonly proof: string }[];
	/** Token refreshes: zero proves nothing reached the credential setup. */
	readonly refreshes: number;
}> {
	return observed(relayReplies, (environment) =>
		runApprovalsCommand({
			arguments: args,
			targetPath,
			target: authTarget,
			options,
			environment,
		}),
	);
}

/** Runs `command` against a scenario's relay and collects what it printed and sent. */
async function observed(
	relayReplies: readonly (() => Response)[],
	command: (environment: FleetCliEnvironment) => Promise<number>,
): Promise<{
	readonly exitCode: number;
	readonly lines: string[];
	readonly calls: { readonly path: string; readonly body: unknown; readonly proof: string }[];
	readonly refreshes: number;
}> {
	const world = await scenario(relayReplies);
	const lines: string[] = [];
	const exitCode = await command({
		io: world.io,
		store: () => world.store,
		confirmSecondFactor: async () => {
			throw new Error('approvals never ask for a second factor');
		},
		write: (line) => lines.push(line),
	});
	return {
		exitCode,
		lines,
		calls: world.relayCalls.map((call) => ({ ...call, body: JSON.parse(call.body) })),
		refreshes: world.refreshCalls.length,
	};
}

describe('approvals list', (): void => {
	it('lists waiting requests through the relay with a proof for central list route', async (): Promise<void> => {
		// Arrange
		const page = {
			kind: 'page',
			items: [{ requestId, kind: 'unprovenCall', state: { kind: 'waiting' }, ...window }],
			next: requestId,
		};
		// Act
		const result = await approvals(['list'], [() => Response.json(page)]);
		// Assert
		expect(result.exitCode).toBe(0);
		expect(result.lines).toEqual([
			`${requestId}  unproven call  waiting  raised ${window.raisedAt}  deadline ${window.deadline}`,
			`More: approvals list --cursor ${requestId}`,
		]);
		const [call] = result.calls;
		expect(call?.path).toBe('/api/auth/organization-admin/v1/approval-list');
		expect(call?.body).toEqual({ organization, filter: 'waiting' });
		const proof = decodeJwt(call?.proof ?? '');
		expect(proof['htu']).toBe(`${target.centralPublicOrigin}/organization-admin/v1/approval-list`);
		expect(proof['intent']).toBe(
			await approvalPersonIntentDigest(globalThis.crypto, {
				operation: 'ApprovalList',
				organization,
				filter: 'waiting',
				cursor: null,
			}),
		);
	});

	it('asks for every request after a cursor with --all --cursor', async (): Promise<void> => {
		const result = await approvals(
			['list'],
			[() => Response.json({ kind: 'page', items: [], next: null })],
			{ all: true, cursor: requestId },
		);
		expect(result.exitCode).toBe(0);
		expect(result.lines).toEqual(['No approval requests.']);
		expect(result.calls[0]?.body).toEqual({ organization, filter: 'all', cursor: requestId });
	});
});

describe('approvals show', (): void => {
	it('shows a request as central views it', async (): Promise<void> => {
		const result = await approvals(['show', requestId], [readRequest(unprovenCallView)]);
		expect(result.exitCode).toBe(0);
		expect(result.lines).toEqual([
			`${requestId}  unproven call  waiting`,
			JSON.stringify(unprovenCallView),
		]);
		expect(result.calls[0]?.body).toEqual({ organization, requestId });
	});

	it('says not found for a request the person may not see', async (): Promise<void> => {
		const result = await approvals(
			['show', requestId],
			[() => Response.json({ kind: 'notVisible' })],
		);
		expect(result).toMatchObject({ exitCode: 2, lines: ['Not found.'] });
	});
});

describe('approvals approve and deny', (): void => {
	it.each([
		['approve', 'allow'],
		['deny', 'decline'],
	] as const)(
		'%s reads the request, then decides %s with one minted operation id',
		async (verb, decision): Promise<void> => {
			// Act
			const result = await approvals(
				[verb, requestId],
				[readRequest(unprovenCallView), saved(decision)],
			);
			// Assert
			expect(result.exitCode).toBe(0);
			expect(result.lines).toEqual([`Decision saved: ${decision}.`]);
			expect(result.calls.map((call) => call.path)).toEqual([
				'/api/auth/organization-admin/v1/approval-read',
				'/api/auth/organization-admin/v1/approval-decide',
			]);
			const decide = result.calls[1];
			expect(decide?.body).toEqual({
				organization,
				requestId,
				operationId: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-7/u),
				answer: { kind: 'unprovenCall', decision },
			});
			expect(decodeJwt(decide?.proof ?? '')['htu']).toBe(
				`${target.centralPublicOrigin}/organization-admin/v1/approval-decide`,
			);
		},
	);

	it('retries a decide that got no answer once, with a fresh proof and the same operation id', async (): Promise<void> => {
		// Act
		const result = await approvals(
			['approve', requestId],
			[readRequest(unprovenCallView), unavailable, saved('allow')],
		);
		// Assert
		expect(result.exitCode).toBe(0);
		const [, first, retry] = result.calls;
		expect(first?.body).toEqual(retry?.body);
		expect(decodeJwt(first?.proof ?? '')['jti']).not.toBe(decodeJwt(retry?.proof ?? '')['jti']);
	});

	it('names the exact repeat command when the retry gets no answer either', async (): Promise<void> => {
		const result = await approvals(
			['approve', requestId],
			[readRequest(twoAllowsView), unavailable, unavailable],
			{ option: '4' },
		);
		expect(result.exitCode).toBe(1);
		const operationId = String(Reflect.get(Object(result.calls[1]?.body), 'operationId'));
		expect(result.lines).toEqual([
			"Central did not answer. To repeat, run the next line exactly. It sends the decide without reading the request, with this exact answer and operation id; within central's 24-hour retention it will not be decided twice.",
			`mise exec -- node scripts/verify-auth/owner-cli.ts --target '/private/runtime/owner'\\''s fleet target.json' approvals approve '${requestId}' --operation-id '${operationId}' --option '4'`,
		]);
		expect(result.calls[2]?.body).toEqual(result.calls[1]?.body);
	});

	it('approves a provider approval with its single allow option', async (): Promise<void> => {
		const result = await approvals(
			['approve', requestId],
			[readRequest(providerApprovalView), savedAnswer({ kind: 'approval', optionId: 1 })],
		);
		expect(result).toMatchObject({ exitCode: 0, lines: ['Decision saved: option 1.'] });
		expect(result.calls[1]?.body).toMatchObject({ answer: { kind: 'approval', optionId: 1 } });
	});

	it('refuses an ambiguous approve locally, sends no decide, and lists the options', async (): Promise<void> => {
		const result = await approvals(['approve', requestId], [readRequest(twoAllowsView)]);
		expect(result.exitCode).toBe(2);
		expect(result.lines).toEqual([
			'More than one option is an allow; choose one with --option. No decision was sent.',
			'Options:',
			'  option 1  allow  this request only  Allow once',
			'  option 4  allow  kept until changed (in the agent settings file)  Always allow',
			'  option 2  decline  this request only  Decline',
		]);
		expect(result.calls).toHaveLength(1);
	});

	it('answers with the --option named, overriding the effect match', async (): Promise<void> => {
		const result = await approvals(
			['approve', requestId],
			[readRequest(twoAllowsView), savedAnswer({ kind: 'approval', optionId: 4 })],
			{ option: '4' },
		);
		expect(result).toMatchObject({ exitCode: 0, lines: ['Decision saved: option 4.'] });
		expect(result.calls[1]?.body).toMatchObject({ answer: { kind: 'approval', optionId: 4 } });
	});

	it('shows every option of a provider approval', async (): Promise<void> => {
		const result = await approvals(['show', requestId], [readRequest(twoAllowsView)]);
		expect(result.lines.slice(0, 6)).toEqual([
			`${requestId}  provider approval  waiting`,
			'Title: Run the migration',
			'Options:',
			'  option 1  allow  this request only  Allow once',
			'  option 4  allow  kept until changed (in the agent settings file)  Always allow',
			'  option 2  decline  this request only  Decline',
		]);
	});

	it('answers a question with its fields', async (): Promise<void> => {
		const answer = {
			kind: 'question',
			answer: {
				kind: 'answered',
				fields: [
					{ fieldId: 1, value: { kind: 'text', value: 'latency' } },
					{ fieldId: 2, value: { kind: 'selectedOptions', selectedOptionIds: [2] } },
				],
			},
		} as const;
		const result = await approvals(
			['answer', requestId],
			[readRequest(questionView), savedAnswer(answer)],
			{ field: ['1=latency', '2=2'] },
		);
		expect(result).toMatchObject({ exitCode: 0, lines: ['Decision saved: answered.'] });
		expect(result.calls[1]?.body).toMatchObject({ answer });
	});

	it('refuses a bad field locally, sends no decide, and lists the fields', async (): Promise<void> => {
		const result = await approvals(['answer', requestId], [readRequest(questionView)], {
			field: ['1=latency', '2=North'],
		});
		expect(result.exitCode).toBe(2);
		expect(result.lines).toEqual([
			'The value for field 2 does not fit that field. No decision was sent.',
			'Fields:',
			'  field 1  text  required  Reason',
			'  field 2  one option id  optional  Region',
			'    option 1  East',
			'    option 2  West',
		]);
		expect(result.calls).toHaveLength(1);
	});

	it.each([
		['approve on a question', ['approve', requestId], () => readRequest(questionView), {}],
		[
			'answer on a provider approval',
			['answer', requestId],
			() => readRequest(providerApprovalView),
			{ field: ['1=x'] },
		],
		[
			'--option on an unproven call',
			['approve', requestId],
			() => readRequest(unprovenCallView),
			{ option: '1' },
		],
	] as const)(
		'refuses %s after the read, sending no decision',
		async (_name, args, reply, options): Promise<void> => {
			const result = await approvals(args, [reply()], options);
			expect(result.exitCode).toBe(2);
			expect(result.lines[0]).toMatch(/No decision was sent\.$/u);
			expect(result.calls).toHaveLength(1);
		},
	);

	it.each([
		[
			'answer',
			['answer', requestId],
			{ option: '1', field: ['1=x'] },
			'option',
			'takes --field, --answer, --operation-id',
		],
		[
			'approve',
			['approve', requestId],
			{ field: ['1=x'] },
			'field',
			'takes --option, --operation-id',
		],
		['list', ['list'], { option: '1' }, 'option', 'takes --all, --cursor'],
		[
			'list',
			['list'],
			{ 'operation-id': '019a3dce-2000-7000-8000-0000000000f1' },
			'operation-id',
			'takes --all, --cursor',
		],
		['show', ['show', requestId], { all: true }, 'all', 'takes no options'],
		['show', ['show', requestId], { field: ['1=x'] }, 'field', 'takes no options'],
		[
			'deny',
			['deny', requestId],
			{ cursor: requestId },
			'cursor',
			'takes --option, --operation-id',
		],
	] as const)(
		'approvals %s refuses an unsupported flag before any credential or request',
		async (subcommand, args, options, flag, takes): Promise<void> => {
			const result = await approvals(args, [], options);
			expect(result).toEqual({
				exitCode: 2,
				lines: [`approvals ${subcommand} does not take --${flag} (it ${takes}). Nothing was sent.`],
				calls: [],
				refreshes: 0,
			});
		},
	);
});

describe('recovery with --operation-id (no read)', (): void => {
	const operationId = '019a3dce-2000-7000-8000-0000000000f1';

	it.each([
		['approve', {}, { kind: 'unprovenCall', decision: 'allow' }],
		['deny', {}, { kind: 'unprovenCall', decision: 'decline' }],
		['approve', { option: '4' }, { kind: 'approval', optionId: 4 }],
		['deny', { option: '2' }, { kind: 'approval', optionId: 2 }],
	] as const)(
		'%s %j sends the decide straight away with the stated answer',
		async (verb, flags, answer): Promise<void> => {
			const result = await approvals([verb, requestId], [savedAnswer(answer)], {
				'operation-id': operationId,
				...flags,
			});
			expect(result.exitCode).toBe(0);
			expect(result.calls.map((call) => call.path)).toEqual([
				'/api/auth/organization-admin/v1/approval-decide',
			]);
			expect(result.calls[0]?.body).toEqual({ organization, requestId, operationId, answer });
		},
	);

	it.each([
		[
			'answer',
			{ field: ['1=latency'] },
			/--field and --answer|must repeat the exact answer: --answer '<json>'.*Nothing was sent\.$/u,
		],
		[
			'answer',
			{ answer: '{"kind":"answered","fields":[' },
			/must repeat the exact answer: --answer '<json>'.*Nothing was sent\.$/u,
		],
		[
			'answer',
			{ answer: '{"kind":"answered","fields":[],"note":"x"}' },
			/must repeat the exact answer: --answer '<json>'.*Nothing was sent\.$/u,
		],
		[
			'answer',
			{ answer: '{"kind":"answered","fields":[{"fieldId":1,"value":{"kind":"text"}}]}' },
			/must repeat the exact answer: --answer '<json>'.*Nothing was sent\.$/u,
		],
		[
			'approve',
			{ option: 'four' },
			/--option takes the option id the first decide used\. Nothing was sent\.$/u,
		],
	] as const)(
		'refuses %s %j before any credential or request',
		async (verb, flags, words): Promise<void> => {
			const result = await approvals([verb, requestId], [], {
				'operation-id': operationId,
				...flags,
			});
			expect(result.exitCode).toBe(2);
			expect(result.lines).toEqual([expect.stringMatching(words)]);
			expect(result.calls).toEqual([]);
			expect(result.refreshes).toBe(0);
		},
	);

	it('decides nothing for a request the person may not see', async (): Promise<void> => {
		const result = await approvals(
			['deny', requestId],
			[() => Response.json({ kind: 'notVisible' })],
		);
		expect(result).toMatchObject({ exitCode: 2, lines: ['Not found.'] });
		expect(result.calls).toHaveLength(1);
	});

	it.each([
		['tooLate', { kind: 'tooLate' }],
		['operationConflict', { kind: 'operationConflict' }],
		[
			'alreadyDecided',
			{ kind: 'alreadyDecided', by: { kind: 'person', personId }, at: window.raisedAt },
		],
	])('a %s decide exits 2 with its words', async (_name, reply): Promise<void> => {
		const result = await approvals(
			['approve', requestId],
			[readRequest(unprovenCallView), () => Response.json(reply)],
		);
		expect(result.exitCode).toBe(2);
		expect(result.lines).toHaveLength(1);
	});
});

describe('outcome words', (): void => {
	it.each([
		[
			{
				kind: 'savedDecision',
				decision: {
					by: { kind: 'person', personId },
					answer: { kind: 'unprovenCall', decision: 'allow' },
				},
			},
			'Decision saved: allow.',
		],
		[
			{ kind: 'alreadyDecided', by: { kind: 'person', personId }, at: '2026-11-23T12:15:00.007Z' },
			`Already decided by person ${personId} at 2026-11-23T12:15:00.007Z; this answer was not saved.`,
		],
		[
			{
				kind: 'alreadyDecided',
				by: { kind: 'session', session: requestId },
				at: '2026-11-23T12:15:00Z',
			},
			`Already decided by session ${requestId} at 2026-11-23T12:15:00Z; this answer was not saved.`,
		],
		[{ kind: 'tooLate' }, 'Too late: the request timed out or was closed before an answer.'],
		[
			{ kind: 'invalid', reason: { kind: 'invalidAnswer', reason: { kind: 'wrongKind' } } },
			'Not accepted: the answer does not fit the request (wrongKind).',
		],
		[
			{
				kind: 'invalid',
				reason: { kind: 'invalidApprovalEnding', reason: { kind: 'bindingMismatch' } },
			},
			'Not accepted: central could not end the request (bindingMismatch).',
		],
		[{ kind: 'notVisible' }, 'Not found.'],
		[{ kind: 'operationConflict' }, 'This operation id was already used with a different answer.'],
	] as const)('%j', (reply, words): void => {
		expect(decideReplyWords(reply)).toBe(words);
	});

	it.each([
		[
			() => Response.json({ result: 'refused', reason: 'notPermitted' }),
			2,
			"Not permitted: answering approvals needs the organization owner's approval:decide.",
		],
		[
			() => Response.json({ result: 'refused', reason: 'requestReused' }),
			2,
			'Central refused (requestReused).',
		],
		[
			() => new Response(null, { status: 401 }),
			1,
			'Central refused the fleet credential; run fleet-login again.',
		],
		[unavailable, 1, 'Central did not answer. Repeat the command.'],
	] as const)('a list answered %#: exit %i, %s', async (reply, exitCode, words): Promise<void> => {
		const result = await approvals(['list'], [reply]);
		expect(result).toMatchObject({ exitCode, lines: [words] });
	});
});

describe('arguments', (): void => {
	it.each([
		[['list', requestId]],
		[['show']],
		[['show', 'not-a-uuid']],
		[['approve', requestId.toUpperCase()]],
		[['answer']],
		[['reply', requestId]],
	])('refuses %j before any request', async (args): Promise<void> => {
		await expect(approvals(args, [])).rejects.toThrow();
	});
});

describe('question recovery with --answer', (): void => {
	const operationId = '019a3dce-2000-7000-8000-0000000000f1';
	const questionAnswer = {
		kind: 'answered',
		fields: [
			{ fieldId: 2, value: { kind: 'selectedOptions', selectedOptionIds: [2] } },
			{ fieldId: 1, value: { kind: 'text', value: "it's latency" } },
		],
	} as const;

	it('answer --operation-id --answer sends the decide straight away with that exact answer', async (): Promise<void> => {
		const result = await approvals(
			['answer', requestId],
			[savedAnswer({ kind: 'question', answer: questionAnswer })],
			{ 'operation-id': operationId, answer: JSON.stringify(questionAnswer) },
		);
		expect(result.exitCode).toBe(0);
		expect(result.calls.map((call) => call.path)).toEqual([
			'/api/auth/organization-admin/v1/approval-decide',
		]);
		expect(result.calls[0]?.body).toEqual({
			organization,
			requestId,
			operationId,
			answer: { kind: 'question', answer: questionAnswer },
		});
	});

	it.each([
		[{ answer: JSON.stringify(questionAnswer) }, /needs --operation-id\. Nothing was sent\.$/u],
		[
			{ 'operation-id': operationId, answer: JSON.stringify(questionAnswer), field: ['1=x'] },
			/--field and --answer cannot be used together\. Nothing was sent\.$/u,
		],
	] as const)(
		'refuses %j before any credential or request',
		async (flags, words): Promise<void> => {
			const result = await approvals(['answer', requestId], [], flags);
			expect(result.exitCode).toBe(2);
			expect(result.lines).toEqual([expect.stringMatching(words)]);
			expect(result.calls).toEqual([]);
			expect(result.refreshes).toBe(0);
		},
	);
});

describe('the printed repeat line, run through the owner CLI', (): void => {
	const decideBody = z.object({ operationId: z.string(), answer: z.unknown() });

	it.each([
		['an unproven call', ['deny', requestId], unprovenCallView, {}],
		['a provider approval', ['approve', requestId], twoAllowsView, { option: '4' }],
		['a question', ['answer', requestId], questionView, { field: ['2=2', "1=it's latency"] }],
	] as const)(
		'%s: run exactly as printed, entrypoint included, it repeats the same decide with no read',
		async (_kind, args, view, options): Promise<void> => {
			// Arrange: the first decide gets no answer, nor does its retry.
			const first = await approvals(args, [readRequest(view), unavailable, unavailable], options);
			expect(first.exitCode).toBe(1);
			const firstBody = decideBody.parse(first.calls[1]?.body);
			// The second line is the command alone: exactly what a person copies.
			const [, printedLine = ''] = first.lines;
			// The entrypoint is the one --help documents.
			const help = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
			expect(await runOwnerCli(['--help'])).toBe(0);
			expect(String(help.mock.calls[0]?.[0])).toMatch(
				new RegExp(`^Usage: ${documentedEntrypoint.join(' ')} --target FILE `, 'u'),
			);
			help.mockRestore();

			// Act: read the line as a POSIX shell would; the entrypoint's words start the process,
			// and what follows them is the argv the CLI's own parser reads.
			const words = posixShellWords(printedLine);
			vi.mocked(readAuthTarget).mockClear().mockResolvedValueOnce(authTarget);
			const recovered = await observed([savedAnswer(Object(firstBody.answer))], (environment) =>
				runOwnerCli(words.slice(documentedEntrypoint.length), environment),
			);

			// Assert: the documented entrypoint, the target in use, and the same decide, unread.
			expect(words.slice(0, documentedEntrypoint.length)).toEqual(documentedEntrypoint);
			expect(vi.mocked(readAuthTarget)).toHaveBeenCalledExactlyOnceWith(targetPath);
			expect(recovered.exitCode).toBe(0);
			expect(recovered.calls.map((call) => call.path)).toEqual([
				'/api/auth/organization-admin/v1/approval-decide',
			]);
			const recoveredBody = decideBody.parse(recovered.calls[0]?.body);
			expect(recoveredBody).toEqual(firstBody);
			const intent = (body: typeof firstBody): string =>
				canonicalJson(
					approvalPersonIntent(
						approvalPersonOperationSchema.parse({
							operation: 'ApprovalDecide',
							organization,
							requestId,
							...body,
						}),
					),
				);
			expect(intent(recoveredBody)).toBe(intent(firstBody));
			expect(decodeJwt(recovered.calls[0]?.proof ?? '')['intent']).toBe(
				decodeJwt(first.calls[1]?.proof ?? '')['intent'],
			);
		},
	);
});
