import { readFile } from 'node:fs/promises';

import {
	engineAdminResultSchemas,
	fleetAdminIntentDigest,
	fleetAdminRequestSchema,
} from '@agent-collaboration/sign-in-core';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { readAuthTarget } from '#sign-in-owner-cli/auth-target';
import {
	runEngineCommand,
	walkRetiredPages,
	type EngineCommandOptions,
} from '#sign-in-owner-cli/fleet/engine-cli-command';
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

/** The `--target` file in use: a space and a quote, so the printed line must quote it. */
const targetPath = "/private/runtime/owner's fleet target.json";

// Central's engine reply bytes (sign-in-core contract-fixtures, codex-router main 4593797b1).
const replyVectors = z
	.array(z.strictObject({ name: z.string(), bytes: z.string() }))
	.parse(
		JSON.parse(
			await readFile(
				new URL(
					'../../../sign-in-core/contract-fixtures/central-engine-admin/engine-admin-reply-vectors.json',
					import.meta.url,
				),
				'utf8',
			),
		),
	);
function vector(name: string): () => Response {
	const found = replyVectors.find((candidate) => candidate.name === name);
	if (found === undefined) throw new Error(`No reply vector ${name}`);
	return () => new Response(found.bytes, { headers: { 'content-type': 'application/json' } });
}
const refused = (reason: string) => (): Response => Response.json({ result: 'refused', reason });
const relayUnavailable = (): Response =>
	Response.json({ error: 'central-unavailable' }, { status: 503 });

const organizationId = target.organizationId;
const attemptId = '019a3dce-2000-7000-8000-0000000000a1';
const cursorOne = '019a3dce-2000-7000-8000-0000000000b1';
const cursorTwo = '019a3dce-2000-7000-8000-0000000000b2';
const retiredItem = (id: string): object => ({
	attemptId: id,
	kind: 'wake_timer',
	subjectKey: '019a3dce-2000-7000-8000-0000000000c1',
	failureClass: 'statement_rejected',
	count: 2,
	retiredAt: '2026-11-23T08:05:02.123Z',
	lastFailure: null,
});
const page = (items: readonly object[], next: string | null) => (): Response =>
	Response.json({ result: 'engineRetired', items, next });

interface EngineRun {
	readonly exitCode: number;
	readonly lines: string[];
	readonly calls: {
		readonly path: string;
		readonly body: unknown;
		readonly proof: Record<string, unknown>;
	}[];
	readonly refreshes: number;
	readonly confirmations: number;
}

/** One `engine` command through runEngineCommand, with the target file in use named. */
async function engine(
	args: readonly string[],
	relayReplies: readonly (() => Response)[],
	options: EngineCommandOptions & { readonly all?: boolean } = {},
	confirmSecondFactor: () => Promise<boolean> = async () => {
		throw new Error('no step-up expected');
	},
): Promise<EngineRun> {
	return observed(
		relayReplies,
		async (environment) =>
			runEngineCommand({ arguments: args, targetPath, target: authTarget, options, environment }),
		confirmSecondFactor,
	);
}

/** Runs `command` against a scenario's relay and collects what it printed and sent. */
async function observed(
	relayReplies: readonly (() => Response)[],
	command: (environment: FleetCliEnvironment) => Promise<number>,
	confirmSecondFactor: () => Promise<boolean> = async () => {
		throw new Error('no step-up expected');
	},
): Promise<{
	readonly exitCode: number;
	readonly lines: string[];
	readonly calls: {
		readonly path: string;
		readonly body: unknown;
		readonly proof: Record<string, unknown>;
	}[];
	readonly refreshes: number;
	readonly confirmations: number;
}> {
	const world = await scenario(relayReplies);
	const lines: string[] = [];
	let confirmations = 0;
	const exitCode = await command({
		io: world.io,
		store: () => world.store,
		confirmSecondFactor: async () => {
			confirmations += 1;
			return confirmSecondFactor();
		},
		write: (line) => lines.push(line),
	});
	return {
		exitCode,
		lines,
		calls: world.relayCalls.map((call) => ({
			path: call.path,
			body: JSON.parse(call.body),
			proof: decodeJwt(call.proof),
		})),
		refreshes: world.refreshCalls.length,
		confirmations,
	};
}

describe('engine health', (): void => {
	it('signs central health route and prints the alarm and every kind', async (): Promise<void> => {
		// Act
		const result = await engine(['health'], [vector('health_millis')]);
		// Assert
		expect(result.exitCode).toBe(0);
		expect(result.lines).toEqual([
			'Engine alarm: 2026-11-23T08:10:03.456Z.',
			'wake_timer  failing 0  retired 1  oldest failure 2026-11-23T08:00:01.123Z  last failure statement_rejected',
			'automation_timer  failing 0  retired 0  oldest failure -  last failure -',
			'direct_message  failing 0  retired 0  oldest failure -  last failure -',
			'system_message_expiry  failing 0  retired 0  oldest failure -  last failure -',
			'legacy_notice_windows  failing 0  retired 0  oldest failure -  last failure -',
			'legacy_workspace_drains  failing 0  retired 0  oldest failure -  last failure -',
			'engine_source  failing 0  retired 0  oldest failure -  last failure -',
		]);
		const [call] = result.calls;
		expect(call?.path).toBe('/api/auth/organization-admin/v1/engine-health');
		expect(call?.body).toEqual({ organizationId });
		expect(call?.proof.htu).toBe(
			`${target.centralPublicOrigin}/organization-admin/v1/engine-health`,
		);
		expect(call?.proof.intent).toBe(
			await fleetAdminIntentDigest(globalThis.crypto, {
				operation: 'EngineHealth',
				organizationId,
			}),
		);
	});

	it.each([
		[{ alarm: null, alarmMissing: false }, 'Engine alarm: none; no work is due.'],
		[
			{ alarm: null, alarmMissing: true },
			'Engine alarm: missing; work is due and no alarm is set.',
		],
	] as const)('reads the alarm %j', async (alarm, words): Promise<void> => {
		const health = JSON.parse(
			replyVectors.find(({ name }) => name === 'health_seconds')?.bytes ?? '{}',
		);
		const result = await engine(['health'], [() => Response.json({ ...health, ...alarm })]);
		expect(result.lines[0]).toBe(words);
	});

	it('shows central empty 503, relayed as central-unavailable, as unavailable', async (): Promise<void> => {
		const result = await engine(['health'], [relayUnavailable]);
		expect(result).toMatchObject({
			exitCode: 1,
			lines: ['Central is unavailable; nothing was read. Repeat with: engine health.'],
		});
	});

	it('a member is refused for want of organization:readAudit', async (): Promise<void> => {
		const result = await engine(['health'], [vector('notPermitted')]);
		expect(result).toMatchObject({
			exitCode: 2,
			lines: [
				"Not permitted: reading engine health needs the organization owner's organization:readAudit.",
			],
		});
	});
});

describe('engine retired: the paging rule', (): void => {
	it('asks again while next is non-null, through an empty page with a cursor, until next is null', async (): Promise<void> => {
		// Arrange: an item, then an empty page that still carries a cursor, then the end.
		const second = '019a3dce-2000-7000-8000-0000000000a2';
		// Act
		const result = await engine(
			['retired'],
			[
				page([retiredItem(attemptId)], cursorOne),
				page([], cursorTwo),
				page([retiredItem(second)], null),
			],
		);
		// Assert
		expect(result.exitCode).toBe(0);
		expect(result.lines).toEqual([
			`${attemptId}  wake_timer  subject 019a3dce-2000-7000-8000-0000000000c1  statement_rejected x2  retired 2026-11-23T08:05:02.123Z`,
			`${second}  wake_timer  subject 019a3dce-2000-7000-8000-0000000000c1  statement_rejected x2  retired 2026-11-23T08:05:02.123Z`,
			'End of the retired list.',
		]);
		expect(result.calls.map((call) => call.body)).toEqual([
			{ organizationId, after: null, limit: 100 },
			{ organizationId, after: cursorOne, limit: 100 },
			{ organizationId, after: cursorTwo, limit: 100 },
		]);
		// Each page is its own signed request: a fresh proof bound to that page's intent.
		const intents = await Promise.all(
			[null, cursorOne, cursorTwo].map(async (after) =>
				fleetAdminIntentDigest(
					globalThis.crypto,
					fleetAdminRequestSchema.parse({
						operation: 'EngineListRetired',
						organizationId,
						after,
						limit: 100,
					}),
				),
			),
		);
		expect(result.calls.map((call) => call.proof.intent)).toEqual(intents);
		expect(new Set(result.calls.map((call) => call.proof.jti)).size).toBe(3);
	});

	it("central's own empty continuation, then its explicit end, is no retired work", async (): Promise<void> => {
		const result = await engine(
			['retired'],
			[vector('retired_empty_continuation'), vector('retired_empty_end')],
		);
		expect(result).toMatchObject({ exitCode: 0, lines: ['No retired engine work.'] });
		expect(result.calls.map((call) => call.body)).toEqual([
			{ organizationId, after: null, limit: 100 },
			{ organizationId, after: '019f0000-0000-7000-8000-000000000101', limit: 100 },
		]);
	});

	it('--cursor continues a walk after that cursor', async (): Promise<void> => {
		const result = await engine(['retired'], [page([], null)], { cursor: cursorOne });
		expect(result.calls.map((call) => call.body)).toEqual([
			{ organizationId, after: cursorOne, limit: 100 },
		]);
	});

	it('a page that gets no answer stops the walk and names the cursor to continue from', async (): Promise<void> => {
		const result = await engine(['retired'], [page([], cursorOne), relayUnavailable]);
		expect(result).toMatchObject({
			exitCode: 1,
			lines: [
				`Central is unavailable; nothing was read. Repeat with: engine retired --cursor ${cursorOne}.`,
			],
		});
	});

	it('a cursor that does not move forward stops the walk rather than asking forever', async (): Promise<void> => {
		const result = await engine(['retired'], [page([], cursorTwo), page([], cursorOne)]);
		expect(result).toMatchObject({
			exitCode: 1,
			lines: [`Central returned a cursor that does not move past ${cursorTwo}; the walk stopped.`],
		});
	});

	it('walkRetiredPages ends only on next: null', async (): Promise<void> => {
		// Arrange: two empty pages with cursors before the end.
		const replies = [cursorOne, cursorTwo, null].map((next) =>
			engineAdminResultSchemas.EngineListRetired.parse({
				result: 'engineRetired',
				items: [],
				next,
			}),
		);
		const asked: (string | null)[] = [];
		// Act
		const walk = await walkRetiredPages({
			after: null,
			write: () => undefined,
			readPage: async (after) => {
				asked.push(after);
				const reply = replies[asked.length - 1];
				return reply === undefined ? { kind: 'unknown' } : { kind: 'answered', result: reply };
			},
		});
		// Assert
		expect(walk).toEqual({ kind: 'ended', items: 0 });
		expect(asked).toEqual([null, cursorOne, cursorTwo]);
	});
});

describe('engine retry and discard', (): void => {
	it.each([
		['retry', 'EngineRetry', 'retried', `Retried: attempt ${attemptId} is due again.`],
		[
			'discard',
			'EngineDiscard',
			'discarded',
			`Discarded: attempt ${attemptId}'s subject is finished and the attempt removed.`,
		],
	] as const)(
		'%s signs the attempt and a minted operation ID',
		async (subcommand, operation, reply, words): Promise<void> => {
			// Act
			const result = await engine([subcommand, attemptId], [vector(reply)]);
			// Assert
			expect(result).toMatchObject({ exitCode: 0, lines: [words], confirmations: 0 });
			const [call] = result.calls;
			const body = z
				.strictObject({
					organizationId: z.string(),
					operationId: z.uuidv7(),
					attemptId: z.string(),
				})
				.parse(call?.body);
			expect(body).toMatchObject({ organizationId, attemptId });
			expect(call?.path).toBe(`/api/auth/organization-admin/v1/engine-${subcommand}`);
			expect(call?.proof.htu).toBe(
				`${target.centralPublicOrigin}/organization-admin/v1/engine-${subcommand}`,
			);
			expect(call?.proof.intent).toBe(
				await fleetAdminIntentDigest(globalThis.crypto, { operation, ...body }),
			);
		},
	);

	it.each(['retry', 'discard'] as const)(
		'%s: secondFactorRequired asks for the step-up, refreshes the same key, and resends the same operation once',
		async (subcommand): Promise<void> => {
			// Act
			const result = await engine(
				[subcommand, attemptId],
				[vector('secondFactorRequired'), vector(subcommand === 'retry' ? 'retried' : 'discarded')],
				{},
				async () => true,
			);
			// Assert
			expect(result.exitCode).toBe(0);
			expect(result.confirmations).toBe(1);
			const [first, resend] = result.calls;
			expect(resend?.body).toEqual(first?.body);
			expect(resend?.proof.intent).toBe(first?.proof.intent);
			expect(resend?.proof.jti).not.toBe(first?.proof.jti);
			// One refresh opens the session; the step-up adds exactly one more, with the same key.
			expect(result.refreshes).toBe(2);
		},
	);

	it('a declined step-up sends nothing again', async (): Promise<void> => {
		const result = await engine(
			['retry', attemptId],
			[vector('secondFactorRequired')],
			{},
			async () => false,
		);
		expect(result).toMatchObject({
			exitCode: 2,
			lines: ['Not confirmed; the retry was not sent again. Nothing changed.'],
			confirmations: 1,
		});
		expect(result.calls).toHaveLength(1);
	});

	it.each([
		['notFound', `Not found: there is no retired attempt ${attemptId}; nothing changed.`],
		[
			'notRetired',
			`Not retired: attempt ${attemptId} is still failing, not retired; nothing changed.`,
		],
		[
			'discardUnsupported',
			`Discard is not supported for attempt ${attemptId}'s kind of work; nothing changed. Retry it instead.`,
		],
		['stale', `Stale: attempt ${attemptId}'s subject moved or is gone; nothing changed.`],
		['subjectUnreadable', `Attempt ${attemptId}'s subject could not be read; nothing changed.`],
		[
			'conflict',
			'Central answered conflict: either the authorization it admitted this discard under changed while applying it, or this operation id is already held by another request or person. Nothing was written to the attempt or its subject.',
		],
		[
			'notPermitted',
			"Not permitted: repairing engine work needs the organization owner's organization:repairWork.",
		],
		['requestReused', 'Central refused (requestReused); nothing changed.'],
	] as const)('discard refused %s', async (reason, words): Promise<void> => {
		const result = await engine(['discard', attemptId], [refused(reason)]);
		expect(result).toMatchObject({ exitCode: 2, lines: [words] });
	});

	it('retry refused conflict names only the operation id: its guard miss is notFound', async (): Promise<void> => {
		const result = await engine(['retry', attemptId], [refused('conflict')]);
		expect(result).toMatchObject({
			exitCode: 2,
			lines: [
				'Central answered conflict: this operation id is already held by another request or person. Nothing was written to the attempt or its subject.',
			],
		});
	});

	it('--operation-id repeats a change under the operation ID given', async (): Promise<void> => {
		const operationId = '019a3dce-2000-7000-8000-0000000000f1';
		const result = await engine(['discard', attemptId], [vector('discarded')], {
			'operation-id': operationId,
		});
		expect(result.calls[0]?.body).toEqual({ organizationId, operationId, attemptId });
	});
});

describe('engine arguments are refused before any credential or request', (): void => {
	it.each([
		[
			['health'],
			{ cursor: cursorOne },
			'engine health does not take --cursor (it takes no options). Nothing was sent.',
		],
		[
			['retired'],
			{ 'operation-id': cursorOne },
			'engine retired does not take --operation-id (it takes --cursor). Nothing was sent.',
		],
		[
			['retry', attemptId],
			{ cursor: cursorOne },
			'engine retry does not take --cursor (it takes --operation-id). Nothing was sent.',
		],
		[
			['discard', attemptId],
			{ all: true },
			'engine discard does not take --all (it takes --operation-id). Nothing was sent.',
		],
		[
			['retry', attemptId.toUpperCase()],
			{},
			'attempt ID must be a lowercase UUIDv7. Nothing was sent.',
		],
		[
			['retired'],
			{ cursor: 'not-a-cursor' },
			'--cursor must be a lowercase UUIDv7. Nothing was sent.',
		],
		[
			['discard', attemptId],
			{ 'operation-id': '0b5f0000-0000-4000-8000-000000000101' },
			'--operation-id must be a lowercase UUIDv7. Nothing was sent.',
		],
		[
			['retry'],
			{},
			'Usage: engine health | engine retired [--cursor ID] | engine retry ATTEMPT_ID | engine discard ATTEMPT_ID [--operation-id ID]. Nothing was sent.',
		],
	] as const)('%j %j', async (args, options, words): Promise<void> => {
		const result = await engine(args, [], options);
		expect(result).toEqual({
			exitCode: 2,
			lines: [words],
			calls: [],
			refreshes: 0,
			confirmations: 0,
		});
	});
});

describe('the printed repair repeat line, run through the owner CLI', (): void => {
	const repairBody = z.strictObject({
		organizationId: z.string(),
		operationId: z.uuidv7(),
		attemptId: z.string(),
	});
	const replyFor = { retry: 'retried', discard: 'discarded' } as const;

	it.each([
		['retry', 'unavailable', relayUnavailable],
		['discard', 'unavailable', relayUnavailable],
		['retry', 'no answer', (): Response => new Response('not json', { status: 200 })],
		['discard', 'no answer', (): Response => new Response('not json', { status: 200 })],
	] as const)(
		'%s with %s: run exactly as printed, entrypoint and --target included, it repeats the same operation',
		async (subcommand, _cause, firstReply): Promise<void> => {
			// Arrange: the first send gets no readable answer.
			const first = await engine([subcommand, attemptId], [firstReply]);
			expect(first.exitCode).toBe(1);
			const firstBody = repairBody.parse(first.calls[0]?.body);
			// The first line explains, naming central's 24-hour receipt limit; the second is the
			// command alone, exactly what a person copies.
			expect(first.lines).toHaveLength(2);
			const [explanation = '', printedLine = ''] = first.lines;
			expect(explanation).toMatch(/run the next line exactly/u);
			expect(explanation).toMatch(/24-hour receipt limit/u);
			// The entrypoint is the one --help documents.
			const help = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
			expect(await runOwnerCli(['--help'])).toBe(0);
			expect(String(help.mock.calls[0]?.[0])).toMatch(
				new RegExp(`^Usage: ${documentedEntrypoint.join(' ')} --target FILE `, 'u'),
			);
			help.mockRestore();

			// Act: read the line as a POSIX shell would; what follows the entrypoint's words is the
			// argv the CLI's own parser reads.
			const words = posixShellWords(printedLine);
			vi.mocked(readAuthTarget).mockClear().mockResolvedValueOnce(authTarget);
			const recovered = await observed([vector(replyFor[subcommand])], async (environment) =>
				runOwnerCli(words.slice(documentedEntrypoint.length), environment),
			);

			// Assert: the documented entrypoint, the target in use, and the same operation.
			expect(words.slice(0, documentedEntrypoint.length)).toEqual(documentedEntrypoint);
			expect(vi.mocked(readAuthTarget)).toHaveBeenCalledExactlyOnceWith(targetPath);
			expect(recovered.exitCode).toBe(0);
			expect(recovered.calls.map((call) => call.path)).toEqual([
				`/api/auth/organization-admin/v1/engine-${subcommand}`,
			]);
			expect(recovered.calls[0]?.body).toEqual(firstBody);
			expect(recovered.calls[0]?.proof.intent).toBe(first.calls[0]?.proof.intent);
			expect(recovered.calls[0]?.proof.jti).not.toBe(first.calls[0]?.proof.jti);
		},
	);
});
