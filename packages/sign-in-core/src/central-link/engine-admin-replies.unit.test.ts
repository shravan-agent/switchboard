import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { engineAdminResultSchemas } from '#sign-in-core/central-link/engine-admin-replies';
import {
	engineAdminPreflightStatuses,
	engineAdminRefusalReasons,
} from '#sign-in-core/central-link/engine-admin-results';
import {
	createFleetAdminLinkClient,
	engineAdminStatusAnswer,
} from '#sign-in-core/central-link/fleet-admin-client';
import {
	engineAdminOperationNames,
	type EngineAdminOperationName,
	type FleetAdminRequest,
} from '#sign-in-core/organizations/fleet-admin-operation';

// Central's engine reply bytes (contract-fixtures/central-engine-admin, codex-router main 4593797b1).
const replyVectors = z
	.array(z.strictObject({ name: z.string(), bytes: z.string() }))
	.min(1)
	.parse(
		JSON.parse(
			await readFile(
				new URL(
					'../../contract-fixtures/central-engine-admin/engine-admin-reply-vectors.json',
					import.meta.url,
				),
				'utf8',
			),
		),
	);
function vector(name: string): string {
	const found = replyVectors.find((candidate) => candidate.name === name);
	if (found === undefined) throw new Error(`No reply vector ${name}`);
	return found.bytes;
}
const resultRoutes = new Map<string, EngineAdminOperationName>([
	['engineHealth', 'EngineHealth'],
	['engineRetired', 'EngineListRetired'],
	['engineRetried', 'EngineRetry'],
	['engineDiscarded', 'EngineDiscard'],
]);
/** The route whose own result a vector carries; null for a typed refusal. */
function resultRoute(bytes: string): EngineAdminOperationName | null {
	const result = z.object({ result: z.string() }).parse(JSON.parse(bytes)).result;
	return resultRoutes.get(result) ?? null;
}
const refusalVectors = replyVectors.filter(({ bytes }) => resultRoute(bytes) === null);
const resultVectors = replyVectors.filter(({ bytes }) => resultRoute(bytes) !== null);

describe("central's engine reply vectors", (): void => {
	it.each(resultVectors)(
		'$name parses on its own route, keeps every field, and is refused on the others',
		({ bytes }): void => {
			// Arrange
			const route = resultRoute(bytes);
			// Act
			const results = engineAdminOperationNames.map((operation) => ({
				operation,
				parsed: engineAdminResultSchemas[operation].safeParse(JSON.parse(bytes)),
			}));
			// Assert
			for (const { operation, parsed } of results) {
				expect(parsed.success).toBe(operation === route);
				if (parsed.success) expect(JSON.stringify(parsed.data)).toBe(bytes);
			}
		},
	);

	it.each(refusalVectors)(
		'$name is a typed refusal exactly on the routes whose table names it',
		({ bytes }): void => {
			// Arrange
			const reason = z.object({ reason: z.string() }).parse(JSON.parse(bytes)).reason;
			// Act / Assert
			for (const operation of engineAdminOperationNames) {
				const named = engineAdminRefusalReasons[operation].some(
					(candidate: string) => candidate === reason,
				);
				expect(engineAdminResultSchemas[operation].safeParse(JSON.parse(bytes)).success).toBe(
					named,
				);
			}
		},
	);

	it('every refusal the table names has a central vector', (): void => {
		const vectorReasons = new Set(
			refusalVectors.map(
				({ bytes }) => z.object({ reason: z.string() }).parse(JSON.parse(bytes)).reason,
			),
		);
		for (const operation of engineAdminOperationNames)
			for (const reason of engineAdminRefusalReasons[operation])
				expect(vectorReasons.has(reason)).toBe(true);
	});

	it('reads an empty page that carries a cursor as a page to ask again from, not the end', (): void => {
		// Act
		const continuation = engineAdminResultSchemas.EngineListRetired.parse(
			JSON.parse(vector('retired_empty_continuation')),
		);
		const end = engineAdminResultSchemas.EngineListRetired.parse(
			JSON.parse(vector('retired_empty_end')),
		);
		// Assert
		expect(continuation).toEqual({
			result: 'engineRetired',
			items: [],
			next: '019f0000-0000-7000-8000-000000000101',
		});
		expect(end).toEqual({ result: 'engineRetired', items: [], next: null });
	});
});

const retiredEnd = JSON.parse(vector('retired_empty_end'));
const healthSeconds = JSON.parse(vector('health_seconds'));
const retiredSeconds = JSON.parse(vector('retired_seconds'));

describe('engine replies outside central’s contract are refused', (): void => {
	it.each([
		{
			case: 'a retired page without next (required since 4593797b1)',
			route: 'EngineListRetired',
			reply: { result: 'engineRetired', items: [] },
		},
		{
			case: 'an unknown field',
			route: 'EngineListRetired',
			reply: { ...retiredEnd, extra: true },
		},
		{
			case: 'an uppercase cursor',
			route: 'EngineListRetired',
			reply: { ...retiredEnd, next: '019F0000-0000-7000-8000-000000000101' },
		},
		{
			case: 'a two-digit retirement fraction',
			route: 'EngineListRetired',
			reply: {
				...retiredSeconds,
				items: [{ ...retiredSeconds.items[0], retiredAt: '2026-11-23T08:05:02.12Z' }],
			},
		},
		{
			case: 'a retirement time with an offset',
			route: 'EngineListRetired',
			reply: {
				...retiredSeconds,
				items: [{ ...retiredSeconds.items[0], retiredAt: '2026-11-23T08:05:02+00:00' }],
			},
		},
		{
			case: 'an impossible date',
			route: 'EngineListRetired',
			reply: {
				...retiredSeconds,
				items: [{ ...retiredSeconds.items[0], retiredAt: '2026-02-30T08:05:02Z' }],
			},
		},
		{
			case: 'an alarm with six fraction digits (the alarm APIs read milliseconds)',
			route: 'EngineHealth',
			reply: { ...healthSeconds, alarm: '2026-11-23T08:10:03.123456Z' },
		},
		{
			case: 'a kind listed twice',
			route: 'EngineHealth',
			reply: { ...healthSeconds, kinds: [...healthSeconds.kinds, healthSeconds.kinds[0]] },
		},
		{
			case: 'an unknown engine kind',
			route: 'EngineHealth',
			reply: {
				...healthSeconds,
				kinds: [{ ...healthSeconds.kinds[0], kind: 'test_support_machine' }],
			},
		},
		{
			case: 'a negative count',
			route: 'EngineHealth',
			reply: { ...healthSeconds, kinds: [{ ...healthSeconds.kinds[0], failing: -1 }] },
		},
		{
			case: 'nameInUse, which these routes never give',
			route: 'EngineRetry',
			reply: { result: 'refused', reason: 'nameInUse' },
		},
	] as const)('$case', ({ route, reply }): void => {
		expect(engineAdminResultSchemas[route].safeParse(reply).success).toBe(false);
	});
});

function scripted(reply: () => Promise<Response>): {
	readonly sent: Request[];
	readonly fetch: (request: Request) => Promise<Response>;
} {
	const sent: Request[] = [];
	return {
		sent,
		fetch: async (request: Request): Promise<Response> => {
			sent.push(request);
			return reply();
		},
	};
}
const operations = {
	EngineHealth: {
		operation: 'EngineHealth',
		organizationId: '019f0000-0000-7000-8000-00000000d201',
	},
	EngineListRetired: {
		operation: 'EngineListRetired',
		organizationId: '019f0000-0000-7000-8000-00000000d201',
		after: null,
		limit: 100,
	},
	EngineRetry: {
		operation: 'EngineRetry',
		organizationId: '019f0000-0000-7000-8000-00000000d201',
		operationId: '019f0000-0000-7000-8000-000000000100',
		attemptId: '019f0000-0000-7000-8000-000000000101',
	},
	EngineDiscard: {
		operation: 'EngineDiscard',
		organizationId: '019f0000-0000-7000-8000-00000000d201',
		operationId: '019f0000-0000-7000-8000-000000000100',
		attemptId: '019f0000-0000-7000-8000-000000000101',
	},
} as const satisfies Readonly<Record<EngineAdminOperationName, FleetAdminRequest>>;

describe("the link client reads central's engine status table", (): void => {
	it.each([
		{ row: 'oversizedUpload', expected: { kind: 'request-refused' } },
		{ row: 'methodNotPost', expected: { kind: 'unknown', reason: 'unavailable' } },
		{ row: 'missingProof', expected: { kind: 'unauthenticated' } },
		{ row: 'badOrganizationAddress', expected: { kind: 'request-refused' } },
		{ row: 'verificationFailed', expected: { kind: 'unauthenticated' } },
		// An empty 503 is central unavailable; no transaction outcome is read from it.
		{ row: 'unavailable', expected: { kind: 'answered-unavailable' } },
	] as const)(
		'$row: every engine route reads it as $expected.kind',
		async ({ row, expected }): Promise<void> => {
			// Arrange
			const status = engineAdminPreflightStatuses[row].status;
			const body =
				status === 413 ? 'Failed to buffer the request body: length limit exceeded' : null;
			// Act / Assert
			expect(engineAdminStatusAnswer(status)).toEqual(expected);
			for (const operation of Object.values(operations)) {
				const transport = scripted(async () => new Response(body, { status }));
				await expect(
					createFleetAdminLinkClient(transport).sendFleetAdminRequest({
						operation,
						accessToken: 'token',
						proof: 'proof',
					}),
				).resolves.toEqual(expected);
			}
		},
	);

	it('a status outside the table is unknown', (): void => {
		expect(engineAdminStatusAnswer(500)).toEqual({ kind: 'unknown', reason: 'unavailable' });
	});

	it.each(replyVectors)(
		'relays $name at 200 to its answered result',
		async ({ bytes }): Promise<void> => {
			// Arrange
			const route = resultRoute(bytes) ?? 'EngineDiscard';
			const transport = scripted(
				async () =>
					new Response(bytes, { status: 200, headers: { 'content-type': 'application/json' } }),
			);
			const body = new TextEncoder().encode('{}');
			// Act
			const answer = await createFleetAdminLinkClient(transport).relayFleetAdminRequest({
				operation: route,
				authorization: 'DPoP token',
				proof: 'proof',
				body,
			});
			// Assert
			expect(answer.kind).toBe('answered');
			if (answer.kind === 'answered') expect(JSON.stringify(answer.result)).toBe(bytes);
			expect(new URL(transport.sent[0]?.url ?? '').pathname).toBe(
				`/organization-admin/v1/${{ EngineHealth: 'engine-health', EngineListRetired: 'engine-retired', EngineRetry: 'engine-retry', EngineDiscard: 'engine-discard' }[route]}`,
			);
		},
	);

	it('a 200 that does not fit the route is a malformed reply, never an answer', async (): Promise<void> => {
		const transport = scripted(async () => Response.json({ result: 'engineRetried' }));
		await expect(
			createFleetAdminLinkClient(transport).sendFleetAdminRequest({
				operation: operations.EngineDiscard,
				accessToken: 'token',
				proof: 'proof',
			}),
		).resolves.toEqual({ kind: 'unknown', reason: 'malformed-reply' });
	});
});
