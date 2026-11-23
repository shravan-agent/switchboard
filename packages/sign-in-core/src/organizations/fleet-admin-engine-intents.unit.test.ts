import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { canonicalJson } from '#sign-in-core/contracts/canonical-json';
import {
	engineAdminOperationNames,
	fleetAdminIntent,
	fleetAdminIntentDigest,
	fleetAdminRequestBody,
	fleetAdminRequestSchema,
	fleetAdminRoutePaths,
	isEngineAdminOperation,
} from '#sign-in-core/organizations/fleet-admin-operation';

// Central's engine intent vectors (codex-router main 4593797b1, `contract-fixtures/central-engine-admin/`):
// per route, the body sign-in sends, the canonical intent bytes and their base64url SHA-256.
const intentVectors = z
	.array(
		z.strictObject({
			path: z.string(),
			requestBody: z.record(z.string(), z.unknown()),
			canonicalIntent: z.string(),
			intentSha256Base64Url: z.string(),
		}),
	)
	.length(4)
	.parse(
		JSON.parse(
			await readFile(
				new URL(
					'../../contract-fixtures/central-engine-admin/engine-admin-intent-vectors.json',
					import.meta.url,
				),
				'utf8',
			),
		),
	);
const operationByPath = new Map(
	engineAdminOperationNames.map((operation) => [fleetAdminRoutePaths[operation], operation]),
);

describe("central's engine intent vectors", (): void => {
	it.each(intentVectors)(
		'$path: the operation sends the vector body and signs its canonical bytes and digest',
		async (vector): Promise<void> => {
			// Arrange
			const operation = operationByPath.get(vector.path);
			if (operation === undefined) throw new Error(`No engine operation for ${vector.path}`);
			const parsed = fleetAdminRequestSchema.parse({ operation, ...vector.requestBody });
			// Act
			const body = fleetAdminRequestBody(parsed);
			const intent = canonicalJson(fleetAdminIntent(parsed));
			const digest = await fleetAdminIntentDigest(globalThis.crypto, parsed);
			// Assert
			expect(fleetAdminRoutePaths[parsed.operation]).toBe(vector.path);
			expect(JSON.stringify(body)).toBe(JSON.stringify(vector.requestBody));
			expect(intent).toBe(vector.canonicalIntent);
			expect(digest).toBe(vector.intentSha256Base64Url);
		},
	);

	it('covers every engine operation exactly once', (): void => {
		expect(intentVectors.map((vector) => operationByPath.get(vector.path)).toSorted()).toEqual(
			[...engineAdminOperationNames].toSorted(),
		);
	});
});

const organizationId = '019f0000-0000-7000-8000-00000000d201';
const attemptId = '019f0000-0000-7000-8000-000000000101';
const operationId = '019f0000-0000-7000-8000-000000000100';

describe('engine bodies refuse what central would sign differently', (): void => {
	it.each([
		{ case: 'an uppercase attempt ID', field: 'attemptId', value: attemptId.toUpperCase() },
		{
			case: 'a UUIDv4 attempt ID',
			field: 'attemptId',
			value: '0b5f0000-0000-4000-8000-000000000101',
		},
		{ case: 'a simple-form attempt ID', field: 'attemptId', value: attemptId.replaceAll('-', '') },
		{ case: 'an uppercase operation ID', field: 'operationId', value: operationId.toUpperCase() },
	])('retry and discard refuse $case', ({ field, value }): void => {
		for (const operation of ['EngineRetry', 'EngineDiscard'] as const)
			expect(
				fleetAdminRequestSchema.safeParse({
					operation,
					organizationId,
					operationId,
					attemptId,
					[field]: value,
				}).success,
			).toBe(false);
	});

	it.each([0, 101, 1.5, null])('the retired list refuses page limit %s', (limit): void => {
		expect(
			fleetAdminRequestSchema.safeParse({
				operation: 'EngineListRetired',
				organizationId,
				after: null,
				limit,
			}).success,
		).toBe(false);
	});

	it('the retired list signs an explicit null for the first page', (): void => {
		// Arrange
		const first = fleetAdminRequestSchema.parse({
			operation: 'EngineListRetired',
			organizationId,
			after: null,
			limit: 100,
		});
		// Act / Assert
		expect(fleetAdminRequestBody(first)).toEqual({ organizationId, after: null, limit: 100 });
		expect(canonicalJson(fleetAdminIntent(first))).toBe(
			`{"operation":"EngineListRetired","operationId":null,"organization":"${organizationId}","params":{"after":null,"limit":100},"target":"${organizationId}","v":1}`,
		);
	});

	it('retry and discard of the same attempt under one operation ID sign different digests', async (): Promise<void> => {
		// Central keys its receipt by operation ID and compares the intent digest: reusing an ID
		// across the two changes is a conflict, never a replay.
		const retry = await fleetAdminIntentDigest(globalThis.crypto, {
			operation: 'EngineRetry',
			organizationId,
			operationId,
			attemptId,
		});
		const discard = await fleetAdminIntentDigest(globalThis.crypto, {
			operation: 'EngineDiscard',
			organizationId,
			operationId,
			attemptId,
		});
		expect(retry).not.toBe(discard);
	});

	it('names exactly the four engine operations as engine operations', (): void => {
		expect(Object.keys(fleetAdminRoutePaths).filter(isEngineAdminOperation)).toEqual([
			'EngineHealth',
			'EngineListRetired',
			'EngineRetry',
			'EngineDiscard',
		]);
	});
});
