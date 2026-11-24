import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { canonicalJson } from '#sign-in-core/contracts/canonical-json';
import {
	fleetAdminIntent,
	fleetAdminIntentDigest,
	fleetAdminRequestSchema,
	fleetAdminRequestBody,
	fleetAdminRoutePaths,
	type FleetAdminRequest,
} from '#sign-in-core/organizations/fleet-admin-operation';

// Producer copies (see the fixtures README): the request and intent triplets from codex-router
// main ea030e513's contract export (#275); the digest vectors from 7fb2de88a, made by central's
// independent JS JCS oracle, whose intent shape #275's intent schema keeps.
async function producerFile(name: string): Promise<unknown> {
	return JSON.parse(
		await readFile(
			new URL(`../../contract-fixtures/central-organization-admin/${name}`, import.meta.url),
			'utf8',
		),
	);
}
const routeOperations = {
	createWorkspace: 'CreateWorkspace',
	workspaceLookup: 'WorkspaceLookup',
	readChangeRecords: 'ReadChangeRecords',
} as const;
const vectorSchema = z.strictObject({
	name: z.string(),
	route: z.enum(['createWorkspace', 'workspaceLookup', 'readChangeRecords']),
	path: z.string(),
	body: z.record(z.string(), z.unknown()),
	intent: z.unknown(),
	jcs: z.string(),
	intentDigest: z.string(),
});
const vectors = z
	.strictObject({ oracle: z.string(), vectors: z.array(vectorSchema).length(5) })
	.parse(await producerFile('OrganizationAdminIntent.vectors.json')).vectors;
const requestFiles = {
	CreateWorkspace: 'CreateWorkspaceRequest',
	WorkspaceLookup: 'WorkspaceLookupRequest',
	ReadChangeRecords: 'ReadChangeRecordsRequest',
} as const;

/** The page's operation for a producer body; an absent `after` is central's null. */
function operationFor(
	operation: FleetAdminRequest['operation'],
	body: Readonly<Record<string, unknown>>,
): z.ZodSafeParseResult<FleetAdminRequest> {
	return fleetAdminRequestSchema.safeParse(
		operation === 'ReadChangeRecords'
			? { operation, ...body, after: body['after'] ?? null }
			: { operation, ...body },
	);
}

describe('admin operations against central producer vectors', (): void => {
	it.each(vectors)(
		'$name: route, body, JCS string and intent digest equal the producer',
		async (vector): Promise<void> => {
			// Arrange
			const parsed = operationFor(routeOperations[vector.route], vector.body);
			if (!parsed.success) throw new Error(`Producer body refused: ${vector.name}`);
			// Act
			const operation = parsed.data;
			// Assert
			expect(fleetAdminRoutePaths[operation.operation]).toBe(vector.path);
			expect(fleetAdminIntent(operation)).toEqual(vector.intent);
			expect(canonicalJson(fleetAdminIntent(operation))).toBe(vector.jcs);
			await expect(fleetAdminIntentDigest(globalThis.crypto, operation)).resolves.toBe(
				vector.intentDigest,
			);
		},
	);

	it.each(Object.entries(requestFiles))(
		'%s: every producer fixture parses and is sent back byte-equal; every negative is refused',
		async (operation, file): Promise<void> => {
			const name = z
				.enum(['CreateWorkspace', 'WorkspaceLookup', 'ReadChangeRecords'])
				.parse(operation);
			const fixtures = z
				.array(z.record(z.string(), z.unknown()))
				.min(1)
				.parse(await producerFile(`${file}.fixtures.json`));
			for (const fixture of fixtures) {
				const parsed = operationFor(name, fixture);
				expect(parsed.success).toBe(true);
				if (parsed.success) expect(fleetAdminRequestBody(parsed.data)).toEqual(fixture);
			}
			const negatives = z
				.array(z.unknown())
				.min(1)
				.parse(await producerFile(`${file}.negatives.json`));
			for (const negative of negatives)
				expect(
					negative !== null && typeof negative === 'object'
						? fleetAdminRequestSchema.safeParse({ ...negative, operation: name }).success
						: false,
				).toBe(false);
		},
	);
});

const listOrganizationId = '019f0000-0000-7000-8000-00000000d201';
const workspaceCursor = '019f0000-0000-7000-8000-00000000d110';

it.each([
	{ body: { organizationId: listOrganizationId }, after: null, limit: 100 },
	{
		body: { organizationId: listOrganizationId, after: null, limit: 100 },
		after: null,
		limit: 100,
	},
	{
		body: { organizationId: listOrganizationId, after: workspaceCursor, limit: 1 },
		after: workspaceCursor,
		limit: 1,
	},
])(
	'encodes the ListWorkspaces body and signs the Central page parameters $body',
	({ body, after, limit }): void => {
		const operation = fleetAdminRequestSchema.parse({ operation: 'ListWorkspaces', ...body });
		expect(fleetAdminRequestBody(operation)).toEqual(body);
		expect(fleetAdminIntent(operation)).toEqual({
			operation: 'ListWorkspaces',
			operationId: null,
			organization: listOrganizationId,
			params: { after, limit },
			target: listOrganizationId,
			v: 1,
		});
	},
);

it.each([null, 0, 101, 1.5])('rejects ListWorkspaces page limit %s', (limit): void => {
	expect(
		fleetAdminRequestSchema.safeParse({
			operation: 'ListWorkspaces',
			organizationId: listOrganizationId,
			limit,
		}).success,
	).toBe(false);
});

it('a changed effect field changes the digest, so a retry cannot change what it does', async (): Promise<void> => {
	const base: FleetAdminRequest = {
		operation: 'CreateWorkspace',
		organizationId: '019a3dce-2000-7000-8000-000000000001',
		operationId: '019a3dce-2000-7000-8000-000000000004',
		name: 'research',
		description: '',
	};
	const renamed = await fleetAdminIntentDigest(globalThis.crypto, { ...base, name: 'research-2' });
	expect(renamed).not.toBe(await fleetAdminIntentDigest(globalThis.crypto, base));
});

it.each([
	{ case: 'a trailing no-break space', name: 'research\u00a0', description: '' },
	{ case: 'a leading ideographic space', name: '\u3000research', description: '' },
	{ case: 'a 257-byte name', name: `${'é'.repeat(128)}x`, description: '' },
	{ case: 'a 2049-byte description', name: 'ok', description: `${'é'.repeat(1024)}x` },
	{ case: 'an uppercase organization ID', name: 'ok', description: '', upper: true },
])('refuses what central refuses rather than trimming it: $case', (input): void => {
	expect(
		fleetAdminRequestSchema.safeParse({
			operation: 'CreateWorkspace',
			organizationId:
				'upper' in input
					? '019A3DCE-2000-7000-8000-000000000001'
					: '019a3dce-2000-7000-8000-000000000001',
			operationId: '019a3dce-2000-7000-8000-000000000004',
			name: input.name,
			description: input.description,
		}).success,
	).toBe(false);
});

it('accepts a 256-byte name and a 2048-byte description at the limit', (): void => {
	expect(
		fleetAdminRequestSchema.safeParse({
			operation: 'CreateWorkspace',
			organizationId: '019a3dce-2000-7000-8000-000000000001',
			operationId: '019a3dce-2000-7000-8000-000000000004',
			name: 'é'.repeat(128),
			description: 'é'.repeat(1024),
		}).success,
	).toBe(true);
});

it("each of central's OrganizationAdminIntent fixtures is the intent built for the request it names", async (): Promise<void> => {
	// Arrange
	const intents = z
		.array(
			z.discriminatedUnion('operation', [
				z.strictObject({
					v: z.literal(1),
					operation: z.literal('CreateWorkspace'),
					organization: z.string(),
					target: z.string(),
					operationId: z.string(),
					params: z.strictObject({ name: z.string(), description: z.string() }),
				}),
				z.strictObject({
					v: z.literal(1),
					operation: z.literal('WorkspaceLookup'),
					organization: z.string(),
					target: z.string(),
					operationId: z.null(),
					params: z.strictObject({}),
				}),
				z.strictObject({
					v: z.literal(1),
					operation: z.literal('ReadChangeRecords'),
					organization: z.string(),
					target: z.string(),
					operationId: z.null(),
					params: z.strictObject({ after: z.string().nullable(), limit: z.number() }),
				}),
			]),
		)
		.min(3)
		.parse(await producerFile('OrganizationAdminIntent.fixtures.json'));
	for (const intent of intents) {
		const request =
			intent.operation === 'CreateWorkspace'
				? {
						operation: intent.operation,
						organizationId: intent.organization,
						operationId: intent.operationId,
						...intent.params,
					}
				: intent.operation === 'WorkspaceLookup'
					? {
							operation: intent.operation,
							organizationId: intent.organization,
							workspaceId: intent.target,
						}
					: { operation: intent.operation, organizationId: intent.organization, ...intent.params };
		// Act
		const built = fleetAdminIntent(fleetAdminRequestSchema.parse(request));
		// Assert
		expect(built).toEqual(intent);
	}
});

it('matches the Central canonical admin intent bytes and digest', async (): Promise<void> => {
	const vector = z
		.strictObject({
			route: z.literal('createWorkspace'),
			requestBody: z.record(z.string(), z.unknown()),
			canonicalIntent: z.string(),
			intentSha256Base64Url: z.string(),
		})
		.parse(await producerFile('OrganizationAdminIntent.canonical.vector.json'));
	const operation = fleetAdminRequestSchema.parse({
		...vector.requestBody,
		operation: routeOperations[vector.route],
	});
	expect(canonicalJson(fleetAdminIntent(operation))).toBe(vector.canonicalIntent);
	await expect(fleetAdminIntentDigest(globalThis.crypto, operation)).resolves.toBe(
		vector.intentSha256Base64Url,
	);
});
