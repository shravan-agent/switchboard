import { readFile } from 'node:fs/promises';

import { expect, it } from 'vitest';
import { z } from 'zod';

import {
	createFleetAdminLinkClient,
	fleetAdminResultSchemas,
	type FleetAdminRefusalReason,
} from '#sign-in-core/central-link/fleet-admin-client';
import type { AdminRefusal } from '#sign-in-core/central-link/generated/central-sign-in.gen';
import { organizationChangeFixtures } from '#sign-in-core/central-link/generated/organization-change-fixtures';
import type { Uuid7 } from '#sign-in-core/contracts/sign-in-platform';
import {
	fleetAdminIntent,
	type FleetAdminRequest,
} from '#sign-in-core/organizations/fleet-admin-operation';

const organizationId = '019a3dce-2000-7000-8000-000000000001';
const create: FleetAdminRequest = {
	operation: 'CreateWorkspace',
	organizationId,
	operationId: '019a3dce-2000-7000-8000-000000000004',
	name: 'research',
	description: '',
};
const workspace = {
	workspaceId: '019a3dce-2000-7000-8000-000000000005',
	name: 'research',
	description: '',
	state: 'active',
};

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

it('sends the DPoP token, the proof and the closed body to the route the operation names', async (): Promise<void> => {
	// Arrange
	const transport = scripted(async () => Response.json({ result: 'applied', workspace }));
	// Act
	const answer = await createFleetAdminLinkClient(transport).sendFleetAdminRequest({
		operation: create,
		accessToken: 'token',
		proof: 'proof',
	});
	// Assert
	expect(answer).toEqual({
		kind: 'answered',
		result: { result: 'applied', workspace },
	});
	const request = transport.sent[0];
	if (request === undefined) throw new Error('No admin request sent');
	expect(new URL(request.url).pathname).toBe('/organization-admin/v1/create-workspace');
	expect(request.headers.get('authorization')).toBe('DPoP token');
	expect(request.headers.get('dpop')).toBe('proof');
	expect(await request.json()).toEqual({
		organizationId,
		operationId: create.operationId,
		name: 'research',
		description: '',
	});
});

const operations: Readonly<Record<FleetAdminRequest['operation'], FleetAdminRequest>> = {
	CreateWorkspace: create,
	WorkspaceLookup: {
		operation: 'WorkspaceLookup',
		organizationId,
		workspaceId: workspace.workspaceId,
	},
	ListWorkspaces: { operation: 'ListWorkspaces', organizationId, limit: 100 },
	ReadChangeRecords: { operation: 'ReadChangeRecords', organizationId, after: null, limit: 10 },
};
/** Which route may answer each result tag; a refusal can come from any of them. */
const routesForResult: Readonly<Record<string, readonly FleetAdminRequest['operation'][]>> = {
	applied: ['CreateWorkspace'],
	found: ['WorkspaceLookup'],
	records: ['ReadChangeRecords'],
	refused: ['CreateWorkspace', 'WorkspaceLookup', 'ListWorkspaces', 'ReadChangeRecords'],
};

it('parses a terminal workspace page containing the shared WorkspaceLookup row', async (): Promise<void> => {
	const payload = { result: 'workspaces', workspaces: [workspace], next: null };
	const transport = scripted(async () => Response.json(payload));
	const client = createFleetAdminLinkClient(transport);
	const answer = await client.sendFleetAdminRequest({
		operation: operations.ListWorkspaces,
		accessToken: 'token',
		proof: 'proof',
	});
	expect(answer).toEqual({ kind: 'answered', result: payload });
	const [request] = transport.sent;
	expect(request?.url).toBe('http://central.invalid/organization-admin/v1/list-workspaces');
	expect(await request?.json()).toEqual({ organizationId, limit: 100 });
});

it('requires next on a Central workspace page', async (): Promise<void> => {
	const transport = scripted(async () => Response.json({ result: 'workspaces', workspaces: [] }));
	await expect(
		createFleetAdminLinkClient(transport).sendFleetAdminRequest({
			operation: operations.ListWorkspaces,
			accessToken: 'token',
			proof: 'proof',
		}),
	).resolves.toEqual({ kind: 'unknown', reason: 'malformed-reply' });
});
async function producerResults(kind: 'fixtures' | 'negatives'): Promise<readonly unknown[]> {
	return z
		.array(z.unknown())
		.min(1)
		.parse(
			JSON.parse(
				await readFile(
					new URL(
						`../../contract-fixtures/central-organization-admin/OrganizationAdminResult.${kind}.json`,
						import.meta.url,
					),
					'utf8',
				),
			),
		);
}
const resultFixtures = await producerResults('fixtures');
const resultNegatives = await producerResults('negatives');

type EngineOnlyRefusal = Exclude<AdminRefusal, FleetAdminRefusalReason>;
// The ten reasons the three Sign-in admin routes admitted on main, pinned here on purpose: the live
// decoder allowlist must not decide which refusals it is tested against, or a wrong widening of it
// would remove that reason's negative case.
const pinnedSignInRefusals = [
	'nameInUse',
	'notPermitted',
	'secondFactorRequired',
	'refreshRequired',
	'authorizationSyncRequired',
	'expired',
	'requestTime',
	'requestReused',
	'conflict',
	'rejected',
] as const satisfies readonly AdminRefusal[];
function isEngineOnlyRefusal(reason: string): reason is EngineOnlyRefusal {
	return !pinnedSignInRefusals.some((pinned) => pinned === reason);
}
// Read from the generated `AdminRefusal` declaration, so a reason Central adds that no Sign-in route
// admits is covered here without editing this file.
const generatedSourceWithoutComments = (
	await readFile(new URL('./generated/central-sign-in.gen.ts', import.meta.url), 'utf8')
).replaceAll(/\/\*[\s\S]*?\*\//g, '');
const generatedAdminRefusalDeclaration =
	generatedSourceWithoutComments.match(/export type AdminRefusal =([^;]*);/)?.[1] ?? '';
const generatedAdminRefusals = [...generatedAdminRefusalDeclaration.matchAll(/"(\w+)"/g)].map(
	([, reason = '']) => reason,
);
const engineOnlyRefusals: readonly EngineOnlyRefusal[] =
	generatedAdminRefusals.filter(isEngineOnlyRefusal);

it('reads the whole generated refusal union, so no case is dropped by a partial read', (): void => {
	// Nothing but quoted members and their bars may remain once the members are removed.
	expect(generatedAdminRefusalDeclaration.replaceAll(/"\w+"|\||\s/g, '')).toBe('');
	expect(generatedAdminRefusals).toEqual(expect.arrayContaining(pinnedSignInRefusals));
	expect(new Set(generatedAdminRefusals).size).toBe(generatedAdminRefusals.length);
	expect(engineOnlyRefusals).toEqual(expect.arrayContaining(['notFound', 'stale']));
});

it.each(engineOnlyRefusals)(
	'treats engine-only refusal %s as malformed on every Sign-in admin route',
	async (reason): Promise<void> => {
		for (const operation of Object.values(operations)) {
			const transport = scripted(async () => Response.json({ result: 'refused', reason }));
			await expect(
				createFleetAdminLinkClient(transport).sendFleetAdminRequest({
					operation,
					accessToken: 'token',
					proof: 'proof',
				}),
			).resolves.toEqual({ kind: 'unknown', reason: 'malformed-reply' });
		}
	},
);

it.each(
	organizationChangeFixtures.map(
		(record) =>
			[
				record.kind === 'machineAllowanceChanged' ? `${record.kind} ${record.state}` : record.kind,
				record,
			] as const,
	),
)('reads the Central change record fixture for %s', (_label, record): void => {
	const reply = { result: 'records', records: [record] };
	expect(fleetAdminResultSchemas.ReadChangeRecords.parse(reply)).toEqual(reply);
	const invalidKind = { ...reply, records: [{ ...record, kind: 'unrecognized-change-kind' }] };
	expect(fleetAdminResultSchemas.ReadChangeRecords.safeParse(invalidKind).success).toBe(false);
	const invalidOrigin = {
		...reply,
		records: [{ ...record, origin: { kind: 'unrecognized-origin' } }],
	};
	expect(fleetAdminResultSchemas.ReadChangeRecords.safeParse(invalidOrigin).success).toBe(false);
	const wrongFields =
		record.kind === 'machineAllowanceChanged'
			? { ...record, targetId: record.workspaceId }
			: { ...record, workspaceId: record.targetId };
	expect(
		fleetAdminResultSchemas.ReadChangeRecords.safeParse({ ...reply, records: [wrongFields] })
			.success,
	).toBe(false);
	if (record.kind === 'machineAllowanceChanged') {
		const invalidState = { ...record, state: 'unrecognized-allowance-state' };
		expect(
			fleetAdminResultSchemas.ReadChangeRecords.safeParse({ ...reply, records: [invalidState] })
				.success,
		).toBe(false);
	}
});

it.each([
	{
		operation: operations.CreateWorkspace,
		path: '/organization-admin/v1/create-workspace',
		body: `{"organizationId":"${organizationId}","operationId":"${create.operationId}","name":"research","description":""}`,
	},
	{
		operation: operations.WorkspaceLookup,
		path: '/organization-admin/v1/workspace-lookup',
		body: `{"organizationId":"${organizationId}","workspaceId":"${workspace.workspaceId}"}`,
	},
	{
		operation: operations.ReadChangeRecords,
		path: '/organization-admin/v1/change-records',
		body: `{"organizationId":"${organizationId}","after":null,"limit":10}`,
	},
	{
		operation: {
			operation: 'ReadChangeRecords',
			organizationId,
			after: create.operationId,
			limit: 10,
		} satisfies FleetAdminRequest,
		path: '/organization-admin/v1/change-records',
		body: `{"organizationId":"${organizationId}","after":"${create.operationId}","limit":10}`,
	},
])(
	'sends $path with the literal expected bytes $body',
	async ({ operation, path, body }): Promise<void> => {
		const transport = scripted(async () => new Response(null, { status: 503 }));
		await createFleetAdminLinkClient(transport).sendFleetAdminRequest({
			operation,
			accessToken: 'token',
			proof: 'proof',
		});
		const request = transport.sent[0];
		if (request === undefined) throw new Error('No admin request sent');
		expect(new URL(request.url).pathname).toBe(path);
		expect(await request.text()).toBe(body);
	},
);

it.each(resultFixtures.map((fixture) => [JSON.stringify(fixture).slice(0, 80), fixture]))(
	'parses central producer result %s on each route that may answer it, and refuses it elsewhere',
	async (_label, fixture): Promise<void> => {
		const tag = z.object({ result: z.string() }).parse(fixture).result;
		const allowed = routesForResult[tag] ?? [];
		expect(allowed.length).toBeGreaterThan(0);
		for (const operation of Object.values(operations)) {
			const transport = scripted(async () => Response.json(fixture));
			const answer = await createFleetAdminLinkClient(transport).sendFleetAdminRequest({
				operation,
				accessToken: 'token',
				proof: 'proof',
			});
			expect(answer).toEqual(
				allowed.includes(operation.operation)
					? { kind: 'answered', result: fixture }
					: { kind: 'unknown', reason: 'malformed-reply' },
			);
		}
	},
);

it.each(resultNegatives.map((negative) => [JSON.stringify(negative).slice(0, 80), negative]))(
	'refuses central producer negative %s on every route',
	async (_label, negative): Promise<void> => {
		for (const operation of Object.values(operations)) {
			const transport = scripted(async () => Response.json(negative));
			await expect(
				createFleetAdminLinkClient(transport).sendFleetAdminRequest({
					operation,
					accessToken: 'token',
					proof: 'proof',
				}),
			).resolves.toEqual({ kind: 'unknown', reason: 'malformed-reply' });
		}
	},
);

it.each([
	{ status: 401, body: '', expected: { kind: 'unauthenticated' } },
	{ status: 400, body: '', expected: { kind: 'request-refused' } },
	// WS7 R-notdue: central's own 503 (the pinned unstamped-store answer) is kept apart.
	{ status: 503, body: '', expected: { kind: 'answered-unavailable' } },
	{ status: 500, body: '', expected: { kind: 'unknown', reason: 'unavailable' } },
	{
		status: 200,
		body: '{"result":"applied"}',
		expected: { kind: 'unknown', reason: 'malformed-reply' },
	},
	{
		status: 200,
		body: '{"result":"refused","reason":"invented"}',
		expected: { kind: 'unknown', reason: 'malformed-reply' },
	},
])('maps $status $body to its own outcome', async ({ status, body, expected }): Promise<void> => {
	const transport = scripted(async () => new Response(body === '' ? null : body, { status }));
	await expect(
		createFleetAdminLinkClient(transport).sendFleetAdminRequest({
			operation: create,
			accessToken: 'token',
			proof: 'proof',
		}),
	).resolves.toEqual(expected);
});

it('keeps a transport failure unknown, never as central having answered 503', async (): Promise<void> => {
	const transport = scripted(async () => {
		throw new Error('Link closed before central answered');
	});
	await expect(
		createFleetAdminLinkClient(transport).sendFleetAdminRequest({
			operation: create,
			accessToken: 'token',
			proof: 'proof',
		}),
	).resolves.toEqual({ kind: 'unknown', reason: 'unavailable' });
});

it.each(['send', 'relay'] as const)(
	'R-retrysignal: a given signal reaches the link request on %s and aborts it; without one the request carries none',
	async (method): Promise<void> => {
		// Arrange
		const transport = scripted(async () => new Response(null, { status: 503 }));
		const client = createFleetAdminLinkClient(transport);
		const deadline = new AbortController();
		const request = async (signal?: AbortSignal): Promise<unknown> =>
			method === 'send'
				? client.sendFleetAdminRequest({
						operation: create,
						accessToken: 'token',
						proof: 'proof',
						...(signal === undefined ? {} : { signal }),
					})
				: client.relayFleetAdminRequest({
						operation: 'CreateWorkspace',
						authorization: 'DPoP token',
						proof: 'proof',
						body: new TextEncoder().encode('{}') as Uint8Array<ArrayBuffer>,
						...(signal === undefined ? {} : { signal }),
					});
		// Act
		await request();
		await request(deadline.signal);
		deadline.abort(new DOMException('Run deadline', 'TimeoutError'));
		// Assert: only the request given the deadline is aborted by it.
		const [first, retry] = transport.sent;
		expect(first?.signal.aborted).toBe(false);
		expect(retry?.signal.aborted).toBe(true);
	},
);

it('reads a mixed page of every Central change kind and keeps the record vocabulary closed', async (): Promise<void> => {
	const base = {
		id: '019a3dce-2000-7000-8000-000000000006',
		requestId: 'central-test-record',
		targetId: workspace.workspaceId,
		createdAtMillis: 1_800_000_000_000,
	};
	const person = {
		kind: 'person',
		personId: organizationId,
		permissionChecked: 'workspace:create',
	};
	const automatic = { kind: 'automatic' };
	const records = organizationChangeFixtures;

	function read(
		replyRecords: readonly unknown[],
	): ReturnType<ReturnType<typeof createFleetAdminLinkClient>['sendFleetAdminRequest']> {
		const reply = { result: 'records', records: replyRecords };
		const transport = scripted(async () => Response.json(reply));
		return createFleetAdminLinkClient(transport).sendFleetAdminRequest({
			operation: operations.ReadChangeRecords,
			accessToken: 'test-token',
			proof: 'test-proof',
		});
	}

	await expect(read(records)).resolves.toEqual({
		kind: 'answered',
		result: { result: 'records', records },
	});
	await expect(
		read([...records, { ...base, kind: 'unrecognized', origin: person }]),
	).resolves.toEqual({
		kind: 'unknown',
		reason: 'malformed-reply',
	});
	await expect(
		read([{ ...base, kind: 'machineExpired', origin: { kind: 'unrecognized' } }]),
	).resolves.toEqual({
		kind: 'unknown',
		reason: 'malformed-reply',
	});
	await expect(
		read([{ ...base, kind: 'machineExpired', origin: { ...automatic, personId: organizationId } }]),
	).resolves.toEqual({
		kind: 'unknown',
		reason: 'malformed-reply',
	});
});

// One page in central's current producer shape: an older targeted record, an automatic expiry and
// the named allowance record. The page carries no cursor; central's next page uses `after` = the
// last record ID of the previous page.
const mixedPageEnrolled = {
	id: '019a3dce-2000-7000-8000-000000000011',
	requestId: 'mixed-page-enrolled',
	kind: 'machineEnrolled',
	origin: { kind: 'person', personId: 'person-opaque-1', permissionChecked: 'machine:enroll' },
	targetId: 'enrollment-opaque-1',
	createdAtMillis: 1_800_000_000_001,
};
const mixedPageExpired = {
	id: '019a3dce-2000-7000-8000-000000000012',
	requestId: 'mixed-page-expired',
	kind: 'machineExpired',
	origin: { kind: 'automatic' },
	targetId: 'enrollment-opaque-1',
	createdAtMillis: 1_800_000_000_002,
};
const mixedPageAllowance = {
	id: '019a3dce-2000-7000-8000-000000000013',
	requestId: 'mixed-page-allowance',
	kind: 'machineAllowanceChanged',
	origin: { kind: 'person', personId: 'person-opaque-2', permissionChecked: 'machine:allow' },
	machineId: '019a3dce-2000-7000-8000-000000000021',
	workspaceId: '019a3dce-2000-7000-8000-000000000022',
	state: 'withdrawn',
	createdAtMillis: 1_800_000_000_003,
};
const mixedPage = [mixedPageEnrolled, mixedPageExpired, mixedPageAllowance];

async function readMixedPage(
	replyRecords: readonly unknown[],
): Promise<
	Awaited<ReturnType<ReturnType<typeof createFleetAdminLinkClient>['sendFleetAdminRequest']>>
> {
	const transport = scripted(async () =>
		Response.json({ result: 'records', records: replyRecords }),
	);
	return createFleetAdminLinkClient(transport).sendFleetAdminRequest({
		operation: operations.ReadChangeRecords,
		accessToken: 'test-token',
		proof: 'test-proof',
	});
}

it('mixed page: decodes a targeted record, an automatic expiry and the allowance record in order with branded IDs', async (): Promise<void> => {
	// Act
	const answer = await readMixedPage(mixedPage);
	// Assert
	expect(answer).toEqual({ kind: 'answered', result: { result: 'records', records: mixedPage } });
	if (answer.kind !== 'answered' || answer.result.result !== 'records') {
		throw new Error('Mixed page was not decoded as records');
	}
	const [enrolled, expired, allowance] = answer.result.records;
	if (enrolled === undefined || expired === undefined) throw new Error('Page is missing records');
	if (allowance?.kind !== 'machineAllowanceChanged') {
		throw new Error('Third record is not the allowance record');
	}
	// These annotations compile only while the decoder brands every ID as Uuid7.
	const brandedIds: readonly Uuid7[] = [
		enrolled.id,
		expired.id,
		allowance.id,
		allowance.machineId,
		allowance.workspaceId,
	];
	expect(brandedIds).toEqual([
		mixedPageEnrolled.id,
		mixedPageExpired.id,
		mixedPageAllowance.id,
		mixedPageAllowance.machineId,
		mixedPageAllowance.workspaceId,
	]);
	expect(answer.result.records.map((record) => record.kind)).toEqual([
		'machineEnrolled',
		'machineExpired',
		'machineAllowanceChanged',
	]);
});

it('mixed page: the next ReadChangeRecords request carries the last record ID as after, in the body and the signed intent', async (): Promise<void> => {
	// Arrange: the last decoded record's id is the next page's cursor.
	const answer = await readMixedPage(mixedPage);
	if (answer.kind !== 'answered' || answer.result.result !== 'records') {
		throw new Error('Mixed page was not decoded as records');
	}
	const lastRecord = answer.result.records.at(-1);
	if (lastRecord === undefined) throw new Error('Mixed page decoded empty');
	const next: FleetAdminRequest = {
		operation: 'ReadChangeRecords',
		organizationId,
		after: lastRecord.id,
		limit: 10,
	};
	const transport = scripted(async () => new Response(null, { status: 503 }));
	// Act
	await createFleetAdminLinkClient(transport).sendFleetAdminRequest({
		operation: next,
		accessToken: 'token',
		proof: 'proof',
	});
	// Assert
	const request = transport.sent[0];
	if (request === undefined) throw new Error('No admin request sent');
	expect(new URL(request.url).pathname).toBe('/organization-admin/v1/change-records');
	expect(await request.text()).toBe(
		`{"organizationId":"${organizationId}","after":"019a3dce-2000-7000-8000-000000000013","limit":10}`,
	);
	expect(fleetAdminIntent(next)).toEqual({
		v: 1,
		operation: 'ReadChangeRecords',
		organization: organizationId,
		target: organizationId,
		operationId: null,
		params: { after: '019a3dce-2000-7000-8000-000000000013', limit: 10 },
	});
});

it('mixed page: one unknown kind makes the whole page malformed and returns no partial list', async (): Promise<void> => {
	const page = [
		mixedPageEnrolled,
		{ ...mixedPageExpired, kind: 'unrecognized-change-kind' },
		mixedPageAllowance,
	];
	await expect(readMixedPage(page)).resolves.toEqual({
		kind: 'unknown',
		reason: 'malformed-reply',
	});
});

const storedRecord = {
	id: '019a3dce-2000-7000-8000-000000000006',
	requestId: 'é'.repeat(64),
	kind: 'workspaceCreated',
	origin: { kind: 'person', personId: 'opaque-person', permissionChecked: 'workspace:create' },
	targetId: 'opaque-target',
	createdAtMillis: 1_800_000_000_000,
};

async function readRecord(record: unknown): Promise<unknown> {
	const transport = scripted(async () => Response.json({ result: 'records', records: [record] }));
	return createFleetAdminLinkClient(transport).sendFleetAdminRequest({
		operation: operations.ReadChangeRecords,
		accessToken: 'test-token',
		proof: 'test-proof',
	});
}

it('accepts opaque change-record identities and a request identity of 128 UTF-8 bytes', async (): Promise<void> => {
	await expect(readRecord(storedRecord)).resolves.toEqual({
		kind: 'answered',
		result: { result: 'records', records: [storedRecord] },
	});
});

it.each([
	{
		field: 'record id version',
		record: { ...storedRecord, id: '019a3dce-2000-4000-8000-000000000006' },
	},
	{ field: 'record id spelling', record: { ...storedRecord, id: storedRecord.id.toUpperCase() } },
	{ field: 'target identity', record: { ...storedRecord, targetId: '' } },
	{
		field: 'person identity',
		record: { ...storedRecord, origin: { ...storedRecord.origin, personId: '' } },
	},
	{
		field: 'checked permission',
		record: { ...storedRecord, origin: { ...storedRecord.origin, permissionChecked: '' } },
	},
	{ field: 'empty request identity', record: { ...storedRecord, requestId: '' } },
	{ field: 'request identity byte length', record: { ...storedRecord, requestId: 'é'.repeat(65) } },
	{ field: 'NUL in request identity', record: { ...storedRecord, requestId: 'request\0identity' } },
])('rejects a Central change record with invalid $field', async ({ record }): Promise<void> => {
	await expect(readRecord(record)).resolves.toEqual({ kind: 'unknown', reason: 'malformed-reply' });
});
