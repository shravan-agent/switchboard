import {
	epochMillisecondsSchema,
	fleetAdminRoutePaths,
	signInSchema,
} from '@agent-collaboration/sign-in-core';
import { eq, is } from 'drizzle-orm';
import { SQLiteTable } from 'drizzle-orm/sqlite-core';
import { decodeProtectedHeader } from 'jose';
import { expect, it } from 'vitest';
import { z } from 'zod';

import {
	emptyControlledCentral,
	holdNotDueStamp,
} from '#sign-in-test-support/test-fixtures/central-forgot-host';
import type { AdminArrival } from '#sign-in-test-support/test-fixtures/controlled-central-admin';
import { useControlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-node-test-clock';
import {
	controlledSignInClock,
	controlledSignInIds,
} from '#sign-in-test-support/test-fixtures/controlled-sign-in-clock';
import { startLocalAuthHarness } from '#sign-in-test-support/test-fixtures/local-auth-harness';
import { ensureLocalOwnerOrganization } from '#sign-in-test-support/test-fixtures/local-owner-organization';
import { openOrganizationAdminPage } from '#sign-in-test-support/test-fixtures/organization-admin-page-driver';
import { holdExpiredStampRecord } from '#sign-in-test-support/test-fixtures/organization-stamp-record';
import {
	peoplePost,
	signInConfirmedPeopleBrowser,
} from '#sign-in-test-support/test-fixtures/people-browser-login';
import {
	armRenewalDeadline,
	fireRetryDeadlineAfterCentralHolds,
	retrySignalObservations,
	setRetryDeadlineBarrier,
} from '#sign-in-test-support/test-fixtures/renewal-deadline-proof';

useControlledSignInClock();
type Harness = Awaited<ReturnType<typeof startLocalAuthHarness>>;
type AdminRoute = 'create-workspace' | 'workspace-lookup' | 'change-records';
const ownerEmail = 'owner@example.invalid';
const initialTime = controlledSignInClock.now();

interface AdminFixture {
	readonly harness: Harness;
	readonly ownerId: string;
	readonly organizationId: string;
	readonly cookie: string;
	/** Moves the issuer, the authenticator app and central's stand-in together. */
	readonly setTime: (milliseconds: number) => Promise<void>;
}

/** The owner signs in through the real provider callback, confirms the app, creates the
 * organization and runs the bootstrap that creates both system clients. */
async function setup(): Promise<AdminFixture> {
	let now = initialTime;
	const harness = await startLocalAuthHarness({
		turnstileSecret: 'published-test',
		authenticatorClock: { now: () => epochMillisecondsSchema.parse(now) },
	});
	try {
		const ownerId = await signInConfirmedPeopleBrowser({ harness, email: ownerEmail });
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
		// The organization's and owner's floors reach central through the after-response drain.
		await harness.settleDeferredWork();
		expect(harness.centralProvisioning.hasFloors(organizationId, ownerId)).toBe(true);
		return {
			harness,
			ownerId,
			organizationId,
			cookie: harness.cookie(),
			async setTime(milliseconds): Promise<void> {
				const response = await harness.auth('/__auth-proof/set-clock', {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ milliseconds }),
				});
				expect(response.status).toBe(200);
				now = epochMillisecondsSchema.parse(milliseconds);
				harness.setCentralAdminTime(milliseconds);
			},
		};
	} catch (error) {
		await harness.close();
		throw error;
	}
}

function adminPost(
	fixture: AdminFixture,
	route: AdminRoute,
	body: Readonly<Record<string, unknown>>,
	headers: Readonly<Record<string, string>> = {},
): Promise<Response> {
	return fixture.harness.auth(`/api/auth/organization-admin/${route}`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			origin: new URL(fixture.harness.issuer).origin,
			cookie: fixture.cookie,
			...headers,
		},
		body: JSON.stringify(body),
	});
}

function createBody(
	fixture: AdminFixture,
	operationId: string,
	name = 'research',
): Readonly<Record<string, unknown>> {
	return { organizationId: fixture.organizationId, operationId, name, description: '' };
}

function answered(arrival: AdminArrival | undefined): unknown {
	return arrival?.outcome.kind === 'answered' ? arrival.outcome.result : arrival?.outcome;
}

/** Every row of every sign-in table, as text, on whichever host's database the harness holds. */
async function allStoredRows(harness: Harness): Promise<string> {
	const tables = Object.values(signInSchema).filter((value) => is(value, SQLiteTable));
	const rows = await Promise.all(tables.map((table) => harness.database.select().from(table)));
	return JSON.stringify(rows);
}

/** No access token, proof, public proof coordinate or private JWK member in `text`. */
function expectNoProofMaterial(fixture: AdminFixture, text: string): void {
	expect(text).not.toMatch(/eyJ[A-Za-z0-9_-]+\.eyJ/u);
	expect(text).not.toMatch(/"d"\s*:/u);
	for (const { authorization, proof } of fixture.harness.centralAdmin.receivedCredentials) {
		const token = authorization.replace(/^DPoP /u, '');
		const jwk = z.object({ x: z.string(), y: z.string() }).parse(decodeProtectedHeader(proof).jwk);
		for (const material of [token, proof, jwk.x, jwk.y]) expect(text).not.toContain(material);
	}
}

it('organization admin: the owner creates, looks up and lists through each route, one fresh key and token per request', async () => {
	// Arrange
	const fixture = await setup();
	const { harness, organizationId, ownerId } = fixture;
	try {
		const operationId = controlledSignInIds.nextId();
		const page = await harness.auth('/organization-admin', { headers: { cookie: fixture.cookie } });
		const pageHtml = await page.text();
		expect(page.status).toBe(200);
		expect(pageHtml).toContain(organizationId);
		// Act: a hostile forwarded host and scheme must not reach the signed htu.
		const created = await adminPost(fixture, 'create-workspace', createBody(fixture, operationId), {
			'x-forwarded-host': 'attacker.example.invalid',
			'x-forwarded-proto': 'http',
		});
		const createdText = await created.text();
		// The stand-in's verdict first, so a refusal names the verifier step that refused.
		expect(harness.centralAdmin.arrivals[0]?.outcome).toEqual({
			kind: 'answered',
			result: expect.objectContaining({ result: 'applied' }),
		});
		const repeated = await adminPost(fixture, 'create-workspace', createBody(fixture, operationId));
		const repeatedText = await repeated.text();
		const workspace = z
			.object({ workspace: z.object({ workspaceId: z.uuidv7() }) })
			.parse(JSON.parse(createdText)).workspace;
		const lookedUp = await adminPost(fixture, 'workspace-lookup', {
			organizationId,
			workspaceId: workspace.workspaceId,
		});
		const lookedUpText = await lookedUp.text();
		const listed = await adminPost(fixture, 'change-records', {
			organizationId,
			after: null,
			limit: 100,
		});
		const listedText = await listed.text();
		// Assert: central's results, unchanged, through the page's routes.
		expect([created.status, repeated.status, lookedUp.status, listed.status]).toEqual([
			200, 200, 200, 200,
		]);
		const expectedWorkspace = {
			workspaceId: workspace.workspaceId,
			name: 'research',
			description: '',
			state: 'active',
		};
		expect(JSON.parse(createdText)).toEqual({
			result: 'applied',
			workspace: expectedWorkspace,
		});
		expect(JSON.parse(repeatedText)).toEqual(JSON.parse(createdText));
		expect(JSON.parse(lookedUpText)).toEqual({ result: 'found', workspace: expectedWorkspace });
		expect(JSON.parse(listedText)).toEqual({
			result: 'records',
			records: [
				expect.objectContaining({
					kind: 'workspaceCreated',
					requestId: operationId,
					targetId: workspace.workspaceId,
					origin: { kind: 'person', personId: ownerId, permissionChecked: 'workspace:create' },
				}),
			],
		});
		expect(harness.centralAdmin.workspaces).toHaveLength(1);
		// Each request verified with its own key and its own token; only public JWK members left.
		const arrivals = harness.centralAdmin.arrivals;
		expect(arrivals.map((arrival) => [arrival.route, arrival.outcome.kind])).toEqual([
			['CreateWorkspace', 'answered'],
			['CreateWorkspace', 'answered'],
			['WorkspaceLookup', 'answered'],
			['ReadChangeRecords', 'answered'],
		]);
		expect(new Set(arrivals.map((arrival) => arrival.proofKeyThumbprint)).size).toBe(4);
		expect(new Set(arrivals.map((arrival) => arrival.accessTokenHash)).size).toBe(4);
		for (const arrival of arrivals)
			expect(arrival.proofJwkMembers).toEqual(['crv', 'kty', 'x', 'y']);
		// Custody: nothing of any key, token or proof is stored or returned.
		for (const text of [pageHtml, createdText, repeatedText, lookedUpText, listedText])
			expectNoProofMaterial(fixture, text);
		expectNoProofMaterial(fixture, await allStoredRows(harness));
		expect(
			harness.centralProvisioning.arrivals.filter((arrival) => arrival.path === 'other'),
		).toEqual([]);
	} finally {
		await harness.close();
	}
});

it('organization admin forwarding treats an engine-only refusal as upstream unavailable', async (): Promise<void> => {
	const fixture = await setup();
	try {
		fixture.harness.centralAdmin.scriptNextRawAnswer('WorkspaceLookup', {
			result: 'refused',
			reason: 'notFound',
		});
		const response = await adminPost(fixture, 'workspace-lookup', {
			organizationId: fixture.organizationId,
			workspaceId: controlledSignInIds.nextId(),
		});
		expect(fixture.harness.centralAdmin.arrivals.at(-1)).toMatchObject({
			route: 'WorkspaceLookup',
			outcome: { kind: 'scripted-raw' },
		});
		expect([response.status, await response.json()]).toEqual([
			503,
			{ error: 'central-unavailable' },
		]);
	} finally {
		await fixture.harness.close();
	}
});

it('organization admin forwarding treats an engine-only refusal to CreateWorkspace as upstream unavailable', async (): Promise<void> => {
	const fixture = await setup();
	try {
		fixture.harness.centralAdmin.scriptNextRawAnswer('CreateWorkspace', {
			result: 'refused',
			reason: 'stale',
		});
		const response = await adminPost(
			fixture,
			'create-workspace',
			createBody(fixture, controlledSignInIds.nextId()),
		);
		expect(fixture.harness.centralAdmin.arrivals.at(-1)).toMatchObject({
			route: 'CreateWorkspace',
			outcome: { kind: 'scripted-raw' },
		});
		expect([response.status, await response.json()]).toEqual([
			503,
			{ error: 'central-unavailable' },
		]);
	} finally {
		await fixture.harness.close();
	}
});

it('organization admin page: renders targeted and allowance records with three distinct origins', async (): Promise<void> => {
	const { harness, cookie, ownerId, organizationId } = await setup();
	try {
		const machineId = controlledSignInIds.nextId();
		const workspaceId = controlledSignInIds.nextId();
		const createdAtMillis = controlledSignInClock.now();
		harness.centralAdmin.scriptNextAnswer('ReadChangeRecords', () => ({
			result: 'records',
			records: [
				{
					kind: 'organizationProvisioned',
					id: controlledSignInIds.nextId(),
					requestId: 'proof-provision',
					origin: { kind: 'signInProvisioning' },
					targetId: organizationId,
					createdAtMillis,
				},
				{
					kind: 'machineAllowanceChanged',
					id: controlledSignInIds.nextId(),
					requestId: 'proof-allow',
					origin: { kind: 'person', personId: ownerId, permissionChecked: 'machine:enroll' },
					machineId,
					workspaceId,
					state: 'active',
					createdAtMillis,
				},
				{
					kind: 'machineAllowanceChanged',
					id: controlledSignInIds.nextId(),
					requestId: 'proof-withdraw',
					origin: { kind: 'automatic' },
					machineId,
					workspaceId,
					state: 'withdrawn',
					createdAtMillis,
				},
			],
		}));
		const page = await openOrganizationAdminPage({ harness, cookie });
		const timestamp = new Date(createdAtMillis).toISOString();
		expect(page.changeRecordLines()).toEqual([
			`${timestamp} organizationProvisioned ${organizationId} by sign-in`,
			`${timestamp} machineAllowanceChanged ${machineId} ${workspaceId} (active) by ${ownerId} (machine:enroll)`,
			`${timestamp} machineAllowanceChanged ${machineId} ${workspaceId} (withdrawn) automatically in Central`,
		]);
	} finally {
		await harness.close();
	}
});

it('organization admin page: the served page reports a create; a duplicate name on a new page shows the nameInUse words after one lookup of its own operation, and the next try applies under a fresh operation ID', async () => {
	// Arrange
	const fixture = await setup();
	try {
		const first = await openOrganizationAdminPage({
			harness: fixture.harness,
			cookie: fixture.cookie,
		});
		const second = await openOrganizationAdminPage({
			harness: fixture.harness,
			cookie: fixture.cookie,
		});
		// Act: the real page script, its forms and its forwarding routes.
		const created = await first.submitCreate({ name: 'research' });
		const duplicate = await second.submitCreate({ name: 'Research' });
		const retried = await second.submitCreate({ name: 'development' });
		// Assert: what the person reads.
		expect(created).toBe('Workspace created.');
		expect(first.reloads()).toBe(1);
		expect(duplicate).toBe('A workspace with that name already exists.');
		expect(retried).toBe('Workspace created.');
		// One lookup, at the refused operation's own ID; then a fresh operation ID.
		const sentByCreateOrLookup = second.requests
			.filter((request) => /\/(create-workspace|workspace-lookup)$/u.test(request.path))
			.map((request) => ({
				route: request.path.split('/').at(-1),
				body: z
					.object({ operationId: z.string().optional(), workspaceId: z.string().optional() })
					.parse(request.body),
			}));
		const [duplicateCreate, ownLookup, freshCreate] = sentByCreateOrLookup;
		expect(sentByCreateOrLookup.map((request) => request.route)).toEqual([
			'create-workspace',
			'workspace-lookup',
			'create-workspace',
		]);
		expect(ownLookup?.body.workspaceId).toBe(duplicateCreate?.body.operationId);
		expect(freshCreate?.body.operationId).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
		);
		expect(freshCreate?.body.operationId).not.toBe(duplicateCreate?.body.operationId);
		expect(fixture.harness.centralAdmin.workspaces.map((workspace) => workspace.name)).toEqual([
			'research',
			'development',
		]);
	} finally {
		await fixture.harness.close();
	}
});

it('organization admin page: a nameInUse whose one lookup at its own operation finds another name shows the nameInUse words, reports nothing created and sends no other create', async () => {
	// Arrange: central's answers for this one exchange are scripted; real central cannot give
	// them together (its lookup at a create's own operation finds that create's name).
	const fixture = await setup();
	try {
		const page = await openOrganizationAdminPage({
			harness: fixture.harness,
			cookie: fixture.cookie,
		});
		const loadRequests = page.requests.length;
		fixture.harness.centralAdmin.scriptNextAnswer('CreateWorkspace', () => ({
			result: 'refused',
			reason: 'nameInUse',
		}));
		fixture.harness.centralAdmin.scriptNextAnswer('WorkspaceLookup', (request) => ({
			result: 'found',
			workspace: {
				workspaceId: request.operation === 'WorkspaceLookup' ? request.workspaceId : '',
				name: 'another-name',
				description: '',
				state: 'active',
			},
		}));
		// Act
		const shown = await page.submitCreate({ name: 'research' });
		// Assert: the words, one create then one lookup at its operation, nothing more.
		expect(shown).toBe('A workspace with that name already exists.');
		expect(page.reloads()).toBe(0);
		const sent = page.requests.slice(loadRequests).map((request) => ({
			route: request.path.split('/').at(-1),
			body: z
				.object({ operationId: z.string().optional(), workspaceId: z.string().optional() })
				.parse(request.body),
		}));
		expect(sent.map((request) => request.route)).toEqual(['create-workspace', 'workspace-lookup']);
		expect(sent[1]?.body.workspaceId).toBe(sent[0]?.body.operationId);
		expect(fixture.harness.centralAdmin.workspaces).toEqual([]);
	} finally {
		await fixture.harness.close();
	}
});

it('organization admin: valid bodies without the cookie-only guards, or for another organization, never reach central', async () => {
	// Arrange
	const fixture = await setup();
	const { harness, organizationId } = fixture;
	try {
		const valid = {
			'create-workspace': createBody(fixture, controlledSignInIds.nextId()),
			'workspace-lookup': { organizationId, workspaceId: controlledSignInIds.nextId() },
			'change-records': { organizationId, after: null, limit: 10 },
		} as const;
		const foreign = controlledSignInIds.nextId();
		const outcomes: unknown[] = [];
		// Act
		for (const [route, body] of Object.entries(valid) as [
			AdminRoute,
			Readonly<Record<string, unknown>>,
		][]) {
			const bearer = await adminPost(fixture, route, body, { authorization: 'Bearer anything' });
			const noSession = await adminPost(fixture, route, body, { cookie: '' });
			// Same host, another port: past the local runtime's own host check, still another origin.
			const otherPort = new URL(harness.issuer);
			otherPort.port = otherPort.port === '1' ? '2' : '1';
			const crossOrigin = await adminPost(fixture, route, body, { origin: otherPort.origin });
			const otherOrganization = await adminPost(fixture, route, {
				...body,
				organizationId: foreign,
			});
			const wrongMethod = await harness.auth(`/api/auth/organization-admin/${route}`, {
				headers: { cookie: fixture.cookie },
			});
			outcomes.push({
				route,
				bearer: [bearer.status, await bearer.json()],
				noSession: [noSession.status, await noSession.json()],
				crossOrigin: [crossOrigin.status, await crossOrigin.json()],
				otherOrganization: [otherOrganization.status, await otherOrganization.json()],
				wrongMethod: wrongMethod.status,
			});
		}
		const pageWithoutSession = await harness.auth('/organization-admin', {
			headers: { cookie: '' },
			redirect: 'manual',
		});
		// Assert
		for (const route of Object.keys(valid))
			expect(outcomes).toContainEqual({
				route,
				bearer: [403, { error: 'not-allowed' }],
				noSession: [401, { error: 'unauthorized' }],
				crossOrigin: [403, { error: 'not-allowed' }],
				otherOrganization: [403, { error: 'organization-mismatch' }],
				wrongMethod: 403,
			});
		expect(pageWithoutSession.status).toBe(303);
		expect(new URL(pageWithoutSession.headers.get('location') ?? 'invalid:').pathname).toBe(
			'/sign-in',
		);
		expect(harness.centralAdmin.arrivals).toEqual([]);
		expect(harness.centralAdmin.workspaces).toEqual([]);
	} finally {
		await harness.close();
	}
});

it('organization admin: a stale second factor is refused, the real step-up runs, and one retry with a fresh key applies once', async () => {
	// Arrange: past central's 900-second window since the owner's app confirmation.
	const fixture = await setup();
	const { harness } = fixture;
	try {
		await fixture.setTime(initialTime + 901_000);
		const body = createBody(fixture, controlledSignInIds.nextId());
		// Act
		const stale = await adminPost(fixture, 'create-workspace', body);
		const staleResult: unknown = await stale.json();
		const confirmed = await harness.totpAuthenticator.confirmApp(ownerEmail, harness.auth);
		const retried = await adminPost(fixture, 'create-workspace', body);
		const retriedText = await retried.text();
		const retriedResult: unknown = JSON.parse(retriedText);
		// Assert
		expect([stale.status, staleResult]).toEqual([
			200,
			{ result: 'refused', reason: 'secondFactorRequired' },
		]);
		expect(confirmed.ok).toBe(true);
		expect([retried.status, retriedResult]).toEqual([
			200,
			expect.objectContaining({ result: 'applied' }),
		]);
		const [refusedArrival, appliedArrival] = harness.centralAdmin.arrivals;
		expect(answered(refusedArrival)).toEqual({ result: 'refused', reason: 'secondFactorRequired' });
		expect(answered(appliedArrival)).toMatchObject({ result: 'applied' });
		expect(refusedArrival?.proofKeyThumbprint).not.toBe(appliedArrival?.proofKeyThumbprint);
		expect(harness.centralAdmin.workspaces).toHaveLength(1);
		for (const text of [JSON.stringify(staleResult), retriedText])
			expectNoProofMaterial(fixture, text);
		expectNoProofMaterial(fixture, await allStoredRows(harness));
	} finally {
		await harness.close();
	}
});

it('organization admin: over an expired stamp renewal cannot replace, the forward answers 503 and reaches no central admin route; once the re-sent stamp lands the same request goes out', async () => {
	// Arrange
	const fixture = await setup();
	const { harness, organizationId } = fixture;
	try {
		await holdExpiredStampRecord({
			database: harness.database,
			organizationId,
			nowMilliseconds: controlledSignInClock.now(),
		});
		const lookup = { organizationId, workspaceId: controlledSignInIds.nextId() };
		const sendsBefore = harness.centralProvisioning.sends.length;
		// Act: the first renewal gets no answer; the second, re-sent unchanged, lands.
		harness.centralProvisioning.replyWith('unavailable');
		const withheld = await adminPost(fixture, 'workspace-lookup', lookup);
		const arrivalsWhileWithheld = harness.centralAdmin.arrivals.length;
		harness.centralProvisioning.replyWith('provisioned');
		const forwarded = await adminPost(fixture, 'workspace-lookup', lookup);
		// Assert
		expect(withheld.status).toBe(503);
		expect(await withheld.json()).toEqual({ error: 'central-unavailable' });
		expect(arrivalsWhileWithheld).toBe(0);
		expect(forwarded.status).toBe(200);
		expect(harness.centralAdmin.arrivals).toHaveLength(1);
		const renewals = harness.centralProvisioning.sends
			.slice(sendsBefore)
			.map((send) => send.organizationStatement);
		expect(renewals).toHaveLength(2);
		expect(renewals[1]).toBe(renewals[0]);
	} finally {
		await harness.close();
	}
});

async function systemClients(harness: Harness): Promise<unknown> {
	const { oauthClient, oauthClientResource } = signInSchema;
	const clients = await harness.database
		.select({
			clientId: oauthClient.clientId,
			redirectUris: oauthClient.redirectUris,
			scopes: oauthClient.scopes,
			applicationType: oauthClient.applicationType,
			tokenEndpointAuthMethod: oauthClient.tokenEndpointAuthMethod,
			requirePKCE: oauthClient.requirePKCE,
			skipConsent: oauthClient.skipConsent,
			grantTypes: oauthClient.grantTypes,
		})
		.from(oauthClient);
	// The link row names the resource by its identifier.
	const links = await harness.database
		.select({ clientId: oauthClientResource.clientId, identifier: oauthClientResource.resourceId })
		.from(oauthClientResource);
	return {
		clients: clients.toSorted((left, right) => left.clientId.localeCompare(right.clientId)),
		links: links.toSorted((left, right) => left.clientId.localeCompare(right.clientId)),
	};
}

it('organization admin: the owner bootstrap creates the admin page and fleet CLI clients next to the unchanged management CLI client, keeps all three under concurrent repeats after creation, and fails closed on a different one', async () => {
	// Arrange: setup already ran the bootstrap once.
	const fixture = await setup();
	const { harness } = fixture;
	const bootstrap = (): Promise<Response> =>
		harness.auth('/api/auth/owner/bootstrap', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: '{}',
		});
	try {
		const first = await systemClients(harness);
		// Act: a repeat, then two concurrent repeats; both clients already exist (not cold-creation racing).
		const repeated = await bootstrap();
		const concurrent = await Promise.all([bootstrap(), bootstrap()]);
		const afterRepeats = await systemClients(harness);
		await harness.database
			.update(signInSchema.oauthClient)
			.set({ redirectUris: JSON.stringify(['https://elsewhere.example.invalid/callback']) })
			.where(eq(signInSchema.oauthClient.clientId, 'admin-page-local'));
		const incompatible = await bootstrap();
		const incompatibleBody: unknown = await incompatible.json();
		const afterIncompatible = await systemClients(harness);
		// The fleet CLI client with a grant its profile does not name is refused too.
		await harness.database
			.update(signInSchema.oauthClient)
			.set({
				redirectUris: JSON.stringify([`${harness.issuer}/organization-admin/callback`]),
			})
			.where(eq(signInSchema.oauthClient.clientId, 'admin-page-local'));
		await harness.database
			.update(signInSchema.oauthClient)
			.set({
				grantTypes: JSON.stringify(['authorization_code', 'refresh_token', 'client_credentials']),
			})
			.where(eq(signInSchema.oauthClient.clientId, 'owner-fleet-cli-local'));
		const extraGrant = await bootstrap();
		const extraGrantBody: unknown = await extraGrant.json();
		// Assert: the CLI profile exactly as before B2, and the admin page's own profile.
		expect(first).toEqual({
			clients: [
				{
					clientId: 'admin-page-local',
					redirectUris: JSON.stringify([`${harness.issuer}/organization-admin/callback`]),
					scopes: JSON.stringify(['fleet:admin']),
					applicationType: 'native',
					tokenEndpointAuthMethod: 'none',
					requirePKCE: true,
					skipConsent: true,
					grantTypes: JSON.stringify(['authorization_code']),
				},
				{
					clientId: 'owner-cli-local',
					redirectUris: JSON.stringify(['http://127.0.0.1/callback']),
					scopes: JSON.stringify(['tool-portal:management']),
					applicationType: 'native',
					tokenEndpointAuthMethod: 'none',
					requirePKCE: true,
					skipConsent: true,
					grantTypes: JSON.stringify(['authorization_code']),
				},
				{
					clientId: 'owner-fleet-cli-local',
					redirectUris: JSON.stringify(['http://127.0.0.1/callback']),
					scopes: JSON.stringify(['fleet:admin', 'offline_access']),
					applicationType: 'native',
					tokenEndpointAuthMethod: 'none',
					requirePKCE: true,
					skipConsent: true,
					grantTypes: JSON.stringify(['authorization_code', 'refresh_token']),
				},
			],
			links: [
				{ clientId: 'admin-page-local', identifier: 'https://central.example.invalid/admin' },
				{ clientId: 'owner-cli-local', identifier: expect.stringMatching(/management$/u) },
				{ clientId: 'owner-fleet-cli-local', identifier: 'https://central.example.invalid/admin' },
			],
		});
		expect(repeated.status).toBe(200);
		expect(concurrent.map((response) => response.status)).toEqual([200, 200]);
		expect(afterRepeats).toEqual(first);
		// A different admin client is neither reused nor rewritten.
		expect([incompatible.status, incompatibleBody]).toEqual([503, { kind: 'incomplete' }]);
		expect([extraGrant.status, extraGrantBody]).toEqual([503, { kind: 'incomplete' }]);
		expect(afterIncompatible).toMatchObject({
			clients: [
				{
					clientId: 'admin-page-local',
					redirectUris: JSON.stringify(['https://elsewhere.example.invalid/callback']),
				},
				expect.objectContaining({ clientId: 'owner-cli-local' }),
				expect.objectContaining({ clientId: 'owner-fleet-cli-local' }),
			],
		});
	} finally {
		await harness.close();
	}
});

it('organization admin: a member forwards with their own credential and central refuses each route as notPermitted, with no effect', async () => {
	// Arrange: the owner invites a member, who signs in and accepts in their own browser.
	const fixture = await setup();
	const { harness, organizationId, ownerId } = fixture;
	try {
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
		expect(harness.centralProvisioning.hasFloors(organizationId, memberId)).toBe(true);
		const member = { cookie: harness.cookie() };
		// The owner forwards first, so a forwarder that reuses an earlier caller's credential shows.
		const ownerRead = await adminPost(fixture, 'change-records', {
			organizationId,
			after: null,
			limit: 10,
		});
		expect(await ownerRead.json()).toEqual({ result: 'records', records: [] });
		// Act: each route, with a body the member's organization makes valid.
		const responses = await Promise.all([
			adminPost(
				fixture,
				'create-workspace',
				createBody(fixture, controlledSignInIds.nextId()),
				member,
			),
			adminPost(
				fixture,
				'workspace-lookup',
				{ organizationId, workspaceId: controlledSignInIds.nextId() },
				member,
			),
			adminPost(fixture, 'change-records', { organizationId, after: null, limit: 10 }, member),
		]);
		const bodies = await Promise.all(responses.map(async (response) => response.text()));
		// Assert: the member's own credential reached central, and central refused it.
		expect(responses.map((response) => response.status)).toEqual([200, 200, 200]);
		for (const body of bodies)
			expect(JSON.parse(body)).toEqual({ result: 'refused', reason: 'notPermitted' });
		expect(harness.centralAdmin.arrivals[0]?.personId).toBe(ownerId);
		const arrivals = harness.centralAdmin.arrivals.slice(1);
		expect(arrivals.map((arrival) => arrival.route).toSorted()).toEqual([
			'CreateWorkspace',
			'ReadChangeRecords',
			'WorkspaceLookup',
		]);
		for (const arrival of arrivals) {
			expect(arrival.personId).toBe(memberId);
			expect(arrival.personId).not.toBe(ownerId);
			expect(arrival.permissions).toEqual([]);
			expect(answered(arrival)).toEqual({ result: 'refused', reason: 'notPermitted' });
		}
		expect(harness.centralAdmin.workspaces).toEqual([]);
		expect(harness.centralAdmin.changeRecords).toEqual([]);
		for (const body of bodies) expectNoProofMaterial(fixture, body);
	} finally {
		await harness.close();
	}
});

it('R-retrysignal (forwarding): after an emptied central recovers, the forwarded retry carries the run deadline to the link and is aborted there; the first send carries none', async () => {
	// Arrange: a not-due ready organization answers one forwarded call, then central restarts empty.
	const fixture = await setup();
	const { harness, organizationId } = fixture;
	const peer = harness.centralProvisioning;
	const prefix = `retry-signal-${controlledSignInIds.nextId()}`;
	try {
		await holdNotDueStamp(harness, organizationId);
		const listRecords = async (): Promise<Response> =>
			adminPost(fixture, 'change-records', { organizationId, after: null, limit: 10 });
		expect((await listRecords()).status).toBe(200);
		emptyControlledCentral(harness, organizationId);
		peer.holdNextAdminRetry();
		await setRetryDeadlineBarrier(harness, prefix);
		await armRenewalDeadline(harness, prefix, organizationId);
		const arrivalsBefore = peer.arrivals.length;
		// Act: the call meets the 503, recovers, and its retry is held until the deadline fires.
		const pending = listRecords();
		await fireRetryDeadlineAfterCentralHolds(harness, prefix, organizationId);
		const answered = await pending;
		// Assert: the caller ends at the deadline; the retry's signal was aborted at the link.
		expect([answered.status, await answered.json()]).toEqual([
			503,
			{ error: 'central-unavailable' },
		]);
		expect(
			peer.arrivals
				.slice(arrivalsBefore)
				.filter((arrival) => arrival.path === fleetAdminRoutePaths.ReadChangeRecords),
		).toHaveLength(2);
		// At the link: the first request carries no deadline, the retry carries the run's and is
		// aborted by it, and both carry the same bytes.
		expect(await retrySignalObservations(harness)).toEqual({
			observations: [{ first: 'not-aborted', retry: 'aborted:TimeoutError', sameBody: true }],
		});
		// Node: the transport closed the held request, and the peer saw it (peer close). workerd
		// shows the aborted signal only before the CENTRAL binding.
		if ((process.env.SIGN_IN_TEST_HOST ?? 'cloudflare') === 'node') {
			await peer.waitForHeldAdminAbort();
			expect(peer.heldAdminAborts()).toBe(1);
		}
	} finally {
		await setRetryDeadlineBarrier(harness, null);
		peer.refuseUnstampedStores(false);
		peer.releaseHeld();
		await harness.close();
	}
});
