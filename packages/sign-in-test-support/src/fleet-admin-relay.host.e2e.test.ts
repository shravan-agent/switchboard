import {
	organization,
	fleetAdminIntentDigest,
	fleetAdminRoutePaths,
	readOrganizationStatementFacts,
	signFleetAdminProof,
	type FleetAdminRequest,
} from '@agent-collaboration/sign-in-core';
import {
	createMemoryProofKeyStore,
	signInFleetCli,
	type FleetCliSession,
} from '@agent-collaboration/sign-in-owner-cli';
import { eq } from 'drizzle-orm';
import { decodeJwt } from 'jose';
import { expect, it } from 'vitest';
import { z } from 'zod';

import {
	emptyControlledCentral,
	holdNotDueStamp,
} from '#sign-in-test-support/test-fixtures/central-forgot-host';
import { useControlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-node-test-clock';
import { controlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-sign-in-clock';
import {
	setupFleetCli,
	sha256,
	type FleetFixture,
} from '#sign-in-test-support/test-fixtures/fleet-cli-fixture';
import { holdExpiredStampRecord } from '#sign-in-test-support/test-fixtures/organization-stamp-record';
import { webSignInCrypto } from '#sign-in-test-support/test-fixtures/recording-sign-in-capabilities';
import {
	armRenewalDeadline,
	fireDeadlineAfterCentralHolds,
	fireRetryDeadlineAfterCentralHolds,
	retrySignalObservations,
	setRetryDeadlineBarrier,
	setRenewalDeadlineBarrier,
} from '#sign-in-test-support/test-fixtures/renewal-deadline-proof';

useControlledSignInClock();
const relayPath = {
	CreateWorkspace: '/api/auth/organization-admin/v1/create-workspace',
	WorkspaceLookup: '/api/auth/organization-admin/v1/workspace-lookup',
	ReadChangeRecords: '/api/auth/organization-admin/v1/change-records',
	EngineHealth: '/api/auth/organization-admin/v1/engine-health',
	EngineListRetired: '/api/auth/organization-admin/v1/engine-retired',
	EngineRetry: '/api/auth/organization-admin/v1/engine-retry',
	EngineDiscard: '/api/auth/organization-admin/v1/engine-discard',
} as const;

/** Central's proof for `signedFor`, as the CLI signs it; `htu` defaults to central's origin. */
async function proofFor(props: {
	readonly fixture: FleetFixture;
	readonly session: FleetCliSession;
	readonly signedFor: FleetAdminRequest;
	readonly htu?: string;
}): Promise<string> {
	return signFleetAdminProof(webSignInCrypto, {
		key: props.session.key,
		htu:
			props.htu ??
			`${props.fixture.target.centralPublicOrigin}${fleetAdminRoutePaths[props.signedFor.operation]}`,
		requestId: props.fixture.io.nextId(),
		issuedAtSeconds: Math.floor(props.fixture.io.now() / 1000),
		bound: {
			accessToken: props.session.accessToken,
			intent: await fleetAdminIntentDigest(webSignInCrypto, props.signedFor),
		},
	});
}

async function relay(props: {
	readonly fixture: FleetFixture;
	readonly operation: FleetAdminRequest['operation'];
	readonly body: string;
	readonly headers: Readonly<Record<string, string>>;
}): Promise<Response> {
	if (props.operation === 'ListWorkspaces')
		throw new Error('ListWorkspaces has no public CLI relay');
	return fetch(new URL(relayPath[props.operation], props.fixture.target.issuer), {
		method: 'POST',
		headers: { 'content-type': 'application/json', ...props.headers },
		body: props.body,
	});
}

async function signedIn(fixture: FleetFixture): Promise<FleetCliSession> {
	return signInFleetCli({
		target: fixture.target,
		store: createMemoryProofKeyStore(webSignInCrypto),
		io: fixture.io,
	});
}

it('relay: an engine-only refusal is upstream unavailable after the verified request reaches Central', async (): Promise<void> => {
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const session = await signedIn(fixture);
		const body = { organizationId: target.organizationId, after: null, limit: 10 };
		const records: FleetAdminRequest = { operation: 'ReadChangeRecords', ...body };
		harness.centralAdmin.scriptNextRawAnswer(records.operation, {
			result: 'refused',
			reason: 'notRetired',
		});
		const response = await relay({
			fixture,
			operation: records.operation,
			body: JSON.stringify(body),
			headers: {
				authorization: `DPoP ${session.accessToken}`,
				dpop: await proofFor({ fixture, session, signedFor: records }),
			},
		});
		expect(harness.centralAdmin.arrivals.at(-1)).toMatchObject({
			route: records.operation,
			outcome: { kind: 'scripted-raw' },
		});
		expect([response.status, await response.json()]).toEqual([
			503,
			{ error: 'central-unavailable' },
		]);
	} finally {
		await harness.close();
	}
});

it('relay: non-canonical JSON reaches central byte for byte on all three routes, and each verifies', async () => {
	// Arrange
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const session = await signedIn(fixture);
		const organizationId = target.organizationId;
		const operationId = fixture.io.nextId();
		const create: FleetAdminRequest = {
			operation: 'CreateWorkspace',
			organizationId,
			operationId,
			name: 'résearch',
			description: '',
		};
		// Whitespace, reordered keys and an escaped é: valid, and not what JSON.stringify emits.
		const createBody = `{\n  "description" : "",\n  "name" : "r\\u00e9search",\n  "operationId" : "${operationId}",\n  "organizationId" : "${organizationId}"\n}`;
		expect(JSON.stringify(JSON.parse(createBody))).not.toBe(createBody);
		// Act
		const created = await relay({
			fixture,
			operation: 'CreateWorkspace',
			body: createBody,
			headers: {
				authorization: `DPoP ${session.accessToken}`,
				dpop: await proofFor({ fixture, session, signedFor: create }),
			},
		});
		const createdResult: unknown = await created.json();
		const workspaceId = String(
			(createdResult as { workspace?: { workspaceId?: string } }).workspace?.workspaceId,
		);
		const lookup: FleetAdminRequest = { operation: 'WorkspaceLookup', organizationId, workspaceId };
		const lookupBody = `{ "workspaceId" : "${workspaceId}" ,   "organizationId":"${organizationId}" }`;
		const lookedUp = await relay({
			fixture,
			operation: 'WorkspaceLookup',
			body: lookupBody,
			headers: {
				authorization: `DPoP ${session.accessToken}`,
				dpop: await proofFor({ fixture, session, signedFor: lookup }),
			},
		});
		const records: FleetAdminRequest = {
			operation: 'ReadChangeRecords',
			organizationId,
			after: null,
			limit: 10,
		};
		const recordsBody = `{"limit":  10, "after" : null,\t"organizationId":"${organizationId}"}`;
		const listed = await relay({
			fixture,
			operation: 'ReadChangeRecords',
			body: recordsBody,
			headers: {
				authorization: `DPoP ${session.accessToken}`,
				dpop: await proofFor({ fixture, session, signedFor: records }),
			},
		});
		// Assert
		expect([created.status, lookedUp.status, listed.status]).toEqual([200, 200, 200]);
		expect(createdResult).toMatchObject({ result: 'applied', workspace: { name: 'résearch' } });
		expect(await lookedUp.json()).toMatchObject({ result: 'found', workspace: { workspaceId } });
		expect(await listed.json()).toMatchObject({ result: 'records' });
		expect(harness.centralAdmin.arrivals.map((arrival) => arrival.bodySha256)).toEqual([
			sha256(createBody),
			sha256(lookupBody),
			sha256(recordsBody),
		]);
		expect(harness.centralAdmin.arrivals.map((arrival) => arrival.outcome.kind)).toEqual([
			'answered',
			'answered',
			'answered',
		]);
	} finally {
		await harness.close();
	}
});

it('relay: a body changed after signing is refused on intent while the original passes; a proof for the relay URL is refused on htu', async () => {
	// Arrange
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const session = await signedIn(fixture);
		const signed: FleetAdminRequest = {
			operation: 'CreateWorkspace',
			organizationId: target.organizationId,
			operationId: fixture.io.nextId(),
			name: 'research',
			description: '',
		};
		const body = (name: string): string =>
			JSON.stringify({
				organizationId: signed.organizationId,
				operationId: signed.operationId,
				name,
				description: '',
			});
		const credential = { authorization: `DPoP ${session.accessToken}` };
		// Act
		const tampered = await relay({
			fixture,
			operation: 'CreateWorkspace',
			body: body('tampered'),
			headers: { ...credential, dpop: await proofFor({ fixture, session, signedFor: signed }) },
		});
		const relayHtu = await relay({
			fixture,
			operation: 'CreateWorkspace',
			body: body('research'),
			headers: {
				...credential,
				dpop: await proofFor({
					fixture,
					session,
					signedFor: signed,
					htu: new URL(relayPath.CreateWorkspace, target.issuer).toString(),
				}),
			},
		});
		const original = await relay({
			fixture,
			operation: 'CreateWorkspace',
			body: body('research'),
			headers: { ...credential, dpop: await proofFor({ fixture, session, signedFor: signed }) },
		});
		// Assert
		expect([tampered.status, relayHtu.status, original.status]).toEqual([401, 401, 200]);
		expect(
			harness.centralAdmin.arrivals.map((arrival) =>
				arrival.outcome.kind === 'refused-unauthenticated'
					? arrival.outcome.failure
					: arrival.outcome.kind,
			),
		).toEqual(['intent', 'proof-htu', 'answered']);
		expect(harness.centralAdmin.workspaces.map((workspace) => workspace.name)).toEqual([
			'research',
		]);
	} finally {
		await harness.close();
	}
});

it('relay: a cookie, a Bearer scheme or a missing DPoP proof is refused at the relay with valid inputs, and nothing reaches central', async () => {
	// Arrange
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const session = await signedIn(fixture);
		const records: FleetAdminRequest = {
			operation: 'ReadChangeRecords',
			organizationId: target.organizationId,
			after: null,
			limit: 10,
		};
		const body = JSON.stringify({ organizationId: target.organizationId, after: null, limit: 10 });
		const proof = async (): Promise<string> => proofFor({ fixture, session, signedFor: records });
		// Act
		const withCookie = await relay({
			fixture,
			operation: 'ReadChangeRecords',
			body,
			headers: {
				authorization: `DPoP ${session.accessToken}`,
				dpop: await proof(),
				cookie: fixture.cookie,
			},
		});
		const bearer = await relay({
			fixture,
			operation: 'ReadChangeRecords',
			body,
			headers: { authorization: `Bearer ${session.accessToken}`, dpop: await proof() },
		});
		const noProof = await relay({
			fixture,
			operation: 'ReadChangeRecords',
			body,
			headers: { authorization: `DPoP ${session.accessToken}` },
		});
		const control = await relay({
			fixture,
			operation: 'ReadChangeRecords',
			body,
			headers: { authorization: `DPoP ${session.accessToken}`, dpop: await proof() },
		});
		// Assert: only the valid control arrives.
		expect([withCookie.status, bearer.status, noProof.status, control.status]).toEqual([
			403, 401, 401, 200,
		]);
		expect(await withCookie.json()).toEqual({ error: 'not-allowed' });
		expect(await bearer.json()).toEqual({ error: 'dpop-required' });
		expect(await noProof.json()).toEqual({ error: 'dpop-required' });
		expect(harness.centralAdmin.arrivals).toHaveLength(1);
		expect(harness.centralAdmin.arrivals[0]?.bodySha256).toBe(sha256(body));
	} finally {
		await harness.close();
	}
});

it('relay: over an expired stamp renewal cannot replace, the relay answers 503 and reaches no central admin route; once the re-sent stamp lands the same request is relayed', async () => {
	// Arrange
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	try {
		const session = await signedIn(fixture);
		const records: FleetAdminRequest = {
			operation: 'ReadChangeRecords',
			organizationId: target.organizationId,
			after: null,
			limit: 10,
		};
		// The literal wire body: central's closed request schema has no `operation`.
		const body = JSON.stringify({ organizationId: target.organizationId, after: null, limit: 10 });
		await holdExpiredStampRecord({
			database: harness.database,
			organizationId: target.organizationId,
			nowMilliseconds: controlledSignInClock.now(),
		});
		const arrivalsBefore = harness.centralAdmin.arrivals.length;
		const sendsBefore = harness.centralProvisioning.sends.length;
		const send = async (): Promise<Response> =>
			relay({
				fixture,
				operation: 'ReadChangeRecords',
				body,
				headers: {
					authorization: `DPoP ${session.accessToken}`,
					dpop: await proofFor({ fixture, session, signedFor: records }),
				},
			});
		// Act: the first renewal gets no answer; the second, re-sent unchanged, lands.
		harness.centralProvisioning.replyWith('unavailable');
		const withheld = await send();
		const arrivalsWhileWithheld = harness.centralAdmin.arrivals.length - arrivalsBefore;
		harness.centralProvisioning.replyWith('provisioned');
		const relayed = await send();
		// Assert
		expect(withheld.status).toBe(503);
		expect(await withheld.json()).toEqual({ error: 'central-unavailable' });
		expect(arrivalsWhileWithheld).toBe(0);
		expect(relayed.status).toBe(200);
		expect(
			harness.centralAdmin.arrivals.slice(arrivalsBefore).map((arrival) => arrival.bodySha256),
		).toEqual([sha256(body)]);
		const renewals = harness.centralProvisioning.sends
			.slice(sendsBefore)
			.map((sent) => sent.organizationStatement);
		expect(renewals).toHaveLength(2);
		expect(renewals[1]).toBe(renewals[0]);
	} finally {
		await harness.close();
	}
});

it('relay: a renewal central never answers ends at its deadline; with nothing pending the relay over a valid stamp still goes out and over an expired one is withheld (D7)', async () => {
	// Arrange: the organization has no pending revisions; central holds every renewal unanswered.
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	const prefix = `relay-deadline-${fixture.io.nextId()}`;
	try {
		const session = await signedIn(fixture);
		const delivered = await harness.auth('/__auth-proof/organization-fleet-call', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ organizationId: target.organizationId }),
		});
		expect(await delivered.json()).toMatchObject({ revisions: { kind: 'delivered' } });
		const records: FleetAdminRequest = {
			operation: 'ReadChangeRecords',
			organizationId: target.organizationId,
			after: null,
			limit: 10,
		};
		// The literal wire body: central's closed request schema has no `operation`.
		const body = JSON.stringify({ organizationId: target.organizationId, after: null, limit: 10 });
		const send = async (): Promise<Response> =>
			relay({
				fixture,
				operation: 'ReadChangeRecords',
				body,
				headers: {
					authorization: `DPoP ${session.accessToken}`,
					dpop: await proofFor({ fixture, session, signedFor: records }),
				},
			});
		const nowSeconds = Math.floor(controlledSignInClock.now() / 1000);
		// A valid stamp with 59 days left: due, so the guard renews first.
		await harness.database
			.update(organization)
			.set({
				fleetState: 'ready',
				fleetStampDigest: 'f'.repeat(64),
				fleetStampExpiresAt: nowSeconds + 59 * 86_400,
				fleetStampSigningKeyId: 'held-native-key',
				fleetStampSent: null,
			})
			.where(eq(organization.id, target.organizationId));
		harness.centralProvisioning.replyWith('hold');
		await setRenewalDeadlineBarrier(harness, prefix);
		const arrivalsBefore = harness.centralAdmin.arrivals.length;
		const heldBefore = harness.centralProvisioning.sends.length;
		// Act: the renewal is held until its deadline fires; then the expired variant.
		await armRenewalDeadline(harness, prefix, target.organizationId);
		const validRelay = send();
		await fireDeadlineAfterCentralHolds(harness, prefix, 1);
		const overValidStamp = await validRelay;
		const arrivalsAfterValid = harness.centralAdmin.arrivals.length - arrivalsBefore;
		await holdExpiredStampRecord({
			database: harness.database,
			organizationId: target.organizationId,
			nowMilliseconds: controlledSignInClock.now(),
		});
		await armRenewalDeadline(harness, prefix, target.organizationId);
		const expiredRelay = send();
		await fireDeadlineAfterCentralHolds(harness, prefix, 2);
		const overExpiredStamp = await expiredRelay;
		// Assert
		expect(overValidStamp.status).toBe(200);
		expect(arrivalsAfterValid).toBe(1);
		expect(overExpiredStamp.status).toBe(503);
		expect(harness.centralAdmin.arrivals.length - arrivalsBefore).toBe(1);
		expect(harness.centralProvisioning.sends.length - heldBefore).toBe(2);
	} finally {
		await setRenewalDeadlineBarrier(harness, null);
		harness.centralProvisioning.releaseHeld();
		harness.centralProvisioning.replyWith('provisioned');
		await harness.close();
	}
});

it('central forgot (WS7 R-notdue, R-floors): after central restarts empty, a ready organization that is not due recovers on its next relayed call; one 503, one fresh setup, its floors pushed again, and the retry is answered', async () => {
	// Arrange: steady state. Sign-in signed its setup statement, central stores it, the record
	// names it with its full lifetime left, and central holds the floors bootstrap pushed.
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	const peer = harness.centralProvisioning;
	try {
		const session = await signedIn(fixture);
		const organizationId = target.organizationId;
		const signed = await harness.auth('/__auth-proof/organization-statement', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ organizationId }),
		});
		const { statement } = z.object({ statement: z.string() }).parse(await signed.json());
		const facts = await readOrganizationStatementFacts(webSignInCrypto, statement);
		peer.holdStamp(organizationId, facts);
		await harness.database
			.update(organization)
			.set({
				fleetState: 'ready',
				fleetStampDigest: facts.digest,
				fleetStampExpiresAt: facts.expiresAt,
				fleetStampSigningKeyId: facts.signingKeyId,
				fleetStampSent: null,
			})
			.where(eq(organization.id, organizationId));
		const records: FleetAdminRequest = {
			operation: 'ReadChangeRecords',
			organizationId,
			after: null,
			limit: 10,
		};
		const readRecords = async (): Promise<Response> =>
			relay({
				fixture,
				operation: 'ReadChangeRecords',
				body: JSON.stringify({ organizationId, after: null, limit: 10 }),
				headers: {
					authorization: `DPoP ${session.accessToken}`,
					dpop: await proofFor({ fixture, session, signedFor: records }),
				},
			});
		expect((await readRecords()).status).toBe(200);
		// Arrange: central restarts empty, with no stamp and no floors, and refuses unstamped stores.
		peer.holdStamp(organizationId, null);
		peer.forgetFloors();
		peer.refuseUnstampedStores(true);
		peer.replyWith('provisioned');
		peer.replyToPushesWith('acknowledge');
		const personId = String(decodeJwt(session.accessToken).sub);
		const sendsBefore = peer.sends.length;
		const pushesBefore = peer.pushes.length;
		const arrivalsBefore = peer.arrivals.length;
		// Act: the CLI's next call, not due for renewal, so the guard reads nothing first.
		const recovered = await readRecords();
		// Assert: the call is answered, after exactly one 503 and one retry of the same request.
		expect(recovered.status).toBe(200);
		expect(await recovered.json()).toMatchObject({ result: 'records' });
		const adminPath = fleetAdminRoutePaths.ReadChangeRecords;
		expect(
			peer.arrivals.slice(arrivalsBefore).filter((arrival) => arrival.path === adminPath),
		).toHaveLength(2);
		// One fresh setup statement, no predecessor, and the record names what central now holds.
		const setups = peer.sends.slice(sendsBefore).map((send) => send.organizationStatement);
		expect(setups).toHaveLength(1);
		expect(decodeJwt(setups[0] ?? '').replaces).toBeUndefined();
		const stored = await readOrganizationStatementFacts(webSignInCrypto, setups[0] ?? '');
		const record = (
			await harness.database
				.select({ digest: organization.fleetStampDigest, sent: organization.fleetStampSent })
				.from(organization)
				.where(eq(organization.id, organizationId))
		)[0];
		expect(record).toEqual({ digest: stored.digest, sent: null });
		// R-floors: the organization fence went first, then the pairs, and central holds both floors.
		const pushed = peer.pushes.slice(pushesBefore);
		expect(pushed[0]?.kind).toBe('organization');
		expect(pushed.some((push) => push.kind === 'person' && push.personId === personId)).toBe(true);
		expect(peer.hasFloors(organizationId, personId)).toBe(true);
	} finally {
		peer.refuseUnstampedStores(false);
		await harness.close();
	}
});

it('R-retrysignal (relay): after an emptied central recovers, the relayed retry carries the run deadline to the link and is aborted there; the first send carries none', async () => {
	// Arrange: a not-due ready organization answers one relayed call, then central restarts empty.
	const fixture = await setupFleetCli();
	const { harness, target } = fixture;
	const peer = harness.centralProvisioning;
	const prefix = `retry-signal-${fixture.io.nextId()}`;
	try {
		const session = await signedIn(fixture);
		const organizationId = target.organizationId;
		await holdNotDueStamp(harness, organizationId);
		const records: FleetAdminRequest = {
			operation: 'ReadChangeRecords',
			organizationId,
			after: null,
			limit: 10,
		};
		const readRecords = async (): Promise<Response> =>
			relay({
				fixture,
				operation: 'ReadChangeRecords',
				// The literal wire body: central's closed request schema has no `operation`.
				body: JSON.stringify({ organizationId, after: null, limit: 10 }),
				headers: {
					authorization: `DPoP ${session.accessToken}`,
					dpop: await proofFor({ fixture, session, signedFor: records }),
				},
			});
		expect((await readRecords()).status).toBe(200);
		emptyControlledCentral(harness, organizationId);
		peer.holdNextAdminRetry();
		await setRetryDeadlineBarrier(harness, prefix);
		await armRenewalDeadline(harness, prefix, organizationId);
		const arrivalsBefore = peer.arrivals.length;
		// Act: the call meets the 503, recovers, and its retry is held until the deadline fires.
		const pending = readRecords();
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
