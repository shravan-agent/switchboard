import { describe, expect, it } from 'vitest';

import {
	readCentralAcknowledgements,
	type CentralAcknowledgement,
} from '#sign-in-test-support/fuzz/central-acknowledgements';
import type { GeneratedRequest } from '#sign-in-test-support/fuzz/request-families/index';
import { assertRequestRefusalEffects } from '#sign-in-test-support/fuzz/request-refusal-effects';
import type { RequestStorageSnapshot } from '#sign-in-test-support/fuzz/request-storage-snapshot';
import type { RouteClassification } from '#sign-in-test-support/fuzz/route-classification';
import type { CentralPeerExchange } from '#sign-in-test-support/test-fixtures/controlled-central-provisioning';

type EffectsFixture = Parameters<typeof assertRequestRefusalEffects>[0]['fixture'];
const personId = '019a3dce-2000-7000-8000-000000000001';
const pushOrganizationId = '019a3dce-2000-7000-8000-0000000000aa';
const pushPersonId = personId;
/** The pair row id: the push's subjectId (product personFence.id). */
const ownSubjectId = '019a3dce-2000-7000-8000-0000000000c1';
const sessionId = '019a3dce-2000-7000-8000-000000000002';
const challengeId = '019a3dce-2000-7000-8000-000000000003';
const passkeyId = '019a3dce-2000-7000-8000-000000000004';
const fixture: EffectsFixture = { sessionId, context: { personId, challengeId, passkeyId } };
const classification: RouteClassification = {
	method: 'POST',
	path: '/api/auth/passkey/confirm',
	exposure: ['owner'],
	requestParts: ['json'],
	documentedAnswers: [403],
	disclosure: 'caller only',
	permittedRefusalEffects: ['consume-passkey-challenge', 'factor-intent'],
	evidence: 'test fixture',
};
const challenge = {
	identifier: `passkey-confirm:${sessionId}:${challengeId}`,
	value: 'challenge-value',
};
const unrelated = { identifier: 'other-verification', value: 'other-value' };
const before: RequestStorageSnapshot = {
	verification: [challenge, unrelated],
	user: [{ id: personId, name: 'Original' }],
	signInAudit: [],
};
function check(after: RequestStorageSnapshot): void {
	assertRequestRefusalEffects({ classification, fixture, before, after });
}

it('allows only the first poll timestamp for the matching pending device and client', (): void => {
	const now = 1_000;
	const pollRoute: RouteClassification = {
		...classification,
		path: '/api/auth/oauth2/token',
		permittedRefusalEffects: ['pending-device-poll'],
	};
	const pending = {
		id: 'device',
		deviceCode: 'code',
		clientId: 'client',
		status: 'pending',
		lastPolledAt: null,
		expiresAt: now + 1,
	};
	const fields = {
		grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
		client_id: 'client',
		device_code: 'code',
	};
	const request: GeneratedRequest = {
		pathname: pollRoute.path,
		init: {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams(fields).toString(),
		},
		label: 'form:valid',
		variant: { encoding: 'form', field: null, mutation: 'valid', flow: 'machine-device' },
		expectation: 'success-or-refusal',
	};
	const input = {
		classification: pollRoute,
		fixture,
		request,
		now,
		before: { deviceCode: [pending] },
		after: { deviceCode: [{ ...pending, lastPolledAt: now }] },
		answer: { status: 400, body: { error: 'authorization_pending' } },
	};
	expect(() => assertRequestRefusalEffects(input)).not.toThrow();
	expect(() =>
		assertRequestRefusalEffects({
			...input,
			answer: { status: 400, body: { error: 'invalid_grant' } },
		}),
	).toThrow('deviceCode');
	expect(() =>
		assertRequestRefusalEffects({
			...input,
			after: { deviceCode: [{ ...pending, lastPolledAt: now, status: 'approved' }] },
		}),
	).toThrow('deviceCode');
	const wrongClient = {
		...request,
		init: {
			...request.init,
			body: new URLSearchParams({ ...fields, client_id: 'other-client' }).toString(),
		},
	};
	expect(() => assertRequestRefusalEffects({ ...input, request: wrongClient })).toThrow(
		'deviceCode',
	);
});

it('allows only consumption of the exact passkey challenge', (): void => {
	expect(() => check({ ...before, verification: [unrelated] })).not.toThrow();
	expect(() => check({ ...before, verification: [challenge] })).toThrow('verification');
	expect(() =>
		check({ ...before, verification: [unrelated, { identifier: 'new', value: 'new' }] }),
	).toThrow('verification');
	expect(() =>
		check({ ...before, verification: [unrelated], user: [{ id: personId, name: 'Changed' }] }),
	).toThrow('user');
});

it('permits only the exact factor intent and rejects another actor, action, target, phase or added row', (): void => {
	const intent = {
		kind: 'second-factor-changed',
		actor_user_id: personId,
		phase: 'intent',
		change_kind: 'passkey-confirmed',
		target_id: passkeyId,
	};
	expect(() => check({ ...before, signInAudit: [intent] })).not.toThrow();
	for (const invalid of [
		{ ...intent, actor_user_id: 'other' },
		{ ...intent, change_kind: 'passkey-removed' },
		{ ...intent, target_id: personId },
		{ ...intent, target_id: 'other' },
		{ ...intent, phase: 'outcome' },
	])
		expect(() => check({ ...before, signInAudit: [invalid] })).toThrow('signInAudit');
	expect(() =>
		check({ ...before, signInAudit: [intent, { ...intent, target_id: 'other' }] }),
	).toThrow('signInAudit');
});

it('permits an expired-session read only to advance (and drain-acknowledge) the expired person’s own pairs', (): void => {
	const expiredAt = 1_000;
	const now = expiredAt + 1;
	const otherPersonId = '019a3dce-2000-7000-8000-000000000009';
	const pair = (
		id: string,
		person: string,
		extra: Record<string, unknown> = {},
	): StoredRowForTest => ({
		id: id === 'own' ? ownSubjectId : id,
		state: 'active',
		person_id: person,
		organization_id: pushOrganizationId,
		revision: 1,
		acknowledged_revision: 1,
		acknowledged_at: 0,
		next_attempt_at: 0,
		updated_at: 0,
		...extra,
	});
	const cleanup: RouteClassification = {
		...classification,
		path: '/api/auth/owner/bootstrap',
		permittedRefusalEffects: ['expired-session-cleanup'],
	};
	const base: RequestStorageSnapshot = {
		session: [{ id: sessionId, userId: personId, expiresAt: expiredAt }],
		personOrganizationAuthorizationRevisions: [pair('own', personId), pair('other', otherPersonId)],
	};
	// Central's evidence the way the campaign gets it: the stand-in's recorded exchanges, read for 200 replies.
	const exchange = (
		revision: number,
		overrides: Record<string, unknown> = {},
		response: CentralPeerExchange['response'] = {
			kind: 'answered',
			status: 200,
			body: JSON.stringify({ acknowledgedRevision: revision }),
		},
	): CentralPeerExchange => ({
		path: '/internal/organization-authorization-revisions',
		requestBody: JSON.stringify({
			kind: 'person',
			organizationId: pushOrganizationId,
			personId: pushPersonId,
			subjectId: ownSubjectId,
			revision,
			state: 'active',
			...overrides,
		}),
		response,
	});
	const centralFor = (...exchanges: CentralPeerExchange[]): CentralEvidence => ({
		acknowledgements: readCentralAcknowledgements(exchanges),
	});
	function run(
		pairs: readonly StoredRowForTest[],
		options: {
			readonly sessionsAfter?: readonly StoredRowForTest[];
			readonly central?: CentralEvidence;
		} = {},
	): void {
		assertRequestRefusalEffects({
			classification: cleanup,
			fixture,
			before: base,
			after: {
				...base,
				session: options.sessionsAfter ?? [],
				personOrganizationAuthorizationRevisions: pairs,
			},
			now,
			...(options.central === undefined ? {} : { central: options.central }),
		});
	}
	const advanced = { revision: 2, next_attempt_at: now, updated_at: now };
	const drained = { ...advanced, acknowledged_revision: 2, acknowledged_at: now };
	const effects = 'personOrganizationAuthorizationRevisions';
	expect(() => run([pair('own', personId, advanced), pair('other', otherPersonId)])).not.toThrow();
	// An acknowledgement needs Central to have received that pair's new revision and to answer with one.
	expect(() =>
		run([pair('own', personId, drained), pair('other', otherPersonId)], {
			central: centralFor(exchange(2)),
		}),
	).not.toThrow();
	// Wrong builds: another person's pair moves, a pair is acknowledged ahead of its revision, a
	// pair is advanced twice.
	expect(() =>
		run([pair('own', personId, advanced), pair('other', otherPersonId, advanced)]),
	).toThrow(effects);
	expect(() =>
		run(
			[
				pair('own', personId, { ...advanced, acknowledged_revision: 3, acknowledged_at: now }),
				pair('other', otherPersonId),
			],
			{ central: centralFor(exchange(2)) },
		),
	).toThrow(effects);
	expect(() =>
		run([pair('own', personId, { ...advanced, revision: 3 }), pair('other', otherPersonId)]),
	).toThrow('did not advance every retained pair');
	// An acknowledgement needs Central's actual 200 reply for that pair's new revision. None of these
	// is one: no evidence, a push whose reply was lost, a 412 (organization floor missing), 409 or 503
	// reply, a reply with a lower floor, a malformed reply, and replies for another revision, person
	// or organization.
	for (const central of [
		undefined,
		centralFor(exchange(2, {}, { kind: 'lost-reply' })),
		centralFor(exchange(2, {}, { kind: 'answered', status: 412, body: '' })),
		centralFor(exchange(2, {}, { kind: 'answered', status: 409, body: '' })),
		centralFor(exchange(2, {}, { kind: 'answered', status: 503, body: '' })),
		centralFor(
			exchange(
				2,
				{},
				{ kind: 'answered', status: 200, body: JSON.stringify({ acknowledgedRevision: 1 }) },
			),
		),
		centralFor(exchange(2, {}, { kind: 'answered', status: 200, body: 'not json' })),
		centralFor(exchange(3)),
		centralFor(exchange(2, { personId: otherPersonId, subjectId: otherPersonId })),
		// A 200 to the same pair and revision for a different subject row, or in a different state.
		centralFor(exchange(2, { subjectId: '019a3dce-2000-7000-8000-0000000000c2' })),
		centralFor(exchange(2, { state: 'inactive' })),
		centralFor(exchange(2, { organizationId: '019a3dce-2000-7000-8000-0000000000bb' })),
	])
		expect(() =>
			run(
				[pair('own', personId, drained), pair('other', otherPersonId)],
				central === undefined ? {} : { central },
			),
		).toThrow(effects);
	// The pair advances only with the exact deletion: a bump while the session survives is refused.
	expect(() =>
		run([pair('own', personId, advanced), pair('other', otherPersonId)], {
			sessionsAfter: base.session ?? [],
		}),
	).toThrow(effects);
	// And a deletion with the fence table unchanged did not do what a refused expired read must do.
	expect(() => run([pair('own', personId), pair('other', otherPersonId)])).toThrow(
		'did not advance every retained pair',
	);
});

type StoredRowForTest = Record<string, unknown>;
interface CentralEvidence {
	readonly acknowledgements: readonly CentralAcknowledgement[];
}

it('S1 closure: a push Central received and a stored acknowledgement are not an acknowledgement unless Central replied 200 for that revision', (): void => {
	const expiredAt = 1_000;
	const now = expiredAt + 1;
	const own = {
		id: ownSubjectId,
		state: 'active',
		person_id: personId,
		organization_id: pushOrganizationId,
		revision: 1,
		acknowledged_revision: 1,
		acknowledged_at: 0,
		next_attempt_at: 0,
		updated_at: 0,
	};
	const cleanup: RouteClassification = {
		...classification,
		path: '/api/auth/owner/bootstrap',
		permittedRefusalEffects: ['expired-session-cleanup'],
	};
	const before: RequestStorageSnapshot = {
		session: [{ id: sessionId, userId: personId, expiresAt: expiredAt }],
		personOrganizationAuthorizationRevisions: [own],
	};
	const stored = {
		...own,
		revision: 2,
		acknowledged_revision: 2,
		acknowledged_at: now,
		next_attempt_at: now,
		updated_at: now,
	};
	const push = (response: CentralPeerExchange['response']): CentralPeerExchange => ({
		path: '/internal/organization-authorization-revisions',
		requestBody: JSON.stringify({
			kind: 'person',
			organizationId: pushOrganizationId,
			personId,
			subjectId: ownSubjectId,
			revision: 2,
			state: 'active',
		}),
		response,
	});
	const check = (exchange: CentralPeerExchange): void =>
		assertRequestRefusalEffects({
			classification: cleanup,
			fixture,
			before,
			after: { ...before, session: [], personOrganizationAuthorizationRevisions: [stored] },
			now,
			central: { acknowledgements: readCentralAcknowledgements([exchange]) },
		});
	// Central received the push for revision 2, but its actual reply was a 412 (organization floor
	// missing): the stored acknowledgement was never returned.
	expect(() => check(push({ kind: 'answered', status: 412, body: '' }))).toThrow(
		'personOrganizationAuthorizationRevisions',
	);
	expect(() => check(push({ kind: 'lost-reply' }))).toThrow(
		'personOrganizationAuthorizationRevisions',
	);
	// Its actual 200 reply paired with that revision is.
	expect(() =>
		check(
			push({ kind: 'answered', status: 200, body: JSON.stringify({ acknowledgedRevision: 2 }) }),
		),
	).not.toThrow();
});

describe('verify-registration challenge consumption', (): void => {
	const registrationRoute: RouteClassification = {
		...classification,
		path: '/api/auth/passkey/verify-registration',
		permittedRefusalEffects: ['consume-passkey-registration-challenge', 'factor-intent'],
	};
	const registrationChallenge = (
		id: string,
	): { id: string; identifier: string; value: string } => ({
		id,
		identifier: `signed-token-${id}`,
		value: JSON.stringify({
			type: 'registration',
			expectedChallenge: `challenge-${id}`,
			userData: { id: personId },
		}),
	});
	const issued = registrationChallenge('019a3dce-2000-7000-8000-0000000000d1');
	const unrelated = registrationChallenge('019a3dce-2000-7000-8000-0000000000d2');
	const registrationFixture: EffectsFixture = { ...fixture, registrationChallengeId: issued.id };
	const userVerificationRefusal = {
		status: 403,
		body: { code: 'USER_VERIFICATION_REQUIRED', message: 'user-verification-required' },
	};
	const boundaryRefusal = {
		status: 400,
		body: { error: 'invalid_request', reason: 'challenge', message: 'refused' },
	};
	function checkRegistration(props: {
		readonly removed: readonly { id: string }[];
		readonly answer: { readonly status: number; readonly body: unknown };
		readonly route?: RouteClassification;
	}): void {
		const rows = [issued, unrelated];
		assertRequestRefusalEffects({
			classification: props.route ?? registrationRoute,
			fixture: registrationFixture,
			before: { ...before, verification: rows },
			after: {
				...before,
				verification: rows.filter((row) => !props.removed.some((gone) => gone.id === row.id)),
			},
			answer: props.answer,
		});
	}

	it('allows the native user-verification refusal to consume exactly the issued challenge', (): void => {
		expect(() =>
			checkRegistration({ removed: [issued], answer: userVerificationRefusal }),
		).not.toThrow();
	});

	it('flags an unrelated challenge of the same person disappearing', (): void => {
		expect(() =>
			checkRegistration({ removed: [unrelated], answer: userVerificationRefusal }),
		).toThrow('verification');
		expect(() =>
			checkRegistration({ removed: [issued, unrelated], answer: userVerificationRefusal }),
		).toThrow('verification');
	});

	it('flags an early boundary refusal that consumes its live challenge', (): void => {
		expect(() => checkRegistration({ removed: [issued], answer: boundaryRefusal })).toThrow(
			'verification',
		);
	});

	it('flags the consumption on a route without the permission', (): void => {
		expect(() =>
			checkRegistration({
				removed: [issued],
				answer: userVerificationRefusal,
				route: { ...registrationRoute, permittedRefusalEffects: ['factor-intent'] },
			}),
		).toThrow('verification');
	});
});
