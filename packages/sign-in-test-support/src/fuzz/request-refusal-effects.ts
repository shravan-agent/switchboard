import { z } from 'zod';

import type { CentralAcknowledgement } from '#sign-in-test-support/fuzz/central-acknowledgements';
import type { RequestCaseFixture } from '#sign-in-test-support/fuzz/request-case-fixture';
import type { ObservedRequestAnswer } from '#sign-in-test-support/fuzz/request-disclosure';
import type { GeneratedRequest } from '#sign-in-test-support/fuzz/request-families/index';
import type { RequestFamilyContext } from '#sign-in-test-support/fuzz/request-families/index';
import {
	rowBytes,
	rowsAdded,
	type RequestStorageSnapshot,
	type StoredRow,
} from '#sign-in-test-support/fuzz/request-storage-snapshot';
import type { RouteClassification } from '#sign-in-test-support/fuzz/route-classification';
import { controlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-sign-in-clock';

const factorActions: Readonly<Record<string, string>> = {
	'/api/auth/two-factor/enable': 'app-enrollment-started',
	'/api/auth/two-factor/verify-totp': 'app-confirmed',
	'/api/auth/two-factor/verify-backup-code': 'recovery-code-used',
	'/api/auth/two-factor/generate-backup-codes': 'recovery-codes-rotated',
	'/api/auth/two-factor/remove-app': 'app-removed',
	'/api/auth/passkey/verify-registration': 'passkey-added',
	'/api/auth/passkey/update-passkey': 'passkey-renamed',
	'/api/auth/passkey/remove': 'passkey-removed',
	'/api/auth/passkey/confirm': 'passkey-confirmed',
};

const nativeUserVerificationRefusalSchema = z.looseObject({
	code: z.literal('USER_VERIFICATION_REQUIRED'),
});
/**
 * verify-registration consumes its challenge natively only on the way to the afterVerification
 * user-verification refusal (403 USER_VERIFICATION_REQUIRED). Then exactly the challenge this case
 * issued may go, and nothing else. Any other refusal (the boundary's 400s among them) consumes none.
 */
function isIssuedRegistrationChallengeConsumption(props: {
	readonly removals: readonly StoredRow[];
	readonly registrationChallengeId: string | null | undefined;
	readonly answer: Pick<ObservedRequestAnswer, 'status' | 'body'> | undefined;
}): boolean {
	const [removed] = props.removals;
	return (
		props.answer?.status === 403 &&
		nativeUserVerificationRefusalSchema.safeParse(props.answer.body).success &&
		typeof props.registrationChallengeId === 'string' &&
		props.removals.length === 1 &&
		removed !== undefined &&
		String(removed.id) === props.registrationChallengeId
	);
}

function withoutFields(row: StoredRow, fields: readonly string[]): string {
	return rowBytes(Object.fromEntries(Object.entries(row).filter(([key]) => !fields.includes(key))));
}

const devicePollInput = z.strictObject({
	grant_type: z.literal('urn:ietf:params:oauth:grant-type:device_code'),
	client_id: z.string(),
	device_code: z.string(),
});
const pendingDevicePollAnswer = z.strictObject({ error: z.literal('authorization_pending') });

function pendingDevicePollRequest(request: GeneratedRequest): unknown {
	const rawBody = request.init.body;
	if (request.pathname !== '/api/auth/oauth2/token' || typeof rawBody !== 'string')
		return undefined;
	const contentType = new Headers(request.init.headers).get('content-type');
	if (contentType === 'application/json') {
		try {
			return JSON.parse(rawBody);
		} catch {
			return undefined;
		}
	}
	if (contentType !== 'application/x-www-form-urlencoded') return undefined;
	const fields = Array.from(new URLSearchParams(rawBody));
	const values = Object.fromEntries(fields);
	return fields.length === Object.keys(values).length ? values : undefined;
}

function isPendingDevicePoll(props: {
	readonly request: GeneratedRequest | undefined;
	readonly answer: Pick<ObservedRequestAnswer, 'status' | 'body'> | undefined;
	readonly old: StoredRow;
	readonly next: StoredRow;
	readonly now: number;
}): boolean {
	const { request, answer, old, next, now } = props;
	if (
		request === undefined ||
		answer?.status !== 400 ||
		!pendingDevicePollAnswer.safeParse(answer.body).success
	)
		return false;
	const input = devicePollInput.safeParse(pendingDevicePollRequest(request));
	return (
		input.success &&
		old.status === 'pending' &&
		old.clientId === input.data.client_id &&
		old.deviceCode === input.data.device_code &&
		typeof old.expiresAt === 'number' &&
		old.expiresAt > now &&
		old.lastPolledAt === null &&
		next.lastPolledAt === now &&
		withoutFields(old, ['lastPolledAt']) === withoutFields(next, ['lastPolledAt'])
	);
}

/** A permission describes one row transition, never a whole table that may change freely. */
export function assertRequestRefusalEffects(props: {
	readonly classification: RouteClassification;
	readonly fixture: Pick<RequestCaseFixture, 'sessionId'> & {
		readonly context: Pick<RequestFamilyContext, 'personId' | 'passkeyId' | 'challengeId'>;
		readonly permittedVerificationIds?: readonly string[];
		readonly registrationChallengeId?: string | null;
	};
	readonly before: RequestStorageSnapshot;
	readonly after: RequestStorageSnapshot;
	readonly request?: GeneratedRequest;
	readonly answer?: Pick<ObservedRequestAnswer, 'status' | 'body'>;
	readonly now?: number;
	/**
	 * Central's actual acknowledgements during this request (a 200 reply paired with its push): the
	 * only evidence an acknowledgement was returned. Receipt of a push, or a reply mode, is not.
	 */
	readonly central?: { readonly acknowledgements: readonly CentralAcknowledgement[] };
}): void {
	const { classification, fixture, before, after } = props;
	const now = props.now ?? controlledSignInClock.now();
	const expired = (before.session ?? []).find(
		(row) =>
			row.id === fixture.sessionId && typeof row.expiresAt === 'number' && row.expiresAt <= now,
	);
	const sessionDeleted =
		expired !== undefined && !(after.session ?? []).some((row) => row.id === expired.id);
	// A refused expired-session read must do what it is permitted to: delete the expired session and
	// advance every retained pair of that person by one, even where nothing else changed.
	if (classification.permittedRefusalEffects.includes('expired-session-cleanup') && sessionDeleted)
		for (const pair of (before.personOrganizationAuthorizationRevisions ?? []).filter(
			(row) => row.person_id === expired?.userId,
		)) {
			const next = (after.personOrganizationAuthorizationRevisions ?? []).find(
				(row) => row.id === pair.id,
			);
			if (next === undefined || Number(next.revision) !== Number(pair.revision) + 1)
				throw new Error(
					'S2 refusal-effects: expired-session cleanup did not advance every retained pair',
				);
		}
	for (const table of new Set([...Object.keys(before), ...Object.keys(after)])) {
		const original = before[table] ?? [];
		const current = after[table] ?? [];
		const additions = rowsAdded({ before: original, after: current });
		const removals = rowsAdded({ before: current, after: original });
		if (additions.length === 0 && removals.length === 0) continue;
		const permissions = classification.permittedRefusalEffects;
		if (
			table === 'deviceCode' &&
			permissions.includes('pending-device-poll') &&
			additions.length === 1 &&
			removals.length === 1
		) {
			const old = removals[0];
			const next = additions[0];
			if (
				old !== undefined &&
				next !== undefined &&
				isPendingDevicePoll({ old, next, now, request: props.request, answer: props.answer })
			)
				continue;
		}
		if (
			table === 'session' &&
			permissions.includes('clear-current-choice') &&
			additions.length === 1 &&
			removals.length === 1
		) {
			const old = removals[0];
			const next = additions[0];
			if (
				old !== undefined &&
				next !== undefined &&
				old.id === fixture.sessionId &&
				next.activeOrganizationId === null &&
				withoutFields(old, ['activeOrganizationId', 'updatedAt']) ===
					withoutFields(next, ['activeOrganizationId', 'updatedAt']) &&
				next.updatedAt === now
			)
				continue;
		}
		if (permissions.includes('expired-session-cleanup') && expired !== undefined) {
			if (
				table === 'session' &&
				additions.length === 0 &&
				removals.length === 1 &&
				removals[0]?.id === expired.id
			)
				continue;
			if (table === 'personOrganizationAuthorizationRevisions' && sessionDeleted) {
				// The refused guard run advances each of the person's pairs once. Drain-on-use
				// (authorization-revision-drainer.ts:78) may then deliver and acknowledge the new
				// revision of a pair whose organization's central confirms it, in the same run.
				const advanced = (row: Record<string, unknown>): Record<string, unknown> =>
					Object.assign({}, row, {
						revision: Number(row.revision) + 1,
						next_attempt_at: now,
						updated_at: now,
					});
				// An acknowledgement is allowed only where Central actually replied 200 to that pair's new
				// revision push, with a floor equal to the stored acknowledged revision.
				const acknowledgedByCentral = (row: Record<string, unknown>): boolean =>
					props.central?.acknowledgements.some(
						(acknowledgement) =>
							acknowledgement.organizationId === row.organization_id &&
							acknowledgement.personId === row.person_id &&
							// The push named this pair's row and carried its state: an acknowledgement for
							// another subject or state is not an acknowledgement of this pair.
							acknowledgement.subjectId === row.id &&
							acknowledgement.state === row.state &&
							acknowledgement.revision === Number(row.revision) + 1 &&
							acknowledgement.acknowledgedRevision >= acknowledgement.revision &&
							acknowledgement.acknowledgedRevision === Number(row.revision) + 1,
					) === true;
				const drained = (row: Record<string, unknown>): Record<string, unknown> =>
					Object.assign(advanced(row), {
						acknowledged_revision: Number(row.revision) + 1,
						acknowledged_at: now,
					});
				const matches =
					current.length === original.length &&
					original.every((row) => {
						const observed = current.find((candidate) => candidate.id === row.id);
						if (observed === undefined) return false;
						if (row.person_id !== expired.userId || typeof row.revision !== 'number')
							return rowBytes(observed) === rowBytes(row);
						return [advanced(row), ...(acknowledgedByCentral(row) ? [drained(row)] : [])].some(
							(allowed) => rowBytes(allowed) === rowBytes(observed),
						);
					});
				if (matches) continue;
			}
		}
		if (
			table === 'verification' &&
			additions.length === 0 &&
			permissions.includes('consume-passkey-registration-challenge') &&
			isIssuedRegistrationChallengeConsumption({
				removals,
				registrationChallengeId: fixture.registrationChallengeId,
				answer: props.answer,
			})
		)
			continue;
		if (table === 'verification' && additions.length === 0) {
			const allowed = removals.every(
				(row) =>
					(permissions.includes('consume-passkey-challenge') &&
						row.identifier ===
							`passkey-confirm:${fixture.sessionId}:${fixture.context.challengeId}`) ||
					((permissions.includes('oauth-code-consumption') ||
						permissions.includes('provider-verification-consumption')) &&
						fixture.permittedVerificationIds?.includes(String(row.id)) === true),
			);
			if (allowed) continue;
		}
		if (table === 'signInAudit' && removals.length === 0 && additions.length === 1) {
			const row = additions[0];
			if (
				permissions.includes('callback-outcome') &&
				row !== undefined &&
				row.kind === 'sign-in' &&
				row.actor_user_id === 'anonymous' &&
				row.phase === 'outcome' &&
				row.change_kind === 'failed' &&
				row.target_id === classification.path.split('/').at(-1) &&
				row.at === now
			)
				continue;
			if (
				permissions.includes('people-change-intent') &&
				row !== undefined &&
				props.request !== undefined
			) {
				let body: Readonly<Record<string, unknown>> = {};
				try {
					body = z
						.record(z.string(), z.unknown())
						.parse(
							JSON.parse(
								typeof props.request.init.body === 'string' ? props.request.init.body : '{}',
							),
						);
				} catch {
					/* malformed input has no permitted native intent */
				}
				const path = classification.path;
				const invitation = (before.invitation ?? []).find(
					(candidate) => candidate.id === body.invitationId,
				);
				const person = (before.user ?? []).find(
					(candidate) => candidate.email === body.memberIdOrEmail,
				);
				const change = path.endsWith('/invite-member')
					? 'invited'
					: path.endsWith('/cancel-invitation')
						? 'invitation-cancelled'
						: path.endsWith('/accept-invitation')
							? 'invitation-accepted'
							: 'member-removed';
				const target =
					change === 'invited'
						? body.email
						: change === 'member-removed'
							? person?.id
							: invitation?.id;
				const organization =
					change === 'invitation-cancelled' || change === 'invitation-accepted'
						? invitation?.organizationId
						: body.organizationId;
				if (
					target !== undefined &&
					organization !== undefined &&
					row.kind === 'organization-people-changed' &&
					row.actor_user_id === fixture.context.personId &&
					row.phase === 'intent' &&
					row.change_kind === change &&
					row.target_id === target &&
					row.organization_id === organization
				)
					continue;
			}
			const action = factorActions[classification.path];
			const target = [
				'/api/auth/passkey/confirm',
				'/api/auth/passkey/update-passkey',
				'/api/auth/passkey/remove',
			].includes(classification.path)
				? fixture.context.passkeyId
				: fixture.context.personId;
			if (
				permissions.includes('factor-intent') &&
				row !== undefined &&
				row.kind === 'second-factor-changed' &&
				row.actor_user_id === fixture.context.personId &&
				row.phase === 'intent' &&
				row.change_kind === action &&
				row.target_id === target
			)
				continue;
		}
		if (
			table === 'twoFactor' &&
			additions.length === 1 &&
			removals.length === 1 &&
			classification.path === '/api/auth/two-factor/verify-totp' &&
			permissions.includes('factor-intent')
		) {
			const old = removals[0];
			const next = additions[0];
			if (
				old !== undefined &&
				next !== undefined &&
				old.userId === fixture.context.personId &&
				typeof old.failedVerificationCount === 'number' &&
				next.failedVerificationCount === old.failedVerificationCount + 1 &&
				withoutFields(old, ['failedVerificationCount', 'lockedUntil']) ===
					withoutFields(next, ['failedVerificationCount', 'lockedUntil'])
			)
				continue;
		}
		throw new Error(`S2 refusal-effects: unauthorized transition in ${table}`);
	}
}
