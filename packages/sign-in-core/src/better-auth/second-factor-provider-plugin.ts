import type { BetterAuthPlugin } from '@better-auth/core';
import { APIError, createAuthEndpoint, createAuthMiddleware, isAPIError } from 'better-auth/api';
import { z } from 'zod';

import { isPasskeyRegistrationRequest } from '#sign-in-core/better-auth/passkey-registration-request';
import {
	describePasskeyRegistrationRefusal,
	verifyPasskeyRegistrationResponse,
	type PasskeyRegistrationExpectation,
} from '#sign-in-core/better-auth/passkey-registration-verification';
import {
	requireFactorActor,
	requireFactorChange,
	type FactorActor,
} from '#sign-in-core/better-auth/second-factor-authorization';
import { requireStoredValue } from '#sign-in-core/better-auth/store-result-adapters';
import { uuid7Schema, type SignInPlatform } from '#sign-in-core/contracts/sign-in-platform';
import type { FactorChangeRecord } from '#sign-in-core/second-factors/factor-change-record';
import type { FactorChange } from '#sign-in-core/second-factors/second-factor-step-up';
import type { SignInStore } from '#sign-in-core/storage/models/sign-in-store';

const mutationPathSchema = z.enum([
	'/two-factor/enable',
	'/two-factor/generate-backup-codes',
	'/passkey/verify-registration',
	'/passkey/update-passkey',
	'/passkey/remove',
	'/two-factor/remove-app',
]);
const mutations = {
	'/two-factor/enable': { action: 'app-enrollment-started', change: 'begin-app-enrollment' },
	'/two-factor/generate-backup-codes': {
		action: 'recovery-codes-rotated',
		change: 'rotate-recovery-codes',
	},
	'/passkey/verify-registration': { action: 'passkey-added', change: 'add-passkey' },
	'/passkey/update-passkey': { action: 'passkey-renamed', change: 'rename-passkey' },
	'/passkey/remove': { action: 'passkey-removed', change: 'remove-passkey' },
	'/two-factor/remove-app': { action: 'app-removed', change: 'remove-app' },
} as const satisfies Readonly<
	Record<
		z.infer<typeof mutationPathSchema>,
		{ readonly action: FactorChangeRecord['action']; readonly change: FactorChange }
	>
>;
const nativeRemovals = new Set([
	'/two-factor/disable',
	'/passkey/delete-passkey',
	'/two-factor/get-totp-uri',
]);
const confirmationPaths = new Set(['/two-factor/verify-totp', '/two-factor/verify-backup-code']);
const publicConfirmationUserSchema = z.object({
	id: uuid7Schema,
	name: z.string(),
	email: z.email(),
	emailVerified: z.boolean(),
	image: z.string().nullish(),
	createdAt: z.union([z.date(), z.iso.datetime()]),
	updatedAt: z.union([z.date(), z.iso.datetime()]),
});
const nativeConfirmationSchema = z.object({
	token: z.string().min(1),
	user: publicConfirmationUserSchema,
});

/** The passkey plugin's challenge cookie name: its default, which sign-in does not override. */
const passkeyChallengeCookieName = 'better-auth-passkey';
/** The verification row the challenge cookie names, as the adapter returns it. */
const storedVerificationRowSchema = z.object({ value: z.string(), expiresAt: z.coerce.date() });
const storedRegistrationChallengeSchema = z.object({
	type: z.literal('registration'),
	expectedChallenge: z.string(),
	userData: z.object({ id: z.string() }),
});

export function createSecondFactorProviderPlugin(props: {
	readonly store: Pick<SignInStore, 'factors' | 'factorChanges'>;
	readonly platform: Pick<SignInPlatform, 'clock' | 'ids'>;
	/** The origin and RP ID the passkey plugin is configured with; verification here must use the same. */
	readonly passkeyRelyingParty: Pick<PasskeyRegistrationExpectation, 'origin' | 'rpId'>;
}): BetterAuthPlugin {
	let pending:
		| { readonly kind: 'none' }
		| {
				readonly kind: 'recorded';
				readonly change: FactorChangeRecord;
				readonly actor: FactorActor;
		  } = { kind: 'none' };
	function requireMutationPermission(actor: FactorActor, change: FactorChange): void {
		requireFactorChange({ clock: props.platform.clock, factors: actor.factors, change });
	}
	/**
	 * The live registration challenge the signed cookie names, read without any write: one adapter
	 * `findOne` on `verification`. An expired row counts as absent, as the plugin's own consume treats
	 * it. (`internalAdapter.findVerificationValue` is not used: it deletes expired rows table-wide.)
	 */
	async function readLiveRegistrationChallenge(
		context: Parameters<Parameters<typeof createAuthMiddleware>[0]>[0],
		actor: FactorActor,
	): Promise<string | null> {
		const cookie = context.context.createAuthCookie(passkeyChallengeCookieName);
		const token = await context.getSignedCookie(cookie.name, context.context.secret);
		if (!token) return null;
		const row = storedVerificationRowSchema.safeParse(
			await context.context.adapter.findOne({
				model: 'verification',
				where: [{ field: 'identifier', value: token }],
			}),
		);
		if (!row.success || row.data.expiresAt.getTime() < props.platform.clock.now()) return null;
		let storedJson: unknown;
		try {
			storedJson = JSON.parse(row.data.value);
		} catch {
			return null;
		}
		const challenge = storedRegistrationChallengeSchema.safeParse(storedJson);
		return challenge.success && challenge.data.userData.id === actor.personId
			? challenge.data.expectedChallenge
			: null;
	}
	/**
	 * Verify the registration the way the passkey plugin will, without consuming its challenge, so a
	 * known client fault answers 400 instead of the plugin's 500. A missing, expired or foreign
	 * challenge is left to the plugin's own 4xx answers; a verifier failure no credential error
	 * explains answers 500 here, before the plugin consumes anything.
	 */
	async function refuseUnverifiableRegistration(
		context: Parameters<Parameters<typeof createAuthMiddleware>[0]>[0],
		actor: FactorActor,
	): Promise<void> {
		const expectedChallenge = await readLiveRegistrationChallenge(context, actor);
		if (expectedChallenge === null) return;
		const body = z.object({ response: z.unknown() }).safeParse(context.body);
		const verification = await verifyPasskeyRegistrationResponse({
			response: body.success ? body.data.response : undefined,
			expected: { challenge: expectedChallenge, ...props.passkeyRelyingParty },
		});
		switch (verification.kind) {
			case 'verified':
				return;
			case 'refused':
				throw new APIError('BAD_REQUEST', {
					error: 'invalid_request',
					reason: verification.reason,
					message: describePasskeyRegistrationRefusal(verification.reason),
				});
			case 'verifier-failed':
				context.context.logger.error('Passkey registration verifier failed', verification.failure);
				throw new APIError('INTERNAL_SERVER_ERROR', {
					message: 'passkey-registration-verifier-failed',
				});
			default: {
				const unreachable: never = verification;
				throw new Error(`Unhandled verification outcome ${JSON.stringify(unreachable)}`);
			}
		}
	}
	return {
		id: 'sign-in-second-factors',
		hooks: {
			before: [
				{
					matcher: (context) =>
						nativeRemovals.has(context.path ?? '') ||
						confirmationPaths.has(context.path ?? '') ||
						mutationPathSchema.safeParse(context.path).success ||
						context.path === '/passkey/generate-register-options',
					handler: createAuthMiddleware(async (context): Promise<void> => {
						const pathname = context.path ?? '';
						if (nativeRemovals.has(pathname))
							throw new APIError('NOT_FOUND', { code: 'NOT_OFFERED', message: 'not-found' });
						const body = z.record(z.string(), z.unknown()).safeParse(context.body);
						if (
							body.success &&
							(body.data.trustDevice === true || body.data.createSession === true)
						)
							throw new APIError('BAD_REQUEST', {
								code: 'NOT_OFFERED',
								message: 'option-not-offered',
							});
						const actor = await requireFactorActor({ context, store: props.store.factors });
						if (pathname === '/passkey/generate-register-options') {
							requireMutationPermission(actor, 'add-passkey');
							return;
						}
						let action: FactorChangeRecord['action'];
						let targetId = uuid7Schema.parse(actor.personId);
						if (confirmationPaths.has(pathname)) {
							if (
								pathname === '/two-factor/verify-backup-code' &&
								actor.factors.enrollment.kind === 'never-enrolled'
							)
								throw new APIError('FORBIDDEN', { code: 'APP_REQUIRED', message: 'appRequired' });
							action =
								pathname === '/two-factor/verify-totp' ? 'app-confirmed' : 'recovery-code-used';
						} else {
							const path = mutationPathSchema.parse(pathname);
							const mutation = mutations[path];
							requireMutationPermission(actor, mutation.change);
							if (
								path === '/passkey/verify-registration' &&
								!isPasskeyRegistrationRequest(context.body)
							)
								throw new APIError('BAD_REQUEST', {
									code: 'INVALID_REQUEST',
									message: 'invalid-passkey-registration',
								});
							if (path === '/passkey/verify-registration')
								await refuseUnverifiableRegistration(context, actor);
							if (
								path === '/two-factor/enable' &&
								body.success &&
								body.data.method !== undefined &&
								body.data.method !== 'totp'
							)
								throw new APIError('BAD_REQUEST', { code: 'NOT_OFFERED', message: 'app-required' });
							if (path === '/passkey/remove' || path === '/passkey/update-passkey') {
								const parsed = z.object({ id: uuid7Schema }).safeParse(context.body);
								if (!parsed.success)
									throw new APIError('BAD_REQUEST', {
										code: 'INVALID_REQUEST',
										message: 'invalid-passkey-id',
									});
								targetId = parsed.data.id;
							}
							action = mutation.action;
						}
						const change: FactorChangeRecord = {
							requestId: props.platform.ids.nextId(),
							actorPersonId: actor.personId,
							action,
							targetId,
						};
						requireStoredValue(await props.store.factorChanges.record(change, 'intent'));
						pending = { kind: 'recorded', change, actor };
					}),
				},
			],
			after: [
				{
					matcher: (context) =>
						confirmationPaths.has(context.path ?? '') ||
						mutationPathSchema.safeParse(context.path).success,
					handler: createAuthMiddleware(async (context): Promise<unknown> => {
						if (
							pending.kind !== 'recorded' ||
							context.context.returned === undefined ||
							isAPIError(context.context.returned)
						)
							return;
						if (context.context.returned instanceof Response && !context.context.returned.ok)
							return;
						const pathname = context.path ?? '';
						if (confirmationPaths.has(pathname)) {
							const result = nativeConfirmationSchema.safeParse(context.context.returned);
							if (!result.success || result.data.user.id !== pending.actor.personId)
								throw new APIError('SERVICE_UNAVAILABLE', {
									message: 'second-factor-result-unconfirmed',
								});
							// Native first app enrollment (and re-enrollment) rotates the session.
							// Its JSON token can still name the deleted old one; the browser's new
							// cookie follows newSession, so that actual session must receive the stamp.
							const current = context.context.newSession ?? context.context.session;
							if (
								current === null ||
								current === undefined ||
								current.user.id !== pending.actor.personId
							)
								throw new APIError('UNAUTHORIZED', { message: 'session-not-live' });
							const stamped = requireStoredValue(
								await props.store.factors.stampSession({
									personId: pending.actor.personId,
									sessionId: uuid7Schema.parse(current.session.id),
									method: pathname === '/two-factor/verify-totp' ? 'app' : 'recoveryCode',
								}),
							);
							if (stamped.kind !== 'stamped')
								throw new APIError('UNAUTHORIZED', { message: 'session-not-live' });
							requireStoredValue(await props.store.factorChanges.record(pending.change, 'outcome'));
							return context.json({ user: result.data.user });
						}
						requireStoredValue(await props.store.factorChanges.record(pending.change, 'outcome'));
						return undefined;
					}),
				},
			],
		},
		endpoints: {
			removePasskeySafely: createAuthEndpoint(
				'/passkey/remove',
				{ method: 'POST', body: z.strictObject({ id: uuid7Schema }) },
				async (context) => {
					const actor = await requireFactorActor({ context, store: props.store.factors });
					requireMutationPermission(actor, 'remove-passkey');
					const result = requireStoredValue(
						await props.store.factors.removePasskey({
							personId: actor.personId,
							passkeyId: context.body.id,
						}),
					);
					if (result.kind !== 'removed')
						throw new APIError('FORBIDDEN', {
							code: 'ANOTHER_FACTOR_REQUIRED',
							message: 'anotherFactorRequired',
						});
					return context.json({ status: true });
				},
			),
			removeAuthenticatorApp: createAuthEndpoint(
				'/two-factor/remove-app',
				{ method: 'POST', body: z.strictObject({}) },
				async (context) => {
					const actor = await requireFactorActor({ context, store: props.store.factors });
					requireMutationPermission(actor, 'remove-app');
					const result = requireStoredValue(
						await props.store.factors.removeAuthenticatorApp(actor.personId),
					);
					if (result.kind !== 'removed')
						throw new APIError('FORBIDDEN', {
							code: 'ANOTHER_FACTOR_REQUIRED',
							message: 'anotherFactorRequired',
						});
					return context.json({ status: true });
				},
			),
		},
	};
}
