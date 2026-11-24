import { createHash } from 'node:crypto';

import { invitation, organization, passkey, verification } from '@agent-collaboration/sign-in-core';
import { eq } from 'drizzle-orm';
import { z } from 'zod';

import {
	fuzzMachineLogin,
	createFuzzMachineOptions,
	prepareMachineCode,
} from '#sign-in-test-support/fuzz/machine-login-fixture';
import type { RequestFamilyContext } from '#sign-in-test-support/fuzz/request-families/index';
import {
	readRequestStorageRowCounts,
	wipeRequestStorage,
} from '#sign-in-test-support/fuzz/request-storage-snapshot';
import {
	controlledSignInClock,
	controlledSignInIds,
} from '#sign-in-test-support/test-fixtures/controlled-sign-in-clock';
import { startLocalAuthHarness } from '#sign-in-test-support/test-fixtures/local-auth-harness';
import { ensureLocalOwnerOrganization } from '#sign-in-test-support/test-fixtures/local-owner-organization';
import {
	passkeyConfirmationOptionsSchema,
	passkeyPost,
	registerBrowserPasskey,
} from '#sign-in-test-support/test-fixtures/passkey-browser-ceremonies';
import {
	peoplePost,
	signInConfirmedPeopleBrowser,
} from '#sign-in-test-support/test-fixtures/people-browser-login';
import { createSoftwarePasskeyAuthenticator } from '#sign-in-test-support/test-fixtures/software-passkey-authenticator';
import { createSoftwareTotpAuthenticator } from '#sign-in-test-support/test-fixtures/software-totp-authenticator';

export type RequestCaller = 'signed-out' | 'member' | 'owner';
export type RequestHarness = Awaited<ReturnType<typeof startLocalAuthHarness>>;
type Harness = RequestHarness;
export interface RequestCaseFixture {
	readonly harness: Harness;
	readonly context: RequestFamilyContext;
	readonly caller: RequestCaller;
	readonly cookie: string;
	readonly sessionId: string | null;
	readonly forbiddenIdentities: readonly string[];
	readonly foreignIdentities: readonly string[];
	/** The organization the pending invitation joins; the caller's own membership once accepted. */
	readonly invitedOrganizationId: string;
	/** The person the pending invitation is for. */
	readonly invitedPersonId: string;
	readonly issuedCredentials: readonly string[];
	readonly permittedVerificationIds: readonly string[];
	/** The verification row of the registration challenge this case's options request issued, if any. */
	readonly registrationChallengeId: string | null;
}

async function requireId(response: Response): Promise<string> {
	if (!response.ok) throw new Error(`F1 fixture operation refused (${response.status})`);
	return z.object({ id: z.uuidv7() }).parse(await response.json()).id;
}

/** Empty every table and the cookie jar, then prove the baseline is empty (S2 fresh-case baseline). */
export async function resetRequestHarness(harness: RequestHarness): Promise<void> {
	await harness.settleDeferredWork();
	await wipeRequestStorage(harness.database);
	harness.clearBrowserSession();
	for (const [table, count] of Object.entries(
		await readRequestStorageRowCounts(harness.database),
	)) {
		if (count !== 0) throw new Error(`S2 fresh-case-baseline: retained rows in ${table}`);
	}
	if (harness.cookie() !== '') throw new Error('S2 fresh-case-baseline: retained cookie');
}

/** Reset an owned database before native setup; host lifetime is independent of fixture lifetime. */
export async function createRequestCaseFixture(props: {
	readonly caller: RequestCaller;
	readonly path: string;
	readonly existingHarness?: Harness;
	readonly machineRefreshVariant?: boolean;
}): Promise<RequestCaseFixture> {
	const ownedHarness =
		props.existingHarness ?? (await startLocalAuthHarness(createFuzzMachineOptions()));
	const caseId = controlledSignInIds.nextId();
	let browserKey = `${caseId}:setup`;
	const harness: Harness = {
		...ownedHarness,
		totpAuthenticator: createSoftwareTotpAuthenticator(controlledSignInClock),
		useBrowser: (key): void => {
			browserKey = `${caseId}:${key}`;
			ownedHarness.useBrowser(browserKey);
		},
		auth: (pathname, init): Promise<Response> =>
			ownedHarness.authAsBrowser(browserKey, pathname, init),
	};
	try {
		if (props.existingHarness !== undefined) await resetRequestHarness(harness);
		const ownerEmail = 'owner@example.invalid';
		const memberEmail = 'fuzz-member@example.invalid';
		const foreignEmail = 'fuzz-foreign@example.invalid';
		const ownerId = await signInConfirmedPeopleBrowser({ harness, email: ownerEmail });
		const organizationId = await ensureLocalOwnerOrganization(harness);
		const foreignOrganizationId = await requireId(
			await peoplePost(harness, 'create', { name: 'Other organization', slug: 'fuzz-other' }),
		);
		const pendingMember = await requireId(
			await peoplePost(harness, 'invite-member', {
				organizationId,
				email: memberEmail,
				role: 'member',
			}),
		);
		await requireId(
			await peoplePost(harness, 'invite-member', {
				organizationId: foreignOrganizationId,
				email: foreignEmail,
				role: 'member',
			}),
		);
		const ownerCookie = harness.cookie();
		const memberId = await signInConfirmedPeopleBrowser({ harness, email: memberEmail });
		const accepted = await peoplePost(harness, 'accept-invitation', {
			invitationId: pendingMember,
		});
		if (!accepted.ok) throw new Error('F1 fixture native invitation acceptance refused');
		const memberCookie = harness.cookie();
		// Sign-in admits only the owner and invited people, and only an owner may create an
		// organization, so a memberless organization is seeded: no caller belongs to it.
		const memberlessOrganizationId = controlledSignInIds.nextId();
		await harness.database.insert(organization).values({
			id: memberlessOrganizationId,
			name: 'Memberless organization',
			slug: 'fuzz-memberless',
			createdAt: new Date(controlledSignInClock.now()),
		});
		harness.useBrowser(ownerEmail);
		const pendingInvitation = await requireId(
			await peoplePost(
				harness,
				'invite-member',
				{ organizationId: foreignOrganizationId, email: memberEmail, role: 'member' },
				ownerCookie,
			),
		);
		const callerEmail = props.caller === 'member' ? memberEmail : ownerEmail;
		harness.useBrowser(callerEmail);
		let cookie =
			props.caller === 'signed-out' ? '' : props.caller === 'owner' ? ownerCookie : memberCookie;
		const currentCookie = (): string =>
			[
				cookie,
				...harness
					.cookie()
					.split('; ')
					.filter(
						(pair) =>
							!pair.split('=')[0]?.endsWith('session_token') &&
							!pair.split('=')[0]?.endsWith('session_data') &&
							pair !== '',
					),
			]
				.filter((pair) => pair !== '')
				.join('; ');
		const auth = (pathname: string, init: RequestInit = {}): Promise<Response> =>
			harness.auth(pathname, {
				...init,
				headers: { ...Object.fromEntries(new Headers(init.headers)), cookie: currentCookie() },
			});
		const selected = await peoplePost(harness, 'set-active', { organizationId }, cookie);
		if (props.caller !== 'signed-out' && !selected.ok)
			throw new Error('F1 fixture organization selection refused');
		const sessionResult = await auth('/api/auth/get-session');
		const sessionValue = z
			.object({ session: z.object({ id: z.uuidv7() }) })
			.nullable()
			.parse(await sessionResult.json());
		const personId = props.caller === 'member' ? memberId : ownerId;
		const oauthCodeVerifier = 'fuzz-native-verifier-'.repeat(4);
		const oauthCodeChallenge = createHash('sha256').update(oauthCodeVerifier).digest('base64url');
		let context: RequestFamilyContext = {
			issuer: harness.issuer,
			personId,
			organizationId,
			memberId,
			invitationId: pendingInvitation,
			passkeyId: controlledSignInIds.nextId(),
			challengeId: controlledSignInIds.nextId(),
			oauthClientId: harness.target.ownerCliClientId,
			oauthClientSecret: 'unissued-fixture-secret',
			oauthCode: 'unissued-fixture-code',
			oauthToken: 'unissued-fixture-token',
			oauthCodeVerifier,
			oauthCodeChallenge,
			oauthRedirectUri: harness.target.ownerCliRedirectUri,
			oauthResource: harness.target.managementAudience,
			machineRouterClientId: fuzzMachineLogin.routerClientId,
			machineId: controlledSignInIds.nextId(),
			machineEnrollmentId: controlledSignInIds.nextId(),
			machineUserCode: 'ABCDEFGH',
			machineDeviceCode: 'unissued-fixture-device-code',
			machineRefreshToken: 'unissued-machine-refresh-token',
			passkeyRegistrationResponse: {},
			passkeyAuthenticationResponse: {},
			totpCode: await harness.totpAuthenticator.currentCode(callerEmail),
			backupCode: harness.totpAuthenticator.recoveryCode(callerEmail),
			captchaToken: harness.turnstile.issueToken({
				action: 'sign_in_social',
				hostname: new URL(harness.issuer).hostname,
				verdict: 'accepted',
			}),
			callbackQuery: {},
		};
		context = await prepareMachineCode({
			path: props.path,
			harness,
			ownerCookie,
			context,
			machineRefreshVariant: props.machineRefreshVariant === true,
		});
		const issuedCredentials: string[] = [context.backupCode];
		if (context.machineDeviceCode !== 'unissued-fixture-device-code')
			issuedCredentials.push(context.machineDeviceCode);
		if (context.machineRefreshToken !== 'unissued-machine-refresh-token')
			issuedCredentials.push(context.machineRefreshToken);
		if (props.path.startsWith('/api/auth/passkey/') && props.caller !== 'signed-out') {
			const authenticator = await createSoftwarePasskeyAuthenticator();
			const registered = await registerBrowserPasskey({
				harness: { ...harness, auth },
				authenticator,
			});
			if (!registered.ok) throw new Error('F1 fixture native passkey registration refused');
			const row = z
				.object({ id: z.uuidv7() })
				.parse(
					(
						await harness.database
							.select({ id: passkey.id })
							.from(passkey)
							.where(eq(passkey.userId, personId))
					)[0],
				);
			const challenge = passkeyConfirmationOptionsSchema.parse(
				await (await passkeyPost({ ...harness, auth }, 'confirm-options', {})).json(),
			);
			const options = z
				.object({ challenge: z.string(), rp: z.object({ id: z.string() }) })
				.parse(await (await auth('/api/auth/passkey/generate-register-options')).json());
			context = {
				...context,
				passkeyId: row.id,
				challengeId: challenge.challengeId,
				passkeyAuthenticationResponse: z.record(z.string(), z.unknown()).parse(
					authenticator.authenticationResponse({
						challenge: challenge.options.challenge,
						rpId: challenge.options.rpId,
						origin: harness.issuer,
					}),
				),
				passkeyRegistrationResponse: z.record(z.string(), z.unknown()).parse(
					(await createSoftwarePasskeyAuthenticator()).registrationResponse({
						challenge: options.challenge,
						rpId: options.rp.id,
						origin: harness.issuer,
					}),
				),
			};
		}
		if (props.path.startsWith('/api/auth/passkey/') && props.caller === 'signed-out') {
			// Refused before verification, but the family still builds its nested variants from a real credential.
			context = {
				...context,
				passkeyRegistrationResponse: z.record(z.string(), z.unknown()).parse(
					(await createSoftwarePasskeyAuthenticator()).registrationResponse({
						challenge: 'dW5pc3N1ZWQtY2hhbGxlbmdl',
						rpId: new URL(harness.issuer).hostname,
						origin: harness.issuer,
					}),
				),
			};
		}
		if (props.path.startsWith('/api/auth/oauth2/') && props.caller === 'owner') {
			const bootstrap = await auth('/api/auth/owner/bootstrap', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: '{}',
			});
			if (!bootstrap.ok) throw new Error('F1 fixture native OAuth bootstrap refused');
			const query = new URLSearchParams({
				response_type: 'code',
				client_id: context.oauthClientId,
				redirect_uri: context.oauthRedirectUri,
				scope: 'tool-portal:management',
				resource: context.oauthResource,
				code_challenge: oauthCodeChallenge,
				code_challenge_method: 'S256',
				state: 'fuzz-native-state',
			});
			const authorized = await auth(`/api/auth/oauth2/authorize?${query.toString()}`, {
				// A navigation, as the native CLI's browser sends it: a fetch-style request gets a JSON
				// {redirect, url} answer instead of the 302 (oauth-provider handleRedirect).
				headers: { accept: 'text/html', 'sec-fetch-mode': 'navigate' },
			});
			if (authorized.status !== 302)
				throw new Error(`F1 fixture native code authorization refused (${authorized.status})`);
			context = {
				...context,
				oauthCode: z
					.string()
					.min(1)
					.parse(
						new URL(
							authorized.headers.get('location') ?? 'invalid:',
							harness.issuer,
						).searchParams.get('code'),
					),
			};
		}
		if (props.path.startsWith('/api/auth/callback/')) {
			const provider = props.path.endsWith('/google') ? 'google' : 'github';
			const start = await auth('/api/auth/sign-in/social', {
				method: 'POST',
				headers: { 'content-type': 'application/json', 'x-captcha-response': context.captchaToken },
				body: JSON.stringify({
					provider,
					callbackURL: new URL('/owner-ready', harness.issuer).toString(),
				}),
			});
			const url = z.object({ url: z.url() }).parse(await start.json()).url;
			const callback = harness.providerCallback(provider, new URL(url), callerEmail, true);
			context = { ...context, callbackQuery: Object.fromEntries(callback.searchParams) };
			cookie = currentCookie();
		}
		await harness.settleDeferredWork();
		const verificationRows = await harness.database.select().from(verification);
		const permittedVerificationIds = verificationRows
			.filter((row) => {
				try {
					const value = z.record(z.string(), z.unknown()).parse(JSON.parse(row.value));
					return (
						value.sessionId === sessionValue?.session.id ||
						(typeof value.oauthState === 'string' &&
							value.oauthState === context.callbackQuery.state)
					);
				} catch {
					return false;
				}
			})
			.map((row) => row.id);
		const registrationChallengeIds = verificationRows
			.filter((row) => {
				try {
					return z
						.object({
							type: z.literal('registration'),
							userData: z.object({ id: z.literal(personId) }),
						})
						.safeParse(JSON.parse(row.value)).success;
				} catch {
					return false;
				}
			})
			.map((row) => row.id);
		if (registrationChallengeIds.length > 1)
			throw new Error('F1 fixture holds more than one live registration challenge');
		const foreignInvitations = await harness.database
			.select({ id: invitation.id })
			.from(invitation)
			.where(eq(invitation.email, foreignEmail));
		// A caller's own memberships are entitled (B1-C S1, S2), so only organizations the caller does
		// not belong to stay foreign. The owner created the second organization; nobody belongs to the
		// third. The member and the signed-out caller belong to neither.
		const organizationIdsOutsideCallerMemberships =
			props.caller === 'owner'
				? [memberlessOrganizationId]
				: [foreignOrganizationId, memberlessOrganizationId];
		return {
			harness,
			context,
			caller: props.caller,
			cookie: currentCookie(),
			sessionId: sessionValue?.session.id ?? null,
			invitedOrganizationId: foreignOrganizationId,
			invitedPersonId: memberId,
			foreignIdentities: [
				foreignEmail,
				...organizationIdsOutsideCallerMemberships,
				...foreignInvitations.map((row) => row.id),
			],
			forbiddenIdentities:
				props.caller === 'signed-out'
					? [ownerEmail, ownerId, memberEmail, memberId, foreignEmail]
					: props.caller === 'member'
						? [ownerEmail, ownerId, foreignEmail]
						: [foreignEmail],
			issuedCredentials,
			permittedVerificationIds,
			registrationChallengeId: registrationChallengeIds[0] ?? null,
		};
	} catch (error) {
		if (props.existingHarness === undefined) await harness.close();
		throw error;
	}
}
