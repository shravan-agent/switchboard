import { machineRouteGroups } from '#sign-in-test-support/fuzz/machine-route-classification';
import {
	documentedAnswersFor,
	supportedSocialProviders,
	type DocumentedErrorBody,
	type PermittedRefusalEffect,
	type ReachableRouteGroup,
	type RequestPart,
	type RouteCaller,
	type RouteClassification,
	type RouteExposure,
	type RouteIdentity,
} from '#sign-in-test-support/fuzz/route-classification-types';

export {
	documentedAnswersFor,
	supportedSocialProviders,
	type DocumentedErrorBody,
	type PermittedRefusalEffect,
	type RequestPart,
	type RouteCaller,
	type RouteClassification,
	type RouteExposure,
	type RouteIdentity,
};

// These groups are transcribed from the sign-in route contracts and permanent host tests,
// independently of both the provider inventory and request-family registry.
const reachableRouteGroups: readonly ReachableRouteGroup[] = [
	{
		method: 'GET',
		paths: ['/sign-in', '/owner-ready', '/organization-admin'],
		exposure: ['signed-out', 'member', 'owner'],
		requestParts: ['query'],
		documentedAnswers: [200, 303, 429],
		disclosure: 'Page content is limited to the current session and organization.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence: 'sign-in-http-handler.ts; organization-admin.host.e2e.test.ts:153,379',
	},
	{
		method: 'GET',
		paths: ['/me'],
		exposure: ['signed-out', 'member', 'owner'],
		requestParts: ['query'],
		// Signed-in shell pages (sign-in-navigation.ts:92-122): the page for a person with a current
		// organization (200), a step back to /sign-in or /owner-ready (303), a refusal for a person
		// without the page's permission or for a request carrying an authorization header (403).
		documentedAnswers: [200, 303, 403, 429],
		disclosure: "Only the caller's own organization choices and the pages the current role allows.",
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence: 'sign-in-navigation.ts:92-122; sign-in-navigation.host.e2e.test.ts',
	},
	{
		method: 'GET',
		paths: ['/people'],
		exposure: ['signed-out', 'member', 'owner'],
		requestParts: ['query'],
		// Signed-in shell pages (sign-in-navigation.ts:92-122): the page for a person with a current
		// organization (200), a step back to /sign-in or /owner-ready (303), a refusal for a person
		// without the page's permission or for a request carrying an authorization header (403).
		documentedAnswers: [200, 303, 403, 429],
		// A member sees only Me: the People page is refused to a member (sign-in-navigation.ts:107-111).
		documentedAnswersByCaller: { member: [303, 403, 429] },
		disclosure: "Only the caller's own organization choices and the pages the current role allows.",
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence: 'sign-in-navigation.ts:92-122; sign-in-navigation.host.e2e.test.ts',
	},
	{
		method: 'GET',
		paths: ['/api/auth/get-session', '/api/auth/list-accounts'],
		exposure: ['signed-out', 'member', 'owner'],
		requestParts: ['query'],
		documentedAnswers: [200, 401, 403, 429],
		disclosure: 'Only the caller session and linked accounts; no session token in the body.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence: 'session-read-routes.host.e2e.test.ts:44,95,123; sign-in-request-handler.ts:10',
	},
	{
		method: 'GET',
		paths: ['/api/auth/passkey/generate-register-options', '/api/auth/passkey/list-user-passkeys'],
		exposure: ['member', 'owner'],
		requestParts: ['query'],
		documentedAnswers: [200, 400, 401, 403, 429],
		disclosure: 'Only the caller’s passkey enrollment information.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence: 'people-factor-enrollment.host.e2e.test.ts:84; second-factor-provider-plugin.ts',
	},
	{
		method: 'GET',
		paths: [
			'/api/auth/jwks',
			'/api/auth/.well-known/oauth-authorization-server',
			'/api/auth/.well-known/openid-configuration',
			'/.well-known/oauth-authorization-server',
			'/.well-known/openid-configuration',
		],
		exposure: ['signed-out', 'member', 'owner', 'cli'],
		requestParts: ['query'],
		documentedAnswers: [200, 400, 429],
		disclosure: 'Public issuer metadata and public signing keys only.',
		permittedRefusalEffects: ['none'],
		evidence: 'people-organizations.host.e2e.test.ts:257; provider-configuration.ts',
	},
	{
		method: 'GET',
		paths: ['/api/auth/oauth2/authorize', '/api/auth/callback/google', '/api/auth/callback/github'],
		exposure: ['signed-out', 'member', 'owner', 'cli'],
		requestParts: ['query'],
		documentedAnswers: [200, 302, 303, 400, 401, 403, 429],
		disclosure: 'Only the authorized redirect and caller-bound result; no credentials in refusal.',
		permittedRefusalEffects: [
			'none',
			'provider-verification-consumption',
			'expired-session-cleanup',
			'cookie-delete',
		],
		evidence: 'people-organizations.host.e2e.test.ts:273,284; sign-in-http-handler.ts',
	},
	{
		method: 'POST',
		paths: ['/api/auth/oauth2/authorize'],
		exposure: ['signed-out', 'member', 'owner', 'cli'],
		requestParts: ['query', 'form'],
		documentedAnswers: [200, 302, 303, 400, 401, 403, 415, 429],
		disclosure: 'Only the authorized redirect and caller-bound result; no credential in refusal.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence:
			'oauth-provider authorize endpoint accepts GET and POST; sign-in-request-handler.ts:49–70',
	},
	{
		method: 'POST',
		paths: ['/api/auth/callback/google', '/api/auth/callback/github'],
		exposure: ['signed-out', 'member', 'owner'],
		requestParts: ['query', 'form', 'json'],
		documentedAnswers: [302, 400, 415, 429],
		disclosure: 'Only the caller-bound redirect; no credential in refusal.',
		permittedRefusalEffects: ['none'],
		evidence: 'better-auth api/routes/callback.mjs POST merges query and body and redirects',
	},
	{
		method: 'POST',
		paths: ['/api/auth/owner/bootstrap'],
		exposure: ['owner'],
		requestParts: ['json'],
		documentedAnswers: [200, 400, 401, 403, 415, 429],
		disclosure: 'Only the caller’s bootstrap result; no credential in refusal.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence: 'owner-client-bootstrap.ts; b2e-joint-journey.host.e2e.test.ts:139',
	},
	{
		method: 'POST',
		paths: [
			'/api/auth/organization-admin/create-workspace',
			'/api/auth/organization-admin/workspace-lookup',
			'/api/auth/organization-admin/change-records',
		],
		exposure: ['owner'],
		requestParts: ['json'],
		documentedAnswers: [200, 400, 401, 403, 429],
		disclosure:
			'Only the caller’s organization data; no other organization or credential in refusal.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence: 'fleet-admin-forwarding.ts; organization-admin.host.e2e.test.ts',
	},
	{
		method: 'POST',
		paths: [
			'/api/auth/organization-admin/v1/create-workspace',
			'/api/auth/organization-admin/v1/workspace-lookup',
			'/api/auth/organization-admin/v1/change-records',
		],
		exposure: ['cli'],
		requestParts: ['json'],
		documentedAnswers: [200, 400, 401, 403, 413, 429],
		disclosure: 'Only the authorized organization’s data; no credential in refusal.',
		permittedRefusalEffects: ['none'],
		evidence: 'fleet-admin-relay.ts; fleet-admin-relay.host.e2e.test.ts',
	},
	// COVERAGE GAP (PR #24 review S2; Sign-in Lead, step 2d): F1 covers these three routes as
	// UNAUTHENTICATED ADMISSION ONLY. The campaign attaches the caller's cookie and no DPoP token or
	// proof, so every generated request stops at the relay's early refusal (cookie, method, missing
	// DPoP, size) and never reaches a signed request, central's reply decoding or the refusals
	// behind the relay. Signed baselines (a valid CLI-signed request with a known answer, a wrong
	// key, a body changed after signing, a reused proof) are a separate follow-up PR the Lead
	// commissions after PR #24 merges. Signed behaviour is covered outside F1, in the host files
	// named in this row's evidence.
	{
		method: 'POST',
		paths: [
			'/api/auth/organization-admin/v1/approval-list',
			'/api/auth/organization-admin/v1/approval-read',
			'/api/auth/organization-admin/v1/approval-decide',
		],
		exposure: ['cli'],
		requestParts: ['json'],
		// C3 (R5): central's C3 replies and admin refusals arrive at 200; a classified refusal is
		// never a 5xx (central's result matrix), and F1's controlled central is always available.
		documentedAnswers: [200, 400, 401, 403, 413, 429],
		disclosure:
			'Only approval requests the authorized organization owner may see; no credential in refusal.',
		permittedRefusalEffects: ['none'],
		evidence:
			'F1: unauthenticated admission only (signed baselines are the follow-up PR). Signed: fleet-admin-relay.ts; approval-person-relay.host.e2e.test.ts; b3-central-approvals.host.e2e.test.ts',
	},
	// COVERAGE GAP (DEL-07, labelled as PR #24's approval rows): F1 covers these four routes as
	// UNAUTHENTICATED ADMISSION ONLY. The campaign attaches the caller's cookie and no DPoP token or
	// proof, so every generated request stops at the relay's early refusal (cookie, method, missing
	// DPoP, size) and never reaches a signed request, central's reply decoding or the refusals
	// behind the relay. Signed baselines are a separate PR. Signed behaviour is covered outside F1,
	// in the host files named in this row's evidence.
	{
		method: 'POST',
		paths: [
			'/api/auth/organization-admin/v1/engine-health',
			'/api/auth/organization-admin/v1/engine-retired',
			'/api/auth/organization-admin/v1/engine-retry',
			'/api/auth/organization-admin/v1/engine-discard',
		],
		exposure: ['cli'],
		requestParts: ['json'],
		// S2's no-5xx rule: engine replies and typed refusals arrive at 200 (engine-admin-results.md).
		// Central's empty 503 is a classified server answer, relayed as `central-unavailable`, never
		// a crash; F1's controlled central is always available, so it is not a documented answer here.
		documentedAnswers: [200, 400, 401, 403, 413, 429],
		disclosure:
			'Only the authorized organization’s engine health and retired work; no credential in refusal.',
		permittedRefusalEffects: ['none'],
		evidence:
			'F1: unauthenticated admission only (signed baselines are a separate PR). Signed: fleet-admin-relay.ts; engine-admin-relay.host.e2e.test.ts; b3-central-engine-admin.host.e2e.test.ts',
	},
	{
		method: 'POST',
		paths: [
			'/api/auth/organization/create',
			'/api/auth/organization/invite-member',
			'/api/auth/organization/cancel-invitation',
			'/api/auth/organization/accept-invitation',
			'/api/auth/organization/remove-member',
			'/api/auth/organization/set-active',
		],
		exposure: ['member', 'owner'],
		requestParts: ['json', 'form'],
		documentedAnswers: [200, 400, 401, 403, 415, 429],
		disclosure: 'Only data the caller may see in its organization; no credential in refusal.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence:
			'people-organizations.host.e2e.test.ts:58,100,107,201,435,523; organization-invitation-resend.unit.test.ts',
	},
	{
		method: 'POST',
		paths: ['/api/auth/organization/retry-provisioning'],
		exposure: ['member', 'owner'],
		requestParts: ['json', 'form'],
		// 409 is a refused statement (organization-provisioning-plugin.ts:64–76). The F1 host's
		// controlled central confirms setup, so the plugin's 503 "setting up" answer is not a
		// documented answer here: F1 injects no unavailable central, and a 5xx always fails.
		documentedAnswers: [200, 400, 401, 403, 409, 415, 429],
		documentedErrorBodies: {
			409: {
				values: { kind: 'refused' },
				exactKeys: ['kind', 'reason'],
				callers: ['member', 'owner'],
			},
		},
		disclosure: 'Only the caller’s own organization setup state; no credential in refusal.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence:
			'organization-provisioning-plugin.ts:64–76; people-organization-provisioning.host.e2e.test.ts:279–283',
	},
	// B1-C owner People reads (specification S3–S10): cookie-bound, no-store, live owner
	// permission checked around the read. Answers come from organization-membership-read-plugin.ts
	// and the permanent host tests named in each row. The unavailable answer (503) needs an injected
	// storage fault, which this fuzz never injects, so it is not a documented answer here.
	{
		method: 'GET',
		paths: ['/api/auth/organization/self-context'],
		exposure: ['signed-out', 'member', 'owner'],
		requestParts: ['query'],
		documentedAnswers: [200, 400, 401, 429],
		disclosure: 'Only the caller’s own organization choices and current choice.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence:
			'people-organization-context.host.e2e.test.ts:45,53,124,196; management-boundaries.host.e2e.test.ts:406',
	},
	{
		method: 'GET',
		paths: ['/api/auth/organization/people-list'],
		exposure: ['member', 'owner'],
		requestParts: ['query'],
		documentedAnswers: [200, 400, 401, 403, 429],
		// A member sees only Me: the owner People reads are refused to a member (B1-C S3-S10).
		documentedAnswersByCaller: { member: [400, 401, 403, 429] },
		disclosure:
			'Only the current organization’s people page, for a caller with live view permission.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence:
			'people-organization-list.host.e2e.test.ts:98,150; management-boundaries.host.e2e.test.ts:418',
	},
	{
		method: 'GET',
		paths: ['/api/auth/organization/people'],
		exposure: ['member', 'owner'],
		requestParts: ['query'],
		documentedAnswers: [200, 303, 400, 403, 429],
		// A member sees only Me: the owner People reads are refused to a member (B1-C S3-S10).
		documentedAnswersByCaller: { member: [303, 400, 403, 429] },
		disclosure: 'Only the current organization’s people page; signed-out callers go to /sign-in.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence:
			'organization-membership-read-plugin.ts:189–232; management-boundaries.host.e2e.test.ts:423',
	},
	{
		method: 'POST',
		paths: ['/api/auth/organization/person-membership'],
		exposure: ['member', 'owner'],
		requestParts: ['json'],
		documentedAnswers: [200, 400, 401, 403, 429],
		// A member sees only Me: the owner People reads are refused to a member (B1-C S3-S10).
		documentedAnswersByCaller: { member: [400, 401, 403, 429] },
		disclosure:
			'Only whether one person belongs to the caller’s current organization; no other organization.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence:
			'people-membership-lookup.host.e2e.test.ts:98,217,458,472; management-boundaries.host.e2e.test.ts:410',
	},
	{
		method: 'POST',
		paths: ['/api/auth/switchboard/sign-out'],
		exposure: ['signed-out', 'member', 'owner'],
		requestParts: ['json'],
		documentedAnswers: [303, 401, 403, 429],
		disclosure: 'No body; the cookie-bound session ends and the caller is sent to /sign-in.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup', 'cookie-delete'],
		evidence:
			'sign-in-sign-out.ts; management-boundaries.host.e2e.test.ts:297,313; sign-in-navigation.host.e2e.test.ts',
	},
	{
		method: 'POST',
		paths: [
			'/api/auth/passkey/verify-registration',
			'/api/auth/passkey/update-passkey',
			'/api/auth/passkey/remove',
			'/api/auth/passkey/confirm-options',
			'/api/auth/passkey/confirm',
		],
		exposure: ['member', 'owner'],
		requestParts: ['json'],
		documentedAnswers: [200, 400, 401, 403, 415, 429],
		disclosure: 'Only the caller’s factor information; no credential in refusal.',
		permittedRefusalEffects: [
			'none',
			'consume-passkey-challenge',
			// verify-registration consumes its challenge before it verifies, so a ceremony that
			// verifies and then fails policy (user verification) still ends the challenge.
			'consume-passkey-registration-challenge',
			'factor-intent',
			'expired-session-cleanup',
			'cookie-delete',
		],
		evidence:
			'people-passkey-confirmation.host.e2e.test.ts:44,58,82; second-factor-provider-plugin.ts',
	},
	{
		method: 'POST',
		paths: [
			'/api/auth/two-factor/enable',
			'/api/auth/two-factor/verify-totp',
			'/api/auth/two-factor/verify-backup-code',
			'/api/auth/two-factor/generate-backup-codes',
			'/api/auth/two-factor/remove-app',
		],
		exposure: ['member', 'owner'],
		requestParts: ['json', 'form'],
		documentedAnswers: [200, 302, 400, 401, 403, 415, 429],
		disclosure: 'Only the caller’s factor enrollment output; no credential in refusal.',
		permittedRefusalEffects: [
			'none',
			'factor-intent',
			'provider-verification-consumption',
			'expired-session-cleanup',
			'cookie-delete',
		],
		evidence:
			'people-factor-enrollment.host.e2e.test.ts:85,97,190,207,551; factor-enrollment-page.ts',
	},
	{
		method: 'POST',
		paths: ['/api/auth/link-social', '/api/auth/sign-in/social'],
		exposure: ['signed-out', 'member', 'owner'],
		requestParts: ['json'],
		// Better Auth answers an unknown provider with 404 PROVIDER_NOT_FOUND (sign-in.mjs:152,
		// account.mjs:160 in better-auth 1.7.11).
		documentedAnswers: [200, 302, 400, 401, 403, 404, 415, 429],
		documentedErrorBodies: {
			404: {
				values: { code: 'PROVIDER_NOT_FOUND' },
				exactKeys: ['code', 'message'],
				whenRequest: { jsonStringField: 'provider', notOneOf: supportedSocialProviders },
			},
		},
		disclosure: 'Only the caller’s authorized redirect; no credential in refusal.',
		permittedRefusalEffects: [
			'none',
			'login-link-intent',
			'provider-verification-consumption',
			'expired-session-cleanup',
			'cookie-delete',
		],
		evidence: 'sign-in-http-handler.ts; sign-in-request-handler.integration.test.ts',
	},
	...machineRouteGroups,
	{
		method: 'POST',
		paths: ['/api/auth/oauth2/token'],
		exposure: ['cli', 'machine'],
		requestParts: ['form', 'json'],
		documentedAnswers: [200, 400, 401, 403, 415, 429],
		disclosure:
			'Authorized CLI token success may contain its access token and eligible refresh token. The machine device and refresh grants require the bound machine client. Refusals contain no credential.',
		permittedRefusalEffects: ['none', 'oauth-code-consumption', 'pending-device-poll'],
		evidence:
			'sign-in-response-release.ts; machine-token-release.ts; machine-device-login.host.e2e.test.ts',
	},
	{
		method: 'POST',
		paths: ['/api/auth/oauth2/introspect'],
		exposure: ['cli'],
		requestParts: ['form'],
		documentedAnswers: [200, 400, 401, 403, 415, 429],
		disclosure: 'Only authorized token metadata; refusals contain no credential.',
		permittedRefusalEffects: ['none', 'expired-session-cleanup'],
		evidence: 'person-introspection.host.e2e.test.ts:28,47,68',
	},
];

// The before hooks record an intent only on these named operations. The custom
// passkey confirmation consumes its own challenge before verification.
const peopleChangeRoutes = new Set([
	'/api/auth/organization/invite-member',
	'/api/auth/organization/cancel-invitation',
	'/api/auth/organization/accept-invitation',
	'/api/auth/organization/remove-member',
]);
const factorIntentRoutes = new Set([
	'/api/auth/passkey/verify-registration',
	'/api/auth/passkey/update-passkey',
	'/api/auth/passkey/remove',
	'/api/auth/passkey/confirm',
	'/api/auth/two-factor/enable',
	'/api/auth/two-factor/verify-totp',
	'/api/auth/two-factor/verify-backup-code',
	'/api/auth/two-factor/generate-backup-codes',
	'/api/auth/two-factor/remove-app',
]);

const nativeServerOnlyMetadataPaths = new Set([
	'/api/auth/.well-known/oauth-authorization-server',
	'/api/auth/.well-known/openid-configuration',
]);
const admittedButUnservedMetadataPaths = new Set([
	'/api/auth/.well-known/oauth-authorization-server',
	'/api/auth/.well-known/openid-configuration',
	'/.well-known/openid-configuration',
]);

const reachableRoutes: readonly RouteClassification[] = reachableRouteGroups.flatMap(
	({ paths, ...classification }) =>
		paths.map((path) => {
			const effects = classification.permittedRefusalEffects.filter((effect) => {
				if (effect === 'factor-intent') return factorIntentRoutes.has(path);
				if (effect === 'consume-passkey-challenge') return path === '/api/auth/passkey/confirm';
				if (effect === 'consume-passkey-registration-challenge')
					return path === '/api/auth/passkey/verify-registration';
				if (effect === 'login-link-intent') return path === '/api/auth/link-social';
				return true;
			});
			return {
				...classification,
				path,
				providerServerOnly: nativeServerOnlyMetadataPaths.has(path),
				documentedAnswers: admittedButUnservedMetadataPaths.has(path)
					? [404, 429]
					: path === '/api/auth/passkey/confirm-options'
						? [...classification.documentedAnswers, 404]
						: classification.documentedAnswers,
				permittedRefusalEffects: [
					...effects,
					...(peopleChangeRoutes.has(path) ? ['people-change-intent' as const] : []),
					...(path.startsWith('/api/auth/callback/') ? ['callback-outcome' as const] : []),
					...(path === '/api/auth/organization/set-active'
						? ['clear-current-choice' as const]
						: []),
				],
			};
		}),
);

// HTTP identities are transcribed from installed provider declarations and checked
// against the live inventory. The outer refusal contract is independently covered
// by management-boundaries.host.e2e.test.ts. The callback template denotes the
// literal pattern; its allowed Google/GitHub concrete routes have separate rows.
const blockedProviderGroups: readonly {
	readonly method: string;
	readonly paths: readonly string[];
	readonly providerServerOnly: boolean;
}[] = [
	{
		method: 'GET',
		providerServerOnly: false,
		paths: [
			'/api/auth/callback/:id',
			'/api/auth/verify-email',
			'/api/auth/reset-password/:token',
			'/api/auth/list-sessions',
			'/api/auth/delete-user/callback',
			'/api/auth/account-info',
			'/api/auth/token',
			'/api/auth/oauth2/userinfo',
			'/api/auth/oauth2/end-session',
			'/api/auth/oauth2/get-client',
			'/api/auth/oauth2/public-client',
			'/api/auth/oauth2/get-clients',
			'/api/auth/oauth2/get-consent',
			'/api/auth/oauth2/get-consents',
			'/api/auth/passkey/generate-authenticate-options',
			'/api/auth/organization/get-organization',
			'/api/auth/organization/get-full-organization',
			'/api/auth/organization/list',
			'/api/auth/organization/get-invitation',
			'/api/auth/organization/list-invitations',
			'/api/auth/organization/get-active-member',
			'/api/auth/organization/list-user-invitations',
			'/api/auth/organization/list-members',
			'/api/auth/organization/get-active-member-role',
			'/api/auth/ok',
			'/api/auth/error',
		],
	},
	{
		method: 'POST',
		providerServerOnly: false,
		paths: [
			'/api/auth/callback/:id',
			'/api/auth/get-session',
			'/api/auth/sign-out',
			'/api/auth/sign-up/email',
			'/api/auth/sign-in/email',
			'/api/auth/reset-password',
			'/api/auth/verify-password',
			'/api/auth/send-verification-email',
			'/api/auth/change-email',
			'/api/auth/change-password',
			'/api/auth/update-session',
			'/api/auth/update-user',
			'/api/auth/delete-user',
			'/api/auth/request-password-reset',
			'/api/auth/revoke-session',
			'/api/auth/revoke-sessions',
			'/api/auth/revoke-other-sessions',
			'/api/auth/unlink-account',
			'/api/auth/refresh-token',
			'/api/auth/get-access-token',
			'/api/auth/oauth2/consent',
			'/api/auth/oauth2/continue',
			'/api/auth/device/token',
			'/api/auth/device/approve',
			'/api/auth/device/deny',
			'/api/auth/oauth2/userinfo',
			'/api/auth/oauth2/end-session',
			'/api/auth/oauth2/end-session/confirm',
			'/api/auth/oauth2/register',
			'/api/auth/oauth2/create-client',
			'/api/auth/oauth2/public-client-prelogin',
			'/api/auth/oauth2/update-client',
			'/api/auth/oauth2/client/rotate-secret',
			'/api/auth/oauth2/client/rotate-keys',
			'/api/auth/oauth2/delete-client',
			'/api/auth/oauth2/update-consent',
			'/api/auth/oauth2/delete-consent',
			'/api/auth/passkey/verify-authentication',
			'/api/auth/passkey/delete-passkey',
			'/api/auth/organization/update',
			'/api/auth/organization/delete',
			'/api/auth/organization/reject-invitation',
			'/api/auth/organization/check-slug',
			'/api/auth/organization/update-member-role',
			'/api/auth/organization/leave',
			'/api/auth/organization/has-permission',
			'/api/auth/two-factor/get-totp-uri',
			'/api/auth/two-factor/send-otp',
			'/api/auth/two-factor/verify-otp',
			'/api/auth/two-factor/disable',
		],
	},
	{
		method: 'GET',
		providerServerOnly: true,
		paths: ['/api/auth/admin/oauth2/resources', '/api/auth/admin/oauth2/resources/:identifier'],
	},
	{
		method: 'POST',
		providerServerOnly: true,
		paths: [
			'/api/auth/admin/oauth2/create-client',
			'/api/auth/admin/oauth2/resources',
			'/api/auth/admin/oauth2/resources/:identifier/clients/:client_id',
		],
	},
	{
		method: 'PATCH',
		providerServerOnly: true,
		paths: ['/api/auth/admin/oauth2/update-client', '/api/auth/admin/oauth2/resources/:identifier'],
	},
	{
		method: 'DELETE',
		providerServerOnly: true,
		paths: [
			'/api/auth/admin/oauth2/resources/:identifier',
			'/api/auth/admin/oauth2/resources/:identifier/clients/:client_id',
		],
	},
];

const blockedProviderRoutes: readonly RouteClassification[] = blockedProviderGroups.flatMap(
	({ method, paths, providerServerOnly }) =>
		paths.map((path) => ({
			method,
			path,
			providerServerOnly,
			exposure: [providerServerOnly ? 'server-only' : 'blocked'],
			requestParts: [],
			documentedAnswers: [404],
			disclosure: 'No provider output reaches the caller.',
			permittedRefusalEffects: ['none'],
			evidence: 'management-boundaries.host.e2e.test.ts; installed provider endpoint declarations',
		})),
);

export const routeClassification: readonly RouteClassification[] = [
	...reachableRoutes,
	...blockedProviderRoutes,
];

export function routeKey(route: RouteIdentity): string {
	return `${route.method} ${route.path}`;
}
