import { z } from 'zod';

import {
	isSignedInNavigationPath,
	switchboardSignOutPath,
} from '#sign-in-core/contracts/sign-in-navigation';
import {
	isMachineLoginRoute,
	machineDeviceRequestIsValid,
} from '#sign-in-core/machine-login/machine-device-requests';
import { projectMachineDeviceResponse } from '#sign-in-core/response-release/machine-device-response';
import {
	organizationRequestErrorResponse,
	organizationReadResponse,
} from '#sign-in-core/response-release/organization-request-errors';
import {
	releaseSignInResponse,
	type IssuedPersonSession,
	type SignInResponseReleasePorts,
} from '#sign-in-core/response-release/sign-in-response-release';

/** Provider sign-in, tokens and the audited redirect login-link flow are public. */
export function isPublicSignInRoute(
	pathname: string,
	method: string,
	machineLoginEnabled = false,
): boolean {
	if (machineLoginEnabled && isMachineLoginRoute(pathname, method)) return true;
	if (pathname === switchboardSignOutPath) return method === 'POST';
	if (isSignedInNavigationPath(pathname)) return method === 'GET';
	if (pathname === '/api/auth/link-social') return method === 'POST';
	// Cookie-bound reads for the sign-in pages' browser components (owner, 12 Nov).
	// The session token is stripped from get-session before it reaches scripts.
	if (pathname === '/api/auth/get-session' || pathname === '/api/auth/list-accounts')
		return method === 'GET';
	if (pathname.startsWith('/api/auth/organization/')) {
		if (
			[
				'/api/auth/organization/self-context',
				'/api/auth/organization/people-list',
				'/api/auth/organization/people',
			].includes(pathname)
		)
			return method === 'GET';
		if (pathname === '/api/auth/organization/person-membership') return method === 'POST';
		return (
			method === 'POST' &&
			[
				'/api/auth/organization/create',
				'/api/auth/organization/invite-member',
				'/api/auth/organization/cancel-invitation',
				'/api/auth/organization/accept-invitation',
				'/api/auth/organization/remove-member',
				'/api/auth/organization/set-active',
				'/api/auth/organization/retry-provisioning',
			].includes(pathname)
		);
	}
	if (pathname.startsWith('/api/auth/passkey/') || pathname.startsWith('/api/auth/two-factor/'))
		return (
			(method === 'GET' &&
				[
					'/api/auth/passkey/generate-register-options',
					'/api/auth/passkey/generate-authenticate-options',
					'/api/auth/passkey/list-user-passkeys',
				].includes(pathname)) ||
			(method === 'POST' &&
				[
					'/api/auth/two-factor/enable',
					'/api/auth/two-factor/verify-totp',
					'/api/auth/two-factor/verify-backup-code',
					'/api/auth/two-factor/generate-backup-codes',
					'/api/auth/two-factor/remove-app',
					'/api/auth/passkey/verify-registration',
					'/api/auth/passkey/verify-authentication',
					'/api/auth/passkey/update-passkey',
					'/api/auth/passkey/remove',
					'/api/auth/passkey/confirm-options',
					'/api/auth/passkey/confirm',
				].includes(pathname))
		);
	return [
		'/sign-in', // Starts the owner browser authorization journey.
		'/owner-ready', // Resumes native CLI authorization after provider sign-in.
		'/organization-admin', // B2's owner admin page; it holds no token or key.
		'/api/auth/organization-admin/create-workspace', // Cookie-only; the server signs central's request.
		'/api/auth/organization-admin/workspace-lookup', // Cookie-only; the server signs central's request.
		'/api/auth/organization-admin/change-records', // Cookie-only; the server signs central's request.
		'/api/auth/organization-admin/v1/create-workspace', // DPoP-only CLI relay; central verifies.
		'/api/auth/organization-admin/v1/workspace-lookup', // DPoP-only CLI relay; central verifies.
		'/api/auth/organization-admin/v1/change-records', // DPoP-only CLI relay; central verifies.
		'/api/auth/organization-admin/v1/approval-list', // DPoP-only CLI relay (C3); central verifies.
		'/api/auth/organization-admin/v1/approval-read', // DPoP-only CLI relay (C3); central verifies.
		'/api/auth/organization-admin/v1/approval-decide', // DPoP-only CLI relay (C3); central verifies.
		'/api/auth/organization-admin/v1/engine-health', // DPoP-only CLI relay (DEL-07); central verifies.
		'/api/auth/organization-admin/v1/engine-retired', // DPoP-only CLI relay (DEL-07); central verifies.
		'/api/auth/organization-admin/v1/engine-retry', // DPoP-only CLI relay (DEL-07); central verifies.
		'/api/auth/organization-admin/v1/engine-discard', // DPoP-only CLI relay (DEL-07); central verifies.
		'/api/auth/owner/bootstrap', // Audited cookie-only bootstrap uses the in-process provider API.
		'/api/auth/sign-in/social', // Starts configured Google/GitHub provider sign-in.
		'/api/auth/callback/google', // Receives the configured Google OAuth callback.
		'/api/auth/callback/github', // Receives the configured GitHub OAuth callback.
		'/api/auth/oauth2/authorize', // Issues the native owner CLI authorization code with S256.
		'/api/auth/oauth2/token', // Exchanges owner codes or authenticates registered agent clients.
		'/api/auth/oauth2/introspect', // Confirms current person/session status through the release fence.
		'/api/auth/jwks', // Publishes signing keys for audience-bound proof verification.
		'/api/auth/.well-known/oauth-authorization-server', // Publishes provider-base OAuth metadata.
		'/api/auth/.well-known/openid-configuration', // Publishes provider-base OIDC metadata.
		'/.well-known/oauth-authorization-server', // Publishes issuer-root OAuth metadata.
		'/.well-known/openid-configuration', // Publishes issuer-root OIDC metadata.
	].includes(pathname);
}

export async function handleSignInRequest(props: {
	readonly request: Request;
	readonly providerHandler: (request: Request) => Promise<Response>;
	readonly issuedSessions: readonly IssuedPersonSession[];
	readonly createdUserIds: readonly string[];
	readonly ports: SignInResponseReleasePorts;
	readonly machineLoginEnabled?: boolean;
	readonly releaseMachineToken?: (response: Response) => Promise<Response>;
}): Promise<Response> {
	const pathname = new URL(props.request.url).pathname;
	if (!isPublicSignInRoute(pathname, props.request.method, props.machineLoginEnabled))
		return Response.json({ error: 'not-found' }, { status: 404 });
	const machineDevice = isMachineLoginRoute(pathname, props.request.method);
	if (
		(machineDevice || props.releaseMachineToken !== undefined) &&
		!(await machineDeviceRequestIsValid(props.request, props.releaseMachineToken !== undefined))
	)
		return Response.json(
			{ error: 'invalid_request' },
			{ status: 400, headers: { 'cache-control': 'no-store' } },
		);
	const invalidOrganizationRequest = await organizationRequestErrorResponse(props.request);
	if (invalidOrganizationRequest !== null) return invalidOrganizationRequest;
	if (pathname === '/api/auth/organization/invite-member') {
		let resendRequested = false;
		try {
			const contentType = props.request.headers.get('content-type') ?? '';
			if (/^(application\/x-www-form-urlencoded|multipart\/form-data)(?:;|$)/iu.test(contentType)) {
				const body = await props.request.clone().formData();
				resendRequested = body.getAll('resend').some((value) => value === 'true');
			} else {
				const body: unknown = await props.request.clone().json();
				resendRequested =
					body !== null && typeof body === 'object' && 'resend' in body && body.resend === true;
			}
		} catch {
			return Response.json({ error: 'invalid-request' }, { status: 400 });
		}
		if (resendRequested)
			return Response.json({ error: 'invitation-resend-not-allowed' }, { status: 400 });
	}
	let tokenGrant: 'client_credentials' | 'person' | 'introspection' | 'none' = 'none';
	if (pathname === '/api/auth/oauth2/introspect') tokenGrant = 'introspection';
	if (pathname === '/api/auth/oauth2/token' && props.request.method === 'POST') {
		const body = new URLSearchParams(await props.request.clone().text());
		tokenGrant = body.get('grant_type') === 'client_credentials' ? 'client_credentials' : 'person';
	}
	const response = await props.providerHandler(props.request);
	if (props.releaseMachineToken !== undefined) return props.releaseMachineToken(response);
	if (machineDevice) return projectMachineDeviceResponse(pathname, response);
	if (pathname === '/api/auth/organization/person-membership' && response.status === 400) {
		const headers = new Headers(response.headers);
		headers.set('cache-control', 'no-store');
		headers.delete('content-length');
		return Response.json({ error: 'invalid-request' }, { status: 400, headers });
	}
	const released = await releaseSignInResponse({
		response,
		tokenGrant,
		issuedSessions: props.issuedSessions,
		createdUserIds: props.createdUserIds,
		ports: props.ports,
	});
	if (pathname === '/api/auth/organization/accept-invitation' && released.ok)
		return releaseInvitationAcceptance(released);
	return organizationReadResponse(props.request, released);
}

const acceptedInvitationSchema = z.object({
	invitation: z.object({
		id: z.uuidv7(),
		organizationId: z.uuidv7(),
		email: z.email(),
		role: z.string().nullable(),
		status: z.literal('accepted'),
		createdAt: z.iso.datetime(),
		expiresAt: z.iso.datetime(),
	}),
	member: z.object({
		id: z.uuidv7(),
		organizationId: z.uuidv7(),
		userId: z.uuidv7(),
		role: z.string(),
		createdAt: z.iso.datetime(),
	}),
});

async function releaseInvitationAcceptance(response: Response): Promise<Response> {
	const body = acceptedInvitationSchema.safeParse(await response.json().catch(() => null));
	if (!body.success)
		return Response.json(
			{ error: 'sign-in-unavailable' },
			{ status: 503, headers: { 'cache-control': 'no-store' } },
		);
	const headers = new Headers(response.headers);
	headers.delete('content-length');
	headers.set('cache-control', 'no-store');
	return Response.json(body.data, { status: response.status, headers });
}
