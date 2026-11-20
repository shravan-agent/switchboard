import { decodeJwt } from 'jose';
import { z } from 'zod';

import { isSameOriginSignInPost } from '#sign-in-core/better-auth/sign-in-cookie-origin';
import type { FleetAdminAnswer } from '#sign-in-core/central-link/fleet-admin-client';
import {
	createFleetAdminProofKey,
	fleetAdminProofKeyThumbprint,
	signFleetAdminProof,
	type FleetAdminProofKey,
} from '#sign-in-core/central-link/fleet-admin-proof';
import type { SignInConfiguration } from '#sign-in-core/contracts/deployment-configuration';
import { personFleetTokenClaimsSchema } from '#sign-in-core/contracts/person-fleet-token';
import { trustedSignInClientAddressHeader } from '#sign-in-core/contracts/sign-in-client-address';
import type { SignInPlatform } from '#sign-in-core/contracts/sign-in-platform';
import {
	base64UrlSha256,
	fleetAdminIntentDigest,
	fleetAdminRequestSchema,
	fleetAdminRoutePaths,
	type FleetAdminRequest,
} from '#sign-in-core/organizations/fleet-admin-operation';
import type { RunOrganizationFleetCall } from '#sign-in-core/organizations/organization-fleet-call';

/** The owner page's cookie-only forwarding routes, one per central admin route. */
export const fleetAdminForwardingRoutes = {
	'/api/auth/organization-admin/create-workspace': 'CreateWorkspace',
	'/api/auth/organization-admin/workspace-lookup': 'WorkspaceLookup',
	'/api/auth/organization-admin/change-records': 'ReadChangeRecords',
} as const satisfies Record<string, FleetAdminRequest['operation']>;
export type FleetAdminForwardingRoute = keyof typeof fleetAdminForwardingRoutes;

export function isFleetAdminForwardingRoute(
	pathname: string,
): pathname is FleetAdminForwardingRoute {
	return Object.hasOwn(fleetAdminForwardingRoutes, pathname);
}

/** Never served: the in-process authorization stops at the redirect and reads its code. */
export function adminPageRedirectUri(configuration: Pick<SignInConfiguration, 'issuer'>): string {
	return new URL('/organization-admin/callback', configuration.issuer).toString();
}

type SelfCall = (request: Request) => Promise<Response>;
type PersonFleetCredential =
	| { readonly kind: 'issued'; readonly accessToken: string }
	| { readonly kind: 'refused'; readonly status: number };

/**
 * For each admin action the server makes a key that lives
 * only in this call, obtains a person-fleet token bound to it through the full sign-in handler
 * (so every release fence runs), signs central's proof and forwards it over the private link.
 * The key and token are dropped when this returns; nothing is stored or returned.
 */
export async function forwardFleetAdminRequest(props: {
	readonly request: Request;
	readonly route: FleetAdminForwardingRoute;
	readonly configuration: SignInConfiguration;
	readonly platform: Pick<SignInPlatform, 'centralClient' | 'clock' | 'crypto' | 'ids'>;
	readonly hasLiveSession: () => Promise<boolean>;
	readonly signIn: SelfCall;
	/** B2 renew-on-use: the organization's guard runs before anything is forwarded (WS7: and
	 * recovers an organization a freshly emptied central forgot). */
	readonly runFleetCall: RunOrganizationFleetCall;
}): Promise<Response> {
	const noStore = { 'cache-control': 'no-store' };
	if (
		!isSameOriginSignInPost(props.request.method, props.request.headers, props.configuration.issuer)
	)
		return Response.json({ error: 'not-allowed' }, { status: 403, headers: noStore });
	const input: unknown = await props.request.json().catch(() => null);
	const parsed = fleetAdminRequestSchema.safeParse(
		input !== null && typeof input === 'object'
			? { ...input, operation: fleetAdminForwardingRoutes[props.route] }
			: null,
	);
	if (!parsed.success)
		return Response.json({ error: 'invalid-request' }, { status: 400, headers: noStore });
	if (!(await props.hasLiveSession()))
		return Response.json({ error: 'unauthorized' }, { status: 401, headers: noStore });
	const key = await createFleetAdminProofKey(props.platform.crypto);
	const credential = await obtainPersonFleetCredential({ ...props, key });
	if (credential.kind === 'refused')
		return Response.json(
			{ error: 'credential-refused', status: credential.status },
			{ status: 403, headers: noStore },
		);
	const operation = parsed.data;
	// The token names the session's organization and binds this request's key; a body naming
	// another organization, or a token bound elsewhere, is refused before anything is sent.
	const claims = personFleetTokenClaimsSchema.safeParse(decodeJwt(credential.accessToken));
	if (
		!claims.success ||
		claims.data.organization_id !== operation.organizationId ||
		claims.data.cnf.jkt !== (await fleetAdminProofKeyThumbprint(props.platform.crypto, key))
	)
		return Response.json({ error: 'organization-mismatch' }, { status: 403, headers: noStore });
	const proof = await signFleetAdminProof(props.platform.crypto, {
		key,
		htu: `${props.configuration.centralPublicOrigin}${fleetAdminRoutePaths[operation.operation]}`,
		requestId: props.platform.ids.nextId(),
		issuedAtSeconds: Math.floor(props.platform.clock.now() / 1000),
		bound: {
			accessToken: credential.accessToken,
			intent: await fleetAdminIntentDigest(props.platform.crypto, operation),
		},
	});
	// Central refuses an unstamped store before it verifies the proof, so a retry may reuse it.
	const run = await props.runFleetCall<FleetAdminAnswer>({
		organizationId: operation.organizationId,
		// R-retrysignal: only the retry carries the run's deadline to the link.
		send: async (retry) =>
			props.platform.centralClient.sendFleetAdminRequest({
				operation,
				accessToken: credential.accessToken,
				proof,
				...(retry === null ? {} : { signal: retry.signal }),
			}),
		answeredUnavailable: (sent) => sent.kind === 'answered-unavailable',
		atDeadline: { kind: 'unknown', reason: 'timeout' },
	});
	// Rule 4: an expired stamp renewal could not replace is "try again shortly", never sent.
	if (run.kind === 'held')
		return Response.json({ error: 'central-unavailable' }, { status: 503, headers: noStore });
	const answer = run.answer;
	switch (answer.kind) {
		case 'answered':
			return Response.json(answer.result, { headers: noStore });
		case 'unauthenticated':
			return Response.json(
				{ error: 'central-refused-credential' },
				{ status: 502, headers: noStore },
			);
		case 'request-refused':
			return Response.json({ error: 'central-refused-request' }, { status: 502, headers: noStore });
		case 'answered-unavailable':
		case 'unknown':
			return Response.json({ error: 'central-unavailable' }, { status: 503, headers: noStore });
		default:
			return answer satisfies never;
	}
}

/** Native authorization with the caller's own cookie, then a DPoP-bound token exchange. */
async function obtainPersonFleetCredential(props: {
	readonly request: Request;
	readonly configuration: SignInConfiguration;
	readonly platform: Pick<SignInPlatform, 'clock' | 'crypto' | 'ids'>;
	readonly signIn: SelfCall;
	readonly key: FleetAdminProofKey;
}): Promise<PersonFleetCredential> {
	const issuer = props.configuration.issuer;
	const redirectUri = adminPageRedirectUri(props.configuration);
	const verifierBytes = new Uint8Array(32);
	props.platform.crypto.getRandomValues(verifierBytes);
	const verifier = base64Url(verifierBytes);
	// Authorization is the person's browser step and carries their cookie; the exchange is the
	// PKCE client's own call and carries none. Both keep the host's trusted client address.
	const clientAddress = props.request.headers.get(trustedSignInClientAddressHeader);
	const addressed: Record<string, string> =
		clientAddress === null ? {} : { [trustedSignInClientAddressHeader]: clientAddress };
	const cookie = props.request.headers.get('cookie');
	const authorize = new URL('/api/auth/oauth2/authorize', issuer);
	authorize.search = new URLSearchParams({
		response_type: 'code',
		client_id: props.configuration.adminPageClientId,
		redirect_uri: redirectUri,
		scope: 'fleet:admin',
		state: props.platform.ids.nextId(),
		code_challenge: await base64UrlSha256(props.platform.crypto, verifier),
		code_challenge_method: 'S256',
		resource: props.configuration.centralAdminAudience,
	}).toString();
	const authorized = await props.signIn(
		new Request(authorize, {
			headers: {
				...addressed,
				...(cookie === null ? {} : { cookie }),
				'sec-fetch-mode': 'navigate',
				accept: 'text/html',
			},
			redirect: 'manual',
		}),
	);
	const location = authorized.headers.get('location');
	const returned = location === null ? null : new URL(location, issuer);
	const code =
		returned !== null && returned.origin + returned.pathname === redirectUri
			? returned.searchParams.get('code')
			: null;
	if (code === null) return { kind: 'refused', status: authorized.status };
	const tokenEndpoint = new URL('/api/auth/oauth2/token', issuer).toString();
	const exchanged = await props.signIn(
		new Request(tokenEndpoint, {
			method: 'POST',
			headers: {
				...addressed,
				'content-type': 'application/x-www-form-urlencoded',
				dpop: await signFleetAdminProof(props.platform.crypto, {
					key: props.key,
					htu: tokenEndpoint,
					requestId: props.platform.ids.nextId(),
					issuedAtSeconds: Math.floor(props.platform.clock.now() / 1000),
				}),
			},
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code,
				redirect_uri: redirectUri,
				client_id: props.configuration.adminPageClientId,
				code_verifier: verifier,
				resource: props.configuration.centralAdminAudience,
			}).toString(),
		}),
	);
	const body: unknown = await exchanged.json().catch(() => null);
	const token = z.object({ access_token: z.string().min(1) }).safeParse(body);
	return exchanged.ok && token.success
		? { kind: 'issued', accessToken: token.data.access_token }
		: { kind: 'refused', status: exchanged.status };
}

function base64Url(bytes: Uint8Array): string {
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}
