import type { BetterAuthPlugin } from '@better-auth/core';
import { createAuthEndpoint } from 'better-auth/api';
import { deleteSessionCookie } from 'better-auth/cookies';

import { isSameOriginSignInPost } from '#sign-in-core/better-auth/sign-in-cookie-origin';
import {
	signOutFailureMessage,
	switchboardSignOutPath,
} from '#sign-in-core/contracts/sign-in-navigation';
import type { PersonSessionRecords } from '#sign-in-core/storage/models/person-session-records';

const noStore = { 'cache-control': 'no-store' };
const signOutEndpointPath = switchboardSignOutPath.slice('/api/auth'.length);

function signOutFailure(): Response {
	return Response.json({ error: signOutFailureMessage }, { status: 503, headers: noStore });
}

/** Resolve the signed cookie before reading exactly that token's row. A normal
 * live-session read can conflate expiry, missing rows and store failures. */
export function createSignInSignOutPlugin(props: {
	readonly issuer: string;
	readonly sessions: Pick<PersonSessionRecords, 'sessionRowByToken'>;
}): BetterAuthPlugin {
	const switchboardSignOut = createAuthEndpoint(
		signOutEndpointPath,
		// The signed cookie is the only input. Skip the provider's JSON body gate
		// so both native forms and bodyless fetches reach the origin check.
		{ method: 'POST', requireHeaders: true, disableBody: true },
		async (context): Promise<Response> => {
			if (!isSameOriginSignInPost(context.method, context.headers, props.issuer))
				return Response.json({ error: 'not-allowed' }, { status: 403, headers: noStore });

			try {
				const token = await context.getSignedCookie(
					context.context.authCookies.sessionToken.name,
					context.context.secret,
				);
				if (typeof token !== 'string' || token.length === 0)
					return Response.json({ error: 'unauthorized' }, { status: 401, headers: noStore });

				const before = await props.sessions.sessionRowByToken(token);
				if (before.kind === 'store-unavailable') return signOutFailure();
				if (before.value.kind === 'present') {
					// The provider's composed session adapter deletes and advances the
					// retained authorization revisions in the same fenced batch.
					await context.context.internalAdapter.deleteSession(token);
					const after = await props.sessions.sessionRowByToken(token);
					if (after.kind === 'store-unavailable' || after.value.kind !== 'absent')
						return signOutFailure();
				}
				deleteSessionCookie(context);
				const headers = new Headers(context.responseHeaders ?? undefined);
				headers.set('cache-control', 'no-store');
				headers.set('location', '/sign-in');
				return new Response(null, { status: 303, headers });
			} catch {
				return signOutFailure();
			}
		},
	);
	return { id: 'switchboard-sign-out', endpoints: { switchboardSignOut } };
}
