import { z } from 'zod';

export const signInRequestClassSchema = z.enum([
	'sign-in',
	'callback-passkey',
	'second-factor-code',
	'device-code-entry',
	'device-decision',
	'device-code-request',
	'oauth-token',
	'service-page',
	'other',
]);
export type SignInRequestClass = z.infer<typeof signInRequestClassSchema>;

const signInAttemptsLimit = { max: 10, windowSeconds: 60 } as const;
const authRequestsLimit = { max: 300, windowSeconds: 60 } as const;

interface RequestLimitPolicy {
	readonly binding: 'SIGN_IN_ATTEMPTS' | 'AUTH_REQUESTS';
	readonly outer: { readonly max: number; readonly windowSeconds: 60 };
	readonly provider: { readonly max: number; readonly windowSeconds: number };
}
/** R52 owns the inventory and values. Classifying a future device route here
 * grants no route: the public offering fence remains a separate authority. */
export const signInRequestPolicies = {
	'sign-in': {
		binding: 'SIGN_IN_ATTEMPTS',
		outer: signInAttemptsLimit,
		provider: { max: 3, windowSeconds: 10 },
	},
	'callback-passkey': {
		binding: 'SIGN_IN_ATTEMPTS',
		outer: signInAttemptsLimit,
		provider: { max: 10, windowSeconds: 60 },
	},
	'second-factor-code': {
		binding: 'SIGN_IN_ATTEMPTS',
		outer: signInAttemptsLimit,
		provider: { max: 5, windowSeconds: 60 },
	},
	'device-code-entry': {
		binding: 'SIGN_IN_ATTEMPTS',
		outer: signInAttemptsLimit,
		provider: { max: 5, windowSeconds: 60 },
	},
	'device-decision': {
		binding: 'SIGN_IN_ATTEMPTS',
		outer: signInAttemptsLimit,
		provider: { max: 10, windowSeconds: 60 },
	},
	'device-code-request': {
		binding: 'SIGN_IN_ATTEMPTS',
		outer: signInAttemptsLimit,
		provider: { max: 5, windowSeconds: 60 },
	},
	'oauth-token': {
		binding: 'AUTH_REQUESTS',
		outer: authRequestsLimit,
		provider: { max: 30, windowSeconds: 60 },
	},
	'service-page': {
		binding: 'AUTH_REQUESTS',
		outer: authRequestsLimit,
		provider: { max: 100, windowSeconds: 10 },
	},
	other: {
		binding: 'AUTH_REQUESTS',
		outer: authRequestsLimit,
		provider: { max: 100, windowSeconds: 10 },
	},
} as const satisfies Readonly<Record<SignInRequestClass, RequestLimitPolicy>>;

export function classifySignInRequest(pathname: string): SignInRequestClass {
	// A session-gated read of the caller's own passkey records: nothing in it can be guessed, so it
	// must not spend the sign-in attempts budget. Every passkey ceremony and write stays below.
	if (pathname === '/api/auth/passkey/list-user-passkeys') return 'other';
	if (pathname.startsWith('/api/auth/callback/') || pathname.startsWith('/api/auth/passkey/'))
		return 'callback-passkey';
	if (pathname.startsWith('/api/auth/sign-in/') || pathname.startsWith('/api/auth/sign-up/'))
		return 'sign-in';
	if (
		pathname === '/api/auth/two-factor/verify-totp' ||
		pathname === '/api/auth/two-factor/verify-backup-code'
	)
		return 'second-factor-code';
	if (
		pathname === '/device' ||
		pathname === '/api/auth/device' ||
		pathname === '/api/auth/device/verify'
	)
		return 'device-code-entry';
	if (
		pathname === '/api/auth/device/approve' ||
		pathname === '/api/auth/device/deny' ||
		pathname === '/api/auth/machine-login/approve' ||
		pathname === '/api/auth/machine-login/deny'
	)
		return 'device-decision';
	if (pathname === '/api/auth/device/code') return 'device-code-request';
	if (pathname === '/api/auth/oauth2/token') return 'oauth-token';
	if (
		['/sign-in', '/owner-ready', '/organization-admin', '/api/auth/owner/bootstrap'].includes(
			pathname,
		)
	)
		return 'service-page';
	return 'other';
}

const requestLimitAddressSchema = z.string().min(1).brand<'RequestLimitAddress'>();
export type RequestLimitAddress = z.infer<typeof requestLimitAddressSchema>;

/** Host ingress has already validated and normalized this trusted key. */
export function requestLimitAddressKey(value: string | null): RequestLimitAddress {
	return requestLimitAddressSchema.parse(value?.trim() || 'no-trusted-address');
}

export type RequestLimitResult =
	| { readonly kind: 'allowed' }
	| { readonly kind: 'limited'; readonly retryAfterSeconds: number }
	| { readonly kind: 'unavailable' };
export interface SignInRequestLimiter {
	readonly allow: (request: {
		readonly requestClass: SignInRequestClass;
		readonly address: RequestLimitAddress;
	}) => Promise<RequestLimitResult>;
}
