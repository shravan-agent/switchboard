/** Cookie-only writes accept a browser POST from the configured sign-in origin. */
export function isSameOriginSignInPost(method: string, headers: Headers, issuer: string): boolean {
	return (
		method === 'POST' &&
		!headers.has('authorization') &&
		headers.get('origin') === new URL(issuer).origin
	);
}
