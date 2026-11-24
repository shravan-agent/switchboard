import * as hegel from '@hegeldev/hegel';
import { expect, it } from 'vitest';

import { requestFamilies, type RequestFamilyContext } from './index';
import { syntheticRequestFamilyContext } from './synthetic-context';

const context: RequestFamilyContext = {
	...syntheticRequestFamilyContext,
	passkeyAuthenticationResponse: {
		id: 'authentication-credential',
		response: { signature: 'signature' },
	},
};

it('generates the registered method and legal fetch transport for each family', () => {
	const identities = requestFamilies.map(({ route }) => `${route.method} ${route.path}`);
	expect(identities).toHaveLength(68);
	expect(new Set(identities).size).toBe(identities.length);
	for (const family of requestFamilies) {
		const encodings = new Set<string>();
		const labels = new Set<string>();
		const completeLabels = new Set<string>();
		// Each variant family once (as the live driver visits them), then random draws.
		for (const scheduled of [undefined, ...family.variantSteps(context)])
			hegel.test(
				(testCase) => {
					const generated = family.generate(testCase, context, scheduled);
					labels.add(generated.label.split(':')[0] ?? '');
					completeLabels.add(generated.label);
					const url = new URL(generated.pathname, context.issuer);
					expect(url.pathname).toBe(family.route.path);
					expect(generated.init.method).toBe(family.route.method);
					expect(generated.expectation).toBe('success-or-refusal');
					expect(family.callers).toEqual(['signed-out', 'member', 'owner']);
					if (family.route.method === 'GET') {
						expect(generated.init.body).toBeUndefined();
						if (family.route.path === '/api/auth/oauth2/authorize' && generated.label === 'valid') {
							expect(url.searchParams.get('client_id')).toBe(context.oauthClientId);
							expect(url.searchParams.get('code_challenge')).toBe(context.oauthCodeChallenge);
						}
						if (
							family.route.path.startsWith('/api/auth/callback/') &&
							generated.label === 'valid'
						) {
							expect(Object.fromEntries(url.searchParams)).toEqual(context.callbackQuery);
						}
					} else {
						const request = new Request(url, generated.init);
						const bodyText = generated.init.body;
						if (typeof bodyText !== 'string')
							throw new Error('Expected generated request body text');
						encodings.add(request.headers.get('content-type') ?? '');
						if (generated.label.startsWith('malformed:')) expect(generated.init.body).toBe('{');
						if (generated.label === 'json:valid') {
							const body: unknown = JSON.parse(bodyText);
							if (family.route.path === '/api/auth/passkey/verify-registration')
								expect(body).toEqual({
									name: 'Security key',
									response: context.passkeyRegistrationResponse,
								});
							if (family.route.path === '/api/auth/passkey/confirm')
								expect(body).toEqual({
									challengeId: context.challengeId,
									response: context.passkeyAuthenticationResponse,
								});
							if (family.route.path === '/api/auth/two-factor/verify-totp')
								expect(body).toEqual({ code: context.totpCode, trustDevice: false });
							if (family.route.path === '/api/auth/two-factor/verify-backup-code')
								expect(body).toEqual({ code: context.backupCode });
							if (family.route.path === '/api/auth/sign-in/social')
								expect(request.headers.get('x-captcha-response')).toBe(context.captchaToken);
						}
						if (
							family.route.path === '/api/auth/organization-admin/change-records' &&
							generated.label === 'json:near-valid:limit'
						) {
							expect(JSON.parse(bodyText)).toEqual({
								organizationId: context.organizationId,
								after: null,
								limit: -1,
							});
						}
						if (
							family.route.path === '/api/auth/organization-admin/change-records' &&
							generated.label === 'json:wrong-type:limit'
						) {
							expect(JSON.parse(bodyText)).toEqual({
								organizationId: context.organizationId,
								after: null,
								limit: null,
							});
						}
						if (family.route.path === '/api/auth/oauth2/token' && generated.label === 'valid') {
							const form = new URLSearchParams(bodyText);
							expect(Object.fromEntries(form)).toEqual({
								grant_type: 'authorization_code',
								client_id: context.oauthClientId,
								code: context.oauthCode,
								code_verifier: context.oauthCodeVerifier,
								redirect_uri: context.oauthRedirectUri,
								resource: context.oauthResource,
							});
						}
						if (
							family.route.path.startsWith('/api/auth/callback/') &&
							generated.label === 'form:valid'
						) {
							expect(Object.fromEntries(new URLSearchParams(bodyText))).toEqual(
								context.callbackQuery,
							);
						}
						if (
							family.route.path === '/api/auth/oauth2/authorize' &&
							generated.label === 'form:valid'
						) {
							const form = new URLSearchParams(bodyText);
							expect(form.get('client_id')).toBe(context.oauthClientId);
							expect(form.get('code_challenge')).toBe(context.oauthCodeChallenge);
						}
					}
				},
				{
					testCases: scheduled === undefined ? 100 : 1,
					derandomize: true,
					database: hegel.Database.disabled,
				},
			);
		if (family.route.method === 'POST') {
			const isCallback = family.route.path.startsWith('/api/auth/callback/');
			const isForm = family.route.path.startsWith('/api/auth/oauth2/') || isCallback;
			expect(encodings.has('text/plain')).toBe(true);
			expect(encodings.has(isForm ? 'application/x-www-form-urlencoded' : 'application/json')).toBe(
				true,
			);
			if (!isForm || isCallback) expect(labels.has('malformed')).toBe(true);
			if (isCallback) expect(encodings.has('application/json')).toBe(true);
		}
		if (family.route.method === 'GET') expect(labels.has('valid')).toBe(true);
		else if (
			family.route.path === '/api/auth/oauth2/authorize' ||
			family.route.path === '/api/auth/oauth2/revoke' ||
			family.route.path.startsWith('/api/auth/callback/')
		)
			expect(completeLabels.has('form:valid')).toBe(true);
		else if (family.route.path.startsWith('/api/auth/oauth2/'))
			expect(labels.has('valid')).toBe(true);
		else expect(completeLabels.has('json:valid')).toBe(true);
		if (family.route.path === '/api/auth/organization-admin/change-records') {
			expect(completeLabels.has('json:near-valid:limit')).toBe(true);
			expect(completeLabels.has('json:wrong-type:limit')).toBe(true);
		}
	}
});
