import { expect, it } from 'vitest';

import {
	classifySignInRequest,
	requestLimitAddressKey,
	signInRequestPolicies,
} from '#sign-in-core/request-limits/request-limit-policy';

it.each([
	['/api/auth/sign-in/social', 'sign-in', 3, 10],
	['/api/auth/sign-up/email', 'sign-in', 3, 10],
	['/api/auth/callback/google', 'callback-passkey', 10, 60],
	['/api/auth/passkey/confirm', 'callback-passkey', 10, 60],
	['/api/auth/two-factor/verify-totp', 'second-factor-code', 5, 60],
	['/api/auth/two-factor/verify-backup-code', 'second-factor-code', 5, 60],
	['/api/auth/device/verify', 'device-code-entry', 5, 60],
	['/api/auth/device/approve', 'device-decision', 10, 60],
	['/api/auth/device/deny', 'device-decision', 10, 60],
	['/api/auth/device/code', 'device-code-request', 5, 60],
	['/api/auth/oauth2/token', 'oauth-token', 30, 60],
	['/sign-in', 'service-page', 100, 10],
	['/owner-ready', 'service-page', 100, 10],
	['/api/auth/owner/bootstrap', 'service-page', 100, 10],
	['/api/auth/organization/invite-member', 'other', 100, 10],
	['/api/auth/organization-admin/v1/approval-list', 'other', 100, 10],
	['/api/auth/organization-admin/v1/approval-read', 'other', 100, 10],
	['/api/auth/organization-admin/v1/approval-decide', 'other', 100, 10],
	['/api/auth/organization-admin/v1/engine-health', 'other', 100, 10],
	['/api/auth/organization-admin/v1/engine-retired', 'other', 100, 10],
	['/api/auth/organization-admin/v1/engine-retry', 'other', 100, 10],
	['/api/auth/organization-admin/v1/engine-discard', 'other', 100, 10],
	['/unoffered', 'other', 100, 10],
] as const)(
	'R52 classifies %s and assigns its independent native rule',
	(path, expectedClass, max, windowSeconds) => {
		const requestClass = classifySignInRequest(path);
		expect(requestClass).toBe(expectedClass);
		expect(signInRequestPolicies[requestClass].provider).toEqual({ max, windowSeconds });
	},
);

it('uses the host-normalized key and one fallback for an absent address', () => {
	expect(requestLimitAddressKey('192.0.2.9')).toBe('192.0.2.9');
	expect(requestLimitAddressKey('2001:0db8:0001:0002:0000:0000:0000:0000')).toBe(
		'2001:0db8:0001:0002:0000:0000:0000:0000',
	);
	expect(requestLimitAddressKey(null)).toBe('no-trusted-address');
	expect(requestLimitAddressKey('')).toBe('no-trusted-address');
});
