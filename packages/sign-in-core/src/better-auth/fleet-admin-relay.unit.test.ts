import { describe, expect, it } from 'vitest';

import {
	approvalPersonRelayRoutes,
	isFleetAdminRelayRoute,
	relayFleetAdminRequest,
	type OrganizationAdminRelayRoute,
} from '#sign-in-core/better-auth/fleet-admin-relay';
import type { ApprovalPersonAnswer } from '#sign-in-core/central-link/approval-person-client';
import type { CentralLinkClient } from '#sign-in-core/central-link/central-link-client';
import type { FleetAdminAnswer } from '#sign-in-core/central-link/fleet-admin-client';
import type { RunOrganizationFleetCall } from '#sign-in-core/organizations/organization-fleet-call';
import { classifySignInRequest } from '#sign-in-core/request-limits/request-limit-policy';
import { isPublicSignInRoute } from '#sign-in-core/response-release/sign-in-request-handler';

const approvalPaths = Object.keys(approvalPersonRelayRoutes);
const issuer = 'https://sign-in.example.invalid';

interface RelayedCall {
	readonly operation: string;
	readonly authorization: string;
	readonly proof: string;
	readonly body: Uint8Array;
}

/** A link that records each relayed approval call and answers with `answer`. */
function approvalLink(answer: ApprovalPersonAnswer): {
	readonly calls: RelayedCall[];
	readonly client: CentralLinkClient;
} {
	const calls: RelayedCall[] = [];
	const unused = async (): Promise<never> => Promise.reject(new Error('not this family'));
	return {
		calls,
		client: {
			provisionOrganization: unused,
			readStatementDigest: unused,
			pushAuthorizationRevision: unused,
			sendFleetAdminRequest: unused,
			relayFleetAdminRequest: unused,
			sendApprovalPersonRequest: unused,
			relayApprovalPersonRequest: async (props) => {
				calls.push(props);
				return answer;
			},
		},
	};
}

/** No organization guard work: the relay's own send runs once. */
const runDirectly: RunOrganizationFleetCall = async (call) => ({
	kind: 'sent',
	answer: await call.send(),
});

async function relay(props: {
	readonly path: OrganizationAdminRelayRoute;
	readonly answer: ApprovalPersonAnswer;
	readonly init?: RequestInit;
}): Promise<{ readonly response: Response; readonly calls: RelayedCall[] }> {
	const link = approvalLink(props.answer);
	const response = await relayFleetAdminRequest({
		request: new Request(`${issuer}${props.path}`, {
			method: 'POST',
			headers: { authorization: 'DPoP not-a-jwt', dpop: 'proof' },
			body: '{"organization":"019a3dce-2000-7000-8000-000000000001","filter":"all"}',
			...props.init,
		}),
		route: props.path,
		platform: { centralClient: link.client },
		runFleetCall: runDirectly,
	});
	return { response, calls: link.calls };
}

describe('the approval routes on the DPoP relay', (): void => {
	it.each(approvalPaths)('%s is a relay route, released, and rate-classed other', (path): void => {
		expect(isFleetAdminRelayRoute(path)).toBe(true);
		expect(isPublicSignInRoute(path, 'POST')).toBe(true);
		expect(classifySignInRequest(path)).toBe('other');
	});

	it('forwards the credential, proof and body bytes unchanged to the matching operation', async (): Promise<void> => {
		// Arrange
		const body = ' {"organization":"x","requestId":"y"} ';
		// Act
		const { response, calls } = await relay({
			path: '/api/auth/organization-admin/v1/approval-read',
			answer: { kind: 'replied', reply: { kind: 'notVisible' } },
			init: { body },
		});
		// Assert
		expect(response.status).toBe(200);
		await expect(response.json()).resolves.toEqual({ kind: 'notVisible' });
		expect(calls).toEqual([
			{
				operation: 'ApprovalRead',
				authorization: 'DPoP not-a-jwt',
				proof: 'proof',
				body: new TextEncoder().encode(body),
			},
		]);
	});

	it.each([
		['without a DPoP proof', { headers: { authorization: 'DPoP token' } }, 401],
		['with a Bearer token', { headers: { authorization: 'Bearer token', dpop: 'proof' } }, 401],
		[
			'with a cookie',
			{ headers: { cookie: 'session=1', authorization: 'DPoP t', dpop: 'p' } },
			403,
		],
		['as a GET', { method: 'GET', body: null }, 403],
		['larger than 16 KiB', { body: 'x'.repeat(16_385) }, 413],
	] as const)(
		'refuses a request %s before anything reaches central',
		async (_name, init, status): Promise<void> => {
			const { response, calls } = await relay({
				path: '/api/auth/organization-admin/v1/approval-decide',
				answer: { kind: 'replied', reply: { kind: 'tooLate' } },
				init,
			});
			expect(response.status).toBe(status);
			expect(calls).toEqual([]);
		},
	);

	it.each([
		[{ kind: 'replied', reply: { kind: 'operationConflict' } }, 200, { kind: 'operationConflict' }],
		[
			{ kind: 'refused', reason: 'notPermitted' },
			200,
			{ result: 'refused', reason: 'notPermitted' },
		],
		[{ kind: 'unauthenticated' }, 401, null],
		[{ kind: 'request-refused' }, 400, null],
		[{ kind: 'method-refused' }, 503, { error: 'central-unavailable' }],
		[{ kind: 'answered-unavailable' }, 503, { error: 'central-unavailable' }],
		[{ kind: 'unknown', reason: 'malformed-reply' }, 503, { error: 'central-unavailable' }],
	] as const)('answers %j with %i', async (answer, status, body): Promise<void> => {
		const { response } = await relay({
			path: '/api/auth/organization-admin/v1/approval-decide',
			answer,
		});
		expect(response.status).toBe(status);
		expect(response.headers.get('cache-control')).toBe('no-store');
		if (body === null) expect(await response.text()).toBe('');
		else await expect(response.json()).resolves.toEqual(body);
	});
});

const enginePaths = [
	'/api/auth/organization-admin/v1/engine-health',
	'/api/auth/organization-admin/v1/engine-retired',
	'/api/auth/organization-admin/v1/engine-retry',
	'/api/auth/organization-admin/v1/engine-discard',
] as const;

/** A link that records each relayed admin call and answers with `answer`. */
function adminLink(answer: FleetAdminAnswer): {
	readonly calls: RelayedCall[];
	readonly client: CentralLinkClient;
} {
	const calls: RelayedCall[] = [];
	const unused = async (): Promise<never> => Promise.reject(new Error('not this family'));
	return {
		calls,
		client: {
			provisionOrganization: unused,
			readStatementDigest: unused,
			pushAuthorizationRevision: unused,
			sendFleetAdminRequest: unused,
			relayFleetAdminRequest: async (props) => {
				calls.push(props);
				return answer;
			},
			sendApprovalPersonRequest: unused,
			relayApprovalPersonRequest: unused,
		},
	};
}

async function relayEngine(props: {
	readonly path: (typeof enginePaths)[number];
	readonly answer: FleetAdminAnswer;
	readonly init?: RequestInit;
}): Promise<{ readonly response: Response; readonly calls: RelayedCall[] }> {
	const link = adminLink(props.answer);
	const response = await relayFleetAdminRequest({
		request: new Request(`${issuer}${props.path}`, {
			method: 'POST',
			headers: { authorization: 'DPoP not-a-jwt', dpop: 'proof' },
			body: '{"organizationId":"019a3dce-2000-7000-8000-000000000001"}',
			...props.init,
		}),
		route: props.path,
		platform: { centralClient: link.client },
		runFleetCall: runDirectly,
	});
	return { response, calls: link.calls };
}

describe('DEL-07: the engine routes on the DPoP relay', (): void => {
	it.each(enginePaths)('%s is a relay route, released, and rate-classed other', (path): void => {
		expect(isFleetAdminRelayRoute(path)).toBe(true);
		expect(isPublicSignInRoute(path, 'POST')).toBe(true);
		expect(classifySignInRequest(path)).toBe('other');
	});

	it.each([
		['/api/auth/organization-admin/v1/engine-health', 'EngineHealth'],
		['/api/auth/organization-admin/v1/engine-retired', 'EngineListRetired'],
		['/api/auth/organization-admin/v1/engine-retry', 'EngineRetry'],
		['/api/auth/organization-admin/v1/engine-discard', 'EngineDiscard'],
	] as const)(
		'%s forwards the credential, proof and body bytes unchanged as %s',
		async (path, operation): Promise<void> => {
			// Arrange
			const body = ' {"organizationId":"x","attemptId":"y"} ';
			// Act
			const { response, calls } = await relayEngine({
				path,
				answer: { kind: 'answered', result: { result: 'engineRetried' } },
				init: { body },
			});
			// Assert
			expect(response.status).toBe(200);
			await expect(response.json()).resolves.toEqual({ result: 'engineRetried' });
			expect(calls).toEqual([
				{
					operation,
					authorization: 'DPoP not-a-jwt',
					proof: 'proof',
					body: new TextEncoder().encode(body),
				},
			]);
		},
	);

	it.each([
		['without a DPoP proof', { headers: { authorization: 'DPoP token' } }, 401],
		['with a Bearer token', { headers: { authorization: 'Bearer token', dpop: 'proof' } }, 401],
		[
			'with a cookie',
			{ headers: { cookie: 'session=1', authorization: 'DPoP t', dpop: 'p' } },
			403,
		],
		['as a GET', { method: 'GET', body: null }, 403],
		['larger than 16 KiB', { body: 'x'.repeat(16_385) }, 413],
	] as const)(
		'refuses a request %s before anything reaches central',
		async (_name, init, status): Promise<void> => {
			for (const path of enginePaths) {
				const { response, calls } = await relayEngine({
					path,
					answer: { kind: 'answered', result: { result: 'engineDiscarded' } },
					init,
				});
				expect(response.status).toBe(status);
				expect(calls).toEqual([]);
			}
		},
	);

	it.each([
		[
			{ kind: 'answered', result: { result: 'refused', reason: 'secondFactorRequired' } },
			200,
			{ result: 'refused', reason: 'secondFactorRequired' },
		],
		[{ kind: 'unauthenticated' }, 401, null],
		[{ kind: 'request-refused' }, 400, null],
		// Central's empty 503 becomes the relay's classified answer, never a crash.
		[{ kind: 'answered-unavailable' }, 503, { error: 'central-unavailable' }],
		[{ kind: 'unknown', reason: 'malformed-reply' }, 503, { error: 'central-unavailable' }],
	] as const)('answers %j with %i', async (answer, status, body): Promise<void> => {
		const { response } = await relayEngine({
			path: '/api/auth/organization-admin/v1/engine-retry',
			answer,
		});
		expect(response.status).toBe(status);
		expect(response.headers.get('cache-control')).toBe('no-store');
		if (body === null) expect(await response.text()).toBe('');
		else await expect(response.json()).resolves.toEqual(body);
	});
});
