import { decodeJwt } from 'jose';
import { z } from 'zod';

import type { ApprovalPersonAnswer } from '#sign-in-core/central-link/approval-person-client';
import type { FleetAdminAnswer } from '#sign-in-core/central-link/fleet-admin-client';
import type { SignInPlatform } from '#sign-in-core/contracts/sign-in-platform';
import type { ApprovalPersonOperationName } from '#sign-in-core/organizations/approval-person-operation';
import type { FleetAdminRequest } from '#sign-in-core/organizations/fleet-admin-operation';
import type { RunOrganizationFleetCall } from '#sign-in-core/organizations/organization-fleet-call';
import { organizationIdSchema } from '#sign-in-core/storage/models/sign-in-store';

/**
 * The CLI's relay to central's link-only admin routes. The CLI
 * signs `htu` = `centralPublicOrigin` + central's path, which names central's admin endpoint
 * rather than this hop; central checks it against its own configured origin.
 */
export const fleetAdminRelayRoutes = {
	'/api/auth/organization-admin/v1/create-workspace': 'CreateWorkspace',
	'/api/auth/organization-admin/v1/workspace-lookup': 'WorkspaceLookup',
	'/api/auth/organization-admin/v1/change-records': 'ReadChangeRecords',
	// DEL-07: central's engine administration (4593797b1). An empty 503 from central comes back as
	// the relay's classified `central-unavailable`.
	'/api/auth/organization-admin/v1/engine-health': 'EngineHealth',
	'/api/auth/organization-admin/v1/engine-retired': 'EngineListRetired',
	'/api/auth/organization-admin/v1/engine-retry': 'EngineRetry',
	'/api/auth/organization-admin/v1/engine-discard': 'EngineDiscard',
} as const satisfies Record<string, FleetAdminRequest['operation']>;
export type FleetAdminRelayRoute = keyof typeof fleetAdminRelayRoutes;

/** C3 (R5): a signed-in person's approval list, read and decide, on the same relay. */
export const approvalPersonRelayRoutes = {
	'/api/auth/organization-admin/v1/approval-list': 'ApprovalList',
	'/api/auth/organization-admin/v1/approval-read': 'ApprovalRead',
	'/api/auth/organization-admin/v1/approval-decide': 'ApprovalDecide',
} as const satisfies Record<string, ApprovalPersonOperationName>;
export type ApprovalPersonRelayRoute = keyof typeof approvalPersonRelayRoutes;

export type OrganizationAdminRelayRoute = FleetAdminRelayRoute | ApprovalPersonRelayRoute;

function isApprovalPersonRelayRoute(pathname: string): pathname is ApprovalPersonRelayRoute {
	return Object.hasOwn(approvalPersonRelayRoutes, pathname);
}

/**
 * Every DPoP relay route: the admin routes and C3's approval routes. Both tables are read with
 * `Object.hasOwn` directly, which F1's route scanner follows.
 */
export function isFleetAdminRelayRoute(pathname: string): pathname is OrganizationAdminRelayRoute {
	return (
		Object.hasOwn(fleetAdminRelayRoutes, pathname) ||
		Object.hasOwn(approvalPersonRelayRoutes, pathname)
	);
}

/** Central's closed bodies are small; anything larger never reaches the link. */
const maximumRelayBodyBytes = 16_384;
const noStore = { 'cache-control': 'no-store' } as const;

function centralUnavailableResponse(): Response {
	return Response.json({ error: 'central-unavailable' }, { status: 503, headers: noStore });
}
function unauthenticatedResponse(): Response {
	return new Response(null, { status: 401, headers: { ...noStore, 'www-authenticate': 'DPoP' } });
}

/** One relayed send: the credential, proof and body exactly as the CLI sent them. */
interface RelayedCredential {
	readonly authorization: string;
	readonly proof: string;
	readonly body: Uint8Array<ArrayBuffer>;
}

/** How one route family sends through the link and answers the CLI. */
interface RelayFamily<TAnswer> {
	readonly send: (
		credential: RelayedCredential,
		retry: { readonly signal: AbortSignal } | null,
	) => Promise<TAnswer>;
	readonly answeredUnavailable: (answer: TAnswer) => boolean;
	readonly atDeadline: TAnswer;
	readonly respond: (answer: TAnswer) => Response;
}

/**
 * DPoP only: a browser cookie or a Bearer token is refused before anything is sent. The
 * credential, proof and body bytes are forwarded unchanged, and central verifies all three.
 */
export async function relayFleetAdminRequest(props: {
	readonly request: Request;
	readonly route: OrganizationAdminRelayRoute;
	readonly platform: Pick<SignInPlatform, 'centralClient'>;
	/** B2 renew-on-use: the token's organization passes its guard before the relay (WS7: and is
	 * recovered if a freshly emptied central forgot it). */
	readonly runFleetCall: RunOrganizationFleetCall;
}): Promise<Response> {
	const client = props.platform.centralClient;
	if (isApprovalPersonRelayRoute(props.route)) {
		const operation = approvalPersonRelayRoutes[props.route];
		return relayThroughLink(props, {
			send: async (credential, retry) =>
				client.relayApprovalPersonRequest({
					operation,
					...credential,
					...(retry === null ? {} : { signal: retry.signal }),
				}),
			answeredUnavailable: (answer) => answer.kind === 'answered-unavailable',
			atDeadline: { kind: 'unknown', reason: 'timeout' },
			respond: approvalPersonRelayResponse,
		});
	}
	const operation = fleetAdminRelayRoutes[props.route];
	return relayThroughLink(props, {
		send: async (credential, retry) =>
			client.relayFleetAdminRequest({
				operation,
				...credential,
				...(retry === null ? {} : { signal: retry.signal }),
			}),
		answeredUnavailable: (answer) => answer.kind === 'answered-unavailable',
		atDeadline: { kind: 'unknown', reason: 'timeout' },
		respond: fleetAdminRelayResponse,
	});
}

async function relayThroughLink<TAnswer>(
	props: { readonly request: Request; readonly runFleetCall: RunOrganizationFleetCall },
	family: RelayFamily<TAnswer>,
): Promise<Response> {
	if (props.request.method !== 'POST' || props.request.headers.has('cookie'))
		return Response.json({ error: 'not-allowed' }, { status: 403, headers: noStore });
	const authorization = props.request.headers.get('authorization');
	const proof = props.request.headers.get('dpop');
	if (authorization === null || !/^DPoP [^\s]+$/u.test(authorization) || proof === null)
		return Response.json(
			{ error: 'dpop-required' },
			{ status: 401, headers: { ...noStore, 'www-authenticate': 'DPoP' } },
		);
	const body = new Uint8Array(await props.request.arrayBuffer());
	if (body.byteLength > maximumRelayBodyBytes)
		return Response.json({ error: 'too-large' }, { status: 413, headers: noStore });
	const credential: RelayedCredential = { authorization, proof, body };
	// D1: the organization comes from sign-in's own token, read only to pick the guard; central
	// still verifies everything. An unreadable token is relayed unguarded and central refuses it.
	const organizationId = relayOrganizationId(authorization);
	// R-retrysignal: only the retry carries the run's deadline to the link.
	const send = async (retry: { readonly signal: AbortSignal } | null = null): Promise<TAnswer> =>
		family.send(credential, retry);
	// Central refuses an unstamped store before it verifies the proof, so a retry may reuse it.
	const run =
		organizationId === null
			? ({ kind: 'sent', answer: await send() } as const)
			: await props.runFleetCall<TAnswer>({
					organizationId,
					send,
					answeredUnavailable: family.answeredUnavailable,
					atDeadline: family.atDeadline,
				});
	if (run.kind === 'held') return centralUnavailableResponse();
	return family.respond(run.answer);
}

function fleetAdminRelayResponse(answer: FleetAdminAnswer): Response {
	switch (answer.kind) {
		case 'answered':
			return Response.json(answer.result, { headers: noStore });
		case 'unauthenticated':
			return unauthenticatedResponse();
		case 'request-refused':
			return new Response(null, { status: 400, headers: noStore });
		case 'answered-unavailable':
		case 'unknown':
			return centralUnavailableResponse();
		default:
			return answer satisfies never;
	}
}

/**
 * Central's C3 reply or admin refusal goes back to the CLI as central's JSON at 200; its
 * empty-bodied statuses keep their meaning. The relay itself only ever sends POST, so central's
 * 405 means the link is not central's C3 route at all.
 */
function approvalPersonRelayResponse(answer: ApprovalPersonAnswer): Response {
	switch (answer.kind) {
		case 'replied':
			return Response.json(answer.reply, { headers: noStore });
		case 'refused':
			return Response.json({ result: 'refused', reason: answer.reason }, { headers: noStore });
		case 'unauthenticated':
			return unauthenticatedResponse();
		case 'request-refused':
			return new Response(null, { status: 400, headers: noStore });
		case 'method-refused':
		case 'answered-unavailable':
		case 'unknown':
			return centralUnavailableResponse();
		default:
			return answer satisfies never;
	}
}

const relayTokenOrganizationSchema = z.looseObject({ organization_id: organizationIdSchema });

function relayOrganizationId(authorization: string): z.infer<typeof organizationIdSchema> | null {
	try {
		const claims = relayTokenOrganizationSchema.safeParse(
			decodeJwt(authorization.slice('DPoP '.length)),
		);
		return claims.success ? claims.data.organization_id : null;
	} catch {
		return null;
	}
}
