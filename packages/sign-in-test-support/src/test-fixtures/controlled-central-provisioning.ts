import {
	approvalPersonRoutePaths,
	authorizationRevisionPushSchema,
	centralProvisioningRequestSchema,
	centralStatementDigestRequestSchema,
	fleetAdminRoutePaths,
	type AuthorizationRevisionPush,
} from '@agent-collaboration/sign-in-core';
import { decodeJwt, decodeProtectedHeader } from 'jose';

import {
	adminRouteByPath,
	type ControlledCentralAdmin,
} from '#sign-in-test-support/test-fixtures/controlled-central-admin';
import {
	approvalRouteByPath,
	type ControlledCentralApprovals,
} from '#sign-in-test-support/test-fixtures/controlled-central-approvals';
import {
	engineRouteByPath,
	type ControlledCentralEngine,
} from '#sign-in-test-support/test-fixtures/controlled-central-engine';

/** The organization and person floors central admits a person request against. */
export interface CentralHeldFloors {
	readonly organization: {
		readonly revision: number;
		readonly state: 'active' | 'stopped' | 'deleted';
		readonly policyDigest: string;
	} | null;
	readonly person: {
		readonly revision: number;
		readonly state: 'active' | 'inactive';
		readonly subjectId: string;
	} | null;
}

export type ControlledProvisioningReply =
	| 'unavailable'
	| 'provisioned'
	| 'lost-reply'
	/** D7: receive the send and never answer until `releaseHeld`, as an unresponsive central. */
	| 'hold'
	| 'organization-mismatch'
	| 'stale'
	| 'invalid-statement';
type ControlledCentralRoute =
	| '/internal/organization-provisioning'
	| '/internal/organization-statement-digest'
	| '/internal/organization-authorization-revisions'
	| '/internal/device-login-decisions'
	| '/internal/machine-token-decisions'
	| '/organization-admin/v1/revoke-machine-enrollment'
	| (typeof fleetAdminRoutePaths)[keyof typeof fleetAdminRoutePaths]
	| (typeof approvalPersonRoutePaths)[keyof typeof approvalPersonRoutePaths];
/** acknowledge: apply and ACK; lost-reply: apply, then lose the reply; the rest refuse. */
export type ControlledPushReply = 'acknowledge' | 'lost-reply' | 'unavailable' | 'conflict';
export interface CentralPeerArrival {
	readonly method: 'POST' | 'other';
	readonly path: ControlledCentralRoute | 'other';
	readonly hasAuthorization: boolean;
}
/** The facts central reports for its verified stored stamp; never the statement bytes. */
export interface ControlledStoredStamp {
	readonly digest: string;
	readonly expiresAt: number;
	readonly signingKeyId: string;
}
export interface ControlledProvisioningSend {
	readonly organizationId: string;
	readonly organizationStatement: string;
}
/** Exact accepted protocol bodies, retained privately by the organization journey. No headers. */
export interface CentralPeerExchange {
	readonly path: ControlledCentralRoute;
	readonly requestBody: string;
	readonly response:
		| { readonly kind: 'answered'; readonly status: number; readonly body: string }
		| { readonly kind: 'lost-reply' };
}
export interface ControlledCentralProvisioning {
	readonly exchanges: readonly CentralPeerExchange[];
	readonly arrivals: readonly CentralPeerArrival[];
	/** Every parsed revision push, in arrival order, whatever the reply was. */
	readonly pushes: readonly AuthorizationRevisionPush[];
	readonly replyToPushesWith: (mode: ControlledPushReply) => void;
	/** Simulates a recipient that lost its floors (r3 section 5): the next person push gets 412. */
	readonly forgetFloors: () => void;
	/** Resolves once the peer has received at least this many pushes in total. */
	readonly waitForPushes: (count: number) => Promise<void>;
	readonly sends: readonly ControlledProvisioningSend[];
	readonly digestReads: readonly string[];
	readonly replyWith: (mode: ControlledProvisioningReply) => void;
	/** Resolves once this many provisioning sends have been held in total. */
	readonly waitForHeld: (count: number) => Promise<void>;
	/** Ends every held send with a 503, so no request is left open at teardown. */
	readonly releaseHeld: () => void;
	/**
	 * On by default, as central's Initialize behaves: a `provisioned` setup statement (no
	 * `replaces`) for an organization the peer holds nothing for becomes its stored stamp. Without
	 * it, a ready organization would look forgotten to WS7's recovery.
	 */
	readonly applySetupStatements: (enabled: boolean) => void;
	readonly holdStamp: (organizationId: string, stamp: ControlledStoredStamp | null) => void;
	/**
	 * WS7: off by default. When on, an organization the peer holds no stamp for gets a bare 503 on
	 * every admin call and revision push, as pinned central `e847a888` answers an unstamped store
	 * (`organization_unstamped_routes.rs:244-301`).
	 */
	readonly refuseUnstampedStores: (enabled: boolean) => void;
	/**
	 * R-retrysignal: the admin request after the next one is held unanswered until `releaseHeld`;
	 * an abort that reaches the peer while it is held is counted.
	 */
	readonly holdNextAdminRetry: () => void;
	readonly waitForHeldAdmin: () => Promise<void>;
	readonly heldAdminAborts: () => number;
	/** Resolves once an abort reaches the held admin request (Node: the client closed it). */
	readonly waitForHeldAdminAbort: () => Promise<void>;
	/** True once central holds both the organization floor and the person's floor. */
	readonly hasFloors: (organizationId: string, personId: string) => boolean;
	/** The floors central holds: per key, the retained push with the highest revision. */
	readonly readFloors: (organizationId: string, personId: string) => CentralHeldFloors;
	/** The admin routes' stand-in; until attached they answer 503, as an unconfigured central. */
	readonly attachAdmin: (admin: ControlledCentralAdmin) => void;
	/** C3's approval routes' stand-in; until attached they answer 503, as an unconfigured central. */
	readonly attachApprovals: (approvals: ControlledCentralApprovals) => void;
	/** The engine routes' stand-in; until attached they answer 503, as an unconfigured central. */
	readonly attachEngine: (engine: ControlledCentralEngine) => void;
	readonly fetch: (request: Request) => Promise<Response>;
}

const statusForRefusal = {
	'organization-mismatch': 403,
	stale: 409,
	'invalid-statement': 422,
} as const;

/** A producer-contract peer only. It proves consumer sends and parsing, never central's
 * stamp verification, CAS, record or isolation. */
export function createControlledCentralProvisioning(
	machineDecisions?: (request: Request) => Promise<Response>,
): ControlledCentralProvisioning {
	const sends: ControlledProvisioningSend[] = [];
	const exchanges: CentralPeerExchange[] = [];
	const digestReads: string[] = [];
	const arrivals: CentralPeerArrival[] = [];
	const stamps = new Map<string, ControlledStoredStamp>();
	let reply: ControlledProvisioningReply = 'unavailable';
	const pushes: AuthorizationRevisionPush[] = [];
	/**
	 * Central's retained floors: per organization or person key, the applied push with the highest
	 * revision. Applying, hasFloors, readFloors (approval admission) and forgetFloors all read
	 * and write this one map, so forgetting a floor forgets what admission reads.
	 */
	const floors = new Map<string, AuthorizationRevisionPush>();
	let pushReply: ControlledPushReply = 'acknowledge';
	const pushWaiters: { readonly count: number; readonly resolve: () => void }[] = [];
	let admin: ControlledCentralAdmin | null = null;
	let approvals: ControlledCentralApprovals | null = null;
	let engine: ControlledCentralEngine | null = null;
	let heldCount = 0;
	let applySetup = true;
	let refuseUnstamped = false;
	let adminArrivalsUntilHold: number | null = null;
	let heldAdminAbortCount = 0;
	const heldAdmin = Promise.withResolvers<void>();
	const heldAdminAborted = Promise.withResolvers<void>();
	const heldWaiters: { readonly count: number; readonly resolve: () => void }[] = [];
	const heldReleases: (() => void)[] = [];
	function floorKey(push: AuthorizationRevisionPush): string {
		return push.kind === 'organization'
			? `organization/${push.organizationId}`
			: `person/${push.organizationId}/${push.personId}`;
	}
	function applyFloor(push: AuthorizationRevisionPush): number {
		const held = floors.get(floorKey(push));
		if (held === undefined || push.revision >= held.revision) floors.set(floorKey(push), push);
		return Math.max(held?.revision ?? 0, push.revision);
	}
	function recordPush(push: AuthorizationRevisionPush): void {
		pushes.push(push);
		for (const waiter of pushWaiters.filter((entry) => pushes.length >= entry.count)) {
			pushWaiters.splice(pushWaiters.indexOf(waiter), 1);
			waiter.resolve();
		}
	}
	return {
		sends,
		exchanges,
		digestReads,
		arrivals,
		pushes,
		replyToPushesWith: (mode: ControlledPushReply): void => {
			pushReply = mode;
		},
		forgetFloors: (): void => {
			floors.clear();
		},
		waitForPushes: async (count: number): Promise<void> => {
			if (pushes.length >= count) return;
			const waiting = Promise.withResolvers<void>();
			pushWaiters.push({ count, resolve: waiting.resolve });
			return waiting.promise;
		},
		replyWith: (mode: ControlledProvisioningReply): void => {
			reply = mode;
		},
		waitForHeld: async (count: number): Promise<void> => {
			if (heldCount >= count) return;
			const waiting = Promise.withResolvers<void>();
			heldWaiters.push({ count, resolve: waiting.resolve });
			return waiting.promise;
		},
		applySetupStatements: (enabled: boolean): void => {
			applySetup = enabled;
		},
		releaseHeld: (): void => {
			for (const release of heldReleases.splice(0)) release();
		},
		refuseUnstampedStores: (enabled: boolean): void => {
			refuseUnstamped = enabled;
		},
		holdNextAdminRetry: (): void => {
			adminArrivalsUntilHold = 2;
		},
		waitForHeldAdmin: async (): Promise<void> => heldAdmin.promise,
		heldAdminAborts: (): number => heldAdminAbortCount,
		waitForHeldAdminAbort: async (): Promise<void> => heldAdminAborted.promise,
		holdStamp: (organizationId: string, stamp: ControlledStoredStamp | null): void => {
			if (stamp === null) stamps.delete(organizationId);
			else stamps.set(organizationId, stamp);
		},
		readFloors(organizationId: string, personId: string): CentralHeldFloors {
			const organizationFloor = floors.get(`organization/${organizationId}`);
			const personFloor = floors.get(`person/${organizationId}/${personId}`);
			const organization =
				organizationFloor?.kind === 'organization' ? organizationFloor : undefined;
			const person = personFloor?.kind === 'person' ? personFloor : undefined;
			return {
				organization:
					organization === undefined
						? null
						: {
								revision: organization.revision,
								state: organization.state,
								policyDigest: organization.permissionPolicyDigest,
							},
				person:
					person === undefined
						? null
						: { revision: person.revision, state: person.state, subjectId: person.subjectId },
			};
		},
		hasFloors: (organizationId: string, personId: string): boolean =>
			floors.has(`organization/${organizationId}`) &&
			floors.has(`person/${organizationId}/${personId}`),
		attachAdmin: (attached: ControlledCentralAdmin): void => {
			admin = attached;
		},
		attachApprovals: (attached: ControlledCentralApprovals): void => {
			approvals = attached;
		},
		attachEngine: (attached: ControlledCentralEngine): void => {
			engine = attached;
		},
		async fetch(request: Request): Promise<Response> {
			// Count before dispatch, body parsing or authorization rejection. Unknown paths
			// and methods are classified rather than retaining arbitrary request values.
			const pathname = new URL(request.url).pathname;
			const adminRoute = adminRouteByPath[pathname];
			const approvalRoute = approvalRouteByPath[pathname];
			const engineRoute = engineRouteByPath[pathname];
			const route =
				pathname === '/internal/organization-provisioning' ||
				pathname === '/internal/organization-statement-digest' ||
				pathname === '/internal/organization-authorization-revisions' ||
				pathname === '/internal/device-login-decisions' ||
				pathname === '/internal/machine-token-decisions' ||
				pathname === '/organization-admin/v1/revoke-machine-enrollment'
					? pathname
					: adminRoute !== undefined
						? fleetAdminRoutePaths[adminRoute]
						: approvalRoute !== undefined
							? approvalPersonRoutePaths[approvalRoute]
							: engineRoute !== undefined
								? fleetAdminRoutePaths[engineRoute]
								: 'other';
			arrivals.push({
				method: request.method === 'POST' ? 'POST' : 'other',
				path: route,
				hasAuthorization: request.headers.has('authorization'),
			});
			if (request.method !== 'POST' || route === 'other')
				return new Response(null, { status: 404 });
			if (
				route === '/internal/device-login-decisions' ||
				route === '/internal/machine-token-decisions' ||
				route === '/organization-admin/v1/revoke-machine-enrollment'
			)
				return machineDecisions === undefined
					? new Response(null, { status: 404 })
					: await machineDecisions(request);
			if (adminRoute !== undefined && adminArrivalsUntilHold !== null) {
				adminArrivalsUntilHold -= 1;
				if (adminArrivalsUntilHold === 0) {
					adminArrivalsUntilHold = null;
					request.signal.addEventListener(
						'abort',
						(): void => {
							heldAdminAbortCount += 1;
							heldAdminAborted.resolve();
						},
						{ once: true },
					);
					const released = Promise.withResolvers<void>();
					heldReleases.push(released.resolve);
					heldAdmin.resolve();
					await released.promise;
					return new Response(null, { status: 503 });
				}
			}
			if ((adminRoute !== undefined || engineRoute !== undefined) && refuseUnstamped) {
				const named: unknown = await request
					.clone()
					.json()
					.catch(() => null);
				const organizationId =
					named !== null && typeof named === 'object' && 'organizationId' in named
						? String(named.organizationId)
						: '';
				if (!stamps.has(organizationId)) return new Response(null, { status: 503 });
			}
			if (adminRoute !== undefined)
				return admin === null
					? new Response(null, { status: 503 })
					: admin.fetch(request, adminRoute);
			if (approvalRoute !== undefined)
				return approvals === null
					? new Response(null, { status: 503 })
					: approvals.fetch(request, approvalRoute);
			if (engineRoute !== undefined)
				return engine === null
					? new Response(null, { status: 503 })
					: engine.fetch(request, engineRoute);
			if (request.headers.has('authorization')) return new Response(null, { status: 400 });
			const acceptedRoute: ControlledCentralRoute = route;
			const requestBody = await request.text();
			let body: unknown;
			try {
				body = JSON.parse(requestBody);
			} catch {
				body = null;
			}
			async function recordResponse(response: Response): Promise<Response> {
				exchanges.push({
					path: acceptedRoute,
					requestBody,
					response: {
						kind: 'answered',
						status: response.status,
						body: await response.clone().text(),
					},
				});
				return response;
			}
			if (route === '/internal/organization-authorization-revisions') {
				const parsed = authorizationRevisionPushSchema.safeParse(body);
				if (!parsed.success) return new Response(null, { status: 400 });
				recordPush(parsed.data);
				if (pushReply === 'unavailable') return recordResponse(new Response(null, { status: 503 }));
				if (refuseUnstamped && !stamps.has(parsed.data.organizationId))
					return recordResponse(new Response(null, { status: 503 }));
				if (pushReply === 'conflict') return recordResponse(new Response(null, { status: 409 }));
				// Central refuses a person floor whose organization floor it does not hold.
				if (
					parsed.data.kind === 'person' &&
					!floors.has(`organization/${parsed.data.organizationId}`)
				)
					return recordResponse(new Response(null, { status: 412 }));
				const acknowledgedRevision = applyFloor(parsed.data);
				if (pushReply === 'lost-reply') {
					exchanges.push({ path: route, requestBody, response: { kind: 'lost-reply' } });
					throw new Error('Controlled ACK lost after the floor applied');
				}
				return recordResponse(Response.json({ acknowledgedRevision }));
			}
			if (route === '/internal/organization-statement-digest') {
				const parsed = centralStatementDigestRequestSchema.safeParse(body);
				if (!parsed.success) return new Response(null, { status: 400 });
				digestReads.push(parsed.data.organizationId);
				const stamp = stamps.get(parsed.data.organizationId);
				return recordResponse(
					stamp === undefined ? new Response(null, { status: 404 }) : Response.json(stamp),
				);
			}
			const parsed = centralProvisioningRequestSchema.safeParse(body);
			if (!parsed.success) return new Response(null, { status: 400 });
			sends.push(parsed.data);
			switch (reply) {
				case 'lost-reply':
					exchanges.push({ path: route, requestBody, response: { kind: 'lost-reply' } });
					throw new Error('Controlled reply lost after peer receipt');
				case 'hold': {
					const released = Promise.withResolvers<void>();
					heldReleases.push(released.resolve);
					heldCount += 1;
					for (const waiter of heldWaiters.filter((entry) => heldCount >= entry.count)) {
						heldWaiters.splice(heldWaiters.indexOf(waiter), 1);
						waiter.resolve();
					}
					await released.promise;
					return new Response(null, { status: 503 });
				}
				case 'provisioned':
					if (applySetup && !stamps.has(parsed.data.organizationId)) {
						const statement = parsed.data.organizationStatement;
						const claims = decodeJwt(statement);
						const header = decodeProtectedHeader(statement);
						if (claims['replaces'] === undefined && typeof claims.exp === 'number')
							stamps.set(parsed.data.organizationId, {
								digest: Array.from(
									new Uint8Array(
										await globalThis.crypto.subtle.digest(
											'SHA-256',
											new TextEncoder().encode(statement),
										),
									),
									(byte) => byte.toString(16).padStart(2, '0'),
								).join(''),
								expiresAt: claims.exp,
								signingKeyId: String(header.kid),
							});
					}
					return recordResponse(Response.json({ result: 'provisioned' }));
				case 'unavailable':
					return recordResponse(new Response(null, { status: 503 }));
				case 'organization-mismatch':
				case 'stale':
				case 'invalid-statement':
					return recordResponse(new Response(null, { status: statusForRefusal[reply] }));
				default:
					return assertNeverReply(reply);
			}
		},
	};
}

function assertNeverReply(reply: never): never {
	throw new Error(`Unhandled controlled reply: ${String(reply)}`);
}
