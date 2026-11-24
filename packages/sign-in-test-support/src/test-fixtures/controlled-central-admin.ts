import { createHash } from 'node:crypto';

import {
	fleetAdminRequestSchema,
	fleetAdminRoutePaths,
	isEngineAdminOperation,
	type EngineAdminOperationName,
	type FleetAdminRequest,
	type fleetAdminResultSchemas,
} from '@agent-collaboration/sign-in-core';
import {
	calculateJwkThumbprint,
	compactVerify,
	createLocalJWKSet,
	decodeProtectedHeader,
	importJWK,
	jwtVerify,
	type JSONWebKeySet,
} from 'jose';
import { z } from 'zod';

import type { CentralHeldFloors } from '#sign-in-test-support/test-fixtures/controlled-central-provisioning';

/**
 * The named stand-in for central's admin routes until B2e joins
 * the real link. It checks floor presence and the predicates it implements below, taken from
 * central's `request_verifier.rs` and `request_admission.rs` at codex-router 7fb2de88a; it
 * does not check central's floor revisions, policy digest, session or snapshot admission. It
 * earns no credit for central's ledger, organization isolation or Rust admission; only the
 * sign-in side's sends are proven here.
 */
export type AdminRouteName = Exclude<FleetAdminRequest['operation'], EngineAdminOperationName>;
/** The engine routes have their own stand-in (controlled-central-engine.ts). */
export const adminRouteByPath: Readonly<Record<string, AdminRouteName>> = Object.fromEntries(
	Object.entries(fleetAdminRoutePaths)
		.filter(([operation]) => !isEngineAdminOperation(operation))
		.map(([operation, path]) => [path, operation]),
) as Readonly<Record<string, AdminRouteName>>;

/** Central's `SECOND_FACTOR_WINDOW_SECONDS` (request_admission.rs:17). */
const secondFactorWindowSeconds = 900;
const routePermission: Readonly<Record<AdminRouteName, string>> = {
	CreateWorkspace: 'workspace:create',
	WorkspaceLookup: 'organization:view',
	ListWorkspaces: 'organization:view',
	ReadChangeRecords: 'organization:readAudit',
};

/** Why the stand-in answered 401: the step of central's verifier that refused. */
export type AdminVerificationFailure =
	| 'missing-headers'
	| 'not-dpop-scheme'
	| 'token'
	| 'proof-header'
	| 'proof-signature'
	| 'proof-claims'
	| 'proof-method'
	| 'proof-htu'
	| 'proof-ath'
	| 'proof-time'
	| 'proof-key-binding'
	| 'organization'
	| 'expiry-bounds'
	| 'expired'
	| 'operation-body'
	| 'intent';
type FixtureAdminReply = z.input<
	(typeof fleetAdminResultSchemas)[keyof typeof fleetAdminResultSchemas]
>;

export interface AdminArrival {
	readonly route: AdminRouteName;
	readonly outcome:
		| { readonly kind: 'refused-unauthenticated'; readonly failure: AdminVerificationFailure }
		| { readonly kind: 'bad-request' }
		| { readonly kind: 'scripted-raw' }
		| { readonly kind: 'answered'; readonly result: FixtureAdminReply };
	/** The verified binding, kept to prove each request used its own key and token. */
	readonly proofKeyThumbprint: string | null;
	readonly accessTokenHash: string | null;
	readonly proofJwkMembers: readonly string[];
	readonly organizationId: string | null;
	/** The verified token's person and permissions: whose credential the forwarder sent. */
	readonly personId: string | null;
	readonly permissions: readonly string[] | null;
	/** SHA-256 (hex) of the exact body bytes, taken before any parsing. */
	readonly bodySha256: string;
	/** The body as central's route parsed it, or null when it did not parse. */
	readonly request: FleetAdminRequest | null;
}
export interface AdminWorkspace {
	readonly workspaceId: string;
	readonly name: string;
	readonly description: string;
	readonly state: 'active';
}
export interface ControlledCentralAdmin {
	readonly arrivals: readonly AdminArrival[];
	/** Raw tokens and proofs exactly as received; only for the custody scan of rows and responses. */
	readonly receivedCredentials: readonly {
		readonly authorization: string;
		readonly proof: string;
	}[];
	readonly workspaces: readonly AdminWorkspace[];
	readonly changeRecords: readonly {
		readonly id: string;
		readonly requestId: string;
		readonly targetId: string;
	}[];
	readonly fetch: (request: Request, route: AdminRouteName) => Promise<Response>;
	/**
	 * The next verified and admitted request on `route` is answered by `answer` instead of being
	 * applied: for a reply real central cannot be made to give (a lookup at a create's own
	 * operation that finds another name). Verification, admission and arrivals are unchanged.
	 */
	readonly scriptNextAnswer: (
		route: AdminRouteName,
		answer: (request: FleetAdminRequest) => FixtureAdminReply,
	) => void;
	readonly scriptNextRawAnswer: (route: AdminRouteName, body: object) => void;
}

const proofClaimsSchema = z.strictObject({
	jti: z.uuidv7(),
	htm: z.string(),
	htu: z.string(),
	iat: z.number().int(),
	ath: z.string(),
	intent: z.string(),
});
const proofJwkSchema = z.strictObject({
	kty: z.literal('EC'),
	crv: z.literal('P-256'),
	x: z.string(),
	y: z.string(),
});
const tokenClaimsSchema = z.looseObject({
	token_profile: z.literal('person-fleet'),
	sub: z.string(),
	organization_id: z.string(),
	authorization_subject_id: z.string(),
	permissions: z.array(z.string()),
	second_factor_at: z.number().int().optional(),
	iat: z.number().int(),
	exp: z.number().int(),
	cnf: z.looseObject({ jkt: z.string() }),
	organization_revision: z.number().int(),
	person_revision: z.number().int(),
	permission_policy_digest: z.string(),
	session_expires_at_ms: z.number().int(),
	authorization_snapshot_at_ms: z.number().int(),
	authorization_snapshot_valid_until_ms: z.number().int(),
});

/**
 * Central's effective expiry (fleet-signin/src/person_proof/verifier.rs:286-302 at 1ede5c1b9):
 * the earliest of the JWT expiry, the authorization snapshot's deadline and the session's, after
 * the snapshot bounds hold (snapshot not in the future, a deadline after it within 300 s, the
 * session ending after it). Null when the bounds fail.
 */
function effectiveExpiryMs(
	claims: z.infer<typeof tokenClaimsSchema>,
	nowMs: number,
): number | null {
	const snapshot = claims.authorization_snapshot_at_ms;
	const snapshotDeadline = claims.authorization_snapshot_valid_until_ms;
	const sessionDeadline = claims.session_expires_at_ms;
	if (
		snapshot > nowMs ||
		snapshotDeadline <= snapshot ||
		snapshotDeadline - snapshot > 300_000 ||
		sessionDeadline <= snapshot
	)
		return null;
	return Math.min(claims.exp * 1000, snapshotDeadline, sessionDeadline);
}

/** Central's oracle, written apart from sign-in's JCS: sorted keys, then compact JSON. */
export function sortedJson(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(sortedJson).join(',')}]`;
	if (value !== null && typeof value === 'object')
		return `{${Object.keys(value)
			.toSorted()
			.map((key) => `${JSON.stringify(key)}:${sortedJson(Reflect.get(value, key))}`)
			.join(',')}}`;
	return JSON.stringify(value);
}
export function base64UrlSha256(text: string): string {
	return createHash('sha256').update(text).digest('base64url');
}
/** Central's `AdminOperation::intent`, restated from its published vectors. */
function independentIntent(request: FleetAdminRequest): string {
	const organization = request.organizationId;
	if (request.operation === 'ListWorkspaces')
		return base64UrlSha256(
			sortedJson({
				v: 1,
				operation: 'ListWorkspaces',
				organization,
				target: organization,
				operationId: null,
				params: { after: request.after ?? null, limit: request.limit },
			}),
		);
	const intent =
		request.operation === 'CreateWorkspace'
			? {
					v: 1,
					operation: 'CreateWorkspace',
					organization,
					target: organization,
					operationId: request.operationId,
					params: { name: request.name, description: request.description },
				}
			: request.operation === 'WorkspaceLookup'
				? {
						v: 1,
						operation: 'WorkspaceLookup',
						organization,
						target: request.workspaceId,
						operationId: null,
						params: {},
					}
				: request.operation === 'ReadChangeRecords'
					? {
							v: 1,
							operation: 'ReadChangeRecords',
							organization,
							target: organization,
							operationId: null,
							params: { after: request.after, limit: request.limit },
						}
					: // Engine routes are controlled-central-engine.ts's; no admin intent matches them.
						{ notAnAdminRoute: request.operation };
	return base64UrlSha256(sortedJson(intent));
}
export function uuid7Milliseconds(id: string): number {
	return Number.parseInt(id.replaceAll('-', '').slice(0, 12), 16);
}
export function inRequestWindow(atMilliseconds: number, nowMilliseconds: number): boolean {
	return atMilliseconds > nowMilliseconds - 65_000 && atMilliseconds <= nowMilliseconds + 5_000;
}

/** What central's verifier needs to know about itself: the issuer it trusts and its origin. */
export interface CentralPersonVerifierSettings {
	readonly issuer: string;
	readonly audience: string;
	/** Central's CENTRAL_PUBLIC_ORIGIN; every proof's `htu` must start with exactly this. */
	readonly publicOrigin: string;
	readonly readSigningKeys: () => Promise<JSONWebKeySet>;
	readonly now: () => number;
}
type CentralPersonRequestFacts = Partial<
	Pick<AdminArrival, 'proofKeyThumbprint' | 'accessTokenHash' | 'proofJwkMembers'>
>;
export type PersonTokenClaims = z.infer<typeof tokenClaimsSchema>;
export type CentralPersonVerification =
	| {
			readonly kind: 'refused';
			readonly failure: AdminVerificationFailure;
			readonly facts: CentralPersonRequestFacts;
	  }
	| {
			readonly kind: 'verified';
			readonly claims: PersonTokenClaims;
			readonly requestId: string;
			readonly intent: string;
			/** Central's effective expiry (verifier.rs:299), read again at applying time. */
			readonly effectiveExpiryMs: number;
			/** The proof's own time (iat), which central's request window checks again. */
			readonly proofTimeMs: number;
			readonly facts: CentralPersonRequestFacts;
	  };

/**
 * Central's verifier steps for one person request on any organization-admin route, admin or
 * C3: the token, the DPoP proof (header, signature, method, `htu`, `ath`, time, key binding),
 * the organization and the signed intent, given the route's path, body organization and the
 * intent digest computed independently of sign-in's builder.
 */
export async function verifyCentralPersonRequest(
	settings: CentralPersonVerifierSettings,
	request: Request,
	target: {
		readonly path: string;
		readonly organization: string;
		/**
		 * The signed intent's digest, or how to compute it from the full body once the proof checks
		 * pass: central decodes the operation after verifying (approval_person_admission.rs:379-386),
		 * and an undecodable body is refused 401 (OperationBody, organization_signin_port.rs:196).
		 */
		readonly intent: string | (() => string | null);
	},
): Promise<CentralPersonVerification> {
	const authorization = request.headers.get('authorization');
	const proof = request.headers.get('dpop');
	if (authorization === null || proof === null)
		return { kind: 'refused', failure: 'missing-headers', facts: {} };
	const token = /^DPoP ([^\s]+)$/u.exec(authorization)?.[1];
	if (token === undefined) return { kind: 'refused', failure: 'not-dpop-scheme', facts: {} };
	const facts: {
		accessTokenHash: string;
		proofJwkMembers: readonly string[];
		proofKeyThumbprint?: string;
	} = {
		accessTokenHash: base64UrlSha256(token),
		proofJwkMembers: [],
	};
	let claims: z.infer<typeof tokenClaimsSchema>;
	try {
		const verified = await jwtVerify(token, createLocalJWKSet(await settings.readSigningKeys()), {
			issuer: settings.issuer,
			audience: settings.audience,
			typ: 'at+jwt',
			currentDate: new Date(settings.now()),
		});
		claims = tokenClaimsSchema.parse(verified.payload);
	} catch {
		return { kind: 'refused', failure: 'token', facts };
	}
	const effectiveExpiry = effectiveExpiryMs(claims, settings.now());
	if (effectiveExpiry === null) return { kind: 'refused', failure: 'expiry-bounds', facts };
	if (settings.now() >= effectiveExpiry) return { kind: 'refused', failure: 'expired', facts };
	// A malformed proof is a refusal, never a throw (verifier.rs:153-158, UnsupportedHeader: 401).
	let header: ReturnType<typeof decodeProtectedHeader>;
	try {
		header = decodeProtectedHeader(proof);
	} catch {
		return { kind: 'refused', failure: 'proof-header', facts };
	}
	const jwk = z.looseObject({}).safeParse(header.jwk);
	facts.proofJwkMembers = jwk.success ? Object.keys(jwk.data).toSorted() : [];
	const exactHeader = z
		.strictObject({ typ: z.literal('dpop+jwt'), alg: z.literal('ES256'), jwk: proofJwkSchema })
		.safeParse(header);
	if (!exactHeader.success) return { kind: 'refused', failure: 'proof-header', facts };
	let proofClaims: z.infer<typeof proofClaimsSchema>;
	try {
		const verified = await compactVerify(proof, await importJWK(exactHeader.data.jwk, 'ES256'));
		const parsed = proofClaimsSchema.safeParse(
			JSON.parse(new TextDecoder().decode(verified.payload)),
		);
		if (!parsed.success) return { kind: 'refused', failure: 'proof-claims', facts };
		proofClaims = parsed.data;
	} catch {
		return { kind: 'refused', failure: 'proof-signature', facts };
	}
	facts.proofKeyThumbprint = await calculateJwkThumbprint(exactHeader.data.jwk, 'sha256');
	if (proofClaims.htm !== 'POST') return { kind: 'refused', failure: 'proof-method', facts };
	if (proofClaims.htu !== `${settings.publicOrigin}${target.path}`)
		return { kind: 'refused', failure: 'proof-htu', facts };
	if (proofClaims.ath !== base64UrlSha256(token))
		return { kind: 'refused', failure: 'proof-ath', facts };
	if (
		!inRequestWindow(proofClaims.iat * 1000, settings.now()) ||
		!inRequestWindow(uuid7Milliseconds(proofClaims.jti), settings.now())
	)
		return { kind: 'refused', failure: 'proof-time', facts };
	if (claims.cnf.jkt !== facts.proofKeyThumbprint)
		return { kind: 'refused', failure: 'proof-key-binding', facts };
	// Central verifies the token and proof, then decodes the operation, then binds the intent and
	// the organization, in that order (approval_person_admission.rs:379-386; verifier.rs:64-76).
	const intent = typeof target.intent === 'string' ? target.intent : target.intent();
	if (intent === null) return { kind: 'refused', failure: 'operation-body', facts };
	if (proofClaims.intent !== intent) return { kind: 'refused', failure: 'intent', facts };
	if (claims.organization_id !== target.organization)
		return { kind: 'refused', failure: 'organization', facts };
	return {
		kind: 'verified',
		claims,
		requestId: proofClaims.jti,
		intent,
		effectiveExpiryMs: effectiveExpiry,
		proofTimeMs: proofClaims.iat * 1000,
		facts,
	};
}

/**
 * Central's applying admission shared by every person route, at one applying sample `now`
 * (fleet-signin/src/person_proof/admission.rs at 1ede5c1b9 and 4593797b1; the order is
 * collaboration-central-core/src/person_admission_plans.rs:25-61 at 4593797b1): the effective
 * expiry and the request window (admission.rs:189-202), the organization floor (:204-240), then
 * the person floor (:156-173). Null when all pass; each route checks its permission after this.
 * Central's reject-through watermark is not modelled by the provisioning peer.
 */
export function centralApplyingFloorRefusal(props: {
	readonly now: number;
	readonly floors: CentralHeldFloors;
	readonly verified: Extract<CentralPersonVerification, { readonly kind: 'verified' }>;
}):
	| 'expired'
	| 'requestTime'
	| 'authorizationSyncRequired'
	| 'notPermitted'
	| 'refreshRequired'
	| null {
	const { now, floors, verified } = props;
	const { claims } = verified;
	if (now >= verified.effectiveExpiryMs) return 'expired';
	if (
		!inRequestWindow(uuid7Milliseconds(verified.requestId), now) ||
		!inRequestWindow(verified.proofTimeMs, now)
	)
		return 'requestTime';
	const organization = floors.organization;
	if (organization === null) return 'authorizationSyncRequired';
	if (organization.state === 'deleted') return 'notPermitted';
	if (claims.organization_revision > organization.revision) return 'authorizationSyncRequired';
	if (organization.state === 'stopped') return 'notPermitted';
	if (claims.organization_revision < organization.revision) return 'refreshRequired';
	if (claims.permission_policy_digest !== organization.policyDigest) return 'refreshRequired';
	const person = floors.person;
	if (person === null) return 'authorizationSyncRequired';
	if (person.subjectId !== claims.authorization_subject_id) return 'notPermitted';
	if (claims.person_revision > person.revision) return 'authorizationSyncRequired';
	if (person.state === 'inactive') return 'notPermitted';
	if (claims.person_revision < person.revision) return 'refreshRequired';
	return null;
}

export function createControlledCentralAdmin(props: {
	readonly issuer: string;
	readonly audience: string;
	/** Central's CENTRAL_PUBLIC_ORIGIN; every proof's `htu` must start with exactly this. */
	readonly publicOrigin: string;
	readonly readSigningKeys: () => Promise<JSONWebKeySet>;
	readonly now: () => number;
	readonly nextId: () => string;
	/** The provisioning peer's floors: central refuses a person whose floors it lacks. */
	readonly hasFloors: (organizationId: string, personId: string) => boolean;
}): ControlledCentralAdmin {
	const arrivals: AdminArrival[] = [];
	const receivedCredentials: { readonly authorization: string; readonly proof: string }[] = [];
	const workspaces: AdminWorkspace[] = [];
	const usedRequestIds = new Set<string>();
	const ledger = new Map<string, { readonly intent: string; readonly result: FixtureAdminReply }>();
	const scripted = new Map<
		AdminRouteName,
		(
			| {
					readonly kind: 'typed';
					readonly answer: (request: FleetAdminRequest) => FixtureAdminReply;
			  }
			| { readonly kind: 'raw'; readonly body: object }
		)[]
	>();
	const records: {
		readonly id: string;
		readonly requestId: string;
		readonly kind: 'workspaceCreated';
		readonly origin: { kind: 'person'; personId: string; permissionChecked: string };
		readonly targetId: string;
		readonly createdAtMillis: number;
	}[] = [];

	async function verify(
		request: Request,
		route: AdminRouteName,
		body: FleetAdminRequest,
	): Promise<CentralPersonVerification> {
		return verifyCentralPersonRequest(props, request, {
			path: fleetAdminRoutePaths[route],
			organization: body.organizationId,
			intent: independentIntent(body),
		});
	}

	function admit(
		route: AdminRouteName,
		claims: z.infer<typeof tokenClaimsSchema>,
		requestId: string,
	): FixtureAdminReply | null {
		if (props.now() >= claims.exp * 1000) return { result: 'refused', reason: 'expired' };
		if (!props.hasFloors(claims.organization_id, claims.sub))
			return { result: 'refused', reason: 'authorizationSyncRequired' };
		if (!claims.permissions.includes(routePermission[route]))
			return { result: 'refused', reason: 'notPermitted' };
		if (route === 'CreateWorkspace') {
			const age =
				claims.second_factor_at === undefined ? null : props.now() - claims.second_factor_at * 1000;
			if (age === null || age < 0 || age > secondFactorWindowSeconds * 1000)
				return { result: 'refused', reason: 'secondFactorRequired' };
		}
		if (usedRequestIds.has(requestId)) return { result: 'refused', reason: 'requestReused' };
		usedRequestIds.add(requestId);
		return null;
	}

	function apply(
		body: FleetAdminRequest,
		claims: z.infer<typeof tokenClaimsSchema>,
		intent: string,
	): FixtureAdminReply {
		switch (body.operation) {
			case 'CreateWorkspace': {
				const prior = ledger.get(body.operationId);
				if (prior !== undefined)
					return prior.intent === intent ? prior.result : { result: 'refused', reason: 'conflict' };
				// Central #275: names are unique per organization, compared trimmed and without case.
				const nameKey = (name: string): string => name.trim().toLowerCase();
				if (workspaces.some((existing) => nameKey(existing.name) === nameKey(body.name)))
					return { result: 'refused', reason: 'nameInUse' };
				const workspace: AdminWorkspace = {
					// Central #275: the workspace ID is the create's operation ID.
					workspaceId: body.operationId,
					name: body.name,
					description: body.description,
					state: 'active',
				};
				workspaces.push(workspace);
				records.push({
					id: props.nextId(),
					requestId: body.operationId,
					kind: 'workspaceCreated',
					origin: { kind: 'person', personId: claims.sub, permissionChecked: 'workspace:create' },
					targetId: workspace.workspaceId,
					createdAtMillis: props.now(),
				});
				const result: FixtureAdminReply = { result: 'applied', workspace };
				ledger.set(body.operationId, { intent, result });
				return result;
			}
			case 'WorkspaceLookup':
				return {
					result: 'found',
					workspace:
						workspaces.find((workspace) => workspace.workspaceId === body.workspaceId) ?? null,
				};
			case 'ListWorkspaces': {
				const { after = null, limit = 100 } = body;
				const remaining = workspaces
					.filter((workspace) => after === null || workspace.workspaceId > after)
					.toSorted((left, right) => left.workspaceId.localeCompare(right.workspaceId));
				const page = remaining.slice(0, limit);
				return {
					result: 'workspaces',
					workspaces: page,
					next: remaining.length > limit ? (page.at(-1)?.workspaceId ?? null) : null,
				};
			}
			case 'ReadChangeRecords': {
				const start =
					body.after === null ? 0 : records.findIndex((record) => record.id === body.after) + 1;
				return { result: 'records', records: records.slice(start, start + body.limit) };
			}
			case 'EngineHealth':
			case 'EngineListRetired':
			case 'EngineRetry':
			case 'EngineDiscard':
				throw new Error('The engine routes have their own stand-in (controlled-central-engine.ts)');
			default:
				throw new Error('Unknown admin route');
		}
	}

	return {
		arrivals,
		receivedCredentials,
		workspaces,
		changeRecords: records,
		scriptNextAnswer(route, answer): void {
			scripted.set(route, [...(scripted.get(route) ?? []), { kind: 'typed', answer }]);
		},
		scriptNextRawAnswer(route, body): void {
			scripted.set(route, [...(scripted.get(route) ?? []), { kind: 'raw', body }]);
		},
		async fetch(request, route): Promise<Response> {
			const authorization = request.headers.get('authorization');
			const proof = request.headers.get('dpop');
			if (authorization !== null && proof !== null)
				receivedCredentials.push({ authorization, proof });
			const bytes = new Uint8Array(await request.arrayBuffer());
			const bodySha256 = createHash('sha256').update(bytes).digest('hex');
			let decoded: unknown = null;
			try {
				decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
			} catch {
				decoded = null;
			}
			const parsed = fleetAdminRequestSchema.safeParse({
				...z.looseObject({}).catch({}).parse(decoded),
				operation: route,
			});
			if (!parsed.success) {
				arrivals.push({
					route,
					outcome: { kind: 'bad-request' },
					proofKeyThumbprint: null,
					accessTokenHash: null,
					proofJwkMembers: [],
					organizationId: null,
					personId: null,
					permissions: null,
					bodySha256,
					request: null,
				});
				return new Response(null, { status: route === 'ListWorkspaces' ? 401 : 400 });
			}
			const verified = await verify(request, route, parsed.data);
			const facts = {
				proofKeyThumbprint: verified.facts.proofKeyThumbprint ?? null,
				accessTokenHash: verified.facts.accessTokenHash ?? null,
				proofJwkMembers: verified.facts.proofJwkMembers ?? [],
				organizationId: parsed.data.organizationId,
				personId: verified.kind === 'verified' ? verified.claims.sub : null,
				permissions: verified.kind === 'verified' ? verified.claims.permissions : null,
				bodySha256,
				request: parsed.data,
			};
			if (verified.kind === 'refused') {
				arrivals.push({
					route,
					outcome: { kind: 'refused-unauthenticated', failure: verified.failure },
					...facts,
				});
				return new Response(null, { status: 401 });
			}
			const refused = admit(route, verified.claims, verified.requestId);
			const scripts = refused === null ? scripted.get(route) : undefined;
			const script = scripts?.shift();
			if (scripts?.length === 0) scripted.delete(route);
			if (script?.kind === 'raw') {
				arrivals.push({ route, outcome: { kind: 'scripted-raw' }, ...facts });
				return Response.json(script.body);
			}
			const result =
				refused ??
				(script === undefined
					? apply(parsed.data, verified.claims, verified.intent)
					: script.answer(parsed.data));
			arrivals.push({ route, outcome: { kind: 'answered', result }, ...facts });
			return Response.json(result);
		},
	};
}
