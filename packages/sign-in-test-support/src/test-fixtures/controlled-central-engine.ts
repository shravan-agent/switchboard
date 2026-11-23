import { createHash } from 'node:crypto';

import {
	engineKindNames,
	fleetAdminRequestSchema,
	fleetAdminRoutePaths,
	isEngineAdminOperation,
	type EngineAdminOperationName,
	type EngineAdminResultFor,
	type FleetAdminRequest,
} from '@agent-collaboration/sign-in-core';
import { z } from 'zod';

import {
	base64UrlSha256,
	centralApplyingFloorRefusal,
	sortedJson,
	verifyCentralPersonRequest,
	type AdminVerificationFailure,
	type CentralPersonVerifierSettings,
	type PersonTokenClaims,
} from '#sign-in-test-support/test-fixtures/controlled-central-admin';
import type { CentralHeldFloors } from '#sign-in-test-support/test-fixtures/controlled-central-provisioning';

/**
 * The named stand-in for central's engine administration routes (central main 4593797b1). It
 * verifies each request with the admin stand-in's verifier steps, applies central's admission in
 * its order, and answers in the shapes of central's engine reply vectors. It follows central's
 * decision table (`engine-admin-results.md`) for health, the retired pager, retry, discard and the
 * operation receipts, but earns no credit for central's store, engine or alarm; only the sign-in
 * side's sends and readings are proven here. Citations are paths in codex-router at 4593797b1:
 * `http` = collaboration-central-core/src/organization_signin_http.rs, `ops` =
 * person_request/admin_operations.rs, `eplans` = organization_engine_admin_plans.rs, `pager` =
 * fleet-engine/src/machine_event_engine/attempt_administration.rs, `adm` =
 * fleet-signin/src/person_proof/admission.rs.
 */
export const engineRouteByPath: Readonly<Record<string, EngineAdminOperationName>> = {
	[fleetAdminRoutePaths.EngineHealth]: 'EngineHealth',
	[fleetAdminRoutePaths.EngineListRetired]: 'EngineListRetired',
	[fleetAdminRoutePaths.EngineRetry]: 'EngineRetry',
	[fleetAdminRoutePaths.EngineDiscard]: 'EngineDiscard',
};

type EngineKindName = (typeof engineKindNames)[number];
/** A request on one of the four engine routes. */
type EngineRequest = Extract<FleetAdminRequest, { readonly operation: EngineAdminOperationName }>;
function isEngineRequest(request: FleetAdminRequest): request is EngineRequest {
	return isEngineAdminOperation(request.operation);
}
type FailureClass = Extract<
	EngineAdminResultFor<'EngineListRetired'>,
	{ readonly result: 'engineRetired' }
>['items'][number]['failureClass'];

/** One stored `engine_work_attempts` row, as the stand-in holds it. */
interface StoredAttempt {
	readonly organizationId: string;
	readonly attemptId: string;
	readonly kind: EngineKindName;
	readonly subjectKey: string;
	/** `invalid` is a row whose stored state is neither failing nor retired. */
	readonly state: 'failing' | 'retired' | 'invalid';
	readonly failureClass: FailureClass;
	readonly count: number;
	/** RFC 3339 with zero, three, six or nine fraction digits, as central stores it. */
	readonly firstFailedAt: string;
	readonly lastFailedAtMillis: number;
	readonly retiredAt: string;
	readonly lastFailure: string | null;
	/** The subject a discard would finish (pager:531-621). */
	readonly subject: 'finishable' | 'gone' | 'unreadable';
}

export interface EngineArrival {
	readonly route: EngineAdminOperationName;
	readonly outcome:
		| { readonly kind: 'refused-unauthenticated'; readonly failure: AdminVerificationFailure }
		| { readonly kind: 'bad-request' }
		/** An admission refusal, before any operation receipt was read. */
		| { readonly kind: 'refused'; readonly reason: string }
		/** The applied (or replayed) reply's exact bytes. */
		| { readonly kind: 'replied'; readonly bytes: string; readonly replayed: boolean }
		/** Central answered an empty 503: the examined attempt's stored state is invalid. */
		| { readonly kind: 'storage-error' };
	readonly personId: string | null;
	readonly permissions: readonly string[] | null;
	readonly operationId: string | null;
	/** SHA-256 (hex) of the exact body bytes, taken before any parsing. */
	readonly bodySha256: string;
}

export interface ControlledCentralEngine {
	readonly arrivals: readonly EngineArrival[];
	/** A retired attempt; its subject is finishable unless named otherwise. */
	readonly seedRetired: (props: {
		readonly organizationId: string;
		readonly attemptId: string;
		readonly kind?: EngineKindName;
		readonly subject?: StoredAttempt['subject'];
		readonly retiredAt?: string;
		readonly firstFailedAt?: string;
		readonly lastFailedAtMillis?: number;
	}) => void;
	/** A still-failing attempt: never listed as retired, but counted toward the pager's scan cap. */
	readonly seedFailing: (props: {
		readonly organizationId: string;
		readonly attemptId: string;
		readonly kind?: EngineKindName;
	}) => void;
	/** A row whose stored state is invalid: the retired pager answers an empty 503 at it. */
	readonly seedInvalidState: (props: {
		readonly organizationId: string;
		readonly attemptId: string;
	}) => void;
	readonly setAlarm: (alarm: { readonly at: string | null; readonly missing: boolean }) => void;
	/** Whether an attempt row is still stored. */
	readonly holdsAttempt: (organizationId: string, attemptId: string) => boolean;
	readonly fetch: (request: Request, route: EngineAdminOperationName) => Promise<Response>;
}

/** Central's admission address: `{organizationId}`, other members ignored (http:172-176). */
const organizationAddressSchema = z.looseObject({
	organizationId: z
		.string()
		.regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u),
});
/** The route permissions (ops:270-283). */
const routePermission = {
	EngineHealth: 'organization:readAudit',
	EngineListRetired: 'organization:readAudit',
	EngineRetry: 'organization:repairWork',
	EngineDiscard: 'organization:repairWork',
} as const satisfies Record<EngineAdminOperationName, string>;
/** Fresh second factor: inclusive at both ends, a future factor refused (adm:243-253). */
const secondFactorWindowMillis = 900_000;
/** The receipt window: a strict 24-hour cutoff (eplans:149, fleet-runtime workspace_request_log.rs:22-24). */
const receiptWindowMillis = 86_400_000;
/** Only these kinds have a registered finisher (workspace_runtime/engine_admin_dispatch.rs:38-66). */
const finishableKinds: readonly EngineKindName[] = ['wake_timer', 'automation_timer'];

/** Central's `AdminOperation::intent` for the engine routes (ops:701-736), restated apart from sign-in's builder. */
function independentEngineIntent(request: EngineRequest): string {
	const organization = request.organizationId;
	const frame = { v: 1, operation: request.operation, organization, target: organization };
	switch (request.operation) {
		case 'EngineHealth':
			return base64UrlSha256(sortedJson({ ...frame, operationId: null, params: {} }));
		case 'EngineListRetired':
			return base64UrlSha256(
				sortedJson({
					...frame,
					operationId: null,
					params: { after: request.after, limit: request.limit },
				}),
			);
		case 'EngineRetry':
		case 'EngineDiscard':
			return base64UrlSha256(
				sortedJson({
					...frame,
					operationId: request.operationId,
					params: { attemptId: request.attemptId },
				}),
			);
		default:
			return request satisfies never;
	}
}

function secondFactorIsFresh(claims: PersonTokenClaims, now: number): boolean {
	if (claims.second_factor_at === undefined) return false;
	const age = now - claims.second_factor_at * 1000;
	return age >= 0 && age <= secondFactorWindowMillis;
}

export function createControlledCentralEngine(
	props: CentralPersonVerifierSettings & {
		/** The floors central holds, from the provisioning peer's applied revision pushes. */
		readonly readFloors: (organizationId: string, personId: string) => CentralHeldFloors;
	},
): ControlledCentralEngine {
	const arrivals: EngineArrival[] = [];
	const attempts: StoredAttempt[] = [];
	const usedProofIds = new Set<string>();
	/**
	 * The operation receipts, keyed by organization and operation ID: the caller, the signed
	 * intent and the first reply's bytes (eplans:144-185; the store is per organization).
	 */
	const receipts = new Map<
		string,
		{
			readonly personId: string;
			readonly intent: string;
			readonly bytes: string;
			readonly atMillis: number;
		}
	>();
	let alarm: { readonly at: string | null; readonly missing: boolean } = {
		at: null,
		missing: false,
	};

	function organizationAttempts(organizationId: string): StoredAttempt[] {
		return attempts
			.filter((attempt) => attempt.organizationId === organizationId)
			.toSorted((left, right) => left.attemptId.localeCompare(right.attemptId));
	}

	function remove(attempt: StoredAttempt): void {
		attempts.splice(attempts.indexOf(attempt), 1);
	}

	/** Health per kind, all seven in central's order (engine_admin_dispatch.rs:14-25, pager:291-333). */
	function health(organizationId: string): object {
		const stored = organizationAttempts(organizationId);
		return {
			result: 'engineHealth',
			kinds: engineKindNames.map((kind) => {
				const ofKind = stored.filter(
					(attempt) => attempt.kind === kind && attempt.state !== 'invalid',
				);
				// read_attempt_health_by_kind.sql: oldest first failure across both states; the last
				// failure of the newest-failed row, ties broken by attempt ID descending.
				const oldest = ofKind
					.map((attempt) => attempt.firstFailedAt)
					.toSorted((left, right) => Date.parse(left) - Date.parse(right))[0];
				const newest = ofKind.toSorted(
					(left, right) =>
						right.lastFailedAtMillis - left.lastFailedAtMillis ||
						right.attemptId.localeCompare(left.attemptId),
				)[0];
				return {
					kind,
					failing: ofKind.filter((attempt) => attempt.state === 'failing').length,
					retired: ofKind.filter((attempt) => attempt.state === 'retired').length,
					oldestFirstFailedAt: oldest ?? null,
					lastFailure: newest?.failureClass ?? null,
				};
			}),
			alarm: alarm.at,
			alarmMissing: alarm.at === null && alarm.missing,
		};
	}

	/**
	 * The retired pager (pager:336-411): ascending attempt IDs after the exclusive cursor, a scan
	 * capped at four rows per requested item, failing rows skipped but counted. `next` is the last
	 * examined ID when unread scanned rows remain or the scan filled its cap; otherwise null. An
	 * examined row with an invalid stored state is a storage error (pager:378-382).
	 */
	function retired(
		organizationId: string,
		after: string | null,
		limit: number,
	): object | 'storage-error' {
		const cap = limit * 4;
		const scanned = organizationAttempts(organizationId)
			.filter((attempt) => after === null || attempt.attemptId > after)
			.slice(0, cap);
		const items: object[] = [];
		let lastExamined: string | null = null;
		let examined = 0;
		for (const attempt of scanned) {
			if (items.length === limit) break;
			examined += 1;
			lastExamined = attempt.attemptId;
			if (attempt.state === 'invalid') return 'storage-error';
			if (attempt.state === 'failing') continue;
			items.push({
				attemptId: attempt.attemptId,
				kind: attempt.kind,
				subjectKey: attempt.subjectKey,
				failureClass: attempt.failureClass,
				count: attempt.count,
				retiredAt: attempt.retiredAt,
				lastFailure: attempt.lastFailure,
			});
		}
		const unread = examined < scanned.length;
		return {
			result: 'engineRetired',
			items,
			next: unread || scanned.length === cap ? lastExamined : null,
		};
	}

	/** Retry and discard's shared lookup, then each route's decision (pager:413-621). */
	function repair(
		request: Extract<FleetAdminRequest, { readonly operation: 'EngineRetry' | 'EngineDiscard' }>,
	): object {
		const refused = (reason: string): object => ({ result: 'refused', reason });
		const attempt = attempts.find(
			(stored) =>
				stored.organizationId === request.organizationId && stored.attemptId === request.attemptId,
		);
		if (attempt === undefined) return refused('notFound');
		// A record that fails to decode, or that is still failing, is notRetired (pager:444-449).
		if (attempt.state !== 'retired') return refused('notRetired');
		if (request.operation === 'EngineRetry') {
			remove(attempt);
			return { result: 'engineRetried' };
		}
		if (!finishableKinds.includes(attempt.kind)) return refused('discardUnsupported');
		if (attempt.subject === 'gone') return refused('stale');
		if (attempt.subject === 'unreadable') return refused('subjectUnreadable');
		remove(attempt);
		return { result: 'engineDiscarded' };
	}

	return {
		arrivals,
		seedRetired(seed): void {
			attempts.push({
				organizationId: seed.organizationId,
				attemptId: seed.attemptId,
				kind: seed.kind ?? 'wake_timer',
				subjectKey: `${seed.attemptId.slice(0, -3)}102`,
				state: 'retired',
				failureClass: 'statement_rejected',
				count: 2,
				firstFailedAt: seed.firstFailedAt ?? '2026-11-23T08:00:01Z',
				lastFailedAtMillis: seed.lastFailedAtMillis ?? 0,
				retiredAt: seed.retiredAt ?? '2026-11-23T08:05:02.123Z',
				lastFailure: null,
				subject: seed.subject ?? 'finishable',
			});
		},
		seedFailing(seed): void {
			attempts.push({
				organizationId: seed.organizationId,
				attemptId: seed.attemptId,
				kind: seed.kind ?? 'wake_timer',
				subjectKey: `${seed.attemptId.slice(0, -3)}103`,
				state: 'failing',
				failureClass: 'other_store_unavailable',
				count: 1,
				firstFailedAt: '2026-11-23T08:00:00.123456789Z',
				lastFailedAtMillis: 0,
				retiredAt: '2026-11-23T08:00:00Z',
				lastFailure: 'store unavailable',
				subject: 'finishable',
			});
		},
		seedInvalidState(seed): void {
			attempts.push({
				organizationId: seed.organizationId,
				attemptId: seed.attemptId,
				kind: 'wake_timer',
				subjectKey: `${seed.attemptId.slice(0, -3)}104`,
				state: 'invalid',
				failureClass: 'corrupt_row',
				count: 1,
				firstFailedAt: '2026-11-23T08:00:00Z',
				lastFailedAtMillis: 0,
				retiredAt: '2026-11-23T08:00:00Z',
				lastFailure: null,
				subject: 'finishable',
			});
		},
		setAlarm(next): void {
			alarm = next;
		},
		holdsAttempt: (organizationId, attemptId): boolean =>
			attempts.some(
				(attempt) => attempt.organizationId === organizationId && attempt.attemptId === attemptId,
			),
		async fetch(request, route): Promise<Response> {
			const bytes = new Uint8Array(await request.arrayBuffer());
			const bodySha256 = createHash('sha256').update(bytes).digest('hex');
			const absent = { personId: null, permissions: null, operationId: null, bodySha256 } as const;
			const unauthenticated = (failure: AdminVerificationFailure): Response => {
				arrivals.push({ route, outcome: { kind: 'refused-unauthenticated', failure }, ...absent });
				return new Response(null, { status: 401 });
			};
			// Tokio's order (http:27-65, 184-198): the proof headers (401), then only the
			// organization address (400). The full body waits for the proof.
			if (!request.headers.has('authorization') || !request.headers.has('dpop'))
				return unauthenticated('missing-headers');
			let decoded: unknown = null;
			try {
				decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
			} catch {
				decoded = null;
			}
			const address = organizationAddressSchema.safeParse(decoded);
			if (!address.success) {
				arrivals.push({ route, outcome: { kind: 'bad-request' }, ...absent });
				return new Response(null, { status: 400 });
			}
			// Verification, then the full decode and the signed intent: every failure is 401
			// (person_request/request_verifier.rs:76-91; ops:527-530). The body is read with
			// sign-in's closed schema: central also accepts any UUID form for `attemptId` and
			// `after`, and an absent `after`; sign-in never sends those.
			// Set by the intent step once the proof checks pass; a holder, so the type stays open.
			const decodedBody: { value: EngineRequest | null } = { value: null };
			const verified = await verifyCentralPersonRequest(props, request, {
				path: fleetAdminRoutePaths[route],
				organization: address.data.organizationId,
				intent: () => {
					const parsed = fleetAdminRequestSchema.safeParse({
						...z.looseObject({}).catch({}).parse(decoded),
						operation: route,
					});
					if (!parsed.success || !isEngineRequest(parsed.data)) return null;
					decodedBody.value = parsed.data;
					return independentEngineIntent(parsed.data);
				},
			});
			const body = decodedBody.value;
			if (verified.kind === 'refused' || body === null)
				return unauthenticated(verified.kind === 'refused' ? verified.failure : 'operation-body');
			const admitted: EngineRequest = body;
			const { claims } = verified;
			const operationId =
				admitted.operation === 'EngineRetry' || admitted.operation === 'EngineDiscard'
					? admitted.operationId
					: null;
			const facts = {
				personId: claims.sub,
				permissions: claims.permissions,
				operationId,
				bodySha256,
			};
			const refuse = (reason: string): Response => {
				arrivals.push({ route, outcome: { kind: 'refused', reason }, ...facts });
				return Response.json({ result: 'refused', reason });
			};
			// Applying admission at one sample (person_admission_plans.rs:25-61): the floors, the
			// permission (adm:174-178), the fresh factor for a change (adm:179-182), then proof reuse
			// (person_admission_plans.rs:45-53).
			const now = props.now();
			const floorRefusal = centralApplyingFloorRefusal({
				now,
				floors: props.readFloors(claims.organization_id, claims.sub),
				verified,
			});
			if (floorRefusal !== null) return refuse(floorRefusal);
			if (!claims.permissions.includes(routePermission[route])) return refuse('notPermitted');
			const change = operationId !== null;
			if (change && !secondFactorIsFresh(claims, now)) return refuse('secondFactorRequired');
			if (usedProofIds.has(verified.requestId)) return refuse('requestReused');
			const reply = (replyBytes: string, replayed: boolean): Response => {
				usedProofIds.add(verified.requestId);
				arrivals.push({
					route,
					outcome: { kind: 'replied', bytes: replyBytes, replayed },
					...facts,
				});
				return new Response(replyBytes, { headers: { 'content-type': 'application/json' } });
			};
			switch (admitted.operation) {
				case 'EngineHealth':
					return reply(JSON.stringify(health(admitted.organizationId)), false);
				case 'EngineListRetired': {
					const page = retired(admitted.organizationId, admitted.after, admitted.limit);
					if (page === 'storage-error') {
						// The table's row: an empty 503, and the proof is not consumed.
						arrivals.push({ route, outcome: { kind: 'storage-error' }, ...facts });
						return new Response(null, { status: 503 });
					}
					return reply(JSON.stringify(page), false);
				}
				case 'EngineRetry':
				case 'EngineDiscard': {
					// The receipt is read only after admission (eplans:196-200, 250-254): an exact
					// replay returns the first bytes; another actor or intent is conflict, not retained.
					const key = `${admitted.organizationId}/${admitted.operationId}`;
					const prior = receipts.get(key);
					if (prior !== undefined && prior.atMillis > now - receiptWindowMillis) {
						if (prior.personId === claims.sub && prior.intent === verified.intent)
							return reply(prior.bytes, true);
						return reply(JSON.stringify({ result: 'refused', reason: 'conflict' }), false);
					}
					// A fresh repair or refusal is retained under the operation ID (eplans:216-225, 294-296).
					const bytesOut = JSON.stringify(repair(admitted));
					receipts.set(key, {
						personId: claims.sub,
						intent: verified.intent,
						bytes: bytesOut,
						atMillis: now,
					});
					return reply(bytesOut, false);
				}
				default:
					return admitted satisfies never;
			}
		},
	};
}
