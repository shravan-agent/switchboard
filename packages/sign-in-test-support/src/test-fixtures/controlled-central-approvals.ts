import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import {
	approvalPersonReplySchemas,
	approvalPersonRequestBodySchemas,
	approvalPersonRoutePaths,
	type ApprovalPersonOperationName,
	type ApprovalPersonReplyFor,
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
 * The named stand-in for central's C3 person approval routes (central main 1ede5c1b9). It
 * verifies each request with the same verifier steps as the admin stand-in, admits by
 * `approval:decide`, and answers in exactly the shapes of central's committed reply vectors,
 * seeded from them. It follows central's result matrix for list paging, notVisible, the decide
 * results and the operation log, but earns no credit for central's store, admission or deadline
 * settlement; only the sign-in side's sends and readings are proven here.
 */
export const approvalRouteByPath: Readonly<Record<string, ApprovalPersonOperationName>> = {
	[approvalPersonRoutePaths.ApprovalList]: 'ApprovalList',
	[approvalPersonRoutePaths.ApprovalRead]: 'ApprovalRead',
	[approvalPersonRoutePaths.ApprovalDecide]: 'ApprovalDecide',
};

const replyVectors = z
	.strictObject({
		ApprovalListReply: z.array(z.string()).min(1),
		ApprovalReadReply: z.array(z.string()).min(1),
		ApprovalDecideReply: z.array(z.string()).min(1),
	})
	.parse(
		JSON.parse(
			readFileSync(
				new URL(
					'../../../sign-in-core/contract-fixtures/central-person-approvals/approval-person-reply-vectors.json',
					import.meta.url,
				),
				'utf8',
			),
		),
	);
/** Central's own waiting unproven-call view: every seeded request is this view, re-addressed. */
const unprovenCallViewTemplate = z
	.object({ kind: z.literal('request'), view: z.looseObject({ kind: z.literal('unprovenCall') }) })
	.parse(JSON.parse(replyVectors.ApprovalReadReply[0] ?? 'null')).view;

type ReadView = Extract<
	ApprovalPersonReplyFor<'ApprovalRead'>,
	{ readonly kind: 'request' }
>['view'];
type ListedRequest = ApprovalPersonReplyFor<'ApprovalList'>['items'][number];
type ProviderApprovalOffer = Extract<ReadView, { readonly kind: 'providerApproval' }>['offer'];
type QuestionOffer = Extract<ReadView, { readonly kind: 'providerQuestion' }>['offer'];
type DecideAnswer = z.output<(typeof approvalPersonRequestBodySchemas)['ApprovalDecide']>['answer'];
type InvalidAnswer = Extract<
	Extract<DecideReply, { readonly kind: 'invalid' }>['reason'],
	{ readonly kind: 'invalidAnswer' }
>['reason'];
/** What a seeded request offers: an unproven call (central's vector), an approval, a question. */
type StoredOffer =
	| { readonly kind: 'unprovenCall' }
	| { readonly kind: 'providerApproval'; readonly offer: ProviderApprovalOffer }
	| { readonly kind: 'providerQuestion'; readonly offer: QuestionOffer };
type DecideReply = ApprovalPersonReplyFor<'ApprovalDecide'>;
type CentralReply = ApprovalPersonReplyFor<ApprovalPersonOperationName>;
type AdminRefusal = { readonly result: 'refused'; readonly reason: string };

export interface ApprovalArrival {
	readonly route: ApprovalPersonOperationName;
	readonly outcome:
		| { readonly kind: 'refused-unauthenticated'; readonly failure: AdminVerificationFailure }
		| { readonly kind: 'bad-request' }
		| { readonly kind: 'refused'; readonly reason: string }
		| { readonly kind: 'replied'; readonly reply: CentralReply; readonly delivered: boolean };
	readonly personId: string | null;
	readonly permissions: readonly string[] | null;
	readonly operationId: string | null;
	/** SHA-256 (hex) of the exact body bytes, taken before any parsing. */
	readonly bodySha256: string;
}

interface StoredRequest {
	readonly organizationId: string;
	readonly requestId: string;
	readonly raisedAtMillis: number;
	readonly offer: StoredOffer;
	ending:
		| null
		| {
				readonly kind: 'decided';
				readonly personId: string;
				readonly answer: DecideAnswer;
				readonly atMillis: number;
		  }
		| { readonly kind: 'timedOut'; readonly atMillis: number };
}

export interface ControlledCentralApprovals {
	readonly arrivals: readonly ApprovalArrival[];
	/** A waiting unproven call in `organizationId`, raised at `raisedAtMillis` (one-hour deadline). */
	readonly seedUnprovenCall: (props: {
		readonly organizationId: string;
		readonly requestId: string;
		readonly raisedAtMillis: number;
	}) => void;
	/** A waiting provider approval offering `offer`'s options. */
	readonly seedProviderApproval: (props: {
		readonly organizationId: string;
		readonly requestId: string;
		readonly raisedAtMillis: number;
		readonly offer: ProviderApprovalOffer;
	}) => void;
	/** A waiting provider question asking `offer`'s fields. */
	readonly seedQuestion: (props: {
		readonly organizationId: string;
		readonly requestId: string;
		readonly raisedAtMillis: number;
		readonly offer: QuestionOffer;
	}) => void;
	readonly setPageSize: (size: number) => void;
	/**
	 * The next admitted decide is applied and retained, but its reply is lost on the way back
	 * (central answers 503): the "reply lost" row, recovered by an exact retry.
	 */
	readonly loseNextDecideReply: () => void;
	readonly fetch: (request: Request, route: ApprovalPersonOperationName) => Promise<Response>;
}

/** The fields central's three C3 bodies carry, read once the route's own schema accepted them. */
const approvalBodyFieldsSchema = z.looseObject({
	organization: z.string(),
	filter: z.enum(['waiting', 'all']).optional(),
	cursor: z.string().nullish(),
	requestId: z.string().optional(),
	operationId: z.string().optional(),
	answer: z.unknown().optional(),
});
type ApprovalBodyFields = z.output<typeof approvalBodyFieldsSchema>;

const oneHourMillis = 3_600_000;
/** Central's request-log retention: a strict 24-hour cutoff (workspace_request_log.rs:22). */
const retentionMillis = 86_400_000;
/** Central's preflight address: `{organization}`, other members ignored (person_approval_http.rs:65-72). */
const organizationAddressSchema = z.looseObject({
	organization: z
		.string()
		.regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u),
});
const approvalPermission = 'approval:decide';

/** RFC 3339 in UTC with `Z`: whole seconds, or exactly three fraction digits. */
function centralTime(milliseconds: number): string {
	const iso = new Date(milliseconds).toISOString();
	return iso.endsWith('.000Z') ? `${iso.slice(0, -5)}Z` : iso;
}

/** Central's `check_answer` (approval-request-protocol answer_validation.rs), restated. */
function checkAnswer(offer: StoredOffer, answer: DecideAnswer): InvalidAnswer | null {
	if (offer.kind === 'unprovenCall')
		return answer.kind === 'unprovenCall' ? null : { kind: 'wrongKind' };
	if (offer.kind === 'providerApproval') {
		if (answer.kind !== 'approval') return { kind: 'wrongKind' };
		return offer.offer.options.some((option) => option.id === answer.optionId)
			? null
			: { kind: 'unofferedOption', optionId: answer.optionId };
	}
	if (answer.kind !== 'question') return { kind: 'wrongKind' };
	if (answer.answer.kind === 'declined') return null;
	const answered = new Set<number>();
	for (const { fieldId, value } of answer.answer.fields) {
		if (answered.has(fieldId)) return { kind: 'repeatedField', fieldId };
		answered.add(fieldId);
		const field = offer.offer.fields.find((candidate) => candidate.fieldId === fieldId);
		if (field === undefined) return { kind: 'unofferedField', fieldId };
		const choices =
			field.kind === 'singleChoice'
				? { options: field.options, min: 1, max: 1 }
				: field.kind === 'multiChoice'
					? {
							options: field.selection.options,
							min: field.selection.min ?? 0,
							max: field.selection.max ?? field.selection.options.length,
						}
					: null;
		if (choices === null) {
			if (value.kind !== field.kind) return { kind: 'wrongValueType', fieldId };
			continue;
		}
		if (value.kind !== 'selectedOptions') return { kind: 'wrongValueType', fieldId };
		const selected = new Set<number>();
		for (const optionId of value.selectedOptionIds) {
			if (selected.has(optionId)) return { kind: 'repeatedSelection', fieldId, optionId };
			selected.add(optionId);
			if (!choices.options.some((option) => option.optionId === optionId))
				return { kind: 'unofferedOption', optionId };
		}
		if (selected.size < choices.min || selected.size > choices.max)
			return { kind: 'wrongSelectionCount', fieldId };
	}
	const missing = offer.offer.fields.find(
		(field) => field.required && !answered.has(field.fieldId),
	);
	return missing === undefined ? null : { kind: 'missingRequiredField', fieldId: missing.fieldId };
}

/** Central's `ApprovalPersonOperation::intent`, restated from its committed intent vectors. */
function independentApprovalIntent(
	route: ApprovalPersonOperationName,
	body: ApprovalBodyFields,
): string {
	const organization = body.organization;
	const intent =
		route === 'ApprovalList'
			? {
					v: 1,
					operation: route,
					organization,
					target: organization,
					operationId: null,
					params: { filter: body.filter, cursor: body.cursor ?? null },
				}
			: route === 'ApprovalRead'
				? {
						v: 1,
						operation: route,
						organization,
						target: body.requestId,
						operationId: null,
						params: {},
					}
				: {
						v: 1,
						operation: route,
						organization,
						target: body.requestId,
						operationId: body.operationId,
						params: { answer: body.answer },
					};
	return base64UrlSha256(sortedJson(intent));
}

export function createControlledCentralApprovals(
	props: CentralPersonVerifierSettings & {
		/** The floors central holds, from the provisioning peer's applied revision pushes. */
		readonly readFloors: (organizationId: string, personId: string) => CentralHeldFloors;
	},
): ControlledCentralApprovals {
	const arrivals: ApprovalArrival[] = [];
	const requests: StoredRequest[] = [];
	const usedProofIds = new Set<string>();
	/**
	 * Central's organization request log for person decides, keyed by organization and operation
	 * id: the caller, the signed intent and the first result (fleet-approvals/src/
	 * approval_store_person_decide.rs:104-128), readable for 24 hours (fleet-runtime/src/
	 * workspace_request_log.rs:22, a strict cutoff).
	 */
	const operationLog = new Map<
		string,
		{
			readonly personId: string;
			readonly intent: string;
			readonly reply: DecideReply;
			readonly atMillis: number;
		}
	>();
	let pageSize = 100;
	let loseNextDecide = false;

	function settleDeadline(stored: StoredRequest): void {
		const deadline = stored.raisedAtMillis + oneHourMillis;
		if (stored.ending === null && props.now() >= deadline)
			stored.ending = { kind: 'timedOut', atMillis: deadline };
	}

	function window(stored: StoredRequest): { readonly raisedAt: string; readonly deadline: string } {
		return {
			raisedAt: centralTime(stored.raisedAtMillis),
			deadline: centralTime(stored.raisedAtMillis + oneHourMillis),
		};
	}

	/** A parked call's state for an unproven call; a destination state for the provider kinds. */
	function state(stored: StoredRequest): object {
		const { ending } = stored;
		if (stored.offer.kind === 'unprovenCall') {
			if (ending === null) return { kind: 'waiting' };
			return {
				kind: 'ended',
				ending:
					ending.kind === 'timedOut'
						? { kind: 'timedOut' }
						: {
								kind: 'giver',
								decision:
									ending.answer.kind === 'unprovenCall' ? ending.answer.decision : 'decline',
								personId: ending.personId,
							},
				endedAt: centralTime(ending.atMillis),
				delivery: { kind: 'owed' },
			};
		}
		if (ending === null) return { kind: 'waiting', status: 'pending' };
		const accepted =
			ending.kind === 'timedOut'
				? null
				: ending.answer.kind === 'approval'
					? ending.answer.optionId
					: ending.answer.kind === 'question'
						? ending.answer.answer
						: null;
		return {
			kind: 'ended',
			ending:
				ending.kind === 'timedOut' || accepted === null
					? { kind: 'standing', ending: { kind: 'timedOut' } }
					: {
							kind: 'giver',
							decision: { by: { kind: 'person', personId: ending.personId }, answer: accepted },
						},
			endedAt: centralTime(ending.atMillis),
			delivery: { kind: 'owed' },
		};
	}

	function view(stored: StoredRequest): ReadView {
		const shape =
			stored.offer.kind === 'unprovenCall'
				? unprovenCallViewTemplate
				: { kind: stored.offer.kind, offer: stored.offer.offer };
		const read = approvalPersonReplySchemas.ApprovalRead.parse({
			kind: 'request',
			view: {
				...shape,
				requestId: stored.requestId,
				state: state(stored),
				window: window(stored),
			},
		});
		if (read.kind !== 'request') throw new Error('A seeded request always has a view');
		return read.view;
	}

	function summary(stored: StoredRequest): ListedRequest {
		return {
			requestId: stored.requestId,
			kind: stored.offer.kind,
			state:
				stored.ending === null
					? { kind: 'waiting' }
					: { kind: 'ended', ending: stored.ending.kind === 'timedOut' ? 'timedOut' : 'decided' },
			...window(stored),
		};
	}

	/**
	 * Central's applying admission for C3, in its order (fleet-signin/src/
	 * approval_person_admission.rs:105-160; person_proof/admission.rs at 1ede5c1b9):
	 * request time (admission.rs:191-203), the organization floor (admission.rs:205-236), the
	 * person floor (admission.rs:153-174), the approval:decide grant (:175-179), then proof reuse
	 * (:183-185). A Decide refused only for the missing grant is admitted retained-only
	 * (approval_person_admission.rs:145-160): it may read back its own retained result and nothing
	 * else. Central's reject-through watermark is not modelled by the provisioning peer.
	 */
	function admit(
		route: ApprovalPersonOperationName,
		verified: Extract<Awaited<ReturnType<typeof verifyCentralPersonRequest>>, { kind: 'verified' }>,
	):
		| { readonly kind: 'granted' }
		| { readonly kind: 'retained-only' }
		| { readonly kind: 'refused'; readonly refusal: AdminRefusal } {
		const refused = (reason: string) =>
			({ kind: 'refused', refusal: { result: 'refused', reason } }) as const;
		const { claims, requestId } = verified;
		const floorRefusal = centralApplyingFloorRefusal({
			now: props.now(),
			floors: props.readFloors(claims.organization_id, claims.sub),
			verified,
		});
		if (floorRefusal !== null) return refused(floorRefusal);
		const reused = usedProofIds.has(requestId);
		if (!claims.permissions.includes(approvalPermission))
			return route === 'ApprovalDecide' && !reused
				? { kind: 'retained-only' }
				: refused('notPermitted');
		if (reused) return refused('requestReused');
		return { kind: 'granted' };
	}

	/** The retained entry for this organization's operation id, if central still holds it. */
	function retained(
		organizationId: string,
		operationId: string | undefined,
	): (typeof operationLog extends Map<string, infer Entry> ? Entry : never) | undefined {
		const entry = operationLog.get(`${organizationId}/${operationId ?? ''}`);
		return entry !== undefined && entry.atMillis > props.now() - retentionMillis
			? entry
			: undefined;
	}

	function find(organizationId: string, requestId: unknown): StoredRequest | undefined {
		return requests.find(
			(stored) => stored.organizationId === organizationId && stored.requestId === requestId,
		);
	}

	function apply(
		route: ApprovalPersonOperationName,
		body: ApprovalBodyFields,
		claims: PersonTokenClaims,
		intent: string,
	): CentralReply {
		const organizationId = claims.organization_id;
		for (const stored of requests) settleDeadline(stored);
		if (route === 'ApprovalList') {
			const cursor = body.cursor ?? null;
			const visible = requests
				.filter((stored) => stored.organizationId === organizationId)
				.filter((stored) => body.filter === 'all' || stored.ending === null)
				.filter((stored) => cursor === null || stored.requestId < cursor)
				.toSorted((left, right) => right.requestId.localeCompare(left.requestId));
			const page = visible.slice(0, pageSize);
			return {
				kind: 'page',
				items: page.map(summary),
				next: visible.length > pageSize ? (page.at(-1)?.requestId ?? null) : null,
			};
		}
		const stored = find(organizationId, body.requestId);
		if (route === 'ApprovalRead')
			return stored === undefined
				? { kind: 'notVisible' }
				: { kind: 'request', view: view(stored) };
		// approval_store_person_decide.rs:83-100: a retained result for this operation id is
		// replayed to its own caller with the same intent; anything else is operationConflict.
		const prior = retained(organizationId, body.operationId);
		if (prior !== undefined)
			return prior.personId === claims.sub && prior.intent === intent
				? prior.reply
				: { kind: 'operationConflict' };
		const reply = decide(stored, body, claims);
		operationLog.set(`${organizationId}/${body.operationId ?? ''}`, {
			personId: claims.sub,
			intent,
			reply,
			atMillis: props.now(),
		});
		return reply;
	}

	function decide(
		stored: StoredRequest | undefined,
		body: ApprovalBodyFields,
		claims: PersonTokenClaims,
	): DecideReply {
		if (stored === undefined) return { kind: 'notVisible' };
		if (stored.ending?.kind === 'timedOut') return { kind: 'tooLate' };
		if (stored.ending?.kind === 'decided')
			return {
				kind: 'alreadyDecided',
				by: { kind: 'person', personId: stored.ending.personId },
				at: centralTime(stored.ending.atMillis),
			};
		const answer = approvalPersonRequestBodySchemas.ApprovalDecide.shape.answer.parse(body.answer);
		const invalid = checkAnswer(stored.offer, answer);
		if (invalid !== null)
			return { kind: 'invalid', reason: { kind: 'invalidAnswer', reason: invalid } };
		stored.ending = { kind: 'decided', personId: claims.sub, answer, atMillis: props.now() };
		return {
			kind: 'savedDecision',
			decision: { by: { kind: 'person', personId: claims.sub }, answer },
		};
	}

	return {
		arrivals,
		seedUnprovenCall(seed): void {
			requests.push({ ...seed, offer: { kind: 'unprovenCall' }, ending: null });
		},
		seedProviderApproval({ offer, ...seed }): void {
			requests.push({ ...seed, offer: { kind: 'providerApproval', offer }, ending: null });
		},
		seedQuestion({ offer, ...seed }): void {
			requests.push({ ...seed, offer: { kind: 'providerQuestion', offer }, ending: null });
		},
		setPageSize(size): void {
			pageSize = size;
		},
		loseNextDecideReply(): void {
			loseNextDecide = true;
		},
		async fetch(request, route): Promise<Response> {
			const bytes = new Uint8Array(await request.arrayBuffer());
			const bodySha256 = createHash('sha256').update(bytes).digest('hex');
			const absent = { personId: null, permissions: null, operationId: null, bodySha256 } as const;
			const unauthenticated = (failure: AdminVerificationFailure): Response => {
				arrivals.push({
					route,
					outcome: { kind: 'refused-unauthenticated', failure },
					...absent,
				});
				return new Response(null, { status: 401 });
			};
			// Preflight (collaboration-central-core/src/person_approval_http.rs:55-79): both proof
			// headers (401), then only the organization address (400). The full body waits.
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
			// Verification, then the full decode and the signed intent
			// (fleet-signin/src/approval_person_admission.rs:368-395): every failure is 401.
			let body: ApprovalBodyFields | null = null;
			const verified = await verifyCentralPersonRequest(props, request, {
				path: approvalPersonRoutePaths[route],
				organization: address.data.organization,
				intent: () => {
					const parsed = approvalPersonRequestBodySchemas[route].safeParse(decoded);
					if (!parsed.success) return null;
					body = approvalBodyFieldsSchema.parse(parsed.data);
					return independentApprovalIntent(route, body);
				},
			});
			if (verified.kind === 'refused' || body === null)
				return unauthenticated(verified.kind === 'refused' ? verified.failure : 'operation-body');
			const admittedBody: ApprovalBodyFields = body;
			const operationId = route === 'ApprovalDecide' ? (admittedBody.operationId ?? null) : null;
			const facts = {
				personId: verified.claims.sub,
				permissions: verified.claims.permissions,
				operationId,
				bodySha256,
			};
			const admission = admit(route, verified);
			if (admission.kind === 'refused') {
				arrivals.push({
					route,
					outcome: { kind: 'refused', reason: admission.refusal.reason },
					...facts,
				});
				return Response.json(admission.refusal);
			}
			if (admission.kind === 'retained-only') {
				// approval_store_person_decide.rs:38-66: only this caller's retained result under the
				// same intent comes back; otherwise notPermitted (person_approval_application.rs:96),
				// and the proof is not reserved.
				const prior = retained(verified.claims.organization_id, admittedBody.operationId);
				if (
					prior === undefined ||
					prior.personId !== verified.claims.sub ||
					prior.intent !== verified.intent
				) {
					const refusal = { result: 'refused', reason: 'notPermitted' } as const;
					arrivals.push({ route, outcome: { kind: 'refused', reason: refusal.reason }, ...facts });
					return Response.json(refusal);
				}
				usedProofIds.add(verified.requestId);
				arrivals.push({
					route,
					outcome: { kind: 'replied', reply: prior.reply, delivered: true },
					...facts,
				});
				return Response.json(prior.reply);
			}
			usedProofIds.add(verified.requestId);
			const reply = apply(route, admittedBody, verified.claims, verified.intent);
			const delivered = !(route === 'ApprovalDecide' && loseNextDecide);
			if (route === 'ApprovalDecide') loseNextDecide = false;
			arrivals.push({ route, outcome: { kind: 'replied', reply, delivered }, ...facts });
			return delivered ? Response.json(reply) : new Response(null, { status: 503 });
		},
	};
}
