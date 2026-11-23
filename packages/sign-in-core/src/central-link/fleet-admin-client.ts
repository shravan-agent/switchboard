import { z } from 'zod';

import type { CentralTransport } from '#sign-in-core/central-link/central-transport';
import { engineAdminResultSchemas } from '#sign-in-core/central-link/engine-admin-replies';
import { engineAdminPreflightStatuses } from '#sign-in-core/central-link/engine-admin-results';
import type {
	AdminRefusal,
	ListWorkspacesResult_Serialize,
	MachineAllowanceState,
	OrganizationAdminResult_Serialize,
	OrganizationChangeKind,
	OrganizationChangeOrigin,
	OrganizationChangeRecord,
	RevokeMachineEnrollmentRequest as RevokeMachineWireRequest,
	TargetedOrganizationChangeKind,
	WorkspaceView_Serialize,
} from '#sign-in-core/central-link/generated/central-sign-in.gen';
import { organizationChangeFixtures } from '#sign-in-core/central-link/generated/organization-change-fixtures';
import type { AssertWireType, WireTypesEqual } from '#sign-in-core/central-link/wire-type-equality';
import {
	fleetAdminWorkspaceNameSchema,
	listWorkspacesPageLimit,
} from '#sign-in-core/contracts/fleet-admin-wire';
import type { Uuid7 } from '#sign-in-core/contracts/sign-in-platform';
import {
	revokeMachineEnrollmentResultSchema,
	type RevokeMachineEnrollmentRequest,
	type RevokeMachineEnrollmentResult,
} from '#sign-in-core/machine-login/machine-login-contracts';
import {
	fleetAdminRequestBody,
	fleetAdminRoutePaths,
	isEngineAdminOperation,
	type FleetAdminRequest,
} from '#sign-in-core/organizations/fleet-admin-operation';
import type { CentralLinkUncertainty } from '#sign-in-core/organizations/organization-provisioning';

// Central's closed `OrganizationAdminResult` (codex-router #275, merged as `ea030e513`,
// `collaboration-central-core/src/organization_admin_contract.rs`; mirrored in
// `contract-fixtures/central-organization-admin/`), tag `result`.
const centralRecordIdSchema = z
	.string()
	.regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
// A brand marks the value only after the same lowercase UUIDv7 validator succeeds.
const signInRecordIdSchema = centralRecordIdSchema.brand<'Uuid7'>();
const workspaceWireSchema = z.strictObject({
	workspaceId: centralRecordIdSchema,
	name: fleetAdminWorkspaceNameSchema,
	description: z
		.string()
		// Central #275 `WorkspaceView`: at most 2048 UTF-8 bytes, the same bound a create sends.
		.refine((text) => new TextEncoder().encode(text).length <= 2048, 'Description too long'),
	state: z.enum(['active', 'archiving', 'archived']),
});
const signInAdminRefusalReasons = [
	/** Another workspace already holds this name (case-insensitive, trimmed). */
	'nameInUse',
	'notPermitted',
	'secondFactorRequired',
	'refreshRequired',
	'authorizationSyncRequired',
	'expired',
	'requestTime',
	'requestReused',
	/** The same operation ID arrived with a different request. */
	'conflict',
	'rejected',
] as const satisfies readonly AdminRefusal[];

// The workspace and change-record routes share this subset; each engine route owns its own reasons
// (engine-admin-results.ts).
export type FleetAdminRefusalReason = Extract<
	AdminRefusal,
	(typeof signInAdminRefusalReasons)[number]
>;
export const fleetAdminRefusalReasonSchema = z.enum(signInAdminRefusalReasons);
const refusedSchema = z.strictObject({
	result: z.literal('refused'),
	reason: fleetAdminRefusalReasonSchema,
});
const targetedChangeKindSchema = z.enum(
	organizationChangeFixtures
		.filter((record) => record.kind !== 'machineAllowanceChanged')
		.map(({ kind }) => kind),
);
const machineAllowanceStateSchema = z.enum(
	organizationChangeFixtures
		.filter((record) => record.kind === 'machineAllowanceChanged')
		.map(({ state }) => state),
);
const organizationChangeOriginSchema = z.discriminatedUnion('kind', [
	z.strictObject({ kind: z.literal('signInProvisioning') }),
	z.strictObject({ kind: z.literal('automatic') }),
	z.strictObject({
		kind: z.literal('person'),
		personId: z.string().min(1),
		permissionChecked: z.string().min(1),
	}),
]);
const changeRecordFields = z.strictObject({
	id: centralRecordIdSchema,
	requestId: z
		.string()
		.min(1)
		.refine((value) => !value.includes('\0') && new TextEncoder().encode(value).byteLength <= 128),
	origin: organizationChangeOriginSchema,
	createdAtMillis: z.number().int(),
});
const targetedChangeWireSchema = changeRecordFields.extend({
	kind: targetedChangeKindSchema,
	targetId: z.string().min(1),
});
const machineAllowanceWireSchema = changeRecordFields.extend({
	kind: z.literal('machineAllowanceChanged'),
	machineId: centralRecordIdSchema,
	workspaceId: centralRecordIdSchema,
	state: machineAllowanceStateSchema,
});
const changeRecordWireSchema = z.discriminatedUnion('kind', [
	targetedChangeWireSchema,
	machineAllowanceWireSchema,
]);
const changeRecordSchema = z.discriminatedUnion('kind', [
	targetedChangeWireSchema.extend({ id: signInRecordIdSchema }),
	machineAllowanceWireSchema.extend({
		id: signInRecordIdSchema,
		machineId: signInRecordIdSchema,
		workspaceId: signInRecordIdSchema,
	}),
]);
const workspaceSchema = workspaceWireSchema.extend({ workspaceId: signInRecordIdSchema });
const listWorkspacesWirePageSchema = z.strictObject({
	result: z.literal('workspaces'),
	workspaces: z.array(workspaceWireSchema).max(listWorkspacesPageLimit),
	next: centralRecordIdSchema.nullable(),
});
const listWorkspacesWireReplySchema = z.union([listWorkspacesWirePageSchema, refusedSchema]);
const listWorkspacesReplySchema = z.union([
	listWorkspacesWirePageSchema.extend({
		workspaces: z.array(workspaceSchema).max(listWorkspacesPageLimit),
		next: signInRecordIdSchema.nullable(),
	}),
	refusedSchema,
]);
export type ListWorkspacesReply = z.output<typeof listWorkspacesReplySchema>;
type ListWorkspacesWireRefusal = Extract<ListWorkspacesResult_Serialize, { result: 'refused' }>;
type ListWorkspacesWireResult =
	| Exclude<ListWorkspacesResult_Serialize, ListWorkspacesWireRefusal>
	| (ListWorkspacesWireRefusal & { reason: FleetAdminRefusalReason });

export const fleetAdminResultSchemas = {
	CreateWorkspace: z.union([
		z.strictObject({ result: z.literal('applied'), workspace: workspaceSchema }),
		refusedSchema,
	]),
	WorkspaceLookup: z.union([
		z.strictObject({ result: z.literal('found'), workspace: workspaceSchema.nullable() }),
		refusedSchema,
	]),
	ListWorkspaces: listWorkspacesReplySchema,
	ReadChangeRecords: z.union([
		z.strictObject({ result: z.literal('records'), records: z.array(changeRecordSchema) }),
		refusedSchema,
	]),
	...engineAdminResultSchemas,
} as const;
type GeneratedAdminRefusal = Extract<OrganizationAdminResult_Serialize, { result: 'refused' }>;
type SignInAdminWireResult =
	| Exclude<OrganizationAdminResult_Serialize, GeneratedAdminRefusal>
	| (GeneratedAdminRefusal & { reason: FleetAdminRefusalReason });
type AdminReplyFor<Results extends SignInAdminWireResult['result']> = Extract<
	SignInAdminWireResult,
	{ result: Results }
>;
export type FleetAdminResult = z.output<
	(typeof fleetAdminResultSchemas)[keyof typeof fleetAdminResultSchemas]
>;
type SignInWorkspaceId = z.output<typeof workspaceSchema>['workspaceId'];
type SignInAllowanceChange = Extract<
	z.output<typeof changeRecordSchema>,
	{ kind: 'machineAllowanceChanged' }
>;
type PlainWorkspaceIdMatches = WireTypesEqual<SignInWorkspaceId, string>;
// @ts-expect-error A validated workspace ID cannot leave the decoder as an unbranded string.
export type RejectUnbrandedWorkspaceId = AssertWireType<PlainWorkspaceIdMatches>;
export type FleetAdminIdTypes = [
	AssertWireType<WireTypesEqual<SignInWorkspaceId, Uuid7>>,
	AssertWireType<WireTypesEqual<z.output<typeof changeRecordSchema>['id'], Uuid7>>,
	AssertWireType<WireTypesEqual<SignInAllowanceChange['machineId'], Uuid7>>,
	AssertWireType<WireTypesEqual<SignInAllowanceChange['workspaceId'], Uuid7>>,
];
export type FleetAdminWireSchemaTypes = [
	AssertWireType<
		WireTypesEqual<z.output<typeof listWorkspacesWireReplySchema>, ListWorkspacesWireResult>
	>,
	AssertWireType<
		WireTypesEqual<z.input<typeof listWorkspacesReplySchema>, ListWorkspacesWireResult>
	>,
	AssertWireType<
		WireTypesEqual<
			NonNullable<Extract<ListWorkspacesReply, { result: 'workspaces' }>['next']>,
			Uuid7
		>
	>,
	AssertWireType<WireTypesEqual<z.output<typeof workspaceWireSchema>, WorkspaceView_Serialize>>,
	AssertWireType<
		WireTypesEqual<z.output<typeof fleetAdminRefusalReasonSchema>, FleetAdminRefusalReason>
	>,
	AssertWireType<
		WireTypesEqual<z.output<typeof targetedChangeKindSchema>, TargetedOrganizationChangeKind>
	>,
	AssertWireType<
		WireTypesEqual<z.output<typeof machineAllowanceStateSchema>, MachineAllowanceState>
	>,
	AssertWireType<
		WireTypesEqual<z.output<typeof changeRecordWireSchema>['kind'], OrganizationChangeKind>
	>,
	AssertWireType<
		WireTypesEqual<z.output<typeof organizationChangeOriginSchema>, OrganizationChangeOrigin>
	>,
	AssertWireType<WireTypesEqual<z.output<typeof changeRecordWireSchema>, OrganizationChangeRecord>>,
	AssertWireType<
		WireTypesEqual<
			z.input<(typeof fleetAdminResultSchemas)['CreateWorkspace']>,
			AdminReplyFor<'applied' | 'refused'>
		>
	>,
	AssertWireType<
		WireTypesEqual<
			z.input<(typeof fleetAdminResultSchemas)['WorkspaceLookup']>,
			AdminReplyFor<'found' | 'refused'>
		>
	>,
	AssertWireType<
		WireTypesEqual<
			z.input<(typeof fleetAdminResultSchemas)['ReadChangeRecords']>,
			AdminReplyFor<'records' | 'refused'>
		>
	>,
];

/**
 * Central's answer, or why there is none. 401 (any token or proof failure, empty body) and 400
 * (a body central could not parse: our defect, never retried) are their own outcomes.
 */
export type FleetAdminAnswer<TResult = FleetAdminResult> =
	| { readonly kind: 'answered'; readonly result: TResult }
	| { readonly kind: 'unauthenticated' }
	| { readonly kind: 'request-refused' }
	/**
	 * Central itself answered 503. Pinned central `e847a888` answers an unstamped store that way
	 * too (empty body, revealing nothing); only a digest read tells them apart (WS7 R-notdue).
	 */
	| { readonly kind: 'answered-unavailable' }
	| { readonly kind: 'unknown'; readonly reason: CentralLinkUncertainty };

export interface FleetAdminLinkClient {
	/**
	 * `signal`, when given, aborts the request on the link: WS7 R-retrysignal passes the run's
	 * deadline only on the retry after a recovery, never on the first send.
	 */
	readonly sendFleetAdminRequest: (props: {
		readonly operation: FleetAdminRequest;
		readonly accessToken: string;
		readonly proof: string;
		readonly signal?: AbortSignal;
	}) => Promise<FleetAdminAnswer>;
	/**
	 * The CLI's request, relayed unchanged: its own `Authorization`, `DPoP` and body bytes.
	 * Central verifies them; nothing here parses or re-encodes the body.
	 */
	readonly relayFleetAdminRequest: (props: {
		readonly operation: FleetAdminRequest['operation'];
		readonly authorization: string;
		readonly proof: string;
		readonly body: Uint8Array<ArrayBuffer>;
		readonly signal?: AbortSignal;
	}) => Promise<FleetAdminAnswer>;
}

export const revokeMachineEnrollmentPath = '/organization-admin/v1/revoke-machine-enrollment';
export type RevokeMachineEnrollment = (props: {
	readonly request: RevokeMachineEnrollmentRequest;
	readonly accessToken: string;
	readonly proof: string;
	readonly signal?: AbortSignal;
}) => Promise<FleetAdminAnswer<RevokeMachineEnrollmentResult>>;

/** A person's DPoP-carried request to one of central's link-only organization-admin routes. */
export interface CentralPersonPost {
	readonly path: string;
	readonly authorization: string;
	readonly proof: string;
	readonly body: string | Uint8Array<ArrayBuffer>;
	readonly signal?: AbortSignal;
}

/**
 * The one HTTP send every organization-admin route shares: central's response, or why there is
 * none. Each route family reads the response with its own reply rules.
 */
export async function postPersonRequestToCentral(
	transport: CentralTransport,
	props: CentralPersonPost,
): Promise<
	| { readonly kind: 'response'; readonly response: Response }
	| { readonly kind: 'unknown'; readonly reason: CentralLinkUncertainty }
> {
	try {
		const response = await transport.fetch(
			new Request(`http://central.invalid${props.path}`, {
				method: 'POST',
				headers: {
					'content-type': 'application/json',
					authorization: props.authorization,
					dpop: props.proof,
				},
				body: props.body,
				...(props.signal === undefined ? {} : { signal: props.signal }),
			}),
		);
		return { kind: 'response', response };
	} catch (error) {
		return {
			kind: 'unknown',
			reason: error instanceof Error && error.name === 'TimeoutError' ? 'timeout' : 'unavailable',
		};
	}
}

/** A non-200 answer that carries no result, in the shape every admin route reads. */
type FleetAdminStatusAnswer = Exclude<FleetAdminAnswer<never>, { readonly kind: 'answered' }>;

/** The workspace, change-record and revocation routes: 401, 400 and 503 keep their meaning. */
function adminStatusAnswer(status: number): FleetAdminStatusAnswer {
	if (status === 401) return { kind: 'unauthenticated' };
	if (status === 400) return { kind: 'request-refused' };
	if (status === 503) return { kind: 'answered-unavailable' };
	return { kind: 'unknown', reason: 'unavailable' };
}

/**
 * Each pre-admission row of central's engine table (`engine-admin-results.ts`), as sign-in reads
 * it. An oversized body and an unaddressable one are sign-in's own defect, never retried. The
 * relay only ever sends POST, so a 405 means the link does not reach central's engine route. An
 * empty 503 is central unavailable: no transaction outcome can be read from it.
 */
const enginePreflightAnswers = {
	oversizedUpload: { kind: 'request-refused' },
	methodNotPost: { kind: 'unknown', reason: 'unavailable' },
	missingProof: { kind: 'unauthenticated' },
	badOrganizationAddress: { kind: 'request-refused' },
	verificationFailed: { kind: 'unauthenticated' },
	unavailable: { kind: 'answered-unavailable' },
} as const satisfies Readonly<
	Record<keyof typeof engineAdminPreflightStatuses, FleetAdminStatusAnswer>
>;

function isEnginePreflightRow(name: string): name is keyof typeof engineAdminPreflightStatuses {
	return Object.hasOwn(engineAdminPreflightStatuses, name);
}

/** An engine route's non-200 status through the table; a status outside it is unknown. */
export function engineAdminStatusAnswer(status: number): FleetAdminStatusAnswer {
	for (const name of Object.keys(engineAdminPreflightStatuses))
		if (isEnginePreflightRow(name) && engineAdminPreflightStatuses[name].status === status)
			return enginePreflightAnswers[name];
	return { kind: 'unknown', reason: 'unavailable' };
}

/** One send per call; the admin routes travel the private link like every other central call. */
export function createFleetAdminLinkClient(
	transport: CentralTransport,
): FleetAdminLinkClient & { readonly revokeMachineEnrollment: RevokeMachineEnrollment } {
	async function send<TResult>(
		props: CentralPersonPost & {
			readonly resultSchema: z.ZodType<TResult>;
			readonly statusAnswer: (status: number) => FleetAdminStatusAnswer;
		},
	): Promise<FleetAdminAnswer<TResult>> {
		const posted = await postPersonRequestToCentral(transport, props);
		if (posted.kind === 'unknown') return posted;
		const { response } = posted;
		if (response.status !== 200) return props.statusAnswer(response.status);
		let payload: unknown;
		try {
			payload = await response.json();
		} catch {
			return { kind: 'unknown', reason: 'malformed-reply' };
		}
		const parsed = props.resultSchema.safeParse(payload);
		if (!parsed.success) return { kind: 'unknown', reason: 'malformed-reply' };
		return { kind: 'answered', result: parsed.data };
	}
	return {
		sendFleetAdminRequest: async (props) =>
			send<FleetAdminResult>({
				path: fleetAdminRoutePaths[props.operation.operation],
				resultSchema: fleetAdminResultSchemas[props.operation.operation],
				authorization: `DPoP ${props.accessToken}`,
				proof: props.proof,
				body: JSON.stringify(fleetAdminRequestBody(props.operation)),
				statusAnswer: isEngineAdminOperation(props.operation.operation)
					? engineAdminStatusAnswer
					: adminStatusAnswer,
				...(props.signal === undefined ? {} : { signal: props.signal }),
			}),
		relayFleetAdminRequest: async (props) =>
			send<FleetAdminResult>({
				...props,
				path: fleetAdminRoutePaths[props.operation],
				resultSchema: fleetAdminResultSchemas[props.operation],
				statusAnswer: isEngineAdminOperation(props.operation)
					? engineAdminStatusAnswer
					: adminStatusAnswer,
			}),
		revokeMachineEnrollment: async (props) =>
			send({
				path: revokeMachineEnrollmentPath,
				resultSchema: revokeMachineEnrollmentResultSchema,
				statusAnswer: adminStatusAnswer,
				authorization: `DPoP ${props.accessToken}`,
				proof: props.proof,
				body: JSON.stringify({
					organizationId: props.request.organizationId,
					enrollmentId: props.request.enrollmentId,
				} satisfies RevokeMachineWireRequest),
				...(props.signal === undefined ? {} : { signal: props.signal }),
			}),
	};
}
