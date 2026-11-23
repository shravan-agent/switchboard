import { z } from 'zod';

import type {
	AdminOperationId,
	ApprovalIntent_Serialize,
	CreateWorkspaceRequest_Deserialize,
	ListWorkspacesRequest_Deserialize,
	ListWorkspacesRequest_Serialize,
	OrganizationAdminIntent_Serialize,
	OrganizationId,
	ReadChangeRecordsRequest_Deserialize,
	ReadChangeRecordsRequest_Serialize,
	WorkspaceLookupRequest,
} from '#sign-in-core/central-link/generated/central-sign-in.gen';
import type { AssertWireType, WireTypesEqual } from '#sign-in-core/central-link/wire-type-equality';
import { canonicalJson, type CanonicalJsonValue } from '#sign-in-core/contracts/canonical-json';
import {
	centralUuid7Schema,
	fleetAdminWorkspaceNameSchema,
	listWorkspacesIntent,
	listWorkspacesPath,
	listWorkspacesRequestBody,
	listWorkspacesRequestSchema,
} from '#sign-in-core/contracts/fleet-admin-wire';
import type { SignInCrypto } from '#sign-in-core/contracts/sign-in-platform';

export { fleetAdminWorkspaceNameSchema } from '#sign-in-core/contracts/fleet-admin-wire';

// Central's published admin wire (codex-router 7fb2de88a, `contracts/*Request.schema.json`,
// vendored in `contract-fixtures/central-organization-admin/`): closed bodies, routes and the
// T06 signed intent. Central refuses, never trims, a body outside these rules.
export const fleetAdminRequestSchema = z.discriminatedUnion('operation', [
	z.strictObject({
		operation: z.literal('CreateWorkspace'),
		organizationId: centralUuid7Schema,
		/** Chosen once by the page and kept on every retry; central's ledger key. */
		operationId: centralUuid7Schema,
		name: fleetAdminWorkspaceNameSchema,
		description: z
			.string()
			.refine((text) => utf8ByteLength(text) <= 2048, 'A description is at most 2048 bytes'),
	}),
	z.strictObject({
		operation: z.literal('WorkspaceLookup'),
		organizationId: centralUuid7Schema,
		workspaceId: centralUuid7Schema,
	}),
	listWorkspacesRequestSchema,
	z.strictObject({
		operation: z.literal('ReadChangeRecords'),
		organizationId: centralUuid7Schema,
		/** The last record ID of the previous page; null for the first. */
		after: z.uuid().nullable(),
		limit: z.number().int().min(1).max(100),
	}),
	// DEL-07: central's engine administration bodies (4593797b1, admin_operations.rs:199-226).
	// Every ID is a canonical lowercase UUIDv7: the form central's `uuid::Uuid` serializes back
	// into the signed intent, so the bytes sign-in signs are the bytes central rebuilds.
	z.strictObject({
		operation: z.literal('EngineHealth'),
		organizationId: centralUuid7Schema,
	}),
	z.strictObject({
		operation: z.literal('EngineListRetired'),
		organizationId: centralUuid7Schema,
		/** The previous page's `next`, even when its items were empty; null starts a walk. */
		after: centralUuid7Schema.nullable(),
		limit: z.number().int().min(1).max(100),
	}),
	z.strictObject({
		operation: z.literal('EngineRetry'),
		organizationId: centralUuid7Schema,
		/** Minted once per command and kept on its resend; central's receipt key. */
		operationId: centralUuid7Schema,
		attemptId: centralUuid7Schema,
	}),
	z.strictObject({
		operation: z.literal('EngineDiscard'),
		organizationId: centralUuid7Schema,
		operationId: centralUuid7Schema,
		attemptId: centralUuid7Schema,
	}),
]);

/** The four engine operations central's admin wire carries since 4593797b1. */
export const engineAdminOperationNames = [
	'EngineHealth',
	'EngineListRetired',
	'EngineRetry',
	'EngineDiscard',
] as const;
export type EngineAdminOperationName = (typeof engineAdminOperationNames)[number];
export function isEngineAdminOperation(operation: string): operation is EngineAdminOperationName {
	return engineAdminOperationNames.some((engine) => engine === operation);
}
/** An engine operation's signed intent params, as central's generated intent names them. */
type EngineIntentParams<Operation extends EngineAdminOperationName> = Extract<
	OrganizationAdminIntent_Serialize,
	{ operation: Operation }
>['params'];
/**
 * Central exports no request type for the engine bodies (`EngineHealthRequest`,
 * `EngineListRetiredRequest` and `EngineAttemptRequest` derive no specta type), so each body is
 * the organization address, the operation ID for a change, and the generated intent's params:
 * exactly the fields central decodes into that intent.
 */
type EngineWireBodies = {
	EngineHealth: { organizationId: OrganizationId };
	EngineListRetired: { organizationId: OrganizationId } & EngineIntentParams<'EngineListRetired'>;
	EngineRetry: {
		organizationId: OrganizationId;
		operationId: AdminOperationId;
	} & EngineIntentParams<'EngineRetry'>;
	EngineDiscard: {
		organizationId: OrganizationId;
		operationId: AdminOperationId;
	} & EngineIntentParams<'EngineDiscard'>;
};
type FleetAdminWireBodies = {
	CreateWorkspace: CreateWorkspaceRequest_Deserialize;
	WorkspaceLookup: WorkspaceLookupRequest;
	ListWorkspaces: ListWorkspacesRequest_Deserialize;
	ReadChangeRecords: ReadChangeRecordsRequest_Deserialize;
} & EngineWireBodies;
type FleetAdminRequestBodies = Omit<
	FleetAdminWireBodies,
	'ReadChangeRecords' | 'ListWorkspaces'
> & {
	// A local Zod input may carry undefined. The body builder omits either field in that case.
	ListWorkspaces: Omit<FleetAdminWireBodies['ListWorkspaces'], 'after' | 'limit'> & {
		after?: FleetAdminWireBodies['ListWorkspaces']['after'];
		limit?: FleetAdminWireBodies['ListWorkspaces']['limit'];
	};
	ReadChangeRecords: Required<FleetAdminWireBodies['ReadChangeRecords']>;
};
export type FleetAdminRequest = {
	[Operation in keyof FleetAdminRequestBodies]: {
		operation: Operation;
	} & FleetAdminRequestBodies[Operation];
}[keyof FleetAdminRequestBodies];
export type FleetAdminRequestWireType = AssertWireType<
	WireTypesEqual<z.output<typeof fleetAdminRequestSchema>, FleetAdminRequest>
>;
export type FleetAdminOutgoingPhases = [
	AssertWireType<
		WireTypesEqual<FleetAdminWireBodies['CreateWorkspace'], CreateWorkspaceRequest_Deserialize>
	>,
	AssertWireType<WireTypesEqual<FleetAdminWireBodies['WorkspaceLookup'], WorkspaceLookupRequest>>,
	AssertWireType<
		WireTypesEqual<FleetAdminWireBodies['ListWorkspaces'], ListWorkspacesRequest_Deserialize>
	>,
	AssertWireType<
		WireTypesEqual<FleetAdminWireBodies['ReadChangeRecords'], ReadChangeRecordsRequest_Deserialize>
	>,
];
type ReadChangeRecordsSerializerMatches = WireTypesEqual<
	ReadChangeRecordsRequest_Serialize,
	FleetAdminWireBodies['ReadChangeRecords']
>;
// @ts-expect-error The producer's serializer requires after; its request decoder permits omission.
export type RejectReadChangeRecordsSerializer = AssertWireType<ReadChangeRecordsSerializerMatches>;

export type ListWorkspacesOutgoingPhase = AssertWireType<
	WireTypesEqual<ReturnType<typeof listWorkspacesRequestBody>, ListWorkspacesRequest_Deserialize>
>;
type ListWorkspacesSerializerMatches = WireTypesEqual<
	ReturnType<typeof listWorkspacesRequestBody>,
	ListWorkspacesRequest_Serialize
>;
// @ts-expect-error ListWorkspaces requests may omit after and limit; the serializer includes both.
export type RejectListWorkspacesSerializer = AssertWireType<ListWorkspacesSerializerMatches>;

function utf8ByteLength(text: string): number {
	return new TextEncoder().encode(text).length;
}

export const fleetAdminRoutePaths = {
	CreateWorkspace: '/organization-admin/v1/create-workspace',
	WorkspaceLookup: '/organization-admin/v1/workspace-lookup',
	ListWorkspaces: listWorkspacesPath,
	ReadChangeRecords: '/organization-admin/v1/change-records',
	EngineHealth: '/organization-admin/v1/engine-health',
	EngineListRetired: '/organization-admin/v1/engine-retired',
	EngineRetry: '/organization-admin/v1/engine-retry',
	EngineDiscard: '/organization-admin/v1/engine-discard',
} as const satisfies Record<FleetAdminRequest['operation'], string>;

/** The closed JSON body central parses for the route; the body never names its operation. */
export function fleetAdminRequestBody(operation: FleetAdminRequest): CanonicalJsonValue {
	switch (operation.operation) {
		case 'CreateWorkspace':
			return {
				organizationId: operation.organizationId,
				operationId: operation.operationId,
				name: operation.name,
				description: operation.description,
			} satisfies FleetAdminWireBodies['CreateWorkspace'];
		case 'WorkspaceLookup':
			return {
				organizationId: operation.organizationId,
				workspaceId: operation.workspaceId,
			} satisfies FleetAdminWireBodies['WorkspaceLookup'];
		case 'ListWorkspaces':
			return listWorkspacesRequestBody(operation);
		case 'ReadChangeRecords':
			return {
				organizationId: operation.organizationId,
				after: operation.after,
				limit: operation.limit,
			} satisfies FleetAdminWireBodies['ReadChangeRecords'];
		case 'EngineHealth':
			return {
				organizationId: operation.organizationId,
			} satisfies EngineWireBodies['EngineHealth'];
		case 'EngineListRetired':
			return {
				organizationId: operation.organizationId,
				after: operation.after,
				limit: operation.limit,
			} satisfies EngineWireBodies['EngineListRetired'];
		case 'EngineRetry':
		case 'EngineDiscard':
			return {
				organizationId: operation.organizationId,
				operationId: operation.operationId,
				attemptId: operation.attemptId,
			} satisfies EngineWireBodies['EngineRetry' | 'EngineDiscard'];
		default:
			return unreachableOperation(operation);
	}
}

/** T06: `{v:1, operation, organization, target, operationId, params}`, params holding every effect field. */
export function fleetAdminIntent(
	operation: FleetAdminRequest,
): Extract<OrganizationAdminIntent_Serialize, { operation: FleetAdminRequest['operation'] }> {
	const organization = operation.organizationId;
	switch (operation.operation) {
		case 'CreateWorkspace':
			return {
				v: 1,
				operation: operation.operation,
				organization,
				target: organization,
				operationId: operation.operationId,
				params: { name: operation.name, description: operation.description },
			} satisfies OrganizationAdminIntent_Serialize;
		case 'WorkspaceLookup':
			return {
				v: 1,
				operation: operation.operation,
				organization,
				target: operation.workspaceId,
				operationId: null,
				params: {},
			} satisfies OrganizationAdminIntent_Serialize;
		case 'ListWorkspaces':
			return listWorkspacesIntent(operation);
		case 'ReadChangeRecords':
			return {
				v: 1,
				operation: operation.operation,
				organization,
				target: organization,
				operationId: null,
				params: { after: operation.after, limit: operation.limit },
			} satisfies OrganizationAdminIntent_Serialize;
		// Central's `AdminOperation::intent` (admin_operations.rs:701-736 at 4593797b1): every
		// engine intent targets the organization; only retry and discard carry an operation ID.
		case 'EngineHealth':
			return {
				v: 1,
				operation: operation.operation,
				organization,
				target: organization,
				operationId: null,
				params: {},
			} satisfies OrganizationAdminIntent_Serialize;
		case 'EngineListRetired':
			return {
				v: 1,
				operation: operation.operation,
				organization,
				target: organization,
				operationId: null,
				params: { after: operation.after, limit: operation.limit },
			} satisfies OrganizationAdminIntent_Serialize;
		case 'EngineRetry':
			return {
				v: 1,
				operation: operation.operation,
				organization,
				target: organization,
				operationId: operation.operationId,
				params: { attemptId: operation.attemptId },
			} satisfies OrganizationAdminIntent_Serialize;
		case 'EngineDiscard':
			return {
				v: 1,
				operation: operation.operation,
				organization,
				target: organization,
				operationId: operation.operationId,
				params: { attemptId: operation.attemptId },
			} satisfies OrganizationAdminIntent_Serialize;
		default:
			return unreachableOperation(operation);
	}
}

/** Every intent a person's proof signs for central: the admin operations and C3's approvals. */
export type CentralSignedIntent = OrganizationAdminIntent_Serialize | ApprovalIntent_Serialize;
/** T06's frame, which C3 reuses: `{v:1, operation, organization, target, operationId, params}`. */
interface CentralSignedIntentFrame {
	readonly v: 1;
	readonly operation: string;
	readonly organization: string;
	readonly target: string;
	readonly operationId: string | null;
	readonly params: CanonicalJsonValue;
}
/** Per arm: it fits the frame and carries no field beyond it. */
type IntentArmFitsFrame<Arm> = Arm extends CentralSignedIntentFrame
	? [Exclude<keyof Arm, keyof CentralSignedIntentFrame>] extends [never]
		? true
		: false
	: false;
export type CentralSignedIntentFrameCheck = AssertWireType<
	false extends IntentArmFitsFrame<CentralSignedIntent> ? false : true
>;

/** The proof's `intent` claim: base64url(SHA-256(RFC 8785 JCS(intent))). */
export async function centralSignedIntentDigest(
	crypto: SignInCrypto,
	intent: CentralSignedIntent,
): Promise<string> {
	return base64UrlSha256(crypto, canonicalJson(intent));
}

export async function fleetAdminIntentDigest(
	crypto: SignInCrypto,
	operation: FleetAdminRequest,
): Promise<string> {
	return centralSignedIntentDigest(crypto, fleetAdminIntent(operation));
}

/** base64url without padding, as central's `sha256_url`. */
export async function base64UrlSha256(crypto: SignInCrypto, text: string): Promise<string> {
	const digest = new Uint8Array(
		await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)),
	);
	let binary = '';
	for (const byte of digest) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function unreachableOperation(_operation: never): never {
	throw new Error('Unknown Fleet admin operation');
}
