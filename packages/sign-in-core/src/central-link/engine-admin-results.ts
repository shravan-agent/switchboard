import type { AdminRefusal } from '#sign-in-core/central-link/generated/central-sign-in.gen';
import type { AssertWireType } from '#sign-in-core/central-link/wire-type-equality';
import type { EngineAdminOperationName } from '#sign-in-core/organizations/fleet-admin-operation';

// The HTTP status each engine reply and refusal arrives with, from central's decision table
// (`engine-admin-results.md` at codex-router 4593797b1, beside the vendored engine vectors).

/** How a refusal arrives: an empty body or transport text with a status, or the admin envelope. */
export type EngineAdminArrival =
	| { readonly status: 413; readonly body: 'transportText' }
	| { readonly status: 400 | 401 | 405 | 503; readonly body: 'empty' }
	| { readonly status: 200; readonly body: 'adminRefusal' };

/** Every admitted engine reply arrives with 200, keyed by its `result`. */
export const engineAdminReplyStatuses = {
	EngineHealth: { engineHealth: 200 },
	EngineListRetired: { engineRetired: 200 },
	EngineRetry: { engineRetried: 200 },
	EngineDiscard: { engineDiscarded: 200 },
} as const satisfies Readonly<Record<EngineAdminOperationName, Readonly<Record<string, 200>>>>;

/**
 * The matrix's "All four" rows before admission, each with nothing written. Central answers an
 * exact retained retry or discard at 200 with the original bytes, so a replay is never here.
 */
export const engineAdminPreflightStatuses = {
	/** An oversized POST with a valid organization address. */
	oversizedUpload: { status: 413, body: 'transportText' },
	/** Any method other than POST. */
	methodNotPost: { status: 405, body: 'empty' },
	/** The proof header is missing. */
	missingProof: { status: 401, body: 'empty' },
	/** The organization address is invalid. */
	badOrganizationAddress: { status: 400, body: 'empty' },
	/** The signed intent fails verification. */
	verificationFailed: { status: 401, body: 'empty' },
	/**
	 * Authorization storage is unavailable, a read's answer was lost after its proof committed, a
	 * repair's answer was lost before or after it applied, or an examined retired attempt has an
	 * invalid stored state. A 503 alone establishes no transaction outcome.
	 */
	unavailable: { status: 503, body: 'empty' },
} as const satisfies Readonly<Record<string, EngineAdminArrival>>;

/** Admission refusals every engine route can give, at 200 in `{"result":"refused","reason":…}`. */
const engineAdmissionRefusals = [
	'notPermitted',
	'refreshRequired',
	'authorizationSyncRequired',
	'expired',
	'requestTime',
	'requestReused',
] as const satisfies readonly AdminRefusal[];

/**
 * Each route's typed refusals. Health, retired and discard answer `conflict` when the applying
 * floor guard misses; retry answers `notFound` there instead. A change answers `conflict` for an
 * operation ID reused with another intent or actor. These routes never give `nameInUse` or
 * `rejected`, though both belong to the shared admin result type.
 */
export const engineAdminRefusalReasons = {
	EngineHealth: [...engineAdmissionRefusals, 'conflict'],
	EngineListRetired: [...engineAdmissionRefusals, 'conflict'],
	EngineRetry: [
		...engineAdmissionRefusals,
		'secondFactorRequired',
		'conflict',
		'notFound',
		'notRetired',
	],
	EngineDiscard: [
		...engineAdmissionRefusals,
		'secondFactorRequired',
		'conflict',
		'notFound',
		'notRetired',
		'discardUnsupported',
		'stale',
		'subjectUnreadable',
	],
} as const satisfies Readonly<Record<EngineAdminOperationName, readonly AdminRefusal[]>>;
export type EngineAdminRefusalReason<Operation extends EngineAdminOperationName> =
	(typeof engineAdminRefusalReasons)[Operation][number];

export type EngineAdminNeverRefuses = AssertWireType<
	Extract<
		EngineAdminRefusalReason<EngineAdminOperationName>,
		'nameInUse' | 'rejected'
	> extends never
		? true
		: false
>;

/** Every engine refusal arrives at 200 in the admin envelope. */
export const engineAdminRefusalArrival = {
	status: 200,
	body: 'adminRefusal',
} as const satisfies EngineAdminArrival;
