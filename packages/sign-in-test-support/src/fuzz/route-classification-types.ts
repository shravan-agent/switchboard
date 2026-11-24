import type { GeneratedRequest } from '#sign-in-test-support/fuzz/request-families/index';

export interface RouteIdentity {
	readonly method: string;
	readonly path: string;
}

export type RouteExposure =
	| 'signed-out'
	| 'member'
	| 'owner'
	| 'cli'
	| 'machine'
	| 'server-only'
	| 'blocked';
export type RequestPart = 'query' | 'form' | 'json';
export type PermittedRefusalEffect =
	| 'clear-current-choice'
	| 'callback-outcome'
	| 'none'
	| 'consume-passkey-challenge'
	| 'consume-passkey-registration-challenge'
	| 'factor-intent'
	| 'people-change-intent'
	| 'login-link-intent'
	| 'expired-session-cleanup'
	| 'oauth-code-consumption'
	| 'pending-device-poll'
	| 'provider-verification-consumption'
	| 'cookie-delete';

/** The configured social providers: the concrete callback routes below (sign-in-request-handler.ts). */
export const supportedSocialProviders = ['google', 'github'] as const;

export type RouteCaller = 'signed-out' | 'member' | 'owner';

/**
 * A status that is documented only together with its body and the conditions that produce it: the
 * exact set of body keys, the values the native error carries, the callers it is for, and the
 * request input (a changed field) that causes it. Missing any condition is not the documented answer.
 */
export interface DocumentedErrorBody {
	readonly values: Readonly<Record<string, unknown>>;
	readonly exactKeys: readonly string[];
	readonly callers?: readonly RouteCaller[];
	/**
	 * The actual request must be a JSON body whose string field is not one of the supported values:
	 * the input that causes the native refusal (not the generator's variant tag, and not null).
	 */
	readonly whenRequest?: {
		readonly jsonStringField: string;
		readonly notOneOf: readonly string[];
	};
}

/**
 * The answers a caller may get from a route for a request: its own list where the route names one.
 * A success (2xx) is documented only for a caller the route is exposed to (the owner stands for
 * the CLI on a CLI route, which the owner fixture exercises), and not for a request whose body
 * cannot be read (malformed, or the wrong content type) on a route that reads a JSON or form body.
 */
export function documentedAnswersFor(
	classification: Pick<
		RouteClassification,
		'documentedAnswers' | 'documentedAnswersByCaller' | 'exposure' | 'requestParts'
	>,
	caller: RouteCaller,
	request?: Pick<GeneratedRequest, 'variant'>,
	boundMachineRefresh = false,
): readonly number[] {
	const answers =
		classification.documentedAnswersByCaller?.[caller] ?? classification.documentedAnswers;
	const exposed =
		classification.exposure.includes(caller) ||
		(caller === 'owner' && classification.exposure.includes('cli')) ||
		(boundMachineRefresh &&
			classification.exposure.includes('machine') &&
			request?.variant.flow === 'machine-refresh');
	const bodyUnreadable =
		request !== undefined &&
		['malformed', 'wrong-content-type'].includes(request.variant.encoding) &&
		classification.requestParts.some((part) => part === 'json' || part === 'form');
	return exposed && !bodyUnreadable
		? answers
		: answers.filter((status) => status < 200 || status >= 300);
}

export interface RouteClassification extends RouteIdentity {
	readonly exposure: readonly RouteExposure[];
	readonly requestParts: readonly RequestPart[];
	readonly documentedAnswers: readonly number[];
	readonly disclosure: string;
	readonly permittedRefusalEffects: readonly PermittedRefusalEffect[];
	readonly evidence: string;
	readonly providerServerOnly?: boolean;
	/** Fields the body of a native error answer must carry; the only way a 5xx or 404 is documented. */
	readonly documentedErrorBodies?: Readonly<Record<number, DocumentedErrorBody>>;
	/** Statuses whose refusal may be an HTML page (a documented page refusal), not a generic JSON error. */
	readonly htmlRefusals?: readonly number[];
	readonly deviceDecisionRefusal?: 'approve' | 'deny';
	/** Where a caller may get fewer answers than the route-wide list, its own list. */
	readonly documentedAnswersByCaller?: Readonly<Partial<Record<RouteCaller, readonly number[]>>>;
}

export type ReachableRouteGroup = Omit<RouteClassification, 'path' | 'method'> & {
	readonly method: 'GET' | 'POST';
	readonly paths: readonly string[];
};
