import * as hegel from '@hegeldev/hegel';
import { describe, expect, it } from 'vitest';

import { fuzzSettingsExact } from '#sign-in-test-support/fuzz/fuzz-settings';
import {
	requestFamilies,
	type GeneratedRequest,
	type RequestFamily,
	type VariantStep,
} from '#sign-in-test-support/fuzz/request-families/index';
import { variantKey } from '#sign-in-test-support/fuzz/request-families/request-family';
import { syntheticRequestFamilyContext } from '#sign-in-test-support/fuzz/request-families/synthetic-context';

const context = syntheticRequestFamilyContext;

/** Generate one request per call, in a Hegel run closed over `step` (the way the live driver does). */
function generateOnce(family: RequestFamily, step: VariantStep | undefined): GeneratedRequest {
	let generated: GeneratedRequest | undefined;
	hegel.test((testCase): void => {
		generated = family.generate(testCase, context, step);
	}, fuzzSettingsExact(1));
	if (generated === undefined) throw new Error('No request generated');
	return generated;
}

function randomVariantKeys(family: RequestFamily, draws: number): ReadonlySet<string> {
	const seen = new Set<string>();
	hegel.test((testCase): void => {
		seen.add(variantKey(family.generate(testCase, context).variant));
	}, fuzzSettingsExact(draws));
	return seen;
}

/** The named fields a request carries, by how it is encoded; null for a field set to null. */
function fieldsOf(request: GeneratedRequest): Readonly<Record<string, string | null>> | undefined {
	const body = typeof request.init.body === 'string' ? request.init.body : '';
	const contentType = new Headers(request.init.headers).get('content-type') ?? '';
	if (request.init.method === 'GET')
		return Object.fromEntries(new URL(request.pathname, 'http://host.invalid').searchParams);
	if (contentType.startsWith('application/json')) {
		try {
			const parsed: unknown = JSON.parse(body);
			if (typeof parsed !== 'object' || parsed === null) return undefined;
			// Typed: each value is its JSON text, so the string "false" differs from the boolean false.
			return Object.fromEntries(
				Object.entries(parsed).map(([key, value]) => [key, JSON.stringify(value)]),
			);
		} catch {
			return undefined;
		}
	}
	if (contentType.startsWith('application/x-www-form-urlencoded'))
		return Object.fromEntries(new URLSearchParams(body));
	return undefined;
}

/** Every variant family is distinct, and what the pass builds for each step says it is that step. */
function assertPassMatchesWhatIsBuilt(family: RequestFamily): readonly GeneratedRequest[] {
	const steps = family.variantSteps(context);
	const keys = steps.map(variantKey);
	// Distinct (encoding, field and mutation all count): no collapsing.
	expect(new Set(keys).size).toBe(keys.length);
	const built = steps.map((step) => generateOnce(family, step));
	expect(built.map((request) => variantKey(request.variant)).toSorted()).toEqual(keys.toSorted());
	built.forEach((request, index) => {
		expect(request.variant).toEqual(steps[index]);
	});
	return built;
}

function assertChangedFields(
	validFields: Readonly<Record<string, string | null>>,
	fields: Readonly<Record<string, string | null>>,
	step: VariantStep,
): void {
	const changed = Object.keys({ ...validFields, ...fields }).filter(
		(name) => validFields[name] !== fields[name],
	);
	if (step.mutation === 'valid') expect(changed).toEqual([]);
	else if (step.field !== null) expect(changed).toEqual([step.field]);
	else expect(changed).toEqual(['unexpected']);
}

/**
 * Each request really is its variant family, read from the request itself, not its label: the wire
 * body of every field-carrying encoding (JSON, form, query) is parsed and exactly the named field
 * (or, for the valid request, none) differs from the valid fields; transports are what they say.
 */
function assertRequestsAreTheirVariants(built: readonly GeneratedRequest[]): void {
	// The valid fields of each encoding (a JSON body is compared with the valid JSON body).
	const validFieldsOf = (step: VariantStep): ReturnType<typeof fieldsOf> => {
		const valid = built.find(
			(request) =>
				request.variant.encoding === step.encoding &&
				request.variant.flow === step.flow &&
				request.variant.mutation === 'valid',
		);
		return valid === undefined ? undefined : fieldsOf(valid);
	};
	for (const request of built) {
		const step = request.variant;
		const fields = fieldsOf(request);
		const contentType = new Headers(request.init.headers).get('content-type') ?? '';
		if (step.encoding === 'wrong-content-type') {
			// Planned: a valid-looking body under a text/plain media type, nothing else.
			expect(contentType).toBe('text/plain');
			expect(request.init.body, `${variantKey(step)} keeps its planned body`).toBeTypeOf('string');
			continue;
		}
		if (step.encoding === 'malformed') {
			// Planned: exactly an unclosed JSON object under application/json, not any unparsable input.
			expect(contentType).toBe('application/json');
			expect(request.init.body).toBe('{');
			expect(fields).toBeUndefined();
			continue;
		}
		if (step.encoding === 'json-nested') {
			// A nested change leaves every other body field alone and changes the credential inside `response`.
			expect(contentType).toContain('application/json');
			const validJson = validFieldsOf({
				...step,
				encoding: 'json',
				field: null,
				mutation: 'valid',
			});
			expect(validJson, 'the valid json request to compare with').toBeDefined();
			if (validJson !== undefined && fields !== undefined)
				expect(
					Object.keys({ ...validJson, ...fields }).filter(
						(name) => validJson[name] !== fields[name],
					),
				).toEqual(['response']);
			continue;
		}
		// An encoding is what the wire says it is.
		if (step.encoding === 'json') expect(contentType).toContain('application/json');
		if (step.encoding === 'form')
			expect(contentType).toContain('application/x-www-form-urlencoded');
		if (step.encoding === 'query') expect(request.init.method).toBe('GET');
		expect(fields, `${variantKey(step)} has a body to read`).toBeDefined();
		const validFields = validFieldsOf(step);
		expect(validFields, `${step.encoding} has a valid request to compare with`).toBeDefined();
		if (validFields !== undefined && fields !== undefined)
			assertChangedFields(validFields, fields, step);
	}
}

/**
 * The encoding x field x mutation inventory of a route, written here from the route's own kind and
 * the field names on its valid request's wire, not built from the step constructors the schedules use.
 */
const independentMutations = ['near-valid', 'boundary', 'wrong-type'] as const;
/** Form routes that also accept a JSON body; authorize takes a form only. */
const formAndJsonRoutes = new Set([
	'/api/auth/callback/google',
	'/api/auth/callback/github',
	'/api/auth/device/code',
	'/api/auth/machine-login/deny',
	'/api/auth/oauth2/revoke',
]);
const formOnlyRoutes = new Set(['/api/auth/oauth2/authorize']);

function machineTokenInventory(flow: string, fields: readonly string[]): readonly string[] {
	return [
		...['form', 'json'].flatMap((encoding) => [
			`${encoding}|-|valid|${flow}`,
			...fields.flatMap((field) =>
				independentMutations.map((mutation) => `${encoding}|${field}|${mutation}|${flow}`),
			),
		]),
		`malformed|-|valid|${flow}`,
		`wrong-content-type|-|valid|${flow}`,
	];
}

/** The nested members of a real registration credential, changed one at a time (written out, not derived). */
const nestedRegistrationInventory: readonly string[] = [
	'json-nested|clientDataJSON.challenge|near-valid',
	'json-nested|clientDataJSON.origin|near-valid',
	'json-nested|clientDataJSON.type|wrong-type',
	'json-nested|attestationObject.fmt|near-valid',
	'json-nested|attestationObject.fmt|wrong-type',
	'json-nested|attestationObject.attStmt|near-valid',
	'json-nested|attestationObject.attStmt|boundary',
	'json-nested|attestationObject.authData|boundary',
	'json-nested|attestationObject.authData.flags|near-valid',
	'json-nested|attestationObject.authData.flags|boundary',
	'json-nested|attestationObject.authData.rpIdHash|near-valid',
	'json-nested|attestationObject.authData.credentialPublicKey|wrong-type',
	'json-nested|attestationObject.authData.credentialPublicKey|near-valid',
];

function independentInventory(family: RequestFamily): readonly string[] {
	const path = family.route.path;
	const method = family.route.method;
	const primary: string =
		method === 'GET'
			? 'query'
			: formAndJsonRoutes.has(path) || formOnlyRoutes.has(path)
				? 'form'
				: 'json';
	const acceptsJsonToo = method === 'POST' && formAndJsonRoutes.has(path);
	if (path === '/api/auth/oauth2/token')
		return [
			'form|-|valid',
			'form|grant_type|unsupported-grant',
			'wrong-content-type|-|valid',
			...['client_id', 'code', 'code_verifier', 'redirect_uri', 'resource'].flatMap((field) => [
				`form|${field}|near-valid`,
				`form|${field}|boundary`,
			]),
			...machineTokenInventory('machine-device', ['grant_type', 'client_id', 'device_code']),
			...machineTokenInventory('machine-refresh', ['grant_type', 'client_id', 'refresh_token']),
		].toSorted();
	if (path === '/api/auth/oauth2/introspect')
		return [
			'form|-|valid',
			'form|token|near-valid',
			'form|token|boundary',
			'wrong-content-type|-|valid',
		].toSorted();
	const valid = generateOnce(family, family.variantSteps(context)[0]);

	const names = Object.keys(fieldsOf(valid) ?? {});
	const fieldCases = (encoding: string): string[] => [
		`${encoding}|-|valid`,
		...(names.length === 0
			? independentMutations.map((mutation) => `${encoding}|-|${mutation}`)
			: names.flatMap((field) =>
					independentMutations.map((mutation) => `${encoding}|${field}|${mutation}`),
				)),
	];
	return [
		...(path === '/api/auth/passkey/verify-registration' ? nestedRegistrationInventory : []),
		...fieldCases(primary),
		...(acceptsJsonToo ? [...fieldCases('json'), 'malformed|-|valid'] : []),
		...(primary === 'json' ? ['malformed|-|valid'] : []),
		...(method === 'POST' ? ['wrong-content-type|-|valid'] : []),
	].toSorted();
}

/** Both schedules, the coverage plan and what random draws produce, equal the independent inventory. */
function assertSchedulesEqualInventory(family: RequestFamily): void {
	const inventory = independentInventory(family);
	expect(family.variantSteps(context).map(variantKey).toSorted(), 'coverage plan').toEqual(
		inventory,
	);
	expect([...randomVariantKeys(family, 4000)].toSorted(), 'random generator').toEqual(inventory);
}

/** Nothing random draws can produce is missing from the pass. */
function assertRandomDrawsStayInsidePass(family: RequestFamily): void {
	const keys = family.variantSteps(context).map(variantKey);
	const reachable = randomVariantKeys(family, 3000);
	expect([...reachable].filter((key) => !keys.includes(key))).toEqual([]);
}

function assertFamilyIsProved(family: RequestFamily): void {
	assertSchedulesEqualInventory(family);
	assertRequestsAreTheirVariants(assertPassMatchesWhatIsBuilt(family));
	assertRandomDrawsStayInsidePass(family);
}

for (const family of requestFamilies) {
	it(`${family.route.method} ${family.route.path}: the coverage pass is exactly its variant families, each built as it says`, (): void => {
		assertFamilyIsProved(family);
	});
}

const callbackFamily = ((): RequestFamily => {
	const found = requestFamilies.find(
		(candidate) =>
			candidate.route.path === '/api/auth/callback/google' && candidate.route.method === 'POST',
	);
	if (found === undefined) throw new Error('callback family missing');
	return found;
})();

it('a dual-encoding form family plans field mutations under JSON as well as under the form (the reach random generation had)', (): void => {
	const keys = callbackFamily.variantSteps(context).map(variantKey);
	for (const encoding of ['form', 'json'])
		for (const mutation of ['near-valid', 'boundary', 'wrong-type'])
			expect(
				keys.some((key) => key.startsWith(`${encoding}|`) && key.endsWith(`|${mutation}`)),
			).toBe(true);
});

it('wrong builds are caught: unchanged valid JSON labelled as a field mutation, and a pass that drops a variant family', (): void => {
	const mutationStep = callbackFamily
		.variantSteps(context)
		.find((step) => step.encoding === 'json' && step.mutation === 'near-valid');
	if (mutationStep === undefined) throw new Error('no JSON mutation step in the callback plan');
	const validStep = callbackFamily
		.variantSteps(context)
		.find((step) => step.encoding === 'json' && step.mutation === 'valid');
	if (validStep === undefined) throw new Error('no JSON valid step in the callback plan');
	// Wrong build 1: the JSON field mutation returns the valid JSON body unchanged, still labelled.
	const labelsValidAsMutation: RequestFamily = {
		...callbackFamily,
		generate: (testCase, ctx, step): GeneratedRequest => {
			const request = callbackFamily.generate(
				testCase,
				ctx,
				step !== undefined && variantKey(step) === variantKey(mutationStep) ? validStep : step,
			);
			return step === undefined ? request : { ...request, variant: step };
		},
	};
	expect(() =>
		assertRequestsAreTheirVariants(assertPassMatchesWhatIsBuilt(labelsValidAsMutation)),
	).toThrow();
	// Wrong build 2: the pass drops one variant family that random draws still reach.
	const dropsOne: RequestFamily = {
		...callbackFamily,
		variantSteps: (ctx) => callbackFamily.variantSteps(ctx).slice(1),
	};
	expect(() => assertRandomDrawsStayInsidePass(dropsOne)).toThrow();
	// The real family passes the same checks.
	expect(() => assertFamilyIsProved(callbackFamily)).not.toThrow();
});

describe('B4 closure: independent inventory, token fields, and the planned malformed input', (): void => {
	const tokenFamily = ((): RequestFamily => {
		const found = requestFamilies.find(
			(candidate) => candidate.route.path === '/api/auth/oauth2/token',
		);
		if (found === undefined) throw new Error('token family missing');
		return found;
	})();

	/** The same case removed from the coverage plan AND from what random draws produce. */
	function dropsFromBoth(family: RequestFamily, dropped: string): RequestFamily {
		const fallback = family.variantSteps(context)[0];
		if (fallback === undefined) throw new Error('empty plan');
		return {
			...family,
			variantSteps: (ctx) =>
				family.variantSteps(ctx).filter((step) => variantKey(step) !== dropped),
			generate: (testCase, ctx, step) => {
				const request = family.generate(testCase, ctx, step);
				return variantKey(request.variant) === dropped && step === undefined
					? family.generate(testCase, ctx, fallback)
					: request;
			},
		};
	}

	it('fails when the same case is missing from both the plan and the random generator', (): void => {
		const dropped = 'form|code_verifier|boundary';
		expect(tokenFamily.variantSteps(context).map(variantKey)).toContain(dropped);
		expect(() => assertFamilyIsProved(dropsFromBoth(tokenFamily, dropped))).toThrow();
	});

	it('accepts only the malformed input it planned, not any unparsable wire input', (): void => {
		const planned = callbackFamily
			.variantSteps(context)
			.find((step) => step.encoding === 'malformed');
		if (planned === undefined) throw new Error('no malformed step');
		// A wrong build: the "malformed" step sends no body under another media type, which is also
		// unparsable but is not the malformed JSON it planned.
		const sendsAnotherUnparsableInput: RequestFamily = {
			...callbackFamily,
			generate: (testCase, ctx, step) => {
				const request = callbackFamily.generate(testCase, ctx, step);
				return request.variant.encoding === 'malformed'
					? {
							...request,
							init: { method: 'POST', headers: { 'content-type': 'application/octet-stream' } },
						}
					: request;
			},
		};
		expect(() =>
			assertRequestsAreTheirVariants(assertPassMatchesWhatIsBuilt(sendsAnotherUnparsableInput)),
		).toThrow();
	});
});

it('the token request has five near-valid and five boundary field mutations, one family each (independent of the plan builder)', (): void => {
	const family = requestFamilies.find(
		(candidate) => candidate.route.path === '/api/auth/oauth2/token',
	);
	if (family === undefined) throw new Error('token family missing');
	const keys = family.variantSteps(context).map(variantKey);
	for (const field of ['client_id', 'code', 'code_verifier', 'redirect_uri', 'resource'])
		for (const mutation of ['near-valid', 'boundary'])
			expect(keys.filter((key) => key === `form|${field}|${mutation}`)).toHaveLength(1);
	expect(keys.filter((key) => key.endsWith('|near-valid'))).toHaveLength(5);
	expect(keys.filter((key) => key.endsWith('|boundary'))).toHaveLength(5);
});
