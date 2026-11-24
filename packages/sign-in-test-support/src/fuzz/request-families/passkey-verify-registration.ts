import * as generators from '@hegeldev/hegel/generators';

import {
	nestedRegistrationResponse,
	nestedRegistrationSteps,
} from './passkey-registration-mutations';
import {
	chooseStep,
	jsonFamily,
	type GeneratedRequest,
	type RequestFamily,
	type VariantStep,
} from './request-family';

const path = '/api/auth/passkey/verify-registration';
const registrationName = 'Security key';
const authenticatorDataHeaderBytes = 37;

const wholeBodyFamily = jsonFamily(path, (context) => ({
	response: context.passkeyRegistrationResponse,
	name: registrationName,
}));

/**
 * The route's top-level request mutations, plus the real credential with one nested member
 * changed at a time, so well-formed input that fails verification is reached (S2 no-5xx).
 */
export const requestFamily: RequestFamily = {
	...wholeBodyFamily,
	variantSteps: (context): readonly VariantStep[] => [
		...wholeBodyFamily.variantSteps(context),
		...nestedRegistrationSteps,
	],
	generate(testCase, context, given): GeneratedRequest {
		const step = chooseStep(
			testCase,
			[...wholeBodyFamily.variantSteps(context), ...nestedRegistrationSteps],
			given,
		);
		if (step.encoding !== 'json-nested') return wholeBodyFamily.generate(testCase, context, step);
		const response = nestedRegistrationResponse({
			credential: context.passkeyRegistrationResponse,
			step,
			drawnLength: testCase.draw(
				generators.integers({ minValue: 0, maxValue: authenticatorDataHeaderBytes - 1 }),
			),
		});
		return {
			pathname: path,
			init: {
				method: 'POST',
				headers: {
					'content-type': 'application/json',
					origin: new URL(context.issuer).origin,
				},
				body: JSON.stringify({ response, name: registrationName }),
			},
			label: `${step.encoding}:${step.mutation}:${step.field}`,
			variant: step,
			expectation: 'success-or-refusal',
		};
	},
};
