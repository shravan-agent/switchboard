import { jsonFamily } from './request-family';

export const requestFamily = jsonFamily(
	'/api/auth/organization-admin/v1/engine-discard',
	(context) => ({
		organizationId: context.organizationId,
		operationId: context.challengeId,
		attemptId: context.challengeId,
	}),
);
