import { jsonFamily } from './request-family';

export const requestFamily = jsonFamily(
	'/api/auth/organization-admin/v1/engine-health',
	(context) => ({ organizationId: context.organizationId }),
);
