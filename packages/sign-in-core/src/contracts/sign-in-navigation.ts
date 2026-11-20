import { z } from 'zod';

import { organizationChoiceSchema } from '#sign-in-core/contracts/organization-membership';

export const organizationPeoplePermission = 'organization:view';
export const signedInNavigationRoutes = [
	{ path: '/me', label: 'Me', permission: 'person' },
	{ path: '/people', label: 'People', permission: organizationPeoplePermission },
] as const;
export const signedInNavigationPathSchema = z.enum(
	signedInNavigationRoutes.map((route) => route.path),
);
export type SignedInNavigationPath = z.infer<typeof signedInNavigationPathSchema>;
export function isSignedInNavigationPath(pathname: string): pathname is SignedInNavigationPath {
	return signedInNavigationRoutes.some((route) => route.path === pathname);
}
export const switchboardSignOutPath = '/api/auth/switchboard/sign-out';
export const signOutFailureMessage = "Couldn't sign you out; try again";

export const signedInNavigationStateSchema = z.strictObject({
	page: signedInNavigationPathSchema,
	destinations: z.array(signedInNavigationPathSchema).readonly(),
	activeOrganization: organizationChoiceSchema,
	choices: z.array(organizationChoiceSchema).readonly(),
	showOrganizationAdmin: z.boolean(),
});
export type SignedInNavigationState = z.infer<typeof signedInNavigationStateSchema>;
