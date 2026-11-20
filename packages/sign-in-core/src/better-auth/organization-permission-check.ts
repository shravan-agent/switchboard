import { hasPermission } from 'better-auth/plugins/organization';

import {
	organizationAccessControl,
	organizationRoles,
} from '#sign-in-core/better-auth/organization-access-control';
import type { OrganizationChoice } from '#sign-in-core/contracts/organization-membership';
import type { FleetPermission } from '#sign-in-core/organizations/fleet-permission';
import type { SignInStoreResult } from '#sign-in-core/storage/models/sign-in-database';
import type { OrganizationId, PersonId } from '#sign-in-core/storage/models/sign-in-store';
import { availableStoreValue } from '#sign-in-core/storage/store-query-results';

const nativePermissionRequests = {
	'workspace:create': { workspace: ['create'] },
	'workspaceAdmin:allowMachine': { workspaceAdmin: ['allowMachine'] },
	'workspaceAdmin:withdrawMachine': { workspaceAdmin: ['withdrawMachine'] },
	'workspaceAdmin:removeSession': { workspaceAdmin: ['removeSession'] },
	'machine:enroll': { machine: ['enroll'] },
	'machine:revoke': { machine: ['revoke'] },
	'machine:setTokenLifetime': { machine: ['setTokenLifetime'] },
	'organization:view': { organization: ['view'] },
	'organization:readAudit': { organization: ['readAudit'] },
} satisfies Readonly<
	Record<FleetPermission, Parameters<typeof organizationRoles.owner.authorize>[0]>
>;

/** A navigation choice is built from a live membership and the same native
 * permission statements as the checked organization endpoint. */
export function organizationChoiceAllows(
	role: OrganizationChoice['role'],
	permission: FleetPermission,
): boolean {
	return organizationRoles[role].authorize(nativePermissionRequests[permission]).success;
}

/** The endpoint supplies its real context and a fresh member read for the verified person and request organization. */
export async function checkOrganizationPermission(props: {
	readonly context: Parameters<typeof hasPermission>[1];
	readonly personId: PersonId;
	readonly organizationId: OrganizationId;
	readonly permission: FleetPermission;
	readonly readMemberRole: (request: {
		readonly personId: PersonId;
		readonly organizationId: OrganizationId;
	}) => Promise<SignInStoreResult<string | null>>;
}): Promise<SignInStoreResult<boolean>> {
	const member = await props.readMemberRole({
		personId: props.personId,
		organizationId: props.organizationId,
	});
	if (member.kind === 'store-unavailable') return member;
	if (member.value === null) return availableStoreValue(false);
	return availableStoreValue(
		await hasPermission(
			{
				role: member.value,
				organizationId: props.organizationId,
				permissions: nativePermissionRequests[props.permission],
				options: {
					ac: organizationAccessControl,
					roles: organizationRoles,
					dynamicAccessControl: { enabled: false },
				},
				useMemoryCache: false,
			},
			props.context,
		),
	);
}
