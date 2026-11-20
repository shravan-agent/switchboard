import type { SignInPlatform } from '#sign-in-core/contracts/sign-in-platform';
import { createAgentRegistrationStore } from '#sign-in-core/storage/agent-registration-store';
import { createAuthorizationRevisionDeliveryStore } from '#sign-in-core/storage/authorization-revision-delivery-store';
import { createFactorChangeAudit } from '#sign-in-core/storage/factor-change-audit';
import { createLinkedLoginAudit } from '#sign-in-core/storage/linked-login-audit';
import type {
	SignInDatabaseFactory,
	SignInStoreFailure,
} from '#sign-in-core/storage/models/sign-in-database';
import type { SignInStore } from '#sign-in-core/storage/models/sign-in-store';
import { createOrganizationChangeAudit } from '#sign-in-core/storage/organization-change-audit';
import { createOrganizationMembershipStore } from '#sign-in-core/storage/organization-membership-store';
import { createOrganizationStampStore } from '#sign-in-core/storage/organization-stamp-store';
import { createOwnerBootstrapStore } from '#sign-in-core/storage/owner-bootstrap-store';
import { createPasskeyCredentialStore } from '#sign-in-core/storage/passkey-credential-store';
import { createPersonFleetAuthorizationStore } from '#sign-in-core/storage/person-fleet-authorization-store';
import { createPersonSessionStore } from '#sign-in-core/storage/person-session-store';
import { createSecondFactorStore } from '#sign-in-core/storage/second-factor-store';
import { storeFailure } from '#sign-in-core/storage/store-query-results';
import { createWorkspaceManagementAudit } from '#sign-in-core/storage/workspace-management-audit';
import { createWorkspaceResourceStore } from '#sign-in-core/storage/workspace-resource-store';

function closeStoreFailure<TArgs extends readonly unknown[], TResult>(
	operation: (...args: TArgs) => Promise<TResult>,
): (...args: TArgs) => Promise<TResult | SignInStoreFailure> {
	return async (...args: TArgs): Promise<TResult | SignInStoreFailure> => {
		try {
			return await operation(...args);
		} catch (error) {
			return storeFailure(error);
		}
	};
}

export function createSignInStore(props: {
	readonly openDatabase: SignInDatabaseFactory;
	readonly ownerEmail: string;
	readonly platform: SignInPlatform;
}): SignInStore {
	const persons = createPersonSessionStore(props);
	const agents = createAgentRegistrationStore(props);
	const resources = createWorkspaceResourceStore(props.openDatabase);
	const audit = createWorkspaceManagementAudit(props);
	const bootstrap = createOwnerBootstrapStore(props);
	const linkedLogins = createLinkedLoginAudit(props);
	const authorizations = createPersonFleetAuthorizationStore(props.openDatabase);
	const revisionDelivery = createAuthorizationRevisionDeliveryStore(props);
	return {
		revisionDelivery: {
			readPending: closeStoreFailure(revisionDelivery.readPending),
			readOrganization: closeStoreFailure(revisionDelivery.readOrganization),
			recordOrganizationAcknowledgement: closeStoreFailure(
				revisionDelivery.recordOrganizationAcknowledgement,
			),
			recordPersonAcknowledgement: closeStoreFailure(revisionDelivery.recordPersonAcknowledgement),
			deferOrganization: closeStoreFailure(revisionDelivery.deferOrganization),
			deferPerson: closeStoreFailure(revisionDelivery.deferPerson),
			readSynchronization: closeStoreFailure(revisionDelivery.readSynchronization),
			forgetCentralAcknowledgements: closeStoreFailure(
				revisionDelivery.forgetCentralAcknowledgements,
			),
		},
		authorizations: {
			readPersonFleetSnapshot: closeStoreFailure(authorizations.readPersonFleetSnapshot),
		},
		factors: createSecondFactorStore(props),
		passkeys: createPasskeyCredentialStore(props),
		factorChanges: createFactorChangeAudit(props),
		organizations: createOrganizationMembershipStore(props.openDatabase),
		organizationStamps: createOrganizationStampStore(props.openDatabase),
		peopleChanges: createOrganizationChangeAudit(props),
		linkedLogins: {
			record: closeStoreFailure(linkedLogins.record),
			read: closeStoreFailure(linkedLogins.read),
			readAccount: closeStoreFailure(linkedLogins.readAccount),
		},
		persons: {
			isPersonOrganizationSessionActive: closeStoreFailure(
				persons.isPersonOrganizationSessionActive,
			),
			readPersonSession: closeStoreFailure(persons.readPersonSession),
			sessionRowByToken: closeStoreFailure(persons.sessionRowByToken),
			providerEmailAllowed: closeStoreFailure(persons.providerEmailAllowed),
			ensurePersonActive: closeStoreFailure(persons.ensurePersonActive),
			readOwnerSession: closeStoreFailure(persons.readOwnerSession),
			isPersonSessionActive: closeStoreFailure(persons.isPersonSessionActive),
			deleteSession: closeStoreFailure(persons.deleteSession),
			cleanupUnboundPerson: closeStoreFailure(persons.cleanupUnboundPerson),
		},
		agents: {
			clientExists: closeStoreFailure(agents.clientExists),
			read: closeStoreFailure(agents.read),
			record: closeStoreFailure(agents.record),
			complete: closeStoreFailure(agents.complete),
		},
		resources: {
			read: closeStoreFailure(resources.read),
			exists: closeStoreFailure(resources.exists),
		},
		audit: {
			record: closeStoreFailure(audit.record),
			checkOperation: closeStoreFailure(audit.checkOperation),
			reserve: closeStoreFailure(audit.reserve),
			finish: closeStoreFailure(audit.finish),
		},
		bootstrap: {
			readSystemResource: closeStoreFailure(bootstrap.readSystemResource),
			record: closeStoreFailure(bootstrap.record),
			readClient: closeStoreFailure(bootstrap.readClient),
			readLinks: closeStoreFailure(bootstrap.readLinks),
			readAuditIds: closeStoreFailure(bootstrap.readAuditIds),
			recordSignIn: closeStoreFailure(bootstrap.recordSignIn),
		},
	};
}
