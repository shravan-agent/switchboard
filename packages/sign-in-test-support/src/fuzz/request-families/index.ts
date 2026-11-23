import { requestFamily as adminChangeRecordsFamily } from './admin-change-records';
import { requestFamily as adminCreateWorkspaceFamily } from './admin-create-workspace';
import { requestFamily as adminWorkspaceLookupFamily } from './admin-workspace-lookup';
import { requestFamily as authAuthorizationServerFamily } from './auth-authorization-server';
import { requestFamily as authOpenidConfigurationFamily } from './auth-openid-configuration';
import { requestFamily as authorizationServerFamily } from './authorization-server';
import { requestFamily as callbackGithubFamily } from './callback-github';
import { requestFamily as callbackGithubPostFamily } from './callback-github-post';
import { requestFamily as callbackGoogleFamily } from './callback-google';
import { requestFamily as callbackGooglePostFamily } from './callback-google-post';
import { requestFamily as getSessionFamily } from './get-session';
import { requestFamily as linkSocialFamily } from './link-social';
import { requestFamily as listAccountsFamily } from './list-accounts';
import { machineLoginFamilies } from './machine-login';
import { requestFamily as oauth2AuthorizeFamily } from './oauth2-authorize';
import { requestFamily as oauth2AuthorizePostFamily } from './oauth2-authorize-post';
import { requestFamily as oauth2IntrospectFamily } from './oauth2-introspect';
import { requestFamily as oauth2TokenFamily } from './oauth2-token';
import { requestFamily as openidConfigurationFamily } from './openid-configuration';
import { requestFamily as organizationAcceptInvitationFamily } from './organization-accept-invitation';
import { requestFamily as organizationAdminPageFamily } from './organization-admin-page';
import { requestFamily as organizationCancelInvitationFamily } from './organization-cancel-invitation';
import { requestFamily as organizationCreateFamily } from './organization-create';
import { requestFamily as organizationInviteMemberFamily } from './organization-invite-member';
import { requestFamily as organizationPeopleListFamily } from './organization-people-list';
import { requestFamily as organizationPeoplePageFamily } from './organization-people-page';
import { requestFamily as organizationPersonMembershipFamily } from './organization-person-membership';
import { requestFamily as organizationRemoveMemberFamily } from './organization-remove-member';
import { requestFamily as organizationRetryProvisioningFamily } from './organization-retry-provisioning';
import { requestFamily as organizationSelfContextFamily } from './organization-self-context';
import { requestFamily as organizationSetActiveFamily } from './organization-set-active';
import { requestFamily as ownerBootstrapFamily } from './owner-bootstrap';
import { requestFamily as ownerReadyFamily } from './owner-ready';
import { requestFamily as passkeyConfirmFamily } from './passkey-confirm';
import { requestFamily as passkeyConfirmOptionsFamily } from './passkey-confirm-options';
import { requestFamily as passkeyGenerateRegisterOptionsFamily } from './passkey-generate-register-options';
import { requestFamily as passkeyListUserPasskeysFamily } from './passkey-list-user-passkeys';
import { requestFamily as passkeyRemoveFamily } from './passkey-remove';
import { requestFamily as passkeyUpdateFamily } from './passkey-update';
import { requestFamily as passkeyVerifyRegistrationFamily } from './passkey-verify-registration';
import { requestFamily as jwksFamily } from './public-jwks';
import { requestFamily as relayApprovalDecideFamily } from './relay-approval-decide';
import { requestFamily as relayApprovalListFamily } from './relay-approval-list';
import { requestFamily as relayApprovalReadFamily } from './relay-approval-read';
import { requestFamily as relayChangeRecordsFamily } from './relay-change-records';
import { requestFamily as relayCreateWorkspaceFamily } from './relay-create-workspace';
import { requestFamily as relayEngineDiscardFamily } from './relay-engine-discard';
import { requestFamily as relayEngineHealthFamily } from './relay-engine-health';
import { requestFamily as relayEngineRetiredFamily } from './relay-engine-retired';
import { requestFamily as relayEngineRetryFamily } from './relay-engine-retry';
import { requestFamily as relayWorkspaceLookupFamily } from './relay-workspace-lookup';
import { requestFamily as shellMeFamily } from './shell-me';
import { requestFamily as shellPeopleFamily } from './shell-people';
import { requestFamily as signInFamily } from './sign-in';
import { requestFamily as signInSocialFamily } from './sign-in-social';
import { requestFamily as switchboardSignOutFamily } from './switchboard-sign-out';
import { requestFamily as twoFactorEnableFamily } from './two-factor-enable';
import { requestFamily as twoFactorGenerateBackupCodesFamily } from './two-factor-generate-backup-codes';
import { requestFamily as twoFactorRemoveAppFamily } from './two-factor-remove-app';
import { requestFamily as twoFactorVerifyBackupCodeFamily } from './two-factor-verify-backup-code';
import { requestFamily as twoFactorVerifyTotpFamily } from './two-factor-verify-totp';

export type {
	GeneratedRequest,
	RequestFamily,
	RequestFamilyContext,
	VariantStep,
} from './request-family';

export const requestFamilies = [
	signInFamily,
	ownerReadyFamily,
	shellMeFamily,
	shellPeopleFamily,
	organizationAdminPageFamily,
	getSessionFamily,
	listAccountsFamily,
	passkeyGenerateRegisterOptionsFamily,
	passkeyListUserPasskeysFamily,
	oauth2AuthorizeFamily,
	oauth2AuthorizePostFamily,
	jwksFamily,
	authAuthorizationServerFamily,
	authOpenidConfigurationFamily,
	authorizationServerFamily,
	openidConfigurationFamily,
	callbackGoogleFamily,
	callbackGithubFamily,
	callbackGooglePostFamily,
	callbackGithubPostFamily,
	ownerBootstrapFamily,
	adminCreateWorkspaceFamily,
	adminWorkspaceLookupFamily,
	adminChangeRecordsFamily,
	relayCreateWorkspaceFamily,
	relayWorkspaceLookupFamily,
	relayChangeRecordsFamily,
	relayApprovalListFamily,
	relayApprovalReadFamily,
	relayApprovalDecideFamily,
	relayEngineHealthFamily,
	relayEngineRetiredFamily,
	relayEngineRetryFamily,
	relayEngineDiscardFamily,
	passkeyVerifyRegistrationFamily,
	passkeyUpdateFamily,
	passkeyRemoveFamily,
	passkeyConfirmOptionsFamily,
	passkeyConfirmFamily,
	twoFactorEnableFamily,
	twoFactorVerifyTotpFamily,
	twoFactorVerifyBackupCodeFamily,
	twoFactorGenerateBackupCodesFamily,
	twoFactorRemoveAppFamily,
	organizationCreateFamily,
	organizationInviteMemberFamily,
	organizationCancelInvitationFamily,
	organizationAcceptInvitationFamily,
	organizationSelfContextFamily,
	organizationPeopleListFamily,
	organizationPeoplePageFamily,
	organizationPersonMembershipFamily,
	organizationRemoveMemberFamily,
	organizationSetActiveFamily,
	organizationRetryProvisioningFamily,
	linkSocialFamily,
	signInSocialFamily,
	oauth2IntrospectFamily,
	oauth2TokenFamily,
	switchboardSignOutFamily,
	...machineLoginFamilies,
] as const;
