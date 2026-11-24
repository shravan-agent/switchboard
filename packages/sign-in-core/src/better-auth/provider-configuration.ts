import type { PersonProof } from '@agent-collaboration/tool-access/contracts';
import type { BetterAuthPlugin } from '@better-auth/core';
import { getOAuthProviderApi, oauthProvider } from '@better-auth/oauth-provider';
import { passkey } from '@better-auth/passkey';
import { betterAuth, type Auth, type BetterAuthOptions } from 'better-auth';
import { APIError, createAuthMiddleware, getSessionFromCtx } from 'better-auth/api';
import type { captcha } from 'better-auth/plugins/captcha';
import { jwt } from 'better-auth/plugins/jwt';
import { twoFactor } from 'better-auth/plugins/two-factor';

import { agentRegistrationMetadataSchema } from '#sign-in-core/agent-clients/agent-registration';
import { workspaceResourceHasIssuancePolicy } from '#sign-in-core/agent-clients/workspace-resource';
import { authorizationFencedAdapter } from '#sign-in-core/better-auth/authorization-fenced-adapter';
import { createMachineLoginPlugin } from '#sign-in-core/better-auth/machine-login-plugin';
import { refuseMachineRevocation } from '#sign-in-core/better-auth/machine-revocation-hook';
import { signInJwtOptions } from '#sign-in-core/better-auth/native-jwt-options';
import { createOrganizationMembershipReadPlugin } from '#sign-in-core/better-auth/organization-membership-read-plugin';
import { createOrganizationProviderPlugin } from '#sign-in-core/better-auth/organization-provider-options';
import { createOrganizationProvisioningPlugin } from '#sign-in-core/better-auth/organization-provisioning-plugin';
import {
	organizationReadSessionBeforeHook,
	isOrganizationMembershipReadPath,
} from '#sign-in-core/better-auth/organization-read-session';
import { createOrganizationStatementPlugin } from '#sign-in-core/better-auth/organization-statement-plugin';
import { createPasskeyConfirmationPlugin } from '#sign-in-core/better-auth/passkey-confirmation-plugin';
import { personAccessTokenClaims } from '#sign-in-core/better-auth/person-access-token-claims';
import type { ProviderRequestState } from '#sign-in-core/better-auth/provider-request-state';
import { createSecondFactorProviderPlugin } from '#sign-in-core/better-auth/second-factor-provider-plugin';
import { sessionReadWithoutToken } from '#sign-in-core/better-auth/session-read-without-token';
import { createShellSessionPlugin } from '#sign-in-core/better-auth/shell-session-plugin';
import { createSignInSignOutPlugin } from '#sign-in-core/better-auth/sign-in-sign-out';
import {
	agentRegistrationPorts,
	personSessionPorts,
	workspaceResourcePorts,
	requireStoredValue,
} from '#sign-in-core/better-auth/store-result-adapters';
import {
	createTurnstileProviderOptions,
	type TurnstileSecret,
} from '#sign-in-core/better-auth/turnstile-captcha';
import type { ListWorkspaces } from '#sign-in-core/central-link/list-workspaces';
import type { SignInConfiguration } from '#sign-in-core/contracts/deployment-configuration';
import type { OrganizationStatementSigningRequest } from '#sign-in-core/contracts/organization-statement';
import {
	signInClientIpv6SubnetBits,
	trustedSignInClientAddressHeader,
} from '#sign-in-core/contracts/sign-in-client-address';
import { uuid7Schema, type SignInPlatform } from '#sign-in-core/contracts/sign-in-platform';
import { socialLoginProviderSchema } from '#sign-in-core/contracts/social-login-provider';
import {
	parseMachineEnrollmentMetadata,
	unavailableMachineLoginDecisions,
	type MachineLoginDecisions,
} from '#sign-in-core/machine-login/machine-login-contracts';
import {
	classifySignInRequest,
	signInRequestPolicies,
} from '#sign-in-core/request-limits/request-limit-policy';
import type { LiveOwnerSession } from '#sign-in-core/storage/models/person-session-records';
import type { SignInDatabaseFactory } from '#sign-in-core/storage/models/sign-in-database';
import { personIdSchema } from '#sign-in-core/storage/models/sign-in-store';
import type { SignInStore } from '#sign-in-core/storage/models/sign-in-store';

export type ProviderAuthority =
	| { readonly kind: 'public' }
	| { readonly kind: 'person-proof'; readonly proof: PersonProof }
	| { readonly kind: 'owner-bootstrap' };

export interface SignInProviderProps {
	readonly openDatabase: SignInDatabaseFactory;
	readonly machineLoginDecisions?: MachineLoginDecisions;
	readonly listWorkspaces?: ListWorkspaces;
	readonly store: SignInStore;
	readonly platform: SignInPlatform;
	readonly configuration: SignInConfiguration;
	readonly secret: string;
	readonly turnstileSecret: TurnstileSecret;
	readonly google: { readonly clientId: string; readonly clientSecret: string };
	readonly github: { readonly clientId: string; readonly clientSecret: string };
	readonly authority: ProviderAuthority;
	readonly requestState: ProviderRequestState;
	readonly tokenClientId?: string;
	readonly generatedClientId?: string;
}

type SignInProviderOptions = BetterAuthOptions & {
	plugins: [
		ReturnType<typeof captcha>,
		ReturnType<typeof captcha>,
		ReturnType<typeof jwt>,
		ReturnType<typeof oauthProvider>,
		ReturnType<typeof passkey>,
		ReturnType<typeof createOrganizationProviderPlugin>,
		ReturnType<typeof createOrganizationMembershipReadPlugin>,
		ReturnType<typeof twoFactor>,
		ReturnType<typeof createSecondFactorProviderPlugin>,
		ReturnType<typeof createPasskeyConfirmationPlugin>,
		ReturnType<typeof createOrganizationProvisioningPlugin>,
		ReturnType<typeof createOrganizationStatementPlugin>,
		ReturnType<typeof createShellSessionPlugin>,
		ReturnType<typeof createSignInSignOutPlugin>,
		BetterAuthPlugin,
	];
};
export type SignInProvider = Auth<SignInProviderOptions>;

/** Every invocation owns its context. Only the named-binding caller supplies person-proof authority. */
export function createSignInProvider(props: SignInProviderProps): SignInProvider {
	const persons = personSessionPorts(props.store.persons);
	const agents = agentRegistrationPorts(props.store);
	const workspaces = workspaceResourcePorts(props.store);
	const machineLogin = props.configuration.machineLogin;
	// One value for the passkey plugin and the registration boundary that recomputes its verification.
	const passkeyRelyingParty = {
		origin: props.configuration.issuer,
		rpId: new URL(props.configuration.issuer).hostname,
	};
	const turnstile = createTurnstileProviderOptions({
		configuration: props.configuration,
		secret: props.turnstileSecret,
		log: props.platform.log,
	});
	function recordChangedLogin(account: {
		readonly id: string;
		readonly userId: string;
		readonly providerId: string;
	}): void {
		const state = props.requestState.loginLink;
		if (state.kind !== 'intent-recorded') return;
		if (account.userId !== state.change.personId || account.providerId !== state.change.provider)
			throw new APIError('FORBIDDEN', { message: 'login-link-mismatch' });
		props.requestState.loginLink = {
			kind: 'changed',
			change: state.change,
			accountId: uuid7Schema.parse(account.id),
		};
	}
	// Setup signs inside the native server-only endpoint, so key selection stays with the provider.
	async function signStatement(request: OrganizationStatementSigningRequest): Promise<string> {
		return (await provider.api.signOrganizationStatement({ body: request })).statement;
	}
	async function ownerPrivilege(
		userId: string | undefined,
		sessionId: string | undefined,
	): Promise<boolean> {
		if (props.authority.kind === 'public' || userId === undefined || sessionId === undefined)
			return false;
		return (await persons.readOwnerSession(userId, sessionId)) !== null;
	}
	const options: SignInProviderOptions = {
		rateLimit: {
			enabled: true,
			storage: 'memory',
			window: signInRequestPolicies.other.provider.windowSeconds,
			max: signInRequestPolicies.other.provider.max,
			customRules: {
				// Native '*' matches one path segment; '/**' covers nested plugin routes.
				'/**': (request: Request): { readonly window: number; readonly max: number } => {
					const policy =
						signInRequestPolicies[classifySignInRequest(new URL(request.url).pathname)].provider;
					return { window: policy.windowSeconds, max: policy.max };
				},
			},
		},
		// People see this name: the authenticator app's account issuer and the
		// passkey relying-party name (owner decision A10: the product is Switchboard).
		appName: 'Switchboard',
		baseURL: props.configuration.issuer,
		basePath: '/api/auth',
		secret: props.secret,
		// Member, organization and session writes move authorization fences in the same batch.
		database: authorizationFencedAdapter({
			openDatabase: props.openDatabase,
			platform: props.platform,
			onFenceCommitted: (): void => {
				props.requestState.authorizationFenceCommitted = true;
			},
		}),
		advanced: {
			database: { generateId: () => props.platform.ids.nextId() },
			ipAddress: {
				ipAddressHeaders: [trustedSignInClientAddressHeader],
				ipv6Subnet: signInClientIpv6SubnetBits,
			},
		},
		logger: turnstile.logger,
		emailAndPassword: { enabled: false },
		disabledPaths: ['/token'],
		trustedOrigins: [props.configuration.issuer],
		socialProviders: {
			google: { ...props.google, accessType: 'online', disableIdTokenSignIn: true },
			github: { ...props.github, disableIdTokenSignIn: true },
		},
		session: {
			cookieCache: { enabled: false },
			additionalFields: {
				secondFactorAt: { type: 'number', required: false, input: false },
				secondFactorMethod: { type: 'string', required: false, input: false },
			},
		},
		account: {
			storeAccountCookie: false,
			accountLinking: { enabled: true, disableImplicitLinking: true, allowDifferentEmails: true },
		},
		user: {
			additionalFields: { secondFactorSetAt: { type: 'number', required: false, input: false } },
			async validateUserInfo({ user, source }, context): Promise<void | { error: string }> {
				const providerId = socialLoginProviderSchema.safeParse(source.oauth?.providerId);
				if (source.method !== 'oauth' || !providerId.success) return { error: 'not-allowed' };
				if (source.action === 'link-account')
					props.requestState.loginLink = { kind: 'attempted', provider: providerId.data };
				if (
					typeof user.email !== 'string' ||
					!(await persons.providerEmailAllowed(user.email, user.emailVerified === true))
				)
					return { error: 'not-allowed' };
				if (source.action === 'link-account') {
					const current = await provider.api.getSession({
						headers: context.headers ?? new Headers(),
					});
					if (
						current === null ||
						current.user.id !== user.id ||
						!(await persons.isPersonSessionActive(current.user.id, current.session.id))
					)
						return { error: 'not-allowed' };
					const change = {
						requestId: props.platform.ids.nextId(),
						personId: personIdSchema.parse(current.user.id),
						provider: providerId.data,
					};
					requireStoredValue(await props.store.linkedLogins.record(change, 'intent'));
					const recorded = requireStoredValue(
						await props.store.linkedLogins.read(change.requestId),
					);
					if (
						recorded.length !== 1 ||
						!recorded.some(
							(row) =>
								row.phase === 'intent' &&
								row.actorUserId === change.personId &&
								row.targetId === change.provider,
						)
					)
						throw new APIError('SERVICE_UNAVAILABLE', { message: 'login-link-intent-unconfirmed' });
					props.requestState.loginLink = { kind: 'intent-recorded', change };
				}
			},
		},
		hooks: {
			before: createAuthMiddleware(
				async (
					context,
				): Promise<void | {
					readonly context: { readonly context: { readonly session: LiveOwnerSession | null } };
				}> => {
					if (machineLogin !== undefined && context.path === '/oauth2/revoke')
						await refuseMachineRevocation({
							context,
							provider: getOAuthProviderApi(context, provider.options.plugins[3].options),
							routerClientId: machineLogin.routerClientId,
							openDatabase: props.openDatabase,
						});
					if (isOrganizationMembershipReadPath(context.path)) {
						return organizationReadSessionBeforeHook(context);
					}
					if (context.path?.startsWith('/organization/')) {
						const current = await getSessionFromCtx(context, { disableCookieCache: true });
						if (current !== null && current.user.emailVerified) {
							props.requestState.organizationActor = {
								kind: 'authenticated',
								personId: personIdSchema.parse(current.user.id),
								sessionId: uuid7Schema.parse(current.session.id),
							};
						}
					}
					if (props.authority.kind !== 'person-proof') {
						// Native captcha onRequest runs before this hook and all writes.
						return;
					}
					const current = await persons.readOwnerSession(
						props.authority.proof.subject,
						props.authority.proof.sessionRef,
					);
					if (current === null) throw new APIError('FORBIDDEN');
					return { context: { context: { session: current } } };
				},
			),
			after: createAuthMiddleware(async (context) => {
				const candidate = context.context.newSession ?? context.context.session;
				if (
					context.path !== '/sign-out' &&
					candidate !== null &&
					candidate !== undefined &&
					context.context.responseHeaders?.has('set-cookie') === true &&
					!props.requestState.issuedSessions.some(
						(session) => session.sessionId === candidate.session.id,
					)
				)
					props.requestState.issuedSessions.push({
						personId: candidate.user.id,
						sessionId: candidate.session.id,
					});
				// Covers every get-session path (stored, refreshed): the token stays in the cookie.
				if (context.path === '/get-session' || context.path === '/passkey/verify-authentication') {
					const read = sessionReadWithoutToken(context.context.returned);
					if (read.kind === 'stripped') return context.json(read.body);
				}
				return undefined;
			}),
		},
		databaseHooks: {
			user: {
				create: {
					async after(user): Promise<void> {
						props.requestState.createdUserIds.push(user.id);
					},
				},
			},
			session: {
				create: {
					async before(session, context) {
						if (!(await persons.ensurePersonActive(session.userId)))
							throw new APIError('FORBIDDEN', { message: 'not-allowed' });
						const memberships = requireStoredValue(
							await props.store.organizations.membershipsForPerson(session.userId),
						);
						const onlyMembership = memberships.length === 1 ? memberships[0] : undefined;
						return {
							data: {
								...session,
								activeOrganizationId: onlyMembership?.organizationId ?? null,
								// The plugin refuses assertions without UV before creating this session.
								...(context?.path === '/passkey/verify-authentication'
									? { secondFactorAt: props.platform.clock.now(), secondFactorMethod: 'passkey' }
									: {}),
							},
						};
					},
					async after(session): Promise<void> {
						props.requestState.issuedSessions.push({
							personId: session.userId,
							sessionId: session.id,
						});
					},
				},
			},
			account: {
				create: {
					async after(account): Promise<void> {
						recordChangedLogin(account);
					},
					async before(account) {
						return {
							data: {
								...account,
								accessToken: null,
								refreshToken: null,
								idToken: null,
								accessTokenExpiresAt: null,
								refreshTokenExpiresAt: null,
							},
						};
					},
				},
				update: {
					async after(account): Promise<void> {
						recordChangedLogin(account);
					},
					async before(account) {
						return {
							data: {
								...account,
								accessToken: null,
								refreshToken: null,
								idToken: null,
								accessTokenExpiresAt: null,
								refreshTokenExpiresAt: null,
							},
						};
					},
				},
			},
		},
		plugins: [
			...turnstile.plugins,
			jwt(signInJwtOptions(props.configuration)),
			oauthProvider({
				extensions: [
					{
						claims: {
							accessToken: async (input): Promise<Record<string, unknown>> => {
								if (
									machineLogin !== undefined &&
									parseMachineEnrollmentMetadata(input.metadata) !== null
								)
									return {};
								return personAccessTokenClaims(input, {
									configuration: props.configuration,
									store: props.store,
									clock: props.platform.clock,
								});
							},
						},
					},
				],
				loginPage: '/sign-in',
				consentPage: '/consent',
				// Refresh exists only for the fleet CLI client's grants (t15e); the release fence
				// lets a refresh credential out for no other client or profile.
				grantTypes: ['authorization_code', 'client_credentials', 'refresh_token'],
				scopes: ['tool-portal:agent', 'tool-portal:management', 'fleet:admin', 'offline_access'],
				allowDynamicClientRegistration: false,
				cachedTrustedClients: new Set<string>(),
				enforcePerClientResources: true,
				accessTokenExpiresIn: props.configuration.accessTokenSeconds,
				m2mAccessTokenExpiresIn: props.configuration.accessTokenSeconds,
				resources: [
					...(machineLogin === undefined
						? []
						: [
								{
									identifier: machineLogin.machineAudience,
									accessTokenTtl: 3600,
									refreshTokenTtl: 2_592_000,
									allowedScopes: ['offline_access'],
								},
							]),
					{
						identifier: props.configuration.managementAudience,
						accessTokenTtl: props.configuration.accessTokenSeconds,
						allowedScopes: ['tool-portal:management'],
					},
					// Person-fleet tokens are always key-bound: central verifies the DPoP proof itself.
					{
						identifier: props.configuration.centralAdminAudience,
						accessTokenTtl: props.configuration.accessTokenSeconds,
						// Better Auth stores a refresh row with the scopes this list admits; without
						// offline_access a refresh could not rotate (t15e). Central ignores `scope`.
						allowedScopes: ['fleet:admin', 'offline_access'],
						dpopBoundAccessTokensRequired: true,
					},
				],
				generateClientId: () => props.generatedClientId ?? props.platform.ids.nextId(),
				clientPrivileges: async ({ user, session }) => ownerPrivilege(user?.id, session?.id),
				resourcePrivileges: async ({ user, session }) => ownerPrivilege(user?.id, session?.id),
				async customAccessTokenClaims({
					user,
					metadata,
					resources,
				}): Promise<Record<string, unknown>> {
					if (machineLogin !== undefined && parseMachineEnrollmentMetadata(metadata) !== null)
						return {};
					if (user !== undefined && user !== null) {
						const requestedWorkspaces = await Promise.all(
							(resources ?? []).map((identifier: string) => workspaces.read(identifier)),
						);
						if (requestedWorkspaces.some((resource) => resource !== null))
							throw new APIError('BAD_REQUEST', { error: 'invalid_target' });
						if (!(await persons.ensurePersonActive(user.id)))
							throw new APIError('BAD_REQUEST', { error: 'invalid_grant' });
						return {};
					}
					const registration = agentRegistrationMetadataSchema.safeParse(metadata);
					if (!registration.success || props.tokenClientId === undefined)
						throw new APIError('BAD_REQUEST', { error: 'invalid_client' });
					const current = await agents.read(props.tokenClientId);
					if (
						current === null ||
						current.disabled ||
						!current.registrationComplete ||
						current.metadata.organizationId !== registration.data.organizationId
					)
						throw new APIError('BAD_REQUEST', { error: 'invalid_client' });
					if (resources?.length !== 1)
						throw new APIError('BAD_REQUEST', { error: 'invalid_target' });
					const identifier = resources[0];
					if (identifier === undefined || !current.resourceIds.includes(identifier))
						throw new APIError('BAD_REQUEST', { error: 'invalid_target' });
					const resource = await workspaces.read(identifier);
					if (
						resource === null ||
						!workspaceResourceHasIssuancePolicy(resource) ||
						resource.metadata.organizationId !== current.metadata.organizationId
					)
						throw new APIError('BAD_REQUEST', { error: 'invalid_target' });
					return {
						organization_id: current.metadata.organizationId,
						workspace_id: resource.metadata.workspaceId,
					};
				},
				customTokenResponseFields: ({ metadata }): Record<string, unknown> => {
					const enrollment = parseMachineEnrollmentMetadata(metadata);
					return enrollment === null || machineLogin === undefined
						? {}
						: { machine_client_id: enrollment.enrollmentId };
				},
			}),
			passkey({
				rpID: passkeyRelyingParty.rpId,
				origin: passkeyRelyingParty.origin,
				authenticatorSelection: { userVerification: 'required' },
				registration: {
					afterVerification: async ({ verification }): Promise<void> => {
						if (!verification.registrationInfo?.userVerified)
							throw new APIError('FORBIDDEN', {
								code: 'USER_VERIFICATION_REQUIRED',
								message: 'user-verification-required',
							});
					},
				},
				authentication: {
					afterVerification: async ({ verification }): Promise<void> => {
						if (!verification.authenticationInfo.userVerified)
							throw new APIError('UNAUTHORIZED', {
								code: 'USER_VERIFICATION_REQUIRED',
								message: 'user-verification-required',
							});
					},
				},
			}),
			createOrganizationProviderPlugin({
				ownerEmail: props.configuration.ownerEmail,
				store: props.store,
				platform: props.platform,
				requestState: props.requestState,
				signStatement,
			}),
			createOrganizationMembershipReadPlugin({ store: props.store, platform: props.platform }),
			twoFactor({ allowPasswordless: true }),
			createSecondFactorProviderPlugin({
				store: props.store,
				platform: props.platform,
				passkeyRelyingParty,
			}),
			createPasskeyConfirmationPlugin({
				issuer: props.configuration.issuer,
				store: props.store,
				platform: props.platform,
			}),
			createOrganizationProvisioningPlugin({
				store: props.store,
				platform: props.platform,
				signStatement,
			}),
			createOrganizationStatementPlugin({
				configuration: props.configuration,
				platform: props.platform,
				store: props.store,
			}),
			createShellSessionPlugin(props.store.persons),
			createSignInSignOutPlugin({
				issuer: props.configuration.issuer,
				sessions: props.store.persons,
			}),
			machineLogin === undefined
				? { id: 'machine-login-unconfigured' }
				: createMachineLoginPlugin({
						configuration: machineLogin,
						decisions: props.machineLoginDecisions ?? unavailableMachineLoginDecisions,
						listWorkspaces: props.listWorkspaces ?? (async () => ({ result: 'unavailable' })),
						openDatabase: props.openDatabase,
						store: props.store,
						platform: props.platform,
						requestState: props.requestState,
						providerOptions: () => provider.options.plugins[3].options,
					}),
		],
	};
	const provider = betterAuth(options);
	return provider;
}
