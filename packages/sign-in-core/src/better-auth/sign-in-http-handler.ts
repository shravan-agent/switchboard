import { decodeBasicCredentials } from '@better-auth/core/oauth2';
import { decodeJwt, decodeProtectedHeader } from 'jose';

import { renderFactorFormResponse } from '#sign-in-core/better-auth/factor-enrollment-page';
import {
	forwardFleetAdminRequest,
	isFleetAdminForwardingRoute,
} from '#sign-in-core/better-auth/fleet-admin-forwarding';
import {
	isFleetAdminRelayRoute,
	relayFleetAdminRequest,
} from '#sign-in-core/better-auth/fleet-admin-relay';
import {
	minimalOwnerPage,
	ownerAuthorizationResume,
} from '#sign-in-core/better-auth/minimal-owner-pages';
import {
	organizationAdminPage,
	organizationAdminPagePath,
} from '#sign-in-core/better-auth/organization-admin-page';
import {
	createOrganizationFleetCallGuard,
	createOrganizationFleetCallRunner,
} from '#sign-in-core/better-auth/organization-fleet-call-guard';
import { bootstrapOwnerClient } from '#sign-in-core/better-auth/owner-client-bootstrap';
import { completePasskeySignIn } from '#sign-in-core/better-auth/passkey-sign-in-completion';
import {
	createSignInProvider,
	type SignInProviderProps,
} from '#sign-in-core/better-auth/provider-configuration';
import {
	createProviderRequestState,
	type ProviderRequestState,
} from '#sign-in-core/better-auth/provider-request-state';
import { readProviderRouterBody } from '#sign-in-core/better-auth/provider-router-body';
import {
	readSignedInNavigationAccount,
	respondToSignedInNavigation,
	signedInNavigationMembership,
} from '#sign-in-core/better-auth/sign-in-navigation';
import {
	agentRegistrationPorts,
	personSessionPorts,
	workspaceResourcePorts,
	requireStoredValue,
} from '#sign-in-core/better-auth/store-result-adapters';
import { isSignedInNavigationPath } from '#sign-in-core/contracts/sign-in-navigation';
import { runAuthorizationRevisionDrain } from '#sign-in-core/organizations/authorization-revision-drainer';
import type { OrganizationFleetState } from '#sign-in-core/organizations/organization-provisioning';
import { pageAssetResponse } from '#sign-in-core/pages/page-document';
import {
	admitSignInRequest,
	providerLimitedResponse,
} from '#sign-in-core/request-limits/sign-in-request-admission';
import { organizationReadResponse } from '#sign-in-core/response-release/organization-request-errors';
import {
	handleSignInRequest,
	isPublicSignInRoute,
} from '#sign-in-core/response-release/sign-in-request-handler';
import {
	accessTokenReleaseClaimsSchema,
	type SignInResponseReleasePorts,
} from '#sign-in-core/response-release/sign-in-response-release';

export type SignInHttpConfiguration = Omit<
	SignInProviderProps,
	'authority' | 'generatedClientId' | 'requestState' | 'tokenClientId'
>;

/** Real Better Auth HTTP always returns through the portable release fence. No raw person API is published. */
export interface SignInHttpHandlerOptions {
	/** The host keeps work alive past the response: `waitUntil` on Workers, tracked on Node. */
	readonly deferAfterResponse?: (work: Promise<unknown>) => void;
}

export function createSignInHttpHandler(
	configuration: SignInHttpConfiguration,
	options: SignInHttpHandlerOptions = {},
): (request: Request) => Promise<Response> {
	return async (incomingRequest: Request): Promise<Response> => {
		const asset = pageAssetResponse(incomingRequest);
		if (asset !== null) return asset;
		const state = createProviderRequestState();
		try {
			return await respondToSignInRequest(incomingRequest, state);
		} finally {
			// r3 section 5: a committed fence change hints a bounded drain once the response is ready;
			// the periodic drain recovers a lost hint.
			if (state.authorizationFenceCommitted)
				options.deferAfterResponse?.(
					runAuthorizationRevisionDrain({
						...configuration,
						prepareFleetCall: createOrganizationFleetCallGuard(configuration),
					}),
				);
		}
	};
	/**
	 * B2's admin page and its forwarding routes. The forwarder obtains each request's
	 * person-fleet token through this same handler, so every admission and release fence runs.
	 */
	async function respondToOrganizationAdmin(
		request: Request,
		pathname: string,
		state: ProviderRequestState,
	): Promise<Response> {
		const provider = createSignInProvider({
			...configuration,
			requestState: state,
			authority: { kind: 'public' },
		});
		const persons = personSessionPorts(configuration.store.persons);
		const liveSession = async (): Promise<{
			readonly personId: string;
			readonly activeOrganizationId: string | null;
		} | null> => {
			const current = await provider.api.getSession({
				headers: request.headers,
				query: { disableCookieCache: true },
			});
			if (
				current === null ||
				!current.user.emailVerified ||
				!(await persons.isPersonSessionActive(current.user.id, current.session.id))
			)
				return null;
			const activeOrganizationId =
				'activeOrganizationId' in current.session &&
				typeof current.session.activeOrganizationId === 'string'
					? current.session.activeOrganizationId
					: null;
			return { personId: current.user.id, activeOrganizationId };
		};
		if (isFleetAdminForwardingRoute(pathname))
			return forwardFleetAdminRequest({
				request,
				route: pathname,
				configuration: configuration.configuration,
				platform: configuration.platform,
				hasLiveSession: async () => (await liveSession()) !== null,
				signIn: (inner) => respondToSignInRequest(inner, createProviderRequestState()),
				runFleetCall: createOrganizationFleetCallRunner(configuration),
			});
		if (request.method !== 'GET') return Response.json({ error: 'not-found' }, { status: 404 });
		const current = await liveSession();
		// Built, not `Response.redirect`: hosts add headers to every response.
		const seeOther = (pathname: string): Response =>
			new Response(null, {
				status: 303,
				headers: {
					location: new URL(pathname, configuration.configuration.issuer).toString(),
					'cache-control': 'no-store',
				},
			});
		if (current === null) return seeOther('/sign-in');
		const membership = requireStoredValue(
			await configuration.store.organizations.membershipsForPerson(current.personId),
		).find((candidate) => candidate.organizationId === current.activeOrganizationId);
		if (membership === undefined) return seeOther('/owner-ready');
		let showPeopleLink = false;
		try {
			showPeopleLink = (
				await provider.api.hasPermission({
					headers: request.headers,
					body: {
						organizationId: membership.organizationId,
						permissions: { organization: ['view'] },
					},
				})
			).success;
		} catch {
			// A failed read hides only the link; the People page keeps its own guard.
		}
		return organizationAdminPage({
			organizationId: membership.organizationId,
			organizationName: membership.organizationName,
			operationId: configuration.platform.ids.nextId(),
			showPeopleLink,
		});
	}
	async function respondToSignInRequest(
		incomingRequest: Request,
		state: ProviderRequestState,
	): Promise<Response> {
		const persons = personSessionPorts(configuration.store.persons);
		let passkeyAuditPending = false;
		try {
			const admission = await admitSignInRequest({
				request: incomingRequest,
				platform: configuration.platform,
			});
			if (admission.kind === 'refused') return admission.response;
			const request = admission.request;
			const url = new URL(request.url);
			if (!isPublicSignInRoute(url.pathname, request.method))
				return Response.json({ error: 'not-found' }, { status: 404 });
			passkeyAuditPending = url.pathname === '/api/auth/passkey/verify-authentication';
			if (isFleetAdminRelayRoute(url.pathname))
				return await relayFleetAdminRequest({
					request,
					route: url.pathname,
					platform: configuration.platform,
					runFleetCall: createOrganizationFleetCallRunner(configuration),
				});
			if (isFleetAdminForwardingRoute(url.pathname) || url.pathname === organizationAdminPagePath)
				return await respondToOrganizationAdmin(request, url.pathname, state);
			if (isSignedInNavigationPath(url.pathname))
				return await respondToSignedInNavigation({
					page: url.pathname,
					url,
					headers: request.headers,
					provider: createSignInProvider({
						...configuration,
						requestState: state,
						authority: { kind: 'public' },
					}),
					store: configuration.store,
					platform: configuration.platform,
				});
			// Validate continuation before any native factor mutation, not after
			// confirmation has already rotated the browser's session cookie.
			const factorContinuation = url.pathname.startsWith('/api/auth/two-factor/')
				? ownerAuthorizationResume(url.searchParams.get('authorize'), configuration.configuration)
				: null;
			if (factorContinuation?.kind === 'refused') return invalidRequestResponse();
			const factorResume =
				factorContinuation?.kind === 'resume' ? factorContinuation.authorization : null;
			if (url.pathname === '/api/auth/link-social') {
				// The provider refuses a body at parse time, before its session check; so must this
				// wrapper, before its own live-session check can answer first.
				const body = await readProviderRouterBody(request);
				if (body.kind === 'refused') return body.response;
				if (
					body.kind === 'json' &&
					body.payload !== null &&
					typeof body.payload === 'object' &&
					Object.hasOwn(body.payload, 'idToken')
				)
					return Response.json({ error: 'redirect-linking-required' }, { status: 400 });
			}
			if (request.method === 'GET' && ['/sign-in', '/owner-ready'].includes(url.pathname)) {
				const resumedAuthorization = new URL(
					'/api/auth/oauth2/authorize',
					configuration.configuration.issuer,
				);
				resumedAuthorization.search = url.search;
				// Validated before any session read, so a refused continuation has no effect.
				const pageContinuation = ownerAuthorizationResume(
					url.searchParams.get('authorize') ??
						(url.searchParams.has('client_id') ? resumedAuthorization.toString() : null),
					configuration.configuration,
				);
				if (pageContinuation.kind === 'refused') return invalidRequestResponse();
				let createOrganization = false;
				let organizationSetup:
					| { readonly organizationId: string; readonly state: OrganizationFleetState }
					| undefined;
				const account =
					url.pathname === '/owner-ready'
						? await readSignedInNavigationAccount({
								provider: createSignInProvider({
									...configuration,
									requestState: state,
									authority: { kind: 'public' },
								}),
								headers: request.headers,
								store: configuration.store,
								clock: configuration.platform.clock,
							})
						: null;
				const memberships = account?.choices ?? [];
				const activeOrganizationId = account?.activeOrganization?.organizationId ?? null;
				const selectionRequired = memberships.length > 0 && activeOrganizationId === null;
				if (account?.activeOrganization?.role === 'owner') {
					const organizationId = account.activeOrganization.organizationId;
					const fleetState = requireStoredValue(
						await configuration.store.organizations.readFleetState(organizationId),
					);
					if (fleetState !== null) organizationSetup = { organizationId, state: fleetState };
				}
				createOrganization =
					account?.email.toLowerCase() === configuration.configuration.ownerEmail.toLowerCase() &&
					memberships.length === 0;
				return minimalOwnerPage({
					crypto: configuration.platform.crypto,
					memberships,
					activeOrganizationId,
					selectionRequired,
					...(organizationSetup === undefined ? {} : { organizationSetup }),
					factorPage: account?.factorPage ?? 'hidden',
					showNavigationLink: signedInNavigationMembership(account, url) !== null,
					noOrganization: account !== null && memberships.length === 0 && !createOrganization,
					createOrganization,
					ready: url.pathname === '/owner-ready',
					configuration: configuration.configuration,
					resume: pageContinuation.kind === 'resume' ? pageContinuation.authorization : null,
				});
			}
			const body =
				url.pathname === '/api/auth/oauth2/token'
					? new URLSearchParams(await request.clone().text())
					: undefined;
			const tokenClientId =
				body?.get('client_id') ?? basicClientId(request.headers.get('authorization'));
			const providerProps = {
				...configuration,
				requestState: state,
				...(tokenClientId === null || tokenClientId === undefined ? {} : { tokenClientId }),
			};
			if (url.pathname === '/api/auth/owner/bootstrap')
				return bootstrapOwnerClient({ request, provider: providerProps });
			const provider = createSignInProvider({ ...providerProps, authority: { kind: 'public' } });
			if (url.pathname === '/api/auth/link-social') {
				const current = await provider.api.getSession({ headers: request.headers });
				if (
					current === null ||
					!(await persons.isPersonSessionActive(current.user.id, current.session.id))
				)
					return Response.json({ error: 'not-allowed' }, { status: 403 });
			}
			const agents = agentRegistrationPorts(configuration.store);
			const ports: SignInResponseReleasePorts = {
				issuer: configuration.configuration.issuer,
				toolPortalOrigin: configuration.configuration.toolPortalOrigin,
				requestedResource: body?.getAll('resource').length === 1 ? body.get('resource') : null,
				managementAudience: configuration.configuration.managementAudience,
				centralAdminAudience: configuration.configuration.centralAdminAudience,
				ownerFleetCliClientId: configuration.configuration.ownerFleetCliClientId,
				accessTokenSeconds: configuration.configuration.accessTokenSeconds,
				now: configuration.platform.clock.now,
				inspectSignedToken: (token) => {
					if (decodeProtectedHeader(token).typ !== 'at+jwt')
						throw new Error('Wrong signed access token type');
					return accessTokenReleaseClaimsSchema.parse(decodeJwt(token));
				},
				readAgent: agents.read,
				readWorkspaceResource: workspaceResourcePorts(configuration.store).read,
				isPersonSessionActive: persons.isPersonSessionActive,
				isPersonOrganizationSessionActive: async (personId, sessionId, organizationId) =>
					requireStoredValue(
						await configuration.store.persons.isPersonOrganizationSessionActive(
							personId,
							sessionId,
							organizationId,
						),
					),
				deleteSession: persons.deleteSession,
				cleanupUnboundPerson: persons.cleanupUnboundPerson,
			};
			const response = await handleSignInRequest({
				request,
				providerHandler: provider.handler,
				issuedSessions: state.issuedSessions,
				createdUserIds: state.createdUserIds,
				ports,
			});
			if (response.status === 429)
				return await renderFactorFormResponse({
					request,
					crypto: configuration.platform.crypto,
					resume: factorResume,
					response: providerLimitedResponse({
						response,
						requestClass: admission.requestClass,
						log: configuration.platform.log,
					}),
				});
			const method = /\/callback\/(google|github)$/u.exec(url.pathname)?.[1];
			if (state.loginLink.kind === 'changed') {
				const { change, accountId } = state.loginLink;
				requireStoredValue(await configuration.store.linkedLogins.record(change, 'outcome'));
				const recorded = requireStoredValue(
					await configuration.store.linkedLogins.read(change.requestId),
				);
				const account = requireStoredValue(
					await configuration.store.linkedLogins.readAccount(accountId),
				);
				if (
					account === null ||
					account.userId !== change.personId ||
					account.providerId !== change.provider ||
					recorded.length !== 2 ||
					!['intent', 'outcome'].every((phase) =>
						recorded.some(
							(row) =>
								row.phase === phase &&
								row.actorUserId === change.personId &&
								row.targetId === change.provider,
						),
					)
				)
					throw new Error('Login link outcome could not be confirmed');
			}
			if (method !== undefined && state.loginLink.kind === 'none') {
				const actor = state.issuedSessions[0]?.personId ?? 'anonymous';
				const outcome =
					response.headers.has('set-cookie') && state.issuedSessions.length > 0
						? 'succeeded'
						: 'failed';
				requireStoredValue(
					await configuration.store.bootstrap.recordSignIn({ actor, outcome, method }),
				);
			}
			if (url.pathname === '/api/auth/passkey/verify-authentication') {
				// Completion owns this attempt, including an unavailable audit write.
				passkeyAuditPending = false;
				await completePasskeySignIn({
					response,
					issuedSessions: state.issuedSessions,
					recordSignIn: async (record) =>
						requireStoredValue(await configuration.store.bootstrap.recordSignIn(record)),
				});
			}
			return await renderFactorFormResponse({
				request,
				response,
				crypto: configuration.platform.crypto,
				resume: factorResume,
			});
		} catch {
			await Promise.allSettled(
				state.issuedSessions.map((session) => persons.deleteSession(session.sessionId)),
			);
			await Promise.allSettled(
				state.createdUserIds.map((personId) => persons.cleanupUnboundPerson(personId)),
			);
			if (passkeyAuditPending)
				// A release rejection skips completion. Attempt its failed record after cleanup;
				// either an unavailable store result or a rejection still leaves the same 503.
				await Promise.allSettled([
					configuration.store.bootstrap.recordSignIn({
						actor: 'anonymous',
						outcome: 'failed',
						method: 'passkey',
					}),
				]);
			return organizationReadResponse(
				incomingRequest,
				Response.json(
					{ error: 'sign-in-unavailable' },
					{ status: 503, headers: { 'cache-control': 'no-store' } },
				),
			);
		}
	}
}

/**
 * The handler's generic client-input refusal, as its owner-page forwarding routes give before any
 * effect (`fleet-admin-forwarding.ts`): 400 `invalid-request`, no store, no cookie.
 */
function invalidRequestResponse(): Response {
	return Response.json(
		{ error: 'invalid-request' },
		{ status: 400, headers: { 'cache-control': 'no-store' } },
	);
}

/**
 * The client an `Authorization` header names as a Basic credential, decoded by the provider's own
 * decoder (`@better-auth/core` 1.7.11 `dist/oauth2/basic-credentials.mjs:48-60`, which the
 * oauth-provider's client authentication also uses), so this wrapper and the provider never disagree
 * on which client a header names. A header that decoder refuses names none here, and the provider
 * then refuses it itself as `invalid_client` with a Basic challenge (oauth-provider 1.7.11
 * `dist/utils-vIo_wPv5.mjs:607-621`).
 */
function basicClientId(authorization: string | null): string | undefined {
	if (authorization === null) return undefined;
	try {
		return decodeBasicCredentials(authorization).clientId;
	} catch {
		return undefined;
	}
}
