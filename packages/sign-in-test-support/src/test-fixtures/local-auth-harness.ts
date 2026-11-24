import { mkdtemp } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
	signInSchema,
	type SignInClock,
	type SignInObservation,
} from '@agent-collaboration/sign-in-core';
import type { SignInDatabase } from '@agent-collaboration/sign-in-core';
import type {
	SignInHttpConfiguration,
	MachineLoginConfiguration,
	createSignInManagementBinding,
	SocialLoginProvider,
} from '@agent-collaboration/sign-in-core/better-auth';
import type { AuthTarget } from '@agent-collaboration/sign-in-owner-cli';
import { getSessionCookie } from 'better-auth/cookies';
import { and, eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/d1';
import {
	Miniflare,
	Request as WorkerRequest,
	Response as WorkerResponse,
	type WorkerOptions,
} from 'miniflare';
import { z } from 'zod';

import { signInManagementForHost } from '#sign-in-test-support/test-fixtures/async-node-management-caller';
import {
	createAuthProofBarrierServer,
	type ManagementProofControls,
} from '#sign-in-test-support/test-fixtures/auth-proof-barrier-server';
import { createAuthProofForwarderLifecycle } from '#sign-in-test-support/test-fixtures/auth-proof-forwarder-lifecycle';
import {
	authProofHoldTokenHeader,
	createAuthProofHttpResponseHolds,
} from '#sign-in-test-support/test-fixtures/auth-proof-http-response-holds';
import { createAuthProofOutbound } from '#sign-in-test-support/test-fixtures/auth-proof-outbound';
import { recordAuthProofPhase } from '#sign-in-test-support/test-fixtures/auth-proof-phase-recording';
import { observeAuthProofForwarder } from '#sign-in-test-support/test-fixtures/auth-proof-transport-events';
import { navigateLocalBrowser } from '#sign-in-test-support/test-fixtures/browser-navigation';
import { createCaptchaObservationCollector } from '#sign-in-test-support/test-fixtures/captcha-observation-collector';
import { captchaObservationDrainPath } from '#sign-in-test-support/test-fixtures/captcha-observation-control';
import { closedSiteVerifyEndpoint } from '#sign-in-test-support/test-fixtures/closed-siteverify-endpoint';
import {
	createControlledCentralAdmin,
	type ControlledCentralAdmin,
} from '#sign-in-test-support/test-fixtures/controlled-central-admin';
import {
	createControlledCentralApprovals,
	type ControlledCentralApprovals,
} from '#sign-in-test-support/test-fixtures/controlled-central-approvals';
import {
	createControlledCentralEngine,
	type ControlledCentralEngine,
} from '#sign-in-test-support/test-fixtures/controlled-central-engine';
import {
	createControlledCentralProvisioning,
	type ControlledCentralProvisioning,
} from '#sign-in-test-support/test-fixtures/controlled-central-provisioning';
import { startControlledCentralUnixPeer } from '#sign-in-test-support/test-fixtures/controlled-central-unix-peer';
import {
	controlledSignInIds,
	controlledSignInClock,
} from '#sign-in-test-support/test-fixtures/controlled-sign-in-clock';
import { startControlledToolUpstream } from '#sign-in-test-support/test-fixtures/controlled-tool-upstream';
import {
	createControlledTurnstileProtocol,
	type ControlledTurnstileProtocol,
} from '#sign-in-test-support/test-fixtures/controlled-turnstile-protocol';
import {
	createDatabaseProofControls,
	type DatabaseProofControls,
} from '#sign-in-test-support/test-fixtures/database-proof-controls';
import { createExternalSocialProviderProtocol } from '#sign-in-test-support/test-fixtures/external-social-provider-protocol';
import { retainJwksFetchStructuredLog } from '#sign-in-test-support/test-fixtures/jwks-fetch-observation';
import { createLocalAuthBrowser } from '#sign-in-test-support/test-fixtures/local-auth-browser';
import {
	organizationOne,
	organizationTwo,
	toolPortalOrigin,
	managementAudience,
	workspaceOne,
	workspaceConfigurations,
	textBindings,
} from '#sign-in-test-support/test-fixtures/local-auth-configuration';
import {
	createLocalAuthProofClose,
	type AuthProofTeardownObservation,
} from '#sign-in-test-support/test-fixtures/local-auth-proof-close';
import { recordLocalAuthTransportFailure } from '#sign-in-test-support/test-fixtures/local-auth-transport-failure';
import {
	applyLocalSignInMigrations,
	localSignInDatabaseId,
} from '#sign-in-test-support/test-fixtures/local-d1-migrations';
import { loginLocalPerson } from '#sign-in-test-support/test-fixtures/local-person-login';
import type { NativeOwnerCliProfile } from '#sign-in-test-support/test-fixtures/native-owner-cli-profile';
import {
	startNodeAuthProofHost,
	type NodeAuthProofHost,
	type NodeCapabilityRecordingOption,
} from '#sign-in-test-support/test-fixtures/node-auth-proof-host';
import {
	nodeInvocationDigest,
	nodeHttpRequestIdentitySchema,
	type NodeInvocationReceipt,
} from '#sign-in-test-support/test-fixtures/node-management-bridge-contracts';
import { loadNodeProofArtifacts } from '#sign-in-test-support/test-fixtures/node-proof-artifacts';
import { retainOrganizationJourneyEvidence } from '#sign-in-test-support/test-fixtures/organization-journey-evidence';
import { passkeyReleaseFailureStateSchema } from '#sign-in-test-support/test-fixtures/passkey-release-failure';
import { createProofBrowserAddresses } from '#sign-in-test-support/test-fixtures/proof-browser-addresses';
import {
	loadProofBundles,
	proofModuleHashes,
	recordProofHarness,
	type AuthHarnessReadiness,
	type AuthHarnessRequestLimits,
} from '#sign-in-test-support/test-fixtures/proof-bundle-artifacts';
import { loadProofRateLimitBindings } from '#sign-in-test-support/test-fixtures/proof-rate-limit-bindings';
import type { SignInCapabilityRecord } from '#sign-in-test-support/test-fixtures/recording-sign-in-capabilities';
import { retainRevisionJourneyEvidence } from '#sign-in-test-support/test-fixtures/revision-journey-evidence';
import {
	createSoftwareTotpAuthenticator,
	type SoftwareTotpAuthenticator,
} from '#sign-in-test-support/test-fixtures/software-totp-authenticator';
import {
	turnstileTestSecret,
	turnstileTestSiteKey,
} from '#sign-in-test-support/test-fixtures/turnstile-test-keys';
import { webCryptoDigestFailureStateSchema } from '#sign-in-test-support/test-fixtures/web-crypto-digest-failure';
import { clockedWorkerManifest } from '#sign-in-test-support/test-fixtures/worker-module-manifest';

export * from '#sign-in-test-support/test-fixtures/local-auth-configuration';

/** Actual local workerd, D1, Better Auth, named RPC and Gateway/DO. No admission or identity rows are preseeded. */
/** A private link endpoint for the Node host: its socket, and how to stop what serves it. */
export interface CentralLinkEndpoint {
	readonly socketPath: string;
	readonly close: () => Promise<void>;
}

/** One binding in a Worker's environment, as the harness's Miniflare build spells it. */
export type WorkerEnvironmentBinding = NonNullable<WorkerOptions['config']['env']>[string];

/**
 * B2e workerd only: real central runs in its own pinned runtime, started by its own bridge.
 * This names sign-in's CENTRAL binding, the hop that reaches central's link.
 */
export interface WorkerdCentralRuntime {
	readonly centralBinding: WorkerEnvironmentBinding;
	readonly privateWorker?: WorkerOptions;
	readonly storageWorker?: WorkerOptions;
	readonly observationWorker?: WorkerOptions;
}

export async function startLocalAuthHarness(
	options: {
		readonly turnstileSecret: 'published-test' | 'missing';
		readonly host?: 'cloudflare' | 'node';
		readonly issuerHostname?: 'localhost';
		readonly siteVerify?: 'stand-in' | 'connection-refused';
		readonly cloudflareClientAddress?: 'stable-browser' | 'absent';
		readonly authenticatorClock?: SignInClock;
		/**
		 * B2e only: the private link a real central serves, started once the harness knows its
		 * issuer. Node hosts reach it in place of the recording peer; omitted, nothing changes.
		 */
		readonly centralLink?: (issuer: string) => Promise<CentralLinkEndpoint>;
		/**
		 * B2e only: real central, started once the harness knows its issuer. workerd hosts bind
		 * CENTRAL to the hop it names.
		 */
		readonly workerdCentral?: (issuer: string) => Promise<WorkerdCentralRuntime>;
		readonly machineLinkStorageWorker?: WorkerOptions;
		readonly machineLogin?: Omit<MachineLoginConfiguration, 'linkUrlTemplate'>;
		readonly machineDecisions?: (request: Request) => Promise<Response>;
		/**
		 * Test-only (V2, Node host only): record every crypto, clock, ID and central call of the
		 * in-process Node sign-in host. Refused on Cloudflare, whose host runs in workerd.
		 */
		readonly nodeCapabilityRecording?: NodeCapabilityRecordingOption;
	} = {
		turnstileSecret: 'published-test',
	},
): Promise<
	DatabaseProofControls & {
		readonly miniflare: Miniflare;
		readonly signInHost: 'cloudflare' | 'node';
		readonly database: SignInDatabase;
		readonly providerConfiguration: SignInHttpConfiguration | undefined;
		readonly signInManagement: () => Promise<ReturnType<typeof createSignInManagementBinding>>;
		readonly target: AuthTarget;
		readonly effects: Awaited<ReturnType<typeof startControlledToolUpstream>>['effects'];
		readonly issuer: string;
		readonly turnstile: ControlledTurnstileProtocol;
		readonly captchaObservations: () => Promise<readonly SignInObservation[]>;
		/** Every recorded call so far, when `nodeCapabilityRecording` armed the Node host. */
		readonly capabilityRecords: () => readonly SignInCapabilityRecord[];
		readonly makeLimiterUnavailable: () => Promise<void>;
		readonly useControlledServicePageWindow: () => Promise<void>;
		readonly useControlledPasskeyWindow: () => Promise<void>;
		readonly failNextPasskeyUserRead: () => Promise<void>;
		readonly failNextPasskeyReleaseCleanup: () => Promise<void>;
		/** The host's next WebCrypto digest of exactly these bytes rejects (OperationError), once. */
		readonly failNextWebCryptoDigestOf: (input: Uint8Array) => Promise<void>;
		readonly webCryptoDigestFailureState: () => Promise<
			z.infer<typeof webCryptoDigestFailureStateSchema>
		>;
		readonly passkeyReleaseFailureState: () => Promise<
			z.infer<typeof passkeyReleaseFailureStateSchema>
		>;
		readonly lastSessionInsert: () => Promise<{
			readonly query: string;
			readonly parameters: readonly unknown[];
		}>;
		readonly siteVerifyAttempts: ReturnType<typeof createAuthProofOutbound>['siteVerifyAttempts'];
		readonly siteVerifyTransportFailures: ReturnType<
			typeof createAuthProofOutbound
		>['transportFailures'];
		readonly totpAuthenticator: SoftwareTotpAuthenticator;
		readonly centralProvisioning: ControlledCentralProvisioning;
		/** The admin routes' named stand-in for central, and its clock (moved with the host's). */
		readonly centralAdmin: ControlledCentralAdmin;
		/** C3's approval routes' named stand-in for central, on the same clock as the admin one. */
		readonly centralApprovals: ControlledCentralApprovals;
		/** The engine administration routes' named stand-in for central, on the same clock. */
		readonly centralEngine: ControlledCentralEngine;
		readonly setCentralAdminTime: (milliseconds: number) => void;
		/** The production key-change re-sign (B2 rule 6) on either host; renewal itself has no
		 * trigger, it runs inside each real Fleet call (owner, 9 Nov). */
		readonly reSignForKeyChange: () => Promise<unknown>;
		/** Fires the scheduled event for one cron on workerd; Node has no cron (see the drain proof route). */
		readonly fireCron: (cron: string) => Promise<void>;
		/** Resolves once every after-response task the sign-in host deferred has finished. */
		readonly settleDeferredWork: () => Promise<void>;
		readonly cookie: () => string;
		readonly useBrowser: (browserKey: string) => void;
		readonly browserAddress: () => string;
		readonly authAsBrowser: (
			browserKey: string,
			pathname: string,
			init?: RequestInit,
		) => Promise<Response>;
		readonly clearBrowserSession: () => void;
		readonly providerCallback: (
			provider: SocialLoginProvider,
			url: URL,
			email: string,
			verified: boolean,
		) => URL;
		readonly managementHolds: ManagementProofControls;
		readonly httpResponseHolds: ReturnType<typeof createAuthProofHttpResponseHolds>;
		readonly ownerToken: (profile?: NativeOwnerCliProfile) => Promise<string>;
		readonly personToken: (email: string, verified?: boolean) => Promise<string>;
		readonly auth: (pathname: string, init?: RequestInit) => Promise<Response>;
		readonly gateway: (
			pathname: string,
			init?: RequestInit,
			secondHeap?: boolean,
		) => Promise<Response>;
		readonly teardownObservations: readonly AuthProofTeardownObservation[];
		readonly close: () => Promise<void>;
	}
> {
	const root = fileURLToPath(new URL('../../../../', import.meta.url));
	const proofRateLimitBindings = await loadProofRateLimitBindings(root);
	const signInHost = z
		.enum(['cloudflare', 'node'])
		.parse(options.host ?? process.env.SIGN_IN_TEST_HOST ?? 'cloudflare');
	const centralProvisioning = createControlledCentralProvisioning(options.machineDecisions);
	let centralUnix: CentralLinkEndpoint | null = null;
	let nodeHost: NodeAuthProofHost | undefined;
	const nodeHttpReceipts: NodeInvocationReceipt[] = [];
	const runtimeDirectory = await mkdtemp(path.join(tmpdir(), '2026-10-auth-s1-'));
	const resourcePersistencePath = await applyLocalSignInMigrations({
		repositoryRoot: root,
		runtimeDirectory,
	});
	const providers = await createExternalSocialProviderProtocol();
	const totpAuthenticator = createSoftwareTotpAuthenticator(
		options.authenticatorClock ?? controlledSignInClock,
	);
	const turnstile = createControlledTurnstileProtocol();
	const captchaObservations = createCaptchaObservationCollector();
	const browserAddresses = createProofBrowserAddresses(controlledSignInIds);
	const upstream = await startControlledToolUpstream();
	const miniflareReady = Promise.withResolvers<Miniflare>();
	const proofBarriers = createAuthProofBarrierServer();
	const forwarderLifecycle = createAuthProofForwarderLifecycle();
	const httpResponseHolds = createAuthProofHttpResponseHolds();
	const server = createServer((request, response) => {
		void forwarderLifecycle.trackRequest(async (): Promise<void> => {
			const transportRequestId = controlledSignInIds.nextId();
			const pathnameOnly = new URL(request.url ?? '/', 'http://proof.invalid').pathname;
			const requestIdentity = nodeHttpRequestIdentitySchema.parse({
				httpMethod: request.method ?? 'GET',
				path: pathnameOnly,
			});
			let nodeInvocationId: string | null = null;
			const observedSurface =
				pathnameOnly === '/api/auth/jwks'
					? 'jwks'
					: pathnameOnly.startsWith('/management/')
						? 'management'
						: null;
			if (observedSurface !== null)
				await recordAuthProofPhase({
					kind: 'request-start',
					requestId: transportRequestId,
					surface: observedSurface,
					targetOrigin: issuer,
				});
			try {
				const runtime = await miniflareReady.promise;
				let body = '';
				for await (const chunk of request) body += String(chunk);
				const pathname = request.url ?? '/';
				if (pathname === '/__auth-proof/turnstile-siteverify') {
					const verdict = await turnstile.fetch(
						new WorkerRequest(new URL(pathname, issuer).toString(), {
							method: request.method ?? 'POST',
							headers: { 'content-type': 'application/json' },
							body,
						}),
						runtime,
					);
					response.writeHead(verdict.status, Object.fromEntries(verdict.headers));
					response.end(Buffer.from(await verdict.arrayBuffer()));
					return;
				}
				// Management controls are Node capabilities; public HTTP always reaches the Worker fence.
				const barrierResponse = pathname.startsWith('/__auth-proof/management-hold/')
					? null
					: await proofBarriers.handle(pathname, request.method ?? 'GET', body);
				if (barrierResponse !== null) {
					response.writeHead(barrierResponse.status, Object.fromEntries(barrierResponse.headers));
					response.end(Buffer.from(await barrierResponse.arrayBuffer()));
					return;
				}
				const gatewayRequest =
					pathname.startsWith('/management/') ||
					pathname.startsWith('/workspaces/') ||
					pathname.startsWith('/mcp');
				const headers = Object.fromEntries(
					Object.entries(request.headers).flatMap(([name, value]) =>
						value === undefined ? [] : [[name, Array.isArray(value) ? value.join(', ') : value]],
					),
				);
				const browserNavigation =
					!gatewayRequest &&
					request.method === 'GET' &&
					request.headers['sec-fetch-mode'] === 'navigate';
				const nodeRequest = signInHost === 'node' && !gatewayRequest;
				const browserAddress = browserAddresses.forCookie(
					headers.cookie,
					headers['x-auth-proof-browser'],
				);
				const holdToken = headers[authProofHoldTokenHeader] ?? null;
				delete headers[authProofHoldTokenHeader];
				delete headers['x-auth-proof-browser'];
				// This relay is the fixture's trusted proxy/edge. Incoming copies
				// cannot select an address; each browser has one stable assignment.
				delete headers['x-auth-proof-client-address'];
				delete headers['cf-connecting-ip'];
				if (!gatewayRequest) {
					headers['x-auth-proof-client-address'] = browserAddress;
					if (options.cloudflareClientAddress !== 'absent')
						headers['cf-connecting-ip'] = browserAddress;
				}
				const invocationId = nodeRequest ? controlledSignInIds.nextId() : null;
				nodeInvocationId = invocationId;
				const context = {
					...requestIdentity,
					requestId: transportRequestId,
					nodeInvocationId,
					host: signInHost,
				};
				const transport = observeAuthProofForwarder(context, response);
				// Bytes, not text: an edge relays a request without inventing a content type for it.
				const forwardedBody = body === '' ? {} : { body: new TextEncoder().encode(body) };
				if (nodeRequest && nodeHost === undefined)
					throw new Error('Selected Node sign-in host is unavailable');
				if (invocationId !== null) headers['x-auth-proof-invocation'] = invocationId;
				const result =
					nodeRequest && nodeHost !== undefined
						? browserNavigation
							? await navigateLocalBrowser(new URL(pathname, issuer), headers, nodeHost.address)
							: await fetch(new URL(pathname, nodeHost.address), {
									method: request.method ?? 'GET',
									headers,
									...forwardedBody,
									redirect: 'manual',
								})
						: browserNavigation
							? await navigateLocalBrowser(new URL(pathname, issuer), headers, await runtime.ready)
							: await (
									await runtime.getWorker(gatewayRequest ? 'gateway-one' : 'sign-in')
								).fetch(`${issuer}${pathname}`, {
									method: request.method ?? 'GET',
									headers,
									...forwardedBody,
									redirect: 'manual',
								});
				transport.headersReceived(result.status);
				if (!gatewayRequest) browserAddresses.rememberResponse(result.headers, browserAddress);
				if (invocationId !== null) {
					if (result.headers.get('x-auth-proof-invocation') !== invocationId)
						throw new Error('Public sign-in call was not served by its selected Node host');
					nodeHttpReceipts.push({
						...requestIdentity,
						invocationId,
						method: 'http',
						requestHash: await nodeInvocationDigest(body),
						responseHash: await nodeInvocationDigest(await result.clone().text()),
						status: result.status,
					});
				}
				const cookies = result.headers.getSetCookie();
				if (observedSurface !== null)
					await recordAuthProofPhase({
						kind: 'request-end',
						requestId: transportRequestId,
						status: result.status,
					});
				response.writeHead(result.status, {
					...Object.fromEntries(result.headers),
					...(cookies.length === 0 ? {} : { 'set-cookie': cookies }),
				});
				const outgoingBody = Buffer.from(await result.arrayBuffer());
				transport.bodyRead(result.status);
				await httpResponseHolds.send({
					pathname: pathnameOnly,
					method: request.method ?? 'GET',
					holdToken,
					response,
					body: outgoingBody,
				});
			} catch (error) {
				if (observedSurface !== null)
					await recordAuthProofPhase({
						kind: 'request-end',
						requestId: transportRequestId,
						status: 503,
					});
				recordLocalAuthTransportFailure('forwarder', error, {
					...requestIdentity,
					requestId: transportRequestId,
					nodeInvocationId,
				});
				if (response.headersSent) response.destroy();
				else response.writeHead(503).end('Local auth transport failed');
			}
		});
	});
	async function closeServers(): Promise<void> {
		proofBarriers.close();
		server.closeAllConnections();
		await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
		await upstream.close();
		await centralUnix?.close();
	}
	await new Promise<void>((resolveListen, rejectListen) => {
		server.once('error', rejectListen);
		server.listen(0, '127.0.0.1', resolveListen);
	});
	const address = server.address();
	if (address === null || typeof address === 'string')
		throw new Error('Local auth listener unavailable');
	const issuer = `http://${options.issuerHostname ?? '127.0.0.1'}:${address.port}`;
	const siteVerifyURL =
		options.siteVerify === 'connection-refused'
			? await closedSiteVerifyEndpoint()
			: new URL('/__auth-proof/turnstile-siteverify', issuer).toString();
	const bundles = await loadProofBundles(root).catch(async (error: unknown) => {
		await closeServers();
		throw error;
	});
	const authScript = bundles.auth;
	const gatewayScript = bundles.gateway;
	const centralPublicOrigin = 'https://central.example.invalid';
	const machineLogin =
		options.machineLogin === undefined
			? undefined
			: {
					...options.machineLogin,
					linkUrlTemplate:
						signInHost === 'cloudflare'
							? `https://${new URL(issuer).host}/api/fleet/link/{organization_id}`
							: `${centralPublicOrigin}/v1/organizations/{organization_id}/link`,
				};
	const configuration = {
		issuer,
		mode: 'private',
		ownerEmail: 'owner@example.invalid',
		toolPortalOrigin,
		managementAudience,
		centralIdentityAudience: 'https://central.example.invalid/identity',
		centralAdminAudience: 'https://central.example.invalid/admin',
		centralPublicOrigin,
		adminPageClientId: 'admin-page-local',
		ownerFleetCliClientId: 'owner-fleet-cli-local',
		organizationStatementLifetimeSeconds: 10_368_000,
		organizationIds: [organizationOne, organizationTwo],
		ownerCliClientId: 'owner-cli-local',
		ownerCliRedirectUri: 'http://127.0.0.1/callback',
		accessTokenSeconds: 300,
		...(machineLogin === undefined ? {} : { machineLogin }),
		managementHumanCheck: 'remembered-login',
		turnstile: {
			kind: 'local',
			siteKey: turnstileTestSiteKey,
			siteVerifyURLOverride: siteVerifyURL,
		},
	};
	const nodeArtifacts = signInHost === 'node' ? await loadNodeProofArtifacts(root) : null;
	if (signInHost === 'cloudflare' && options.centralLink !== undefined)
		throw new Error(
			'A real central link socket is for the Node host; workerd binds CENTRAL in Miniflare',
		);
	if (signInHost === 'cloudflare' && options.nodeCapabilityRecording !== undefined)
		throw new Error(
			'Capability recording wraps the in-process Node host; the Cloudflare host runs in workerd',
		);
	if (signInHost === 'node' && options.workerdCentral !== undefined)
		throw new Error('A workerd central runtime is for the workerd host; Node uses centralLink');
	const workerdCentral = await (options.workerdCentral?.(issuer) ?? Promise.resolve(null)).catch(
		async (error: unknown) => {
			await closeServers();
			throw error;
		},
	);
	const machineLinkStorageWorker =
		workerdCentral?.storageWorker ?? options.machineLinkStorageWorker;
	if (signInHost === 'node') {
		try {
			centralUnix =
				options.centralLink === undefined
					? await startControlledCentralUnixPeer(centralProvisioning)
					: await options.centralLink(issuer);
			nodeHost = await startNodeAuthProofHost({
				runtimeDirectory,
				centralSocketPath: centralUnix.socketPath,
				configuration,
				issuer,
				clientAddress: {
					kind: 'trusted-proxy',
					peers: ['127.0.0.1', '::1', '::ffff:127.0.0.1'],
					header: 'x-auth-proof-client-address',
				},
				barriers: proofBarriers,
				...(options.nodeCapabilityRecording === undefined
					? {}
					: { capabilityRecording: options.nodeCapabilityRecording }),
				provider: async (request: Request): Promise<Response> => {
					const response = await outbound.fetch(
						new WorkerRequest(request.url, {
							method: request.method,
							headers: Object.fromEntries(request.headers),
							...(['GET', 'HEAD'].includes(request.method) ? {} : { body: await request.text() }),
						}),
						await miniflareReady.promise,
					);
					return new Response(await response.arrayBuffer(), {
						status: response.status,
						headers: Object.fromEntries(response.headers),
					});
				},
				...(options.turnstileSecret === 'published-test'
					? { turnstileSecret: turnstileTestSecret }
					: {}),
				siteVerifyURL,
			});
		} catch (error) {
			await closeServers();
			throw error;
		}
	}
	const outbound = createAuthProofOutbound({
		issuer,
		upstreamOrigin: upstream.url,
		siteVerifyURL,
		...(nodeHost === undefined ? {} : { nodeOrigin: nodeHost.address.origin }),
		provider: providers,
		barriers: proofBarriers,
	});

	const gatewayBindings = {
		SIGN_IN_ISSUER: issuer,
		SIGN_IN_JWKS_URL: `${issuer}/api/auth/jwks`,
		TOOL_PORTAL_ORIGIN: toolPortalOrigin,
		MANAGEMENT_AUDIENCE: managementAudience,
		WORKSPACE_CONFIGURATIONS: JSON.stringify(workspaceConfigurations(upstream.url)),
		ONE_CREDENTIAL: 'Bearer organization-one-canary',
		TWO_CREDENTIAL: 'Bearer workspace-two-canary',
		THREE_CREDENTIAL: 'Bearer organization-two-canary',
		APPROVAL_KEY: '12'.repeat(32),
	};
	const authManifest = clockedWorkerManifest({
		kind: 'production-proof',
		host: 'auth',
		application: authScript,
		production: bundles.productionAuth,
		signingObserver: bundles.signingObserver,
		clock: bundles.clock,
		startup: bundles.startup,
	});
	const gatewayManifest = clockedWorkerManifest({
		kind: 'production-proof',
		host: 'gateway',
		application: gatewayScript,
		production: bundles.productionGateway,
		signingObserver: bundles.signingObserver,
		clock: bundles.clock,
		startup: bundles.startup,
	});
	const miniflare = await Promise.resolve()
		.then(
			async () =>
				new Miniflare({
					resourcePersistencePath,
					handleStructuredLogs: (entry) => {
						retainJwksFetchStructuredLog(entry);
						captchaObservations.handleStructuredLog(entry);
					},
					telemetry: { enabled: false },
					logRequests: false,
					workers: [
						...(nodeArtifacts === null || nodeHost === undefined
							? []
							: ([
									{
										config: {
											type: 'worker',
											name: 'node-management-bridge',
											manifest: clockedWorkerManifest({
												kind: 'storage-proof',
												startup: bundles.startup,
												application: nodeArtifacts.bridge,
												clock: bundles.clock,
											}),
											compatibilityDate: '2026-08-15',
											compatibilityFlags: ['nodejs_compat'],
											env: {
												...textBindings({ NODE_SIGN_IN_ORIGIN: nodeHost.address.origin }),
												SELF_MANAGEMENT: {
													type: 'worker',
													workerName: 'node-management-bridge',
													exportName: 'NodeAgentClientManagement',
												},
											},
										},
										dev: { outboundService: { type: 'fetcher', handler: outbound.fetch } },
									},
								] satisfies WorkerOptions[])),
						{
							config: {
								type: 'worker',
								name: 'sign-in',
								manifest: authManifest,
								compatibilityDate: '2026-08-15',
								compatibilityFlags: ['nodejs_compat'],
								env: {
									DB: { type: 'd1', id: localSignInDatabaseId },
									CENTRAL: workerdCentral?.centralBinding ?? {
										type: 'fetcher',
										handler: async (incoming): Promise<WorkerResponse> => {
											const response = await centralProvisioning.fetch(
												new Request(incoming.url, {
													method: incoming.method,
													headers: Object.fromEntries(incoming.headers),
													...(['GET', 'HEAD'].includes(incoming.method)
														? {}
														: { body: await incoming.arrayBuffer() }),
												}),
											);
											return new WorkerResponse(await response.arrayBuffer(), {
												status: response.status,
												headers: Object.fromEntries(response.headers),
											});
										},
									},
									...(machineLinkStorageWorker === undefined
										? {}
										: {
												CENTRAL_LINK: {
													type: 'worker',
													workerName: machineLinkStorageWorker.config.name,
												},
											}),
									...proofRateLimitBindings,
									...textBindings({
										SIGN_IN_CONFIGURATION: JSON.stringify(configuration),
										AUTH_PROOF_CONTROL_ORIGIN: issuer,
										AUTH_SECRET: 'test-only-auth-secret-'.repeat(3),
										...(options.turnstileSecret === 'published-test'
											? { TURNSTILE_SECRET_KEY: turnstileTestSecret }
											: {}),
										GOOGLE_CLIENT_ID: 'fixture-google-client',
										GOOGLE_CLIENT_SECRET: 'fixture-google-secret',
										GITHUB_CLIENT_ID: 'fixture-github-client',
										GITHUB_CLIENT_SECRET: 'fixture-github-secret',
									}),
								},
							},
							dev: { outboundService: { type: 'fetcher', handler: outbound.fetch } },
						},
						...(machineLinkStorageWorker === undefined ? [] : [machineLinkStorageWorker]),
						...(workerdCentral?.privateWorker === undefined ? [] : [workerdCentral.privateWorker]),
						...(workerdCentral?.observationWorker === undefined
							? []
							: [workerdCentral.observationWorker]),
						...['gateway-one', 'gateway-two'].map((name): WorkerOptions => ({
							config: {
								type: 'worker',
								name,
								manifest: gatewayManifest,
								compatibilityDate: '2026-08-15',
								env: {
									...textBindings(gatewayBindings),
									SIGN_IN: {
										type: 'worker',
										workerName: signInHost === 'node' ? 'node-management-bridge' : 'sign-in',
										exportName:
											signInHost === 'node' ? 'NodeAgentClientManagement' : 'AgentClientManagement',
									},
									WORKSPACES: {
										type: 'durable-object',
										workerName: 'gateway-one',
										exportName: 'WorkspaceAuthority',
									},
									CALL_ANALYTICS: { type: 'analytics-engine-dataset', name: 'auth-proof-calls' },
								},
								...(name === 'gateway-one'
									? {
											exports: {
												WorkspaceAuthority: { type: 'durable-object', storage: 'sqlite' },
											},
										}
									: {}),
							},
							dev: { outboundService: { type: 'fetcher', handler: outbound.fetch } },
						})),
					],
				}),
		)
		.catch(async (error: unknown) => {
			await closeServers();
			throw error;
		});
	miniflareReady.resolve(miniflare);
	const database = await (async (): Promise<SignInDatabase> => {
		await miniflare.ready;
		return (
			nodeHost?.database ??
			drizzle(await miniflare.getD1Database('DB', 'sign-in'), { schema: signInSchema })
		);
	})().catch(async (error: unknown) => {
		try {
			await miniflare.dispose();
		} finally {
			await closeServers();
		}
		throw error;
	});
	let readiness: AuthHarnessReadiness = { ready: false, readinessEvent: 'none' };
	let requestLimitIdentity: AuthHarnessRequestLimits = {
		outerCounter: signInHost === 'node' ? 'node-fixed-window' : 'cloudflare-real-binding',
		backingFailure: 'none',
		observations: [],
	};
	let limitObservations: AuthHarnessRequestLimits['observations'] = [];
	const browser = createLocalAuthBrowser({
		issuer,
		onJwksReady: () => recordTarget({ ready: true, readinessEvent: 'jwks' }),
		onSignInSession: async (cookie) => {
			const signedCookie = getSessionCookie(new Headers({ cookie }));
			if (signedCookie === null)
				throw new Error('Completed provider callback has no session cookie');
			const value = decodeURIComponent(signedCookie);
			const boundary = value.lastIndexOf('.');
			if (boundary <= 0) throw new Error('Completed provider callback has no signed session token');
			const rows = await database
				.select({ id: signInSchema.session.id })
				.from(signInSchema.session)
				.innerJoin(signInSchema.user, eq(signInSchema.user.id, signInSchema.session.userId))
				.where(
					and(
						eq(signInSchema.session.token, value.slice(0, boundary)),
						eq(signInSchema.user.emailVerified, true),
					),
				);
			if (
				!z
					.array(z.object({ id: z.uuidv7() }))
					.length(1)
					.safeParse(rows).success
			)
				throw new Error('Completed provider callback has no verified session row');
			await recordTarget({ ready: true, readinessEvent: 'signInSession' });
		},
	});
	function auth(pathname: string, init: RequestInit = {}): Promise<Response> {
		const headers = new Headers(init.headers);
		headers.delete('x-auth-proof-browser');
		return browser.auth(pathname, { ...init, headers });
	}
	function authAsBrowser(
		browserKey: string,
		pathname: string,
		init: RequestInit = {},
	): Promise<Response> {
		const headers = new Headers(init.headers);
		headers.set('x-auth-proof-browser', browserAddresses.transportFor(browserKey));
		return browser.auth(pathname, { ...init, headers });
	}
	const target: AuthTarget = {
		issuer,
		managementAudience,
		gatewayUrl: issuer,
		organizationId: organizationOne,
		workspaceId: workspaceOne,
		ownerCliClientId: configuration.ownerCliClientId,
		ownerCliRedirectUri: configuration.ownerCliRedirectUri,
		tokenCachePath: path.join(runtimeDirectory, 'owner-token.json'),
		centralAdminAudience: configuration.centralAdminAudience,
		centralPublicOrigin: configuration.centralPublicOrigin,
		ownerFleetCliClientId: configuration.ownerFleetCliClientId,
	};
	const databaseControls = createDatabaseProofControls({ database, auth });
	const receiptId = controlledSignInIds.nextId();
	async function recordTarget(next: AuthHarnessReadiness): Promise<void> {
		const rank = { none: 0, signInSession: 1, jwks: 2, personToken: 3 };
		if (rank[next.readinessEvent] >= rank[readiness.readinessEvent]) readiness = next;
		const requestLimits: AuthHarnessRequestLimits = {
			...requestLimitIdentity,
			observations: limitObservations,
		};
		await recordProofHarness({
			requestLimits,
			receiptId,
			identity: bundles.identity,
			configuration: {
				signIn: configuration,
				gateway: gatewayBindings,
				moduleHashes: {
					auth: proofModuleHashes(authManifest),
					gateway: proofModuleHashes(gatewayManifest),
				},
			},
			client: { ...target, entry: 'scripts/verify-auth/owner-cli.ts' },
			...readiness,
		});
	}
	await recordTarget({ ready: false, readinessEvent: 'none' });
	async function retainLimitObservations(
		observations: readonly SignInObservation[],
	): Promise<readonly SignInObservation[]> {
		limitObservations = observations.filter(
			(observation) =>
				observation.kind === 'request-limited' || observation.kind === 'request-limit-unavailable',
		);
		await recordTarget(readiness);
		return observations;
	}
	async function personToken(
		email: string,
		verified = true,
		profile?: NativeOwnerCliProfile,
	): Promise<string> {
		browserAddresses.useBrowser(email);
		const token = await loginLocalPerson({
			target,
			repositoryRoot: root,
			issuer,
			email,
			verified,
			auth,
			database,
			google: providers.google,
			totpAuthenticator,
			...(profile === undefined ? {} : { profile }),
			cookies: browser.cookies,
			captchaToken: (): string =>
				turnstile.issueToken({
					action: 'sign_in_social',
					hostname: new URL(issuer).hostname,
					verdict: 'accepted',
				}),
		});
		await recordTarget({ ready: true, readinessEvent: 'personToken' });
		return token;
	}

	let centralAdminIds = 0;
	let centralAdminTime: number = controlledSignInClock.now();
	const centralAdmin = createControlledCentralAdmin({
		issuer,
		audience: configuration.centralAdminAudience,
		publicOrigin: configuration.centralPublicOrigin,
		readSigningKeys: async () =>
			z
				.object({ keys: z.array(z.looseObject({ kty: z.string() })) })
				.parse(await (await auth('/api/auth/jwks')).json()),
		now: () => centralAdminTime,
		nextId: () => {
			centralAdminIds += 1;
			const timestamp = centralAdminTime.toString(16).padStart(12, '0');
			return `${timestamp.slice(0, 8)}-${timestamp.slice(8)}-7000-8000-${centralAdminIds.toString(16).padStart(12, '0')}`;
		},
		hasFloors: centralProvisioning.hasFloors,
	});
	centralProvisioning.attachAdmin(centralAdmin);
	const centralApprovals = createControlledCentralApprovals({
		issuer,
		audience: configuration.centralAdminAudience,
		publicOrigin: configuration.centralPublicOrigin,
		readSigningKeys: async () =>
			z
				.object({ keys: z.array(z.looseObject({ kty: z.string() })) })
				.parse(await (await auth('/api/auth/jwks')).json()),
		now: () => centralAdminTime,
		readFloors: centralProvisioning.readFloors,
	});
	centralProvisioning.attachApprovals(centralApprovals);
	const centralEngine = createControlledCentralEngine({
		issuer,
		audience: configuration.centralAdminAudience,
		publicOrigin: configuration.centralPublicOrigin,
		readSigningKeys: async () =>
			z
				.object({ keys: z.array(z.looseObject({ kty: z.string() })) })
				.parse(await (await auth('/api/auth/jwks')).json()),
		now: () => centralAdminTime,
		readFloors: centralProvisioning.readFloors,
	});
	centralProvisioning.attachEngine(centralEngine);
	const proofClose = createLocalAuthProofClose({
		runtime: miniflare,
		nodeHost,
		identity: nodeArtifacts?.identity ?? null,
		receiptId,
		httpReceipts: nodeHttpReceipts,
		lifecycle: forwarderLifecycle,
		closeServers,
		captureEvidence: async (): Promise<void> => {
			await retainRevisionJourneyEvidence({
				database,
				receiptId,
				signInHost,
				peer: centralProvisioning,
			});
			await retainOrganizationJourneyEvidence({
				database,
				peer: centralProvisioning,
				receiptId,
				signInHost,
			});
		},
	});

	return {
		miniflare,
		signInHost,
		centralProvisioning,
		centralAdmin,
		centralApprovals,
		centralEngine,
		setCentralAdminTime: (milliseconds: number): void => {
			centralAdminTime = milliseconds;
		},
		totpAuthenticator,
		database,
		providerConfiguration: nodeHost?.configuration,
		signInManagement: () => signInManagementForHost(miniflare, signInHost),
		...databaseControls,
		target,
		effects: upstream.effects,
		issuer,
		turnstile,
		siteVerifyAttempts: outbound.siteVerifyAttempts,
		siteVerifyTransportFailures: outbound.transportFailures,
		async failNextPasskeyUserRead(): Promise<void> {
			const response = await auth('/__auth-proof/fail-next-passkey-user-read', { method: 'POST' });
			if (!response.ok) throw new Error('Passkey user read fault not armed');
		},
		async failNextWebCryptoDigestOf(input: Uint8Array): Promise<void> {
			const response = await auth('/__auth-proof/web-crypto-digest-failure', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ inputBase64url: Buffer.from(input).toString('base64url') }),
			});
			if (!response.ok) throw new Error('WebCrypto digest fault not armed');
		},
		async webCryptoDigestFailureState(): Promise<
			z.infer<typeof webCryptoDigestFailureStateSchema>
		> {
			const response = await auth('/__auth-proof/web-crypto-digest-failure');
			return z
				.strictObject({ state: webCryptoDigestFailureStateSchema })
				.parse(await response.json()).state;
		},
		async failNextPasskeyReleaseCleanup(): Promise<void> {
			const response = await auth('/__auth-proof/passkey-release-failure', { method: 'POST' });
			if (!response.ok) throw new Error('Passkey release cleanup fault not armed');
		},
		async passkeyReleaseFailureState(): Promise<z.infer<typeof passkeyReleaseFailureStateSchema>> {
			const response = await auth('/__auth-proof/passkey-release-failure');
			return z
				.strictObject({ state: passkeyReleaseFailureStateSchema })
				.parse(await response.json()).state;
		},
		async lastSessionInsert() {
			const response = await auth('/__auth-proof/last-session-insert');
			if (!response.ok) throw new Error('Session insert recorder unavailable');
			return z
				.strictObject({ query: z.string(), parameters: z.array(z.unknown()) })
				.parse(await response.json());
		},
		async makeLimiterUnavailable(): Promise<void> {
			const response = await auth('/__auth-proof/limiter-unavailable', { method: 'POST' });
			if (!response.ok) throw new Error('Limiter failure control was not armed');
			requestLimitIdentity = {
				...requestLimitIdentity,
				backingFailure:
					signInHost === 'node' ? 'node-counter-throws' : 'cloudflare-binding-rejects',
			};
			await recordTarget(readiness);
		},
		async useControlledServicePageWindow(): Promise<void> {
			// Node already uses the injected clock in its real production counter.
			if (signInHost === 'node') return;
			const response = await auth('/__auth-proof/limiter-controlled-window', { method: 'POST' });
			if (!response.ok) throw new Error('Controlled service-page window was not armed');
			z.strictObject({ kind: z.literal('controlled-window') }).parse(await response.json());
			requestLimitIdentity = {
				...requestLimitIdentity,
				outerCounter: 'cloudflare-controlled-binding-stand-in',
				proofCase: 'service-page-exact-budget',
			};
			await recordTarget(readiness);
		},
		async useControlledPasskeyWindow(): Promise<void> {
			if (signInHost === 'node') return;
			const response = await auth('/__auth-proof/limiter-controlled-passkey-window', {
				method: 'POST',
			});
			if (!response.ok) throw new Error('Controlled passkey window was not armed');
			z.strictObject({ kind: z.literal('controlled-passkey-window') }).parse(await response.json());
			requestLimitIdentity = {
				...requestLimitIdentity,
				outerCounter: 'cloudflare-controlled-binding-stand-in',
				proofCase: 'passkey-exact-budget',
			};
			await recordTarget(readiness);
		},
		capabilityRecords(): readonly SignInCapabilityRecord[] {
			const recording = nodeHost?.capabilityRecording ?? null;
			if (recording === null) throw new Error('Capability recording was not armed on a Node host');
			return recording.records();
		},
		async captchaObservations(): Promise<readonly SignInObservation[]> {
			if (nodeHost !== undefined) {
				const response = await auth(captchaObservationDrainPath);
				if (!response.ok) throw new Error('Node captcha observation marker failed');
				return retainLimitObservations(nodeHost.captchaObservations());
			}
			const requestId = controlledSignInIds.nextId();
			const drained = captchaObservations.waitForDrain(requestId);
			const response = await auth(`${captchaObservationDrainPath}?request_id=${requestId}`);
			if (!response.ok) throw new Error('Captcha observation stream marker failed');
			await drained;
			return retainLimitObservations(captchaObservations.observations());
		},
		async reSignForKeyChange(): Promise<unknown> {
			const response = await auth('/__auth-proof/organization-key-change', { method: 'POST' });
			if (!response.ok) throw new Error('Key-change re-sign did not complete');
			return z.strictObject({ result: z.unknown() }).parse(await response.json()).result;
		},
		async fireCron(cron: string): Promise<void> {
			if (nodeHost !== undefined) throw new Error('The Node host has no cron');
			const outcome = await (await miniflare.getWorker('sign-in')).scheduled({ cron });
			if (outcome.outcome !== 'ok') throw new Error(`Scheduled ${cron} ended ${outcome.outcome}`);
		},
		async settleDeferredWork(): Promise<void> {
			const response = await auth('/__auth-proof/deferred-work');
			if (!response.ok) throw new Error('Deferred work did not settle');
		},
		cookie: browser.cookie,
		useBrowser: browserAddresses.useBrowser,
		browserAddress: browserAddresses.current,
		authAsBrowser,
		clearBrowserSession: browser.clear,
		providerCallback: providers.authorize,
		managementHolds: proofBarriers.managementHolds,
		httpResponseHolds,
		auth,
		ownerToken: (profile) => personToken('owner@example.invalid', true, profile),
		personToken,
		async gateway(pathname, init = {}, secondHeap = false): Promise<Response> {
			const worker = await miniflare.getWorker(secondHeap ? 'gateway-two' : 'gateway-one');
			const incoming = new Request(new URL(pathname, issuer), init);
			const response = await worker.fetch(incoming.url, {
				method: incoming.method,
				headers: Object.fromEntries(incoming.headers),
				...(['GET', 'HEAD'].includes(incoming.method) ? {} : { body: await incoming.text() }),
				signal: incoming.signal,
			});
			return new Response(response.status === 204 ? null : await response.arrayBuffer(), {
				status: response.status,
				headers: Object.fromEntries(response.headers),
			});
		},
		teardownObservations: proofClose.observations,
		close: proofClose.close,
	};
}
