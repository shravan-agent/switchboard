import { AsyncLocalStorage } from 'node:async_hooks';
import { Writable } from 'node:stream';

import {
	createSignInStore,
	epochMillisecondsSchema,
	type SignInClock,
	type SignInDatabase,
	type SignInObservation,
	type SignInRequestLimiter,
	type RequestLimitResult,
} from '@agent-collaboration/sign-in-core';
import {
	createSignInHttpHandler,
	createSignInManagementBinding,
	type SignInHttpConfiguration,
} from '@agent-collaboration/sign-in-core/better-auth';
import {
	createNodeSignInConfiguration,
	createNodeSignInLogging,
	nodeSignInSettingsSchema,
	openNodeSignInDatabase,
	startNodeSignInListener,
	type NodeSignInSettings,
	createCentralUnixTransport,
} from '@agent-collaboration/sign-in-host-node';
import { sql } from 'drizzle-orm';
import { vi } from 'vitest';
import { z } from 'zod';

import type { createAuthProofBarrierServer } from '#sign-in-test-support/test-fixtures/auth-proof-barrier-server';
import { handleConfiguredAuthProofTokenRequest } from '#sign-in-test-support/test-fixtures/auth-proof-tokens';
import {
	createDeferredWorkTracker,
	handleAuthorizationDrainProof,
	proofRenewalDeadlineActive,
	withProofRenewalDeadline,
} from '#sign-in-test-support/test-fixtures/authorization-drain-proof';
import { handleAuthorizationFenceProof } from '#sign-in-test-support/test-fixtures/authorization-fence-proof';
import { captchaObservationDrainPath } from '#sign-in-test-support/test-fixtures/captcha-observation-control';
import { handleConfiguredCaptchaProviderProof } from '#sign-in-test-support/test-fixtures/captcha-provider-proof';
import { controlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-sign-in-clock';
import {
	databaseFaultSchema,
	matchesDatabaseFault,
	organizationReadProjection,
	type DatabaseFault,
} from '#sign-in-test-support/test-fixtures/database-fault-identity';
import { handleFleetAdminClientProof } from '#sign-in-test-support/test-fixtures/fleet-admin-client-proof';
import {
	fleetSnapshotHoldPoint,
	readFleetSnapshotProbe,
	type FleetSnapshotProbe,
} from '#sign-in-test-support/test-fixtures/fleet-snapshot-proof';
import { handleIntrospectionClientFixture } from '#sign-in-test-support/test-fixtures/introspection-client-fixture';
import { createClockFreeProofJwksFetch } from '#sign-in-test-support/test-fixtures/jwks-fetch-observation';
import {
	requireSignedAgentProjection,
	withNativeSigningObservation,
} from '#sign-in-test-support/test-fixtures/native-signature-observer';
import {
	nodeInvocationDigest,
	nodeHttpRequestIdentitySchema,
	nodeManagementBridgeCallSchema,
	type NodeInvocationReceipt,
	type NodeManagementBridgeCall,
} from '#sign-in-test-support/test-fixtures/node-management-bridge-contracts';
import { recordNodeProofInvocationFailure } from '#sign-in-test-support/test-fixtures/node-proof-invocation-failure';
import { decorateNodeProofStore } from '#sign-in-test-support/test-fixtures/node-proof-store';
import { withNodeProviderNetwork } from '#sign-in-test-support/test-fixtures/node-provider-network';
import { handleOrganizationKeyChangeProofRequest } from '#sign-in-test-support/test-fixtures/organization-key-change-proof';
import {
	readOrganizationReadProbe,
	type OrganizationReadProbe,
} from '#sign-in-test-support/test-fixtures/organization-read-proof';
import { createPasskeyReleaseFailure } from '#sign-in-test-support/test-fixtures/passkey-release-failure';
import {
	readPersonConfirmationProbe,
	personSessionReadKind,
	type PersonConfirmationProbe,
} from '#sign-in-test-support/test-fixtures/person-confirmation-proof';
import {
	createRecordingSignInCapabilities,
	type RecordingSignInCapabilities,
} from '#sign-in-test-support/test-fixtures/recording-sign-in-capabilities';
import { handleWebCryptoDigestFailureControl } from '#sign-in-test-support/test-fixtures/web-crypto-digest-failure';

export interface NodeAuthProofHost {
	readonly address: URL;
	readonly database: SignInDatabase;
	readonly configuration: SignInHttpConfiguration;
	readonly receipts: readonly NodeInvocationReceipt[];
	readonly captchaObservations: () => readonly SignInObservation[];
	/** The recorder around this host's crypto, clock, IDs and central client, when armed. */
	readonly capabilityRecording: RecordingSignInCapabilities | null;
	readonly close: () => Promise<void>;
}

function offsetClock(clock: SignInClock, offsetMilliseconds: number): SignInClock {
	return { now: () => epochMillisecondsSchema.parse(clock.now() + offsetMilliseconds) };
}

/** Test-only (V2): record every crypto, clock, ID and central call the in-process host makes. */
export interface NodeCapabilityRecordingOption {
	/** Known bytes in place of the host's randomness; without it the real randomness is kept. */
	readonly randomBytes?: (byteLength: number) => Uint8Array<ArrayBuffer>;
	/**
	 * Moves the injected core clock this far from the process clock, which this host pins to the
	 * controlled time for Better Auth. A clock read that bypasses the capability then shows.
	 */
	readonly clockOffsetMilliseconds?: number;
}

export async function startNodeAuthProofHost(props: {
	readonly runtimeDirectory: string;
	readonly centralSocketPath: string;
	readonly configuration: unknown;
	readonly issuer: string;
	readonly barriers: ReturnType<typeof createAuthProofBarrierServer>;
	readonly provider: (request: Request) => Promise<Response>;
	readonly turnstileSecret?: string;
	readonly siteVerifyURL?: string;
	readonly clientAddress?: NodeSignInSettings['clientAddress'];
	readonly capabilityRecording?: NodeCapabilityRecordingOption;
}): Promise<NodeAuthProofHost> {
	const passkeyReleaseFailure = createPasskeyReleaseFailure();
	let failNextPasskeyUserRead = false;
	let lastSessionInsert: {
		readonly query: string;
		readonly parameters: readonly unknown[];
	} | null = null;
	const passkeyReads = new AsyncLocalStorage<{ failAfterInsert: boolean }>();
	let fault: DatabaseFault | null = null;
	const organizationReads = { lookup: 0, list: 0 };
	let observed: { readonly clientId: string; readonly keys: readonly string[] } | null = null;
	const disabledWrites: { readonly client_id: string }[] = [];
	const receipts: NodeInvocationReceipt[] = [];
	const observations: SignInObservation[] = [];
	let milliseconds = controlledSignInClock.now();
	/** Moves the injected core clock and native Date together, as the set-clock control does. */
	function setControlledTime(next: number): void {
		milliseconds = epochMillisecondsSchema.parse(next);
		vi.setSystemTime(milliseconds);
	}
	vi.setSystemTime(milliseconds);
	const confirmationReads = new AsyncLocalStorage<{
		phase:
			| { readonly kind: 'pending'; readonly probe: PersonConfirmationProbe }
			| { readonly kind: 'advanced'; readonly probe: PersonConfirmationProbe };
	}>();
	const opened = await openNodeSignInDatabase({
		stateDirectory: props.runtimeDirectory,
		logger: {
			logQuery(query: string, parameters: unknown[]): void {
				const call = { query, parameters };
				passkeyReleaseFailure.beforeDriverCall(call);
				const passkeyRead = passkeyReads.getStore();
				if (/^\s*insert into "session"/iu.test(query)) {
					lastSessionInsert = call;
					if (passkeyRead !== undefined && failNextPasskeyUserRead) {
						failNextPasskeyUserRead = false;
						passkeyRead.failAfterInsert = true;
					}
				} else if (passkeyRead?.failAfterInsert && /^\s*select\b.*\bfrom "user"/iu.test(query)) {
					passkeyRead.failAfterInsert = false;
					throw new Error('Injected passkey user read failure');
				}
				const confirmation = confirmationReads.getStore();
				if (
					confirmation?.phase.kind === 'pending' &&
					personSessionReadKind(call, confirmation.phase.probe.sessionId) === 'provider'
				) {
					milliseconds = epochMillisecondsSchema.parse(
						milliseconds + confirmation.phase.probe.advanceBeforeReadMilliseconds,
					);
					vi.setSystemTime(milliseconds);
					confirmation.phase = { kind: 'advanced', probe: confirmation.phase.probe };
				}
				const projection = organizationReadProjection(call);
				if (projection === 'membership-facts') organizationReads.lookup += 1;
				if (projection === 'people-members') organizationReads.list += 1;
				if (fault !== null && matchesDatabaseFault(call, fault)) {
					if (fault.skipMatches !== undefined && fault.skipMatches > 0) {
						fault.skipMatches -= 1;
					} else {
						if (fault.once === true) fault = null;
						throw new Error('Injected Node sign-in driver failure');
					}
				}
				if (
					observed !== null &&
					observed.keys.length > 0 &&
					matchesDatabaseFault(call, {
						operation: 'update',
						table: 'oauthClient',
						column: 'disabled',
						key: observed.clientId,
						additionalKeys: [...observed.keys],
					})
				)
					disabledWrites.push({ client_id: observed.clientId });
			},
		},
	});
	if (opened.kind !== 'available') throw new Error('Node proof migration failed');
	const journal = z
		.array(
			z.object({ journal_mode: z.enum(['delete', 'truncate', 'persist', 'memory', 'wal', 'off']) }),
		)
		.parse(await opened.database.openDatabase().all(sql`PRAGMA journal_mode`));
	const timeout = z
		.array(z.object({ timeout: z.number().int().nonnegative() }))
		.parse(await opened.database.openDatabase().all(sql`PRAGMA busy_timeout`));
	process.stderr.write(
		`${JSON.stringify({ event: 'node-proof-database-settings', journal, timeout })}\n`,
	);
	const settings = nodeSignInSettingsSchema.parse({
		stateDirectory: props.runtimeDirectory,
		centralSocketPath: props.centralSocketPath,
		port: 0,
		configuration: props.configuration,
		...(props.clientAddress === undefined ? {} : { clientAddress: props.clientAddress }),
		secret: 'test-only-auth-secret-'.repeat(3),
		...(props.turnstileSecret === undefined ? {} : { turnstileSecretKey: props.turnstileSecret }),
		google: { clientId: 'fixture-google-client', clientSecret: 'fixture-google-secret' },
		github: { clientId: 'fixture-github-client', clientSecret: 'fixture-github-secret' },
	});
	const baseConfiguration = createNodeSignInConfiguration({
		settings,
		database: opened.database,
		clock: { now: () => epochMillisecondsSchema.parse(milliseconds) },
		log: (observation: SignInObservation): void => {
			observations.push(observation);
			logging.log(observation);
		},
	});
	const capabilityRecording =
		props.capabilityRecording === undefined
			? null
			: createRecordingSignInCapabilities({
					crypto: baseConfiguration.platform.crypto,
					clock: offsetClock(
						baseConfiguration.platform.clock,
						props.capabilityRecording.clockOffsetMilliseconds ?? 0,
					),
					ids: baseConfiguration.platform.ids,
					...(props.capabilityRecording.randomBytes === undefined
						? {}
						: { randomBytes: props.capabilityRecording.randomBytes }),
				});
	// The recorder wraps the very capabilities the host built, so nothing else changes.
	const capabilityPlatform =
		capabilityRecording === null
			? baseConfiguration.platform
			: {
					...baseConfiguration.platform,
					crypto: capabilityRecording.crypto,
					clock: capabilityRecording.clock,
					ids: capabilityRecording.ids,
					centralClient: capabilityRecording.recordCentralClient(
						baseConfiguration.platform.centralClient,
					),
				};
	let backingUnavailable = false;
	const platform: SignInHttpConfiguration['platform'] = {
		...capabilityPlatform,
		requestLimiter: {
			async allow(
				request: Parameters<SignInRequestLimiter['allow']>[0],
			): Promise<RequestLimitResult> {
				if (backingUnavailable) throw new Error('Injected Node counter failure');
				return baseConfiguration.platform.requestLimiter.allow(request);
			},
		},
	};
	const configuration: SignInHttpConfiguration = {
		...baseConfiguration,
		platform,
		store:
			capabilityRecording === null
				? baseConfiguration.store
				: createSignInStore({
						openDatabase: baseConfiguration.openDatabase,
						platform,
						ownerEmail: settings.configuration.ownerEmail,
					}),
	};
	const logging = createNodeSignInLogging({
		clock: configuration.platform.clock,
		output: new Writable({
			write(_chunk, _encoding, callback): void {
				callback();
			},
		}),
		endpoint: undefined,
	});

	async function barrier(
		channel: 'hold' | 'management-hold' | 'confirmation-hold',
		operation: 'status' | 'arrive',
		key: string,
		event?: unknown,
	): Promise<Response> {
		const response = await props.barriers.handle(
			`/__auth-proof/${channel}/${operation}?key=${encodeURIComponent(key)}`,
			operation === 'status' ? 'GET' : 'POST',
			event === undefined ? '' : JSON.stringify(event),
		);
		if (response === null || !response.ok) throw new Error('Node proof barrier unavailable');
		return response;
	}
	function configurationWithHold(
		hold:
			| { readonly kind: 'none' }
			| { readonly kind: 'token'; readonly clientId: string }
			| { readonly kind: 'management'; readonly requestId: string }
			| { readonly kind: 'confirmation'; readonly sessionId: string }
			| { readonly kind: 'fleet-snapshot'; readonly probe: FleetSnapshotProbe }
			| { readonly kind: 'organization-read'; readonly probe: OrganizationReadProbe },
		invocationId?: string,
	): SignInHttpConfiguration {
		let agentReads = 0;
		let ownerReads = 0;
		const decorated = decorateNodeProofStore({
			store: configuration.store,
			...(hold.kind === 'organization-read'
				? {
						organizationRead: {
							async afterRead(kind: 'lookup' | 'list', organizationId: string): Promise<void> {
								if (kind === hold.probe.kind && organizationId === hold.probe.organizationId)
									await barrier('hold', 'arrive', hold.probe.key, {
										point: 'organization-read',
										kind,
									});
							},
						},
					}
				: {}),
			...(hold.kind === 'confirmation'
				? {
						personConfirmation: {
							clock: configuration.platform.clock,
							async afterRead(observation: {
								readonly sessionId: string;
								readonly checkedAt: number;
							}): Promise<void> {
								if (observation.sessionId === hold.sessionId)
									await barrier('confirmation-hold', 'arrive', hold.sessionId, {
										point: 'first-person-session-read',
										sessionId: hold.sessionId,
										checkedAt: observation.checkedAt,
									});
							},
						},
					}
				: {}),
			onOwnerReadFailure(reason): void {
				process.stderr.write(
					`${JSON.stringify({ event: 'node-proof-owner-store-failed', invocationId, reason })}\n`,
				);
			},
			async beforeAgentRead(clientId): Promise<void> {
				if (hold.kind !== 'token' || hold.clientId !== clientId) return;
				agentReads += 1;
				if (agentReads === 2)
					await barrier('hold', 'arrive', clientId, requireSignedAgentProjection(clientId));
			},
			async beforeOwnerRead(): Promise<void> {
				if (hold.kind !== 'management') return;
				ownerReads += 1;
				if (ownerReads === 3)
					await barrier('management-hold', 'arrive', hold.requestId, {
						point: 'before-provider-owner-read',
						requestId: hold.requestId,
					});
			},
		});
		if (hold.kind !== 'fleet-snapshot') return { ...configuration, store: decorated };
		const probe = hold.probe;
		return {
			...configuration,
			store: {
				...decorated,
				authorizations: {
					// The coherent read returns first; only then does the probe act.
					async readPersonFleetSnapshot(personId, sessionId) {
						const snapshot = await decorated.authorizations.readPersonFleetSnapshot(
							personId,
							sessionId,
						);
						if (probe.mode === 'advance') setControlledTime(milliseconds + probe.milliseconds);
						else await barrier('hold', 'arrive', probe.key, { point: fleetSnapshotHoldPoint });
						return snapshot;
					},
				},
			},
		};
	}
	async function runManagement(
		call: NodeManagementBridgeCall,
		invocationId: string,
	): Promise<Response> {
		const current = configurationWithHold(
			'props' in call && 'requestId' in call.props && typeof call.props.requestId === 'string'
				? { kind: 'management', requestId: call.props.requestId }
				: { kind: 'none' },
			invocationId,
		);
		const publicHandler = createSignInHttpHandler(current);
		const binding = createSignInManagementBinding(current, {
			jwksFetch: createClockFreeProofJwksFetch({
				caller: 'node-owner-person',
				fetch: async (input, init) => publicHandler(new Request(input, init)),
				observe: (event) => process.stderr.write(`${JSON.stringify({ ...event, invocationId })}\n`),
			}),
		});
		switch (call.method) {
			case 'humanCheckStatus':
				return Response.json(await binding.humanCheckStatus());
			case 'isLiveOwner':
				return Response.json(await binding.isLiveOwner(call.props));
			case 'ownsAgentClient':
				return Response.json(await binding.ownsAgentClient(call.props));
			case 'registerAndLink':
				return Response.json(await binding.registerAndLink(call.props));
			case 'link':
				return Response.json(await binding.link(call.props));
			case 'unlink':
				return Response.json(await binding.unlink(call.props));
			case 'disable':
				return Response.json(await binding.disable(call.props));
			default: {
				const unhandled: never = call;
				throw new Error(`Unknown management call: ${String(unhandled)}`);
			}
		}
	}
	async function handle(request: Request): Promise<Response> {
		const authorizationFence = await handleAuthorizationFenceProof(
			request,
			() => configuration,
			async (key): Promise<void> => {
				await barrier('hold', 'arrive', key, { point: 'before-authorization-fence-batch' });
			},
		);
		if (authorizationFence !== null) return authorizationFence;
		const fleetAdminClient = await handleFleetAdminClientProof(request, () => configuration);
		if (fleetAdminClient !== null) return fleetAdminClient;
		const authorizationDrain = await handleAuthorizationDrainProof(
			request,
			() => configuration,
			async (key, event) => {
				await barrier('hold', 'arrive', key, event);
			},
		);
		if (authorizationDrain !== null) return authorizationDrain;
		if (new URL(request.url).pathname === '/__auth-proof/deferred-work') {
			await deferredWork.settled();
			return Response.json({ kind: 'settled' });
		}
		const pathname = new URL(request.url).pathname;
		const releaseFailureControl = passkeyReleaseFailure.control(request);
		if (releaseFailureControl !== null) return releaseFailureControl;
		const webCryptoFailureControl = await handleWebCryptoDigestFailureControl(request);
		if (webCryptoFailureControl !== null) return webCryptoFailureControl;
		if (pathname === captchaObservationDrainPath) return Response.json({ kind: 'complete' });
		const captchaProof = await handleConfiguredCaptchaProviderProof(request, () => configuration);
		if (captchaProof !== null) return captchaProof;
		const introspectionFixture = await handleIntrospectionClientFixture(
			request,
			() => configuration,
		);
		if (introspectionFixture !== null) return introspectionFixture;
		const organizationRead = readOrganizationReadProbe(request);
		if (organizationRead !== null)
			return createSignInHttpHandler(
				configurationWithHold({ kind: 'organization-read', probe: organizationRead }),
			)(request);
		const fleetSnapshot = readFleetSnapshotProbe(request);
		if (fleetSnapshot !== null)
			return createSignInHttpHandler(
				configurationWithHold({ kind: 'fleet-snapshot', probe: fleetSnapshot }),
			)(request);
		const confirmation = readPersonConfirmationProbe(request);
		if (confirmation !== null)
			return confirmationReads.run({ phase: { kind: 'pending', probe: confirmation } }, () =>
				createSignInHttpHandler(
					configurationWithHold({ kind: 'confirmation', sessionId: confirmation.sessionId }),
				)(request),
			);
		if (pathname === '/__auth-proof/node-management')
			return runManagement(
				nodeManagementBridgeCallSchema.parse(await request.json()),
				z.uuidv7().parse(request.headers.get('x-auth-proof-invocation')),
			);
		if (pathname === '/__auth-proof/set-clock') {
			const input = z
				.strictObject({ milliseconds: z.number().int().nonnegative() })
				.parse(await request.json());
			setControlledTime(input.milliseconds);
			return Response.json({ controlledMilliseconds: milliseconds });
		}
		if (pathname === '/__auth-proof/fail-next-passkey-user-read' && request.method === 'POST') {
			failNextPasskeyUserRead = true;
			return Response.json({ kind: 'armed' });
		}
		if (pathname === '/__auth-proof/last-session-insert' && request.method === 'GET')
			return Response.json(lastSessionInsert);
		if (pathname === '/__auth-proof/limiter-unavailable' && request.method === 'POST') {
			backingUnavailable = true;
			return Response.json({ kind: 'armed' });
		}
		if (pathname === '/__auth-proof/database-control') {
			if (request.method === 'GET')
				return Response.json({ disabledWrites, driverFailures: [], organizationReads });
			const control = z
				.discriminatedUnion('kind', [
					z.strictObject({ kind: z.literal('fault'), fault: databaseFaultSchema.nullable() }),
					z.strictObject({ kind: z.literal('observe-organization-reads') }),
					z.strictObject({
						kind: z.literal('observe-disable'),
						clientId: z.string(),
						keys: z.array(z.string()),
					}),
				])
				.parse(await request.json());
			if (control.kind === 'fault') fault = control.fault;
			else if (control.kind === 'observe-organization-reads') {
				organizationReads.lookup = 0;
				organizationReads.list = 0;
			} else {
				observed = control;
				disabledWrites.length = 0;
			}
			return Response.json({ kind: 'applied' });
		}
		const negative = await handleConfiguredAuthProofTokenRequest(request, () => configuration);
		const keyChange = await handleOrganizationKeyChangeProofRequest(request, () => configuration);
		if (keyChange !== null) return keyChange;
		if (negative !== null) return negative;
		if (pathname === '/api/auth/oauth2/token' && request.method === 'POST') {
			const body = new URLSearchParams(await request.clone().text());
			let clientId = body.get('client_id');
			if (clientId === null) {
				const basic = request.headers.get('authorization')?.match(/^Basic ([^\s]+)$/iu)?.[1];
				try {
					clientId = basic === undefined ? null : (atob(basic).split(':')[0] ?? null);
				} catch {
					clientId = null;
				}
			}
			if (body.get('grant_type') === 'client_credentials' && clientId !== null) {
				const status = z
					.object({ armed: z.boolean() })
					.parse(await (await barrier('hold', 'status', clientId)).json());
				if (status.armed) {
					const selectedClient = clientId;
					return withNativeSigningObservation(selectedClient, () =>
						createSignInHttpHandler(
							configurationWithHold({ kind: 'token', clientId: selectedClient }),
						)(request),
					);
				}
			}
		}
		// D7 host-path proof: while a renewal barrier is set, relays get the barrier-gated deadline.
		if (proofRenewalDeadlineActive() && pathname.startsWith('/api/auth/organization-admin/'))
			return createSignInHttpHandler(
				withProofRenewalDeadline(
					configuration,
					async (key, event) => {
						await barrier('hold', 'arrive', key, event);
					},
					createCentralUnixTransport(props.centralSocketPath),
				),
				{ deferAfterResponse },
			)(request);
		return createSignInHttpHandler(configuration, { deferAfterResponse })(request);
	}
	// Mirrors the production host: after-response drain hints are owned and awaited on close.
	const deferredWork = createDeferredWorkTracker();
	function deferAfterResponse(work: Promise<unknown>): void {
		void deferredWork.track(work);
	}
	const started = await startNodeSignInListener({
		hostname: '127.0.0.1',
		port: 0,
		issuer: props.issuer,
		clientAddress: settings.clientAddress,
		logging,
		handle: async (request) =>
			withNodeProviderNetwork(
				props.provider,
				async () => {
					const invocationId = z.uuidv7().parse(request.headers.get('x-auth-proof-invocation'));
					const requestBody = await request.clone().text();
					let response: Response;
					try {
						response = await passkeyReads.run({ failAfterInsert: false }, () => handle(request));
					} catch (error) {
						recordNodeProofInvocationFailure(error, {
							...nodeHttpRequestIdentitySchema.parse({
								httpMethod: request.method,
								path: new URL(request.url).pathname,
							}),
							invocationId,
						});
						// Match the production listener's failure response while retaining
						// attribution for the failing test invocation as well as successes.
						response = Response.json(
							{ error: 'sign-in-unavailable' },
							{ status: 503, headers: { 'cache-control': 'no-store' } },
						);
					}
					const responseBody = request.method === 'HEAD' ? '' : await response.clone().text();
					let method: NodeInvocationReceipt['method'] = 'http';
					if (new URL(request.url).pathname === '/__auth-proof/node-management') {
						try {
							const call = nodeManagementBridgeCallSchema.safeParse(JSON.parse(requestBody));
							method = call.success ? call.data.method : 'invalid-management';
						} catch {
							method = 'invalid-management';
						}
					}
					receipts.push({
						...nodeHttpRequestIdentitySchema.parse({
							httpMethod: request.method,
							path: new URL(request.url).pathname,
						}),
						invocationId,
						method,
						requestHash: await nodeInvocationDigest(requestBody),
						responseHash: await nodeInvocationDigest(responseBody),
						status: response.status,
					});
					response.headers.set('x-auth-proof-invocation', invocationId);
					return response;
				},
				props.siteVerifyURL === undefined ? [] : [props.siteVerifyURL],
			),
	});
	if (started.kind !== 'started') {
		opened.database.close();
		await logging.close();
		throw new Error('Node proof listener failed');
	}
	return {
		address: started.listener.address,
		database: opened.database.openDatabase(),
		configuration,
		receipts,
		captchaObservations: () => observations.slice(),
		capabilityRecording,
		async close(): Promise<void> {
			await started.listener.close();
			await deferredWork.settled();
			opened.database.close();
			await logging.close();
		},
	};
}
