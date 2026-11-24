import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { requestLimitObservationSchema } from '@agent-collaboration/sign-in-core';
import { requirePrivateRuntimePath } from '@agent-collaboration/sign-in-owner-cli';
import { build, type Plugin } from 'esbuild';
import { z } from 'zod';

import { proofStartupModuleSource } from '#sign-in-test-support/test-fixtures/worker-module-manifest';

const proofEntries = {
	auth: 'packages/sign-in-test-support/src/test-fixtures/auth-proof-entrypoint.ts',
	gateway: 'packages/tool-host-cloudflare/src/test-fixtures/workspace-gateway-proof-entrypoint.ts',
} as const;
const productionEntries = {
	auth: 'packages/sign-in-host-cloudflare/dist/index.js',
	gateway: 'packages/tool-host-cloudflare/dist/index.js',
} as const;
export const proofArtifactNames = [
	'auth',
	'gateway',
	'productionAuth',
	'productionGateway',
	'signingObserver',
	'clock',
	'startup',
] as const;
const proofWorkerModulesSchema = z.strictObject({
	auth: z.string(),
	gateway: z.string(),
	productionAuth: z.string(),
	productionGateway: z.string(),
	signingObserver: z.string(),
	clock: z.string(),
	startup: z.string(),
});
export type ProofWorkerModules = z.infer<typeof proofWorkerModulesSchema>;
const bundleIdentitySchema = z.strictObject({ file: z.string(), sha256: z.string().length(64) });
export const proofBundleManifestSchema = z.strictObject({
	auth: bundleIdentitySchema,
	gateway: bundleIdentitySchema,
	productionAuth: bundleIdentitySchema,
	productionGateway: bundleIdentitySchema,
	signingObserver: bundleIdentitySchema,
	clock: bundleIdentitySchema,
	startup: bundleIdentitySchema,
	configurationSource: z.string().length(64),
	clientSource: z.string().length(64),
});
export type ProofBundleManifest = z.infer<typeof proofBundleManifestSchema>;

export function proofDigest(contents: string): string {
	return createHash('sha256').update(contents).digest('hex');
}

export function proofModuleHashes(manifest: unknown): Readonly<Record<string, string>> {
	const parsed = z
		.object({
			modules: z.record(z.string(), z.object({ type: z.literal('esm'), contents: z.string() })),
		})
		.parse(manifest);
	return Object.fromEntries(
		Object.entries(parsed.modules).map(([name, module]) => [name, proofDigest(module.contents)]),
	);
}

export async function proofSourceIdentities(
	root: string,
): Promise<{ readonly configurationSource: string; readonly clientSource: string }> {
	const configurationFiles = [
		'packages/sign-in-host-cloudflare/wrangler.example.jsonc',
		'packages/sign-in-test-support/src/test-fixtures/local-auth-harness.ts',
		'packages/sign-in-test-support/src/test-fixtures/auth-proof-application.ts',
		'packages/sign-in-test-support/src/test-fixtures/node-auth-proof-host.ts',
		'packages/sign-in-test-support/src/test-fixtures/passkey-release-failure.ts',
		'packages/sign-in-test-support/src/test-fixtures/web-crypto-digest-failure.ts',
		'packages/sign-in-test-support/src/test-fixtures/auth-proof-tokens.ts',
		'packages/sign-in-test-support/src/test-fixtures/authorization-drain-proof.ts',
		'packages/sign-in-test-support/src/test-fixtures/central-forgot-host.ts',
		'packages/sign-in-test-support/src/test-fixtures/manual-deadlines.ts',
		'packages/sign-in-test-support/src/test-fixtures/renewal-deadline-proof.ts',
		'packages/sign-in-test-support/src/test-fixtures/controlled-central-provisioning.ts',
		'packages/sign-in-test-support/src/test-fixtures/controlled-central-unix-peer.ts',
		'packages/sign-in-test-support/src/test-fixtures/local-auth-proof-close.ts',
		'packages/sign-in-test-support/src/test-fixtures/auth-proof-forwarder-lifecycle.ts',
		'packages/sign-in-test-support/src/test-fixtures/auth-proof-http-response-holds.ts',
		'packages/sign-in-test-support/src/test-fixtures/auth-proof-phase-recording.ts',
		'packages/sign-in-test-support/src/test-fixtures/jwks-fetch-observation.ts',
		'packages/sign-in-test-support/src/test-fixtures/local-auth-configuration.ts',
		'packages/sign-in-test-support/src/test-fixtures/local-auth-browser.ts',
		'packages/sign-in-test-support/src/test-fixtures/proof-browser-addresses.ts',
		'packages/sign-in-test-support/src/test-fixtures/proof-rate-limit-bindings.ts',
		'packages/sign-in-test-support/src/test-fixtures/auth-proof-rate-limit-bindings.ts',
		'packages/sign-in-test-support/src/test-fixtures/local-auth-transport-failure.ts',
		'packages/sign-in-test-support/src/test-fixtures/google-oauth-protocol.ts',
		'packages/sign-in-test-support/src/test-fixtures/github-oauth-protocol.ts',
		'packages/sign-in-test-support/src/test-fixtures/external-social-provider-protocol.ts',
		'packages/sign-in-test-support/src/test-fixtures/auth-proof-transport-events.ts',
		'packages/sign-in-test-support/src/test-fixtures/database-proof-controls.ts',
		'packages/sign-in-test-support/src/test-fixtures/worker-module-manifest.ts',
		'packages/sign-in-test-support/src/test-fixtures/controlled-sign-in-clock.ts',
		'packages/sign-in-test-support/src/test-fixtures/controlled-sign-in-time.ts',
		'packages/sign-in-test-support/src/test-fixtures/controlled-worker-date.ts',
		'packages/sign-in-test-support/src/test-fixtures/auth-proof-clock-control.ts',
		'packages/sign-in-test-support/src/test-fixtures/controlled-turnstile-protocol.ts',
		'packages/sign-in-test-support/src/test-fixtures/turnstile-test-keys.ts',
		'packages/sign-in-test-support/src/test-fixtures/captcha-observation-collector.ts',
		'packages/sign-in-test-support/src/test-fixtures/captcha-observation-control.ts',
		'packages/sign-in-test-support/src/test-fixtures/captcha-provider-proof.ts',
		'packages/sign-in-test-support/src/test-fixtures/auth-proof-outbound.ts',
		'packages/sign-in-test-support/src/test-fixtures/closed-siteverify-endpoint.ts',
	];
	const clientFiles = [
		'packages/sign-in-test-support/src/test-fixtures/served-owner-browser.ts',
		'packages/sign-in-test-support/src/test-fixtures/isolated-page-dom.ts',
		'packages/sign-in-test-support/src/test-fixtures/current-session-owner-token.ts',
		'packages/sign-in-test-support/src/test-fixtures/native-cli-proof.ts',
		'packages/sign-in-test-support/src/test-fixtures/controlled-native-cli-clock.ts',
		'packages/sign-in-test-support/src/test-fixtures/auth-proof-phase-recording.ts',
		'packages/sign-in-test-support/src/test-fixtures/native-owner-cli-profile.ts',
		'packages/sign-in-test-support/src/test-fixtures/jwks-fetch-observation.ts',
		'packages/sign-in-owner-cli/src/owner-cli.ts',
		'packages/sign-in-owner-cli/src/owner-cli-login.ts',
		'packages/sign-in-test-support/src/test-fixtures/workspace-agent-proof.ts',
		'packages/sign-in-test-support/src/test-fixtures/local-person-login.ts',
		'packages/sign-in-test-support/src/test-fixtures/local-owner-organization.ts',
		'packages/sign-in-test-support/src/test-fixtures/software-totp-authenticator.ts',
	];
	const [configuration, client] = await Promise.all([
		Promise.all(configurationFiles.map((file) => readFile(path.join(root, file), 'utf8'))),
		Promise.all(clientFiles.map((file) => readFile(path.join(root, file), 'utf8'))),
	]);
	return {
		configurationSource: proofDigest(JSON.stringify(configuration)),
		clientSource: proofDigest(JSON.stringify(client)),
	};
}

const frozenProductionHosts: Plugin = {
	name: 'frozen-production-host-modules',
	setup(bundler): void {
		bundler.onResolve(
			{ filter: new RegExp('^#sign-in-test-support/test-fixtures/controlled-worker-date$') },
			() => ({ path: './controlled-date.mjs', external: true }),
		);
		bundler.onResolve(
			{ filter: new RegExp('^#sign-in-test-support/test-fixtures/native-signature-observer$') },
			() => ({ path: './native-signature-observer.mjs', external: true }),
		);
		bundler.onResolve(
			{
				filter: new RegExp(
					'^(?:@agent-collaboration/sign-in-host-cloudflare|#worker-host/(?:index|durable-workspace-authority/workspace-authority))$',
				),
			},
			(request) => ({
				path:
					request.path === '@agent-collaboration/sign-in-host-cloudflare'
						? './production-auth.mjs'
						: './production-gateway.mjs',
				external: true,
			}),
		);
	},
};

/** Production bytes come only from the workspace build; no test module, clock shim,
 * source-path alias or test plugin participates in this bundle. */
export async function bundleProductionWorker(
	root: string,
	name: keyof typeof productionEntries,
): Promise<string> {
	return bundleWorker({ root, entry: productionEntries[name], kind: 'production' });
}
export async function bundleProofApplication(root: string, entry: string): Promise<string> {
	return bundleWorker({ root, entry, kind: 'proof' });
}
async function bundleWorker(props: {
	readonly root: string;
	readonly entry: string;
	readonly kind: 'production' | 'proof';
}): Promise<string> {
	const result = await build({
		absWorkingDir: props.root,
		entryPoints: [props.entry],
		bundle: true,
		write: false,
		format: 'esm',
		platform: 'neutral',
		target: 'es2022',
		conditions: ['workerd', 'worker', 'browser'],
		mainFields: ['module', 'main'],
		external: ['cloudflare:workers', 'node:*'],
		logLevel: 'silent',
		...(props.kind === 'production'
			? { tsconfigRaw: { compilerOptions: {} } }
			: { plugins: [frozenProductionHosts] }),
	});
	const output = result.outputFiles[0];
	if (output === undefined) throw new Error('Worker bundle is empty');
	return output.text;
}
async function buildProofModules(root: string): Promise<ProofWorkerModules> {
	const [auth, gateway, productionAuth, productionGateway, signingObserver, clock] =
		await Promise.all([
			bundleWorker({ root, entry: proofEntries.auth, kind: 'proof' }),
			bundleWorker({ root, entry: proofEntries.gateway, kind: 'proof' }),
			bundleProductionWorker(root, 'auth'),
			bundleProductionWorker(root, 'gateway'),
			bundleWorker({
				root,
				entry: 'packages/sign-in-test-support/src/test-fixtures/native-signature-observer.ts',
				kind: 'production',
			}),
			bundleWorker({
				root,
				entry: 'packages/sign-in-test-support/src/test-fixtures/controlled-worker-date.ts',
				kind: 'production',
			}),
		]);
	return {
		auth,
		gateway,
		productionAuth,
		productionGateway,
		signingObserver,
		clock,
		startup: proofStartupModuleSource,
	};
}

/** Freeze each module independently; the Date shim never changes production bytes. */
export async function prepareProofBundles(
	root: string,
	evidence: string,
): Promise<ProofBundleManifest> {
	const modules = await buildProofModules(root);
	const entries = await Promise.all(
		proofArtifactNames.map(async (name) => {
			const file = path.join(evidence, `${name}.mjs`);
			await writeFile(file, modules[name], { mode: 0o600, flag: 'wx' });
			return [name, { file, sha256: proofDigest(modules[name]) }] as const;
		}),
	);
	return proofBundleManifestSchema.parse({
		...Object.fromEntries(entries),
		...(await proofSourceIdentities(root)),
	});
}

export async function loadProofBundles(
	root: string,
): Promise<ProofWorkerModules & { readonly identity: ProofBundleManifest | null }> {
	const manifestFile = process.env.AUTH_PROOF_MANIFEST_FILE;
	if (manifestFile === undefined) return { ...(await buildProofModules(root)), identity: null };
	const identity = proofBundleManifestSchema.parse(
		JSON.parse(await readFile(await requirePrivateRuntimePath(manifestFile, true), 'utf8')),
	);
	const actualSources = await proofSourceIdentities(root);
	if (
		actualSources.configurationSource !== identity.configurationSource ||
		actualSources.clientSource !== identity.clientSource
	)
		throw new Error('Proof fixture source differs from the declared configuration/client');
	const entries = await Promise.all(
		proofArtifactNames.map(async (name) => {
			const contents = await readFile(
				await requirePrivateRuntimePath(identity[name].file, true),
				'utf8',
			);
			if (proofDigest(contents) !== identity[name].sha256)
				throw new Error('Executed proof module differs from its declared artifact');
			return [name, contents] as const;
		}),
	);
	return { ...proofWorkerModulesSchema.parse(Object.fromEntries(entries)), identity };
}

export const authHarnessReadinessSchema = z.discriminatedUnion('ready', [
	z.strictObject({ ready: z.literal(false), readinessEvent: z.literal('none') }),
	z.strictObject({
		ready: z.literal(true),
		readinessEvent: z.enum(['jwks', 'personToken', 'signInSession']),
	}),
]);
export type AuthHarnessReadiness = z.infer<typeof authHarnessReadinessSchema>;

const requestLimitReceiptFields = z.strictObject({
	backingFailure: z.enum(['none', 'node-counter-throws', 'cloudflare-binding-rejects']),
	observations: z.array(requestLimitObservationSchema),
});
export const authHarnessRequestLimitsSchema = z.discriminatedUnion('outerCounter', [
	requestLimitReceiptFields.extend({
		outerCounter: z.enum(['node-fixed-window', 'cloudflare-real-binding']),
	}),
	requestLimitReceiptFields.extend({
		outerCounter: z.literal('cloudflare-controlled-binding-stand-in'),
		proofCase: z.enum(['service-page-exact-budget', 'passkey-exact-budget']),
	}),
]);
export type AuthHarnessRequestLimits = z.infer<typeof authHarnessRequestLimitsSchema>;

export async function recordProofHarness(
	props: {
		readonly receiptId: string;
		readonly identity: ProofBundleManifest | null;
		readonly configuration: unknown;
		readonly client: unknown;
		readonly requestLimits: AuthHarnessRequestLimits;
	} & AuthHarnessReadiness,
): Promise<void> {
	const manifestFile = process.env.AUTH_PROOF_MANIFEST_FILE;
	if (manifestFile === undefined || props.identity === null) return;
	const directory = path.dirname(await requirePrivateRuntimePath(manifestFile, true));
	await writeFile(path.join(directory, `harness-${props.receiptId}.json`), JSON.stringify(props), {
		mode: 0o600,
	});
}
