import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { z } from 'zod';

import {
	nodeInvocationReceiptSchema,
	type NodeInvocationReceipt,
} from '#sign-in-test-support/test-fixtures/node-management-bridge-contracts';
import {
	bundleProofApplication,
	proofDigest,
} from '#sign-in-test-support/test-fixtures/proof-bundle-artifacts';

const artifactSchema = z.strictObject({ file: z.string(), sha256: z.string().length(64) });
export const nodeProofManifestSchema = z.strictObject({
	nodeHost: artifactSchema,
	modules: z.array(artifactSchema).min(1),
	bridge: artifactSchema,
	configurationSource: z.string().length(64),
});
export type NodeProofManifest = z.infer<typeof nodeProofManifestSchema>;

async function nodeConfigurationSource(root: string): Promise<string> {
	const files = [
		'local-auth-harness',
		'local-auth-proof-close',
		'auth-proof-forwarder-lifecycle',
		'auth-proof-http-response-holds',
		'auth-proof-phase-recording',
		'local-auth-configuration',
		'local-person-login',
		'current-session-owner-token',
		'local-owner-organization',
		'software-totp-authenticator',
		'native-owner-cli-profile',
		'local-auth-browser',
		'proof-browser-addresses',
		'proof-rate-limit-bindings',
		'auth-proof-rate-limit-bindings',
		'local-auth-transport-failure',
		'auth-proof-transport-events',
		'auth-proof-outbound',
		'captcha-provider-proof',
		'controlled-turnstile-protocol',
		'captcha-observation-control',
		'turnstile-test-keys',
		'closed-siteverify-endpoint',
		'node-auth-proof-host',
		'passkey-release-failure',
		'web-crypto-digest-failure',
		'node-proof-invocation-failure',
		'jwks-fetch-observation',
		'node-proof-store',
		'node-proof-receipt-readback',
		'node-provider-network',
		'node-management-bridge-worker',
		'node-management-bridge-contracts',
		'async-node-management-caller',
		'google-oauth-protocol',
		'github-oauth-protocol',
		'external-social-provider-protocol',
		'introspection-client-fixture',
		'person-confirmation-proof',
		'auth-proof-barrier-server',
	];
	return proofDigest(
		JSON.stringify(
			await Promise.all([
				readFile(
					path.join(root, 'packages/sign-in-host-cloudflare/wrangler.example.jsonc'),
					'utf8',
				),
				...files.map((name) =>
					readFile(
						path.join(root, `packages/sign-in-test-support/src/test-fixtures/${name}.ts`),
						'utf8',
					),
				),
			]),
		),
	);
}
async function nodeModuleInventory(
	root: string,
): Promise<readonly z.infer<typeof artifactSchema>[]> {
	const files = (
		await Promise.all(
			['sign-in-host-node', 'sign-in-core', 'sign-in-platform-web'].map(async (name) => {
				const directory = path.join(root, 'packages', name, 'dist');
				return (await readdir(directory, { recursive: true }))
					.filter((file) => file.endsWith('.js'))
					.map((file) => path.join(directory, file));
			}),
		)
	)
		.flat()
		.toSorted();
	return Promise.all(
		files.map(async (file) => ({ file, sha256: proofDigest(await readFile(file, 'utf8')) })),
	);
}

export async function prepareNodeProofArtifacts(
	root: string,
	evidence: string,
): Promise<NodeProofManifest> {
	const bridge = await bundleProofApplication(
		root,
		'packages/sign-in-test-support/src/test-fixtures/node-management-bridge-worker.ts',
	);
	const bridgeFile = path.join(evidence, 'node-management-bridge.mjs');
	await writeFile(bridgeFile, bridge, { mode: 0o600, flag: 'wx' });
	const nodeHostFile = path.join(root, 'packages/sign-in-host-node/dist/index.js');
	return {
		nodeHost: { file: nodeHostFile, sha256: proofDigest(await readFile(nodeHostFile, 'utf8')) },
		modules: [...(await nodeModuleInventory(root))],
		bridge: { file: bridgeFile, sha256: proofDigest(bridge) },
		configurationSource: await nodeConfigurationSource(root),
	};
}

export async function loadNodeProofArtifacts(
	root: string,
): Promise<{ readonly bridge: string; readonly identity: NodeProofManifest | null }> {
	const file = process.env.AUTH_PROOF_NODE_MANIFEST_FILE;
	if (file === undefined)
		return {
			bridge: await bundleProofApplication(
				root,
				'packages/sign-in-test-support/src/test-fixtures/node-management-bridge-worker.ts',
			),
			identity: null,
		};
	const identity = nodeProofManifestSchema.parse(JSON.parse(await readFile(file, 'utf8')));
	if (identity.configurationSource !== (await nodeConfigurationSource(root)))
		throw new Error('Node proof configuration changed after declaration');
	const actualModules = await nodeModuleInventory(root);
	if (JSON.stringify(actualModules) !== JSON.stringify(identity.modules))
		throw new Error('Node production module inventory differs from declared target');
	for (const artifact of [identity.nodeHost, identity.bridge])
		if (proofDigest(await readFile(artifact.file, 'utf8')) !== artifact.sha256)
			throw new Error('Node proof artifact changed after declaration');
	return { bridge: await readFile(identity.bridge.file, 'utf8'), identity };
}

export async function retainNodeProofReceipts(props: {
	readonly receiptId: string;
	readonly identity: NodeProofManifest | null;
	readonly expected: readonly NodeInvocationReceipt[];
	readonly actual: readonly NodeInvocationReceipt[];
}): Promise<void> {
	const file = process.env.AUTH_PROOF_NODE_MANIFEST_FILE;
	if (file !== undefined && props.identity !== null)
		await writeFile(
			path.join(path.dirname(file), `node-harness-${props.receiptId}.json`),
			JSON.stringify(props),
			{ mode: 0o600 },
		);
}

function receiptsByInvocationId(
	rows: readonly NodeInvocationReceipt[],
): readonly NodeInvocationReceipt[] {
	return z
		.array(nodeInvocationReceiptSchema)
		.parse(rows)
		.toSorted((left, right) => left.invocationId.localeCompare(right.invocationId));
}

export function compareNodeProofReceipts(
	expected: readonly NodeInvocationReceipt[],
	actual: readonly NodeInvocationReceipt[],
): void {
	if (
		expected.length !== actual.length ||
		new Set(actual.map((row) => row.invocationId)).size !== actual.length ||
		JSON.stringify(receiptsByInvocationId(expected)) !==
			JSON.stringify(receiptsByInvocationId(actual))
	)
		throw new Error('Node invocation receipts differ from initiating calls');
}
