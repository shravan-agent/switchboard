import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { join } from 'node:path';
import { promisify } from 'node:util';

const runFile = promisify(execFile);

export const b3CentralProofPin = {
	commit: '773ad8fb2afb62935fb1ddaeb61b015625c53ab0',
	tree: '1d8bfd7399a414592e3bcae216aab65d17379e94',
	// Locked production CLI debug build, then signed for direct macOS execution.
	nativeSha256: '8544dbcf88551959035c0b45e35313c8622de4a1d336cf50c7bc468f846be1f1',
	workers: {
		'build/index.js': '7310518d55edbf93729e5ee54eb6f9e047d6061f3357769fddd5df5ffb1c0c9b',
		'build/index_bg.wasm': 'b53afc2201569aeb187a6c6c59ffd698526e23c2270edf35f5101fbe766a6385',
		'build-link/index.js': '520efec986aa9b4586248119fe0128dd191a2baa44aaaeb6b8f660d7014e30a8',
		'build-link/index_bg.wasm': '7f3a3ee682e8867d1224b5999c6f46456870afeba1fb08db4eea75752f9d3c9f',
	},
} as const;

async function assertDigest(file: string, expected: string): Promise<string> {
	const digest = createHash('sha256');
	for await (const chunk of createReadStream(file)) {
		if (!Buffer.isBuffer(chunk)) throw new Error('Central proof artifact did not supply bytes');
		digest.update(chunk);
	}
	const actual = digest.digest('hex');
	if (actual !== expected) throw new Error(`Central proof artifact SHA-256 mismatch (${actual})`);
	return actual;
}

/** A native Central build a live proof runs against: its source commit and binary digest. */
export interface CentralNativeProofPin {
	readonly commit: string;
	readonly nativeSha256: string;
}

/**
 * C3's live approval proof: Central main 1ede5c1b9 (#389, the person approval routes), the locked
 * production CLI debug build, signed for direct macOS execution.
 */
export const c3CentralProofPin = {
	commit: '1ede5c1b9afbe6bd427ac742f8b63d53a225151e',
	nativeSha256: 'a8ae59ac7ce508b7418d40854057f55232eccb3c97b757aa661c39635a7468cd',
} as const satisfies CentralNativeProofPin;

/**
 * DEL-07's live engine administration proof: Central main 4593797b1 (#394, the signed engine
 * administration route contracts), the locked production CLI debug build, signed for direct macOS
 * execution.
 */
export const engineCentralProofPin = {
	commit: '4593797b1c6a0dd03af6bbed6d8b00a0c4cc876f',
	nativeSha256: 'b6a56bb7185a925d888d4e9ab88fb406e83852b5e5e9c33776d7bed9befde453',
} as const satisfies CentralNativeProofPin;

export async function assertB3CentralNativeProofArtifact(
	executable: string,
	pin: CentralNativeProofPin = b3CentralProofPin,
): Promise<void> {
	const sha256 = await assertDigest(executable, pin.nativeSha256);
	process.stdout.write(
		JSON.stringify({
			event: 'b3-central-native-proof-pin',
			commit: pin.commit,
			sha256,
		}) + '\n',
	);
}

export async function assertB3CentralWorkerProofArtifacts(checkout: string): Promise<void> {
	const result = await runFile('git', ['-C', checkout, 'rev-parse', 'HEAD', 'HEAD^{tree}']);
	const [commit, tree] = result.stdout.trim().split('\n');
	if (commit !== b3CentralProofPin.commit || tree !== b3CentralProofPin.tree)
		throw new Error(`Central proof checkout is not the recorded source (${commit}, ${tree})`);
	const changes = await runFile('git', ['-C', checkout, 'status', '--porcelain']);
	if (changes.stdout !== '') throw new Error('Central proof checkout is dirty');
	const base = join(checkout, 'crates/collaboration-central-cloudflare');
	const hashes = await Promise.all(
		Object.entries(b3CentralProofPin.workers).map(
			async ([artifact, expected]) =>
				[artifact, await assertDigest(join(base, artifact), expected)] as const,
		),
	);
	process.stdout.write(
		JSON.stringify({
			event: 'b3-central-worker-proof-pin',
			commit,
			sha256: Object.fromEntries(hashes),
		}) + '\n',
	);
}
