import { z } from 'zod';

export const webCryptoDigestFailureStateSchema = z.enum(['idle', 'armed', 'fired']);

const webCryptoDigestFailurePath = '/__auth-proof/web-crypto-digest-failure';
const armSchema = z.strictObject({ inputBase64url: z.base64url().min(1) });

let state: z.infer<typeof webCryptoDigestFailureStateSchema> = 'idle';
let armedInput: Uint8Array | null = null;
let installed = false;

function bufferSourceBytes(data: BufferSource): Uint8Array {
	return ArrayBuffer.isView(data)
		? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
		: new Uint8Array(data);
}
/** Decoded without Buffer, which the workerd host does not provide. */
function base64urlBytes(encoded: string): Uint8Array {
	const base64 = encoded.replaceAll('-', '+').replaceAll('_', '/');
	const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='));
	return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
	return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}

/**
 * Wrap this runtime's WebCrypto `digest` once. While armed, the first digest of exactly the armed
 * bytes rejects as WebCrypto does on an operation failure; every other digest runs unchanged.
 */
function installDigestFailure(): void {
	if (installed) return;
	const subtle = globalThis.crypto.subtle;
	const digest = subtle.digest.bind(subtle);
	Object.defineProperty(subtle, 'digest', {
		configurable: true,
		writable: true,
		value: (algorithm: AlgorithmIdentifier, data: BufferSource): Promise<ArrayBuffer> => {
			if (armedInput !== null && sameBytes(bufferSourceBytes(data), armedInput)) {
				armedInput = null;
				state = 'fired';
				return Promise.reject(
					new DOMException('Injected WebCrypto digest failure', 'OperationError'),
				);
			}
			return digest(algorithm, data);
		},
	});
	installed = true;
}

/** Test-only control: POST arms a one-shot digest failure for the given bytes; GET reads its state. */
export async function handleWebCryptoDigestFailureControl(
	request: Request,
): Promise<Response | null> {
	if (new URL(request.url).pathname !== webCryptoDigestFailurePath) return null;
	if (request.method === 'POST') {
		const input = armSchema.parse(await request.json());
		installDigestFailure();
		armedInput = base64urlBytes(input.inputBase64url);
		state = 'armed';
	}
	return Response.json({ state });
}
