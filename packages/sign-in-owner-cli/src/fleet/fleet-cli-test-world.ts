import {
	createFleetAdminProofKey,
	fleetAdminProofKeyThumbprint,
} from '@agent-collaboration/sign-in-core';

import type { AuthTarget, FleetTarget } from '#sign-in-owner-cli/auth-target';
import type { FleetCliIo } from '#sign-in-owner-cli/fleet/fleet-credential';
import { createMemoryProofKeyStore } from '#sign-in-owner-cli/fleet/proof-key-store';

// The fleet CLI's unit-test world: one scripted issuer token endpoint and relay. Unit tests only.

export const target: FleetTarget = {
	issuer: 'https://sign-in.example.invalid',
	organizationId: '019a3dce-2000-7000-8000-000000000001',
	ownerCliRedirectUri: 'http://127.0.0.1/callback',
	centralAdminAudience: 'https://central.example.invalid/admin',
	centralPublicOrigin: 'https://central.example.invalid',
	ownerFleetCliClientId: 'owner-fleet-cli',
};

/** The JWS header or payload, read without verifying: the test checks what the CLI sent. */
function jwsPart(token: string, index: 0 | 1): Record<string, unknown> {
	return JSON.parse(Buffer.from(token.split('.')[index] ?? '', 'base64url').toString('utf8'));
}
export const decodeProtectedHeader = (token: string): Record<string, unknown> => jwsPart(token, 0);
export const decodeJwt = (token: string): Record<string, unknown> => jwsPart(token, 1);

export function unsignedToken(claims: Readonly<Record<string, unknown>>): string {
	const part = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
	return `${part({ alg: 'none' })}.${part(claims)}.`;
}

/** A scripted issuer token endpoint and relay; central's answers come from `relayReplies`. */
export async function scenario(relayReplies: readonly (() => Response)[]): Promise<{
	readonly io: FleetCliIo;
	readonly relayCalls: { readonly path: string; readonly body: string; readonly proof: string }[];
	readonly refreshCalls: string[];
	readonly store: ReturnType<typeof createMemoryProofKeyStore>;
	readonly session: {
		readonly accessToken: string;
		readonly key: Awaited<ReturnType<typeof createFleetAdminProofKey>>;
	};
}> {
	const key = await createFleetAdminProofKey(globalThis.crypto);
	const store = createMemoryProofKeyStore(globalThis.crypto);
	await store.save({ key, refreshToken: 'refresh-1' });
	const relayCalls: { readonly path: string; readonly body: string; readonly proof: string }[] = [];
	const refreshCalls: string[] = [];
	let ids = 0;
	const io: FleetCliIo = {
		crypto: globalThis.crypto,
		now: () => 2_208_988_800_000,
		nextId: () => {
			ids += 1;
			return `019a3dce-2000-7000-8000-${ids.toString(16).padStart(12, '0')}`;
		},
		browser: async () => {
			throw new Error('no browser in this case');
		},
		async fetch(input, init) {
			const url = new URL(String(input));
			const headers = new Headers(init?.headers);
			if (url.pathname === '/api/auth/oauth2/token') {
				const form = new URLSearchParams(
					typeof init?.body === 'string'
						? init.body
						: init?.body instanceof URLSearchParams
							? init.body
							: '',
				);
				refreshCalls.push(form.get('refresh_token') ?? '');
				const jwk = decodeProtectedHeader(headers.get('dpop') ?? '').jwk;
				const thumbprint =
					jwk === undefined
						? ''
						: await fleetAdminProofKeyThumbprint(globalThis.crypto, {
								privateKey: key.privateKey,
								publicJwk: jwk as typeof key.publicJwk,
							});
				return Response.json({
					access_token: unsignedToken({
						aud: target.centralAdminAudience,
						client_id: target.ownerFleetCliClientId,
						token_profile: 'person-fleet',
						cnf: { jkt: thumbprint },
					}),
					token_type: 'DPoP',
					refresh_token: `refresh-${refreshCalls.length + 1}`,
				});
			}
			relayCalls.push({
				path: url.pathname,
				body: typeof init?.body === 'string' ? init.body : '',
				proof: headers.get('dpop') ?? '',
			});
			const reply = relayReplies[relayCalls.length - 1];
			if (reply === undefined) throw new Error('unexpected relay call');
			return reply();
		},
	};
	return { io, relayCalls, refreshCalls, store, session: { accessToken: 'access-1', key } };
}

export const authTarget: AuthTarget = {
	issuer: target.issuer,
	managementAudience: 'https://portal.example.invalid/management',
	gatewayUrl: 'https://portal.example.invalid',
	ownerCliClientId: 'owner-cli',
	ownerCliRedirectUri: target.ownerCliRedirectUri,
	organizationId: target.organizationId,
	workspaceId: '019a3dce-2000-7000-8000-000000000002',
	tokenCachePath: '/nonexistent/owner-token.json',
	centralAdminAudience: target.centralAdminAudience,
	centralPublicOrigin: target.centralPublicOrigin,
	ownerFleetCliClientId: target.ownerFleetCliClientId,
};

/** The owner CLI entrypoint exactly as its `--help` prints it, as the words a shell passes. */
export const documentedEntrypoint = [
	'mise',
	'exec',
	'--',
	'node',
	'scripts/verify-auth/owner-cli.ts',
];

/**
 * The words a POSIX shell reads from a line built only of unquoted safe characters,
 * single-quoted text and `\'` (XCU 2.2.1–2.2.2). Any other shell syntax is refused, not guessed.
 */
export function posixShellWords(line: string): string[] {
	const wordPattern = /^((?:'[^']*'|\\'|[\w./=:@%+,-])+)(?: |$)/u;
	const words: string[] = [];
	let rest = line;
	while (rest !== '') {
		const match = wordPattern.exec(rest);
		if (match?.[1] === undefined) throw new Error(`Not a plain shell word at: ${rest}`);
		words.push(
			match[1].replaceAll(/'([^']*)'|\\'/gu, (_segment, quoted?: string) => quoted ?? "'"),
		);
		rest = rest.slice(match[0].length);
	}
	return words;
}
