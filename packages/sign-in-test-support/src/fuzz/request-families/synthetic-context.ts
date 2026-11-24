import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';

import { encodeCBOR, type CBORType } from '@levischuck/tiny-cbor';
import { z } from 'zod';

import type { RequestFamilyContext } from './request-family';

const syntheticOrigin = 'https://issuer.example.invalid';
const syntheticRpId = 'issuer.example.invalid';

/**
 * A registration credential with the real wire structure (client data, CBOR attestation object,
 * authenticator data with an attested COSE key), for planning and offline generation. Nothing
 * verifies it: families that change its nested members need the structure, not a live challenge.
 */
function syntheticRegistrationCredential(): Readonly<Record<string, unknown>> {
	const jwk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
		format: 'jwk',
	});
	const coseKey = encodeCBOR(
		new Map<number, CBORType>([
			[1, 2],
			[3, -7],
			[-1, 1],
			[-2, Buffer.from(String(jwk.x), 'base64url')],
			[-3, Buffer.from(String(jwk.y), 'base64url')],
		]),
	);
	const credentialId = randomBytes(16);
	const credentialIdLength = Buffer.alloc(2);
	credentialIdLength.writeUInt16BE(credentialId.length);
	const authData = Buffer.concat([
		createHash('sha256').update(syntheticRpId).digest(),
		Buffer.from([0x45]),
		Buffer.alloc(4),
		Buffer.alloc(16),
		credentialIdLength,
		credentialId,
		coseKey,
	]);
	const attestationObject = encodeCBOR(
		new Map<string, CBORType>([
			['fmt', 'none'],
			['attStmt', new Map<string, CBORType>()],
			['authData', authData],
		]),
	);
	const credential = credentialId.toString('base64url');
	return z.record(z.string(), z.unknown()).parse({
		id: credential,
		rawId: credential,
		type: 'public-key',
		response: {
			clientDataJSON: Buffer.from(
				JSON.stringify({
					type: 'webauthn.create',
					challenge: 'Y2hhbGxlbmdl',
					origin: syntheticOrigin,
				}),
			).toString('base64url'),
			attestationObject: Buffer.from(attestationObject).toString('base64url'),
			transports: ['usb'],
		},
		clientExtensionResults: {},
		authenticatorAttachment: 'cross-platform',
	});
}

/** Placeholder identities for planning and offline generation; no host sees these values. */
export const syntheticRequestFamilyContext: RequestFamilyContext = {
	issuer: 'https://issuer.example.invalid',
	personId: 'person',
	organizationId: 'organization',
	memberId: 'member',
	invitationId: 'invitation',
	passkeyId: 'passkey',
	challengeId: 'challenge',
	passkeyRegistrationResponse: syntheticRegistrationCredential(),
	passkeyAuthenticationResponse: { id: 'authentication-credential' },
	totpCode: '840293',
	backupCode: 'synthetic-recovery-code',
	captchaToken: 'synthetic-captcha-token',
	callbackQuery: { code: 'provider-code', state: 'provider-state' },
	oauthClientId: 'client',
	oauthClientSecret: 'secret',
	oauthCode: 'code',
	oauthToken: 'token',
	oauthCodeVerifier: 'verifier',
	oauthCodeChallenge: 'challenge',
	oauthRedirectUri: 'http://127.0.0.1:49152/callback',
	oauthResource: 'https://resource.example.invalid',
	machineRouterClientId: 'router-client',
	machineId: 'machine-id',
	machineEnrollmentId: 'machine-enrollment',
	machineUserCode: 'ABCDEFGH',
	machineDeviceCode: 'device-code',
	machineRefreshToken: 'unissued-machine-refresh-token',
};
