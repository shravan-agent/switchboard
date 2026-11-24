import { createHash, generateKeyPairSync, sign } from 'node:crypto';

import { passkey, user, verification } from '@agent-collaboration/sign-in-core';
import { encodeCBOR, type CBORType } from '@levischuck/tiny-cbor';
import type { RegistrationResponseJSON } from '@simplewebauthn/server';
import { decodeAttestationObject } from '@simplewebauthn/server/helpers';
import { eq, sql } from 'drizzle-orm';
import { expect, it } from 'vitest';
import { z } from 'zod';

import { useControlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-node-test-clock';
import { controlledSignInIds } from '#sign-in-test-support/test-fixtures/controlled-sign-in-clock';
import { startLocalAuthHarness } from '#sign-in-test-support/test-fixtures/local-auth-harness';
import {
	passkeyPost,
	registerBrowserPasskey,
} from '#sign-in-test-support/test-fixtures/passkey-browser-ceremonies';
import { signInConfirmedPeopleBrowser } from '#sign-in-test-support/test-fixtures/people-browser-login';
import { createSoftwarePasskeyAuthenticator } from '#sign-in-test-support/test-fixtures/software-passkey-authenticator';

useControlledSignInClock();
const ownerEmail = 'owner@example.invalid';

const authenticatorDataHeaderBytes = 37;
const credentialIdLengthOffset = authenticatorDataHeaderBytes + 16;
const attestedCredentialFlag = 0x40;
const backupEligibleFlag = 0x08;
const backupStateFlag = 0x10;

interface ValidAttestation {
	readonly attestation: Map<string, CBORType>;
	readonly authData: Uint8Array;
}
function readValidAttestation(valid: RegistrationResponseJSON): ValidAttestation {
	// The verifier's own decoder, so each case is cut from what it would read.
	const decoded: unknown = decodeAttestationObject(
		Uint8Array.from(Buffer.from(valid.response.attestationObject, 'base64url')),
	);
	const entries = z.instanceof(Map).parse(decoded);
	const authData = z.instanceof(Uint8Array).parse(entries.get('authData'));
	// The software authenticator's 'none' attestation: an empty statement.
	const attestation = new Map<string, CBORType>([
		['fmt', 'none'],
		['attStmt', new Map<string, CBORType>()],
		['authData', authData],
	]);
	return { attestation, authData };
}
function withAttestation(
	valid: RegistrationResponseJSON,
	changes: (current: ValidAttestation) => Map<string, CBORType>,
): RegistrationResponseJSON {
	return {
		...valid,
		response: {
			...valid.response,
			attestationObject: Buffer.from(encodeCBOR(changes(readValidAttestation(valid)))).toString(
				'base64url',
			),
		},
	};
}
function withClientData(
	valid: RegistrationResponseJSON,
	change: (clientData: Record<string, unknown>) => Record<string, unknown>,
): RegistrationResponseJSON {
	const current = z
		.record(z.string(), z.unknown())
		.parse(JSON.parse(Buffer.from(valid.response.clientDataJSON, 'base64url').toString()));
	return {
		...valid,
		response: {
			...valid.response,
			clientDataJSON: Buffer.from(JSON.stringify(change(current))).toString('base64url'),
		},
	};
}
/** The credential public key's position in authData: after the header, AAGUID, length and ID. */
function credentialPublicKeyOffset(authData: Uint8Array): number {
	const credentialIdLength = new DataView(
		authData.buffer,
		authData.byteOffset,
		authData.byteLength,
	).getUint16(credentialIdLengthOffset);
	return credentialIdLengthOffset + 2 + credentialIdLength;
}

type Reason = 'challenge' | 'origin' | 'signature' | 'credentialData' | 'publicKey' | 'malformed';
const faultCases: readonly {
	readonly label: string;
	readonly reason: Reason;
	readonly alter: (valid: RegistrationResponseJSON) => RegistrationResponseJSON;
}[] = [
	{
		label: 'a tampered challenge in the client data',
		reason: 'challenge',
		alter: (valid) => withClientData(valid, (data) => ({ ...data, challenge: 'dGFtcGVyZWQ' })),
	},
	{
		label: 'a client data origin that is not the issuer',
		reason: 'origin',
		alter: (valid) =>
			withClientData(valid, (data) => ({ ...data, origin: 'https://other.example.invalid' })),
	},
	{
		label: 'a packed self-attestation signed by a different key',
		reason: 'signature',
		alter: (valid) =>
			withAttestation(valid, ({ attestation, authData }) => {
				const signedBytes = Buffer.concat([
					authData,
					createHash('sha256')
						.update(Buffer.from(valid.response.clientDataJSON, 'base64url'))
						.digest(),
				]);
				attestation.set('fmt', 'packed');
				attestation.set(
					'attStmt',
					new Map<string, CBORType>([
						['alg', -7],
						[
							'sig',
							sign('sha256', signedBytes, {
								key: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey,
								dsaEncoding: 'der',
							}),
						],
					]),
				);
				return attestation;
			}),
	},
	{
		label: 'authData with no attested credential data',
		reason: 'credentialData',
		alter: (valid) =>
			withAttestation(valid, ({ attestation, authData }) => {
				const header = authData.slice(0, authenticatorDataHeaderBytes);
				header[32] = (header[32] ?? 0) & ~attestedCredentialFlag;
				attestation.set('authData', header);
				return attestation;
			}),
	},
	{
		label: 'authData claiming a backup of a single-device credential',
		reason: 'malformed',
		alter: (valid) =>
			withAttestation(valid, ({ attestation, authData }) => {
				// Backed up (BS) without backup eligibility (BE): SimpleWebAuthn's InvalidBackupFlags.
				const changed = Uint8Array.from(authData);
				changed[32] = ((changed[32] ?? 0) | backupStateFlag) & ~backupEligibleFlag;
				attestation.set('authData', changed);
				return attestation;
			}),
	},
	{
		label: 'a credential public key that is not a COSE map',
		reason: 'publicKey',
		alter: (valid) =>
			withAttestation(valid, ({ attestation, authData }) => {
				attestation.set(
					'authData',
					Uint8Array.from([
						...authData.slice(0, credentialPublicKeyOffset(authData)),
						...encodeCBOR(7),
					]),
				);
				return attestation;
			}),
	},
];

async function storedPasskeyCount(
	harness: Awaited<ReturnType<typeof startLocalAuthHarness>>,
): Promise<number> {
	return (await harness.database.select({ id: passkey.id }).from(passkey)).length;
}

it('passkey registration: a valid ceremony still gives 200 and stores the passkey', async () => {
	const harness = await startLocalAuthHarness();
	try {
		await signInConfirmedPeopleBrowser({ harness, email: ownerEmail });
		const response = await registerBrowserPasskey({
			harness,
			authenticator: await createSoftwarePasskeyAuthenticator(),
		});
		expect(response.status).toBe(200);
		expect(await storedPasskeyCount(harness)).toBe(1);
	} finally {
		await harness.close();
	}
});

it.each(faultCases)(
	'passkey registration: $label gives 400 with reason $reason and stores nothing',
	async ({ reason, alter }) => {
		const harness = await startLocalAuthHarness();
		try {
			await signInConfirmedPeopleBrowser({ harness, email: ownerEmail });
			const response = await registerBrowserPasskey({
				harness,
				authenticator: await createSoftwarePasskeyAuthenticator(),
				alterResponse: alter,
			});
			expect(response.status).toBe(400);
			expect(await response.json()).toMatchObject({ error: 'invalid_request', reason });
			expect(await storedPasskeyCount(harness)).toBe(0);
		} finally {
			await harness.close();
		}
	},
);

it('passkey registration: a storage failure after a passed verification is still a server error', async () => {
	const harness = await startLocalAuthHarness();
	try {
		await signInConfirmedPeopleBrowser({ harness, email: ownerEmail });
		// The verification passes; only the write after it is made to fail.
		await harness.database.run(
			sql`CREATE TRIGGER refuse_passkey_insert BEFORE INSERT ON passkey BEGIN SELECT RAISE(ABORT, 'forced storage failure'); END`,
		);
		const response = await registerBrowserPasskey({
			harness,
			authenticator: await createSoftwarePasskeyAuthenticator(),
		});
		expect(response.status).toBeGreaterThanOrEqual(500);
		expect(await storedPasskeyCount(harness)).toBe(0);
		expect(
			(await harness.database.select({ id: user.id }).from(user).where(eq(user.email, ownerEmail)))
				.length,
		).toBe(1);
	} finally {
		await harness.close();
	}
});

type Harness = Awaited<ReturnType<typeof startLocalAuthHarness>>;

/** Native registration options: the live challenge the browser cookie now names, and the RP ID. */
async function issueRegistrationChallenge(
	harness: Harness,
): Promise<{ readonly challenge: string; readonly rpId: string }> {
	const options = z
		.object({ challenge: z.string().min(1), rp: z.object({ id: z.string().min(1) }) })
		.parse(await (await harness.auth('/api/auth/passkey/generate-register-options')).json());
	return { challenge: options.challenge, rpId: options.rp.id };
}
function postRegistration(harness: Harness, response: RegistrationResponseJSON): Promise<Response> {
	return passkeyPost(harness, 'verify-registration', { name: 'Controlled test passkey', response });
}
async function verificationRows(harness: Harness): Promise<readonly unknown[]> {
	return harness.database.select().from(verification).orderBy(verification.id);
}
async function registrationChallengeRows(
	harness: Harness,
): Promise<readonly (typeof verification.$inferSelect)[]> {
	return (await harness.database.select().from(verification)).filter(
		(row) => z.object({ type: z.literal('registration') }).safeParse(JSON.parse(row.value)).success,
	);
}
const tamperChallenge = faultCases[0];
if (tamperChallenge?.reason !== 'challenge')
	throw new Error('The first fault case is the tampered challenge');

it('passkey registration: a refused fault deletes no verification row, not even an unrelated expired one', async () => {
	const harness = await startLocalAuthHarness();
	try {
		await signInConfirmedPeopleBrowser({ harness, email: ownerEmail });
		const authenticator = await createSoftwarePasskeyAuthenticator();
		const issued = await issueRegistrationChallenge(harness);
		// An unrelated verification row that expired long ago: Better Auth's findVerificationValue
		// would delete it as a side effect of the lookup.
		await harness.database.insert(verification).values({
			id: controlledSignInIds.nextId(),
			identifier: 'unrelated-expired-witness',
			value: '{}',
			expiresAt: new Date(0),
			createdAt: new Date(0),
			updatedAt: new Date(0),
		});
		const before = await verificationRows(harness);
		expect(before).toHaveLength(2);
		const response = await postRegistration(
			harness,
			tamperChallenge.alter(
				authenticator.registrationResponse({ ...issued, origin: harness.issuer }),
			),
		);
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ error: 'invalid_request', reason: 'challenge' });
		expect(await verificationRows(harness)).toEqual(before);
		expect(await storedPasskeyCount(harness)).toBe(0);
	} finally {
		await harness.close();
	}
});

it("passkey registration: an expired challenge reaches the plugin's own not-found answer and is never verified here", async () => {
	const harness = await startLocalAuthHarness();
	try {
		await signInConfirmedPeopleBrowser({ harness, email: ownerEmail });
		const authenticator = await createSoftwarePasskeyAuthenticator();
		const issued = await issueRegistrationChallenge(harness);
		const [challengeRow] = await registrationChallengeRows(harness);
		if (challengeRow === undefined) throw new Error('No registration challenge was stored');
		// Expired before it was created: expired for any clock reading.
		await harness.database
			.update(verification)
			.set({ expiresAt: new Date(challengeRow.createdAt.getTime() - 1) })
			.where(eq(verification.id, challengeRow.id));
		// A tampered challenge: had the boundary verified it, the answer would name reason 'challenge'.
		const response = await postRegistration(
			harness,
			tamperChallenge.alter(
				authenticator.registrationResponse({ ...issued, origin: harness.issuer }),
			),
		);
		expect(response.status).toBe(400);
		const body: unknown = await response.json();
		expect(body).toMatchObject({ code: 'CHALLENGE_NOT_FOUND' });
		expect(body).not.toHaveProperty('reason');
		expect(await storedPasskeyCount(harness)).toBe(0);
	} finally {
		await harness.close();
	}
});

it('passkey registration: a WebCrypto failure in verification is a server error that consumes nothing', async () => {
	const harness = await startLocalAuthHarness();
	try {
		await signInConfirmedPeopleBrowser({ harness, email: ownerEmail });
		const authenticator = await createSoftwarePasskeyAuthenticator();
		const issued = await issueRegistrationChallenge(harness);
		const valid = authenticator.registrationResponse({ ...issued, origin: harness.issuer });
		// The verifier's client data hash is the first digest of exactly these bytes.
		await harness.failNextWebCryptoDigestOf(
			Buffer.from(valid.response.clientDataJSON, 'base64url'),
		);
		const before = await verificationRows(harness);
		const response = await postRegistration(harness, valid);
		expect(response.status).toBe(500);
		expect(await harness.webCryptoDigestFailureState()).toBe('fired');
		expect(await verificationRows(harness)).toEqual(before);
		expect(await storedPasskeyCount(harness)).toBe(0);
	} finally {
		await harness.close();
	}
});
