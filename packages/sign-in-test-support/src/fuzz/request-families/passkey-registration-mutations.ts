import { createHash, generateKeyPairSync, sign } from 'node:crypto';

import { encodeCBOR, type CBORType } from '@levischuck/tiny-cbor';
import { decodeAttestationObject } from '@simplewebauthn/server/helpers';
import { z } from 'zod';

import type { VariantStep } from './request-family';

/**
 * Mutations of a real registration credential's nested structure, one member at a time. The
 * request guard and the verification boundary both read these members, so each one is reached
 * from inside the decoded client data, attestation object or authenticator data, not from the
 * outside of the request body.
 */
type NestedMutation = Extract<VariantStep['mutation'], 'near-valid' | 'boundary' | 'wrong-type'>;

const authenticatorDataHeaderBytes = 37;
const flagsOffset = 32;
const attestedCredentialFlag = 0x40;
const userVerifiedFlag = 0x04;
const credentialIdLengthOffset = authenticatorDataHeaderBytes + 16;

const credentialShapeSchema = z.looseObject({
	response: z.looseObject({ clientDataJSON: z.string(), attestationObject: z.string() }),
});

interface DecodedCredential {
	readonly credential: z.infer<typeof credentialShapeSchema>;
	readonly clientData: Record<string, unknown>;
	readonly attestation: Map<string, CBORType>;
	readonly authData: Uint8Array;
}

function decodeCredential(raw: Readonly<Record<string, unknown>>): DecodedCredential {
	const credential = credentialShapeSchema.parse(raw);
	const clientData = z
		.record(z.string(), z.unknown())
		.parse(JSON.parse(Buffer.from(credential.response.clientDataJSON, 'base64url').toString()));
	// The verifier's own decoder, so each mutation is cut from what it would read.
	const decoded: unknown = decodeAttestationObject(
		Uint8Array.from(Buffer.from(credential.response.attestationObject, 'base64url')),
	);
	const decodedAttestation = z
		.instanceof(Map)
		.transform((entries) => ({
			fmt: z.string().parse(entries.get('fmt')),
			// The software authenticator's 'none' attestation: an empty statement.
			attStmt: z
				.instanceof(Map)
				.refine((statement) => statement.size === 0)
				.parse(entries.get('attStmt')),
			authData: z.instanceof(Uint8Array).parse(entries.get('authData')),
		}))
		.parse(decoded);
	const { authData } = decodedAttestation;
	const attestation = new Map<string, CBORType>([
		['fmt', decodedAttestation.fmt],
		['attStmt', new Map<string, CBORType>()],
		['authData', authData],
	]);
	return { credential, clientData, attestation, authData };
}

function encodeCredential(
	decoded: DecodedCredential,
	changes: {
		readonly clientData?: Record<string, unknown>;
		readonly attestation?: Map<string, CBORType>;
	},
): Record<string, unknown> {
	return {
		...decoded.credential,
		response: {
			...decoded.credential.response,
			clientDataJSON: Buffer.from(
				JSON.stringify(changes.clientData ?? decoded.clientData),
			).toString('base64url'),
			attestationObject: Buffer.from(
				encodeCBOR(changes.attestation ?? decoded.attestation),
			).toString('base64url'),
		},
	};
}

function withAuthData(decoded: DecodedCredential, authData: Uint8Array): Record<string, unknown> {
	return encodeCredential(decoded, {
		attestation: new Map<string, CBORType>(decoded.attestation).set('authData', authData),
	});
}
function withClientData(
	decoded: DecodedCredential,
	changes: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
	return encodeCredential(decoded, { clientData: { ...decoded.clientData, ...changes } });
}
function withAttestation(
	decoded: DecodedCredential,
	changes: ReadonlyMap<string, CBORType>,
): Record<string, unknown> {
	const attestation = new Map<string, CBORType>(decoded.attestation);
	for (const [key, value] of changes) attestation.set(key, value);
	return encodeCredential(decoded, { attestation });
}
function credentialPublicKeyOffset(authData: Uint8Array): number {
	const credentialIdLength = new DataView(
		authData.buffer,
		authData.byteOffset,
		authData.byteLength,
	).getUint16(credentialIdLengthOffset);
	return credentialIdLengthOffset + 2 + credentialIdLength;
}
function withCredentialPublicKey(
	decoded: DecodedCredential,
	publicKey: Uint8Array,
): Record<string, unknown> {
	return withAuthData(
		decoded,
		Uint8Array.from([
			...decoded.authData.slice(0, credentialPublicKeyOffset(decoded.authData)),
			...publicKey,
		]),
	);
}
/** A packed self-attestation whose signature is well-formed DER from a key that is not the credential's. */
function packedAttestationSignedByOtherKey(decoded: DecodedCredential): Record<string, unknown> {
	const signedBytes = Buffer.concat([
		decoded.authData,
		createHash('sha256')
			.update(Buffer.from(decoded.credential.response.clientDataJSON, 'base64url'))
			.digest(),
	]);
	return withAttestation(
		decoded,
		new Map<string, CBORType>([
			['fmt', 'packed'],
			[
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
			],
		]),
	);
}

interface NestedMutationPlan {
	readonly field: string;
	readonly mutation: NestedMutation;
	readonly apply: (decoded: DecodedCredential, drawnLength: number) => Record<string, unknown>;
}

const nestedMutationPlans: readonly NestedMutationPlan[] = [
	{
		field: 'clientDataJSON.challenge',
		mutation: 'near-valid',
		apply: (decoded) => withClientData(decoded, { challenge: 'dGFtcGVyZWQ' }),
	},
	{
		field: 'clientDataJSON.origin',
		mutation: 'near-valid',
		apply: (decoded) => withClientData(decoded, { origin: 'https://other.example.invalid' }),
	},
	{
		field: 'clientDataJSON.type',
		mutation: 'wrong-type',
		apply: (decoded) => withClientData(decoded, { type: 1 }),
	},
	{
		field: 'attestationObject.fmt',
		mutation: 'near-valid',
		apply: (decoded) =>
			withAttestation(decoded, new Map<string, CBORType>([['fmt', 'unknown-format']])),
	},
	{
		field: 'attestationObject.fmt',
		mutation: 'wrong-type',
		apply: (decoded) => withAttestation(decoded, new Map<string, CBORType>([['fmt', 7]])),
	},
	{
		field: 'attestationObject.attStmt',
		mutation: 'near-valid',
		apply: packedAttestationSignedByOtherKey,
	},
	{
		field: 'attestationObject.attStmt',
		mutation: 'boundary',
		apply: (decoded) =>
			withAttestation(
				decoded,
				new Map<string, CBORType>([
					['fmt', 'packed'],
					[
						'attStmt',
						new Map<string, CBORType>([
							['alg', -7],
							['sig', new Uint8Array(70).fill(1)],
						]),
					],
				]),
			),
	},
	{
		field: 'attestationObject.authData',
		mutation: 'boundary',
		apply: (decoded, drawnLength) => withAuthData(decoded, decoded.authData.slice(0, drawnLength)),
	},
	{
		field: 'attestationObject.authData.flags',
		mutation: 'near-valid',
		apply: (decoded) => {
			const header = decoded.authData.slice(0, authenticatorDataHeaderBytes);
			header[flagsOffset] = (header[flagsOffset] ?? 0) & ~attestedCredentialFlag;
			return withAuthData(decoded, header);
		},
	},
	{
		field: 'attestationObject.authData.flags',
		mutation: 'boundary',
		apply: (decoded) => {
			const changed = Uint8Array.from(decoded.authData);
			changed[flagsOffset] = (changed[flagsOffset] ?? 0) & ~userVerifiedFlag;
			return withAuthData(decoded, changed);
		},
	},
	{
		field: 'attestationObject.authData.rpIdHash',
		mutation: 'near-valid',
		apply: (decoded) => {
			const changed = Uint8Array.from(decoded.authData);
			changed[0] = (changed[0] ?? 0) ^ 0xff;
			return withAuthData(decoded, changed);
		},
	},
	{
		field: 'attestationObject.authData.credentialPublicKey',
		mutation: 'wrong-type',
		apply: (decoded) => withCredentialPublicKey(decoded, encodeCBOR(7)),
	},
	{
		field: 'attestationObject.authData.credentialPublicKey',
		mutation: 'near-valid',
		apply: (decoded) => withCredentialPublicKey(decoded, encodeCBOR(new Map([[1, 2]]))),
	},
];

export const nestedRegistrationSteps: readonly VariantStep[] = nestedMutationPlans.map((plan) => ({
	encoding: 'json-nested',
	field: plan.field,
	mutation: plan.mutation,
}));

/** The request body's `response`, built from the real credential with the planned member changed. */
export function nestedRegistrationResponse(props: {
	readonly credential: Readonly<Record<string, unknown>>;
	readonly step: VariantStep;
	readonly drawnLength: number;
}): Record<string, unknown> {
	const plan = nestedMutationPlans.find(
		(candidate) =>
			candidate.field === props.step.field && candidate.mutation === props.step.mutation,
	);
	if (plan === undefined)
		throw new Error(`No nested registration mutation for ${props.step.field}`);
	return plan.apply(decodeCredential(props.credential), props.drawnLength);
}
