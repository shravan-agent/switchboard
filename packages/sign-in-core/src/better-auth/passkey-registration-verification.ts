import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { z } from 'zod';

/**
 * Why a registration response was refused. Closed: every refusal is one of these, and a switch
 * over it ends in a `never` check, so a new reason cannot be added without handling it.
 */
export type PasskeyRegistrationRefusalReason =
	| 'challenge'
	| 'origin'
	| 'rpId'
	| 'signature'
	| 'attestation'
	| 'credentialData'
	| 'publicKey'
	| 'malformed';

/**
 * What one verification run concluded. `verifier-failed` is not a client fault: the verifier failed
 * in a way no known credential error explains (WebCrypto unavailable or throwing, for one), so the
 * caller answers it as the server error it is.
 */
export type PasskeyRegistrationVerification =
	| { readonly kind: 'verified' }
	| { readonly kind: 'refused'; readonly reason: PasskeyRegistrationRefusalReason }
	| { readonly kind: 'verifier-failed'; readonly failure: unknown };

export interface PasskeyRegistrationExpectation {
	readonly challenge: string;
	readonly origin: string;
	readonly rpId: string;
}

/**
 * The wire fields verification reads. The request guard has already decoded this body once;
 * this is the typed view the verifier takes. `transports` is left out: verification only echoes it.
 */
const registrationResponseWireSchema = z.object({
	id: z.string(),
	rawId: z.string(),
	type: z.literal('public-key'),
	response: z.object({ clientDataJSON: z.string(), attestationObject: z.string() }),
});

/**
 * The known credential errors, by what @simplewebauthn/server 13.3.3 and the libraries it calls
 * throw for client-supplied input. Anything not listed here is not assumed to be the client's fault.
 */
interface ThrownError {
	readonly name: string;
	readonly message: string;
}

/** The name and message of a thrown value. DOMException is read the same way on every runtime. */
function readThrownError(error: unknown): ThrownError | null {
	if (typeof error !== 'object' || error === null || !('name' in error) || !('message' in error))
		return null;
	const { name, message } = error;
	return typeof name === 'string' && typeof message === 'string' ? { name, message } : null;
}

/**
 * The attestation statement failures that are the client's: each format's own checks of the
 * statement and its certificates, by exact message, with the format suffix it throws. A
 * certificate-path failure is the client's only when the client's chain is at fault (not
 * chained, out of validity, revoked); a fault in the server's trust anchors or in the
 * path-building dependency falls through to a verifier failure.
 * Android Key differs: it validates the chain against the root the client sends, so a bad anchor
 * there is the client's.
 */
const knownAttestationFaultPatterns: readonly RegExp[] = [
	/^Unsupported Attestation Format: /u,
	/^None attestation had unexpected attestation statement$/u,
	/^(?:No attestation (?:signature|certificate) provided in attestation statement|Attestation statement did not contain (?:alg|pubArea|certInfo)|Attestation statement contained invalid alg -?\d+) \((?:Packed|Packed\|Full|FIDOU2F|Android Key|Apple|SafetyNet|TPM|TPM\|RSA|TPM\|ECC)\)$/u,
	// Packed full attestation: the leaf certificate's subject and validity.
	/^(?:Certificate OU was not "Authenticator Attestation"|Certificate CN was empty|Certificate O was empty|Certificate C was not two-character ISO 3166 code|Certificate basic constraints CA was not `false`|Certificate version was not `3` \(ASN\.1 value of 2\)|Certificate not good (?:before|after) ".*"|Metadata does not indicate support for full attestations) \(Packed\|Full\)$/u,
	// The leaf's AAGUID extension disagrees with the authenticator data.
	/^Certificate extension id-fido-gen-ce-aaguid \([\d.]+\) value of "[\da-f]*" was present but not equal to attestation statement AAGUID value of "[\da-f]*" \((?:Packed\|Full|TPM)\)$/u,
	// The client's certificate chain, as validateCertificatePath reports it.
	/^(?:x5c could not be chained to any specified trust anchor|Found certificate out of validity period in x5c:\n[\s\S]*|Found revoked certificate in x5c:\n[\s\S]*) \((?:Packed|Packed\|Full|FIDOU2F|Android Key|Apple|SafetyNet|TPM|TPM\|RSA|TPM\|ECC)\)$/u,
	/^(?:Could not parse trust anchor certificate:\n[\s\S]*|No specified trust anchor was valid for verifying x5c) \(Android Key\)$/u,
	// FIDO U2F.
	/^AAGUID "[\da-f]*" was not expected value$/u,
	// Android Key.
	/^(?:Credential public key does not equal leaf cert public key|Certificate did not contain extKeyStore|Attestation challenge was not equal to client data hash|teeEnforced contained "allApplications \[600\]" tag|x5c root certificate was not a known root certificate) \(Android Key\)$/u,
	// Apple.
	/^(?:credCert missing extensions|credCert missing "1\.2\.840\.113635\.100\.8\.2" extension|credCert nonce was not expected value|Credential public key does not equal credCert public key) \(Apple\)$/u,
	// Android SafetyNet.
	/^(?:No ver value in attestation|No response was included in attStmt by authenticator|Payload timestamp "\d+" was later than "\d+"|Payload timestamp "\d+" has expired|Could not verify payload nonce|Could not verify device integrity|Certificate common name was not "attest\.android\.com") \(SafetyNet\)$/u,
	// TPM.
	/^(?:Unexpected ver ".*", expected "2\.0"|No certificates present in x5c array|Certificate basic constraints CA was not `false`|Certificate version was not `3` \(ASN\.1 value of 2\)|Certificate subject was not empty|Certificate was missing extensions|Certificate did not contain subjectAltName extension|Certificate subjectAltName extension directoryName was empty|Certificate contained incomplete subjectAltName data|Certificate did not contain ExtendedKeyUsage extension|Could not match TPM manufacturer ".*"|Unexpected extKeyUsage ".*", expected "2\.23\.133\.8\.3"|Unexpected magic value ".*", expected "0xff544347"|Unexpected type ".*", expected "TPM_ST_ATTEST_CERTIFY"|Attested name comparison failed|CertInfo extra data did not equal hashed attestation|Certificate not good (?:before|after) ".*"|Unexpected type ".*") \(TPM\)$/u,
	/^(?:COSE public key missing (?:n|e) \(TPM\|RSA\)|PubArea unique is not same as credentialPublicKey \(TPM\|RSA\)|Parsed pubArea type is RSA, but missing parameters\.rsa \(TPM\|RSA\)|Unexpected public key exp -?\d+, expected -?\d+ \(TPM\|RSA\)|COSE public key missing (?:crv|x|y) \(TPM\|ECC\)|PubArea unique is not same as public key x and y \(TPM\|ECC\)|Parsed pubArea type is ECC, but missing parameters\.ecc \(TPM\|ECC\)|Public area key curve ID ".*" mapped to ".*" which did not match public key crv of ".*" \(TPM\|ECC\))$/u,
	/^(?:Credential public key with kty .* did not match .*|Unsupported pubArea\.type ".*"|Unexpected TPM attested name alg .*)$/u,
	// An attestation certificate that is not X.509, or whose public key is not one the verifier reads.
	/^Data does not match to Certificate ASN1 schema/u,
	/^(?:Certificate public key was missing parameters \(EC2\)|Certificate public key contained unexpected namedCurve .* \(EC2\)|Certificate public key contained unexpected algorithm ID .*)$/u,
];
function isKnownAttestationFault(error: ThrownError): boolean {
	return knownAttestationFaultPatterns.some((pattern) => pattern.test(error.message));
}

const knownCredentialFaults: readonly {
	readonly reason: PasskeyRegistrationRefusalReason;
	readonly matches: (error: ThrownError) => boolean;
}[] = [
	{
		reason: 'challenge',
		matches: (error) => error.message.startsWith('Unexpected registration response challenge '),
	},
	{
		reason: 'origin',
		matches: (error) => error.message.startsWith('Unexpected registration response origin '),
	},
	{ reason: 'rpId', matches: (error) => error.name === 'UnexpectedRPIDHash' },
	{
		reason: 'credentialData',
		matches: (error) =>
			/^No (credential ID|public key) was provided by authenticator$|^No AAGUID was present during registration$/u.test(
				error.message,
			),
	},
	{
		reason: 'publicKey',
		matches: (error) =>
			// WebCrypto refuses key bytes that do not describe a key (a point off the curve): DataError.
			error.name === 'DataError' ||
			// A key that decodes to something other than a COSE map fails on `.get` inside the verifier.
			/^(Credential public key was missing numeric alg|Unexpected public key alg |decodedPublicKey\.get is not a function|Public key was missing (alg|crv|x|y|n|e) \(|Public key had invalid alg |Unexpected COSE crv value of |unknown COSE curve |Signature verification with public key of kty |Could not map COSE alg value of |Unexpected RSA key algorithm )/u.test(
				error.message,
			),
	},
	{
		reason: 'signature',
		// The signature bytes are not a DER ECDSA signature: the ASN.1 parser refuses them.
		matches: (error) =>
			/^(Data does not match to ECDSASigValue ASN1 schema|Input buffer has zero length$|Invalid signature component length )/u.test(
				error.message,
			),
	},
	{ reason: 'attestation', matches: isKnownAttestationFault },
	{
		reason: 'malformed',
		matches: (error) =>
			// A single-device credential that claims a backup (BS without BE).
			error.name === 'InvalidBackupFlags' ||
			/^(Missing credential ID$|Credential ID was not base64url-encoded$|Unexpected credential type |Unexpected registration response type|Unexpected value for TokenBinding |Unexpected tokenBinding\.status |User presence was required|Authenticator data was \d+ bytes|Leftover bytes detected while parsing authenticator data$|Error decoding authenticator extensions: )/u.test(
				error.message,
			),
	},
];

function classifyVerificationFault(error: unknown): PasskeyRegistrationVerification {
	const thrown = readThrownError(error);
	if (thrown !== null)
		for (const { reason, matches } of knownCredentialFaults)
			if (matches(thrown)) return { kind: 'refused', reason };
	return { kind: 'verifier-failed', failure: error };
}

/**
 * Run the verifier the Better Auth passkey plugin will run, and name a known client fault instead of
 * throwing it. A failure no known credential error explains stays a verifier failure.
 */
export async function verifyPasskeyRegistrationResponse(props: {
	readonly response: unknown;
	readonly expected: PasskeyRegistrationExpectation;
}): Promise<PasskeyRegistrationVerification> {
	const wire = registrationResponseWireSchema.safeParse(props.response);
	if (!wire.success) return { kind: 'refused', reason: 'malformed' };
	try {
		const verification = await verifyRegistrationResponse({
			response: { ...wire.data, clientExtensionResults: {} },
			expectedChallenge: props.expected.challenge,
			expectedOrigin: props.expected.origin,
			expectedRPID: props.expected.rpId,
			requireUserVerification: false,
		});
		// A well-formed signature that does not verify (valid DER from the wrong key, say) is reported
		// as `verified: false`, not thrown. The attestation formats sign-in accepts report it the same way.
		return verification.verified ? { kind: 'verified' } : { kind: 'refused', reason: 'signature' };
	} catch (error) {
		return classifyVerificationFault(error);
	}
}

/** The message a client reads for each reason; exhaustive, so a new reason fails the build here. */
export function describePasskeyRegistrationRefusal(
	reason: PasskeyRegistrationRefusalReason,
): string {
	switch (reason) {
		case 'challenge':
			return 'The registration answers a different challenge.';
		case 'origin':
			return 'The registration was made for a different origin.';
		case 'rpId':
			return 'The registration was made for a different relying party.';
		case 'signature':
			return 'The registration signature does not verify.';
		case 'attestation':
			return 'The registration attestation is not acceptable.';
		case 'credentialData':
			return 'The registration carries no attested credential data.';
		case 'publicKey':
			return 'The registration public key is not an acceptable COSE key.';
		case 'malformed':
			return 'The registration response is malformed.';
		default: {
			const unreachable: never = reason;
			return unreachable;
		}
	}
}
