import { expect, it } from 'vitest';
import { z } from 'zod';

import { useControlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-node-test-clock';
import { controlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-sign-in-clock';
import { readCurrentBrowserSession } from '#sign-in-test-support/test-fixtures/current-browser-session';
import { startLocalAuthHarness } from '#sign-in-test-support/test-fixtures/local-auth-harness';
import { ensureLocalOwnerOrganization } from '#sign-in-test-support/test-fixtures/local-owner-organization';
import { registerBrowserPasskey } from '#sign-in-test-support/test-fixtures/passkey-browser-ceremonies';
import { signInConfirmedPeopleBrowser } from '#sign-in-test-support/test-fixtures/people-browser-login';
import { createSoftwarePasskeyAuthenticator } from '#sign-in-test-support/test-fixtures/software-passkey-authenticator';
import { allSignInRowFingerprints } from '#sign-in-test-support/test-fixtures/stored-row-fingerprints';

useControlledSignInClock();
type Harness = Awaited<ReturnType<typeof startLocalAuthHarness>>;

async function readyForLimitProof(harness: Harness): Promise<void> {
	// An actual JWKS fetch/import is the readiness witness for these signed-out
	// flood cases; no receipt is marked ready because a listener merely exists.
	expect((await harness.auth('/api/auth/jwks')).status).toBe(200);
}

function socialAttemptInit(
	harness: Harness,
	additionalHeaders: Readonly<Record<string, string>> = {},
): RequestInit {
	return {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			'x-captcha-response': harness.turnstile.issueToken({
				action: 'sign_in_social',
				hostname: new URL(harness.issuer).hostname,
				verdict: 'accepted',
			}),
			...additionalHeaders,
		},
		body: JSON.stringify({
			provider: 'google',
			callbackURL: new URL('/owner-ready', harness.issuer).toString(),
		}),
	};
}

function socialAttempt(
	harness: Harness,
	additionalHeaders: Readonly<Record<string, string>> = {},
): Promise<Response> {
	return harness.auth('/api/auth/sign-in/social', socialAttemptInit(harness, additionalHeaders));
}

/** The same start from another fixture browser, which the harness gives its own stable address. */
function socialAttemptFromSecondAddress(harness: Harness): Promise<Response> {
	return harness.authAsBrowser(
		'second-address',
		'/api/auth/sign-in/social',
		socialAttemptInit(harness),
	);
}

it('people: an unavailable outer backing call returns 503 before native captcha or state effects', async () => {
	const harness = await startLocalAuthHarness();
	try {
		await readyForLimitProof(harness);
		// Positive control: this same valid request reaches native captcha and
		// OAuth state normally before the backing failure is armed.
		expect((await socialAttempt(harness)).status).toBe(200);
		const before = await allSignInRowFingerprints(harness);
		const nativeAttempts = harness.siteVerifyAttempts();
		expect(nativeAttempts).toBe(1);
		await harness.makeLimiterUnavailable();
		const response = await socialAttempt(harness);
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: 'sign-in-unavailable' });
		expect(harness.siteVerifyAttempts()).toBe(nativeAttempts);
		expect(await allSignInRowFingerprints(harness)).toEqual(before);
		expect(await harness.captchaObservations()).toContainEqual({
			kind: 'request-limit-unavailable',
			requestClass: 'sign-in',
		});
	} finally {
		await harness.close();
	}
});

it('people: changing spoofed XFF leaves native counting on the trusted host address', async () => {
	const harness = await startLocalAuthHarness();
	try {
		await readyForLimitProof(harness);
		const address = harness.browserAddress();
		const started = await Promise.all(
			[1, 2, 3].map((suffix) =>
				socialAttempt(harness, { 'x-forwarded-for': `198.51.100.${suffix}` }),
			),
		);
		expect(started.map((response) => response.status)).toEqual([200, 200, 200]);
		const before = await allSignInRowFingerprints(harness);
		const refused = await socialAttempt(harness, { 'x-forwarded-for': '198.51.100.4' });
		expect(refused.status).toBe(429);
		expectRetryAfter(refused);
		expect(harness.browserAddress()).toBe(address);
		expect(await allSignInRowFingerprints(harness)).toEqual(before);
		// Four starts stay below the real CF outer budget: this is trusted-input
		// and native keying proof, not vendor throttle/reset proof.
	} finally {
		await harness.close();
	}
});
function expectRetryAfter(response: Response): void {
	expect(
		z.coerce.number().int().positive().safeParse(response.headers.get('retry-after')).success,
	).toBe(true);
}

it('people: social starts hit the native limit and the real outer counter (Miniflare binding, Node counter) without more stored effects, and another address still passes', async () => {
	const harness = await startLocalAuthHarness({ turnstileSecret: 'published-test' });
	try {
		await readyForLimitProof(harness);
		const address = harness.browserAddress();
		const first = await Promise.all(Array.from({ length: 3 }, () => socialAttempt(harness)));
		expect(first.map((response) => response.status)).toEqual([200, 200, 200]);
		const beforeLimit = await allSignInRowFingerprints(harness);
		const refused = await socialAttempt(harness);
		expect(refused.status).toBe(429);
		expectRetryAfter(refused);
		expect(await allSignInRowFingerprints(harness)).toEqual(beforeLimit);
		// Node counts in its real host map; Cloudflare counts in Miniflare's real
		// rate-limit binding. Neither is the hosted vendor counter.
		const continued = await Promise.all(Array.from({ length: 12 }, () => socialAttempt(harness)));
		expect(continued.every((response) => response.status === 429)).toBe(true);
		expect(harness.browserAddress()).toBe(address);
		expect(await allSignInRowFingerprints(harness)).toEqual(beforeLimit);
		const observations = await harness.captchaObservations();
		expect(
			observations.filter((observation) => observation.kind === 'request-limited'),
		).toHaveLength(13);
		expect(observations).toContainEqual({
			kind: 'request-limited',
			requestClass: 'sign-in',
			layer: 'provider',
		});
		expect(observations).toContainEqual({
			kind: 'request-limited',
			requestClass: 'sign-in',
			layer: 'outer',
		});
		// R52: the count is per address, so a second address is not limited.
		expect((await socialAttemptFromSecondAddress(harness)).status).toBe(200);
	} finally {
		await harness.close();
	}
});

async function firstLimitedPage(props: {
	readonly harness: Harness;
	readonly attempt?: number;
}): Promise<{ readonly attempt: number; readonly response: Response }> {
	const attempt = props.attempt ?? 1;
	const response = await props.harness.auth('/owner-ready');
	if (response.status === 429) return { attempt, response };
	expect(response.status).toBe(200);
	if (attempt >= 601) throw new Error('The service page never reached its outer limit');
	// Await the real response event, not a sleep or an injected clock jump.
	return firstLimitedPage({ harness: props.harness, attempt: attempt + 1 });
}

it('people: the service page controlled window refuses exactly request 301 without a write, and another address still passes', async () => {
	const harness = await startLocalAuthHarness({ turnstileSecret: 'published-test' });
	try {
		await readyForLimitProof(harness);
		await harness.useControlledServicePageWindow();
		const before = await allSignInRowFingerprints(harness);
		const limited = await firstLimitedPage({ harness });
		expectRetryAfter(limited.response);
		expect(limited.attempt).toBe(301);
		// Cloudflare substitutes only this counter; HTTP, adapter and address keying remain real.
		expect(await allSignInRowFingerprints(harness)).toEqual(before);
		expect(await harness.captchaObservations()).toContainEqual({
			kind: 'request-limited',
			requestClass: 'service-page',
			layer: 'outer',
		});
		// R52: the count is per address, so a second address is not limited.
		expect((await harness.authAsBrowser('second-address', '/owner-ready')).status).toBe(200);
	} finally {
		await harness.close();
	}
});

it.runIf((process.env.SIGN_IN_TEST_HOST ?? 'cloudflare') === 'cloudflare')(
	'people: the service page real Miniflare binding refuses within 601 requests without a write, and another address still passes',
	async () => {
		const harness = await startLocalAuthHarness({ turnstileSecret: 'published-test' });
		try {
			await readyForLimitProof(harness);
			const before = await allSignInRowFingerprints(harness);
			const limited = await firstLimitedPage({ harness });
			expect(limited.attempt).toBeLessThanOrEqual(601);
			expectRetryAfter(limited.response);
			expect(await allSignInRowFingerprints(harness)).toEqual(before);
			expect(await harness.captchaObservations()).toContainEqual({
				kind: 'request-limited',
				requestClass: 'service-page',
				layer: 'outer',
			});
			expect((await harness.authAsBrowser('second-address', '/owner-ready')).status).toBe(200);
		} finally {
			await harness.close();
		}
	},
);

it('people: five failed recovery codes reach native verification and the sixth is limited without another intent or stamp', async () => {
	const harness = await startLocalAuthHarness();
	try {
		await readyForLimitProof(harness);
		await signInConfirmedPeopleBrowser({ harness, email: 'owner@example.invalid' });
		const session = await readCurrentBrowserSession({
			cookie: harness.cookie(),
			database: harness.database,
		});
		function attempt(): Promise<Response> {
			return harness.auth('/api/auth/two-factor/verify-backup-code', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ code: 'never-issued-recovery-code' }),
			});
		}
		const failed = await Promise.all(Array.from({ length: 5 }, () => attempt()));
		expect(failed.map((response) => response.status)).toEqual([401, 401, 401, 401, 401]);
		const beforeLimit = await allSignInRowFingerprints(harness);
		const limited = await attempt();
		expect(limited.status).toBe(429);
		expectRetryAfter(limited);
		expect(await allSignInRowFingerprints(harness)).toEqual(beforeLimit);
		expect(
			await readCurrentBrowserSession({ cookie: harness.cookie(), database: harness.database }),
		).toEqual(session);
		expect(await harness.captchaObservations()).toContainEqual({
			kind: 'request-limited',
			requestClass: 'second-factor-code',
			layer: 'provider',
		});
		const nextWindow = controlledSignInClock.now() + 60_000;
		expect(
			(
				await harness.auth('/__auth-proof/set-clock', {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ milliseconds: nextWindow }),
				})
			).status,
		).toBe(200);
		const recovered = await harness.auth('/api/auth/two-factor/verify-backup-code', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				code: harness.totpAuthenticator.recoveryCode('owner@example.invalid'),
			}),
		});
		expect(recovered.status).toBe(200);
		expect(
			await readCurrentBrowserSession({ cookie: harness.cookie(), database: harness.database }),
		).toMatchObject({
			id: session.id,
			secondFactorAt: nextWindow,
			secondFactorMethod: 'recoveryCode',
		});
	} finally {
		await harness.close();
	}
});

it('people: the token endpoint counts refused clients and limits the thirty-first request without minting or storing anything', async () => {
	const harness = await startLocalAuthHarness();
	try {
		await readyForLimitProof(harness);
		const before = await allSignInRowFingerprints(harness);
		function attempt(): Promise<Response> {
			return harness.auth('/api/auth/oauth2/token', {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					grant_type: 'client_credentials',
					client_id: 'not-an-enrolled-client',
					client_secret: 'test-only-unknown-client-secret',
				}).toString(),
			});
		}
		const failed = await Promise.all(Array.from({ length: 30 }, () => attempt()));
		expect(failed.every((response) => response.status === 400 || response.status === 401)).toBe(
			true,
		);
		const limited = await attempt();
		expect(limited.status).toBe(429);
		expectRetryAfter(limited);
		expect(await allSignInRowFingerprints(harness)).toEqual(before);
		expect(await harness.captchaObservations()).toContainEqual({
			kind: 'request-limited',
			requestClass: 'oauth-token',
			layer: 'provider',
		});
		expect(
			(
				await harness.auth('/__auth-proof/set-clock', {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ milliseconds: controlledSignInClock.now() + 60_000 }),
				})
			).status,
		).toBe(200);
		const nextWindow = await attempt();
		expect(nextWindow.status === 400 || nextWindow.status === 401).toBe(true);
		expect(await allSignInRowFingerprints(harness)).toEqual(before);
	} finally {
		await harness.close();
	}
});

async function signedOutBudgetAssertion(harness: Harness): Promise<{
	readonly body: Readonly<Record<string, unknown>>;
	readonly cookie: string;
}> {
	await signInConfirmedPeopleBrowser({ harness, email: 'owner@example.invalid' });
	await ensureLocalOwnerOrganization(harness);
	const authenticator = await createSoftwarePasskeyAuthenticator();
	expect((await registerBrowserPasskey({ harness, authenticator })).status).toBe(200);
	// A distinct browser has fresh address budgets, but the real registered credential remains.
	harness.useBrowser('signed-out-budget');
	harness.clearBrowserSession();
	const response = await harness.auth('/api/auth/passkey/generate-authenticate-options', {
		headers: {
			'x-captcha-response': harness.turnstile.issueToken({
				action: 'passkey_sign_in',
				hostname: new URL(harness.issuer).hostname,
				verdict: 'accepted',
			}),
		},
	});
	expect(response.status).toBe(200);
	const options = z
		.object({ challenge: z.string(), rpId: z.string() })
		.parse(await response.json());
	return {
		cookie: harness.cookie(),
		body: {
			response: authenticator.authenticationResponse({
				challenge: options.challenge,
				rpId: options.rpId,
				origin: harness.issuer,
				userVerified: true,
			}),
		},
	};
}

it.each(['challenge', 'verify'] as const)(
	'people: the native passkey provider %s budget refuses independently of the outer budget',
	async (route) => {
		const harness = await startLocalAuthHarness();
		try {
			await readyForLimitProof(harness);
			const assertion = route === 'verify' ? await signedOutBudgetAssertion(harness) : null;
			async function providerAttempt(overBudget = false): Promise<{ readonly status: number }> {
				const response = await harness.auth('/__auth-proof/captcha-provider', {
					method: 'POST',
					headers: {
						'content-type': 'application/json',
						'x-captcha-response': harness.turnstile.issueToken({
							action: 'passkey_sign_in',
							hostname: new URL(harness.issuer).hostname,
							verdict: 'accepted',
						}),
					},
					body: JSON.stringify(
						assertion === null
							? { endpoint: 'passkey', mode: 'provider' }
							: {
									endpoint: 'passkey-verification',
									mode: 'provider',
									assertion: overBudget ? assertion.body : {},
								},
					),
				});
				expect(response.status).toBe(200);
				return z
					.object({ response: z.object({ kind: z.literal('response'), status: z.number() }) })
					.parse(await response.json()).response;
			}
			const allowed = await Promise.all(Array.from({ length: 10 }, () => providerAttempt()));
			expect(allowed.map((response) => response.status)).toEqual(
				Array.from({ length: 10 }, () => (route === 'verify' ? 400 : 200)),
			);
			const before = await allSignInRowFingerprints(harness);
			expect((await providerAttempt(true)).status).toBe(429);
			expect(await allSignInRowFingerprints(harness)).toEqual(before);
			expect(
				(await harness.captchaObservations()).filter(
					(observation) => observation.kind === 'request-limited',
				),
			).toEqual([{ kind: 'request-limited', requestClass: 'callback-passkey', layer: 'provider' }]);
			if (assertion !== null) {
				const accepted = await harness.authAsBrowser(
					'second-address',
					'/api/auth/passkey/verify-authentication',
					{
						method: 'POST',
						headers: { 'content-type': 'application/json', cookie: assertion.cookie },
						body: JSON.stringify(assertion.body),
					},
				);
				expect(accepted.status).toBe(200);
			}
		} finally {
			await harness.close();
		}
	},
);

it('people: the outer passkey budget refuses challenge GET and verify POST before challenge or session effects', async () => {
	const harness = await startLocalAuthHarness();
	try {
		await readyForLimitProof(harness);
		await harness.useControlledPasskeyWindow();
		const assertion = await signedOutBudgetAssertion(harness);
		const init = (): RequestInit => ({
			headers: {
				'x-captcha-response': harness.turnstile.issueToken({
					action: 'passkey_sign_in',
					hostname: new URL(harness.issuer).hostname,
					verdict: 'accepted',
				}),
			},
		});
		// Exactly ten public challenge starts exhaust this address's controlled window.
		// The first verify attempt has an unused native per-path budget and a valid assertion.
		const challenges = await Promise.all(
			Array.from({ length: 9 }, () =>
				harness.auth('/api/auth/passkey/generate-authenticate-options', init()),
			),
		);
		for (const response of challenges) expect(response.status).toBe(200);
		const before = await allSignInRowFingerprints(harness);
		const beforeObservations = await harness.captchaObservations();
		const verify = await harness.auth('/api/auth/passkey/verify-authentication', {
			method: 'POST',
			headers: { 'content-type': 'application/json', cookie: assertion.cookie },
			body: JSON.stringify(assertion.body),
		});
		expect(verify.status).toBe(429);
		expectRetryAfter(verify);
		expect(await allSignInRowFingerprints(harness)).toEqual(before);
		expect((await harness.captchaObservations()).slice(beforeObservations.length)).toEqual([
			{ kind: 'request-limited', requestClass: 'callback-passkey', layer: 'outer' },
		]);
		const beforeChallengeObservations = await harness.captchaObservations();
		const limited = await harness.auth('/api/auth/passkey/generate-authenticate-options', init());
		expect(limited.status).toBe(429);
		expectRetryAfter(limited);
		expect(await allSignInRowFingerprints(harness)).toEqual(before);
		expect((await harness.captchaObservations()).slice(beforeChallengeObservations.length)).toEqual(
			[{ kind: 'request-limited', requestClass: 'callback-passkey', layer: 'outer' }],
		);
		expect(
			(
				await harness.authAsBrowser(
					'second-address',
					'/api/auth/passkey/generate-authenticate-options',
					init(),
				)
			).status,
		).toBe(200);
		const accepted = await harness.authAsBrowser(
			'second-address',
			'/api/auth/passkey/verify-authentication',
			{
				method: 'POST',
				headers: { 'content-type': 'application/json', cookie: assertion.cookie },
				body: JSON.stringify(assertion.body),
			},
		);
		expect(accepted.status).toBe(200);
	} finally {
		await harness.close();
	}
});

async function firstOuterPasskeyRefusal(props: {
	readonly harness: Harness;
	readonly attempt?: number;
}): Promise<{ readonly attempt: number; readonly response: Response }> {
	const attempt = props.attempt ?? 1;
	const before = await allSignInRowFingerprints(props.harness);
	const observations = await props.harness.captchaObservations();
	const challenge = attempt % 2 === 1;
	const response = challenge
		? await props.harness.auth('/api/auth/passkey/generate-authenticate-options', {
				headers: {
					'x-captcha-response': props.harness.turnstile.issueToken({
						action: 'passkey_sign_in',
						hostname: new URL(props.harness.issuer).hostname,
						verdict: 'accepted',
					}),
				},
			})
		: await props.harness.auth('/api/auth/passkey/verify-authentication', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: '{}',
			});
	if (response.status === 429) {
		expect(await allSignInRowFingerprints(props.harness)).toEqual(before);
		expect((await props.harness.captchaObservations()).slice(observations.length)).toEqual([
			{ kind: 'request-limited', requestClass: 'callback-passkey', layer: 'outer' },
		]);
		return { attempt, response };
	}
	expect(response.status).toBe(challenge ? 200 : 400);
	if (attempt >= 21) throw new Error('Real passkey binding did not refuse within one rollover');
	return firstOuterPasskeyRefusal({ harness: props.harness, attempt: attempt + 1 });
}

it('people: the real outer passkey binding refuses within 21 mixed-path starts and a second address still passes', async () => {
	const harness = await startLocalAuthHarness();
	try {
		await readyForLimitProof(harness);
		const limited = await firstOuterPasskeyRefusal({ harness });
		expect(limited.attempt).toBeLessThanOrEqual(21);
		expectRetryAfter(limited.response);
		expect(
			(
				await harness.authAsBrowser(
					'second-address',
					'/api/auth/passkey/generate-authenticate-options',
					{
						headers: {
							'x-captcha-response': harness.turnstile.issueToken({
								action: 'passkey_sign_in',
								hostname: new URL(harness.issuer).hostname,
								verdict: 'accepted',
							}),
						},
					},
				)
			).status,
		).toBe(200);
	} finally {
		await harness.close();
	}
});

const passkeyListPath = '/api/auth/passkey/list-user-passkeys';

function passkeyChallengeStart(harness: Harness): Promise<Response> {
	return harness.auth('/api/auth/passkey/generate-authenticate-options', {
		headers: {
			'x-captcha-response': harness.turnstile.issueToken({
				action: 'passkey_sign_in',
				hostname: new URL(harness.issuer).hostname,
				verdict: 'accepted',
			}),
		},
	});
}

/** A signed-in person with one registered passkey, in a fresh controlled window for this address. */
async function signedInWithPasskeyInFreshWindow(harness: Harness): Promise<void> {
	await readyForLimitProof(harness);
	await signInConfirmedPeopleBrowser({ harness, email: 'owner@example.invalid' });
	await ensureLocalOwnerOrganization(harness);
	expect(
		(
			await registerBrowserPasskey({
				harness,
				authenticator: await createSoftwarePasskeyAuthenticator(),
			})
		).status,
	).toBe(200);
	await harness.useControlledPasskeyWindow();
	const nextWindow = controlledSignInClock.now() + 60_000;
	expect(
		(
			await harness.auth('/__auth-proof/set-clock', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ milliseconds: nextWindow }),
			})
		).status,
	).toBe(200);
}

it('people: eleven passkey list reads in one window all succeed and leave the sign-in attempts budget untouched', async () => {
	const harness = await startLocalAuthHarness();
	try {
		await signedInWithPasskeyInFreshWindow(harness);
		for (let read = 1; read <= 11; read += 1) {
			const response = await harness.auth(passkeyListPath);
			expect(response.status, `list read ${read}`).toBe(200);
		}
		// The same address's next sign-in attempt is still admitted by the shared outer budget.
		expect((await passkeyChallengeStart(harness)).status).toBe(200);
		expect(
			(await harness.captchaObservations()).filter(
				(observation) => observation.kind === 'request-limited',
			),
		).toEqual([]);
	} finally {
		await harness.close();
	}
});

it('people: control: eleven passkey ceremony starts in one window still give 429 with retry-after', async () => {
	const harness = await startLocalAuthHarness();
	try {
		await signedInWithPasskeyInFreshWindow(harness);
		const started: number[] = [];
		for (let attempt = 1; attempt <= 10; attempt += 1)
			started.push((await passkeyChallengeStart(harness)).status);
		expect(started).toEqual(Array.from({ length: 10 }, () => 200));
		const before = await harness.captchaObservations();
		const limited = await passkeyChallengeStart(harness);
		expect(limited.status).toBe(429);
		expectRetryAfter(limited);
		// The outer budget refused: its body and observation differ from the native provider's refusal.
		expect(await limited.json()).toEqual({ error: 'rate-limited' });
		expect((await harness.captchaObservations()).slice(before.length)).toEqual([
			{ kind: 'request-limited', requestClass: 'callback-passkey', layer: 'outer' },
		]);
	} finally {
		await harness.close();
	}
});
