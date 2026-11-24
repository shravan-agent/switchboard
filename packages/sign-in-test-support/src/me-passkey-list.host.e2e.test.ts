import type { Locator, Route } from 'playwright';
import { expect, it } from 'vitest';

import { useControlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-node-test-clock';
import { registerBrowserPasskey } from '#sign-in-test-support/test-fixtures/passkey-browser-ceremonies';
import { runProofBrowserScenario } from '#sign-in-test-support/test-fixtures/playwright-browser';
import {
	runNavigationSteps,
	visitNavigation,
	withNavigationBrowser,
	type NavigationBrowser,
} from '#sign-in-test-support/test-fixtures/sign-in-navigation-browser';
import { createSoftwarePasskeyAuthenticator } from '#sign-in-test-support/test-fixtures/software-passkey-authenticator';

useControlledSignInClock();

const passkeyListPath = '/api/auth/passkey/list-user-passkeys';
const matchesPasskeyList = (url: URL): boolean => url.pathname === passkeyListPath;

async function recoverWithRetry(props: {
	readonly browser: NavigationBrowser;
	readonly passkeyList: Locator;
}): Promise<void> {
	const { proof } = props.browser;
	const { passkeyList } = props;
	const alert = passkeyList.getByRole('alert');
	const retry = alert.getByRole('button', { name: 'Retry', exact: true });
	const releaseRetry = Promise.withResolvers<void>();
	async function holdRetry(route: Route): Promise<void> {
		await releaseRetry.promise;
		await route.continue();
	}
	await proof.page.route(matchesPasskeyList, holdRetry);
	try {
		const recovered = await proof.responseTo(passkeyListPath, async (): Promise<void> => {
			await retry.focus();
			expect(await retry.evaluate((button) => button === document.activeElement)).toBe(true);
			const requested = proof.page.waitForRequest((request) =>
				matchesPasskeyList(new URL(request.url())),
			);
			await proof.page.keyboard.press('Enter');
			await requested;
			expect(await passkeyList.evaluate((region) => region === document.activeElement)).toBe(true);
			const loading = passkeyList.getByRole('status').filter({ hasText: 'Loading passkeys…' });
			await loading.waitFor({ state: 'attached' });
			releaseRetry.resolve();
		});
		expect(recovered.response.status).toBe(200);
		const passkey = passkeyList
			.getByRole('listitem')
			.getByText('Controlled test passkey', { exact: true });
		await passkey.waitFor();
		expect(await alert.count()).toBe(0);
		expect(await passkeyList.getByRole('status').textContent()).toBe('');
		expect(await passkeyList.evaluate((region) => region === document.activeElement)).toBe(true);
	} finally {
		releaseRetry.resolve();
		await proof.page.unrouteAll({ behavior: 'wait' });
	}
}

async function observeListRecovery(browser: NavigationBrowser): Promise<void> {
	const { harness, proof } = browser;
	const registration = await registerBrowserPasskey({
		harness,
		authenticator: await createSoftwarePasskeyAuthenticator(),
	});
	expect(registration.status).toBe(200);
	// Reloading Me can no longer exhaust the sign-in attempts quota, so this test injects the refusal
	// instead of driving the host to it. Reads can still be limited by the `other` class; the real
	// limiter's 429 is witnessed in people-request-limits.host.e2e.test.ts. What this proves is Retry.
	const repeatedRequest = Promise.withResolvers<void>();
	let refused = false;
	async function refuseFirstListRequest(route: Route): Promise<void> {
		if (refused) {
			repeatedRequest.resolve();
			await route.continue();
			return;
		}
		refused = true;
		await route.fulfill({
			status: 429,
			headers: { 'retry-after': '1' },
			json: { message: 'Too many requests' },
		});
	}
	await proof.page.route(matchesPasskeyList, refuseFirstListRequest);
	try {
		const limited = await proof.responseTo(passkeyListPath, () => visitNavigation(browser, '/me'));
		expect(limited.response.status).toBe(429);
		const passkeyList = proof.page.getByRole('region', { name: 'Passkey list' });
		const alert = passkeyList.getByRole('alert');
		const errorOrAutomaticRequest = await Promise.race([
			alert.waitFor().then(() => 'error displayed'),
			repeatedRequest.promise.then(() => 'list requested again before Retry'),
		]);
		expect(errorOrAutomaticRequest).toBe('error displayed');
		expect(await passkeyList.locator('[data-slot="skeleton"]').count()).toBe(0);
		expect(await alert.textContent()).toContain('Passkeys are unavailable.');
		await recoverWithRetry({ browser, passkeyList });
	} finally {
		await proof.page.unrouteAll({ behavior: 'wait' });
	}
}

it.each(['node', 'cloudflare'] as const)(
	'Me retries a rate-limited passkey list on %s',
	async (host) => {
		await runProofBrowserScenario((signal) =>
			withNavigationBrowser({ host, signal, exercise: observeListRecovery }),
		);
	},
);

async function observeUnavailableList(browser: NavigationBrowser): Promise<void> {
	const { proof } = browser;
	const passkeyList = proof.page.getByRole('region', { name: 'Passkey list' });
	const alert = passkeyList.getByRole('alert');
	const retry = alert.getByRole('button', { name: 'Retry', exact: true });
	await runNavigationSteps(['http-503', 'connection-failed'] as const, async (failure) => {
		const repeatedRequest = Promise.withResolvers<void>();
		let refused = false;
		async function refuseFirstListRequest(route: Route): Promise<void> {
			if (refused) {
				repeatedRequest.resolve();
				await route.continue();
				return;
			}
			refused = true;
			if (failure === 'http-503') {
				await route.fulfill({ status: 503, json: { message: 'Service unavailable' } });
			} else {
				await route.abort('connectionfailed');
			}
		}
		await proof.page.route(matchesPasskeyList, refuseFirstListRequest);
		try {
			await visitNavigation(browser, '/me');
			const errorOrAutomaticRequest = await Promise.race([
				alert.waitFor().then(() => 'error displayed'),
				repeatedRequest.promise.then(() => 'list requested again before Retry'),
			]);
			expect(errorOrAutomaticRequest, failure).toBe('error displayed');
			expect(refused, failure).toBe(true);
			expect(await passkeyList.locator('[data-slot="skeleton"]').count(), failure).toBe(0);
			expect(await alert.textContent(), failure).toContain('Passkeys are unavailable.');
			const recovered = await proof.responseTo(passkeyListPath, () => retry.click());
			expect(recovered.response.status, failure).toBe(200);
			await passkeyList.getByText('No passkeys yet.', { exact: true }).waitFor();
			expect(await alert.count(), failure).toBe(0);
		} finally {
			await proof.page.unrouteAll({ behavior: 'wait' });
		}
	});
}

it.each(['node', 'cloudflare'] as const)('Me retries a failed passkey list on %s', async (host) => {
	await runProofBrowserScenario((signal) =>
		withNavigationBrowser({ host, signal, exercise: observeUnavailableList }),
	);
});
