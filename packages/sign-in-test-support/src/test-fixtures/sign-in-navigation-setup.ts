import { fileURLToPath } from 'node:url';

import { passkey, twoFactor } from '@agent-collaboration/sign-in-core';
import { eq } from 'drizzle-orm';
import { expect } from 'vitest';
import { z } from 'zod';

import { loginThroughNativeOwnerCli } from '#sign-in-test-support/test-fixtures/native-cli-proof';
import { installOrganizationBrowserCookie } from '#sign-in-test-support/test-fixtures/organization-browser-transport';
import { signInPeopleBrowser } from '#sign-in-test-support/test-fixtures/people-browser-login';
import {
	navigationOwnerEmail,
	runNavigationSteps,
	visitNavigation,
	type NavigationBrowser,
} from '#sign-in-test-support/test-fixtures/sign-in-navigation-browser';

export async function observeNavigationReadiness(browser: NavigationBrowser): Promise<void> {
	const { harness, proof } = browser;
	await runNavigationSteps(['/me', '/people'], async (route): Promise<void> => {
		const signedOut = await harness.auth(route, { headers: { cookie: '' } });
		expect(signedOut.status).toBe(303);
		expect(signedOut.headers.get('location')).toBe('/sign-in');
	});
	const pending = await signInPeopleBrowser({ harness, email: navigationOwnerEmail });
	expect(pending).toBe(browser.ownerId);
	await runNavigationSteps(['/me', '/people'], async (route): Promise<void> => {
		const response = await harness.auth(`${route}?stage=setup%20pending`);
		expect(response.status).toBe(303);
		expect(response.headers.get('location')).toBe('/owner-ready?stage=setup%20pending');
	});
	await installOrganizationBrowserCookie({
		page: proof,
		issuer: harness.issuer,
		cookie: harness.cookie(),
	});
	await proof.navigate(`${harness.issuer}/owner-ready`);
	await proof.page.getByRole('heading', { name: 'Confirm your changes' }).waitFor();
	expect(await proof.page.getByRole('link', { name: 'Go to Me' }).count()).toBe(0);
	await harness.totpAuthenticator.ensureConfirmed(navigationOwnerEmail, harness.auth);
	await installOrganizationBrowserCookie({
		page: proof,
		issuer: harness.issuer,
		cookie: harness.cookie(),
	});
	await proof.navigate(`${harness.issuer}/owner-ready`);
	await proof.page.getByRole('link', { name: 'Go to Me' }).click();
	await proof.page.getByRole('heading', { name: 'Me', exact: true }).waitFor();
}

export async function observeNavigationCliContinuation(browser: NavigationBrowser): Promise<void> {
	const { harness, proof, ownerCookie, signal } = browser;
	await visitNavigation(browser, '/me');
	let deliveredCallback = false;
	await loginThroughNativeOwnerCli({
		target: harness.target,
		repositoryRoot: fileURLToPath(new URL('../../../../', import.meta.url)),
		signal,
		cancelBrowser: () => proof.cancel('Navigation continuation did not finish'),
		async browser(initialUrl): Promise<readonly string[]> {
			const opened = new URL(initialUrl);
			const authorization = z.url().parse(opened.searchParams.get('authorize'));
			const authorize = new URL(authorization);
			const routes = [
				['/me', opened.search],
				['/people', authorize.search],
			] as const;
			await runNavigationSteps(routes, async ([route, exactQuery]): Promise<void> => {
				const response = await harness.auth(`${route}${exactQuery}`, {
					headers: { cookie: ownerCookie },
				});
				expect(response.status).toBe(303);
				// Report equality without including the opaque authorization challenge in a test failure.
				expect(response.headers.get('location') === `/owner-ready${exactQuery}`).toBe(true);
			});
			await proof.navigate(`${harness.issuer}/people${authorize.search}`);
			expect(new URL(proof.page.url()).pathname).toBe('/owner-ready');
			expect(await proof.page.getByRole('link', { name: 'Go to Me' }).count()).toBe(0);
			const callback = proof.page.waitForRequest((request): boolean => {
				const url = new URL(request.url());
				return (
					url.origin !== harness.issuer &&
					url.pathname ===
						new URL(authorize.searchParams.get('redirect_uri') ?? 'invalid:').pathname &&
					url.searchParams.has('code')
				);
			});
			void callback.catch(() => undefined);
			await proof.page.getByRole('button', { name: 'Continue to management CLI' }).click();
			const result = new URL((await callback).url());
			expect(result.searchParams.get('state') === authorize.searchParams.get('state')).toBe(true);
			deliveredCallback = true;
			return [result.searchParams.get('code') ?? ''];
		},
	});
	expect(deliveredCallback).toBe(true);
}

export async function observeNavigationFactors(browser: NavigationBrowser): Promise<void> {
	const { harness, proof, ownerId } = browser;
	const rows = async (): Promise<(typeof twoFactor.$inferSelect)[]> =>
		harness.database.select().from(twoFactor).where(eq(twoFactor.userId, ownerId));
	const original = (await rows())[0];
	if (original === undefined) throw new Error('Original app missing');
	await visitNavigation(browser, '/me');
	const recovery = await proof.responseTo('/api/auth/two-factor/generate-backup-codes', () =>
		proof.page.getByRole('button', { name: 'Replace recovery codes' }).click(),
	);
	expect(recovery.response.status).toBe(200);
	await proof.page.getByRole('heading', { name: 'New recovery codes' }).waitFor();
	expect((await rows())[0]?.backupCodes !== original.backupCodes).toBe(true);
	await proof.afterNavigation('/owner-ready', () =>
		proof.page.getByRole('button', { name: "I've saved my recovery codes" }).click(),
	);
	await proof.page.getByRole('link', { name: 'Go to Me' }).click();
	await proof.page.getByRole('heading', { name: 'Me', exact: true }).waitFor();

	await proof.addVirtualAuthenticator();
	const registration = await proof.responseTo('/api/auth/passkey/verify-registration', () =>
		proof.page.getByRole('button', { name: 'Add passkey' }).click(),
	);
	expect(registration.response.status).toBe(200);
	expect(
		await harness.database
			.select({ id: passkey.id })
			.from(passkey)
			.where(eq(passkey.userId, ownerId)),
	).toHaveLength(1);
	await proof.afterNavigation('/owner-ready', () =>
		proof.page.getByRole('button', { name: 'Remove app before replacing it' }).click(),
	);
	expect(await rows()).toEqual([]);
	await proof.page.getByRole('link', { name: 'Go to Me' }).click();
	const enrollment = await proof.responseTo('/api/auth/two-factor/enable', () =>
		proof.page.getByRole('button', { name: 'Set up replacement app' }).click(),
	);
	expect(enrollment.response.status).toBe(200);
	const totpURI = await proof.page.locator('#totp-uri').textContent();
	const backupCodes = await proof.page.locator('ul code').allTextContents();
	harness.totpAuthenticator.observeEnrollment(navigationOwnerEmail, {
		method: 'totp',
		totpURI,
		backupCodes,
	});
	await proof.page
		.getByRole('textbox', { name: 'App code' })
		.fill(await harness.totpAuthenticator.currentCode(navigationOwnerEmail));
	await proof.afterNavigation('/owner-ready', () =>
		proof.page.getByRole('button', { name: 'Confirm app', exact: true }).click(),
	);
	expect((await rows())[0]?.verified).toBe(true);
	await proof.page.getByRole('link', { name: 'Go to Me' }).click();
	await proof.page.getByRole('heading', { name: 'Me', exact: true }).waitFor();
}
