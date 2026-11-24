import { fileURLToPath } from 'node:url';

import { member, passkey, session, twoFactor, user } from '@agent-collaboration/sign-in-core';
import { and, eq } from 'drizzle-orm';
import type { Page } from 'playwright';
import { expect } from 'vitest';
import { z } from 'zod';

import { controlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-sign-in-clock';
import { readCurrentBrowserSession } from '#sign-in-test-support/test-fixtures/current-browser-session';
import { observeMePageDocument } from '#sign-in-test-support/test-fixtures/me-page-document-observer';
import type {
	MePageRequestOutcome,
	MePageWaitBlock,
} from '#sign-in-test-support/test-fixtures/me-page-request-tracker';
import { loginThroughNativeOwnerCli } from '#sign-in-test-support/test-fixtures/native-cli-proof';
import {
	organizationBrowserCookie,
	installOrganizationBrowserCookie,
} from '#sign-in-test-support/test-fixtures/organization-browser-transport';
import { signInPeopleBrowser } from '#sign-in-test-support/test-fixtures/people-browser-login';
import {
	navigationOwnerEmail,
	runNavigationSteps,
	visitNavigation,
	type FreshNavigationBrowser,
	type NavigationBrowser,
} from '#sign-in-test-support/test-fixtures/sign-in-navigation-browser';

export async function observeFreshOwnerEnrollment(browser: FreshNavigationBrowser): Promise<void> {
	const { harness, proof } = browser;
	const ownerId = await signInPeopleBrowser({ harness, email: navigationOwnerEmail });
	const initialCookie = harness.cookie();
	expect(
		await harness.database
			.select({ id: twoFactor.id })
			.from(twoFactor)
			.where(eq(twoFactor.userId, ownerId)),
	).toEqual([]);
	expect(
		await harness.database.select({ id: member.id }).from(member).where(eq(member.userId, ownerId)),
	).toEqual([]);
	async function expectSetupRedirects(cookie: string): Promise<void> {
		await runNavigationSteps(['/me', '/people'], async (route): Promise<void> => {
			const response = await harness.auth(route, { headers: { cookie } });
			expect(response.status).toBe(303);
			expect(response.headers.get('location')).toBe('/owner-ready');
		});
	}
	await expectSetupRedirects(initialCookie);
	await installOrganizationBrowserCookie({
		page: proof,
		issuer: harness.issuer,
		cookie: initialCookie,
	});
	await proof.navigate(`${harness.issuer}/owner-ready`);
	const start = proof.page
		.locator('[data-sign-in-island-mounted]')
		.getByRole('button', { name: 'Set up authenticator app' });
	await start.waitFor();
	expect(await proof.page.getByRole('link', { name: 'Go to Me' }).count()).toBe(0);
	const enrollment = await proof.responseTo('/api/auth/two-factor/enable', () => start.click());
	expect(enrollment.response.status).toBe(200);
	harness.totpAuthenticator.observeEnrollment(
		navigationOwnerEmail,
		await proof.readBody(enrollment),
	);
	const confirmation = await proof.responseTo(
		'/api/auth/two-factor/verify-totp',
		async (): Promise<void> =>
			proof.enter(
				'input[autocomplete="one-time-code"]',
				await harness.totpAuthenticator.currentCode(navigationOwnerEmail),
			),
	);
	expect(confirmation.response.status).toBe(200);
	await proof.afterNavigation('/owner-ready', () =>
		proof.page.getByRole('button', { name: "I've saved my recovery codes" }).click(),
	);
	const enrolledCookie = await organizationBrowserCookie(proof, harness.issuer);
	await expectSetupRedirects(enrolledCookie);
	expect(await proof.page.getByRole('link', { name: 'Go to Me' }).count()).toBe(0);
	await proof.page.locator('#organization-name').fill('First shell organization');
	await proof.afterNavigation('/owner-ready', () =>
		proof.page.getByRole('button', { name: 'Create organization' }).click(),
	);
	await proof.page.getByRole('link', { name: 'Go to Me' }).click();
	await proof.page.getByRole('heading', { name: 'Me', exact: true }).waitFor();
	const readyCookie = await organizationBrowserCookie(proof, harness.issuer);
	const ready = await readCurrentBrowserSession({
		cookie: readyCookie,
		database: harness.database,
	});
	expect(ready.personId).toBe(ownerId);
	expect(
		await harness.database
			.select({ role: member.role })
			.from(member)
			.where(eq(member.userId, ownerId)),
	).toEqual([{ role: 'owner' }]);

	// Remove only enrollment. A recent session confirmation and the exact
	// selected membership survive, so either of those still passes on its own.
	async function readSelectedSession(): Promise<unknown> {
		return (
			await harness.database
				.select({
					organizationId: session.activeOrganizationId,
					confirmedAt: session.secondFactorAt,
					method: session.secondFactorMethod,
				})
				.from(session)
				.where(eq(session.id, ready.id))
		)[0];
	}
	const selected = z
		.object({
			organizationId: z.uuidv7(),
			confirmedAt: z.number().int(),
			method: z.string().min(1),
		})
		.parse(await readSelectedSession());
	expect(selected.confirmedAt).toBe(controlledSignInClock.now());
	expect(
		await harness.database
			.select({ role: member.role })
			.from(member)
			.where(and(eq(member.userId, ownerId), eq(member.organizationId, selected.organizationId))),
	).toEqual([{ role: 'owner' }]);
	expect(
		await harness.database
			.select({ id: passkey.id })
			.from(passkey)
			.where(eq(passkey.userId, ownerId)),
	).toEqual([]);

	await harness.database.delete(twoFactor).where(eq(twoFactor.userId, ownerId));
	await harness.database
		.update(user)
		.set({ secondFactorSetAt: null, twoFactorEnabled: false })
		.where(eq(user.id, ownerId));
	expect(await readSelectedSession()).toEqual(selected);
	expect(
		await harness.database
			.select({ id: twoFactor.id })
			.from(twoFactor)
			.where(eq(twoFactor.userId, ownerId)),
	).toEqual([]);
	expect(
		(
			await harness.database
				.select({ enrolledAt: user.secondFactorSetAt, enabled: user.twoFactorEnabled })
				.from(user)
				.where(eq(user.id, ownerId))
		)[0],
	).toEqual({ enrolledAt: null, enabled: false });
	await expectSetupRedirects(readyCookie);
}

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
	await followReadyLinkToMe(browser);
}

/** The requests the Me page's island must see end before the page is at rest. */
const mePageTerminalRequestPaths = [
	'/api/auth/passkey/list-user-passkeys',
	'/api/auth/get-session',
] as const;

async function rejectWhenAborted<TValue>(
	wait: Promise<TValue>,
	signal: AbortSignal,
): Promise<TValue> {
	void wait.catch(() => undefined);
	signal.throwIfAborted();
	const aborted = Promise.withResolvers<never>();
	const abort = (): void => aborted.reject(signal.reason);
	signal.addEventListener('abort', abort, { once: true });
	try {
		return await Promise.race([wait, aborted.promise]);
	} finally {
		signal.removeEventListener('abort', abort);
	}
}

/**
 * Runs `reachMe`, which must end with the browser on the Me page, then waits for the requests
 * that page's island issues to end. The Me heading is server-rendered, so it says nothing about
 * them, and closing the harness rejects any request still open, so a journey must not go on or
 * return before they have. Requests are bound to the committed main-frame document that issued
 * them (its loader id), not to a pathname, so a request of the document left behind never counts.
 * The wait fails, with a `MePageWaitError`, on a lost page, a document that cannot mount, or another
 * document committing first; it has no timeout and no grace period. Known gap: a named request
 * that the document never issues is not an error here, because the page publishes no event that
 * says startup has issued every fetch it will issue (and adding one is a product change). That
 * case surfaces only as the suite watchdog, never as a false pass or a false failure.
 * Once the requests are over, the passkey section must also be at rest (see
 * `awaitPasskeySectionTerminalState`). `onBlocked` observes what a returned journey is still waiting for.
 */
export async function awaitMePageRequestsAfter(
	browser: NavigationBrowser,
	reachMe: () => Promise<void>,
	options: { readonly onBlocked?: (block: MePageWaitBlock) => void } = {},
): Promise<ReadonlyMap<string, MePageRequestOutcome>> {
	const { harness, proof, signal } = browser;
	const observation = await observeMePageDocument({
		proof,
		origin: new URL(harness.issuer).origin,
		paths: mePageTerminalRequestPaths,
		...(options.onBlocked === undefined ? {} : { onBlocked: options.onBlocked }),
	});
	try {
		// A causal failure of the wait ends the journey too, so a page that cannot mount does not
		// leave it waiting for an element that will never appear.
		await Promise.race([
			reachMe(),
			observation.tracker.settled.then(() => new Promise<never>(() => {})),
		]);
		observation.tracker.observeJourneyReturned();
		// The requests being over, finished or failed after their headers, is the outcome this wait owns.
		// N4 makes more than the 10 passkey requests a minute that request class admits, so a late
		// visit's list is a 429; since the Retry alert (#16) that is a terminal UI state too. The section
		// must then be at rest: a terminal marker shown and the loading skeleton gone.
		const outcomes = await rejectWhenAborted(observation.tracker.settled, signal);
		await rejectWhenAborted(awaitPasskeySectionTerminalState(proof.page), signal);
		return outcomes;
	} finally {
		await observation.stop();
	}
}

/**
 * The Me passkey section is at rest once it shows a real terminal state (the list rows, "No passkeys
 * yet.", or the error alert with Retry) and the loading skeleton is gone. A page stuck on the
 * skeleton, or showing it beside the alert or the rows, fails this wait instead of passing on the
 * requests alone.
 * Neither wait has a clock: each ends on the DOM event, or rejects when the page closes, which the
 * scenario abort does.
 */
export async function awaitPasskeySectionTerminalState(page: Page): Promise<void> {
	const section = page.getByRole('region', { name: 'Passkey list' });
	await section
		.getByRole('listitem')
		.or(section.getByText('No passkeys yet.', { exact: true }))
		.or(section.getByRole('alert').getByRole('button', { name: 'Retry', exact: true }))
		.first()
		.waitFor({ timeout: 0 });
	await section
		.locator('[data-slot="skeleton"]')
		.first()
		.waitFor({ state: 'detached', timeout: 0 });
}

export function followReadyLinkToMe(
	browser: NavigationBrowser,
): Promise<ReadonlyMap<string, MePageRequestOutcome>> {
	const { proof } = browser;
	return awaitMePageRequestsAfter(browser, async (): Promise<void> => {
		await proof.page.getByRole('link', { name: 'Go to Me' }).click();
		await proof.page.getByRole('heading', { name: 'Me', exact: true }).waitFor();
	});
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
			const routes = (['/me', '/people'] as const).flatMap((route) =>
				[opened.search, authorize.search].map((query) => [route, query] as const),
			);
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
	await followReadyLinkToMe(browser);

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
	await followReadyLinkToMe(browser);
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
	await followReadyLinkToMe(browser);
}
