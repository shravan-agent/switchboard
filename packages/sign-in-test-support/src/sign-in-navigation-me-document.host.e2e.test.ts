import { expect, it } from 'vitest';

import type { AuthProofHttpResponseHold } from '#sign-in-test-support/test-fixtures/auth-proof-http-response-holds';
import { useControlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-node-test-clock';
import { MePageWaitError } from '#sign-in-test-support/test-fixtures/me-page-request-tracker';
import { runProofBrowserScenario } from '#sign-in-test-support/test-fixtures/playwright-browser';
import { withNavigationBrowser } from '#sign-in-test-support/test-fixtures/sign-in-navigation-browser';
import { holdBrowserReply } from '#sign-in-test-support/test-fixtures/sign-in-navigation-layout';
import { awaitMePageRequestsAfter } from '#sign-in-test-support/test-fixtures/sign-in-navigation-setup';

useControlledSignInClock();

const hosts = ['node', 'cloudflare'] as const;
const listPath = '/api/auth/passkey/list-user-passkeys';
const pageIsland = /\/assets\/sign-in-pages-[^/]+\.js$/u;

it.each(hosts)(
	'sign-in navigation Me wait follows the second visit, not the first visit document that is also at /me, on %s',
	async (host): Promise<void> => {
		await runProofBrowserScenario((signal) =>
			withNavigationBrowser({
				host,
				signal,
				exercise: async (browser): Promise<void> => {
					const { harness, proof } = browser;
					// Document A is committed at /me, with its island script held so that it has requested
					// nothing yet.
					const firstDocumentIsland = await holdBrowserReply(browser, pageIsland);
					try {
						const firstList = harness.httpResponseHolds.armNextGetResponse(
							listPath,
							browser.signal,
						);
						await proof.page.goto(`${harness.issuer}/me?document=first`, { waitUntil: 'commit' });
						expect(await firstDocumentIsland.status).toBe(200);
						const secondList = Promise.withResolvers<AuthProofHttpResponseHold>();
						const blockedOnSecondList = Promise.withResolvers<void>();
						void secondList.promise.catch(() => undefined);
						void blockedOnSecondList.promise.catch(() => undefined);
						// The wait is installed while A is still the page. Releasing A's script makes A request its
						// session and list, both while the wait is installed and A's pathname is /me.
						const waiting = awaitMePageRequestsAfter(
							browser,
							async (): Promise<void> => {
								firstDocumentIsland.release();
								// A's list is open in the proof server; nothing of document B exists yet.
								await firstList.entered;
								secondList.resolve(
									harness.httpResponseHolds.armNextGetResponse(listPath, browser.signal),
								);
								await proof.navigate(`${harness.issuer}/me?document=second`);
							},
							{
								onBlocked: (block): void => {
									if (block.openPaths.includes(listPath)) blockedOnSecondList.resolve();
								},
							},
						);
						void waiting.catch(() => undefined);
						// B commits and its list is held. A's requests, which end when B commits, must not stand in
						// for B's: a wait that counts them returns here without ever observing B's open list.
						const first = await Promise.race([
							secondList.promise
								.then((held) => Promise.all([held.entered, blockedOnSecondList.promise]))
								.then(() => 'blocked-on-second-document-list' as const),
							waiting.then(() => 'returned-on-first-document-requests' as const),
						]);
						expect(first).toBe('blocked-on-second-document-list');
						(await secondList.promise).release();
						await waiting;
					} finally {
						await firstDocumentIsland.close();
					}
				},
			}),
		);
	},
);

it.each(hosts)(
	'sign-in navigation Me wait fails as mountFailed, and does not wait, when the island script cannot load on %s',
	async (host): Promise<void> => {
		await runProofBrowserScenario((signal) =>
			withNavigationBrowser({
				host,
				signal,
				exercise: async (browser): Promise<void> => {
					const { harness, proof } = browser;
					await proof.page.route(pageIsland, (route) => route.abort());
					try {
						const failure = await awaitMePageRequestsAfter(browser, async (): Promise<void> => {
							await proof.navigate(`${harness.issuer}/me`);
						}).then(
							() => null,
							(error: unknown) => error,
						);
						expect(failure).toBeInstanceOf(MePageWaitError);
						expect(failure).toMatchObject({ failure: { kind: 'mountFailed' } });
					} finally {
						await proof.page.unroute(pageIsland);
					}
				},
			}),
		);
	},
);
