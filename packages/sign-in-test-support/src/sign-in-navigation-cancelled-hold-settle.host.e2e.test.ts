import { expect, it } from 'vitest';

import { useControlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-node-test-clock';
import { runProofBrowserScenario } from '#sign-in-test-support/test-fixtures/playwright-browser';
import { withNavigationBrowser } from '#sign-in-test-support/test-fixtures/sign-in-navigation-browser';
import { observeCancelledHoldProof } from '#sign-in-test-support/test-fixtures/sign-in-navigation-layout';

useControlledSignInClock();

const hosts = ['node', 'cloudflare'] as const;
const sessionPath = '/api/auth/get-session';

it.each(hosts)(
	'sign-in navigation N8 cancelled-hold navigation is not over while its Me document session request is held, and returns once it is released on %s',
	async (host): Promise<void> => {
		await runProofBrowserScenario((signal) =>
			withNavigationBrowser({
				host,
				signal,
				exercise: async (browser): Promise<void> => {
					// The next session request the proof server sees is the Me island's own: nothing else
					// is open on this page. Holding its response keeps that request open.
					const sessionHold = browser.harness.httpResponseHolds.armNextGetResponse(
						sessionPath,
						browser.signal,
					);
					const blockedOnHeldSession = Promise.withResolvers<void>();
					void blockedOnHeldSession.promise.catch(() => undefined);
					try {
						const tail = observeCancelledHoldProof(browser, {
							onBlocked: (block): void => {
								if (block.openPaths.includes(sessionPath)) blockedOnHeldSession.resolve();
							},
						});
						void tail.catch(() => undefined);
						// Release only on the explicit observation that the returned journey's wait is blocked on
						// the held request. A journey that returns without waiting never makes it, so it loses
						// this race whatever order the browser reports its events in.
						const first = await Promise.race([
							Promise.all([sessionHold.entered, blockedOnHeldSession.promise]).then(
								() => 'blocked-on-held-session' as const,
							),
							tail.then(() => 'returned-without-waiting' as const),
						]);
						expect(first).toBe('blocked-on-held-session');
						sessionHold.release();
						await tail;
					} finally {
						sessionHold.release();
					}
				},
			}),
		);
	},
);
