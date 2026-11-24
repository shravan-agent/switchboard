import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { expect, it } from 'vitest';

import { launchProofBrowser } from '#sign-in-test-support/test-fixtures/playwright-browser';
import { awaitPasskeySectionTerminalState } from '#sign-in-test-support/test-fixtures/sign-in-navigation-setup';

const skeleton = '<div data-slot="skeleton" aria-hidden="true"></div>';
const stuckSections = [
	['no terminal marker yet', skeleton],
	['a terminal marker with the skeleton still shown', `${skeleton}<div role="listitem">key</div>`],
] as const;

it.each(stuckSections)(
	'the Me passkey terminal-state wait stays pending while %s, and rejects when the scenario aborts',
	async (_name, sectionHtml): Promise<void> => {
		const scenario = new AbortController();
		const proof = await launchProofBrowser({
			evidence: await mkdtemp(path.join(tmpdir(), '2026-11-passkey-wait-abort-')),
			scenarioSignal: scenario.signal,
		});
		const browser = proof.page.context().browser();
		// A scenario signal turns off the launcher's own close at test end, and the abort closes only the
		// page, so this test closes the whole browser and context itself, whichever way it ends.
		try {
			await proof.page.setContent(
				`<main><div role="region" aria-label="Passkey list">${sectionHtml}</div></main>`,
			);
			const wait = awaitPasskeySectionTerminalState(proof.page);
			let state = 'pending';
			const outcome = wait.then(
				(): void => {
					state = 'settled';
				},
				(): void => {
					state = 'rejected';
				},
			);
			// The page's commands are ordered: each round trip returns after the earlier command's reply, so
			// after three the wait's two steps (marker, then skeleton gone) have each had theirs.
			for (let roundTrip = 0; roundTrip < 3; roundTrip += 1) await proof.page.evaluate('0');
			expect(state).toBe('pending');
			scenario.abort();
			await outcome;
			expect(state).toBe('rejected');
		} finally {
			scenario.abort();
			await proof.close();
		}
		expect(browser?.isConnected()).toBe(false);
	},
);
