import { it } from 'vitest';

import { useControlledSignInClock } from '#sign-in-test-support/test-fixtures/controlled-node-test-clock';
import { runProofBrowserScenario } from '#sign-in-test-support/test-fixtures/playwright-browser';
import {
	withNavigationBrowser,
	type NavigationBrowser,
} from '#sign-in-test-support/test-fixtures/sign-in-navigation-browser';
import {
	observeLegacyOrganizationAdmin,
	observeNavigationComposition,
	observePasskeyLayout,
} from '#sign-in-test-support/test-fixtures/sign-in-navigation-layout';
import {
	observeNavigationPermissions,
	observeNavigationSwitch,
	observePeopleInShell,
} from '#sign-in-test-support/test-fixtures/sign-in-navigation-permissions';
import {
	observeNavigationCliContinuation,
	observeNavigationFactors,
	observeNavigationReadiness,
} from '#sign-in-test-support/test-fixtures/sign-in-navigation-setup';
import { observeNavigationSignOut } from '#sign-in-test-support/test-fixtures/sign-in-navigation-sign-out';

useControlledSignInClock();

const hosts = ['node', 'cloudflare'] as const;
const cases = [
	['N1/N2 exact owner and member links and direct People refusals', observeNavigationPermissions],
	[
		'N3 committed, unanswered and refused switches with fresh readback and Back',
		observeNavigationSwitch,
	],
	[
		'N4 Me recovery and authenticator forms settle through existing factor pages',
		observeNavigationFactors,
	],
	[
		'N5 current-session sign-out, fenced failures and retained-cookie replay',
		observeNavigationSignOut,
	],
	['N6 owner reaches a working checked People island from the shell', observePeopleInShell],
	['N7 signed-out and setup-pending entry and ready link', observeNavigationReadiness],
	['N7 exact continuation query and the same CLI callback', observeNavigationCliContinuation],
	['N8 stable Add and following controls during real list delivery', observePasskeyLayout],
	['N9 rendered Sidebar, mobile Sheet and passkey Item', observeNavigationComposition],
	['N10 legacy admin creates, looks up and audits a workspace', observeLegacyOrganizationAdmin],
] as const satisfies readonly (readonly [string, (browser: NavigationBrowser) => Promise<void>])[];

it.each(hosts.flatMap((host) => cases.map(([name, exercise]) => [name, host, exercise] as const)))(
	'sign-in navigation %s on %s',
	async (_name, host, exercise): Promise<void> => {
		await runProofBrowserScenario((signal) => withNavigationBrowser({ host, exercise, signal }));
	},
);
