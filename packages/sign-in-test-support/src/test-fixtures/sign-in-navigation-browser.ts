import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { organization as organizationTable, session } from '@agent-collaboration/sign-in-core';
import { eq } from 'drizzle-orm';
import { expect } from 'vitest';
import { z } from 'zod';

import { readCurrentBrowserSession } from '#sign-in-test-support/test-fixtures/current-browser-session';
import { startLocalAuthHarness } from '#sign-in-test-support/test-fixtures/local-auth-harness';
import { ensureLocalOwnerOrganization } from '#sign-in-test-support/test-fixtures/local-owner-organization';
import { withNativeBrowserCleanup } from '#sign-in-test-support/test-fixtures/native-browser-cleanup';
import {
	installOrganizationBrowserCookie,
	organizationBrowserCookie,
} from '#sign-in-test-support/test-fixtures/organization-browser-transport';
import {
	peoplePost,
	signInConfirmedPeopleBrowser,
} from '#sign-in-test-support/test-fixtures/people-browser-login';
import {
	launchProofBrowser,
	type PlaywrightBrowserPage,
} from '#sign-in-test-support/test-fixtures/playwright-browser';

export const navigationOwnerEmail = 'owner@example.invalid';
export const navigationMemberEmail = 'shell-member@example.invalid';
export const signOutPath = '/api/auth/switchboard/sign-out';
export const peopleListPath = '/api/auth/organization/people-list';
export const peopleLookupPath = '/api/auth/organization/person-membership';

export type NavigationHost = 'node' | 'cloudflare';
export interface NavigationBrowser {
	readonly harness: Awaited<ReturnType<typeof startLocalAuthHarness>>;
	readonly proof: PlaywrightBrowserPage;
	readonly organization: { readonly id: string; readonly name: string };
	readonly ownerCookie: string;
	readonly ownerId: string;
	readonly signal: AbortSignal;
}

export async function withNavigationBrowser(props: {
	readonly host: NavigationHost;
	readonly signal: AbortSignal;
	readonly exercise: (browser: NavigationBrowser) => Promise<void>;
}): Promise<void> {
	const evidence = await mkdtemp(path.join(tmpdir(), `2026-11-sign-in-navigation-${props.host}-`));
	const harness = await startLocalAuthHarness({
		host: props.host,
		turnstileSecret: 'published-test',
		issuerHostname: 'localhost',
	});
	let proof: PlaywrightBrowserPage | undefined;
	await withNativeBrowserCleanup(
		async (): Promise<void> => {
			expect(harness.signInHost).toBe(props.host);
			const ownerId = await signInConfirmedPeopleBrowser({ harness, email: navigationOwnerEmail });
			const organizationId = await ensureLocalOwnerOrganization(harness);
			expect((await peoplePost(harness, 'set-active', { organizationId })).status).toBe(200);
			const selected = z
				.object({ id: z.uuidv7(), name: z.string() })
				.parse(
					(
						await harness.database
							.select({ id: organizationTable.id, name: organizationTable.name })
							.from(organizationTable)
							.where(eq(organizationTable.id, organizationId))
					)[0],
				);
			await harness.settleDeferredWork();
			const ownerCookie = harness.cookie();
			proof = await launchProofBrowser({
				evidence,
				origin: harness.issuer,
				width: 1280,
				colorScheme: 'dark',
				scenarioSignal: props.signal,
			});
			await installOrganizationBrowserCookie({
				page: proof,
				issuer: harness.issuer,
				cookie: ownerCookie,
			});
			process.stdout.write(
				`${JSON.stringify({ event: 'sign-in-navigation-browser', requestedHost: props.host, actualHarnessHost: harness.signInHost, evidence })}\n`,
			);
			await props.exercise({
				harness,
				proof,
				organization: selected,
				ownerCookie,
				ownerId,
				signal: props.signal,
			});
		},
		() =>
			withNativeBrowserCleanup(
				async (): Promise<void> => {
					await proof?.close();
				},
				() => harness.close(),
			),
	);
}

export async function visitNavigation(
	browser: NavigationBrowser,
	route: '/me' | '/people',
): Promise<void> {
	const response = await browser.proof.page.goto(`${browser.harness.issuer}${route}`);
	expect(response?.status()).toBe(200);
	await browser.proof.page
		.locator('[data-sign-in-island-mounted] [data-slot="dropdown-menu-trigger"]')
		.waitFor();
	expect(new URL(browser.proof.page.url()).pathname).toBe(route);
}

export async function readActiveOrganization(browser: NavigationBrowser): Promise<string | null> {
	const cookie = await organizationBrowserCookie(browser.proof, browser.harness.issuer);
	const current = await readCurrentBrowserSession({ cookie, database: browser.harness.database });
	const rows = await browser.harness.database
		.select({ organizationId: session.activeOrganizationId })
		.from(session)
		.where(eq(session.id, current.id));
	return z.object({ organizationId: z.uuidv7().nullable() }).parse(rows[0]).organizationId;
}

export async function createNavigationMember(browser: NavigationBrowser): Promise<string> {
	const { harness, organization, ownerCookie } = browser;
	const invited = await peoplePost(
		harness,
		'invite-member',
		{
			organizationId: organization.id,
			email: navigationMemberEmail,
			role: 'member',
		},
		ownerCookie,
	);
	expect(invited.status).toBe(200);
	const { id } = z.object({ id: z.uuidv7() }).parse(await invited.json());
	await signInConfirmedPeopleBrowser({ harness, email: navigationMemberEmail });
	expect((await peoplePost(harness, 'accept-invitation', { invitationId: id })).status).toBe(200);
	expect(
		(await peoplePost(harness, 'set-active', { organizationId: organization.id })).status,
	).toBe(200);
	return harness.cookie();
}

/** These cases share one real browser and vary its state in causal order. */
export async function runNavigationSteps<TStep>(
	steps: readonly TStep[],
	runStep: (step: TStep) => Promise<void>,
): Promise<void> {
	await steps.reduce(async (previous: Promise<void>, step): Promise<void> => {
		await previous;
		await runStep(step);
	}, Promise.resolve());
}

export async function bootstrapNavigationAdmin(browser: NavigationBrowser): Promise<void> {
	const { harness, ownerCookie, organization, ownerId } = browser;
	const response = await harness.auth('/api/auth/owner/bootstrap', {
		method: 'POST',
		headers: { cookie: ownerCookie, 'content-type': 'application/json' },
		body: '{}',
	});
	expect(response.status).toBe(200);
	await harness.settleDeferredWork();
	expect(harness.centralProvisioning.hasFloors(organization.id, ownerId)).toBe(true);
}
