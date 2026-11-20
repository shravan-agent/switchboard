import { member, session } from '@agent-collaboration/sign-in-core';
import { and, eq } from 'drizzle-orm';
import type { Route } from 'playwright';
import { expect } from 'vitest';
import { z } from 'zod';

import { controlledSignInIds } from '#sign-in-test-support/test-fixtures/controlled-sign-in-clock';
import { withNativeBrowserCleanup } from '#sign-in-test-support/test-fixtures/native-browser-cleanup';
import {
	installOrganizationBrowserCookie,
	OrganizationBrowserResponses,
} from '#sign-in-test-support/test-fixtures/organization-browser-transport';
import { peoplePost } from '#sign-in-test-support/test-fixtures/people-browser-login';
import {
	bootstrapNavigationAdmin,
	createNavigationMember,
	navigationMemberEmail,
	navigationOwnerEmail,
	peopleListPath,
	peopleLookupPath,
	readActiveOrganization,
	runNavigationSteps,
	visitNavigation,
	type NavigationBrowser,
} from '#sign-in-test-support/test-fixtures/sign-in-navigation-browser';

const switchPath = '/api/auth/organization/set-active';

async function loseBeforeWrite(route: Route): Promise<void> {
	await route.abort('connectionclosed');
}

async function expectDestinations(
	browser: NavigationBrowser,
	names: readonly string[],
): Promise<void> {
	const { page } = browser.proof;
	const links = page.getByRole('navigation', { name: 'Signed-in navigation' }).getByRole('link');
	await links.first().waitFor();
	expect(await links.allTextContents()).toEqual(names);
	expect(await links.first().getAttribute('aria-current')).toBe('page');
	expect(await links.first().getAttribute('href')).toBe('/me');

	await page.setViewportSize({ width: 400, height: 844 });
	await page.getByRole('button', { name: 'Toggle navigation' }).click();
	const sheet = page.getByRole('dialog', { name: 'Sidebar' });
	await sheet.waitFor();
	expect(await sheet.locator('[data-slot="sidebar-content"]').count()).toBe(1);
	expect(await sheet.getByRole('link').allTextContents()).toEqual(names);
	expect(await sheet.getByRole('link', { name: 'Me' }).getAttribute('aria-current')).toBe('page');
	await page.keyboard.press('Escape');
	await sheet.waitFor({ state: 'hidden' });
	await page.setViewportSize({ width: 1280, height: 844 });
}

export async function observeNavigationPermissions(browser: NavigationBrowser): Promise<void> {
	const { harness, proof, organization } = browser;
	await bootstrapNavigationAdmin(browser);
	await visitNavigation(browser, '/me');
	await expectDestinations(browser, ['Me', 'People']);
	const switcher = proof.page.locator('[data-slot="dropdown-menu-trigger"]');
	await switcher.click();
	await proof.page.getByRole('menuitem', { name: 'Organization admin' }).waitFor();

	const cookie = await createNavigationMember(browser);
	await installOrganizationBrowserCookie({ page: proof, issuer: harness.issuer, cookie });
	await visitNavigation(browser, '/me');
	expect(await readActiveOrganization(browser)).toBe(organization.id);
	await expectDestinations(browser, ['Me']);
	await switcher.click();
	await proof.page.getByRole('menuitemradio').first().waitFor();
	expect(await proof.page.getByRole('menuitem', { name: 'Organization admin' }).count()).toBe(0);

	const before = await harness.database
		.select()
		.from(member)
		.where(eq(member.organizationId, organization.id));
	await runNavigationSteps(
		[
			'/people',
			`/api/auth/organization/people?organizationId=${organization.id}`,
			`${peopleListPath}?organizationId=${organization.id}&offset=0`,
		],
		async (endpoint): Promise<void> => {
			const refused = await harness.auth(endpoint, { headers: { cookie } });
			expect(refused.status).toBe(403);
			expect(await refused.json()).toEqual({ kind: 'refused' });
		},
	);
	const lookup = await peoplePost(
		harness,
		'person-membership',
		{
			organizationId: organization.id,
			email: navigationOwnerEmail,
		},
		cookie,
	);
	expect(lookup.status).toBe(403);
	expect(await lookup.json()).toEqual({ kind: 'refused' });
	await harness.settleDeferredWork();
	const arrivals = harness.centralAdmin.arrivals.length;
	const create = await harness.auth('/api/auth/organization-admin/create-workspace', {
		method: 'POST',
		headers: { cookie, 'content-type': 'application/json' },
		body: JSON.stringify({
			organizationId: organization.id,
			operationId: controlledSignInIds.nextId(),
			name: 'Denied workspace',
			description: '',
		}),
	});
	expect(create.status).toBe(200);
	expect(await create.json()).toEqual({ result: 'refused', reason: 'notPermitted' });
	expect(
		harness.centralAdmin.arrivals.slice(arrivals).map((arrival) => arrival.permissions),
	).toEqual([[]]);
	expect(harness.centralAdmin.workspaces).toEqual([]);
	expect(harness.centralAdmin.changeRecords).toEqual([]);
	expect(
		await harness.database.select().from(member).where(eq(member.organizationId, organization.id)),
	).toEqual(before);
}

export async function observePeopleInShell(browser: NavigationBrowser): Promise<void> {
	const { proof, organization, harness, ownerCookie } = browser;
	await createNavigationMember(browser);
	await installOrganizationBrowserCookie({
		page: proof,
		issuer: harness.issuer,
		cookie: ownerCookie,
	});
	await visitNavigation(browser, '/me');
	const listResponse = await proof.responseTo(peopleListPath, async (): Promise<void> => {
		await proof.afterNavigation('/people', () =>
			proof.page.getByRole('link', { name: 'People', exact: true }).click(),
		);
		await proof.page
			.locator('[data-sign-in-island-mounted] [data-slot="dropdown-menu-trigger"]')
			.waitFor();
		expect(await proof.page.getByRole('table', { name: 'Members' }).count()).toBe(1);
	});
	expect(listResponse.response.status).toBe(200);
	expect(new URL(proof.page.url()).pathname).toBe('/people');
	expect(
		await proof.page
			.getByRole('link', { name: 'People', exact: true })
			.getAttribute('aria-current'),
	).toBe('page');
	await proof.page
		.getByRole('table', { name: 'Members' })
		.getByRole('button', { name: `Look up ${navigationMemberEmail}` })
		.waitFor();
	expect(await proof.page.locator('[data-slot="dropdown-menu-trigger"]').textContent()).toBe(
		organization.name,
	);
	await proof.page.getByRole('textbox', { name: 'Email' }).fill(navigationMemberEmail);
	const lookedUp = await proof.responseTo(peopleLookupPath, async (): Promise<void> =>
		proof.page.getByRole('button', { name: 'Look up', exact: true }).click(),
	);
	expect(lookedUp.response.status).toBe(200);
	await proof.page
		.getByLabel('Membership result')
		.getByText(/member/iu)
		.waitFor();
}

async function chooseFromMenu(browser: NavigationBrowser, name: string): Promise<void> {
	await browser.proof.page.locator('[data-slot="dropdown-menu-trigger"]').click();
	await browser.proof.page.getByRole('menuitemradio', { name: new RegExp(name, 'u') }).click();
}

export async function observeNavigationSwitch(browser: NavigationBrowser): Promise<void> {
	const { harness, proof, ownerCookie, organization, ownerId } = browser;
	const secondName = 'Second shell membership';
	const created = await peoplePost(
		harness,
		'create',
		{ name: secondName, slug: 'second-shell-membership' },
		ownerCookie,
	);
	expect(created.status).toBe(200);
	const { id: secondId } = z.object({ id: z.uuidv7() }).parse(await created.json());
	const secondMembership = (
		await harness.database
			.select()
			.from(member)
			.where(and(eq(member.organizationId, secondId), eq(member.userId, ownerId)))
	)[0];
	if (secondMembership === undefined) throw new Error('Second owner membership missing');
	expect(
		(await peoplePost(harness, 'set-active', { organizationId: organization.id }, ownerCookie))
			.status,
	).toBe(200);

	const replies = new OrganizationBrowserResponses(proof);
	await replies.enable(harness.issuer);
	await withNativeBrowserCleanup(
		async (): Promise<void> => {
			await visitNavigation(browser, '/people');
			await runNavigationSteps([false, true], async (loseReply): Promise<void> => {
				await proof.afterNavigation('/me', async (): Promise<void> => {
					const pending = replies.arm((url) => url.pathname === switchPath);
					await chooseFromMenu(browser, secondName);
					const held = await pending;
					expect(held.responseStatusCode).toBe(200);
					expect(await readActiveOrganization(browser)).toBe(secondId);
					if (loseReply) await replies.lose(held);
					else await replies.releaseForNavigation(held);
				});
				await proof.page.getByRole('button', { name: secondName, exact: true }).waitFor();
				expect(await readActiveOrganization(browser)).toBe(secondId);
				if (!loseReply) {
					await proof.page.goBack();
					await proof.page.getByRole('button', { name: secondName, exact: true }).waitFor();
					expect(new URL(proof.page.url()).pathname).toBe('/people');
				}
				expect(
					(
						await peoplePost(
							harness,
							'set-active',
							{ organizationId: organization.id },
							ownerCookie,
						)
					).status,
				).toBe(200);
				await visitNavigation(browser, '/me');
			});

			// Playwright disables BFCache by default. Observe the real Back above,
			// then drive the already-mounted page's persisted-restoration handler.
			await visitNavigation(browser, '/people');
			const oldOrganization = proof.page.getByRole('button', {
				name: organization.name,
				exact: true,
			});
			expect(await oldOrganization.isVisible()).toBe(true);
			expect(
				(await peoplePost(harness, 'set-active', { organizationId: secondId }, ownerCookie)).status,
			).toBe(200);
			expect(await readActiveOrganization(browser)).toBe(secondId);
			expect(await oldOrganization.isVisible()).toBe(true);
			process.stdout.write(
				'Navigation N3: dispatching persisted pageshow to the mounted stale document\n',
			);
			const restored = await proof.responseTo('/people', () =>
				proof.afterNavigation('/people', () =>
					proof.page.evaluate((): void => {
						window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
					}),
				),
			);
			expect(restored.response.status).toBe(200);
			await proof.page.getByRole('button', { name: secondName, exact: true }).waitFor();
			expect(await readActiveOrganization(browser)).toBe(secondId);
			expect(await oldOrganization.count()).toBe(0);
			expect(
				(await peoplePost(harness, 'set-active', { organizationId: organization.id }, ownerCookie))
					.status,
			).toBe(200);
			await visitNavigation(browser, '/me');

			// Lose the request at its ingress. No commit is possible, and the readback
			// must land on the still-active organization.
			await replies.close();
			await proof.page.route(`**${switchPath}`, loseBeforeWrite);
			try {
				await proof.afterNavigation('/me', () => chooseFromMenu(browser, secondName));
				await proof.page.getByRole('button', { name: organization.name, exact: true }).waitFor();
				expect(await readActiveOrganization(browser)).toBe(organization.id);
			} finally {
				await proof.page.unroute(`**${switchPath}`, loseBeforeWrite);
			}
			await replies.enable(harness.issuer);

			await runNavigationSteps([false, true], async (loseReply): Promise<void> => {
				await visitNavigation(browser, '/me');
				await proof.page.locator('[data-slot="dropdown-menu-trigger"]').click();
				await harness.database.delete(member).where(eq(member.id, secondMembership.id));
				await proof.afterNavigation(undefined, async (): Promise<void> => {
					const pending = replies.arm((url) => url.pathname === switchPath);
					await proof.page.getByRole('menuitemradio', { name: /Second shell membership/u }).click();
					const held = await pending;
					expect(held.responseStatusCode).toBe(403);
					expect(await readActiveOrganization(browser)).toBeNull();
					if (loseReply) await replies.lose(held);
					else await replies.releaseForNavigation(held);
				});
				expect(new URL(proof.page.url()).pathname).toBe('/owner-ready');
				const choice = proof.page.getByRole('button', { name: `Choose ${organization.name}` });
				await choice.waitFor();
				expect(await choice.isEnabled()).toBe(true);
				expect(await proof.page.locator('#choose-organization button').count()).toBe(1);
				await proof.afterNavigation('/owner-ready', () => choice.click());
				await proof.page.getByRole('link', { name: 'Go to Me' }).click();
				await proof.page.getByRole('button', { name: organization.name, exact: true }).waitFor();
				expect(await readActiveOrganization(browser)).toBe(organization.id);
				await harness.database.insert(member).values(secondMembership);
			});
			await visitNavigation(browser, '/me');
			await proof.page.locator('[data-slot="dropdown-menu-trigger"]').click();
			await harness.database.delete(member).where(eq(member.userId, ownerId));
			await proof.afterNavigation('/owner-ready', async (): Promise<void> => {
				const pending = replies.arm((url) => url.pathname === switchPath);
				await proof.page.getByRole('menuitemradio', { name: /Second shell membership/u }).click();
				const held = await pending;
				expect(held.responseStatusCode).toBe(403);
				await replies.releaseForNavigation(held);
			});
			await proof.page.getByRole('button', { name: 'Create organization' }).waitFor();
			expect(await proof.page.locator('#choose-organization').count()).toBe(0);
			const rows = await harness.database.select().from(session).where(eq(session.userId, ownerId));
			expect(rows.some((row) => row.activeOrganizationId === null)).toBe(true);
		},
		() => replies.close(),
	);
}
