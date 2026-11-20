import { passkey } from '@agent-collaboration/sign-in-core';
import { eq } from 'drizzle-orm';
import type { Route } from 'playwright';
import { expect } from 'vitest';

import { controlledSignInIds } from '#sign-in-test-support/test-fixtures/controlled-sign-in-clock';
import { withNativeBrowserCleanup } from '#sign-in-test-support/test-fixtures/native-browser-cleanup';
import {
	bootstrapNavigationAdmin,
	runNavigationSteps,
	visitNavigation,
	type NavigationBrowser,
} from '#sign-in-test-support/test-fixtures/sign-in-navigation-browser';

interface HeldBrowserReply {
	readonly status: Promise<number>;
	readonly release: () => void;
	readonly close: () => Promise<void>;
}

async function holdBrowserReply(
	browser: NavigationBrowser,
	pattern: RegExp,
): Promise<HeldBrowserReply> {
	const requested = Promise.withResolvers<number>();
	const release = Promise.withResolvers<void>();
	const ended = Promise.withResolvers<void>();
	void requested.promise.catch(() => undefined);
	void ended.promise.catch(() => undefined);
	let entered = false;
	async function hold(route: Route): Promise<void> {
		entered = true;
		try {
			const response = await route.fetch();
			requested.resolve(response.status());
			await release.promise;
			await route.fulfill({ response });
			ended.resolve();
		} catch (error) {
			requested.reject(error);
			ended.reject(error);
		}
	}
	await browser.proof.page.route(pattern, hold, { times: 1 });
	return {
		status: requested.promise,
		release: () => release.resolve(),
		async close(): Promise<void> {
			release.resolve();
			await browser.proof.page.unroute(pattern, hold);
			if (entered) await ended.promise;
		},
	};
}

const passkeyList = /\/api\/auth\/passkey\/list-user-passkeys(?:\?|$)/u;
const pageIsland = /\/assets\/sign-in-pages-[^/]+\.js$/u;

export async function observePasskeyLayout(browser: NavigationBrowser): Promise<void> {
	const { proof, harness } = browser;
	await proof.addVirtualAuthenticator();
	const add = proof.page.getByRole('button', { name: 'Add passkey', exact: true });
	const following = proof.page.getByRole('button', { name: 'Replace recovery codes', exact: true });
	async function positions(): Promise<readonly object[]> {
		expect(await add.count()).toBe(1);
		const addBox = await add.boundingBox();
		const followingBox = await following.boundingBox();
		if (addBox === null || followingBox === null) throw new Error('Persistent control missing');
		return [addBox, followingBox];
	}

	await runNavigationSteps([0, 1, 4], async (count): Promise<void> => {
		await runNavigationSteps([400, 1280], async (width): Promise<void> => {
			await proof.page.setViewportSize({ width, height: 844 });
			const asset = await holdBrowserReply(browser, pageIsland);
			await withNativeBrowserCleanup(
				async (): Promise<void> => {
					const list = await holdBrowserReply(browser, passkeyList);
					await withNativeBrowserCleanup(
						async (): Promise<void> => {
							const navigation = await proof.page.goto(`${harness.issuer}/me`, {
								waitUntil: 'commit',
							});
							expect(navigation?.status()).toBe(200);
							expect(await asset.status).toBe(200);
							await add.waitFor();
							await following.waitFor();
							await proof.page.locator('[data-slot="skeleton"]').waitFor();
							const ssr = await positions();
							asset.release();
							expect(await list.status).toBe(200);
							await proof.page
								.locator('[data-sign-in-island-mounted] [data-slot="card-action"]')
								.first()
								.waitFor();
							expect(await add.isEnabled()).toBe(true);
							expect(await positions()).toEqual(ssr);

							list.release();
							const rows = proof.page
								.getByRole('region', { name: 'Passkey list' })
								.getByRole('listitem');
							if (count === 0)
								await proof.page.getByText('No passkeys yet.', { exact: true }).waitFor();
							else await rows.nth(count - 1).waitFor({ state: 'attached' });
							expect(await positions()).toEqual(ssr);
							expect(await rows.count()).toBe(count);
							if (count > 1) {
								const viewport = proof.page.getByRole('region', { name: 'Passkey list' });
								expect(
									await viewport.evaluate((region) => region.scrollHeight > region.clientHeight),
								).toBe(true);
								await rows.last().getByRole('button', { name: 'Rename' }).focus();
								expect(
									await rows
										.last()
										.getByRole('button', { name: 'Rename' })
										.evaluate((button) => button === document.activeElement),
								).toBe(true);
								expect(await viewport.evaluate((region) => region.scrollTop > 0)).toBe(true);
							}
						},
						() => list.close(),
					);
				},
				() => asset.close(),
			);
		});
		if (count === 0) {
			const registration = await proof.responseTo('/api/auth/passkey/verify-registration', () =>
				add.click(),
			);
			expect(registration.response.status).toBe(200);
			await proof.page
				.getByRole('region', { name: 'Passkey list' })
				.getByRole('listitem')
				.first()
				.waitFor({ state: 'attached' });
		}
		if (count === 1) {
			// Arrange a populated store without reusing the native authenticator
			// for another credential that the provider has already excluded.
			const registered = (
				await harness.database.select().from(passkey).where(eq(passkey.userId, browser.ownerId))
			)[0];
			if (registered === undefined) throw new Error('Native layout fixture passkey missing');
			await harness.database.insert(passkey).values(
				Array.from({ length: 3 }, (_, index) => {
					const id = controlledSignInIds.nextId();
					return {
						...registered,
						id,
						credentialID: Buffer.from(id).toString('base64url'),
						name: `Additional layout passkey ${index + 1}`,
					};
				}),
			);
		}
	});
}

export async function observeNavigationComposition(browser: NavigationBrowser): Promise<void> {
	const { proof } = browser;
	await visitNavigation(browser, '/me');
	expect(await proof.page.locator('[data-slot="sidebar-wrapper"]').count()).toBe(1);
	expect(
		await proof.page
			.locator('[data-slot="card-action"]')
			.getByRole('button', { name: 'Add passkey' })
			.count(),
	).toBe(1);
	await proof.addVirtualAuthenticator();
	const registration = await proof.responseTo('/api/auth/passkey/verify-registration', () =>
		proof.page.getByRole('button', { name: 'Add passkey' }).click(),
	);
	expect(registration.response.status).toBe(200);
	const row = proof.page.getByRole('region', { name: 'Passkey list' }).getByRole('listitem');
	await row.waitFor();
	expect(await row.getAttribute('data-slot')).toBe('item');
	await proof.page.setViewportSize({ width: 400, height: 844 });
	await proof.page.getByRole('button', { name: 'Toggle navigation' }).click();
	const sheet = proof.page.getByRole('dialog', { name: 'Sidebar' });
	await sheet.waitFor();
	expect(await sheet.getAttribute('data-slot')).toBe('sidebar');
	expect(await sheet.getAttribute('data-mobile')).toBe('true');
}

export async function observeLegacyOrganizationAdmin(browser: NavigationBrowser): Promise<void> {
	const { proof, harness, organization } = browser;
	await bootstrapNavigationAdmin(browser);
	await visitNavigation(browser, '/me');
	await proof.page.locator('[data-slot="dropdown-menu-trigger"]').click();
	const adminPage = await proof.responseTo('/organization-admin', () =>
		proof.afterNavigation('/organization-admin', () =>
			proof.page.getByRole('menuitem', { name: 'Organization admin' }).click(),
		),
	);
	expect(adminPage.response.status).toBe(200);
	await proof.page.getByRole('heading', { name: 'Create a workspace' }).waitFor();
	const name = 'Workspace created from Phase 1';
	await proof.page.getByRole('textbox', { name: 'Name', exact: true }).fill(name);
	const created = await proof.responseTo('/api/auth/organization-admin/create-workspace', () =>
		proof.page.getByRole('button', { name: 'Create workspace', exact: true }).click(),
	);
	expect(created.response.status).toBe(200);
	await proof.page.locator('#workspaces').getByText(name, { exact: false }).waitFor();
	await proof.page
		.locator('#change-records')
		.getByText('workspaceCreated', { exact: false })
		.waitFor();
	const answered = harness.centralAdmin.arrivals.filter(
		(arrival) => arrival.organizationId === organization.id && arrival.outcome.kind === 'answered',
	);
	expect(new Set(answered.map((arrival) => arrival.route))).toEqual(
		new Set(['CreateWorkspace', 'WorkspaceLookup', 'ReadChangeRecords']),
	);
	expect(
		harness.centralAdmin.workspaces.filter((workspace) => workspace.name === name),
	).toHaveLength(1);
}
