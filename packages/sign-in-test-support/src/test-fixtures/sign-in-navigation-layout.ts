import { passkey } from '@agent-collaboration/sign-in-core';
import { eq } from 'drizzle-orm';
import type { Route } from 'playwright';
import { expect } from 'vitest';
import { z } from 'zod';

import { holdCommittedDocumentReply } from '#sign-in-test-support/test-fixtures/committed-document-reply-hold';
import { controlledSignInIds } from '#sign-in-test-support/test-fixtures/controlled-sign-in-clock';
import type { MePageWaitBlock } from '#sign-in-test-support/test-fixtures/me-page-request-tracker';
import { withNativeBrowserCleanup } from '#sign-in-test-support/test-fixtures/native-browser-cleanup';
import {
	bootstrapNavigationAdmin,
	runNavigationSteps,
	visitNavigation,
	type NavigationBrowser,
} from '#sign-in-test-support/test-fixtures/sign-in-navigation-browser';
import { awaitMePageRequestsAfter } from '#sign-in-test-support/test-fixtures/sign-in-navigation-setup';

export interface HeldBrowserReply {
	readonly status: Promise<number>;
	/** How many requests the route has seen, including those it passed through after the first. */
	readonly matchedRequests: () => number;
	readonly release: () => void;
	readonly close: () => Promise<void>;
}

/**
 * Holds the first request matching `pattern` and passes every later one through.
 *
 * The route is never registered with `{ times: 1 }`. Playwright drops a spent route at
 * once, and when it was the last one it sends `Fetch.disable` while the held document's
 * own subresources are being requested. A request that Chromium creates during that
 * disable is neither paused nor served, the document never reaches DOMContentLoaded, and
 * the zero-timeout `goto` waits forever. `close()` removes the route once the page has
 * settled.
 */
export async function holdBrowserReply(
	browser: NavigationBrowser,
	pattern: RegExp,
	signal: AbortSignal = browser.signal,
): Promise<HeldBrowserReply> {
	const requested = Promise.withResolvers<number>();
	const release = Promise.withResolvers<void>();
	const ended = Promise.withResolvers<void>();
	void requested.promise.catch(() => undefined);
	void ended.promise.catch(() => undefined);
	let entered = false;
	let matchedRequests = 0;
	function abort(): void {
		requested.reject(signal.reason);
		release.resolve();
	}
	if (signal.aborted) abort();
	else signal.addEventListener('abort', abort, { once: true });
	async function hold(route: Route): Promise<void> {
		matchedRequests += 1;
		if (entered) {
			await route.fallback();
			return;
		}
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
	await browser.proof.page.route(pattern, hold);
	return {
		status: requested.promise,
		matchedRequests: () => matchedRequests,
		release: () => release.resolve(),
		async close(): Promise<void> {
			signal.removeEventListener('abort', abort);
			release.resolve();
			if (!browser.proof.page.isClosed()) {
				await browser.proof.page.unroute(pattern, hold);
				if (entered) await ended.promise;
			}
		},
	};
}

const passkeyList = /\/api\/auth\/passkey\/list-user-passkeys(?:\?|$)/u;
const pageIsland = /\/assets\/sign-in-pages-[^/]+\.js$/u;

const paintedControl = z.object({
	x: z.number(),
	y: z.number(),
	width: z.number(),
	height: z.number(),
});
const layoutFrame = z.object({
	phase: z.enum(['mount', 'list']),
	add: paintedControl.nullable(),
	following: paintedControl.nullable(),
	hit: z.boolean(),
});
async function installLayoutFrameProbe(proof: NavigationBrowser['proof']): Promise<void> {
	await proof.evaluate(
		`(()=>{
		const frames=[];
		let phase='mount';
		let running=true;
		function control(label){
			const visible=[...document.querySelectorAll('button')].filter(button=>
				button.textContent.trim()===label && button.getClientRects().length>0);
			return visible.length===1 ? visible[0] : null;
		}
		function box(button) {
			if(!button)return null;
			const {x,y,width,height}=button.getBoundingClientRect();
			return {x,y,width,height};
		}
		function sample(){
			if(!running)return;
			const add=control('Add passkey');
			const target=box(add);
			const hit=target!==null && add.contains(document.elementFromPoint(
				target.x+target.width/2, target.y+target.height/2));
			frames.push({phase,add:target,following:box(control('Replace recovery codes')),hit});
			requestAnimationFrame(sample);
		}
		window.navigationLayoutFrames={
			next(nextPhase){phase=nextPhase;return new Promise(resolve=>requestAnimationFrame(()=>resolve(true)));},
			finish(){return new Promise(resolve=>requestAnimationFrame(()=>{running=false;resolve(frames);}));}
		};
		requestAnimationFrame(sample);
		return true;
	})()`,
		z.literal(true),
	);
}

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
			const asset = await holdCommittedDocumentReply(proof, {
				urlPattern: '*/assets/sign-in-pages-*.js',
				matches: pageIsland,
				signal: browser.signal,
			});
			await withNativeBrowserCleanup(
				async (): Promise<void> => {
					const list = await holdCommittedDocumentReply(proof, {
						urlPattern: '*/api/auth/passkey/list-user-passkeys*',
						matches: passkeyList,
						signal: browser.signal,
					});
					await withNativeBrowserCleanup(
						// The visit ends on the Me island's own requests, so the session request that is not
						// held cannot still be open when the next visit or the harness close comes.
						() =>
							awaitMePageRequestsAfter(browser, async (): Promise<void> => {
								const navigation = await proof.page.goto(`${harness.issuer}/me`, {
									waitUntil: 'commit',
								});
								expect(navigation?.status()).toBe(200);
								expect(await asset.status).toBe(200);
								await add.waitFor();
								await following.waitFor();
								await proof.page.locator('[data-slot="skeleton"]').waitFor();
								const ssr = await positions();
								await installLayoutFrameProbe(proof);
								await proof.evaluate(
									"window.navigationLayoutFrames.next('mount')",
									z.literal(true),
								);
								asset.release();
								expect(await list.status).toBe(200);
								await proof.page
									.locator('[data-sign-in-island-mounted] [data-slot="card-action"]')
									.first()
									.waitFor();
								expect(await add.isEnabled()).toBe(true);
								expect(await positions()).toEqual(ssr);

								await proof.evaluate("window.navigationLayoutFrames.next('list')", z.literal(true));
								list.release();
								const rows = proof.page
									.getByRole('region', { name: 'Passkey list' })
									.getByRole('listitem');
								if (count === 0)
									await proof.page.getByText('No passkeys yet.', { exact: true }).waitFor();
								else await rows.nth(count - 1).waitFor({ state: 'attached' });
								expect(await positions()).toEqual(ssr);
								expect(await rows.count()).toBe(count);
								const frames = await proof.evaluate(
									'window.navigationLayoutFrames.finish()',
									z.array(layoutFrame),
								);
								expect(new Set(frames.map((frame) => frame.phase))).toEqual(
									new Set(['mount', 'list']),
								);
								// Compare every painted-frame opportunity from before
								// the asset release through the settled list commit.
								expect(
									frames.every(
										(frame) => frame.hit && frame.add !== null && frame.following !== null,
									),
								).toBe(true);
								expect(
									frames.every(
										(frame) => JSON.stringify([frame.add, frame.following]) === JSON.stringify(ssr),
									),
								).toBe(true);
								process.stdout.write(
									`${JSON.stringify({ event: 'navigation-layout-frames', width, count, frames: frames.length })}\n`,
								);
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
							}).then(() => undefined),
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
	await observeCancelledHoldProof(browser);
}

/** Navigates to a Me document whose hold is cancelled before its request arrives. */
export async function observeCancelledHoldProof(
	browser: NavigationBrowser,
	options: { readonly onBlocked?: (block: MePageWaitBlock) => void } = {},
): Promise<void> {
	const { proof, harness } = browser;
	const cancelled = new AbortController();
	const absent = await holdBrowserReply(
		browser,
		/\/me\?hold-cancel-proof=1$/u,
		AbortSignal.any([browser.signal, cancelled.signal]),
	);
	try {
		cancelled.abort(new Error('Held request cancelled before arrival'));
		absent.release();
		// The navigation ends on the Me island's own requests, not at DOMContentLoaded, so none is
		// still open in the proof server when the harness closes.
		await awaitMePageRequestsAfter(
			browser,
			async (): Promise<void> => {
				await proof.navigate(`${harness.issuer}/me?hold-cancel-proof=1`);
				await expect(absent.status).rejects.toThrow('Held request cancelled before arrival');
			},
			options,
		);
	} finally {
		await absent.close();
	}
}

export async function observeNavigationComposition(browser: NavigationBrowser): Promise<void> {
	const { proof, harness, ownerId } = browser;
	await visitNavigation(browser, '/me');
	expect(await proof.page.locator('[data-slot="sidebar-wrapper"]').count()).toBe(1);
	expect(
		await proof.page
			.locator('[data-slot="card-action"]')
			.getByRole('button', { name: 'Add passkey' })
			.count(),
	).toBe(1);
	const empty = proof.page.getByText('No passkeys yet.', { exact: true });
	await empty.waitFor();
	expect(await empty.getAttribute('data-slot')).toBe('empty-description');
	await proof.addVirtualAuthenticator();
	const registration = await proof.responseTo('/api/auth/passkey/verify-registration', () =>
		proof.page.getByRole('button', { name: 'Add passkey' }).click(),
	);
	expect(registration.response.status).toBe(200);
	const row = proof.page.getByRole('region', { name: 'Passkey list' }).getByRole('listitem');
	await row.waitFor();
	expect(await row.getAttribute('data-slot')).toBe('item');
	const [registered] = await harness.database
		.select({ id: passkey.id, name: passkey.name })
		.from(passkey)
		.where(eq(passkey.userId, ownerId));
	if (registered === undefined) throw new Error('Composition fixture passkey missing');
	await row.getByRole('button', { name: 'Rename' }).click();
	const field = row.locator('[data-slot="field"]');
	const name = row.getByRole('textbox', { name: 'Passkey name' });
	await name.waitFor();
	expect(await field.getByRole('textbox', { name: 'Passkey name' }).count()).toBe(1);
	await name.fill('A name that the store refuses');
	await harness.setDatabaseFault({
		operation: 'update',
		table: 'passkey',
		key: registered.id,
		once: true,
	});
	const refused = await proof.responseTo('/api/auth/passkey/update-passkey', () =>
		row.getByRole('button', { name: 'Save' }).click(),
	);
	expect(refused.response.status).toBeGreaterThanOrEqual(400);
	const error = row.getByRole('alert');
	await error.waitFor();
	expect(await error.getAttribute('data-slot')).toBe('field-error');
	expect(await name.getAttribute('aria-describedby')).toBe(await error.getAttribute('id'));
	expect(
		(
			await harness.database
				.select({ name: passkey.name })
				.from(passkey)
				.where(eq(passkey.id, registered.id))
		)[0]?.name,
	).toBe(registered.name);
	await row.getByRole('button', { name: 'Cancel' }).click();
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
