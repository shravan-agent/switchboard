import {
	personOrganizationAuthorizationRevisions,
	session,
} from '@agent-collaboration/sign-in-core';
import { getSessionCookie } from 'better-auth/cookies';
import { and, eq } from 'drizzle-orm';
import { expect } from 'vitest';
import { z } from 'zod';

import { readCurrentBrowserSession } from '#sign-in-test-support/test-fixtures/current-browser-session';
import { organizationBrowserCookie } from '#sign-in-test-support/test-fixtures/organization-browser-transport';
import { signInConfirmedPeopleBrowser } from '#sign-in-test-support/test-fixtures/people-browser-login';
import { waitForBrowserEvent } from '#sign-in-test-support/test-fixtures/playwright-network';
import {
	navigationOwnerEmail,
	signOutPath,
	visitNavigation,
	type NavigationBrowser,
} from '#sign-in-test-support/test-fixtures/sign-in-navigation-browser';

function signedBrowserToken(cookie: string): string | null {
	return getSessionCookie(new Headers({ cookie }));
}

async function sessionRow(
	browser: NavigationBrowser,
	id: string,
): Promise<{ readonly id: string; readonly token: string }> {
	const rows = await browser.harness.database
		.select({ id: session.id, token: session.token })
		.from(session)
		.where(eq(session.id, id));
	return z.object({ id: z.uuidv7(), token: z.string().min(1) }).parse(rows[0]);
}

async function observeSignOutStatus(
	proof: NavigationBrowser['proof'],
	submit: () => Promise<void>,
): Promise<number> {
	// A manual redirect is opaque to Fetch. Observe the replay's wire
	// status through CDP's raw response headers, before the document is replaced.
	let replayRequestId: string | undefined;
	function rememberReplay(event: {
		readonly requestId: string;
		readonly request: { readonly method: string; readonly url: string };
	}): void {
		if (event.request.method === 'POST' && new URL(event.request.url).pathname === signOutPath)
			replayRequestId = event.requestId;
	}
	proof.protocol.on('Network.requestWillBeSent', rememberReplay);
	const replay = waitForBrowserEvent<{ readonly requestId: string; readonly statusCode: number }>({
		signal: proof.signal,
		subscribe(receive) {
			proof.protocol.on('Network.responseReceivedExtraInfo', receive);
			return (): void => {
				proof.protocol.off('Network.responseReceivedExtraInfo', receive);
			};
		},
		matches: (receipt) => receipt.requestId === replayRequestId,
	});
	try {
		await submit();
		return (await replay.completed).statusCode;
	} finally {
		replay.cancel();
		proof.protocol.off('Network.requestWillBeSent', rememberReplay);
	}
}

export async function observeNavigationSignOut(browser: NavigationBrowser): Promise<void> {
	const { harness, proof, ownerCookie, ownerId, organization } = browser;
	await visitNavigation(browser, '/me');
	const originalCookie = await organizationBrowserCookie(proof, harness.issuer);
	const original = await readCurrentBrowserSession({
		cookie: originalCookie,
		database: harness.database,
	});
	const row = await sessionRow(browser, original.id);

	await signInConfirmedPeopleBrowser({ harness, email: navigationOwnerEmail });
	const otherCookie = harness.cookie();
	const other = await readCurrentBrowserSession({
		cookie: otherCookie,
		database: harness.database,
	});
	expect(other.id).not.toBe(original.id);
	expect(other.personId).toBe(original.personId);

	async function facts(): Promise<{ readonly present: boolean; readonly revision: number }> {
		const [rows, revisions] = await Promise.all([
			harness.database.select({ id: session.id }).from(session).where(eq(session.token, row.token)),
			harness.database
				.select({ revision: personOrganizationAuthorizationRevisions.revision })
				.from(personOrganizationAuthorizationRevisions)
				.where(
					and(
						eq(personOrganizationAuthorizationRevisions.personId, ownerId),
						eq(personOrganizationAuthorizationRevisions.organizationId, organization.id),
					),
				),
		]);
		return {
			present: rows.length === 1,
			revision: z.object({ revision: z.number().int() }).parse(revisions[0]).revision,
		};
	}
	const before = await facts();
	expect(before.present).toBe(true);
	const native = await harness.auth('/api/auth/sign-out', {
		method: 'POST',
		headers: { cookie: ownerCookie },
	});
	expect(native.status).toBe(404);
	const crossOrigin = await harness.auth(signOutPath, {
		method: 'POST',
		headers: { cookie: originalCookie, origin: 'https://foreign.example.invalid' },
	});
	expect(crossOrigin.status).toBe(403);
	expect(crossOrigin.headers.getSetCookie()).toEqual([]);
	expect(await facts()).toEqual(before);

	const button = proof.page.getByRole('button', { name: 'Sign out', exact: true });
	async function attemptFromBrowser(): Promise<void> {
		expect(await observeSignOutStatus(proof, () => button.click())).toBe(503);
		await proof.page.getByRole('alert').getByText("Couldn't sign you out; try again").waitFor();
		expect(
			signedBrowserToken(await organizationBrowserCookie(proof, harness.issuer)) ===
				signedBrowserToken(originalCookie),
		).toBe(true);
	}

	await harness.setDatabaseFault({
		operation: 'delete',
		table: 'session',
		key: row.token,
		once: true,
	});
	await attemptFromBrowser();
	expect(await facts()).toEqual(before);

	await harness.setDatabaseFault({
		operation: 'select',
		table: 'session',
		projection: 'session-id-by-token',
		key: row.token,
		once: true,
	});
	await attemptFromBrowser();
	expect(await facts()).toEqual(before);

	await harness.setDatabaseFault({
		operation: 'select',
		table: 'session',
		projection: 'session-id-by-token',
		key: row.token,
		skipMatches: 1,
		once: true,
	});
	await attemptFromBrowser();
	expect(await facts()).toEqual({ present: false, revision: before.revision + 1 });

	expect(
		await observeSignOutStatus(proof, () =>
			proof.afterNavigation('/sign-in', () => button.click()),
		),
	).toBe(303);
	expect(signedBrowserToken(await organizationBrowserCookie(proof, harness.issuer))).toBeNull();
	expect(await facts()).toEqual({ present: false, revision: before.revision + 1 });
	expect((await sessionRow(browser, other.id)).id).toBe(other.id);
	expect((await harness.auth('/me', { headers: { cookie: otherCookie } })).status).toBe(200);
	const signedOut = await harness.auth('/me', { headers: { cookie: originalCookie } });
	expect(signedOut.status).toBe(303);
	expect(signedOut.headers.get('location')).toBe('/sign-in');

	// With both reads available, a present row completes in one request.
	const otherSignOut = await harness.auth(signOutPath, {
		method: 'POST',
		headers: { cookie: otherCookie },
	});
	expect(otherSignOut.status).toBe(303);
	expect(otherSignOut.headers.get('location')).toBe('/sign-in');
	expect(
		otherSignOut.headers
			.getSetCookie()
			.some((cookie) => cookie.includes('session_token=') && /Max-Age=0/iu.test(cookie)),
	).toBe(true);
	expect(
		await harness.database.select({ id: session.id }).from(session).where(eq(session.id, other.id)),
	).toEqual([]);
	expect(await facts()).toEqual({ present: false, revision: before.revision + 2 });
}
