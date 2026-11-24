// @vitest-environment jsdom
import { expect, it } from 'vitest';

import { organizationAdminPage } from '#sign-in-core/better-auth/organization-admin-page';

it.each([false, true])(
	'renders the owner-only People link only when permission is %s',
	async (showPeopleLink) => {
		const response = organizationAdminPage({
			organizationId: '019a3dce-2000-7000-8000-0000000000a1',
			organizationName: '<script>untrusted()</script>',
			operationId: '019a3dce-2000-7000-8000-0000000000a2',
			showPeopleLink,
		});
		const page = new DOMParser().parseFromString(await response.text(), 'text/html');
		expect(page.querySelector('h1')?.textContent).toBe('<script>untrusted()</script>');
		const link = page.querySelector('a');
		expect(link?.textContent ?? null).toBe(showPeopleLink ? 'People' : null);
		if (showPeopleLink)
			expect(link?.getAttribute('href')).toBe(
				'/api/auth/organization/people?organizationId=019a3dce-2000-7000-8000-0000000000a1',
			);
	},
);

/**
 * Vitest's `window` is Node's global; scripts the page runs see the jsdom window it also exposes as
 * `jsdom`, which has no `fetch` of its own.
 */
function jsdomWindowRunningServedScripts(): object {
	const handle: unknown = Reflect.get(globalThis, 'jsdom');
	const servedWindow: unknown =
		typeof handle === 'object' && handle !== null ? Reflect.get(handle, 'window') : undefined;
	if (typeof servedWindow !== 'object' || servedWindow === null)
		throw new Error('The jsdom window is not exposed by the test environment.');
	return servedWindow;
}

it('labels each change record with the origin it names: the person and permission, automatic in Central, or sign-in', async () => {
	// Arrange
	const organizationId = '019a3dce-2000-7000-8000-0000000000a1';
	const createdAtMillis = Date.UTC(2026, 10, 22, 9, 30);
	const timestamp = new Date(createdAtMillis).toISOString();
	const personId = 'person-owner';
	const workspaceId = '019a3dce-2000-7000-8000-0000000000a3';
	const record = {
		kind: 'organizationProvisioned',
		requestId: 'request-1',
		targetId: organizationId,
		createdAtMillis,
	};
	const records = [
		{ ...record, id: 'record-1', origin: { kind: 'signInProvisioning' } },
		{
			...record,
			id: 'record-2',
			origin: { kind: 'person', personId, permissionChecked: 'machine:enroll' },
		},
		{ ...record, id: 'record-3', origin: { kind: 'automatic' } },
		// The page looks up each created workspace only after it has rendered every row, so this record
		// makes that lookup the served render's explicit completion.
		{
			...record,
			kind: 'workspaceCreated',
			id: 'record-4',
			targetId: workspaceId,
			origin: { kind: 'automatic' },
		},
	];
	const renderCompleted = Promise.withResolvers<void>();
	const servedWindow = jsdomWindowRunningServedScripts();
	Reflect.set(servedWindow, 'fetch', (route: unknown): Promise<Response> => {
		if (String(route).endsWith('/workspace-lookup')) {
			renderCompleted.resolve();
			return Promise.resolve(Response.json({ result: 'found', workspace: null }));
		}
		return Promise.resolve(Response.json({ result: 'records', records }));
	});
	// A page that fails to render says so in its status line; that ends the wait with the reason.
	const statusObserver = new MutationObserver((): void => {
		renderCompleted.reject(
			new Error(document.getElementById('status')?.textContent ?? 'status changed'),
		);
	});
	try {
		const html = await organizationAdminPage({
			organizationId,
			organizationName: 'research',
			operationId: '019a3dce-2000-7000-8000-0000000000a2',
			showPeopleLink: false,
		}).text();
		const served = new DOMParser().parseFromString(html, 'text/html');
		document.body.innerHTML = served.body.innerHTML;
		const listed = (): string[] =>
			[...document.querySelectorAll('#change-records li')].map((entry) => entry.textContent ?? '');
		statusObserver.observe(document.getElementById('status') ?? document.body, {
			childList: true,
			characterData: true,
			subtree: true,
		});
		// Act: run the served page script against the stubbed forwarding route.
		const script = document.createElement('script');
		script.textContent = served.querySelector('script')?.textContent ?? '';
		document.body.append(script);
		await renderCompleted.promise;
		// Assert
		expect(listed()).toEqual([
			`${timestamp} organizationProvisioned ${organizationId} by sign-in`,
			`${timestamp} organizationProvisioned ${organizationId} by ${personId} (machine:enroll)`,
			`${timestamp} organizationProvisioned ${organizationId} automatically in Central`,
			`${timestamp} workspaceCreated ${workspaceId} automatically in Central`,
		]);
	} finally {
		statusObserver.disconnect();
		Reflect.deleteProperty(servedWindow, 'fetch');
		document.body.innerHTML = '';
	}
});
