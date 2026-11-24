import { expect, it } from 'vitest';

import {
	createMePageDocumentTracker,
	MePageWaitError,
	type MePageWaitBlock,
} from '#sign-in-test-support/test-fixtures/me-page-request-tracker';

const origin = 'http://localhost:1';
const listPath = '/api/auth/passkey/list-user-passkeys';
const sessionPath = '/api/auth/get-session';

function newTracker(onBlocked?: (block: MePageWaitBlock) => void): {
	readonly tracker: ReturnType<typeof createMePageDocumentTracker>;
	readonly issue: (loaderId: string, requestId: string, path: string, type?: string) => void;
} {
	const tracker = createMePageDocumentTracker({
		origin,
		paths: [listPath, sessionPath],
		...(onBlocked === undefined ? {} : { onBlocked }),
	});
	return {
		tracker,
		issue: (loaderId, requestId, path, type = 'Fetch'): void =>
			tracker.observeRequestIssued({
				requestId,
				loaderId,
				method: 'GET',
				url: `${origin}${path}`,
				resourceType: type,
			}),
	};
}

async function failureOf(wait: Promise<unknown>): Promise<unknown> {
	return wait.then(
		() => null,
		(error: unknown) => (error instanceof MePageWaitError ? error.failure : error),
	);
}

it('does not let a request of the previous Me document stand in for the committed Me document', async () => {
	const { tracker, issue } = newTracker();
	// The previous document is also at /me. Its session request goes out after this tracker began
	// and ends when the next document commits; the pathname is the same, the loader is not.
	issue('old', 'old-session', sessionPath);
	tracker.observeMainFrameCommitted({ loaderId: 'new', pathname: '/me' });
	tracker.observeRequestTerminal({ requestId: 'old-session', outcome: 'failed', cancelled: true });
	issue('new', 'new-list', listPath);
	tracker.observeRequestTerminal({ requestId: 'new-list', outcome: 'finished', cancelled: false });
	let settled = false;
	void tracker.settled.then(() => {
		settled = true;
	});
	await Promise.resolve();
	expect(settled).toBe(false);
	issue('new', 'new-session', sessionPath);
	tracker.observeRequestTerminal({
		requestId: 'new-session',
		outcome: 'finished',
		cancelled: false,
	});
	expect([...(await tracker.settled)]).toEqual([
		[listPath, 'finished'],
		[sessionPath, 'finished'],
	]);
});

it('admits a path once per document, so a later request of the same path is not startup', async () => {
	const { tracker, issue } = newTracker();
	tracker.observeMainFrameCommitted({ loaderId: 'me', pathname: '/me' });
	issue('me', 'first-list', listPath);
	issue('me', 'second-list', listPath);
	issue('me', 'session', sessionPath);
	tracker.observeRequestTerminal({
		requestId: 'second-list',
		outcome: 'finished',
		cancelled: false,
	});
	tracker.observeRequestTerminal({ requestId: 'session', outcome: 'finished', cancelled: false });
	let settled = false;
	void tracker.settled.then(() => {
		settled = true;
	});
	await Promise.resolve();
	expect(settled).toBe(false);
	tracker.observeRequestTerminal({ requestId: 'first-list', outcome: 'failed', cancelled: false });
	expect([...(await tracker.settled)]).toEqual([
		[sessionPath, 'finished'],
		[listPath, 'failed'],
	]);
});

it('admits requests the document issued before its commit event arrived', async () => {
	const { tracker, issue } = newTracker();
	issue('me', 'list', listPath);
	issue('me', 'session', sessionPath);
	tracker.observeMainFrameCommitted({ loaderId: 'me', pathname: '/me' });
	tracker.observeRequestTerminal({ requestId: 'list', outcome: 'finished', cancelled: false });
	tracker.observeRequestTerminal({ requestId: 'session', outcome: 'finished', cancelled: false });
	expect((await tracker.settled).size).toBe(2);
});

it('ignores requests of another method, origin or path', async () => {
	const { tracker } = newTracker();
	tracker.observeMainFrameCommitted({ loaderId: 'me', pathname: '/me' });
	for (const [method, url] of [
		['POST', `${origin}${listPath}`],
		['GET', `http://elsewhere.invalid${listPath}`],
		['GET', `${origin}/api/auth/other`],
	] as const) {
		tracker.observeRequestIssued({
			requestId: url + method,
			loaderId: 'me',
			method,
			url,
			resourceType: 'Fetch',
		});
		tracker.observeRequestTerminal({
			requestId: url + method,
			outcome: 'finished',
			cancelled: false,
		});
	}
	let settled = false;
	void tracker.settled.then(() => {
		settled = true;
	});
	await Promise.resolve();
	expect(settled).toBe(false);
});

it('reports what a returned journey is blocked on, and only once it has returned', async () => {
	const blocks: MePageWaitBlock[] = [];
	const { tracker, issue } = newTracker((block) => blocks.push(block));
	tracker.observeMainFrameCommitted({ loaderId: 'me', pathname: '/me' });
	expect(blocks).toEqual([]);
	tracker.observeJourneyReturned();
	expect(blocks.at(-1)).toEqual({ openPaths: [], missingPaths: [listPath, sessionPath] });
	issue('me', 'session', sessionPath);
	expect(blocks.at(-1)).toEqual({ openPaths: [sessionPath], missingPaths: [listPath] });
});

it('fails with pageLost when the page closes before the requests end', async () => {
	const { tracker } = newTracker();
	tracker.observeMainFrameCommitted({ loaderId: 'me', pathname: '/me' });
	tracker.observePageLost('page closed');
	expect(await failureOf(tracker.settled)).toEqual({ kind: 'pageLost', reason: 'page closed' });
});

it('fails with documentLeft when another document commits first', async () => {
	const { tracker, issue } = newTracker();
	tracker.observeMainFrameCommitted({ loaderId: 'me', pathname: '/me' });
	issue('me', 'session', sessionPath);
	tracker.observeMainFrameCommitted({ loaderId: 'elsewhere', pathname: '/people' });
	expect(await failureOf(tracker.settled)).toEqual({ kind: 'documentLeft', loaderId: 'elsewhere' });
});

it('fails with mountFailed when a script of the document fails, but not when it is cancelled', async () => {
	const cancelled = newTracker();
	cancelled.tracker.observeMainFrameCommitted({ loaderId: 'me', pathname: '/me' });
	cancelled.issue('me', 'island', '/assets/island.js', 'Script');
	cancelled.tracker.observeRequestTerminal({
		requestId: 'island',
		outcome: 'failed',
		cancelled: true,
	});
	const failed = newTracker();
	failed.tracker.observeMainFrameCommitted({ loaderId: 'me', pathname: '/me' });
	failed.issue('me', 'island', '/assets/island.js', 'Script');
	failed.tracker.observeRequestTerminal({
		requestId: 'island',
		outcome: 'failed',
		cancelled: false,
	});
	expect(await failureOf(failed.tracker.settled)).toMatchObject({ kind: 'mountFailed' });
	let cancelledSettled = false;
	void cancelled.tracker.settled.then(
		() => {
			cancelledSettled = true;
		},
		() => {
			cancelledSettled = true;
		},
	);
	await Promise.resolve();
	expect(cancelledSettled).toBe(false);
});

it('fails with mountFailed when the document throws', async () => {
	const { tracker } = newTracker();
	tracker.observeMainFrameCommitted({ loaderId: 'me', pathname: '/me' });
	tracker.observeScriptError('boom');
	expect(await failureOf(tracker.settled)).toEqual({ kind: 'mountFailed', detail: 'boom' });
});

it('counts a request that finished before its document was claimed as finished', async () => {
	const { tracker, issue } = newTracker();
	issue('me', 'session', sessionPath);
	issue('me', 'list', listPath);
	// Both ended before the commit event reached the tracker; no completion is left to observe.
	tracker.observeRequestTerminal({ requestId: 'session', outcome: 'finished', cancelled: false });
	tracker.observeRequestTerminal({ requestId: 'list', outcome: 'failed', cancelled: false });
	tracker.observeMainFrameCommitted({ loaderId: 'me', pathname: '/me' });
	expect([...(await tracker.settled)]).toEqual([
		[sessionPath, 'finished'],
		[listPath, 'failed'],
	]);
});

it('fails with mountFailed for a script that failed before its document was claimed', async () => {
	const { tracker, issue } = newTracker();
	issue('me', 'island', '/assets/island.js', 'Script');
	tracker.observeRequestTerminal({ requestId: 'island', outcome: 'failed', cancelled: false });
	tracker.observeMainFrameCommitted({ loaderId: 'me', pathname: '/me' });
	expect(await failureOf(tracker.settled)).toMatchObject({ kind: 'mountFailed' });
});
