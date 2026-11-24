import type { HeldBrowserReply } from '#sign-in-test-support/test-fixtures/sign-in-navigation-layout';

interface PausedResponse {
	readonly requestId: string;
	readonly networkId?: string;
	readonly responseStatusCode?: number;
	readonly request: { readonly url: string };
}
interface HoldListeners {
	readonly requestIssued: (event: { requestId: string; loaderId: string }) => void;
	readonly mainFrameCommitted: (event: { frame: { parentId?: string; loaderId: string } }) => void;
	readonly paused: (event: PausedResponse) => void;
}
/** The part of a page-target protocol session this fixture drives, so its cleanup can be exercised without a browser. */
export interface HoldSession {
	on(event: 'Network.requestWillBeSent', listener: HoldListeners['requestIssued']): unknown;
	on(event: 'Page.frameNavigated', listener: HoldListeners['mainFrameCommitted']): unknown;
	on(event: 'Fetch.requestPaused', listener: HoldListeners['paused']): unknown;
	off(event: 'Network.requestWillBeSent', listener: HoldListeners['requestIssued']): unknown;
	off(event: 'Page.frameNavigated', listener: HoldListeners['mainFrameCommitted']): unknown;
	off(event: 'Fetch.requestPaused', listener: HoldListeners['paused']): unknown;
	send(
		method: 'Network.enable' | 'Network.disable' | 'Page.enable' | 'Page.disable' | 'Fetch.disable',
	): Promise<unknown>;
	send(method: 'Network.setCacheDisabled', params: { cacheDisabled: boolean }): Promise<unknown>;
	send(method: 'Fetch.continueResponse', params: { requestId: string }): Promise<unknown>;
	send(
		method: 'Fetch.enable',
		params: { patterns: { urlPattern: string; requestStage: 'Response' }[] },
	): Promise<unknown>;
}
/** The part of the proof page this fixture drives. */
export interface HoldableProof<TPage extends { isClosed(): boolean }> {
	readonly page: TPage;
	readonly context: { newCDPSession(page: NoInfer<TPage>): Promise<HoldSession> };
}

/**
 * How many holds on a page need the browser cache off. A cached response is never requested, so
 * it could not be held; Playwright turns the cache off the same way while it intercepts.
 */
const holdsNeedingNoCache = new WeakMap<object, number>();

async function acquireNoCache(session: HoldSession, page: object): Promise<void> {
	const count = (holdsNeedingNoCache.get(page) ?? 0) + 1;
	holdsNeedingNoCache.set(page, count);
	if (count === 1) await session.send('Network.setCacheDisabled', { cacheDisabled: true });
}

/** Counts the hold out even when the page is gone, and restores the cache when it was the last. */
async function releaseNoCache(
	session: HoldSession,
	page: object & { isClosed(): boolean },
): Promise<void> {
	const count = (holdsNeedingNoCache.get(page) ?? 1) - 1;
	holdsNeedingNoCache.set(page, count);
	if (count === 0 && !page.isClosed())
		await session.send('Network.setCacheDisabled', { cacheDisabled: false });
}

/**
 * Holds, once its headers have arrived, the first response to a request that the *committed*
 * main-frame document issued, and passes every other matching response through.
 *
 * The document is the first main-frame commit after the hold is created, told apart by the loader
 * id Chromium gives each committed document. A request of the document left behind, or one issued
 * before the commit, is not held whatever its URL. It pauses responses on a protocol session of its
 * own rather than a Playwright route, because a route cannot say which document issued a request.
 *
 * `close()` runs every cleanup step even when an earlier one fails, restores the cache last of all,
 * then reports the first failure. The session stays attached: detaching it breaks the page's later
 * WebAuthn registration. Its events stop and its listeners and request map go.
 */
export async function holdCommittedDocumentReply<TPage extends { isClosed(): boolean }>(
	proof: HoldableProof<TPage>,
	props: {
		/** CDP wildcard that narrows what the browser pauses. */
		readonly urlPattern: string;
		readonly matches: RegExp;
		readonly signal: AbortSignal;
	},
): Promise<HeldBrowserReply> {
	const { signal } = props;
	const session = await proof.context.newCDPSession(proof.page);
	const requested = Promise.withResolvers<number>();
	const release = Promise.withResolvers<void>();
	const ended = Promise.withResolvers<void>();
	void requested.promise.catch(() => undefined);
	void ended.promise.catch(() => undefined);
	const loaderOfRequest = new Map<string, string>();
	let committedLoaderId: string | null = null;
	let entered = false;
	let matchedRequests = 0;
	function abort(): void {
		requested.reject(signal.reason);
		release.resolve();
	}
	if (signal.aborted) abort();
	else signal.addEventListener('abort', abort, { once: true });
	const requestIssued: HoldListeners['requestIssued'] = (event): void => {
		loaderOfRequest.set(event.requestId, event.loaderId);
	};
	const mainFrameCommitted: HoldListeners['mainFrameCommitted'] = (event): void => {
		if (event.frame.parentId === undefined && committedLoaderId === null)
			committedLoaderId = event.frame.loaderId;
	};
	async function resume(requestId: string): Promise<void> {
		try {
			await session.send('Fetch.continueResponse', { requestId });
		} catch (error) {
			if (!proof.page.isClosed()) throw error;
		}
	}
	const paused: HoldListeners['paused'] = (event): void => {
		void (async (): Promise<void> => {
			if (!props.matches.test(event.request.url)) {
				await resume(event.requestId);
				return;
			}
			matchedRequests += 1;
			const issuedByCommittedDocument =
				committedLoaderId !== null &&
				event.networkId !== undefined &&
				loaderOfRequest.get(event.networkId) === committedLoaderId;
			if (entered || !issuedByCommittedDocument) {
				await resume(event.requestId);
				return;
			}
			entered = true;
			requested.resolve(event.responseStatusCode ?? 0);
			await release.promise;
			await resume(event.requestId);
			ended.resolve();
		})().catch((error: unknown): void => {
			requested.reject(error);
			ended.reject(error);
		});
	};
	session.on('Network.requestWillBeSent', requestIssued);
	session.on('Page.frameNavigated', mainFrameCommitted);
	session.on('Fetch.requestPaused', paused);
	let cacheHeld = false;
	let closing: Promise<void> | undefined;
	function close(): Promise<void> {
		closing ??= (async (): Promise<void> => {
			signal.removeEventListener('abort', abort);
			release.resolve();
			const failures: unknown[] = [];
			async function attempt(step: () => Promise<unknown>): Promise<void> {
				try {
					await step();
				} catch (error) {
					failures.push(error);
				}
			}
			if (!proof.page.isClosed()) {
				if (entered) await attempt(() => ended.promise);
				await attempt(() => session.send('Fetch.disable'));
				await attempt(() => session.send('Network.disable'));
				await attempt(() => session.send('Page.disable'));
			}
			session.off('Network.requestWillBeSent', requestIssued);
			session.off('Page.frameNavigated', mainFrameCommitted);
			session.off('Fetch.requestPaused', paused);
			loaderOfRequest.clear();
			if (cacheHeld) await attempt(() => releaseNoCache(session, proof.page));
			cacheHeld = false;
			const [first, ...rest] = failures;
			if (rest.length > 0) throw new AggregateError(failures, 'Hold cleanup failed');
			if (failures.length > 0) throw first;
		})();
		return closing;
	}
	try {
		await session.send('Network.enable');
		cacheHeld = true;
		await acquireNoCache(session, proof.page);
		await session.send('Page.enable');
		await session.send('Fetch.enable', {
			patterns: [{ urlPattern: props.urlPattern, requestStage: 'Response' }],
		});
	} catch (error) {
		await close().catch(() => undefined);
		throw error;
	}
	return {
		status: requested.promise,
		matchedRequests: () => matchedRequests,
		release: () => release.resolve(),
		close,
	};
}
