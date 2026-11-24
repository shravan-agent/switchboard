import {
	createMePageDocumentTracker,
	type MePageWaitBlock,
} from '#sign-in-test-support/test-fixtures/me-page-request-tracker';
import type { PlaywrightBrowserPage } from '#sign-in-test-support/test-fixtures/playwright-browser';

export interface MePageDocumentObservation {
	readonly tracker: ReturnType<typeof createMePageDocumentTracker>;
	/** Removes every listener this observation installed. */
	readonly stop: () => Promise<void>;
}

/**
 * Feeds a Me document tracker from the proof page's own Chromium protocol events: the main-frame
 * commit and its loader id, each request with the loader id of the document that issued it, and
 * the request's terminal event. Nothing here waits for time.
 */
export async function observeMePageDocument(props: {
	readonly proof: PlaywrightBrowserPage;
	readonly origin: string;
	readonly paths: readonly string[];
	readonly onBlocked?: (block: MePageWaitBlock) => void;
}): Promise<MePageDocumentObservation> {
	const { proof } = props;
	const { protocol, page } = proof;
	const tracker = createMePageDocumentTracker({
		origin: props.origin,
		paths: props.paths,
		...(props.onBlocked === undefined ? {} : { onBlocked: props.onBlocked }),
	});
	const committed = (event: {
		frame: { parentId?: string; loaderId: string; url: string };
	}): void => {
		if (event.frame.parentId !== undefined) return;
		tracker.observeMainFrameCommitted({
			loaderId: event.frame.loaderId,
			pathname: new URL(event.frame.url).pathname,
		});
	};
	const issued = (event: {
		requestId: string;
		loaderId: string;
		type?: string;
		request: { method: string; url: string };
	}): void =>
		tracker.observeRequestIssued({
			requestId: event.requestId,
			loaderId: event.loaderId,
			method: event.request.method,
			url: event.request.url,
			resourceType: event.type ?? 'Other',
		});
	const finished = (event: { requestId: string }): void =>
		tracker.observeRequestTerminal({
			requestId: event.requestId,
			outcome: 'finished',
			cancelled: false,
		});
	const failed = (event: { requestId: string; canceled?: boolean }): void =>
		tracker.observeRequestTerminal({
			requestId: event.requestId,
			outcome: 'failed',
			cancelled: event.canceled === true,
		});
	const pageError = (error: Error): void => tracker.observeScriptError(error.message);
	const closed = (): void => tracker.observePageLost('page closed');
	const crashed = (): void => tracker.observePageLost('page crashed');
	protocol.on('Page.frameNavigated', committed);
	protocol.on('Network.requestWillBeSent', issued);
	protocol.on('Network.loadingFinished', finished);
	protocol.on('Network.loadingFailed', failed);
	page.on('pageerror', pageError);
	page.on('close', closed);
	page.on('crash', crashed);
	await protocol.send('Page.enable');
	return {
		tracker,
		stop(): Promise<void> {
			protocol.off('Page.frameNavigated', committed);
			protocol.off('Network.requestWillBeSent', issued);
			protocol.off('Network.loadingFinished', finished);
			protocol.off('Network.loadingFailed', failed);
			page.off('pageerror', pageError);
			page.off('close', closed);
			page.off('crash', crashed);
			return Promise.resolve();
		},
	};
}
