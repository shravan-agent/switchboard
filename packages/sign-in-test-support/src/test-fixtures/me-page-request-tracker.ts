export type MePageRequestOutcome = 'finished' | 'failed';

/** Why a Me page wait ended without every startup request ending. Each is an observed event, not elapsed time. */
export type MePageWaitFailure =
	| { readonly kind: 'pageLost'; readonly reason: string }
	| { readonly kind: 'documentLeft'; readonly loaderId: string }
	| { readonly kind: 'mountFailed'; readonly detail: string };

export class MePageWaitError extends Error {
	constructor(readonly failure: MePageWaitFailure) {
		super(`Me page wait failed: ${failure.kind}`);
		this.name = 'MePageWaitError';
	}
}

/** What a wait that has not ended is waiting for. */
export interface MePageWaitBlock {
	/** Startup requests the document issued that have no terminal event yet. */
	readonly openPaths: readonly string[];
	/** Startup requests the document has not issued yet. */
	readonly missingPaths: readonly string[];
}

/**
 * Follows the startup requests of one committed Me document, told apart from every other
 * document by its loader id, which Chromium gives each document it commits in the main frame.
 *
 * - The document is the first main-frame commit at `/me` after the tracker exists. A later
 *   main-frame commit ends the wait with `documentLeft`.
 * - Startup admission is per named path and closes when the document has issued that path once:
 *   later requests of the path belong to a user action, and that action's own journey awaits them.
 *   Requests of any other loader, whatever their pathname, are never admitted.
 * - The wait resolves when every named path was admitted and has a terminal event.
 * - It rejects with a `MePageWaitError` when the page is lost, a script of the document fails or
 *   throws (the island cannot mount), or another document commits first.
 * - Known gap: a named path that the document never requests is not an error here. The page
 *   publishes no event that says startup has issued every fetch it will issue, so nothing causal
 *   can end that wait; it shows up only as the suite watchdog, never as a false pass or a false failure.
 */
export function createMePageDocumentTracker(props: {
	readonly origin: string;
	readonly paths: readonly string[];
	/** Called each time the journey has returned and the wait is still pending, with what it waits for. */
	readonly onBlocked?: (block: MePageWaitBlock) => void;
}): {
	readonly observeMainFrameCommitted: (commit: {
		readonly loaderId: string;
		readonly pathname: string;
	}) => void;
	readonly observeRequestIssued: (request: {
		readonly requestId: string;
		readonly loaderId: string;
		readonly method: string;
		readonly url: string;
		readonly resourceType: string;
	}) => void;
	readonly observeRequestTerminal: (terminal: {
		readonly requestId: string;
		readonly outcome: MePageRequestOutcome;
		readonly cancelled: boolean;
	}) => void;
	readonly observeScriptError: (detail: string) => void;
	readonly observePageLost: (reason: string) => void;
	/** The journey that reaches Me has returned; from now on blocking is reported. */
	readonly observeJourneyReturned: () => void;
	/** Settles once every named path ended, or rejects with a `MePageWaitError`. */
	readonly settled: Promise<ReadonlyMap<string, MePageRequestOutcome>>;
} {
	interface IssuedRequest {
		readonly loaderId: string;
		readonly path: string | null;
		readonly isScript: boolean;
	}
	const requests = new Map<string, IssuedRequest>();
	/** Every terminal event by request id, kept so a request that ended before its loader was claimed still counts. */
	const terminals = new Map<
		string,
		{ readonly outcome: MePageRequestOutcome; readonly cancelled: boolean }
	>();
	const admittedByPath = new Map<string, string>();
	const outcomes = new Map<string, MePageRequestOutcome>();
	const settled = Promise.withResolvers<ReadonlyMap<string, MePageRequestOutcome>>();
	void settled.promise.catch(() => undefined);
	let claimedLoaderId: string | null = null;
	let journeyReturned = false;
	let ended = false;

	function fail(failure: MePageWaitFailure): void {
		if (ended) return;
		ended = true;
		settled.reject(new MePageWaitError(failure));
	}
	function missingPaths(): string[] {
		return props.paths.filter((path) => !admittedByPath.has(path));
	}
	function evaluate(): void {
		if (ended || claimedLoaderId === null) return;
		const missing = missingPaths();
		if (missing.length === 0 && outcomes.size === props.paths.length) {
			ended = true;
			settled.resolve(outcomes);
			return;
		}
		if (journeyReturned)
			props.onBlocked?.({
				openPaths: props.paths.filter((path) => admittedByPath.has(path) && !outcomes.has(path)),
				missingPaths: missing,
			});
	}
	function admitted(requestId: string): string | null {
		const request = requests.get(requestId);
		return request?.path !== null &&
			request?.path !== undefined &&
			request.loaderId === claimedLoaderId &&
			admittedByPath.get(request.path) === requestId
			? request.path
			: null;
	}
	function applyTerminal(requestId: string): void {
		if (ended) return;
		const terminal = terminals.get(requestId);
		const request = requests.get(requestId);
		if (terminal === undefined || request === undefined || request.loaderId !== claimedLoaderId)
			return;
		if (request.isScript && terminal.outcome === 'failed' && !terminal.cancelled) {
			fail({ kind: 'mountFailed', detail: 'a script of the document failed to load' });
			return;
		}
		const path = admitted(requestId);
		if (path === null || outcomes.has(path)) return;
		outcomes.set(path, terminal.outcome);
	}
	return {
		observeMainFrameCommitted(commit): void {
			if (ended) return;
			if (claimedLoaderId !== null) {
				if (commit.loaderId !== claimedLoaderId)
					fail({ kind: 'documentLeft', loaderId: commit.loaderId });
				return;
			}
			if (commit.pathname !== '/me') return;
			claimedLoaderId = commit.loaderId;
			// Requests the document issued before the commit event reached this observer.
			for (const [requestId, request] of requests) {
				if (
					request.loaderId === commit.loaderId &&
					request.path !== null &&
					!admittedByPath.has(request.path)
				)
					admittedByPath.set(request.path, requestId);
			}
			for (const requestId of requests.keys()) applyTerminal(requestId);
			evaluate();
		},
		observeRequestIssued(request): void {
			const url = new URL(request.url);
			const path =
				request.method === 'GET' &&
				url.origin === props.origin &&
				props.paths.includes(url.pathname)
					? url.pathname
					: null;
			requests.set(request.requestId, {
				loaderId: request.loaderId,
				path,
				isScript: request.resourceType === 'Script',
			});
			if (path !== null && request.loaderId === claimedLoaderId && !admittedByPath.has(path))
				admittedByPath.set(path, request.requestId);
			evaluate();
		},
		observeRequestTerminal(terminal): void {
			terminals.set(terminal.requestId, terminal);
			applyTerminal(terminal.requestId);
			evaluate();
		},
		observeScriptError(detail): void {
			if (claimedLoaderId !== null) fail({ kind: 'mountFailed', detail });
		},
		observePageLost(reason): void {
			fail({ kind: 'pageLost', reason });
		},
		observeJourneyReturned(): void {
			journeyReturned = true;
			evaluate();
		},
		settled: settled.promise,
	};
}
