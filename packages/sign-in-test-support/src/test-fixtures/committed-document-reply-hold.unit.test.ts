import { expect, it } from 'vitest';

import {
	holdCommittedDocumentReply,
	type HoldSession,
} from '#sign-in-test-support/test-fixtures/committed-document-reply-hold';

interface FakeSession {
	readonly session: HoldSession;
	readonly sent: string[];
	readonly listenerCount: () => number;
	readonly emit: (event: string, payload: object) => void;
}

function fakeSession(failing: { readonly method?: string } = {}): FakeSession {
	const listeners = new Map<string, Set<(payload: never) => void>>();
	const sent: string[] = [];
	const session: HoldSession = {
		on(event: string, listener: (payload: never) => void): void {
			listeners.set(event, (listeners.get(event) ?? new Set()).add(listener));
		},
		off(event: string, listener: (payload: never) => void): void {
			listeners.get(event)?.delete(listener);
		},
		send(method: string, params?: object): Promise<unknown> {
			sent.push(
				method === 'Network.setCacheDisabled' ? `${method}:${JSON.stringify(params)}` : method,
			);
			return method === failing.method
				? Promise.reject(new Error(`${method} failed`))
				: Promise.resolve({});
		},
	};
	return {
		session,
		sent,
		listenerCount: (): number => [...listeners.values()].reduce((sum, set) => sum + set.size, 0),
		emit(event, payload): void {
			for (const listener of listeners.get(event) ?? []) listener(payload as never);
		},
	};
}

function fakeProof(session: HoldSession): {
	readonly page: { isClosed: () => boolean; closed: boolean };
	readonly context: { newCDPSession: () => Promise<HoldSession> };
} {
	const page = {
		closed: false,
		isClosed(): boolean {
			return this.closed;
		},
	};
	return { page, context: { newCDPSession: () => Promise.resolve(session) } };
}

const hold = { urlPattern: '*/api/*', matches: /\/api\//u, signal: new AbortController().signal };

it('removes its listeners and restores the cache on a clean close', async () => {
	const fake = fakeSession();
	const held = await holdCommittedDocumentReply(fakeProof(fake.session), hold);
	expect(fake.listenerCount()).toBe(3);
	await held.close();
	expect(fake.listenerCount()).toBe(0);
	expect(fake.sent.filter((sent) => sent.startsWith('Network.setCacheDisabled'))).toEqual([
		'Network.setCacheDisabled:{"cacheDisabled":true}',
		'Network.setCacheDisabled:{"cacheDisabled":false}',
	]);
});

it('restores the cache and removes its listeners when Fetch.disable fails, then reports the failure', async () => {
	const fake = fakeSession({ method: 'Fetch.disable' });
	const held = await holdCommittedDocumentReply(fakeProof(fake.session), hold);
	await expect(held.close()).rejects.toThrow('Fetch.disable failed');
	expect(fake.listenerCount()).toBe(0);
	expect(fake.sent.at(-1)).toBe('Network.setCacheDisabled:{"cacheDisabled":false}');
});

it('restores the cache when the held response cannot be resumed', async () => {
	const fake = fakeSession({ method: 'Fetch.continueResponse' });
	const held = await holdCommittedDocumentReply(fakeProof(fake.session), hold);
	fake.emit('Network.requestWillBeSent', { requestId: 'network-1', loaderId: 'document' });
	fake.emit('Page.frameNavigated', { frame: { loaderId: 'document' } });
	fake.emit('Fetch.requestPaused', {
		requestId: 'paused-1',
		networkId: 'network-1',
		responseStatusCode: 200,
		request: { url: 'http://localhost/api/list' },
	});
	expect(await held.status).toBe(200);
	await expect(held.close()).rejects.toThrow('Fetch.continueResponse failed');
	expect(fake.listenerCount()).toBe(0);
	expect(fake.sent.at(-1)).toBe('Network.setCacheDisabled:{"cacheDisabled":false}');
});

it('counts a hold out when the page is already gone, so the next hold disables the cache again', async () => {
	const fake = fakeSession();
	const proof = fakeProof(fake.session);
	const first = await holdCommittedDocumentReply(proof, hold);
	proof.page.closed = true;
	await first.close();
	proof.page.closed = false;
	const second = await holdCommittedDocumentReply(proof, hold);
	await second.close();
	expect(
		fake.sent.filter((sent) => sent === 'Network.setCacheDisabled:{"cacheDisabled":true}'),
	).toHaveLength(2);
});

it('restores the cache only after the last of two holds on one page closes', async () => {
	const fake = fakeSession();
	const proof = fakeProof(fake.session);
	const first = await holdCommittedDocumentReply(proof, hold);
	const second = await holdCommittedDocumentReply(proof, hold);
	await second.close();
	expect(fake.sent).not.toContain('Network.setCacheDisabled:{"cacheDisabled":false}');
	await first.close();
	expect(fake.sent.at(-1)).toBe('Network.setCacheDisabled:{"cacheDisabled":false}');
});
