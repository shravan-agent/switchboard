// @vitest-environment jsdom
import { createContext, Script } from 'node:vm';

import { expect, it, vi } from 'vitest';

import { factorFormScript } from '#sign-in-core/better-auth/factor-form-script';

it.each([
	{ path: 'enable', name: 'method', value: 'totp', expected: '{"method":"totp"}' },
	{ path: 'verify-totp', name: 'code', value: '123456', expected: '{"code":"123456"}' },
])(
	'the $path form submits native JSON and uses server-rendered HTML',
	async ({ path, name, value, expected }) => {
		// The DOM/form path is real; the HTTP server and returned page are outside
		// this transport claim. Public-host tests exercise that native server path.
		document.body.innerHTML = `<form data-factor-form action="/api/auth/two-factor/${path}"><input name="${name}" value="${value}"><button type="submit">Continue</button></form><p id="status"></p>`;
		const form = document.querySelector('form');
		const button = document.querySelector('button');
		if (!(form instanceof HTMLFormElement) || !(button instanceof HTMLButtonElement))
			throw new Error('Factor form test is incomplete');
		const written = Promise.withResolvers<string>();
		const fetch = vi.fn(
			async (_url: string, _init: RequestInit): Promise<Response> =>
				new Response('<main>Server setup page</main>', {
					headers: { 'content-type': 'text/html' },
				}),
		);
		const context = createContext({
			document: {
				addEventListener: (type: string, listener: EventListener): void =>
					document.addEventListener(type, listener, { once: true }),
				getElementById: (id: string): HTMLElement | null => document.getElementById(id),
				open: (): void => undefined,
				write: (html: string): void => written.resolve(html),
				close: (): void => undefined,
			},
			HTMLFormElement,
			FormData,
			fetch,
			location: {
				assign: (): void => {
					throw new Error('Setup response should not redirect');
				},
			},
			Error,
		});
		new Script(
			factorFormScript()
				.replace(/^<script>/u, '')
				.replace(/<\/script>$/u, ''),
		).runInContext(context);
		form.requestSubmit(button);
		expect(await written.promise).toBe('<main>Server setup page</main>');
		expect(fetch).toHaveBeenCalledTimes(1);
		const call = fetch.mock.calls[0];
		if (call === undefined) throw new Error('Factor form did not send a request');
		expect(new URL(call[0]).pathname).toBe(`/api/auth/two-factor/${path}`);
		expect(new Headers(call[1].headers).get('content-type')).toBe('application/json');
		expect(new Headers(call[1].headers).get('accept')).toBe('text/html');
		expect(call[1].body).toBe(expected);
	},
);

/** Browsers' nonce: per the HTML spec the `nonce` property sets an internal
 * slot and never the content attribute, so serialized markup keeps whatever
 * attribute it had. jsdom reflects the property into the attribute instead,
 * which would hide a controller that only sets the property. */
class BrowserNonceDomParser {
	parseFromString(html: string, type: DOMParserSupportedType): Document {
		const parsed = new DOMParser().parseFromString(html, type);
		for (const script of parsed.querySelectorAll('script')) {
			let nonceSlot = script.getAttribute('nonce') ?? '';
			Object.defineProperty(script, 'nonce', {
				configurable: true,
				get: (): string => nonceSlot,
				set: (value: string): void => {
					nonceSlot = value;
				},
			});
		}
		return parsed;
	}
}

it('keeps the active document nonce when a form replaces its page, without rewriting controller source', async () => {
	document.body.innerHTML =
		'<form data-factor-form action="/api/auth/two-factor/enable"><input name="method" value="totp"><button>Continue</button></form>';
	const form = document.querySelector('form');
	const button = document.querySelector('button');
	if (!(form instanceof HTMLFormElement) || !(button instanceof HTMLButtonElement))
		throw new Error('Missing form');
	const written = Promise.withResolvers<string>();
	const controller = 'const attribute = \'nonce="literal-in-source"\';';
	const context = createContext({
		document: {
			currentScript: { nonce: 'active-document-nonce' },
			addEventListener: (type: string, listener: EventListener): void =>
				document.addEventListener(type, listener, { once: true }),
			open: (): void => undefined,
			write: (html: string): void => written.resolve(html),
			close: (): void => undefined,
		},
		DOMParser: BrowserNonceDomParser,
		HTMLFormElement,
		FormData,
		fetch: async (): Promise<Response> =>
			new Response(
				`<html><head></head><body><script nonce="response-document-nonce">${controller}</script></body></html>`,
				{ headers: { 'content-type': 'text/html' } },
			),
	});
	new Script(
		factorFormScript()
			.replace(/^<script>/u, '')
			.replace(/<\/script>$/u, ''),
	).runInContext(context);
	form.requestSubmit(button);
	const page = new DOMParser().parseFromString(await written.promise, 'text/html');
	// The written markup is what the next document parses, so its attribute must carry the nonce.
	expect(page.querySelector('script')?.getAttribute('nonce')).toBe('active-document-nonce');
	expect(page.querySelector('script')?.textContent).toBe(controller);
});

it('shows the pending button spinner while the request runs and hides it again when it fails', async () => {
	document.body.innerHTML =
		'<form data-factor-form action="/api/auth/two-factor/generate-backup-codes"><button type="submit"><span data-pending-indicator hidden><svg data-slot="spinner"></svg></span>Replace recovery codes</button></form><p id="status"></p>';
	const form = document.querySelector('form');
	const button = document.querySelector('button');
	const spinner = document.querySelector('[data-pending-indicator]');
	if (!(form instanceof HTMLFormElement) || !(button instanceof HTMLButtonElement) || !spinner)
		throw new Error('Factor form test is incomplete');
	const response = Promise.withResolvers<Response>();
	const context = createContext({
		document: {
			addEventListener: (type: string, listener: EventListener): void =>
				document.addEventListener(type, listener, { once: true }),
			getElementById: (id: string): HTMLElement | null => document.getElementById(id),
		},
		HTMLFormElement,
		FormData,
		fetch: async (): Promise<Response> => response.promise,
		Error,
	});
	new Script(
		factorFormScript()
			.replace(/^<script>/u, '')
			.replace(/<\/script>$/u, ''),
	).runInContext(context);
	form.requestSubmit(button);
	expect({
		disabled: button.disabled,
		busy: button.getAttribute('aria-busy'),
		spinnerHidden: spinner.hasAttribute('hidden'),
	}).toEqual({ disabled: true, busy: 'true', spinnerHidden: false });
	response.reject(new Error('network down'));
	await vi.waitFor(() =>
		expect(document.getElementById('status')?.textContent).toBe(
			'Factor confirmation is unavailable. Please try again.',
		),
	);
	expect({
		disabled: button.disabled,
		busy: button.getAttribute('aria-busy'),
		spinnerHidden: spinner.hasAttribute('hidden'),
	}).toEqual({ disabled: false, busy: null, spinnerHidden: true });
});
