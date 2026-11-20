import type { Response } from 'playwright';
import { z } from 'zod';

import { withNativeBrowserCleanup } from '#sign-in-test-support/test-fixtures/native-browser-cleanup';
import type { NativeAwaitObserver } from '#sign-in-test-support/test-fixtures/native-browser-progress';
import type { PlaywrightBrowserPage } from '#sign-in-test-support/test-fixtures/playwright-browser';
import type { BrowserNetworkResponse } from '#sign-in-test-support/test-fixtures/playwright-network';

export const nativePasskeyRegistrationReady =
	"!!document.querySelector('#security-heading') && [...document.querySelectorAll('[data-sign-in-island][data-sign-in-island-mounted]')].some(root=>{try{return JSON.parse(root.dataset.islandState||'null')?.kind==='passkey-management'&&[...root.querySelectorAll('button')].some(button=>button.textContent.trim()==='Add passkey'&&!button.disabled);}catch{return false;}})";

export const nativePasskeyRegistrationButton =
	'[data-sign-in-island][data-sign-in-island-mounted] button';
export const nativePasskeyRegistrationBinding = 'reportNativePasskeyRegistration';

const controllerSchema = z.enum(['island', 'legacy', 'other']);
const browserEventSchema = z.discriminatedUnion('kind', [
	z.strictObject({ kind: z.literal('installed') }),
	z.strictObject({
		kind: z.literal('state'),
		mounted: z.boolean(),
		ready: z.boolean(),
		legacyStatus: z.boolean(),
		islandAlert: z.boolean(),
	}),
	z.strictObject({
		kind: z.literal('input'),
		phase: z.enum(['down', 'up', 'click']),
		controller: controllerSchema,
		expectedControl: z.boolean(),
		trusted: z.boolean(),
		mounted: z.boolean(),
	}),
	z.strictObject({
		kind: z.literal('create'),
		phase: z.enum(['entered', 'fulfilled', 'rejected', 'threw']),
		controller: controllerSchema,
		mounted: z.boolean(),
		credentialPresent: z.boolean().optional(),
	}),
]);

type RegistrationEvent =
	| z.infer<typeof browserEventSchema>
	| { readonly kind: 'created' }
	| { readonly kind: 'options-requested' }
	| { readonly kind: 'options-response'; readonly status: number };

export interface NativePasskeyRegistrationRecord {
	readonly sequence: number;
	readonly event: RegistrationEvent;
}

export interface NativePasskeyRegistrationObservation {
	readonly install: (
		page: Pick<PlaywrightBrowserPage, 'evaluate'>,
		observe: NativeAwaitObserver,
	) => Promise<void>;
	readonly finish: () => Promise<void>;
}

/** Observe only controller/phase booleans; native arguments, results and errors are never emitted. */
export const nativePasskeyRegistrationScript = `(()=>{
if(globalThis.__nativePasskeyRegistrationObservation)throw new Error('Registration observation already installed');
const binding=globalThis.${nativePasskeyRegistrationBinding};
if(typeof binding!=='function')throw new Error('Registration observation binding missing');
const credentials=navigator.credentials;
if(!credentials||typeof credentials.create!=='function')throw new Error('Native credential creation missing');
function emit(event){try{binding(JSON.stringify(event));}catch{/* Diagnostics must not change the native producer. */}}
function managementRoot(){return [...document.querySelectorAll('[data-sign-in-island]')].find(root=>{try{return JSON.parse(root.dataset.islandState||'null')?.kind==='passkey-management';}catch{return false;}});}
function state(){const root=managementRoot();return {mounted:!!root?.hasAttribute('data-sign-in-island-mounted'),ready:(${nativePasskeyRegistrationReady}),legacyStatus:!!document.getElementById('status')?.textContent?.trim(),islandAlert:!!root?.querySelector('[role="alert"]')?.textContent?.trim()};}
let lastState='';
function changed(){const current=state();const serialized=JSON.stringify(current);if(serialized!==lastState){lastState=serialized;emit({kind:'state',...current});}}
let activationController='other';
for(const [name,phase] of [['mousedown','down'],['mouseup','up'],['click','click']])document.addEventListener(name,event=>{
const button=typeof event.target?.closest==='function'?event.target.closest('button'):null;
const root=managementRoot();
const expectedControl=!!button&&!!root?.contains(button)&&button.textContent.trim()==='Add passkey';
const mounted=!!root?.hasAttribute('data-sign-in-island-mounted');
const controller=expectedControl?(button.id==='add-passkey'?'legacy':mounted?'island':'other'):'other';
if(phase==='click')activationController=controller;
emit({kind:'input',phase,controller,expectedControl,trusted:event.isTrusted,mounted});
},true);
const originalCreate=credentials.create;
credentials.create=function(...args){
const controller=activationController;const mounted=state().mounted;
emit({kind:'create',phase:'entered',controller,mounted});
try{const pending=Reflect.apply(originalCreate,this,args);
void pending.then(value=>emit({kind:'create',phase:'fulfilled',controller,mounted,credentialPresent:value!==null&&value!==undefined}),()=>emit({kind:'create',phase:'rejected',controller,mounted}));
return pending;
}catch(error){emit({kind:'create',phase:'threw',controller,mounted});throw error;}
};
const observer=new MutationObserver(changed);
observer.observe(document,{subtree:true,childList:true,characterData:true,attributes:true,attributeFilter:['data-sign-in-island-mounted','disabled']});
globalThis.__nativePasskeyRegistrationObservation={ready:()=>state().ready};
emit({kind:'installed'});changed();return true;
})()`;

export interface NativePasskeyRegistrationTransport {
	readonly addBinding: () => Promise<void>;
	readonly subscribe: (
		event: 'Runtime.bindingCalled' | 'Network.requestWillBeSent' | 'Network.responseReceived',
		listener: (value: unknown) => void,
	) => () => void;
}

/** One owner serializes a private trace; finishing cannot await an uncompleted browser operation. */
export function createNativePasskeyRegistrationObservation(props: {
	readonly transport: NativePasskeyRegistrationTransport;
	readonly issuer: string;
	readonly write: (record: NativePasskeyRegistrationRecord) => Promise<void>;
}): NativePasskeyRegistrationObservation {
	let sequence = 0;
	let accepting = true;
	let pendingWrite = Promise.resolve();
	let failure: { readonly kind: 'none' } | { readonly kind: 'failed'; readonly error: unknown } = {
		kind: 'none',
	};
	function record(event: RegistrationEvent): void {
		if (!accepting) return;
		const entry = { sequence: ++sequence, event };
		pendingWrite = pendingWrite
			.then(() => props.write(entry))
			.catch((error: unknown): void => {
				if (failure.kind === 'none') failure = { kind: 'failed', error };
			});
	}
	async function drain(): Promise<void> {
		await pendingWrite;
		if (failure.kind === 'failed') throw failure.error;
	}
	function isOptions(url: string): boolean {
		try {
			const parsed = new URL(url);
			return (
				parsed.origin === props.issuer &&
				parsed.pathname === '/api/auth/passkey/generate-register-options'
			);
		} catch {
			return false;
		}
	}
	const subscriptions = [
		props.transport.subscribe('Runtime.bindingCalled', (value): void => {
			const binding = z.object({ name: z.string(), payload: z.string() }).safeParse(value);
			if (!binding.success || binding.data.name !== nativePasskeyRegistrationBinding) return;
			try {
				const event = browserEventSchema.parse(JSON.parse(binding.data.payload));
				record(event);
			} catch {
				const error = new Error('Registration observation event schema mismatch');
				if (failure.kind === 'none') failure = { kind: 'failed', error };
			}
		}),
		props.transport.subscribe('Network.requestWillBeSent', (value): void => {
			const request = z.object({ request: z.object({ url: z.string() }) }).safeParse(value);
			if (request.success && isOptions(request.data.request.url))
				record({ kind: 'options-requested' });
		}),
		props.transport.subscribe('Network.responseReceived', (value): void => {
			const response = z
				.object({ response: z.object({ url: z.string(), status: z.number().int() }) })
				.safeParse(value);
			if (response.success && isOptions(response.data.response.url))
				record({ kind: 'options-response', status: response.data.response.status });
		}),
	];
	record({ kind: 'created' });
	return {
		install: async (page, observe): Promise<void> => {
			await drain();
			await observe('registration: observation binding', () => props.transport.addBinding());
			await observe('registration: observation installation', () =>
				page.evaluate(nativePasskeyRegistrationScript, z.literal(true)),
			);
			await drain();
		},
		finish: async (): Promise<void> => {
			accepting = false;
			for (const unsubscribe of subscriptions) unsubscribe();
			await drain();
		},
	};
}

const committedPasskeyList =
	"[...document.querySelectorAll('[data-sign-in-island][data-sign-in-island-mounted]')].some(root=>{try{const state=JSON.parse(root.dataset.islandState||'null');return state?.kind==='passkey-management'&&(root.querySelector('[data-slot=item]')!==null||[...root.querySelectorAll('p')].some(paragraph=>paragraph.textContent?.trim()==='No passkeys yet.'));}catch{return false;}})";

/** Wait for the delivered list render before measuring the control that follows it. */
export async function registerNativePasskey(props: {
	readonly page: PlaywrightBrowserPage;
	readonly initialListResponse: Promise<Response>;
	readonly observeAwait: NativeAwaitObserver;
	readonly observeCleanup: NativeAwaitObserver;
}): Promise<BrowserNetworkResponse> {
	const { page, observeAwait, observeCleanup } = props;
	page.recordAwait('registration: initial list response');
	const listResponse = await observeAwait(
		'registration: initial list response',
		() => props.initialListResponse,
	);
	if (listResponse.status() !== 200) throw new Error('Initial passkey list request failed');
	page.recordAwait('registration: initial list response body completion');
	const responseFailure = await observeAwait(
		'registration: initial list response body completion',
		() => listResponse.finished(),
	);
	if (responseFailure !== null) throw responseFailure;
	await page.readyWhen(committedPasskeyList, 'registration: committed initial list render', () =>
		page.recordPasskeyListCommit(),
	);
	await observeAwait('registration: mounted island control readiness', () =>
		page.readyWhen(nativePasskeyRegistrationReady, 'registration: mounted Add passkey control'),
	);
	const registrationError = page.evaluate(
		`new Promise((resolve,reject)=>{const root=[...document.querySelectorAll('[data-sign-in-island]')].find(node=>JSON.parse(node.dataset.islandState).kind==='passkey-management');if(!root)throw new Error('Passkey management root missing');const inspect=()=>{const error=root.querySelector('[role="alert"]');if(error?.textContent?.trim())resolve(error.textContent.trim());};const observer=new MutationObserver(inspect);observer.observe(root,{childList:true,subtree:true,characterData:true});window.cancelPasskeyRegistrationObservation=()=>{observer.disconnect();reject(new Error('Registration observation cancelled'));};inspect();})`,
		z.string(),
	);
	void registrationError.catch(() => undefined);
	return withNativeBrowserCleanup(
		() =>
			observeAwait('registration: verify response or browser rejection', () =>
				Promise.race([
					page.responseTo('/api/auth/passkey/verify-registration', () =>
						page.click(nativePasskeyRegistrationButton, 'Add passkey'),
					),
					registrationError.then((message): never => {
						throw new Error('Browser rejected registration before native verification: ' + message);
					}),
				]),
			),
		() =>
			observeCleanup('registration: cancel browser rejection observation', () =>
				page.evaluate(
					`(()=>{window.cancelPasskeyRegistrationObservation?.();delete window.cancelPasskeyRegistrationObservation;return true;})()`,
					z.literal(true),
					observeCleanup,
				),
			).then((): void => {}),
	);
}
