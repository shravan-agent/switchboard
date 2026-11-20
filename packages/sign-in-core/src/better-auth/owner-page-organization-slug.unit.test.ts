// @vitest-environment jsdom
import { createContext, Script } from 'node:vm';

import { expect, it } from 'vitest';

import { minimalOwnerPage } from '#sign-in-core/better-auth/minimal-owner-pages';
import { signInConfigurationSchema } from '#sign-in-core/contracts/deployment-configuration';
import type { SignInCrypto } from '#sign-in-core/contracts/sign-in-platform';

/** Known random bytes 00…0f, so every page's nonce is the same fixed value. */
const fixedBytesCrypto: SignInCrypto = {
	getRandomValues: (bytes) => {
		bytes.set(Array.from({ length: bytes.byteLength }, (_, index) => index % 256));
		return bytes;
	},
	subtle: globalThis.crypto.subtle,
};

const configuration = signInConfigurationSchema.parse({
	issuer: 'http://127.0.0.1:3000',
	mode: 'private',
	ownerEmail: 'owner@example.invalid',
	toolPortalOrigin: 'https://portal.invalid',
	managementAudience: 'https://portal.invalid/management',
	centralIdentityAudience: 'https://central.example.invalid/identity',
	centralAdminAudience: 'https://central.example.invalid/admin',
	centralPublicOrigin: 'https://central.example.invalid',
	adminPageClientId: 'admin-page-local',
	ownerFleetCliClientId: 'owner-fleet-cli-local',
	organizationStatementLifetimeSeconds: 10_368_000,
	organizationIds: ['11111111-1111-7111-8111-111111111111'],
	ownerCliClientId: 'owner-cli-local',
	ownerCliRedirectUri: 'http://127.0.0.1/callback',
	turnstile: { kind: 'local', siteKey: '1x00000000000000000000AA' },
});

/** Loads the served owner page and runs its delivered inline controllers. */
async function servedOrganizationForm(): Promise<{
	readonly name: HTMLInputElement;
	readonly slug: HTMLInputElement;
}> {
	const response = minimalOwnerPage({
		crypto: fixedBytesCrypto,
		ready: true,
		configuration,
		resume: null,
		factorPage: 'confirmed',
		createOrganization: true,
	});
	const served = new DOMParser().parseFromString(await response.text(), 'text/html');
	document.body.innerHTML = served.body.innerHTML;
	const context = createContext({
		document,
		HTMLFormElement,
		fetch: async (): Promise<Response> => Response.json([]),
		FormData,
		Uint8Array,
		atob,
		btoa,
		Error,
		location: { assign: (): void => undefined, reload: (): void => undefined },
		window: {},
	});
	// Classic inline controllers only: the island bootstrap is an inline module
	// this harness does not run, as it never ran the island bundle.
	for (const script of served.querySelectorAll('script'))
		if (!script.src && script.type !== 'module')
			new Script(script.textContent).runInContext(context);
	const name = document.querySelector('input[name="organizationName"]');
	const slug = document.querySelector('input[name="organizationSlug"]');
	if (!(name instanceof HTMLInputElement) || !(slug instanceof HTMLInputElement))
		throw new Error('The served organization form is missing');
	return { name, slug };
}

function typeInto(input: HTMLInputElement, value: string): void {
	input.value = value;
	input.dispatchEvent(new Event('input'));
}

it('derives the short name from the organization name until the person edits it', async () => {
	const { name, slug } = await servedOrganizationForm();

	typeInto(name, '  Research & Tools Lab!  ');
	expect(slug.value).toBe('research-tools-lab');
	expect(slug.checkValidity()).toBe(true);

	typeInto(slug, 'lab');
	typeInto(name, 'Renamed Lab');
	expect(slug.value).toBe('lab');

	typeInto(slug, '');
	typeInto(name, 'Renamed Lab');
	expect(slug.value).toBe('renamed-lab');
});
