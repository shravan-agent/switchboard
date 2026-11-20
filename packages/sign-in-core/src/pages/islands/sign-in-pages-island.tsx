/** @jsxImportSource react */
/** Browser entry for the sign-in pages: Better Auth UI components rendered
 * into the server's island roots. The server-rendered native controls inside
 * each root stay as the no-script fallback; Better Auth's endpoints still
 * decide every effect. */
// First: no schema may be constructed before zod's JIT is switched off.
import '#sign-in-core/pages/islands/zod-without-jit';
import {
	AuthProvider,
	BackupCodes,
	ConfirmSecondFactorStep,
	EnableTwoFactorStep,
	PasskeyManager,
	PasskeyButton,
	passkeyPlugin,
	twoFactorPlugin,
} from '@agent-collaboration/auth-ui';
import { Button } from '@agent-collaboration/tool-access-ui/ui/button';
import { Card, CardContent } from '@agent-collaboration/tool-access-ui/ui/card';
import { Toaster } from '@agent-collaboration/tool-access-ui/ui/sonner';
import { passkeyClient } from '@better-auth/passkey/client';
import { QueryClient } from '@tanstack/react-query';
import { twoFactorClient } from 'better-auth/client/plugins';
import { createAuthClient } from 'better-auth/react';
import type * as React from 'react';
import { createPortal } from 'react-dom';
import { createRoot, type Root } from 'react-dom/client';

import type {
	OrganizationPeopleListRequest,
	OrganizationPersonLookupRequest,
} from '#sign-in-core/contracts/organization-membership';
import {
	OrganizationPeople,
	type OrganizationPeopleTransport,
} from '#sign-in-core/pages/islands/organization-people';
import { attachPasskeySignInTurnstile } from '#sign-in-core/pages/islands/passkey-sign-in-turnstile';
import { PersonOrganizationChoice } from '#sign-in-core/pages/islands/person-organization-choice';
import {
	signInIslandAttribute,
	signInIslandStateSchema,
	type SignInIslandState,
} from '#sign-in-core/pages/islands/sign-in-island-state';
import { SignedInNavigation } from '#sign-in-core/pages/islands/signed-in-navigation';

const authClient = createAuthClient({
	plugins: [twoFactorClient(), passkeyClient()],
	fetchOptions: { onRequest: attachPasskeySignInTurnstile },
});
const queryClient = new QueryClient();

/** Stable across island renders so another island mounting cannot restart a pending read. */
const organizationPeopleTransport: OrganizationPeopleTransport = {
	list: async (request: OrganizationPeopleListRequest): Promise<unknown> => {
		let reply: unknown;
		await authClient.$fetch<unknown>('/organization/people-list', {
			method: 'GET',
			query: request,
			onResponse: async ({ response }): Promise<void> => {
				reply = await response.clone().json();
			},
		});
		return reply;
	},
	lookup: async (request: OrganizationPersonLookupRequest): Promise<unknown> => {
		let reply: unknown;
		await authClient.$fetch<unknown>('/organization/person-membership', {
			method: 'POST',
			body: request,
			onResponse: async ({ response }): Promise<void> => {
				reply = await response.clone().json();
			},
		});
		return reply;
	},
};

/** The sign-in service's audited passkey removal route (not Better Auth's delete). */
async function removePasskey(passkeyId: string): Promise<void> {
	const result = await authClient.$fetch('/passkey/remove', {
		method: 'POST',
		body: { id: passkeyId },
	});
	if (result.error !== null) throw new Error('Passkey removal was refused');
}

function NavigationLink(props: {
	readonly href: string;
	readonly className?: string;
	readonly children?: React.ReactNode;
}): React.ReactElement {
	return (
		<a href={props.href} className={props.className}>
			{props.children}
		</a>
	);
}

function PagePasskeyManager(): React.ReactElement {
	return (
		<PasskeyManager
			removePasskey={removePasskey}
			labels={{
				empty: 'No passkeys yet.',
				add: 'Add passkey',
				rename: 'Rename',
				save: 'Save',
				cancel: 'Cancel',
				remove: 'Remove',
				name: 'Passkey name',
				unnamed: 'Passkey',
				failed:
					"That passkey change didn't complete. If it was cancelled, try again; if it needs a recent confirmation, confirm with your app first.",
			}}
		/>
	);
}

function SignInPageContent({ state }: { readonly state: SignInIslandState }): React.ReactElement {
	switch (state.kind) {
		case 'passkey-sign-in':
			return <PasskeyButton />;
		case 'second-factor-enrollment':
			return (
				<EnableTwoFactorStep
					onFinished={() => location.assign(state.ownerReadyLocation)}
					labels={{
						start: 'Set up authenticator app',
						startDescription:
							'Use an authenticator app on your phone. You will scan a code, enter the six digits it shows, then save your recovery codes.',
						scanDescription: 'Scan this with your authenticator app, then enter the code it shows.',
						verify: 'Confirm app',
						savedCodes: "I've saved my recovery codes",
					}}
				/>
			);
		case 'second-factor-confirmation':
			return (
				<ConfirmSecondFactorStep
					onConfirmed={() => location.assign(state.ownerReadyLocation)}
					labels={{
						appCodeDescription:
							"Enter the code from your authenticator app to confirm it's you before making a change.",
						confirm: 'Confirm',
						recoveryCode: 'Recovery code',
						recoveryCodeDescription:
							'Enter one of the recovery codes you saved when you set up your app. Each code works once.',
						useRecoveryCode: 'Use a recovery code instead',
						useAppCode: 'Use your authenticator app instead',
					}}
				/>
			);
		case 'person-organization-choice':
			return (
				<PersonOrganizationChoice
					choices={state.choices}
					activeOrganizationId={state.activeOrganizationId}
				/>
			);
		case 'organization-people':
			return (
				<OrganizationPeople
					key={state.organizationId}
					organizationId={state.organizationId}
					organizationName={state.organizationName}
					transport={organizationPeopleTransport}
				/>
			);
		case 'passkey-management':
			return <PagePasskeyManager />;
		case 'signed-in-navigation': {
			const active = state.navigation.activeOrganization;
			return (
				<SignedInNavigation
					navigation={state.navigation}
					passkeys={<PagePasskeyManager />}
					people={
						<OrganizationPeople
							key={active.organizationId}
							organizationId={active.organizationId}
							organizationName={active.organizationName}
							transport={organizationPeopleTransport}
						/>
					}
				/>
			);
		}
		case 'recovery-codes':
			return (
				<Card>
					<CardContent className="flex flex-col gap-4">
						<BackupCodes codes={[...state.codes]} />
						<Button className="w-full" onClick={() => location.assign(state.ownerReadyLocation)}>
							I've saved my recovery codes
						</Button>
					</CardContent>
				</Card>
			);
		default: {
			const unhandled = state satisfies never;
			throw new Error(`Unhandled sign-in island state: ${JSON.stringify(unhandled)}`);
		}
	}
}

function IslandProviders({
	children,
	continueLocation,
}: {
	readonly children: React.ReactNode;
	readonly continueLocation: string;
}): React.ReactElement {
	return (
		<AuthProvider
			authClient={authClient}
			queryClient={queryClient}
			navigate={({ to }) => location.assign(to)}
			Link={NavigationLink}
			plugins={[twoFactorPlugin({ allowPasswordless: true }), passkeyPlugin({ autoFill: false })]}
			redirectTo={continueLocation}
		>
			{children}
		</AuthProvider>
	);
}

interface MountedIsland {
	readonly root: HTMLElement;
	readonly state: SignInIslandState;
}

/** The React tree of the document currently shown. A factor form replaces the
 * page with document.write, which keeps this window and so this module: its
 * old container is then gone, and the next mount starts a new tree. */
let pageTree: {
	readonly container: HTMLElement;
	readonly reactRoot: Root;
	readonly islands: MountedIsland[];
} | null = null;

const mountedIslandAttribute = 'data-sign-in-island-mounted';

/** Mounts the page's island roots. Each page calls it from its inline module
 * bootstrap, including a page a factor form writes: the bundle is evaluated
 * once per window, so mounting cannot be an import side effect. Idempotent: a
 * root already mounted is skipped. One tree per page, with each root a portal
 * under one auth provider, so one ErrorToaster watches the shared query
 * client and a failure is toasted at most once. */
export function mountSignInIslands(page: Document): void {
	if (pageTree !== null && !pageTree.container.isConnected) {
		pageTree.reactRoot.unmount();
		pageTree = null;
	}
	const added: MountedIsland[] = [];
	for (const root of page.querySelectorAll<HTMLElement>(`[${signInIslandAttribute}]`)) {
		if (root.hasAttribute(mountedIslandAttribute)) continue;
		const parsedState = signInIslandStateSchema.safeParse(
			JSON.parse(root.dataset['islandState'] ?? 'null'),
		);
		if (!parsedState.success) continue;
		// The island replaces the root's no-script fallback.
		root.replaceChildren();
		root.setAttribute(mountedIslandAttribute, '');
		added.push({ root, state: parsedState.data });
	}
	if (added.length === 0) return;
	if (pageTree === null) {
		const container = page.createElement('div');
		page.body.append(container);
		pageTree = { container, reactRoot: createRoot(container), islands: [] };
	}
	pageTree.islands.push(...added);
	const passkeyState = pageTree.islands.find(
		(island) => island.state.kind === 'passkey-sign-in',
	)?.state;
	pageTree.reactRoot.render(
		<IslandProviders
			continueLocation={
				passkeyState?.kind === 'passkey-sign-in' ? passkeyState.continueLocation : '/owner-ready'
			}
		>
			{pageTree.islands.map(({ root, state }, index) =>
				createPortal(<SignInPageContent state={state} />, root, String(index)),
			)}
			<Toaster />
		</IslandProviders>,
	);
}
