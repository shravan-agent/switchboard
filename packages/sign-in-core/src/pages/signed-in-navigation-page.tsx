/** @jsxImportSource react */
import { PasskeyListSkeleton, PasskeyManagementCard } from '@agent-collaboration/auth-ui';
import { Button, Card, CardContent, Skeleton } from '@agent-collaboration/tool-access-ui/server';
import type * as React from 'react';

import { factorFormScript } from '#sign-in-core/better-auth/factor-form-script';
import type { PageNonce } from '#sign-in-core/contracts/page-nonce';
import type { SignedInNavigationState } from '#sign-in-core/contracts/sign-in-navigation';
import { MeSecurity, SignOutCard } from '#sign-in-core/pages/me-security';
import {
	IslandRoot,
	PageStatus,
	pageDocument,
	signInPagesIslandScript,
} from '#sign-in-core/pages/page-document';
import { SignedInShell, organizationSwitcherButton } from '#sign-in-core/pages/signed-in-shell';

function SignedInNavigationFallback({
	state,
}: {
	readonly state: SignedInNavigationState;
}): React.ReactElement {
	return (
		<SignedInShell
			state={state}
			switcher={organizationSwitcherButton(state.activeOrganization.organizationName, true)}
		>
			<PageStatus />
			{state.page === '/me' ? (
				<MeSecurity
					passkeys={
						<PasskeyManagementCard
							addAction={
								<Button type="button" variant="outline" disabled>
									Add passkey
								</Button>
							}
						>
							<PasskeyListSkeleton />
						</PasskeyManagementCard>
					}
					signOut={<SignOutCard />}
				/>
			) : (
				<Card>
					<CardContent>
						<Skeleton className="h-16 w-full" />
						<noscript>Enable JavaScript to read this organization's people.</noscript>
					</CardContent>
				</Card>
			)}
		</SignedInShell>
	);
}

export function renderSignedInNavigationPage(props: {
	readonly nonce: PageNonce;
	readonly state: SignedInNavigationState;
}): Response {
	const document = pageDocument({
		title: props.state.page === '/me' ? 'Me' : 'People',
		nonce: props.nonce,
		layout: 'shell',
		challenge: 'none',
		scripts: factorFormScript() + signInPagesIslandScript,
		children: (
			<IslandRoot
				state={{ kind: 'signed-in-navigation', navigation: props.state }}
				fallback={<SignedInNavigationFallback state={props.state} />}
			/>
		),
	});
	return new Response(document.html, { headers: document.headers });
}
