/** @jsxImportSource react */
import { Alert } from '@agent-collaboration/tool-access-ui/ui/alert';
import {
	DropdownMenu,
	DropdownMenuContent,
	DropdownMenuGroup,
	DropdownMenuItem,
	DropdownMenuLabel,
	DropdownMenuRadioGroup,
	DropdownMenuRadioItem,
	DropdownMenuSeparator,
	DropdownMenuTrigger,
} from '@agent-collaboration/tool-access-ui/ui/dropdown-menu';
import * as React from 'react';

import {
	signedInNavigationRoutes,
	signOutFailureMessage,
	type SignedInNavigationState,
} from '#sign-in-core/contracts/sign-in-navigation';
import {
	setActivePersonOrganization,
	switchPersonOrganization,
} from '#sign-in-core/pages/islands/person-organization-choice';
import { MeSecurity, SignOutCard } from '#sign-in-core/pages/me-security';
import { SignedInShell, organizationSwitcherButton } from '#sign-in-core/pages/signed-in-shell';

function OrganizationSwitcher({
	navigation,
}: {
	readonly navigation: SignedInNavigationState;
}): React.ReactElement {
	const pending = React.useRef(false);
	const [switching, setSwitching] = React.useState(false);
	function switchOrganization(organizationId: string): void {
		if (pending.current || organizationId === navigation.activeOrganization.organizationId) return;
		pending.current = true;
		setSwitching(true);
		void switchPersonOrganization(organizationId, {
			setActive: setActivePersonOrganization,
			// A fresh server route resolves both successful switches and lost responses.
			// The first table entry is person-scoped for every ready membership.
			replace: (): void => location.assign(signedInNavigationRoutes[0].path),
		});
	}

	return (
		<DropdownMenu>
			<DropdownMenuTrigger
				render={organizationSwitcherButton(
					navigation.activeOrganization.organizationName,
					switching,
				)}
			/>
			<DropdownMenuContent align="end" className="min-w-48">
				<DropdownMenuGroup>
					<DropdownMenuLabel>Switch organization</DropdownMenuLabel>
					<DropdownMenuRadioGroup
						value={navigation.activeOrganization.organizationId}
						onValueChange={switchOrganization}
					>
						{navigation.choices.map((choice) => (
							<DropdownMenuRadioItem key={choice.organizationId} value={choice.organizationId}>
								<span className="min-w-0 break-words">{choice.organizationName}</span>
								<span className="ml-auto text-muted-foreground">
									{choice.role === 'owner' ? 'Owner' : 'Member'}
								</span>
							</DropdownMenuRadioItem>
						))}
					</DropdownMenuRadioGroup>
				</DropdownMenuGroup>
				{navigation.showOrganizationAdmin && (
					<>
						<DropdownMenuSeparator />
						<DropdownMenuItem render={<a href="/organization-admin" />}>
							Organization admin
						</DropdownMenuItem>
					</>
				)}
			</DropdownMenuContent>
		</DropdownMenu>
	);
}

function SignOut(): React.ReactElement {
	const [state, setState] = React.useState<'ready' | 'pending' | 'failed'>('ready');
	const pending = React.useRef(false);
	function submit(event: React.FormEvent<HTMLFormElement>): void {
		event.preventDefault();
		if (pending.current) return;
		pending.current = true;
		setState('pending');
		void fetch(event.currentTarget.action, { method: 'POST', redirect: 'manual' })
			.then((response): void => {
				if (response.type !== 'opaqueredirect') throw new Error(signOutFailureMessage);
				location.replace('/sign-in');
			})
			.catch((): void => {
				pending.current = false;
				setState('failed');
			});
	}
	return (
		<>
			<SignOutCard busy={state === 'pending'} onSubmit={submit} />
			{state === 'failed' && (
				<Alert role="alert" variant="destructive">
					{signOutFailureMessage}
				</Alert>
			)}
		</>
	);
}

export function SignedInNavigation(props: {
	readonly navigation: SignedInNavigationState;
	readonly passkeys: React.ReactNode;
	readonly people: React.ReactNode;
}): React.ReactElement {
	React.useEffect(() => {
		function revalidate(event: PageTransitionEvent): void {
			if (event.persisted) location.reload();
		}
		window.addEventListener('pageshow', revalidate);
		return (): void => window.removeEventListener('pageshow', revalidate);
	}, []);

	return (
		<SignedInShell
			state={props.navigation}
			switcher={<OrganizationSwitcher navigation={props.navigation} />}
		>
			<Alert
				id="status"
				role="status"
				aria-live="polite"
				variant="destructive"
				className="empty:hidden"
			/>
			{props.navigation.page === '/me' ? (
				<MeSecurity passkeys={props.passkeys} signOut={<SignOut />} />
			) : (
				props.people
			)}
		</SignedInShell>
	);
}
