/** @jsxImportSource react */
import { Button } from '@agent-collaboration/tool-access-ui/ui/button';
import { Separator } from '@agent-collaboration/tool-access-ui/ui/separator';
import {
	Sidebar,
	SidebarContent,
	SidebarGroup,
	SidebarInset,
	SidebarMenu,
	SidebarMenuButton,
	SidebarMenuItem,
	SidebarProvider,
	SidebarTrigger,
} from '@agent-collaboration/tool-access-ui/ui/sidebar';
import { ChevronDown, UserRound, UsersRound } from 'lucide-react';
import type * as React from 'react';

import {
	signedInNavigationRoutes,
	type SignedInNavigationState,
} from '#sign-in-core/contracts/sign-in-navigation';

export function SignedInShell(props: {
	readonly state: SignedInNavigationState;
	readonly switcher: React.ReactNode;
	readonly children: React.ReactNode;
}): React.ReactElement {
	const { page, destinations } = props.state;
	return (
		<SidebarProvider className="flex-col [--sidebar-width:16rem] [--sidebar-width-icon:3rem]">
			<header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-3 border-b bg-background px-4">
				<SidebarTrigger aria-label="Toggle navigation" />
				<Separator orientation="vertical" className="max-h-4" />
				<span className="text-sm font-semibold">Switchboard</span>
				<div className="ml-auto min-w-0">{props.switcher}</div>
			</header>
			<div className="flex min-w-0 flex-1">
				<Sidebar className="top-14 h-[calc(100svh-3.5rem)]">
					<SidebarContent>
						<SidebarGroup>
							<nav aria-label="Signed-in navigation">
								<SidebarMenu>
									{signedInNavigationRoutes
										.filter((route) => destinations.includes(route.path))
										.map((route) => (
											<SidebarMenuItem key={route.path}>
												<SidebarMenuButton
													render={<a href={route.path} />}
													aria-current={page === route.path ? 'page' : undefined}
													isActive={page === route.path}
												>
													{route.path === '/me' ? (
														<UserRound aria-hidden="true" />
													) : (
														<UsersRound aria-hidden="true" />
													)}
													<span>{route.label}</span>
												</SidebarMenuButton>
											</SidebarMenuItem>
										))}
								</SidebarMenu>
							</nav>
						</SidebarGroup>
					</SidebarContent>
				</Sidebar>
				<SidebarInset className="min-w-0">
					<div className="mx-auto flex w-full max-w-5xl flex-col gap-4 px-4 py-6 sm:px-6">
						<h1 className="text-xl font-semibold">{page === '/me' ? 'Me' : 'People'}</h1>
						{props.children}
					</div>
				</SidebarInset>
			</div>
		</SidebarProvider>
	);
}

export function organizationSwitcherButton(
	organizationName: string,
	disabled = false,
): React.ReactElement {
	return (
		<Button variant="outline" type="button" disabled={disabled} className="max-w-52">
			<span className="truncate">{organizationName}</span>
			<ChevronDown aria-hidden="true" />
		</Button>
	);
}
