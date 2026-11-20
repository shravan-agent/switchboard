/** @jsxImportSource react */
import { Button } from '@agent-collaboration/tool-access-ui/ui/button';
import {
	Card,
	CardAction,
	CardDescription,
	CardHeader,
	CardTitle,
} from '@agent-collaboration/tool-access-ui/ui/card';
import type * as React from 'react';

import { switchboardSignOutPath } from '#sign-in-core/contracts/sign-in-navigation';
import { FactorManagementCards } from '#sign-in-core/pages/factor-management-cards';

export function MeSecurity(props: {
	readonly passkeys: React.ReactNode;
	readonly signOut: React.ReactNode;
}): React.ReactElement {
	return (
		<section aria-labelledby="security-heading" className="flex flex-col gap-3">
			<h2 id="security-heading" className="text-sm font-medium">
				Security
			</h2>
			{props.passkeys}
			<FactorManagementCards resume={null} />
			{props.signOut}
		</section>
	);
}

export function SignOutCard(props: {
	readonly busy?: boolean;
	readonly onSubmit?: React.FormEventHandler<HTMLFormElement>;
}): React.ReactElement {
	return (
		<Card>
			<CardHeader>
				<CardTitle>Current session</CardTitle>
				<CardDescription>End this browser session.</CardDescription>
				<CardAction>
					<form method="post" action={switchboardSignOutPath} onSubmit={props.onSubmit}>
						<Button type="submit" variant="outline" disabled={props.busy}>
							Sign out
						</Button>
					</form>
				</CardAction>
			</CardHeader>
		</Card>
	);
}
