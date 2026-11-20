import {
	Card,
	CardAction,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from '@agent-collaboration/tool-access-ui/ui/card';
import { Skeleton } from '@agent-collaboration/tool-access-ui/ui/skeleton';
import type * as React from 'react';

export function PasskeyListSkeleton(): React.ReactElement {
	return <Skeleton className="h-12 w-full" />;
}

export function PasskeyManagementCard(props: {
	readonly addAction: React.ReactNode;
	readonly children: React.ReactNode;
}): React.ReactElement {
	return (
		<Card>
			<CardHeader variant="divided">
				<CardTitle>
					<h2>Passkeys</h2>
				</CardTitle>
				<CardDescription>
					Add a passkey before replacing your app. You must always keep one working app or passkey.
				</CardDescription>
				<CardAction>{props.addAction}</CardAction>
			</CardHeader>
			<CardContent
				className="h-40 overflow-y-auto overscroll-contain sm:h-36"
				role="region"
				aria-label="Passkey list"
				tabIndex={0}
			>
				{props.children}
			</CardContent>
		</Card>
	);
}
