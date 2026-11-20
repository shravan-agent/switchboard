/** @jsxImportSource react */
import {
	Button,
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
	Spinner,
} from '@agent-collaboration/tool-access-ui/server';
import type * as React from 'react';

export function factorAction(path: string, resume: string | null): string {
	return `/api/auth/two-factor/${path}${resume === null ? '' : `?authorize=${encodeURIComponent(resume)}`}`;
}

export function ownerReadyLocation(resume: string | null): string {
	return `/owner-ready${resume === null ? '' : `?authorize=${encodeURIComponent(resume)}`}`;
}

/** A factor form's submit button. Its spinner is hidden until the factor
 * form controller marks the request pending, like every other pending button. */
function FactorSubmitButton({
	children,
}: {
	readonly children: React.ReactNode;
}): React.ReactElement {
	return (
		<Button type="submit" variant="outline">
			<span data-pending-indicator hidden>
				<Spinner />
			</span>
			{children}
		</Button>
	);
}

export function FactorManagementCards({
	resume,
}: {
	readonly resume: string | null;
}): React.ReactElement {
	return (
		<>
			<Card>
				<CardHeader>
					<CardTitle>Recovery codes</CardTitle>
					<CardDescription>Replacing them makes your current codes stop working.</CardDescription>
				</CardHeader>
				<CardContent>
					<form
						data-factor-form
						method="post"
						action={factorAction('generate-backup-codes', resume)}
					>
						<FactorSubmitButton>Replace recovery codes</FactorSubmitButton>
					</form>
				</CardContent>
			</Card>
			<Card>
				<CardHeader>
					<CardTitle>Authenticator app</CardTitle>
					<CardDescription>
						To change phones, remove the app, then set up the replacement.
					</CardDescription>
				</CardHeader>
				<CardContent className="flex flex-wrap gap-2">
					<form data-factor-form method="post" action={factorAction('remove-app', resume)}>
						<FactorSubmitButton>Remove app before replacing it</FactorSubmitButton>
					</form>
					<form data-factor-form method="post" action={factorAction('enable', resume)}>
						<input type="hidden" name="method" value="totp" />
						<FactorSubmitButton>Set up replacement app</FactorSubmitButton>
					</form>
				</CardContent>
			</Card>
		</>
	);
}
