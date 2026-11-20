/** @jsxImportSource react */
import { PasskeyManagementCard } from '@agent-collaboration/auth-ui';
import {
	Alert,
	AlertDescription,
	Button,
	Card,
	CardContent,
	CardDescription,
	CardFooter,
	CardHeader,
	CardTitle,
	Field,
	FieldLabel,
	Input,
} from '@agent-collaboration/tool-access-ui/server';
import * as React from 'react';
import { renderSVG } from 'uqr';

import type { FactorPageState } from '#sign-in-core/better-auth/factor-enrollment-page';
import {
	factorAction,
	FactorManagementCards,
	ownerReadyLocation,
} from '#sign-in-core/pages/factor-management-cards';
import { IslandRoot } from '#sign-in-core/pages/page-document';

function ConfirmationForm({ resume }: { readonly resume: string | null }): React.ReactElement {
	return (
		<form
			data-factor-form
			method="post"
			action={factorAction('verify-totp', resume)}
			className="flex flex-col gap-4"
		>
			<Field>
				<FieldLabel htmlFor="app-code">App code</FieldLabel>
				<Input
					id="app-code"
					name="code"
					inputMode="numeric"
					autoComplete="one-time-code"
					required
				/>
			</Field>
			<Button type="submit" className="w-full">
				Confirm app
			</Button>
		</form>
	);
}

function RecoveryCodes({ codes }: { readonly codes: readonly string[] }): React.ReactElement {
	return (
		<Card>
			<CardHeader>
				<CardTitle>
					<h2>Save your recovery codes</h2>
				</CardTitle>
				<CardDescription>
					Each code works once. Keep them somewhere safe. They will not be shown again.
				</CardDescription>
			</CardHeader>
			<CardContent>
				<ul className="grid grid-cols-1 gap-2 font-mono sm:grid-cols-2">
					{codes.map((code) => (
						<li key={code} className="break-all">
							<code>{code}</code>
						</li>
					))}
				</ul>
			</CardContent>
		</Card>
	);
}

export { ownerReadyLocation };

export type FactorPageContent =
	| {
			readonly kind: 'enrollment';
			readonly totpURI: string;
			readonly secret: string;
			readonly backupCodes: readonly string[];
	  }
	| { readonly kind: 'recovery-codes'; readonly backupCodes: readonly string[] }
	| { readonly kind: 'refused' }
	| { readonly kind: 'limited' };

export function FactorResponseContent({
	content,
	resume,
}: {
	readonly content: FactorPageContent;
	readonly resume: string | null;
}): React.ReactElement {
	switch (content.kind) {
		case 'enrollment':
			return (
				<>
					<Card>
						<CardHeader>
							<CardTitle>
								<h2>Set up your authenticator app</h2>
							</CardTitle>
							<CardDescription>
								Scan the code with your app, or enter the setup key manually.
							</CardDescription>
						</CardHeader>
						<CardContent className="flex flex-col gap-4 [&_code]:break-all">
							<figure
								id="factor-qr"
								aria-label="Authenticator setup QR code"
								className="flex justify-center [&_svg]:size-56 [&_svg]:max-w-full"
								dangerouslySetInnerHTML={{ __html: renderSVG(content.totpURI) }}
							/>
							<Field>
								<FieldLabel>Setup key</FieldLabel>
								<code id="totp-secret">{content.secret}</code>
							</Field>
							<details>
								<summary className="cursor-pointer text-muted-foreground">Setup URI</summary>
								<p className="mt-2">
									<code id="totp-uri">{content.totpURI}</code>
								</p>
							</details>
							<p className="text-xs text-muted-foreground">
								This is the only time the setup key is shown.
							</p>
						</CardContent>
					</Card>
					<RecoveryCodes codes={content.backupCodes} />
					<Card>
						<CardHeader>
							<CardTitle>
								<h2>Confirm your app</h2>
							</CardTitle>
						</CardHeader>
						<CardContent>
							<ConfirmationForm resume={resume} />
						</CardContent>
					</Card>
				</>
			);
		case 'recovery-codes':
			return (
				<IslandRoot
					state={{
						kind: 'recovery-codes',
						codes: [...content.backupCodes],
						ownerReadyLocation: ownerReadyLocation(resume),
					}}
					fallback={<RecoveryCodes codes={content.backupCodes} />}
				/>
			);
		case 'refused':
			return (
				<FactorRefusalCard resume={resume}>
					The change was refused. Confirm with your current app, passkey or a recovery code, then
					try again.
				</FactorRefusalCard>
			);
		case 'limited':
			return (
				<FactorRefusalCard resume={resume}>Wait a minute before trying again.</FactorRefusalCard>
			);
		default:
			return content satisfies never;
	}
}

/** An error page: one message, what to do, and one way back that keeps the
 * pending CLI authorization. The page heading names the problem. */
function FactorRefusalCard(props: {
	readonly resume: string | null;
	readonly children: React.ReactNode;
}): React.ReactElement {
	return (
		<Card>
			<CardContent>
				<Alert variant="destructive">
					<AlertDescription>{props.children}</AlertDescription>
				</Alert>
			</CardContent>
			<CardFooter>
				<Button
					className="w-full"
					nativeButton={false}
					render={<a href={ownerReadyLocation(props.resume)} />}
				>
					Back to your sign-in
				</Button>
			</CardFooter>
		</Card>
	);
}

/** The page heading for a factor response. */
export function factorResponseTitle(content: FactorPageContent): string {
	switch (content.kind) {
		case 'enrollment':
			return 'Authenticator setup';
		case 'recovery-codes':
			return 'New recovery codes';
		case 'refused':
			return 'Confirmation is needed';
		case 'limited':
			return 'Too many attempts';
		default:
			return content satisfies never;
	}
}

export function FactorControls({
	state,
	resume,
}: {
	readonly state: FactorPageState;
	readonly resume: string | null;
}): React.ReactElement | null {
	if (state === 'hidden') return null;
	if (state === 'enroll-app')
		return (
			<Card>
				<CardContent>
					<IslandRoot
						state={{
							kind: 'second-factor-enrollment',
							ownerReadyLocation: ownerReadyLocation(resume),
						}}
						fallback={
							<form
								data-factor-form
								method="post"
								action={factorAction('enable', resume)}
								className="flex flex-col gap-4"
							>
								<p className="text-sm text-muted-foreground">
									Start with an authenticator app and save its recovery codes. You can then add a
									passkey.
								</p>
								<input type="hidden" name="method" value="totp" />
								<Button type="submit" className="w-full">
									Set up authenticator app
								</Button>
							</form>
						}
					/>
				</CardContent>
			</Card>
		);
	if (state === 'confirm') return <ConfirmSecondFactorCard resume={resume} />;
	return <SecurityManagement resume={resume} />;
}

/** The confirm step: the app code is the primary way; a recovery code or a
 * passkey are the alternatives. */
function ConfirmSecondFactorCard({
	resume,
}: {
	readonly resume: string | null;
}): React.ReactElement {
	return (
		<Card>
			<CardContent className="flex flex-col gap-4">
				<IslandRoot
					state={{
						kind: 'second-factor-confirmation',
						ownerReadyLocation: ownerReadyLocation(resume),
					}}
					fallback={
						<div className="flex flex-col gap-4">
							<p className="text-sm text-muted-foreground">
								Enter the code from your authenticator app to confirm it's you before making a
								change.
							</p>
							<ConfirmationForm resume={resume} />
							<p className="text-center text-xs text-muted-foreground">or</p>
							<form
								data-factor-form
								method="post"
								action={factorAction('verify-backup-code', resume)}
								className="flex flex-col gap-2"
							>
								<Field>
									<FieldLabel htmlFor="recovery-code">Recovery code</FieldLabel>
									<Input id="recovery-code" name="code" autoComplete="off" required />
								</Field>
								<Button type="submit" variant="outline" className="w-full">
									Use recovery code
								</Button>
							</form>
						</div>
					}
				/>
				<Button type="button" id="confirm-passkey" variant="outline" className="w-full">
					Confirm with passkey
				</Button>
			</CardContent>
		</Card>
	);
}

/** Factor management once confirmed: secondary to the page's task. You must
 * always keep one working app or passkey. */
function SecurityManagement({ resume }: { readonly resume: string | null }): React.ReactElement {
	return (
		<section aria-labelledby="security-heading" className="flex flex-col gap-3">
			<h2 id="security-heading" className="text-sm font-medium">
				Security
			</h2>
			<IslandRoot
				state={{ kind: 'passkey-management' }}
				fallback={
					<PasskeyManagementCard
						addAction={
							<Button type="button" id="add-passkey" variant="outline">
								Add passkey
							</Button>
						}
					>
						<div id="passkey-list" className="flex flex-col gap-3" />
						<template id="passkey-row">
							<form className="flex flex-col gap-2">
								<Field>
									<FieldLabel>
										Passkey name
										<Input name="name" aria-label="Passkey name" />
									</FieldLabel>
								</Field>
								<div className="flex flex-wrap gap-2">
									<Button type="submit" variant="outline">
										Rename passkey
									</Button>
									<Button type="button" variant="destructive" data-remove-passkey>
										Remove passkey
									</Button>
								</div>
							</form>
						</template>
					</PasskeyManagementCard>
				}
			/>
			<FactorManagementCards resume={resume} />
		</section>
	);
}
