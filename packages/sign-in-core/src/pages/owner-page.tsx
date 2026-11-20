/** @jsxImportSource react */

import { GitHubIcon, GoogleIcon } from '@agent-collaboration/auth-ui/icons';
import {
	Button,
	Card,
	CardContent,
	CardDescription,
	CardFooter,
	CardHeader,
	CardTitle,
	Field,
	FieldDescription,
	FieldGroup,
	FieldLabel,
	Input,
} from '@agent-collaboration/tool-access-ui/server';
import * as React from 'react';

import type { FactorPageState } from '#sign-in-core/better-auth/factor-enrollment-page';
import type { SignInConfiguration } from '#sign-in-core/contracts/deployment-configuration';
import type { OrganizationChoice } from '#sign-in-core/contracts/organization-membership';
import type { OrganizationFleetState } from '#sign-in-core/organizations/organization-provisioning';
import { FactorControls } from '#sign-in-core/pages/factor-page';
import {
	IslandRoot,
	PageStatus,
	SetupSteps,
	type SetupStep,
} from '#sign-in-core/pages/page-document';
import { OrganizationChooserCard } from '#sign-in-core/pages/person-organization-choice';
import type { OrganizationId } from '#sign-in-core/storage/models/sign-in-store';

export interface OwnerPageProps {
	readonly ready: boolean;
	readonly continueLocation?: string;
	readonly configuration: SignInConfiguration;
	readonly resume: string | null;
	readonly createOrganization?: boolean;
	readonly noOrganization?: boolean;
	readonly showNavigationLink?: boolean;
	/** The selected organization's Fleet setup, shown to its owner (B2). */
	readonly organizationSetup?: {
		readonly organizationId: string;
		readonly state: OrganizationFleetState;
	};
	readonly factorPage?: FactorPageState;
	readonly memberships?: readonly OrganizationChoice[];
	readonly selectionRequired: boolean;
	readonly activeOrganizationId?: OrganizationId | null;
}

/** What the signed-in page still asks about organizations. The server decides:
 * an owner with no organization creates one; a member of several chooses one. */
type OrganizationTask = 'create' | 'choose' | 'none';

function organizationTaskOf(props: OwnerPageProps): OrganizationTask {
	if (props.selectionRequired) return 'choose';
	return props.createOrganization === true ? 'create' : 'none';
}

function factorStepPending(factorPage: FactorPageState): boolean {
	return factorPage === 'enroll-app' || factorPage === 'confirm';
}

/** One flow, in order: the second factor, then the organization step. The
 * same two steps, with the same titles, from start to finish: the factor step
 * is current until the person's second factor is confirmed, then done. The
 * organization step opens only after that. */
export function signInFlowSteps(
	factorPage: FactorPageState,
	organizationTask: Exclude<OrganizationTask, 'none'>,
): readonly SetupStep[] {
	const factorConfirmed = factorPage === 'confirmed';
	const organizationTitle =
		organizationTask === 'create' ? 'Create your organization' : 'Choose your organization';
	const organizationVerb = organizationTask === 'create' ? 'create' : 'choose';
	return [
		{
			title: 'Your second factor',
			status: factorConfirmed ? 'done' : 'current',
		},
		{
			title: organizationTitle,
			status: factorConfirmed ? 'current' : 'upcoming',
			note:
				factorPage === 'confirm'
					? `Confirm your second factor first, then ${organizationVerb} your organization.`
					: `Set up your authenticator app first, then confirm its code to ${organizationVerb} your organization.`,
		},
	];
}

/** The page heading names the page's current task (or the flow it belongs to). */
export function ownerPageTitle(props: OwnerPageProps): string {
	if (!props.ready) return 'Sign-in';
	const factorPage = props.factorPage ?? 'hidden';
	const organizationTask = organizationTaskOf(props);
	if (organizationTask === 'create' && factorPage !== 'hidden') return 'Set up your account';
	if (organizationTask === 'choose') {
		if (factorStepPending(factorPage)) return 'Finish signing in';
		return 'Choose your organization';
	}
	switch (factorPage) {
		case 'enroll-app':
			return 'Set up your second factor';
		case 'confirm':
			return 'Confirm your changes';
		case 'confirmed':
		case 'hidden':
			return 'Your account';
		default:
			return factorPage satisfies never;
	}
}

function SignInCard({
	configuration,
	continueLocation,
}: {
	readonly continueLocation: string;
	readonly configuration: SignInConfiguration;
}): React.ReactElement {
	return (
		<Card>
			<CardHeader>
				<CardDescription>Use your invited Google or GitHub account.</CardDescription>
			</CardHeader>
			<form id="owner-sign-in" className="flex flex-col gap-4">
				<CardContent>
					<div
						id="sign-in-captcha"
						data-sitekey={configuration.turnstile.siteKey}
						data-action="sign_in_social"
					/>
				</CardContent>
				<CardFooter className="flex flex-col gap-2">
					<Button type="submit" value="google" variant="outline" className="w-full">
						<GoogleIcon aria-hidden="true" data-icon="inline-start" />
						Continue with Google
					</Button>
					<Button type="submit" value="github" variant="outline" className="w-full">
						<GitHubIcon aria-hidden="true" data-icon="inline-start" />
						Continue with GitHub
					</Button>
					<div className="w-full">
						<IslandRoot state={{ kind: 'passkey-sign-in', continueLocation }} fallback={null} />
					</div>
					<div
						id="sign-in-passkey-captcha"
						data-sitekey={configuration.turnstile.siteKey}
						data-action="passkey_sign_in"
					/>
				</CardFooter>
			</form>
		</Card>
	);
}

function CreateOrganizationCard(): React.ReactElement {
	return (
		<Card>
			<form id="create-organization" className="flex flex-col gap-4">
				<CardContent>
					<FieldGroup>
						<Field>
							<FieldLabel htmlFor="organization-name">Name</FieldLabel>
							<Input id="organization-name" name="organizationName" required />
						</Field>
						<Field>
							<FieldLabel htmlFor="organization-slug">Short name</FieldLabel>
							<Input
								id="organization-slug"
								name="organizationSlug"
								pattern="[a-z0-9\-]+"
								aria-describedby="organization-slug-hint"
								required
							/>
							<FieldDescription id="organization-slug-hint">
								Used in links: lowercase letters, numbers, hyphens.
							</FieldDescription>
						</Field>
					</FieldGroup>
				</CardContent>
				<CardFooter>
					<Button type="submit" className="w-full">
						Create organization
					</Button>
				</CardFooter>
			</form>
		</Card>
	);
}

/** The one action when creating the organization is refused because the
 * second-factor confirmation has expired. Hidden until the page controller
 * reveals it; reloading the page returns the person to the confirm step. */
function ConfirmSecondFactorAgain(): React.ReactElement {
	return (
		<Button
			id="confirm-second-factor-again"
			type="button"
			variant="outline"
			className="w-full"
			hidden
		>
			Confirm again
		</Button>
	);
}

function MembershipChoices(props: OwnerPageProps): React.ReactElement | null {
	if ((props.memberships?.length ?? 0) === 0) return null;
	const choices = props.memberships ?? [];
	const activeOrganizationId = props.activeOrganizationId ?? null;
	return (
		<IslandRoot
			state={{ kind: 'person-organization-choice', choices, activeOrganizationId }}
			fallback={
				<OrganizationChooserCard
					choices={choices}
					activeOrganizationId={activeOrganizationId}
					pending
				/>
			}
		/>
	);
}

/** The signed-in page's continuation to the management CLI. It is the primary
 * action only on the plain account page; elsewhere it is a quiet footer link. */
function ContinueToCli(props: {
	readonly prominence: 'primary' | 'link';
	readonly disabled: boolean;
}): React.ReactElement {
	return (
		<form
			id="owner-sign-in"
			className={props.prominence === 'primary' ? 'flex w-full flex-col' : undefined}
		>
			<Button
				type="submit"
				disabled={props.disabled}
				variant={props.prominence === 'primary' ? 'default' : 'link'}
				className={props.prominence === 'primary' ? 'w-full' : 'text-muted-foreground'}
			>
				Continue to management CLI
			</Button>
		</form>
	);
}

/** Continuing to the CLI is the page's one task once nothing is left to set
 * up: no organization to choose, and no factor or organization step pending. */
function continueIsThePageTask(props: OwnerPageProps): boolean {
	const factorPage = props.factorPage ?? 'hidden';
	return (
		props.ready &&
		!props.selectionRequired &&
		(factorPage === 'hidden' || (factorPage === 'confirmed' && props.createOrganization !== true))
	);
}

/** B2's Fleet setup status for the selected organization, in one message.
 * Pending: what is happening and what to do, with Try again; the page
 * controller retries and rewrites the same message (Ready removes the form).
 * Ready: the message alone. The ids are the controller's and the tests'
 * contract. */
export const organizationSetupPendingMessage =
	"Switchboard hasn't finished setting up your organization yet. If this doesn't change, try again.";

function OrganizationSetupCard({
	setup,
}: {
	readonly setup: NonNullable<OwnerPageProps['organizationSetup']>;
}): React.ReactElement {
	const ready = setup.state === 'ready';
	return (
		<Card data-organization-id={setup.organizationId}>
			<CardHeader>
				<CardTitle>Fleet setup</CardTitle>
				<CardDescription id="organization-setup-state">
					{ready ? 'Ready' : organizationSetupPendingMessage}
				</CardDescription>
			</CardHeader>
			{!ready && (
				<CardFooter>
					<form
						id="retry-organization-provisioning"
						data-organization-id={setup.organizationId}
						className="flex w-full flex-col"
					>
						<Button type="submit" variant="outline" className="w-full">
							Try again
						</Button>
					</form>
				</CardFooter>
			)}
		</Card>
	);
}

export function OwnerPage(props: OwnerPageProps): React.ReactElement {
	if (!props.ready)
		return (
			<>
				<SignInCard
					configuration={props.configuration}
					continueLocation={props.continueLocation ?? '/owner-ready'}
				/>
				<PageStatus />
			</>
		);
	const factorPage = props.factorPage ?? 'hidden';
	if (continueIsThePageTask(props))
		return (
			<>
				<Card>
					<CardHeader>
						<CardDescription>
							{props.noOrganization === true
								? 'You do not belong to an organization.'
								: "You're signed in."}
						</CardDescription>
					</CardHeader>
					<CardFooter>
						<ContinueToCli prominence="primary" disabled={false} />
					</CardFooter>
				</Card>
				<PageStatus />
				<MembershipChoices {...props} />
				{props.organizationSetup !== undefined && (
					<OrganizationSetupCard setup={props.organizationSetup} />
				)}
				{factorPage === 'confirmed' && <FactorControls state={factorPage} resume={props.resume} />}
			</>
		);
	const organizationTask = organizationTaskOf(props);
	const factorPending = factorStepPending(factorPage);
	const steps =
		organizationTask !== 'none' &&
		factorPage !== 'hidden' &&
		!(organizationTask === 'choose' && factorPending)
			? signInFlowSteps(factorPage, organizationTask)
			: undefined;
	let currentTask: React.ReactElement;
	if (factorPending) currentTask = <FactorControls state={factorPage} resume={props.resume} />;
	else if (organizationTask === 'choose') currentTask = <MembershipChoices {...props} />;
	else if (organizationTask === 'create') currentTask = <CreateOrganizationCard />;
	else currentTask = <FactorControls state={factorPage} resume={props.resume} />;
	const creatingOrganization = !factorPending && organizationTask === 'create';
	return (
		<>
			{steps !== undefined && <SetupSteps steps={steps} />}
			{currentTask}
			{(organizationTask !== 'choose' || factorPending) && <MembershipChoices {...props} />}
			<PageStatus />
			{creatingOrganization && <ConfirmSecondFactorAgain />}
			{props.organizationSetup !== undefined && (
				<OrganizationSetupCard setup={props.organizationSetup} />
			)}
		</>
	);
}

/** Secondary actions under the page's one task. */
export function OwnerPageFooter(props: OwnerPageProps): React.ReactElement | undefined {
	if (props.showNavigationLink === true)
		return (
			<a className="font-medium text-foreground underline-offset-4 hover:underline" href="/me">
				Go to Me
			</a>
		);
	if (!props.ready || continueIsThePageTask(props)) return undefined;
	return <ContinueToCli prominence="link" disabled={props.selectionRequired} />;
}
