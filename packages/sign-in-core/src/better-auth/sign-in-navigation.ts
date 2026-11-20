import type { FactorPageState } from '#sign-in-core/better-auth/factor-enrollment-page';
import { organizationChoiceAllows } from '#sign-in-core/better-auth/organization-permission-check';
import { readNativeOrganizationSessionView } from '#sign-in-core/better-auth/organization-read-session';
import type { SignInProvider } from '#sign-in-core/better-auth/provider-configuration';
import { requireStoredValue } from '#sign-in-core/better-auth/store-result-adapters';
import type { OrganizationChoice } from '#sign-in-core/contracts/organization-membership';
import { mintPageNonce } from '#sign-in-core/contracts/page-nonce';
import {
	signedInNavigationRoutes,
	type SignedInNavigationPath,
} from '#sign-in-core/contracts/sign-in-navigation';
import type { SignInPlatform } from '#sign-in-core/contracts/sign-in-platform';
import { readPersonOrganizationContext } from '#sign-in-core/organizations/person-organization-context';
import { renderSignedInNavigationPage } from '#sign-in-core/pages/signed-in-navigation-page';
import { decideRecentSecondFactor } from '#sign-in-core/second-factors/second-factor-step-up';
import { personIdSchema, type SignInStore } from '#sign-in-core/storage/models/sign-in-store';

interface SignedInNavigationAccount {
	readonly choices: readonly OrganizationChoice[];
	readonly activeOrganization: OrganizationChoice | null;
	readonly factorPage: FactorPageState;
	readonly email: string;
}

export async function readSignedInNavigationAccount(props: {
	readonly provider: SignInProvider;
	readonly headers: Headers;
	readonly store: Pick<SignInStore, 'organizations' | 'factors'>;
	readonly clock: SignInPlatform['clock'];
}): Promise<SignedInNavigationAccount | null> {
	const session = readNativeOrganizationSessionView(
		await props.provider.api.getSession({
			headers: props.headers,
			query: { disableCookieCache: true, disableRefresh: true },
		}),
	);
	if (session.kind === 'unavailable') throw new Error('Session unavailable');
	if (session.kind === 'signed-out') return null;

	const [organization, factors] = await Promise.all([
		readPersonOrganizationContext({ session, store: props.store.organizations }),
		props.store.factors.readSession(
			personIdSchema.parse(session.value.user.id),
			session.value.session.id,
		),
	]);
	if (organization.kind !== 'available') throw new Error('Organization context unavailable');
	const storedFactors = requireStoredValue(factors);
	const factorPage =
		storedFactors === null
			? 'hidden'
			: storedFactors.enrollment.kind === 'never-enrolled'
				? 'enroll-app'
				: decideRecentSecondFactor({
							now: props.clock.now(),
							confirmation: storedFactors.confirmation,
					  }).kind === 'confirmed'
					? 'confirmed'
					: 'confirm';
	return {
		choices: organization.choices,
		activeOrganization:
			organization.choices.find(
				(choice) => choice.organizationId === organization.activeOrganizationId,
			) ?? null,
		factorPage,
		email: session.value.user.email,
	};
}

export function hasPendingSignInContinuation(url: URL): boolean {
	return url.searchParams.has('authorize') || url.searchParams.has('client_id');
}

/** The link on the setup page and direct shell requests use the same facts. */
export function signedInNavigationMembership(
	account: SignedInNavigationAccount | null,
	url: URL,
): OrganizationChoice | null {
	if (account?.factorPage !== 'confirmed' || hasPendingSignInContinuation(url)) return null;
	return account.activeOrganization;
}

function redirectToSignInStep(location: string): Response {
	return new Response(null, { status: 303, headers: { location, 'cache-control': 'no-store' } });
}

export async function respondToSignedInNavigation(props: {
	readonly page: SignedInNavigationPath;
	readonly url: URL;
	readonly headers: Headers;
	readonly provider: SignInProvider;
	readonly store: SignInStore;
	readonly platform: SignInPlatform;
}): Promise<Response> {
	if (props.headers.has('authorization'))
		return Response.json(
			{ kind: 'refused' },
			{ status: 403, headers: { 'cache-control': 'no-store' } },
		);
	const account = await readSignedInNavigationAccount({ ...props, clock: props.platform.clock });
	if (account === null) return redirectToSignInStep('/sign-in');
	const activeOrganization = signedInNavigationMembership(account, props.url);
	if (activeOrganization === null) return redirectToSignInStep(`/owner-ready${props.url.search}`);

	const destinations = signedInNavigationRoutes
		.filter(
			(route) =>
				route.permission === 'person' ||
				organizationChoiceAllows(activeOrganization.role, route.permission),
		)
		.map((route) => route.path);
	if (!destinations.includes(props.page))
		return Response.json(
			{ kind: 'refused' },
			{ status: 403, headers: { 'cache-control': 'no-store' } },
		);
	return renderSignedInNavigationPage({
		nonce: mintPageNonce(props.platform.crypto),
		state: {
			page: props.page,
			activeOrganization,
			choices: account.choices,
			destinations,
			showOrganizationAdmin: activeOrganization.role === 'owner',
		},
	});
}
