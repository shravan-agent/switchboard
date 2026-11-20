import type { BetterAuthPlugin, GenericEndpointContext } from '@better-auth/core';
import { createAuthEndpoint } from 'better-auth/api';
import { z } from 'zod';

import { checkOrganizationPermission } from '#sign-in-core/better-auth/organization-permission-check';
import {
	readStoredOrganizationSession,
	organizationReadResponseHeaders,
} from '#sign-in-core/better-auth/organization-read-session';
import {
	organizationPeopleListRequestSchema,
	organizationPersonLookupRequestSchema,
	type OrganizationPeopleListReply,
	type OrganizationPeopleListRequest,
	type OrganizationPersonLookupReply,
	type OrganizationPersonLookupRequest,
} from '#sign-in-core/contracts/organization-membership';
import { mintPageNonce } from '#sign-in-core/contracts/page-nonce';
import { organizationPeoplePermission } from '#sign-in-core/contracts/sign-in-navigation';
import type { SignInPlatform } from '#sign-in-core/contracts/sign-in-platform';
import {
	transitionCheckedRead,
	type CheckedReadEvent,
	type CheckedReadState,
} from '#sign-in-core/organizations/checked-read-transitions';
import { readPersonOrganizationContext } from '#sign-in-core/organizations/person-organization-context';
import { renderOrganizationPeoplePage } from '#sign-in-core/pages/organization-people-page';
import {
	organizationIdSchema,
	personIdSchema,
	type OrganizationId,
	type SignInStore,
} from '#sign-in-core/storage/models/sign-in-store';

type ReadPermission =
	| { readonly kind: 'allowed' }
	| { readonly kind: 'refused'; readonly status: 401 | 403 }
	| { readonly kind: 'unavailable' };
type CheckedRequest =
	| { readonly kind: 'lookup'; readonly value: OrganizationPersonLookupRequest }
	| { readonly kind: 'list'; readonly value: OrganizationPeopleListRequest };
type CheckedReply = {
	readonly status: 200 | 401 | 403 | 503;
	readonly body: OrganizationPeopleListReply | OrganizationPersonLookupReply;
};

/** Four cookie-bound reads; no endpoint writes or treats the active choice as permission. */
export function createOrganizationMembershipReadPlugin(props: {
	readonly store: {
		readonly persons: Pick<SignInStore['persons'], 'readPersonSession'>;
		readonly organizations: Pick<
			SignInStore['organizations'],
			| 'membershipsForPerson'
			| 'readMemberRole'
			| 'readPersonMembershipFacts'
			| 'listOrganizationPeople'
		>;
	};
	readonly platform: Pick<SignInPlatform, 'clock' | 'crypto'>;
}): BetterAuthPlugin {
	async function checkReadPermission(
		context: GenericEndpointContext,
		organizationId: OrganizationId,
	): Promise<ReadPermission> {
		if (context.headers?.has('authorization')) return { kind: 'refused', status: 401 };
		const acquired = readStoredOrganizationSession(context.context.session);
		if (acquired.kind === 'unavailable') return acquired;
		if (acquired.kind === 'signed-out') return { kind: 'refused', status: 401 };
		try {
			const live = await props.store.persons.readPersonSession(
				acquired.value.user.id,
				acquired.value.session.id,
			);
			if (live.kind === 'store-unavailable') return { kind: 'unavailable' };
			if (live.value === null) return { kind: 'refused', status: 401 };
			if (live.value.session.activeOrganizationId !== organizationId)
				return { kind: 'refused', status: 403 };
			const permission = await checkOrganizationPermission({
				context,
				personId: personIdSchema.parse(live.value.user.id),
				organizationId,
				permission: organizationPeoplePermission,
				readMemberRole: props.store.organizations.readMemberRole,
			});
			if (permission.kind === 'store-unavailable') return { kind: 'unavailable' };
			return permission.value ? { kind: 'allowed' } : { kind: 'refused', status: 403 };
		} catch {
			return { kind: 'unavailable' };
		}
	}
	async function checkedRead(
		context: GenericEndpointContext,
		request: CheckedRequest,
	): Promise<CheckedReply> {
		let state: CheckedReadState = { state: 'start', kind: request.kind };
		function apply(event: CheckedReadEvent): void {
			const result = transitionCheckedRead(state, event, { now: props.platform.clock.now() });
			if (result.kind !== 'next') throw new Error('Invalid checked read sequence');
			state = result.state;
		}
		function refused(check: Exclude<ReadPermission, { readonly kind: 'allowed' }>): CheckedReply {
			apply({ kind: check.kind === 'unavailable' ? 'store-failed' : 'check-failed' });
			return check.kind === 'unavailable'
				? { status: 503, body: { kind: 'unavailable' } }
				: { status: check.status, body: { kind: 'refused' } };
		}
		const first = await checkReadPermission(context, request.value.organizationId);
		if (first.kind !== 'allowed') return refused(first);
		apply({ kind: 'first-check-passed' });
		try {
			switch (request.kind) {
				case 'lookup': {
					const facts = await props.store.organizations.readPersonMembershipFacts(request.value);
					if (facts.kind === 'store-unavailable') return refused({ kind: 'unavailable' });
					apply({ kind: 'facts-read', facts: { kind: 'lookup', value: facts.value } });
					break;
				}
				case 'list': {
					const facts = await props.store.organizations.listOrganizationPeople(request.value);
					if (facts.kind === 'store-unavailable') return refused({ kind: 'unavailable' });
					apply({ kind: 'facts-read', facts: { kind: 'list', value: facts.value } });
					break;
				}
				default:
					request satisfies never;
			}
		} catch {
			return refused({ kind: 'unavailable' });
		}
		const second = await checkReadPermission(context, request.value.organizationId);
		if (second.kind !== 'allowed') return refused(second);
		apply({ kind: 'second-check-passed' });
		// Reading through a closure avoids a false control-flow narrowing across apply().
		const finalState = (): CheckedReadState => state;
		const answered = finalState();
		if (answered.state !== 'answered') throw new Error('Checked read has no releasable answer');
		return { status: 200, body: answered.result };
	}
	return {
		id: 'organization-membership-reads',
		endpoints: {
			readPersonOrganizationContext: createAuthEndpoint(
				'/organization/self-context',
				{ method: 'GET', query: z.unknown() },
				async (context) => {
					organizationReadResponseHeaders(context);
					if (!z.strictObject({}).safeParse(context.query ?? {}).success) {
						context.setStatus(400);
						return context.json({ error: 'invalid-request' });
					}
					const body = await readPersonOrganizationContext({
						session: readStoredOrganizationSession(context.context.session),
						store: props.store.organizations,
					});
					if (body.kind === 'signed-out') context.setStatus(401);
					if (body.kind === 'unavailable') context.setStatus(503);
					return context.json(body);
				},
			),
			readOrganizationPersonMembership: createAuthEndpoint(
				'/organization/person-membership',
				{ method: 'POST', body: z.unknown() },
				async (context) => {
					organizationReadResponseHeaders(context);
					const request = organizationPersonLookupRequestSchema.safeParse(context.body);
					if (!request.success) {
						context.setStatus(400);
						return context.json({ error: 'invalid-request' });
					}
					const result = await checkedRead(context, { kind: 'lookup', value: request.data });
					context.setStatus(result.status);
					return context.json(result.body);
				},
			),
			listOrganizationPeople: createAuthEndpoint(
				'/organization/people-list',
				{ method: 'GET', query: z.unknown() },
				async (context) => {
					organizationReadResponseHeaders(context);
					const request = organizationPeopleListRequestSchema.safeParse(context.query);
					if (!request.success) {
						context.setStatus(400);
						return context.json({ error: 'invalid-request' });
					}
					const result = await checkedRead(context, { kind: 'list', value: request.data });
					context.setStatus(result.status);
					return context.json(result.body);
				},
			),
			organizationPeoplePage: createAuthEndpoint(
				'/organization/people',
				{ method: 'GET', query: z.unknown() },
				async (context) => {
					organizationReadResponseHeaders(context);
					const request = z
						.strictObject({ organizationId: organizationIdSchema })
						.safeParse(context.query);
					if (!request.success) {
						context.setStatus(400);
						return context.json({ error: 'invalid-request' });
					}
					const check = await checkReadPermission(context, request.data.organizationId);
					if (check.kind === 'refused' && check.status === 401)
						return new Response(null, {
							status: 303,
							headers: { location: '/sign-in', 'cache-control': 'no-store' },
						});
					if (check.kind !== 'allowed') {
						context.setStatus(check.kind === 'unavailable' ? 503 : 403);
						return context.json({ kind: check.kind });
					}
					const own = await readPersonOrganizationContext({
						session: readStoredOrganizationSession(context.context.session),
						store: props.store.organizations,
					});
					if (own.kind !== 'available') {
						context.setStatus(503);
						return context.json({ kind: 'unavailable' });
					}
					const organization = own.choices.find(
						(choice) => choice.organizationId === request.data.organizationId,
					);
					if (organization === undefined) {
						context.setStatus(403);
						return context.json({ kind: 'refused' });
					}
					return renderOrganizationPeoplePage({
						organizationId: organization.organizationId,
						organizationName: organization.organizationName,
						nonce: mintPageNonce(props.platform.crypto),
					});
				},
			),
		},
	};
}
