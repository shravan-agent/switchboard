import { and, eq, exists, gt, notExists, or, sql } from 'drizzle-orm';
import { z } from 'zod';

import type { SignInPlatform } from '#sign-in-core/contracts/sign-in-platform';
import { createAuthorizationFenceMutations } from '#sign-in-core/storage/authorization-fence-mutations';
import {
	storedSessionSchema,
	storedUserSchema,
	type LiveOwnerSession,
	type PersonSessionRecords,
	type SessionRowPresence,
} from '#sign-in-core/storage/models/person-session-records';
import type {
	SignInDatabaseFactory,
	SignInStoreResult,
} from '#sign-in-core/storage/models/sign-in-database';
import {
	invitation,
	member,
	personOrganizationAuthorizationRevisions,
	session,
	user,
} from '#sign-in-core/storage/sign-in-schema';
import {
	availableStoreValue,
	readStoreValue,
	storeFailure,
} from '#sign-in-core/storage/store-query-results';

export function createPersonSessionStore(props: {
	readonly openDatabase: SignInDatabaseFactory;
	readonly ownerEmail: string;
	readonly platform: SignInPlatform;
}): PersonSessionRecords {
	const database = props.openDatabase;
	async function providerEmailAllowed(
		email: string,
		verified: boolean,
	): Promise<SignInStoreResult<boolean>> {
		if (!verified) return availableStoreValue(false);
		if (email.toLowerCase() === props.ownerEmail.toLowerCase()) return availableStoreValue(true);
		const now = new Date(props.platform.clock.now());
		const admitted = await readStoreValue(
			async () =>
				database()
					.select({ id: user.id })
					.from(user)
					.where(
						and(
							eq(user.email, email.toLowerCase()),
							exists(
								database().select({ id: member.id }).from(member).where(eq(member.userId, user.id)),
							),
						),
					)
					.limit(1),
			z.array(z.object({ id: z.string() })),
		);
		if (admitted.kind === 'store-unavailable') return admitted;
		if (admitted.value.length > 0) return availableStoreValue(true);
		const invited = await readStoreValue(
			async () =>
				database()
					.select({ id: invitation.id })
					.from(invitation)
					.where(
						and(
							eq(invitation.email, email.toLowerCase()),
							eq(invitation.status, 'pending'),
							gt(invitation.expiresAt, now),
						),
					)
					.limit(1),
			z.array(z.object({ id: z.string() })),
		);
		return invited.kind === 'available' ? availableStoreValue(invited.value.length > 0) : invited;
	}
	async function ensurePersonActive(personId: string): Promise<SignInStoreResult<boolean>> {
		const person = await readStoreValue(
			async () =>
				(await database().select().from(user).where(eq(user.id, personId)).limit(1))[0] ?? null,
			storedUserSchema.nullable(),
		);
		if (person.kind === 'store-unavailable') return person;
		return person.value === null
			? availableStoreValue(false)
			: providerEmailAllowed(person.value.email, person.value.emailVerified);
	}
	async function readCurrentSession(
		personId: string,
		sessionId: string,
	): Promise<SignInStoreResult<LiveOwnerSession | null>> {
		const [current, person] = await Promise.all([
			readStoreValue(
				async () =>
					(
						await database()
							.select()
							.from(session)
							.where(and(eq(session.id, sessionId), eq(session.userId, personId)))
							.limit(1)
					)[0] ?? null,
				storedSessionSchema.nullable(),
			),
			readStoreValue(
				async () =>
					(await database().select().from(user).where(eq(user.id, personId)).limit(1))[0] ?? null,
				storedUserSchema.nullable(),
			),
		]);
		if (current.kind === 'store-unavailable') return current;
		if (person.kind === 'store-unavailable') return person;
		if (
			current.value === null ||
			person.value === null ||
			!person.value.emailVerified ||
			current.value.expiresAt.getTime() <= props.platform.clock.now()
		)
			return availableStoreValue(null);
		return availableStoreValue({ session: current.value, user: person.value });
	}
	return {
		async isPersonOrganizationSessionActive(
			personId,
			sessionId,
			organizationId,
		): Promise<SignInStoreResult<boolean>> {
			const current = await readCurrentSession(personId, sessionId);
			if (current.kind === 'store-unavailable') return current;
			if (current.value === null) return availableStoreValue(false);
			const membership = await readStoreValue(
				async () =>
					database()
						.select({ id: member.id })
						.from(member)
						.where(and(eq(member.userId, personId), eq(member.organizationId, organizationId)))
						.limit(1),
				z.array(z.object({ id: z.string() })),
			);
			return membership.kind === 'available'
				? availableStoreValue(membership.value.length === 1)
				: membership;
		},
		async sessionRowByToken(token): Promise<SignInStoreResult<SessionRowPresence>> {
			const row = await readStoreValue(
				async () =>
					(
						await database()
							.select({ id: session.id })
							.from(session)
							.where(eq(session.token, token))
							.limit(1)
					)[0] ?? null,
				z.object({ id: storedSessionSchema.shape.id }).nullable(),
			);
			if (row.kind === 'store-unavailable') return row;
			return availableStoreValue(
				row.value === null ? { kind: 'absent' } : { kind: 'present', id: row.value.id },
			);
		},
		readPersonSession: readCurrentSession,
		providerEmailAllowed,
		ensurePersonActive,
		async isPersonSessionActive(personId, sessionId): Promise<SignInStoreResult<boolean>> {
			const current = await readCurrentSession(personId, sessionId);
			if (current.kind === 'store-unavailable') return current;
			if (current.value === null) return availableStoreValue(false);
			const activeOrganizationId = current.value.session.activeOrganizationId;
			if (activeOrganizationId === null) return ensurePersonActive(personId);
			const membership = await readStoreValue(
				async () =>
					database()
						.select({ id: member.id })
						.from(member)
						.where(
							and(eq(member.userId, personId), eq(member.organizationId, activeOrganizationId)),
						)
						.limit(1),
				z.array(z.object({ id: z.string() })),
			);
			return membership.kind === 'available'
				? availableStoreValue(membership.value.length === 1)
				: membership;
		},
		async readOwnerSession(
			personId,
			sessionId,
		): Promise<SignInStoreResult<LiveOwnerSession | null>> {
			const current = await readCurrentSession(personId, sessionId);
			if (current.kind === 'store-unavailable' || current.value === null) return current;
			const activeOrganizationId = current.value.session.activeOrganizationId;
			if (activeOrganizationId === null) return availableStoreValue(null);
			const owner = await readStoreValue(
				async () =>
					database()
						.select({ id: member.id })
						.from(member)
						.where(
							and(
								eq(member.organizationId, activeOrganizationId),
								eq(member.userId, personId),
								eq(member.role, 'owner'),
							),
						)
						.limit(1),
				z.array(z.object({ id: z.string() })),
			);
			return owner.kind === 'available'
				? availableStoreValue(owner.value.length === 1 ? current.value : null)
				: owner;
		},
		async deleteSession(sessionId): Promise<SignInStoreResult<void>> {
			// Release-fence cleanup ends a session like sign-out does: its person's fences move with it.
			try {
				await createAuthorizationFenceMutations(props).deleteRows(
					'session',
					eq(session.id, sessionId),
				);
				return availableStoreValue(undefined);
			} catch (error) {
				return storeFailure(error);
			}
		},
		async cleanupUnboundPerson(personId): Promise<SignInStoreResult<void>> {
			try {
				const now = new Date(props.platform.clock.now());
				const deletable = and(
					eq(user.id, personId),
					notExists(
						database().select({ id: member.id }).from(member).where(eq(member.userId, user.id)),
					),
					notExists(
						database()
							.select({ id: invitation.id })
							.from(invitation)
							.where(
								and(
									eq(invitation.email, user.email),
									eq(invitation.status, 'pending'),
									gt(invitation.expiresAt, now),
								),
							),
					),
					or(
						eq(user.emailVerified, false),
						and(
							eq(user.emailVerified, true),
							notExists(
								database()
									.select({ id: session.id })
									.from(session)
									.where(eq(session.userId, user.id)),
							),
						),
					),
				);
				const deletion = database().delete(user).where(deletable).returning({ id: user.id });
				// r3 section 3, user deletion: every retained pair of a deleted person bumps and
				// goes inactive in the same batch, selected by the deletion's own predicate.
				const fencedAt = props.platform.clock.now();
				const fences = database()
					.update(personOrganizationAuthorizationRevisions)
					.set({
						revision: sql`${personOrganizationAuthorizationRevisions.revision} + ${1}`,
						state: 'inactive',
						nextAttemptAt: fencedAt,
						updatedAt: fencedAt,
					})
					.where(
						and(
							eq(personOrganizationAuthorizationRevisions.personId, personId),
							exists(database().select({ id: user.id }).from(user).where(deletable)),
						),
					)
					.returning({ id: personOrganizationAuthorizationRevisions.id });
				const outcome = await props.platform.runAtomically([fences, deletion]);
				return outcome.kind === 'committed'
					? availableStoreValue(undefined)
					: { kind: 'store-unavailable', reason: outcome.reason };
			} catch (error) {
				return storeFailure(error);
			}
		},
	};
}
