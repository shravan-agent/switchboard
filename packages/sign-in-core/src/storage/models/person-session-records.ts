import { z } from 'zod';

import { uuid7Schema } from '#sign-in-core/contracts/sign-in-platform';
import type { SignInStoreResult } from '#sign-in-core/storage/models/sign-in-database';
import { organizationIdSchema } from '#sign-in-core/storage/models/sign-in-store';

export const storedUserSchema = z.object({
	id: uuid7Schema,
	name: z.string(),
	email: z.email(),
	emailVerified: z.boolean(),
	image: z.string().nullable(),
	createdAt: z.date(),
	updatedAt: z.date(),
});
export const storedSessionSchema = z.object({
	id: uuid7Schema,
	token: z.string(),
	userId: uuid7Schema,
	expiresAt: z.date(),
	createdAt: z.date(),
	updatedAt: z.date(),
	ipAddress: z.string().nullable(),
	userAgent: z.string().nullable(),
	activeOrganizationId: organizationIdSchema.nullable(),
});
export const liveOwnerSessionSchema = z.object({
	session: storedSessionSchema,
	user: storedUserSchema,
});
export type LiveOwnerSession = z.infer<typeof liveOwnerSessionSchema>;

export type SessionRowPresence =
	| { readonly kind: 'present'; readonly id: string }
	| { readonly kind: 'absent' };

export interface PersonSessionRecords {
	readonly sessionRowByToken: (token: string) => Promise<SignInStoreResult<SessionRowPresence>>;
	readonly isPersonOrganizationSessionActive: (
		personId: string,
		sessionId: string,
		organizationId: string,
	) => Promise<SignInStoreResult<boolean>>;
	readonly readPersonSession: (
		personId: string,
		sessionId: string,
	) => Promise<SignInStoreResult<LiveOwnerSession | null>>;
	readonly providerEmailAllowed: (
		email: string,
		verified: boolean,
	) => Promise<SignInStoreResult<boolean>>;
	readonly ensurePersonActive: (personId: string) => Promise<SignInStoreResult<boolean>>;
	readonly readOwnerSession: (
		personId: string,
		sessionId: string,
	) => Promise<SignInStoreResult<LiveOwnerSession | null>>;
	readonly isPersonSessionActive: (
		personId: string,
		sessionId: string,
	) => Promise<SignInStoreResult<boolean>>;
	readonly deleteSession: (sessionId: string) => Promise<SignInStoreResult<void>>;
	readonly cleanupUnboundPerson: (personId: string) => Promise<SignInStoreResult<void>>;
}
