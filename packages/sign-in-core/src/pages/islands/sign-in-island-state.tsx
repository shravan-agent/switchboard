import { z } from 'zod';

import { organizationChoiceSchema } from '#sign-in-core/contracts/organization-membership';
import { signedInNavigationStateSchema } from '#sign-in-core/contracts/sign-in-navigation';
import { organizationIdSchema } from '#sign-in-core/storage/models/sign-in-store';

/** The server decides each page's state; browser islands only render it. Each
 * island root is marked with this attribute and carries its state as JSON in
 * `data-island-state`, parsed at entry. */
export const signInIslandAttribute = 'data-sign-in-island';

const sameOriginPathSchema = z
	.string()
	.startsWith('/')
	.refine((path) => !path.startsWith('//'));

export const signInIslandStateSchema = z.discriminatedUnion('kind', [
	z.strictObject({ kind: z.literal('passkey-sign-in'), continueLocation: sameOriginPathSchema }),
	z.strictObject({
		kind: z.literal('second-factor-enrollment'),
		ownerReadyLocation: sameOriginPathSchema,
	}),
	z.strictObject({
		kind: z.literal('second-factor-confirmation'),
		ownerReadyLocation: sameOriginPathSchema,
	}),
	z.strictObject({ kind: z.literal('passkey-management') }),
	z.strictObject({
		kind: z.literal('signed-in-navigation'),
		navigation: signedInNavigationStateSchema,
	}),
	z.strictObject({
		kind: z.literal('person-organization-choice'),
		choices: z.array(organizationChoiceSchema).readonly(),
		activeOrganizationId: organizationIdSchema.nullable(),
	}),
	z.strictObject({
		kind: z.literal('organization-people'),
		organizationId: organizationIdSchema,
		organizationName: z.string(),
	}),
	z.strictObject({
		kind: z.literal('recovery-codes'),
		codes: z.array(z.string().min(1)).min(1),
		ownerReadyLocation: sameOriginPathSchema,
	}),
]);
export type SignInIslandState = z.infer<typeof signInIslandStateSchema>;
