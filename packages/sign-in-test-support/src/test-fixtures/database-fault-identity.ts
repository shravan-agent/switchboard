import { z } from 'zod';

export const databaseFaultSchema = z.strictObject({
	operation: z.enum(['insert', 'update', 'delete', 'select']),
	projection: z
		.enum([
			'membership-facts',
			'session-id-by-token',
			'membership-invitations',
			'people-members',
			'people-count',
			'people-invitations',
			'memberships',
		])
		.optional(),
	once: z.boolean().optional(),
	skipMatches: z.number().int().nonnegative().optional(),
	table: z.enum([
		'user',
		'session',
		'account',
		'organization',
		'member',
		'invitation',
		'twoFactor',
		'passkey',
		'verification',
		'sign_in_audit',
		'oauthClient',
		'oauthClientResource',
	]),
	key: z.string().min(1),
	additionalKeys: z.array(z.string()).default([]),
	phase: z.enum(['intent', 'outcome']).optional(),
	changeKind: z.string().optional(),
	auditKind: z.string().optional(),
	column: z.enum(['disabled', 'clientSecret', 'secondFactorSetAt']).optional(),
});
export type DatabaseFault = z.infer<typeof databaseFaultSchema>;

export interface PreparedDriverCall {
	readonly query: string;
	readonly parameters: readonly unknown[];
}
export function matchesDatabaseFault(call: PreparedDriverCall, fault: DatabaseFault): boolean {
	const table = /\b(?:insert\s+into|update|delete\s+from|from)\s+["`]?([\w]+)["`]?/iu.exec(
		call.query,
	)?.[1];
	const operation = /^\s*(insert|update|delete|select)\b/iu.exec(call.query)?.[1]?.toLowerCase();
	if (table !== fault.table || operation !== fault.operation) return false;
	function contains(value: string): boolean {
		return call.parameters.includes(value) || call.query.includes(`'${value}'`);
	}
	return (
		[fault.key, ...fault.additionalKeys].some(contains) &&
		(fault.phase === undefined || contains(fault.phase)) &&
		(fault.changeKind === undefined || contains(fault.changeKind)) &&
		(fault.auditKind === undefined || contains(fault.auditKind)) &&
		(fault.column === undefined || call.query.includes(`"${fault.column}" =`)) &&
		(fault.projection === undefined || organizationReadProjection(call) === fault.projection)
	);
}

/** The projection identifies the production select without counting unrelated permission reads. */
export function organizationReadProjection(
	call: PreparedDriverCall,
): DatabaseFault['projection'] | null {
	const query = call.query.replaceAll(/\s+/gu, ' ').trim();
	if (!/^select\b/iu.test(query)) return null;
	if (query.startsWith('select "id" from "session" where "session"."token" ='))
		return 'session-id-by-token';
	if (query.startsWith('select "member"."role" from "member" inner join "user"'))
		return 'membership-facts';
	if (query.startsWith('select "user"."name", "user"."email", "member"."role" from "member"'))
		return 'people-members';
	if (query.startsWith('select count(*) from "member"')) return 'people-count';
	if (query.startsWith('select "id", "status", "expiresAt", "email", "role" from "invitation"'))
		return 'people-invitations';
	if (query.startsWith('select "id", "status", "expiresAt" from "invitation"'))
		return 'membership-invitations';
	if (
		query.startsWith(
			'select "member"."organizationId", "organization"."name", "member"."userId", "member"."role" from "member"',
		)
	)
		return 'memberships';
	return null;
}
