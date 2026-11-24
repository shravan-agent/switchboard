import { z } from 'zod';

import {
	engineAdminRefusalReasons,
	type EngineAdminRefusalReason,
} from '#sign-in-core/central-link/engine-admin-results';
import type {
	EngineFailureClass,
	EngineKindHealth_Serialize,
	EngineKindName,
	EngineRetiredItem_Serialize,
	OrganizationAdminResult_Serialize,
} from '#sign-in-core/central-link/generated/central-sign-in.gen';
import type { AssertWireType, WireTypesEqual } from '#sign-in-core/central-link/wire-type-equality';
import { centralUuid7Schema } from '#sign-in-core/contracts/fleet-admin-wire';
import type { Uuid7 } from '#sign-in-core/contracts/sign-in-platform';
import type { EngineAdminOperationName } from '#sign-in-core/organizations/fleet-admin-operation';

// Central's engine replies (`OrganizationAdminResult` at codex-router 4593797b1, generated in
// `central-sign-in.gen.ts`), read with unknown fields refused. Each wire schema's output equals
// the generated `_Serialize` type, the phase central produces; IDs a caller sends back leave the
// decoder branded.

/** The closed set of engine kinds an admin sees. */
export const engineKindNames = [
	'wake_timer',
	'automation_timer',
	'direct_message',
	'system_message_expiry',
	'legacy_notice_windows',
	'legacy_workspace_drains',
	'engine_source',
] as const satisfies readonly EngineKindName[];
const engineFailureClasses = [
	'corrupt_row',
	'constraint_violated',
	'statement_rejected',
	'refused',
	'other_store_unavailable',
] as const satisfies readonly EngineFailureClass[];

/**
 * A wall-clock text that names a real UTC second, without reading any clock: its first 19
 * characters survive a round trip through `Date`.
 */
function namesRealUtcSecond(text: string): boolean {
	const second = new Date(`${text.slice(0, 19)}Z`);
	return !Number.isNaN(second.getTime()) && second.toISOString().slice(0, 19) === text.slice(0, 19);
}
/**
 * Engine facts (`oldestFirstFailedAt`, `retiredAt`): UTC RFC 3339 with `Z` and zero, three, six or
 * nine fraction digits, Chrono's `AutoSi` (engine-admin-results.md, "Paging and time").
 */
const engineFactTimeSchema = z
	.string()
	.regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(?:\d{3}|\d{6}|\d{9}))?Z$/u)
	.refine(namesRealUtcSecond, 'Not a UTC time');
/** The engine alarm: the host alarm APIs read milliseconds, so zero or three digits. */
const engineAlarmTimeSchema = z
	.string()
	.regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u)
	.refine(namesRealUtcSecond, 'Not a UTC time');
const engineCountSchema = z.number().int().nonnegative();
const engineAttemptIdSchema = centralUuid7Schema.brand<'Uuid7'>();

const engineKindHealthSchema = z.strictObject({
	kind: z.enum(engineKindNames),
	failing: engineCountSchema,
	retired: engineCountSchema,
	oldestFirstFailedAt: engineFactTimeSchema.nullable(),
	lastFailure: z.enum(engineFailureClasses).nullable(),
});
const engineHealthWireSchema = z.strictObject({
	result: z.literal('engineHealth'),
	// Central builds health from the complete registry, zero counts included
	// (attempt_administration.rs:281-324; engine_admin_dispatch.rs:14-35): all seven kinds, each
	// exactly once. A partial or repeated list is not central's answer.
	kinds: z
		.array(engineKindHealthSchema)
		.refine(
			(kinds) =>
				kinds.length === engineKindNames.length &&
				engineKindNames.every(
					(name) => kinds.filter((health) => health.kind === name).length === 1,
				),
			{ message: 'Every registered engine kind is listed exactly once' },
		),
	alarm: engineAlarmTimeSchema.nullable(),
	alarmMissing: z.boolean(),
});
const engineRetiredItemWireSchema = z.strictObject({
	attemptId: centralUuid7Schema,
	kind: z.enum(engineKindNames),
	subjectKey: z.string().min(1),
	failureClass: z.enum(engineFailureClasses),
	count: engineCountSchema,
	retiredAt: engineFactTimeSchema,
	lastFailure: z.string().nullable(),
});
const engineRetiredWireSchema = z.strictObject({
	result: z.literal('engineRetired'),
	items: z.array(engineRetiredItemWireSchema),
	/** Required on every page: non-null means ask again, even after an empty page; null is the end. */
	next: centralUuid7Schema.nullable(),
});
const engineRetiredSchema = engineRetiredWireSchema.extend({
	items: z.array(engineRetiredItemWireSchema.extend({ attemptId: engineAttemptIdSchema })),
	next: engineAttemptIdSchema.nullable(),
});
const engineRetriedSchema = z.strictObject({ result: z.literal('engineRetried') });
const engineDiscardedSchema = z.strictObject({ result: z.literal('engineDiscarded') });

const refusedResult = z.literal('refused');

/** Each engine route's 200 reply: its own result, or one of its own typed refusals. */
export const engineAdminResultSchemas = {
	EngineHealth: z.union([
		engineHealthWireSchema,
		z.strictObject({
			result: refusedResult,
			reason: z.enum(engineAdminRefusalReasons.EngineHealth),
		}),
	]),
	EngineListRetired: z.union([
		engineRetiredSchema,
		z.strictObject({
			result: refusedResult,
			reason: z.enum(engineAdminRefusalReasons.EngineListRetired),
		}),
	]),
	EngineRetry: z.union([
		engineRetriedSchema,
		z.strictObject({
			result: refusedResult,
			reason: z.enum(engineAdminRefusalReasons.EngineRetry),
		}),
	]),
	EngineDiscard: z.union([
		engineDiscardedSchema,
		z.strictObject({
			result: refusedResult,
			reason: z.enum(engineAdminRefusalReasons.EngineDiscard),
		}),
	]),
} as const satisfies Readonly<Record<EngineAdminOperationName, z.ZodType>>;
export type EngineAdminResultFor<Operation extends EngineAdminOperationName> = z.output<
	(typeof engineAdminResultSchemas)[Operation]
>;

type GeneratedResult<Result extends OrganizationAdminResult_Serialize['result']> = Extract<
	OrganizationAdminResult_Serialize,
	{ result: Result }
>;
type GeneratedEngineReply<
	Operation extends EngineAdminOperationName,
	Result extends OrganizationAdminResult_Serialize['result'],
> = GeneratedResult<Result> | { result: 'refused'; reason: EngineAdminRefusalReason<Operation> };
type RetiredReply = Extract<EngineAdminResultFor<'EngineListRetired'>, { result: 'engineRetired' }>;
export type EngineAdminWireSchemaTypes = [
	AssertWireType<
		WireTypesEqual<z.output<typeof engineKindHealthSchema>, EngineKindHealth_Serialize>
	>,
	AssertWireType<
		WireTypesEqual<z.output<typeof engineRetiredItemWireSchema>, EngineRetiredItem_Serialize>
	>,
	AssertWireType<
		WireTypesEqual<z.output<typeof engineHealthWireSchema>, GeneratedResult<'engineHealth'>>
	>,
	AssertWireType<
		WireTypesEqual<z.output<typeof engineRetiredWireSchema>, GeneratedResult<'engineRetired'>>
	>,
	AssertWireType<
		WireTypesEqual<
			z.input<(typeof engineAdminResultSchemas)['EngineHealth']>,
			GeneratedEngineReply<'EngineHealth', 'engineHealth'>
		>
	>,
	AssertWireType<
		WireTypesEqual<
			z.input<(typeof engineAdminResultSchemas)['EngineListRetired']>,
			GeneratedEngineReply<'EngineListRetired', 'engineRetired'>
		>
	>,
	AssertWireType<
		WireTypesEqual<
			z.input<(typeof engineAdminResultSchemas)['EngineRetry']>,
			GeneratedEngineReply<'EngineRetry', 'engineRetried'>
		>
	>,
	AssertWireType<
		WireTypesEqual<
			z.input<(typeof engineAdminResultSchemas)['EngineDiscard']>,
			GeneratedEngineReply<'EngineDiscard', 'engineDiscarded'>
		>
	>,
	AssertWireType<WireTypesEqual<RetiredReply['items'][number]['attemptId'], Uuid7>>,
	AssertWireType<WireTypesEqual<NonNullable<RetiredReply['next']>, Uuid7>>,
];
