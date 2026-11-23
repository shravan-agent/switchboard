import {
	fleetAdminRequestSchema,
	type EngineAdminResultFor,
	type FleetAdminRequest,
	type FleetAdminResult,
} from '@agent-collaboration/sign-in-core';
import { z } from 'zod';

import { requireFleetTarget, type AuthTarget } from '#sign-in-owner-cli/auth-target';
import {
	runFleetAdminCommand,
	type FleetAdminOutcome,
} from '#sign-in-owner-cli/fleet/fleet-admin-command';
import type { FleetCliEnvironment } from '#sign-in-owner-cli/fleet/fleet-cli-commands';
import { fleetCliSession } from '#sign-in-owner-cli/fleet/fleet-credential';
import {
	suppliedFlags,
	unsupportedSubcommandFlag,
	unsupportedSubcommandFlagWords,
} from '#sign-in-owner-cli/fleet/subcommand-flags';

export const engineCommandName = 'engine';

/** `engine health`, `engine retired [--cursor ID]`, `engine retry|discard ATTEMPT_ID`. */
const engineArgumentsSchema = z.union([
	z.tuple([z.enum(['health', 'retired'])]),
	z.tuple([z.enum(['retry', 'discard']), z.string()]),
]);
type EngineSubcommand = z.output<typeof engineArgumentsSchema>[0];

const engineSubcommandFlags = {
	health: [],
	retired: ['cursor'],
	retry: ['operation-id'],
	discard: ['operation-id'],
} as const satisfies Record<EngineSubcommand, readonly string[]>;

export interface EngineCommandOptions {
	/** A retired walk's cursor, as a stopped walk prints it: the walk continues after it. */
	readonly cursor?: string | undefined;
	/** A retry or discard's operation ID, to repeat one that got no answer. */
	readonly 'operation-id'?: string | undefined;
}

/** Central's page limit for the retired list (`RecordPageLimit`, 1..=100): the most it allows. */
const retiredPageLimit = 100;
/** The canonical lowercase UUIDv7 central re-serializes into the signed intent. */
const canonicalUuid7Schema = z
	.string()
	.regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);

type HealthReply = Extract<
	EngineAdminResultFor<'EngineHealth'>,
	{ readonly result: 'engineHealth' }
>;
type RetiredReply = Extract<
	EngineAdminResultFor<'EngineListRetired'>,
	{ readonly result: 'engineRetired' }
>;
type RetiredItem = RetiredReply['items'][number];
/**
 * A refusal as the admin outcome carries it. Each engine route's schema admits only its own
 * reasons (engine-admin-results.ts); the shared result type still names every admin reason.
 */
type AdminRefusalReason = Extract<FleetAdminResult, { readonly result: 'refused' }>['reason'];

const credentialRefused = 'Central refused the fleet credential; run fleet-login again.';

export function healthLines(health: HealthReply): readonly string[] {
	const alarm =
		health.alarm !== null
			? `Engine alarm: ${health.alarm}.`
			: health.alarmMissing
				? 'Engine alarm: missing; work is due and no alarm is set.'
				: 'Engine alarm: none; no work is due.';
	return [
		alarm,
		...health.kinds.map(
			(kind) =>
				`${kind.kind}  failing ${kind.failing}  retired ${kind.retired}  oldest failure ${kind.oldestFirstFailedAt ?? '-'}  last failure ${kind.lastFailure ?? '-'}`,
		),
	];
}

export function retiredItemLine(item: RetiredItem): string {
	return `${item.attemptId}  ${item.kind}  subject ${item.subjectKey}  ${item.failureClass} x${item.count}  retired ${item.retiredAt}${item.lastFailure === null ? '' : `  last failure: ${item.lastFailure}`}`;
}

/** The words for a typed refusal on an engine route; nothing changed in any of them. */
export function engineRefusalWords(
	subcommand: EngineSubcommand,
	reason: AdminRefusalReason,
	attemptId: string | null,
): string {
	const attempt = attemptId ?? '';
	switch (reason) {
		case 'notPermitted':
			return subcommand === 'health' || subcommand === 'retired'
				? "Not permitted: reading engine health needs the organization owner's organization:readAudit."
				: "Not permitted: repairing engine work needs the organization owner's organization:repairWork.";
		case 'secondFactorRequired':
			return 'Central still needs a recent second factor; nothing changed.';
		case 'notFound':
			return `Not found: there is no retired attempt ${attempt}; nothing changed.`;
		case 'notRetired':
			return `Not retired: attempt ${attempt} is still failing, not retired; nothing changed.`;
		case 'discardUnsupported':
			return `Discard is not supported for attempt ${attempt}'s kind of work; nothing changed. Retry it instead.`;
		case 'stale':
			return `Stale: attempt ${attempt}'s subject moved or is gone; nothing changed.`;
		case 'subjectUnreadable':
			return `Attempt ${attempt}'s subject could not be read; nothing changed.`;
		case 'conflict':
			return subcommand === 'retry' || subcommand === 'discard'
				? 'This operation id was already used for a different request; nothing changed.'
				: 'Central saw its authorization change during the request; nothing was read. Repeat the command.';
		case 'refreshRequired':
		case 'authorizationSyncRequired':
		case 'expired':
		case 'requestTime':
		case 'requestReused':
		case 'nameInUse':
		case 'rejected':
			// nameInUse and rejected are never given on an engine route; read the same way if they were.
			return `Central refused (${reason}); nothing changed.`;
		default:
			return reason satisfies never;
	}
}

/** What one retired walk read, and where it stopped if it could not finish. */
export type RetiredWalk =
	| { readonly kind: 'ended'; readonly items: number }
	| {
			readonly kind: 'stopped';
			readonly outcome: Exclude<FleetAdminOutcome, { readonly kind: 'answered' }>;
			/** The cursor the unanswered page was asked from; null for the first page. */
			readonly after: string | null;
	  }
	| { readonly kind: 'refused'; readonly reason: AdminRefusalReason }
	/** Central gave a cursor that does not move past the one asked from: the walk stops. */
	| { readonly kind: 'cursor-stalled'; readonly after: string };

/**
 * The paging rule: a non-null `next` means ask again, even after an empty page; only
 * `next: null` ends the walk. Each page is written as it arrives.
 */
export async function walkRetiredPages(props: {
	readonly after: string | null;
	readonly readPage: (after: string | null) => Promise<FleetAdminOutcome>;
	readonly write: (line: string) => void;
}): Promise<RetiredWalk> {
	let after = props.after;
	let items = 0;
	for (;;) {
		const outcome = await props.readPage(after);
		if (outcome.kind !== 'answered') return { kind: 'stopped', outcome, after };
		const reply = outcome.result;
		if (reply.result === 'refused') return { kind: 'refused', reason: reply.reason };
		if (reply.result !== 'engineRetired')
			return {
				kind: 'stopped',
				outcome: { kind: 'unknown' },
				after,
			};
		for (const item of reply.items) props.write(retiredItemLine(item));
		items += reply.items.length;
		if (reply.next === null) return { kind: 'ended', items };
		// Central's cursor is the last examined attempt ID, so it always moves forward.
		if (after !== null && reply.next <= after) return { kind: 'cursor-stalled', after };
		after = reply.next;
	}
}

function unansweredWords(
	subcommand: EngineSubcommand,
	outcome: Exclude<FleetAdminOutcome, { readonly kind: 'answered' }>,
	repeat: string,
): string {
	const change = subcommand === 'retry' || subcommand === 'discard';
	switch (outcome.kind) {
		case 'unauthenticated':
			return credentialRefused;
		case 'not-confirmed':
			return `Not confirmed; the ${subcommand} was not sent again. Nothing changed.`;
		case 'unavailable':
			return change
				? `Central is unavailable; this ${subcommand} may or may not have applied. Repeat with: ${repeat}; it will not apply twice.`
				: `Central is unavailable; nothing was read. Repeat with: ${repeat}.`;
		case 'unknown':
		case 'created-earlier':
			return change
				? `Central did not answer. Repeat with: ${repeat}; it will not apply twice.`
				: `Central did not answer. Repeat with: ${repeat}.`;
		default:
			return outcome satisfies never;
	}
}

/**
 * Runs one engine command; returns the process exit code. No token or key is printed.
 * `options` carries every flag the person supplied: each must be one this subcommand takes.
 */
export async function runEngineCommand(props: {
	readonly arguments: readonly string[];
	readonly target: AuthTarget;
	readonly options: EngineCommandOptions;
	readonly environment: FleetCliEnvironment;
}): Promise<number> {
	const { environment } = props;
	const parsedArguments = engineArgumentsSchema.safeParse(props.arguments);
	if (!parsedArguments.success) {
		environment.write(
			'Usage: engine health | engine retired [--cursor ID] | engine retry ATTEMPT_ID | engine discard ATTEMPT_ID [--operation-id ID]. Nothing was sent.',
		);
		return 2;
	}
	const [subcommand] = parsedArguments.data;
	const ownFlags = engineSubcommandFlags[subcommand];
	// Refused before any credential or request.
	const unsupported = unsupportedSubcommandFlag(ownFlags, suppliedFlags(props.options));
	if (unsupported !== null) {
		environment.write(
			unsupportedSubcommandFlagWords({
				command: 'engine',
				subcommand,
				ownFlags,
				flag: unsupported,
			}),
		);
		return 2;
	}
	const identifiers = [
		['attempt ID', parsedArguments.data[1]],
		['--cursor', props.options.cursor],
		['--operation-id', props.options['operation-id']],
	] as const;
	for (const [name, value] of identifiers)
		if (value !== undefined && !canonicalUuid7Schema.safeParse(value).success) {
			environment.write(`${name} must be a lowercase UUIDv7. Nothing was sent.`);
			return 2;
		}

	const target = requireFleetTarget(props.target);
	const { io } = environment;
	const store = environment.store({
		issuer: target.issuer,
		clientId: target.ownerFleetCliClientId,
	});
	const session = await fleetCliSession({ target, store, io });
	const organizationId = target.organizationId;
	const run = async (operation: FleetAdminRequest): Promise<FleetAdminOutcome> =>
		runFleetAdminCommand({
			target,
			store,
			session,
			operation,
			io,
			confirmSecondFactor: async () =>
				environment.confirmSecondFactor(new URL('/owner-ready', target.issuer).toString()),
		});

	if (subcommand === 'health') {
		const outcome = await run(
			fleetAdminRequestSchema.parse({ operation: 'EngineHealth', organizationId }),
		);
		if (outcome.kind !== 'answered') {
			environment.write(unansweredWords(subcommand, outcome, 'engine health'));
			return outcome.kind === 'not-confirmed' ? 2 : 1;
		}
		const reply = outcome.result;
		if (reply.result === 'refused') {
			environment.write(engineRefusalWords(subcommand, reply.reason, null));
			return 2;
		}
		if (reply.result !== 'engineHealth') {
			environment.write('Central did not answer. Repeat with: engine health.');
			return 1;
		}
		for (const line of healthLines(reply)) environment.write(line);
		return 0;
	}

	if (subcommand === 'retired') {
		const walk = await walkRetiredPages({
			after: props.options.cursor ?? null,
			write: environment.write,
			readPage: async (after) =>
				run(
					fleetAdminRequestSchema.parse({
						operation: 'EngineListRetired',
						organizationId,
						after,
						limit: retiredPageLimit,
					}),
				),
		});
		switch (walk.kind) {
			case 'ended':
				environment.write(
					walk.items === 0 ? 'No retired engine work.' : 'End of the retired list.',
				);
				return 0;
			case 'refused':
				environment.write(engineRefusalWords(subcommand, walk.reason, null));
				return 2;
			case 'stopped':
				environment.write(
					unansweredWords(
						subcommand,
						walk.outcome,
						walk.after === null ? 'engine retired' : `engine retired --cursor ${walk.after}`,
					),
				);
				return 1;
			case 'cursor-stalled':
				environment.write(
					`Central returned a cursor that does not move past ${walk.after}; the walk stopped.`,
				);
				return 1;
			default:
				return walk satisfies never;
		}
	}

	const attemptId = parsedArguments.data[1] ?? '';
	// Minted once for this invocation and kept on its step-up resend; a repeat names it explicitly.
	const operationId = props.options['operation-id'] ?? io.nextId();
	const operation = fleetAdminRequestSchema.parse({
		operation: subcommand === 'retry' ? 'EngineRetry' : 'EngineDiscard',
		organizationId,
		operationId,
		attemptId,
	});
	const outcome = await run(operation);
	const repeat = `engine ${subcommand} ${attemptId} --operation-id ${operationId}`;
	if (outcome.kind !== 'answered') {
		environment.write(unansweredWords(subcommand, outcome, repeat));
		return outcome.kind === 'not-confirmed' ? 2 : 1;
	}
	const reply = outcome.result;
	switch (reply.result) {
		case 'engineRetried':
			environment.write(`Retried: attempt ${attemptId} is due again.`);
			return 0;
		case 'engineDiscarded':
			environment.write(
				`Discarded: attempt ${attemptId}'s subject is finished and the attempt removed.`,
			);
			return 0;
		case 'refused':
			environment.write(engineRefusalWords(subcommand, reply.reason, attemptId));
			return 2;
		default:
			environment.write(`Central did not answer. Repeat with: ${repeat}; it will not apply twice.`);
			return 1;
	}
}
