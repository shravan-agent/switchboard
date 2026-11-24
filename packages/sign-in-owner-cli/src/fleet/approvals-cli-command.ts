import {
	approvalOperationIdSchema,
	approvalRequestIdSchema,
	type ApprovalPersonAdminRefusal,
	type ApprovalPersonReplyFor,
} from '@agent-collaboration/sign-in-core';
import { z } from 'zod';

import { requireFleetTarget, type AuthTarget } from '#sign-in-owner-cli/auth-target';
import {
	buildQuestionAnswer,
	fieldLines,
	optionLines,
	optionRefusalWords,
	questionRefusalWords,
	recoveryAnswer,
	repeatCommand,
	resolveApprovalOption,
} from '#sign-in-owner-cli/fleet/approval-answers';
import { decideApproval, sendApprovalOperation } from '#sign-in-owner-cli/fleet/approval-command';
import {
	unsupportedApprovalsFlag,
	unsupportedFlagWords,
} from '#sign-in-owner-cli/fleet/approvals-cli-flags';
import type { FleetCliEnvironment } from '#sign-in-owner-cli/fleet/fleet-cli-commands';
import { fleetCliSession } from '#sign-in-owner-cli/fleet/fleet-credential';

export const approvalsCommandName = 'approvals';

/**
 * `approvals list [--all] [--cursor ID]`, `show ID`, `approve|deny ID [--option ID]` and
 * `answer ID --field FIELD_ID=VALUE...`; a decide also takes `--operation-id ID` to repeat.
 */
const approvalsArgumentsSchema = z.union([
	z.tuple([z.literal('list')]),
	z.tuple([z.enum(['show', 'approve', 'deny', 'answer']), approvalRequestIdSchema]),
]);

export interface ApprovalsCommandOptions {
	readonly all?: boolean | undefined;
	readonly cursor?: string | undefined;
	readonly 'operation-id'?: string | undefined;
	/** An offered option id, as `show` lists it: overrides approve/deny's effect match. */
	readonly option?: string | undefined;
	/** `FIELD_ID=VALUE`, once per answered field of a question. */
	readonly field?: readonly string[] | undefined;
	/** A question's complete answer as JSON: only in a recovery, with `--operation-id`. */
	readonly answer?: string | undefined;
}

type ReadView = Extract<
	ApprovalPersonReplyFor<'ApprovalRead'>,
	{ readonly kind: 'request' }
>['view'];
type DecideReply = ApprovalPersonReplyFor<'ApprovalDecide'>;
type ListedRequest = ApprovalPersonReplyFor<'ApprovalList'>['items'][number];
type DecidedBy = Extract<DecideReply, { readonly kind: 'alreadyDecided' }>['by'];
type DecideAnswer = Parameters<typeof decideApproval>[0]['operation']['answer'];

const requestKindWords = {
	providerApproval: 'provider approval',
	providerQuestion: 'question',
	unprovenCall: 'unproven call',
} as const satisfies Record<ListedRequest['kind'], string>;

function decidedByWords(by: DecidedBy): string {
	return by.kind === 'person' ? `person ${by.personId}` : `session ${by.session}`;
}

function listedRequestLine(item: ListedRequest): string {
	const state = item.state.kind === 'waiting' ? 'waiting' : item.state.ending;
	return `${item.requestId}  ${requestKindWords[item.kind]}  ${state}  raised ${item.raisedAt}  deadline ${item.deadline}`;
}

function decisionWords(
	answer: Extract<DecideReply, { kind: 'savedDecision' }>['decision']['answer'],
): string {
	switch (answer.kind) {
		case 'unprovenCall':
			return answer.decision;
		case 'approval':
			return `option ${answer.optionId}`;
		case 'question':
			return answer.answer.kind;
		default:
			return answer satisfies never;
	}
}

/** The words for each decide reply (R5). */
export function decideReplyWords(reply: DecideReply): string {
	switch (reply.kind) {
		case 'savedDecision':
			return `Decision saved: ${decisionWords(reply.decision.answer)}.`;
		case 'alreadyDecided':
			return `Already decided by ${decidedByWords(reply.by)} at ${reply.at}; this answer was not saved.`;
		case 'tooLate':
			return 'Too late: the request timed out or was closed before an answer.';
		case 'invalid':
			return reply.reason.kind === 'invalidAnswer'
				? `Not accepted: the answer does not fit the request (${reply.reason.reason.kind}).`
				: `Not accepted: central could not end the request (${reply.reason.reason.kind}).`;
		case 'notVisible':
			return 'Not found.';
		case 'operationConflict':
			return 'This operation id was already used with a different answer.';
		default:
			return reply satisfies never;
	}
}

export function adminRefusalWords(reason: ApprovalPersonAdminRefusal): string {
	return reason === 'notPermitted'
		? "Not permitted: answering approvals needs the organization owner's approval:decide."
		: `Central refused (${reason}).`;
}

const credentialRefused = 'Central refused the fleet credential; run fleet-login again.';

/**
 * Runs one approvals command; returns the process exit code. No token or key is printed.
 * `options` carries every flag the person supplied: each must be one this subcommand takes.
 */
export async function runApprovalsCommand(props: {
	readonly arguments: readonly string[];
	/** The `--target` file as given: a printed repeat command names it again. */
	readonly targetPath: string;
	readonly target: AuthTarget;
	readonly options: ApprovalsCommandOptions;
	readonly environment: FleetCliEnvironment;
}): Promise<number> {
	const parsed = approvalsArgumentsSchema.parse(props.arguments);
	const { environment } = props;
	// S3: refused before any credential or request.
	const supplied = Object.entries(props.options)
		.filter(([, value]) => value !== undefined)
		.map(([flag]) => flag);
	const unsupported = unsupportedApprovalsFlag(parsed[0], supplied);
	if (unsupported !== null) {
		environment.write(unsupportedFlagWords(parsed[0], unsupported));
		return 2;
	}
	// --answer is a recovery's stated answer: only with --operation-id, never with --field.
	if (props.options.answer !== undefined && props.options['operation-id'] === undefined) {
		environment.write(
			"--answer repeats a question's exact answer in a recovery, so it needs --operation-id. Nothing was sent.",
		);
		return 2;
	}
	if (props.options.answer !== undefined && props.options.field !== undefined) {
		environment.write('--field and --answer cannot be used together. Nothing was sent.');
		return 2;
	}
	// B1: a decide repeated with its operation id goes straight to Decide, with no read.
	const recovery =
		parsed[0] !== 'list' && parsed[0] !== 'show' && props.options['operation-id'] !== undefined
			? {
					operationId: approvalOperationIdSchema.parse(props.options['operation-id']),
					answer: recoveryAnswer({
						verb: parsed[0],
						option: props.options.option,
						answerJson: props.options.answer,
					}),
				}
			: null;
	if (recovery?.answer.kind === 'refused') {
		environment.write(recovery.answer.words);
		return 2;
	}
	const target = requireFleetTarget(props.target);
	const { io } = environment;
	const store = environment.store({
		issuer: target.issuer,
		clientId: target.ownerFleetCliClientId,
	});
	const session = await fleetCliSession({ target, store, io });
	const organization = target.organizationId;
	const send = { target, session, io } as const;
	const { targetPath } = props;

	if (parsed[0] === 'list') {
		const outcome = await sendApprovalOperation({
			...send,
			operation: {
				operation: 'ApprovalList',
				organization,
				filter: props.options.all === true ? 'all' : 'waiting',
				cursor:
					props.options.cursor === undefined
						? null
						: approvalRequestIdSchema.parse(props.options.cursor),
			},
		});
		if (outcome.kind !== 'replied') return writeUnanswered(environment, outcome);
		if (outcome.reply.items.length === 0) environment.write('No approval requests.');
		for (const item of outcome.reply.items) environment.write(listedRequestLine(item));
		if (outcome.reply.next !== null)
			environment.write(
				`More: approvals list${props.options.all === true ? ' --all' : ''} --cursor ${outcome.reply.next}`,
			);
		return 0;
	}

	const [command, requestId] = parsed;
	if (recovery !== null && command !== 'show' && recovery.answer.kind === 'answer')
		return decideAndReport({
			...send,
			environment,
			targetPath,
			organization,
			requestId,
			operationId: recovery.operationId,
			answer: recovery.answer.answer,
		});
	const read = await sendApprovalOperation({
		...send,
		operation: { operation: 'ApprovalRead', organization, requestId },
	});
	if (read.kind !== 'replied') return writeUnanswered(environment, read);
	if (read.reply.kind === 'notVisible') {
		environment.write('Not found.');
		return 2;
	}
	const { view } = read.reply;
	if (command === 'show') {
		environment.write(`${view.requestId}  ${requestKindWords[view.kind]}  ${view.state.kind}`);
		for (const line of offerLines(view)) environment.write(line);
		environment.write(JSON.stringify(view));
		return 0;
	}
	const answer = answerFor(command, view, props.options);
	if (answer.kind === 'refused') {
		for (const line of answer.lines) environment.write(line);
		return 2;
	}
	// Minted once for this invocation and reused by its retry; a repeat names it explicitly.
	return decideAndReport({
		...send,
		environment,
		targetPath,
		organization,
		requestId,
		operationId: io.nextId(),
		answer: answer.answer,
	});
}

/** One decide (with its single retry after no answer) and its words; the exit code. */
async function decideAndReport(props: {
	readonly target: Parameters<typeof decideApproval>[0]['target'];
	readonly session: Parameters<typeof decideApproval>[0]['session'];
	readonly io: Parameters<typeof decideApproval>[0]['io'];
	readonly environment: FleetCliEnvironment;
	readonly targetPath: string;
	readonly organization: string;
	readonly requestId: string;
	readonly operationId: string;
	readonly answer: DecideAnswer;
}): Promise<number> {
	const { environment } = props;
	const decided = await decideApproval({
		target: props.target,
		session: props.session,
		io: props.io,
		operation: {
			operation: 'ApprovalDecide',
			organization: props.organization,
			requestId: props.requestId,
			operationId: props.operationId,
			answer: props.answer,
		},
	});
	if (decided.kind === 'unknown') {
		// The command is a line of its own, with nothing after it, so copying it gives exactly it:
		// the documented entrypoint, this --target, then the approvals words, every value quoted.
		environment.write(
			"Central did not answer. To repeat, run the next line exactly. It sends the decide without reading the request, with this exact answer and operation id; within central's 24-hour retention it will not be decided twice.",
		);
		environment.write(repeatCommand(props));
		return 1;
	}
	if (decided.kind !== 'replied') return writeUnanswered(environment, decided);
	environment.write(decideReplyWords(decided.reply));
	return decided.reply.kind === 'savedDecision' ? 0 : 2;
}

/** What `show` lists for a request's offer: each option, or the prompt and each field. */
function offerLines(view: ReadView): readonly string[] {
	switch (view.kind) {
		case 'providerApproval':
			return [`Title: ${view.offer.title}`, 'Options:', ...optionLines(view.offer)];
		case 'providerQuestion':
			return [`Prompt: ${view.offer.prompt}`, 'Fields:', ...fieldLines(view.offer)];
		case 'unprovenCall':
			return [];
		default:
			return view satisfies never;
	}
}

/**
 * The Answer a decide command sends, or why nothing is sent. An unproven call takes approve
 * (allow) or deny (decline); a provider approval takes the one option the verb or `--option`
 * resolves; a question takes `answer` with its fields.
 */
function answerFor(
	command: 'approve' | 'deny' | 'answer',
	view: ReadView,
	options: ApprovalsCommandOptions,
):
	| { readonly kind: 'answer'; readonly answer: DecideAnswer }
	| { readonly kind: 'refused'; readonly lines: readonly string[] } {
	const kind = requestKindWords[view.kind];
	if (command === 'answer') {
		if (view.kind !== 'providerQuestion')
			return refused(
				`This request is a ${kind}; answer it with approve or deny. No decision was sent.`,
			);
		const built = buildQuestionAnswer({ offer: view.offer, fieldArguments: options.field ?? [] });
		return built.kind === 'built'
			? { kind: 'answer', answer: { kind: 'question', answer: built.answer } }
			: refused(questionRefusalWords(built), 'Fields:', ...fieldLines(view.offer));
	}
	switch (view.kind) {
		case 'unprovenCall':
			return options.option === undefined
				? {
						kind: 'answer',
						answer: { kind: 'unprovenCall', decision: command === 'approve' ? 'allow' : 'decline' },
					}
				: refused(
						'--option is for provider approvals; this request is an unproven call. No decision was sent.',
					);
		case 'providerApproval': {
			const resolution = resolveApprovalOption({
				offer: view.offer,
				verb: command,
				option: options.option,
			});
			return resolution.kind === 'resolved'
				? { kind: 'answer', answer: { kind: 'approval', optionId: resolution.optionId } }
				: refused(optionRefusalWords(resolution), 'Options:', ...optionLines(view.offer));
		}
		case 'providerQuestion':
			return refused(
				`This request is a question; answer it with approvals answer ${view.requestId} --field FIELD_ID=VALUE. No decision was sent.`,
				'Fields:',
				...fieldLines(view.offer),
			);
		default:
			return view satisfies never;
	}
}

function refused(...lines: readonly string[]): {
	readonly kind: 'refused';
	readonly lines: readonly string[];
} {
	return { kind: 'refused', lines };
}

function writeUnanswered(
	environment: FleetCliEnvironment,
	outcome:
		| { readonly kind: 'refused'; readonly reason: ApprovalPersonAdminRefusal }
		| { readonly kind: 'unauthenticated' }
		| { readonly kind: 'unknown' },
): number {
	switch (outcome.kind) {
		case 'refused':
			environment.write(adminRefusalWords(outcome.reason));
			return 2;
		case 'unauthenticated':
			environment.write(credentialRefused);
			return 1;
		case 'unknown':
			environment.write('Central did not answer. Repeat the command.');
			return 1;
		default:
			return outcome satisfies never;
	}
}
