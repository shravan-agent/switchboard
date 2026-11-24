import {
	canonicalJson,
	offeredOptionIdSchema,
	questionAnswerSchema,
	questionFieldIdSchema,
	questionNumberSchema,
	type ApprovalPersonOperation,
	type ApprovalPersonReplyFor,
} from '@agent-collaboration/sign-in-core';

import { ownerCliEntrypoint, shellWord } from '#sign-in-owner-cli/owner-cli-entrypoint';

// How the owner CLI turns an approve, a deny or `--field` arguments into central's Answer
// (Sign-in Lead's DEL-06 step 2b decisions). Every refusal here happens before anything is sent.

type ReadView = Extract<
	ApprovalPersonReplyFor<'ApprovalRead'>,
	{ readonly kind: 'request' }
>['view'];
export type ProviderApprovalOffer = Extract<
	ReadView,
	{ readonly kind: 'providerApproval' }
>['offer'];
export type QuestionOffer = Extract<ReadView, { readonly kind: 'providerQuestion' }>['offer'];
type OfferedOption = ProviderApprovalOffer['options'][number];
type QuestionField = QuestionOffer['fields'][number];
type DecideAnswer = Extract<
	ApprovalPersonOperation,
	{ readonly operation: 'ApprovalDecide' }
>['answer'];
type QuestionAnswer = Extract<DecideAnswer, { readonly kind: 'question' }>['answer'];
type QuestionFieldAnswer = Extract<QuestionAnswer, { readonly kind: 'answered' }>['fields'][number];

/** The words for an option's lifetime, as `show` and the refusals list it. */
export function lifetimeWords(lasts: OfferedOption['lasts']): string {
	switch (lasts.kind) {
		case 'thisRequest':
			return 'this request only';
		case 'thisTurn':
			return `this turn (kept ${lasts.kept === 'agentMemory' ? 'in agent memory' : 'nowhere'})`;
		case 'thisSession':
			return `this session (kept ${lasts.kept === 'agentMemory' ? 'in agent memory' : 'nowhere'})`;
		case 'keptUntilChanged':
			return `kept until changed (in the ${lasts.kept === 'agentSettingsFile' ? 'agent settings file' : 'agent rules file'})`;
		case 'notVerified':
			return 'lifetime not verified';
		default:
			return lasts satisfies never;
	}
}

/** One line per offered option: its id (what `--option` takes), effect, lifetime and label. */
export function optionLines(offer: ProviderApprovalOffer): readonly string[] {
	return offer.options.map(
		(option) =>
			`  option ${option.id}  ${option.effect}  ${lifetimeWords(option.lasts)}  ${option.label}`,
	);
}

/** `approve` takes the single allow option and `deny` the single decline option. */
const verbEffect = { approve: 'allow', deny: 'decline' } as const;

export type OptionResolution =
	| { readonly kind: 'resolved'; readonly optionId: number }
	| { readonly kind: 'ambiguous'; readonly effect: 'allow' | 'decline' }
	| { readonly kind: 'none'; readonly effect: 'allow' | 'decline' }
	| { readonly kind: 'unoffered'; readonly optionId: number }
	| { readonly kind: 'invalid-option' };

/**
 * The one option an approve or deny answers with. `--option` names it explicitly and overrides
 * the effect match; otherwise exactly one option must have the verb's effect.
 */
export function resolveApprovalOption(props: {
	readonly offer: ProviderApprovalOffer;
	readonly verb: 'approve' | 'deny';
	readonly option: string | undefined;
}): OptionResolution {
	if (props.option !== undefined) {
		const parsed = offeredOptionIdSchema.safeParse(
			/^\d+$/u.test(props.option) ? Number(props.option) : Number.NaN,
		);
		if (!parsed.success) return { kind: 'invalid-option' };
		return props.offer.options.some((option) => option.id === parsed.data)
			? { kind: 'resolved', optionId: parsed.data }
			: { kind: 'unoffered', optionId: parsed.data };
	}
	const effect = verbEffect[props.verb];
	const matching = props.offer.options.filter((option) => option.effect === effect);
	const [only] = matching;
	if (only === undefined) return { kind: 'none', effect };
	return matching.length === 1
		? { kind: 'resolved', optionId: only.id }
		: { kind: 'ambiguous', effect };
}

const effectWords = { allow: 'an allow', decline: 'a decline' } as const;

export function optionRefusalWords(
	resolution: Exclude<OptionResolution, { kind: 'resolved' }>,
): string {
	switch (resolution.kind) {
		case 'ambiguous':
			return `More than one option is ${effectWords[resolution.effect]}; choose one with --option. No decision was sent.`;
		case 'none':
			return `No option is ${effectWords[resolution.effect]}; choose one with --option. No decision was sent.`;
		case 'unoffered':
			return `Option ${resolution.optionId} is not offered. No decision was sent.`;
		case 'invalid-option':
			return '--option takes an option id from the list below. No decision was sent.';
		default:
			return resolution satisfies never;
	}
}

type MultiChoiceField = Extract<QuestionField, { readonly kind: 'multiChoice' }>;

/** Central's count range for a multi-choice field: min defaults to 0, max to every option. */
function multiChoiceCounts(field: MultiChoiceField): {
	readonly min: number;
	readonly max: number;
} {
	return {
		min: field.selection.min ?? 0,
		max: field.selection.max ?? field.selection.options.length,
	};
}

/** What a field's value is, as `show` and the refusals list it. */
function fieldKindWords(field: QuestionField): string {
	switch (field.kind) {
		case 'text':
			return 'text';
		case 'number':
			return 'number';
		case 'boolean':
			return 'true or false';
		case 'singleChoice':
			return 'one option id';
		case 'multiChoice': {
			const { min, max } = multiChoiceCounts(field);
			return `option ids, comma-separated (${min} to ${max})`;
		}
		default:
			return field satisfies never;
	}
}

/** One line per field (with its choice options): its id, what value fits, required or not, label. */
export function fieldLines(offer: QuestionOffer): readonly string[] {
	return offer.fields.flatMap((field) => {
		const line = `  field ${field.fieldId}  ${fieldKindWords(field)}  ${field.required ? 'required' : 'optional'}  ${field.label}`;
		const choices =
			field.kind === 'singleChoice'
				? field.options
				: field.kind === 'multiChoice'
					? field.selection.options
					: [];
		return [line, ...choices.map((choice) => `    option ${choice.optionId}  ${choice.label}`)];
	});
}

export type QuestionAnswerBuild =
	| { readonly kind: 'built'; readonly answer: QuestionAnswer }
	| { readonly kind: 'malformed-argument'; readonly argument: string }
	| { readonly kind: 'unknown-field'; readonly fieldId: string }
	| { readonly kind: 'repeated-field'; readonly fieldId: number }
	| { readonly kind: 'wrong-value'; readonly fieldId: number }
	| { readonly kind: 'unknown-choice'; readonly fieldId: number; readonly choice: string }
	| { readonly kind: 'repeated-choice'; readonly fieldId: number; readonly optionId: number }
	| {
			readonly kind: 'choice-count';
			readonly fieldId: number;
			readonly count: number;
			readonly min: number;
			readonly max: number;
	  }
	| { readonly kind: 'missing-required'; readonly fieldId: number };

/** One field's value as the field's declared kind takes it; null when it does not fit. */
function fieldValue(
	field: Exclude<QuestionField, MultiChoiceField>,
	text: string,
): QuestionFieldAnswer['value'] | null {
	switch (field.kind) {
		case 'text':
			return text.isWellFormed() ? { kind: 'text', value: text } : null;
		case 'number': {
			const parsed = questionNumberSchema.safeParse(text);
			return parsed.success ? { kind: 'number', value: parsed.data } : null;
		}
		case 'boolean':
			return text === 'true' || text === 'false'
				? { kind: 'boolean', value: text === 'true' }
				: null;
		case 'singleChoice': {
			const optionId = /^\d+$/u.test(text) ? Number(text) : Number.NaN;
			return field.options.some((option) => option.optionId === optionId)
				? { kind: 'selectedOptions', selectedOptionIds: [optionId] }
				: null;
		}
		default:
			return field satisfies never;
	}
}

/**
 * A multi-choice value `a,b`: option ids (numbers, so never containing a comma), each offered,
 * none repeated, and as many as central's count range allows. An empty value selects none.
 */
function multiChoiceValue(
	field: MultiChoiceField,
	text: string,
): { readonly kind: 'value'; readonly value: QuestionFieldAnswer['value'] } | QuestionAnswerBuild {
	const fieldId = field.fieldId;
	const choices = text === '' ? [] : text.split(',').map((choice) => choice.trim());
	const selected: number[] = [];
	for (const choice of choices) {
		const optionId = /^\d+$/u.test(choice) ? Number(choice) : Number.NaN;
		if (!field.selection.options.some((option) => option.optionId === optionId))
			return { kind: 'unknown-choice', fieldId, choice };
		if (selected.includes(optionId)) return { kind: 'repeated-choice', fieldId, optionId };
		selected.push(optionId);
	}
	const { min, max } = multiChoiceCounts(field);
	if (selected.length < min || selected.length > max)
		return { kind: 'choice-count', fieldId, count: selected.length, min, max };
	return { kind: 'value', value: { kind: 'selectedOptions', selectedOptionIds: selected } };
}

/**
 * `--field ID=VALUE` arguments as central's QuestionAnswer, in the order given. Refused before
 * sending: a malformed argument, an unknown or repeated field id, a value that does not fit the
 * field's declared kind, a multi-choice value with an unknown or repeated option or a count out
 * of range, and a required field left out.
 */
export function buildQuestionAnswer(props: {
	readonly offer: QuestionOffer;
	readonly fieldArguments: readonly string[];
}): QuestionAnswerBuild {
	const answered: QuestionFieldAnswer[] = [];
	for (const argument of props.fieldArguments) {
		const separator = argument.indexOf('=');
		if (separator <= 0) return { kind: 'malformed-argument', argument };
		const idText = argument.slice(0, separator);
		const fieldId = questionFieldIdSchema.safeParse(
			/^\d+$/u.test(idText) ? Number(idText) : Number.NaN,
		);
		const field = fieldId.success
			? props.offer.fields.find((candidate) => candidate.fieldId === fieldId.data)
			: undefined;
		if (field === undefined) return { kind: 'unknown-field', fieldId: idText };
		if (answered.some((prior) => prior.fieldId === field.fieldId))
			return { kind: 'repeated-field', fieldId: field.fieldId };
		const text = argument.slice(separator + 1);
		if (field.kind === 'multiChoice') {
			const choice = multiChoiceValue(field, text);
			if (choice.kind !== 'value') return choice;
			answered.push({ fieldId: field.fieldId, value: choice.value });
			continue;
		}
		const value = fieldValue(field, text);
		if (value === null) return { kind: 'wrong-value', fieldId: field.fieldId };
		answered.push({ fieldId: field.fieldId, value });
	}
	const missing = props.offer.fields.find(
		(field) => field.required && !answered.some((prior) => prior.fieldId === field.fieldId),
	);
	if (missing !== undefined) return { kind: 'missing-required', fieldId: missing.fieldId };
	return { kind: 'built', answer: { kind: 'answered', fields: answered } };
}

export function questionRefusalWords(
	build: Exclude<QuestionAnswerBuild, { kind: 'built' }>,
): string {
	switch (build.kind) {
		case 'malformed-argument':
			return `--field takes FIELD_ID=VALUE, not "${build.argument}". No decision was sent.`;
		case 'unknown-field':
			return `Field ${build.fieldId} is not on this question. No decision was sent.`;
		case 'repeated-field':
			return `Field ${build.fieldId} is given more than once. No decision was sent.`;
		case 'wrong-value':
			return `The value for field ${build.fieldId} does not fit that field. No decision was sent.`;
		case 'unknown-choice':
			return `Field ${build.fieldId} has no option "${build.choice}". No decision was sent.`;
		case 'repeated-choice':
			return `Field ${build.fieldId} lists option ${build.optionId} more than once. No decision was sent.`;
		case 'choice-count':
			return `Field ${build.fieldId} takes ${build.min} to ${build.max} options, not ${build.count}. No decision was sent.`;
		case 'missing-required':
			return `Field ${build.fieldId} is required. No decision was sent.`;
		default:
			return build satisfies never;
	}
}

/**
 * PR #24 review B1 and the Lead's step 2d decision: a recovery with `--operation-id` sends the
 * decide straight away, with no read, so central can return a result it retained even after
 * `approval:decide` was removed. The answer must be stated in full: `--option N` for a provider
 * approval, the verb alone (approve allows, deny declines) for an unproven call, and for a
 * question the complete answer as one `--answer '<json>'`, exactly as the no-answer advice
 * printed it. The JSON is read with the step-1 QuestionAnswer schema (strict, equal to the
 * generated type) and sent through the same canonical intent builder, so its bytes match the
 * first send. Nothing is stored locally.
 */
export function recoveryAnswer(props: {
	readonly verb: 'approve' | 'deny' | 'answer';
	readonly option: string | undefined;
	readonly answerJson: string | undefined;
}):
	| { readonly kind: 'answer'; readonly answer: DecideAnswer }
	| { readonly kind: 'refused'; readonly words: string } {
	if (props.verb === 'answer') {
		const refused = {
			kind: 'refused',
			words:
				"A question's recovery with --operation-id sends the decide without reading the request, so it must repeat the exact answer: --answer '<json>' as the first decide's advice printed it. Nothing was sent.",
		} as const;
		if (props.answerJson === undefined) return refused;
		let decoded: unknown;
		try {
			decoded = JSON.parse(props.answerJson);
		} catch {
			return refused;
		}
		const answer = questionAnswerSchema.safeParse(decoded);
		return answer.success
			? { kind: 'answer', answer: { kind: 'question', answer: answer.data } }
			: refused;
	}
	if (props.option === undefined)
		return {
			kind: 'answer',
			answer: { kind: 'unprovenCall', decision: props.verb === 'approve' ? 'allow' : 'decline' },
		};
	const optionId = offeredOptionIdSchema.safeParse(
		/^\d+$/u.test(props.option) ? Number(props.option) : Number.NaN,
	);
	return optionId.success
		? { kind: 'answer', answer: { kind: 'approval', optionId: optionId.data } }
		: {
				kind: 'refused',
				words:
					'A recovery with --operation-id must repeat the exact answer: --option takes the option id the first decide used. Nothing was sent.',
			};
}

/**
 * The exact, runnable command that repeats this decide: the documented entrypoint, the target in
 * use, then the same operation id and answer, sent without a read. Every value is one quoted
 * shell word. A question's answer is printed whole as `--answer '<json>'` (its canonical JSON),
 * since its fields cannot be retyped without the question.
 */
export function repeatCommand(props: {
	readonly targetPath: string;
	readonly requestId: string;
	readonly operationId: string;
	readonly answer: DecideAnswer;
}): string {
	const words = (verb: 'approve' | 'deny' | 'answer', ...flags: readonly string[]): string =>
		[
			ownerCliEntrypoint,
			'--target',
			shellWord(props.targetPath),
			'approvals',
			verb,
			shellWord(props.requestId),
			'--operation-id',
			shellWord(props.operationId),
			...flags,
		].join(' ');
	switch (props.answer.kind) {
		case 'unprovenCall':
			return words(props.answer.decision === 'allow' ? 'approve' : 'deny');
		case 'approval':
			return words('approve', '--option', shellWord(String(props.answer.optionId)));
		case 'question':
			return words('answer', '--answer', shellWord(canonicalJson(props.answer.answer)));
		default:
			return props.answer satisfies never;
	}
}
