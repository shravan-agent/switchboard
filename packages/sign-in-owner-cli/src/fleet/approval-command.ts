import {
	approvalPersonAdminRefusals,
	approvalPersonIntentDigest,
	approvalPersonReplySchemas,
	approvalPersonRequestBody,
	approvalPersonRoutePaths,
	type ApprovalPersonAdminRefusal,
	type ApprovalPersonOperation,
	type ApprovalPersonOperationName,
	type ApprovalPersonReplyFor,
} from '@agent-collaboration/sign-in-core';
import { z } from 'zod';

import type { FleetTarget } from '#sign-in-owner-cli/auth-target';
import { sendSignedRelayRequest } from '#sign-in-owner-cli/fleet/fleet-admin-command';
import type { FleetCliIo, FleetCliSession } from '#sign-in-owner-cli/fleet/fleet-credential';

/** Sign-in's DPoP relay for each of central's C3 approval routes. */
const approvalRelayPaths = {
	ApprovalList: '/api/auth/organization-admin/v1/approval-list',
	ApprovalRead: '/api/auth/organization-admin/v1/approval-read',
	ApprovalDecide: '/api/auth/organization-admin/v1/approval-decide',
} as const satisfies Record<ApprovalPersonOperationName, string>;

/** One approval operation's outcome, as the CLI reads it. */
export type ApprovalCommandOutcome<Operation extends ApprovalPersonOperationName> =
	| { readonly kind: 'replied'; readonly reply: ApprovalPersonReplyFor<Operation> }
	| { readonly kind: 'refused'; readonly reason: ApprovalPersonAdminRefusal }
	| { readonly kind: 'unauthenticated' }
	/** No readable answer: the same operation, with the same operation id, is safe to repeat. */
	| { readonly kind: 'unknown' };

const adminRefusalSchema = z.strictObject({
	result: z.literal('refused'),
	reason: z.enum(approvalPersonAdminRefusals),
});

type ApprovalReplyOrRefusal<Operation extends ApprovalPersonOperationName> =
	| { readonly kind: 'replied'; readonly reply: ApprovalPersonReplyFor<Operation> }
	| { readonly kind: 'refused'; readonly reason: ApprovalPersonAdminRefusal };

/** Each operation's reply through its step-1 schema, or C3's admin refusal; null otherwise. */
const replyReaders: {
	readonly [Operation in ApprovalPersonOperationName]: (
		payload: unknown,
	) => ApprovalReplyOrRefusal<Operation> | null;
} = {
	ApprovalList: (payload) => readReply(payload, approvalPersonReplySchemas.ApprovalList),
	ApprovalRead: (payload) => readReply(payload, approvalPersonReplySchemas.ApprovalRead),
	ApprovalDecide: (payload) => readReply(payload, approvalPersonReplySchemas.ApprovalDecide),
};

function readReply<Reply>(
	payload: unknown,
	schema: z.ZodType<Reply>,
):
	| { readonly kind: 'replied'; readonly reply: Reply }
	| { readonly kind: 'refused'; readonly reason: ApprovalPersonAdminRefusal }
	| null {
	const refused = adminRefusalSchema.safeParse(payload);
	if (refused.success) return { kind: 'refused', reason: refused.data.reason };
	const reply = schema.safeParse(payload);
	return reply.success ? { kind: 'replied', reply: reply.data } : null;
}

/** One C3 operation through the relay, signed with a fresh proof. */
export async function sendApprovalOperation<Operation extends ApprovalPersonOperationName>(props: {
	readonly target: FleetTarget;
	readonly session: FleetCliSession;
	readonly io: FleetCliIo;
	readonly operation: Extract<ApprovalPersonOperation, { readonly operation: Operation }>;
}): Promise<ApprovalCommandOutcome<Operation>> {
	const name: Operation = props.operation.operation;
	const answer = await sendSignedRelayRequest({
		target: props.target,
		session: props.session,
		io: props.io,
		centralPath: approvalPersonRoutePaths[name],
		relayPath: approvalRelayPaths[name],
		intentDigest: await approvalPersonIntentDigest(props.io.crypto, props.operation),
		body: approvalPersonRequestBody(props.operation),
		readReply: replyReaders[name],
	});
	if (answer.kind === 'answered') return answer.reply;
	// C3 reads a 503 as no answer, as before: its decide recovery repeats with the same operation id.
	return answer.kind === 'unavailable' ? { kind: 'unknown' } : answer;
}

/**
 * A decide sent with one operation id. With no readable answer it is sent once more, with a
 * fresh proof and the same operation id, so central replays the first result rather than
 * deciding again; a different answer under that id would be `operationConflict`.
 */
export async function decideApproval(props: {
	readonly target: FleetTarget;
	readonly session: FleetCliSession;
	readonly io: FleetCliIo;
	readonly operation: Extract<ApprovalPersonOperation, { readonly operation: 'ApprovalDecide' }>;
}): Promise<ApprovalCommandOutcome<'ApprovalDecide'>> {
	const first = await sendApprovalOperation(props);
	return first.kind === 'unknown' ? sendApprovalOperation(props) : first;
}
