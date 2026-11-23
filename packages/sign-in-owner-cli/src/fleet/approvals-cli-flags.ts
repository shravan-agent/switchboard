import {
	unsupportedSubcommandFlag,
	unsupportedSubcommandFlagWords,
} from '#sign-in-owner-cli/fleet/subcommand-flags';

// The flags each `approvals` subcommand takes (PR #24 review S3).

export type ApprovalsSubcommand = 'list' | 'show' | 'approve' | 'deny' | 'answer';

const subcommandFlags = {
	list: ['all', 'cursor'],
	show: [],
	approve: ['option', 'operation-id'],
	deny: ['option', 'operation-id'],
	answer: ['field', 'answer', 'operation-id'],
} as const satisfies Record<ApprovalsSubcommand, readonly string[]>;

/** The first supplied flag this subcommand does not take, or null when every flag is its own. */
export function unsupportedApprovalsFlag(
	subcommand: ApprovalsSubcommand,
	suppliedFlags: readonly string[],
): string | null {
	return unsupportedSubcommandFlag(subcommandFlags[subcommand], suppliedFlags);
}

export function unsupportedFlagWords(subcommand: ApprovalsSubcommand, flag: string): string {
	return unsupportedSubcommandFlagWords({
		command: 'approvals',
		subcommand,
		ownFlags: subcommandFlags[subcommand],
		flag,
	});
}
