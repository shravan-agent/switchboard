// The flags each fleet subcommand takes (PR #24 review S3). A flag a subcommand does not use is
// refused before any credential or request, so it can never be silently ignored.

/** Flags every fleet subcommand takes: the target file and how to sign in and keep keys. */
const sharedFlags = ['target', 'no-browser', 'memory-only'] as const;

/** The first supplied flag outside the subcommand's own and the shared ones, or null. */
export function unsupportedSubcommandFlag(
	ownFlags: readonly string[],
	suppliedFlags: readonly string[],
): string | null {
	const allowed: readonly string[] = [...sharedFlags, ...ownFlags];
	return suppliedFlags.find((flag) => !allowed.includes(flag)) ?? null;
}

/** `<command> <subcommand> does not take --flag (it takes …). Nothing was sent.` */
export function unsupportedSubcommandFlagWords(props: {
	readonly command: string;
	readonly subcommand: string;
	readonly ownFlags: readonly string[];
	readonly flag: string;
}): string {
	const takes =
		props.ownFlags.length === 0
			? 'takes no options'
			: `takes ${props.ownFlags.map((name) => `--${name}`).join(', ')}`;
	return `${props.command} ${props.subcommand} does not take --${props.flag} (it ${takes}). Nothing was sent.`;
}

/** The flags a person actually supplied: every option with a value. */
export function suppliedFlags(options: Readonly<Record<string, unknown>>): readonly string[] {
	return Object.entries(options)
		.filter(([, value]) => value !== undefined)
		.map(([flag]) => flag);
}
