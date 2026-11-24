/**
 * The documented way to start the owner CLI from the monorepo root, as `--help` prints it. A
 * line the CLI tells a person to run exactly starts with these words.
 */
export const ownerCliEntrypoint = 'mise exec -- node scripts/verify-auth/owner-cli.ts';

/** One POSIX shell word: single-quoted, with each `'` closed, escaped and reopened. */
export function shellWord(text: string): string {
	return `'${text.replaceAll("'", "'\\''")}'`;
}
