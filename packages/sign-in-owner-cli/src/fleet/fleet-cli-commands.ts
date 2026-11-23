import { createInterface } from 'node:readline/promises';

import {
	fleetAdminCreateWords,
	fleetAdminRequestSchema,
	type FleetAdminRequest,
} from '@agent-collaboration/sign-in-core';
import { createWebSignInCapabilities } from '@agent-collaboration/sign-in-platform-web';
import { z } from 'zod';

import { requireFleetTarget, type AuthTarget } from '#sign-in-owner-cli/auth-target';
import { runFleetAdminCommand } from '#sign-in-owner-cli/fleet/fleet-admin-command';
import {
	fleetCliSession,
	signInFleetCli,
	type FleetCliIo,
} from '#sign-in-owner-cli/fleet/fleet-credential';
import {
	nodeSecurityCommandRunner,
	selectProofKeyStore,
	type ProofKeyStore,
} from '#sign-in-owner-cli/fleet/proof-key-store';

export const fleetCommands = [
	'fleet-login',
	'fleet-create-workspace',
	'fleet-workspace-lookup',
	'fleet-change-records',
] as const;
export type FleetCommand = (typeof fleetCommands)[number];
export function isFleetCommand(command: string | undefined): command is FleetCommand {
	return fleetCommands.some((candidate) => candidate === command);
}
export const deviceSignInUnavailable =
	"Device sign-in isn't available yet; use --no-browser to sign in from another machine's browser.";

export interface FleetCommandOptions {
	readonly 'operation-id'?: string | undefined;
	readonly name?: string | undefined;
	readonly description?: string | undefined;
	readonly 'workspace-id'?: string | undefined;
	readonly after?: string | undefined;
	readonly limit?: string | undefined;
	readonly 'no-browser'?: boolean | undefined;
	readonly 'memory-only'?: boolean | undefined;
}

/** The process's real effects; tests replace any of them. */
export interface FleetCliEnvironment {
	readonly io: FleetCliIo;
	readonly store: (target: { readonly issuer: string; readonly clientId: string }) => ProofKeyStore;
	readonly confirmSecondFactor: (confirmationUrl: string) => Promise<boolean>;
	readonly write: (line: string) => void;
}

export function nodeFleetCliEnvironment(props: {
	readonly noBrowser: boolean;
	readonly memoryOnly: boolean;
	readonly openBrowser: (url: string) => Promise<void>;
}): FleetCliEnvironment {
	const capabilities = createWebSignInCapabilities();
	const show = async (url: string): Promise<void> => {
		if (props.noBrowser) process.stdout.write(`AUTHORIZATION_URL=${url}\n`);
		else await props.openBrowser(url);
	};
	return {
		io: {
			fetch: async (input, init) => fetch(input, init),
			now: () => capabilities.clock.now(),
			nextId: () => capabilities.ids.nextId(),
			crypto: capabilities.crypto,
			browser: show,
		},
		store: ({ issuer, clientId }) =>
			selectProofKeyStore({
				platform: process.platform,
				memoryOnly: props.memoryOnly,
				runner: nodeSecurityCommandRunner,
				crypto: capabilities.crypto,
				issuer,
				clientId,
				warn: (message) => process.stderr.write(`${message}\n`),
			}),
		async confirmSecondFactor(confirmationUrl): Promise<boolean> {
			if (props.noBrowser) process.stdout.write(`CONFIRMATION_URL=${confirmationUrl}\n`);
			else await props.openBrowser(confirmationUrl);
			process.stdout.write(
				'Central needs a recent second factor. Confirm it in the browser, then press Enter (type "cancel" to stop).\n',
			);
			const lines = createInterface({ input: process.stdin });
			try {
				const answer = await lines.question('');
				return answer.trim().toLowerCase() !== 'cancel';
			} catch {
				return false;
			} finally {
				lines.close();
			}
		},
		write: (line) => process.stdout.write(`${line}\n`),
	};
}

function fleetOperation(
	command: Exclude<FleetCommand, 'fleet-login'>,
	organizationId: string,
	options: FleetCommandOptions,
): FleetAdminRequest {
	const input =
		command === 'fleet-create-workspace'
			? {
					operation: 'CreateWorkspace',
					organizationId,
					operationId: options['operation-id'],
					name: options.name,
					description: options.description ?? '',
				}
			: command === 'fleet-workspace-lookup'
				? { operation: 'WorkspaceLookup', organizationId, workspaceId: options['workspace-id'] }
				: {
						operation: 'ReadChangeRecords',
						organizationId,
						after: options.after ?? null,
						limit: options.limit === undefined ? 100 : z.coerce.number().parse(options.limit),
					};
	return fleetAdminRequestSchema.parse(input);
}

/** Runs one fleet command; returns the process exit code. No token or key is ever printed. */
export async function runFleetCommand(props: {
	readonly command: FleetCommand;
	readonly target: AuthTarget;
	readonly options: FleetCommandOptions;
	readonly environment: FleetCliEnvironment;
}): Promise<number> {
	const target = requireFleetTarget(props.target);
	const environment = props.environment;
	const store = environment.store({
		issuer: target.issuer,
		clientId: target.ownerFleetCliClientId,
	});
	const io = environment.io;
	if (props.command === 'fleet-login') {
		await signInFleetCli({ target, store, io });
		environment.write(`Fleet credential ready (${store.custody}).`);
		return 0;
	}
	const operation = fleetOperation(props.command, target.organizationId, props.options);
	const session = await fleetCliSession({ target, store, io });
	const outcome = await runFleetAdminCommand({
		target,
		store,
		session,
		operation,
		io,
		confirmSecondFactor: async () =>
			environment.confirmSecondFactor(new URL('/owner-ready', target.issuer).toString()),
	});
	switch (outcome.kind) {
		case 'answered':
			if (outcome.result.result === 'refused' && outcome.result.reason === 'nameInUse') {
				environment.write(fleetAdminCreateWords.nameInUse);
				return 2;
			}
			if (
				outcome.result.result === 'refused' &&
				outcome.result.reason === 'conflict' &&
				operation.operation === 'CreateWorkspace'
			) {
				environment.write(fleetAdminCreateWords.conflict);
				return 2;
			}
			environment.write(JSON.stringify(outcome.result));
			return outcome.result.result === 'refused' ? 2 : 0;
		case 'created-earlier':
			environment.write(fleetAdminCreateWords.created);
			environment.write(JSON.stringify({ workspace: outcome.workspace }));
			return 0;
		case 'not-confirmed':
			environment.write('Not confirmed; nothing was retried.');
			return 2;
		case 'unauthenticated':
			environment.write('Central refused the fleet credential; run fleet-login again.');
			return 1;
		case 'unavailable':
		case 'unknown':
			environment.write(
				operation.operation === 'CreateWorkspace'
					? `Central did not answer. Repeat the command with --operation-id ${operation.operationId}; it will not run twice.`
					: 'Central did not answer. Repeat the command.',
			);
			return 1;
		default:
			return unreachableOutcome(outcome);
	}
}

function unreachableOutcome(_outcome: never): never {
	throw new Error('Unknown fleet admin outcome');
}
