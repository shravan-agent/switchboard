import { z } from 'zod';

import {
	databaseFaultSchema,
	matchesDatabaseFault,
	organizationReadProjection,
	type DatabaseFault,
	type PreparedDriverCall,
} from '#sign-in-test-support/test-fixtures/database-fault-identity';
import {
	createDatabaseReadHold,
	type DatabaseReadHold,
} from '#sign-in-test-support/test-fixtures/database-proof-holds';
import { createPasskeyReleaseFailure } from '#sign-in-test-support/test-fixtures/passkey-release-failure';

const passkeyReleaseFailure = createPasskeyReleaseFailure();
let failNextPasskeyUserRead = false;
let lastSessionInsert: { readonly query: string; readonly parameters: readonly unknown[] } | null =
	null;
export function handlePasskeySessionProofControl(request: Request): Response | null {
	const releaseFailureControl = passkeyReleaseFailure.control(request);
	if (releaseFailureControl !== null) return releaseFailureControl;
	const pathname = new URL(request.url).pathname;
	if (pathname === '/__auth-proof/fail-next-passkey-user-read' && request.method === 'POST') {
		failNextPasskeyUserRead = true;
		return Response.json({ kind: 'armed' });
	}
	if (pathname === '/__auth-proof/last-session-insert' && request.method === 'GET')
		return Response.json(lastSessionInsert);
	return null;
}

let activeFault: DatabaseFault | null = null;
const organizationReads = { lookup: 0, list: 0 };
let observedClient: { readonly clientId: string; readonly keys: readonly string[] } | null = null;
const disabledWrites: { readonly client_id: string }[] = [];
const driverFailures: {
	readonly operation: string;
	readonly table: string;
	readonly reason: 'unique-key' | 'other-database-error';
}[] = [];
function recordDriverFailure(call: PreparedDriverCall, error: unknown): void {
	let cause: unknown = error;
	let unique = false;
	while (cause instanceof Error) {
		unique ||= /unique|duplicate/iu.test(cause.message);
		cause = cause.cause;
	}
	driverFailures.push({
		operation:
			/^\s*(insert|update|delete|select)/iu.exec(call.query)?.[1]?.toLowerCase() ??
			'other-operation',
		table:
			/\b(?:insert\s+into|update|delete\s+from|from)\s+["`]?([\w]+)["`]?/iu.exec(call.query)?.[1] ??
			'other-table',
		reason: unique ? 'unique-key' : 'other-database-error',
	});
}

export async function handleDatabaseProofControl(request: Request): Promise<Response | null> {
	const url = new URL(request.url);
	if (url.pathname !== '/__auth-proof/database-control') return null;
	if (request.method === 'GET')
		return Response.json({
			disabledWrites,
			driverFailures: driverFailures.slice(-8),
			organizationReads,
		});
	const control = z
		.discriminatedUnion('kind', [
			z.strictObject({ kind: z.literal('fault'), fault: databaseFaultSchema.nullable() }),
			z.strictObject({ kind: z.literal('observe-organization-reads') }),
			z.strictObject({
				kind: z.literal('observe-disable'),
				clientId: z.string(),
				keys: z.array(z.string()),
			}),
		])
		.parse(await request.json());
	if (control.kind === 'fault') activeFault = control.fault;
	else if (control.kind === 'observe-organization-reads') {
		organizationReads.lookup = 0;
		organizationReads.list = 0;
	} else {
		observedClient = control;
		disabledWrites.length = 0;
	}
	return Response.json({ kind: 'applied' });
}

function recordWrite(call: PreparedDriverCall, changedRows: number): void {
	if (
		observedClient !== null &&
		changedRows > 0 &&
		matchesDatabaseFault(call, {
			operation: 'update',
			table: 'oauthClient',
			key: observedClient.clientId,
			additionalKeys: [...observedClient.keys],
			column: 'disabled',
		})
	) {
		for (let row = 0; row < changedRows; row += 1)
			disabledWrites.push({ client_id: observedClient.clientId });
	}
}

/** Test-only public driver wrapper. The SQL and parameters come only from Drizzle;
 * identity-based rejection precedes execution, and every other call reaches real D1. */
export function recordingD1Database(
	binding: AuthWorkerEnv['DB'],
	hold: DatabaseReadHold = { kind: 'none' },
	readFault: () => DatabaseFault | null = () => activeFault,
	/** Runs once the rows of a read (alone, or in a batch after the whole batch) are back. */
	afterDriverRead: (query: string) => Promise<void> = async () => undefined,
): AuthWorkerEnv['DB'] {
	let failUserReadAfterInsert = false;
	function rejectFault(call: PreparedDriverCall): void {
		const projection = organizationReadProjection(call);
		if (projection === 'membership-facts') organizationReads.lookup += 1;
		if (projection === 'people-members') organizationReads.list += 1;
		passkeyReleaseFailure.beforeDriverCall(call);
		if (/^\s*insert into "session"/iu.test(call.query)) {
			lastSessionInsert = { query: call.query, parameters: call.parameters };
			if (failNextPasskeyUserRead) {
				failNextPasskeyUserRead = false;
				failUserReadAfterInsert = true;
			}
		} else if (failUserReadAfterInsert && /^\s*select\b.*\bfrom "user"/iu.test(call.query)) {
			failUserReadAfterInsert = false;
			throw new Error('Injected passkey user read failure');
		}
		const fault = readFault();
		if (fault !== null && matchesDatabaseFault(call, fault)) {
			if (fault.skipMatches !== undefined && fault.skipMatches > 0) {
				fault.skipMatches -= 1;
			} else {
				if (fault.once === true && fault === activeFault) activeFault = null;
				throw new Error('Injected sign-in driver failure');
			}
		}
	}
	const observer = createDatabaseReadHold(hold);
	const calls = new WeakMap<
		D1PreparedStatement,
		PreparedDriverCall & { readonly statement: D1PreparedStatement }
	>();

	function wrapStatement(
		statement: D1PreparedStatement,
		query: string,
		parameters: readonly unknown[],
	): D1PreparedStatement {
		const call = { statement, query, parameters };
		function raw<TValue = unknown[]>(options: {
			columnNames: true;
		}): Promise<[string[], ...TValue[]]>;
		function raw<TValue = unknown[]>(options?: { columnNames?: false }): Promise<TValue[]>;
		async function raw<TValue = unknown[]>(options?: {
			columnNames?: boolean;
		}): Promise<[string[], ...TValue[]] | TValue[]> {
			try {
				rejectFault(call);
				await observer.beforeRead(call);
				if (options?.columnNames === true) {
					const result = await statement.raw<TValue>({ columnNames: true });
					await observer.afterRead(call);
					recordWrite(call, result.length - 1);
					await afterDriverRead(query);
					return result;
				}
				const result = await statement.raw<TValue>();
				await observer.afterRead(call);
				recordWrite(call, result.length);
				await afterDriverRead(query);
				return result;
			} catch (error) {
				recordDriverFailure(call, error);
				throw error;
			}
		}
		const wrapped = {
			bind: (...values: unknown[]) => wrapStatement(statement.bind(...values), query, values),
			first: statement.first.bind(statement),
			async run<TValue>(): Promise<D1Result<TValue>> {
				rejectFault(call);
				const result = await statement.run<TValue>();
				recordWrite(call, result.meta.changes);
				return result;
			},
			async all<TValue>(): Promise<D1Result<TValue>> {
				rejectFault(call);
				const result = await statement.all<TValue>();
				recordWrite(call, result.meta.changes);
				await afterDriverRead(query);
				return result;
			},
			raw,
		} satisfies D1PreparedStatement;
		calls.set(wrapped, call);
		return wrapped;
	}
	async function runBatch<TValue>(
		statements: D1PreparedStatement[],
		runner: (statements: D1PreparedStatement[]) => Promise<D1Result<TValue>[]>,
	): Promise<D1Result<TValue>[]> {
		const entries = statements.map((statement) => {
			const call = calls.get(statement);
			if (call === undefined) throw new Error('Unrecorded statement in proof batch');
			rejectFault(call);
			return call;
		});
		const results = await runner(entries.map((entry) => entry.statement));
		entries.forEach((entry, index) => recordWrite(entry, results[index]?.meta.changes ?? 0));
		for (const entry of entries) await afterDriverRead(entry.query);
		return results;
	}
	return {
		prepare: (query) => wrapStatement(binding.prepare(query), query, []),
		batch: <TValue>(statements: D1PreparedStatement[]) =>
			runBatch<TValue>(statements, (group) => binding.batch<TValue>(group)),
		exec: binding.exec.bind(binding),
		dump: binding.dump.bind(binding),
		withSession(constraint): D1DatabaseSession {
			const session = binding.withSession(constraint);
			return {
				prepare: (query) => wrapStatement(session.prepare(query), query, []),
				batch: <TValue>(statements: D1PreparedStatement[]) =>
					runBatch<TValue>(statements, (group) => session.batch<TValue>(group)),
				getBookmark: session.getBookmark.bind(session),
			};
		},
	};
}
