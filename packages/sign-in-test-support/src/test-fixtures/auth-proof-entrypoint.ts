import { handleAuthProofRequest } from '#sign-in-test-support/test-fixtures/auth-proof-application';
import { handleAuthProofClockControl } from '#sign-in-test-support/test-fixtures/auth-proof-clock-control';
import { createDeferredWorkTracker } from '#sign-in-test-support/test-fixtures/authorization-drain-proof';
import { handleDatabaseProofControl } from '#sign-in-test-support/test-fixtures/recording-d1-database';
import { handleWebCryptoDigestFailureControl } from '#sign-in-test-support/test-fixtures/web-crypto-digest-failure';

export { AgentClientManagement } from '#sign-in-test-support/test-fixtures/management-observation-holds';

// One isolate serves the proof; its after-response work is tracked so tests wait on events.
const deferredWork = createDeferredWorkTracker();

// Test-only composition preserves the production named entrypoint and adds a post-signing hold control.
export default {
	async fetch(
		request: Request,
		bindings: AuthWorkerEnv,
		context: ExecutionContext,
	): Promise<Response> {
		if (new URL(request.url).pathname === '/__auth-proof/deferred-work') {
			await deferredWork.settled();
			return Response.json({ kind: 'settled' });
		}
		return (
			(await handleAuthProofClockControl(request)) ??
			(await handleDatabaseProofControl(request)) ??
			(await handleWebCryptoDigestFailureControl(request)) ??
			handleAuthProofRequest(request, bindings, {
				waitUntil: (work: Promise<unknown>): void => context.waitUntil(deferredWork.track(work)),
			})
		);
	},
};
