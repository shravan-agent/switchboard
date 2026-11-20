/** @jsxImportSource react */
import { Alert, Button } from '@agent-collaboration/tool-access-ui/server';
import { CircleCheck, CircleDot, Circle } from 'lucide-react';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server.browser';

import type { PageNonce } from '#sign-in-core/contracts/page-nonce';
import {
	signInIslandAttribute,
	type SignInIslandState,
} from '#sign-in-core/pages/islands/sign-in-island-state';
import {
	signInPagesIsland,
	signInPagesIslandPath,
	signInStylesheet,
	signInStylesheetPath,
} from '#sign-in-page-assets';

/** Fingerprinted page assets, served from memory on both hosts. */
const pageAssets: ReadonlyMap<string, { readonly body: string; readonly contentType: string }> =
	new Map([
		[signInStylesheetPath, { body: signInStylesheet, contentType: 'text/css; charset=utf-8' }],
		[
			signInPagesIslandPath,
			{ body: signInPagesIsland, contentType: 'text/javascript; charset=utf-8' },
		],
	]);

export function pageAssetResponse(request: Request): Response | null {
	const asset = pageAssets.get(new URL(request.url).pathname);
	if (asset === undefined || !['GET', 'HEAD'].includes(request.method)) return null;
	return new Response(request.method === 'HEAD' ? null : asset.body, {
		headers: {
			'content-type': asset.contentType,
			'cache-control': 'public, max-age=31536000, immutable',
			'x-content-type-options': 'nosniff',
		},
	});
}

/** Mounts the sign-in pages' islands; the page's nonce is added by
 * pageDocument and carries to the bundle import. An inline module runs on
 * every page, including one a factor form writes, while the bundle is
 * evaluated once per window, so the page calls the mount itself. */
export const signInPagesIslandScript = `<script type="module">import { mountSignInIslands } from ${JSON.stringify(signInPagesIslandPath)}; mountSignInIslands(document);</script>`;

/** The island replaces `fallback` (the native, no-script form) when it mounts. */
export function IslandRoot(props: {
	readonly state: SignInIslandState;
	readonly fallback: React.ReactNode;
}): React.ReactElement {
	return (
		<div {...{ [signInIslandAttribute]: '' }} data-island-state={JSON.stringify(props.state)}>
			{props.fallback}
		</div>
	);
}

export function PageStatus(): React.ReactElement {
	// Status messages are errors unless a controller marks one as information.
	return (
		<Alert
			id="status"
			role="status"
			aria-live="polite"
			variant="destructive"
			className="empty:hidden data-[tone=info]:text-card-foreground"
		/>
	);
}

export function PageBackLink({ href }: { readonly href: string }): React.ReactElement {
	return (
		<Button variant="link" nativeButton={false} render={<a href={href} />}>
			Back to your sign-in
		</Button>
	);
}

export type SetupStepStatus = 'done' | 'current' | 'upcoming';

export interface SetupStep {
	readonly title: string;
	readonly status: SetupStepStatus;
	/** Shown under an upcoming step: what has to happen first. */
	readonly note?: string;
}

function SetupStepMarker({ status }: { readonly status: SetupStepStatus }): React.ReactElement {
	switch (status) {
		case 'done':
			return <CircleCheck aria-hidden="true" className="size-4 text-primary" />;
		case 'current':
			return <CircleDot aria-hidden="true" className="size-4 text-primary" />;
		case 'upcoming':
			return <Circle aria-hidden="true" className="size-4 text-muted-foreground" />;
		default:
			return status satisfies never;
	}
}

const setupStepStatusLabel: Readonly<Record<SetupStepStatus, string>> = {
	done: 'Done',
	current: 'Current step',
	upcoming: 'Upcoming',
};

/** Steps in order; only the current one is active, later ones show what they wait for. */
export function SetupSteps({
	steps,
}: {
	readonly steps: readonly SetupStep[];
}): React.ReactElement {
	return (
		<ol aria-label="Setup steps" className="flex flex-col gap-3">
			{steps.map((step) => (
				<li
					key={step.title}
					aria-current={step.status === 'current' ? 'step' : undefined}
					className="flex gap-3"
				>
					<span className="mt-0.5">
						<SetupStepMarker status={step.status} />
					</span>
					<div className="flex flex-col gap-0.5">
						<h2
							className={
								step.status === 'upcoming'
									? 'text-sm text-muted-foreground'
									: 'text-sm font-medium text-foreground'
							}
						>
							{step.title}
						</h2>
						<span className="sr-only">{setupStepStatusLabel[step.status]}</span>
						{step.status === 'upcoming' && step.note !== undefined && (
							<p className="text-xs text-muted-foreground">{step.note}</p>
						)}
					</div>
				</li>
			))}
		</ol>
	);
}

/** Which third-party challenge a page may load. Only the sign-in page runs
 * Turnstile; signed-in pages name no third party at all (owner, 12 Nov). */
export type PageChallenge = 'turnstile' | 'none';

const turnstileOrigin = 'https://challenges.cloudflare.com';

export function pageContentSecurityPolicy(nonce: string, challenge: PageChallenge): string {
	const turnstile = challenge === 'turnstile' ? ` ${turnstileOrigin}` : '';
	return [
		"default-src 'none'",
		`script-src 'nonce-${nonce}'${turnstile}`,
		"style-src 'self'",
		"img-src 'self' data:",
		`connect-src 'self'${turnstile}`,
		// The sign-in page frames only Turnstile. Signed-in pages frame only blob:
		// documents: Better Auth UI prints recovery codes through a blob: text
		// file in an iframe (owner, 13 Nov: use Better Auth UI as shipped). A blob:
		// document inherits this policy, so its scripts stay nonce-gated.
		`frame-src ${challenge === 'turnstile' ? turnstileOrigin : 'blob:'}`,
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	].join('; ');
}

/** All executable fragments are owned form controllers or the nonce-loaded
 * pages island; user values enter JSX as text. */
export function pageDocument(props: {
	readonly title: string;
	readonly layout?: 'shell';
	readonly children: React.ReactNode;
	readonly scripts: string;
	readonly challenge: PageChallenge;
	readonly headers?: Headers;
	/** Secondary actions, shown as quiet links under the page's one task. */
	readonly footer?: React.ReactNode | undefined;
	/** Minted by the response builder that decided to render this page (S1). */
	readonly nonce: PageNonce;
}): { readonly html: string; readonly headers: Headers } {
	const nonce = props.nonce;
	const headers = new Headers(props.headers);
	headers.set('content-type', 'text/html; charset=utf-8');
	headers.set('cache-control', 'no-store');
	headers.set('referrer-policy', 'no-referrer');
	headers.set('x-content-type-options', 'nosniff');
	headers.set('content-security-policy', pageContentSecurityPolicy(nonce, props.challenge));
	const document = renderToStaticMarkup(
		<html lang="en" className="dark">
			<head>
				<meta charSet="utf-8" />
				<meta name="viewport" content="width=device-width, initial-scale=1" />
				<title>{props.title}</title>
				<link rel="stylesheet" href={signInStylesheetPath} />
			</head>
			<body>
				{props.layout === 'shell' ? (
					props.children
				) : (
					<main className="mx-auto flex min-h-svh w-full max-w-md flex-col justify-center gap-6 px-4 py-10">
						<header className="flex flex-col items-center gap-1 text-center">
							<p className="text-sm font-medium text-muted-foreground">Switchboard</p>
							<h1 className="text-xl font-medium">{props.title}</h1>
						</header>
						{props.children}
						{props.footer !== undefined && (
							<footer className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
								{props.footer}
							</footer>
						)}
					</main>
				)}
			</body>
		</html>,
	);
	const scripts = props.scripts.replaceAll('<script', `<script nonce="${nonce}"`);
	return {
		html: '<!doctype html>' + document.replace('</body>', () => `${scripts}</body>`),
		headers,
	};
}
