import * as React from 'react';

import {
	OrganizationChooserCard,
	type OrganizationChooserCardProps,
} from '#sign-in-core/pages/person-organization-choice';

interface OrganizationChoiceBrowser {
	readonly setActive: (organizationId: string) => Promise<{ readonly ok: boolean }>;
	readonly replace: () => void;
	readonly showRefusal?: () => void;
}

/** A switch's response cannot establish the stored choice. Every ending reads it back. */
export async function switchPersonOrganization(
	organizationId: string,
	browser: OrganizationChoiceBrowser,
): Promise<void> {
	try {
		const response = await browser.setActive(organizationId);
		if (!response.ok) browser.showRefusal?.();
	} catch {
		// A lost response may follow a committed switch. The page render decides.
	} finally {
		browser.replace();
	}
}

export function setActivePersonOrganization(organizationId: string): Promise<Response> {
	return fetch('/api/auth/organization/set-active', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ organizationId }),
	});
}

export function PersonOrganizationChoice(
	props: Pick<OrganizationChooserCardProps, 'choices' | 'activeOrganizationId'>,
): React.ReactElement {
	const [pending, setPending] = React.useState(false);
	const pendingReference = React.useRef(false);
	function submit(event: React.FormEvent<HTMLFormElement>): void {
		event.preventDefault();
		if (pendingReference.current) return;
		const submitter = event.nativeEvent instanceof SubmitEvent ? event.nativeEvent.submitter : null;
		if (!(submitter instanceof HTMLButtonElement) || submitter.value.length === 0) return;
		pendingReference.current = true;
		setPending(true);
		void switchPersonOrganization(submitter.value, {
			setActive: setActivePersonOrganization,
			replace: (): void => location.replace(location.href),
			showRefusal: (): void => {
				const status = document.getElementById('status');
				if (status !== null) status.textContent = "That organization isn't available";
			},
		});
	}
	return <OrganizationChooserCard {...props} pending={pending} onSubmit={submit} />;
}
