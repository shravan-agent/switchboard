/** @jsxImportSource react */
import { Button, Card } from '@agent-collaboration/tool-access-ui/server';
import { ChevronRight } from 'lucide-react';
import type * as React from 'react';

import type { OrganizationChoice } from '#sign-in-core/contracts/organization-membership';
import type { OrganizationId } from '#sign-in-core/storage/models/sign-in-store';

export interface OrganizationChooserCardProps {
	readonly choices: readonly OrganizationChoice[];
	readonly activeOrganizationId: OrganizationId | null;
	readonly pending?: boolean;
	readonly onSubmit?: (event: React.FormEvent<HTMLFormElement>) => void;
}

/** The existing membership card, shared by its server fallback and browser island. */
export function OrganizationChooserCard(props: OrganizationChooserCardProps): React.ReactElement {
	return (
		<Card className="py-2">
			<form id="choose-organization" onSubmit={props.onSubmit}>
				<ul aria-label="Your organizations" className="flex flex-col">
					{props.choices.map((choice) => {
						const current = choice.organizationId === props.activeOrganizationId;
						const canChoose = !current;
						return (
							<li key={choice.organizationId} className="px-2">
								<Button
									type="submit"
									name="organizationId"
									value={choice.organizationId}
									aria-label={
										canChoose ? `Choose ${choice.organizationName}` : choice.organizationName
									}
									disabled={!canChoose || props.pending === true}
									variant="ghost"
									className="h-auto w-full justify-start gap-3 px-2 py-2 text-left"
								>
									<span
										aria-hidden="true"
										className="flex size-8 shrink-0 items-center justify-center rounded-md bg-muted text-sm font-medium text-foreground"
									>
										{choice.organizationName.trim().charAt(0).toUpperCase() || '?'}
									</span>
									<span className="flex min-w-0 flex-1 flex-col">
										<span className="truncate text-sm font-medium text-foreground">
											{choice.organizationName}
										</span>
										<span className="text-xs text-muted-foreground">
											{choice.role === 'owner' ? 'Owner' : 'Member'}
											{current ? ' · Current' : ''}
										</span>
									</span>
									{canChoose && (
										<ChevronRight aria-hidden="true" className="text-muted-foreground" />
									)}
								</Button>
							</li>
						);
					})}
				</ul>
			</form>
		</Card>
	);
}
