// Third-party notices: THIRD_PARTY_NOTICES.md#better-auth-ui (repository root).
/** Better Auth UI's shadcn components (Base UI variant), copied from
 * better-auth-ui `examples/start-shadcn-baseui-example` at 2b028ec5256d and
 * composed from tool-access-ui's primitives. Browser-only: these hydrate and
 * call Better Auth through the supplied auth client. */
export { AuthProvider } from '@auth-ui/components/auth/auth-provider';
export { EnableTwoFactorDialog } from '@auth-ui/components/auth/two-factor/enable-two-factor-dialog';
export { twoFactorPlugin } from '@auth-ui/lib/auth/two-factor-plugin';
export {
	EnableTwoFactorStep,
	type EnableTwoFactorStepProps,
} from '@auth-ui/components/auth/two-factor/enable-two-factor-step';
export {
	ConfirmSecondFactorStep,
	type ConfirmSecondFactorStepProps,
} from '@auth-ui/components/auth/two-factor/confirm-second-factor-step';
export {
	PasskeyManager,
	type PasskeyManagerProps,
} from '@auth-ui/components/auth/passkey/passkey-manager';
export { passkeyPlugin } from '@better-auth-ui/core/plugins/passkey';
export { BackupCodes } from '@auth-ui/components/auth/two-factor/backup-codes';
export { PasskeyButton } from '@auth-ui/components/auth/passkey/passkey-button';
export {
	PasskeyListSkeleton,
	PasskeyManagementCard,
} from '@auth-ui/components/auth/passkey/passkey-management-card';
