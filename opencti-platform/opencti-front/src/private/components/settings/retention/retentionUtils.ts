// Scopes of the policies an administrator creates; the platform creates the others and they cannot be deleted
const USER_RETENTION_SCOPES = ['knowledge', 'conflicts'];

export const isDeletableRetentionRule = (scope: string | null | undefined) => !scope || USER_RETENTION_SCOPES.includes(scope);
