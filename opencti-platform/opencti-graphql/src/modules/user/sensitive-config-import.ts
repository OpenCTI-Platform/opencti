import { getProtectedSensitiveConfig } from '../../domain/settings';
import type { AuthContext, AuthUser } from '../../types/user';
import { isSensitiveChangesAllowed } from './user-domain';

export type ConfigImportSensitiveType = 'roles' | 'groups' | 'markings' | 'platform_organization';

export const CONFIG_IMPORT_SENSITIVE_REASON = 'Requires the right to manage the sensitive configuration';

// The protected sensitive configuration (protected_sensitive_config) is enforced by the settings screens: a user who cannot manage it
// cannot change a protected role or group, nor the main organization. The import of a configuration applies the same rule.
export const isConfigImportSensitiveChangeAllowed = async (context: AuthContext, user: AuthUser, type: ConfigImportSensitiveType, standardId?: string) => {
  if (isSensitiveChangesAllowed(user.id, user.roles ?? [])) {
    return true;
  }
  const config = await getProtectedSensitiveConfig(context, user);
  const typeConfig = config[type];
  if (!config.enabled || !typeConfig.enabled) {
    return true;
  }
  return standardId !== undefined && !typeConfig.protected_ids.includes(standardId);
};
