import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreEntity } from '../../../types/store';
import { RELATION_HAS_CAPABILITY, RELATION_HAS_CAPABILITY_IN_DRAFT } from '../../../schema/internalRelationship';
import { roleCapabilities } from '../user-domain';
import type { RoleImportConfiguration } from './role-import-schema';

export type BasicStoreEntityRole = BasicStoreEntity & { name: string; description?: string; can_manage_sensitive_config?: boolean };

const capabilityNames = async (context: AuthContext, user: AuthUser, roleId: string, relationshipType: string) => {
  return (await roleCapabilities(context, user, roleId, relationshipType)).map(({ name }) => name).sort();
};

export const getRoleConfigPresetConfiguration = async (context: AuthContext, user: AuthUser, role: BasicStoreEntityRole): Promise<RoleImportConfiguration> => {
  const [capabilities, capabilitiesInDraft] = await Promise.all([
    capabilityNames(context, user, role.id, RELATION_HAS_CAPABILITY),
    capabilityNames(context, user, role.id, RELATION_HAS_CAPABILITY_IN_DRAFT),
  ]);
  return {
    name: role.name,
    description: role.description ?? '',
    can_manage_sensitive_config: role.can_manage_sensitive_config ?? false,
    capabilities,
    capabilities_in_draft: capabilitiesInDraft,
  };
};
