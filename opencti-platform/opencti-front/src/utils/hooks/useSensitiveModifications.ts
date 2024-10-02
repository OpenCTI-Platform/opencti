import { Role_role$data } from '@components/settings/roles/__generated__/Role_role.graphql';
import useAuth from './useAuth';
import useHelper from './useHelper';

const PROTECT_SENSITIVE_CHANGES_FF = 'PROTECT_SENSITIVE_CHANGES';

const ADMINISTRATORS_GROUP_ID = 'group--1d9d9a2a-d7e1-5a22-8e90-572d597750ac';
const CONNECTORS_GROUP_ID = 'group--599fc7ab-02f4-50c1-94f9-4b68da122010';
const DEFAULT_GROUP_ID = 'group--a7991a4f-6192-59a4-87d3-d006d2c41cc8';
const PROTECTED_GROUPS_IDS = [ADMINISTRATORS_GROUP_ID, CONNECTORS_GROUP_ID, DEFAULT_GROUP_ID];

const ADMINISTRATOR_ROLE_ID = 'role--22abb1ff-6ea9-5833-8bf1-aea5c4c971ce';
const CONNECTOR_ROLE_ID = 'role--b375ed46-a11c-56d5-a2d4-0c654f61eeee';
const DEFAULT_ROLE_ID = 'role--a7991a4f-6192-59a4-87d3-d006d2c41cc8';
const PROTECTED_ROLES_IDS = [ADMINISTRATOR_ROLE_ID, CONNECTOR_ROLE_ID, DEFAULT_ROLE_ID];

const useSensitiveModifications = () => {
  const { me } = useAuth();
  const { isFeatureEnable } = useHelper();
  const isGroupEditionAllowed = (groupStandardId: string) => {
    if (me.can_manage_sensitive_config) {
      return true;
    }
    return !PROTECTED_GROUPS_IDS.includes(groupStandardId);
  };

  /**
   * Return true when current user has the fake capa can_manage_sensitive_config enabled.
   * @param roleStandardId
   */
  const isRoleEditionAllowed = (roleStandardId: string) => {
    if (me.can_manage_sensitive_config) {
      return true;
    }
    return !PROTECTED_ROLES_IDS.includes(roleStandardId);
  };

  /**
   * True when a role has the fake capa can_manage_sensitive_config enabled, false if not.
   * when can_manage_sensitive_config undefined => true.
   * @param role
   */
  const isRoleWithManageSensitiveConfig = (role: Role_role$data) => {
    return role.can_manage_sensitive_config ?? true;
  };

  return {
    ffenabled: isFeatureEnable(PROTECT_SENSITIVE_CHANGES_FF),
    isGroupEditionAllowed,
    isRoleEditionAllowed,
    isRoleWithManageSensitiveConfig,
    isPlatformOrgaModificationAllowed: me.can_manage_sensitive_config ?? true,
  };
};

export default useSensitiveModifications;
