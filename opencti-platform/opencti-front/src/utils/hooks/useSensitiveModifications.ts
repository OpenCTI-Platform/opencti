import useAuth from './useAuth';
import useHelper from './useHelper';

const PROTECT_SENSITIVE_CHANGES_FF = 'PROTECT_SENSITIVE_CHANGES';

const useSensitiveModifications = (type?: string, id?: string) => {
  const { me, settings } = useAuth();
  const sensitiveConfig = settings.platform_protected_sensitive_config;

  const { isFeatureEnable } = useHelper();
  const isSensitiveConfigEnabled = sensitiveConfig.enabled;
  const isSensitiveModificationEnabled = isFeatureEnable(PROTECT_SENSITIVE_CHANGES_FF) && isSensitiveConfigEnabled;
  let isAllowed = me.can_manage_sensitive_config != null ? me.can_manage_sensitive_config : true;

  if (!isSensitiveModificationEnabled) {
    isAllowed = true;
  }

  if (type === 'group') {
    const protectedGroupsIds = sensitiveConfig.groups.protected_ids;
    if (id) {
      isAllowed = (me.can_manage_sensitive_config || !protectedGroupsIds?.includes(id));
    }
    return {
      isAllowed,
      isSensitive: isSensitiveModificationEnabled && sensitiveConfig.groups.enabled && (!id || protectedGroupsIds?.includes(id)),
    };
  }

  if (type === 'role') {
    const protectedRolesIds = sensitiveConfig.roles.protected_ids;
    if (id) {
      isAllowed = (me.can_manage_sensitive_config || !protectedRolesIds?.includes(id));
    }
    return {
      isAllowed,
      isSensitive: isSensitiveModificationEnabled && sensitiveConfig.roles.enabled && (!id || protectedRolesIds?.includes(id)),
    };
  }

  if (type === 'marking') {
    const protectedMarkingsIds = sensitiveConfig.markings.protected_ids;
    if (id) {
      isAllowed = (me.can_manage_sensitive_config || !protectedMarkingsIds?.includes(id));
    }
    return {
      isAllowed,
      isSensitive: isSensitiveModificationEnabled && sensitiveConfig.markings.enabled && (!id || protectedMarkingsIds?.includes(id)),
    };
  }

  if (type === 'platform_organization') {
    return {
      isAllowed,
      isSensitive: isSensitiveModificationEnabled && sensitiveConfig.platform_organization.enabled,
    };
  }

  if (type === 'rules') {
    return {
      isAllowed,
      isSensitive: isSensitiveModificationEnabled && sensitiveConfig.rules.enabled,
    };
  }

  if (type === 'ee') {
    return {
      isAllowed,
      isSensitive: isSensitiveModificationEnabled && sensitiveConfig.ce_ee_toggle.enabled,
    };
  }

  if (type === 'file_indexing') {
    return {
      isAllowed,
      isSensitive: isSensitiveModificationEnabled && sensitiveConfig.file_indexing.enabled,
    };
  }
  return {
    isAllowed,
    isSensitiveModificationEnabled,
  };
};

export default useSensitiveModifications;
