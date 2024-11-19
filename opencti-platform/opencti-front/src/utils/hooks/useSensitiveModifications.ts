import useAuth from './useAuth';

export type SensitiveConfigType = 'ce_ee_toggle' | 'file_indexing' | 'groups' | 'markings' | 'platform_organization' | 'roles' | 'rules';

const useSensitiveModifications = (type?: SensitiveConfigType, id?: string) => {
  const { me, settings } = useAuth();
  const sensitiveConfig = settings.platform_protected_sensitive_config;

  const isSensitiveConfigEnabled = sensitiveConfig.enabled;

  if (!isSensitiveConfigEnabled) {
    return {
      isAllowed: true,
      isSensitive: false,
    };
  }

  const isAllowed = me.can_manage_sensitive_config ?? true;
  let isSensitive: boolean = isSensitiveConfigEnabled;

  if (type && sensitiveConfig[type]) {
    const config = sensitiveConfig[type];
    const protectedIds = config.protected_ids ?? [];
    isSensitive = config.enabled && (!id || protectedIds.includes(id));
  }

  return {
    isAllowed,
    isSensitive,
  };
};

export default useSensitiveModifications;
