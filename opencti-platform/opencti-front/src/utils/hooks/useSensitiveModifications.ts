import useAuth from './useAuth';
import useHelper from './useHelper';

const PROTECT_SENSITIVE_CHANGES_FF = 'PROTECT_SENSITIVE_CHANGES';

const useSensitiveModifications = (type?: string, id?: string) => {
  const { me, settings } = useAuth();
  const sensitiveConfig = settings.platform_protected_sensitive_config;

  const { isFeatureEnable } = useHelper();
  const isSensitiveConfigEnabled = sensitiveConfig.enabled;
  const isSensitiveModificationEnabled = isFeatureEnable(PROTECT_SENSITIVE_CHANGES_FF) && isSensitiveConfigEnabled;
  if (!isSensitiveModificationEnabled) {
    return {
      isAllowed: true,
      isSensitive: false,
      isSensitiveModificationEnabled,
    };
  }
  const isAllowed = me.can_manage_sensitive_config ?? true;
  let isSensitive = isSensitiveConfigEnabled;

  if (type) {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    const config = sensitiveConfig[type];
    const protectedIds = config.protected_ids ?? [];
    isSensitive = config.enabled && (!id || protectedIds.includes(id));
  }

  return {
    isAllowed,
    isSensitive,
    isSensitiveModificationEnabled,
  };
};

export default useSensitiveModifications;
