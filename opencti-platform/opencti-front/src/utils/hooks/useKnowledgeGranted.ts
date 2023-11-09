import useAuth from './useAuth';
import { BYPASS } from './useGranted';

const useKnowledgeGranted = (
  capabilities: string[],
  overrideEntity: string,
  matchAll = false,
): boolean => {
  const { me } = useAuth();
  const groups = me.groups?.edges?.map((e) => e?.node) ?? [];
  const roles = groups.flatMap((g) => g?.roles);
  const overrides = roles.flatMap((r) => r?.capabilities_overrides)?.filter((o) => o);

  let userCapabilities = (me.capabilities ?? []).map((c) => c.name);
  if (overrideEntity) {
    const override = overrides.filter((o) => o?.entity === overrideEntity);
    if (override?.[0]?.capabilities) {
      const overrideCapabilities = [];
      for (const capability of override[0].capabilities) {
        if (capability?.name) {
          overrideCapabilities.push(capability.name);
        }
      }
      userCapabilities = overrideCapabilities;
    }
  }
  if (userCapabilities.includes(BYPASS)) {
    return true;
  }
  let numberOfAvailableCapabilities = 0;
  for (let index = 0; index < capabilities.length; index += 1) {
    const checkCapability = capabilities[index];
    const matchingCapabilities = userCapabilities.filter(
      (r) => r.includes(checkCapability),
    );
    if (matchingCapabilities.length > 0) {
      numberOfAvailableCapabilities += 1;
    }
  }
  if (matchAll) {
    return numberOfAvailableCapabilities === capabilities.length;
  }
  return numberOfAvailableCapabilities > 0;
};

export default useKnowledgeGranted;
