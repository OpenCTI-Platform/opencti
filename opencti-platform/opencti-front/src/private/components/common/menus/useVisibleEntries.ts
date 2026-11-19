import useAuth from '../../../../utils/hooks/useAuth';
import { isGrantedTo } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { useHiddenEntities } from '../../../../utils/hooks/useEntitySettings';
import type { MenuEntry } from './menuEntry';

// Single place deciding if a menu entry is available for the current user.
// Used by both the menus themselves and the pages search, so they never diverge.
const useVisibleEntries = (entries: MenuEntry[]): MenuEntry[] => {
  const { me } = useAuth();
  const { isFeatureEnable, isTrashEnable } = useHelper();
  const isEnterpriseEdition = useEnterpriseEdition();
  const hiddenEntities = useHiddenEntities();
  const inDraft = !!me.draftContext;
  return entries.filter(({ path, entityType, requiredCapabilities, capabilitiesInDraft, featureFlag, requiresEE, availableInDraft }) => (
    (!inDraft || availableInDraft)
    && (!featureFlag || isFeatureEnable(featureFlag))
    && (!requiresEE || isEnterpriseEdition)
    && (!requiredCapabilities || isGrantedTo(me, requiredCapabilities, false, { capabilitiesInDraft }))
    // Switched off by the platform settings rather than by the entry's own rules: the entry's own entity type is
    // hidden (not a shared URL: several types, e.g. every observable, resolve to one page), or the trash is disabled.
    && !(entityType && hiddenEntities.includes(entityType))
    && !(path === '/dashboard/trash' && !isTrashEnable())
  ));
};

export default useVisibleEntries;
