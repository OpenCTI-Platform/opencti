import useAuth from '../../../../utils/hooks/useAuth';
import { isGrantedTo } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import type { MenuEntry } from './NavToolbarMenu';

// Single place deciding if a menu entry is available for the current user.
// Used by both the menus themselves and the pages search, so they never diverge.
const useVisibleEntries = (entries: MenuEntry[]): MenuEntry[] => {
  const { me } = useAuth();
  const { isFeatureEnable } = useHelper();
  return entries.filter(({ requiredCapabilities, featureFlag }) => (
    (!featureFlag || isFeatureEnable(featureFlag))
    && (!requiredCapabilities || isGrantedTo(me, requiredCapabilities))
  ));
};

export default useVisibleEntries;
