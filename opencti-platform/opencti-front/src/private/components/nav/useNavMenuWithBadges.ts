import { useMemo } from 'react';
import useIntegrationsNavBadge from './useIntegrationsNavBadge';
import useNavMenu, { NavGroup, NavItemBadge } from './useNavMenu';

const withNavItemBadge = (groups: NavGroup[], itemId: string, badge?: NavItemBadge): NavGroup[] => {
  if (!badge) {
    return groups;
  }

  return groups.map((group) => ({
    ...group,
    items: group.items.map((item) => (item.id === itemId ? { ...item, badge } : item)),
  }));
};

const useNavMenuWithBadges = (): NavGroup[] => {
  const groups = useNavMenu();
  const integrationsBadge = useIntegrationsNavBadge();

  return useMemo(
    () => withNavItemBadge(groups, 'integrations', integrationsBadge),
    [groups, integrationsBadge],
  );
};

export default useNavMenuWithBadges;
