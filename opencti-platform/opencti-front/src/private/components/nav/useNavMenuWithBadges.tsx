import React, { useMemo } from 'react';
import { PreloadedQuery } from 'react-relay';
import IntegrationsNavBadge from './IntegrationsNavBadge';
import useNavMenu, { NavGroup } from './useNavMenu';
import { useIntegrationsNavBadgeQuery } from './__generated__/useIntegrationsNavBadgeQuery.graphql';

const withNavItemBadge = (groups: NavGroup[], itemId: string, badge: React.ReactNode): NavGroup[] => {
  return groups.map((group) => ({
    ...group,
    items: group.items.map((item) => (item.id === itemId ? { ...item, badge } : item)),
  }));
};

const useNavMenuWithBadges = (
  integrationsBadgeQueryRef: PreloadedQuery<useIntegrationsNavBadgeQuery> | null | undefined,
  collapsed: boolean,
): NavGroup[] => {
  const groups = useNavMenu();

  return useMemo(
    () => (integrationsBadgeQueryRef
      ? withNavItemBadge(groups, 'integrations', <IntegrationsNavBadge queryRef={integrationsBadgeQueryRef} compact={collapsed} />)
      : groups),
    [groups, integrationsBadgeQueryRef, collapsed],
  );
};

export default useNavMenuWithBadges;
