import { useEffect, useMemo } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useFormatter } from '../../../components/i18n';
import { fetchQuery } from '../../../relay/environment';
import useGranted, { MODULES } from '../../../utils/hooks/useGranted';
import { CATALOG_POLLING_INTERVAL_MS } from '../integrations/catalog/catalog-constants';
import { NavItemBadge } from './useNavMenu';
import { useIntegrationsNavBadgeQuery } from './__generated__/useIntegrationsNavBadgeQuery.graphql';

// latest_compatible_version and incompatibility are not needed for the count: they are fetched
// so that refreshing the badge also refreshes the update chips of the Deployed page (same records).
export const integrationsNavBadgeQuery = graphql`
  query useIntegrationsNavBadgeQuery {
    connectors {
      update_available
      latest_compatible_version
      incompatibility
    }
  }
`;

// Same cadence as the catalog polling, so the badge follows catalog syncs and auto-upgrades
// without a page reload. Skipped while the tab is hidden, refreshed as soon as it is visible again.
const refreshIntegrationsNavBadge = () => {
  if (document.hidden) {
    return;
  }
  fetchQuery<useIntegrationsNavBadgeQuery>(integrationsNavBadgeQuery, {}, { fetchPolicy: 'network-only' })
    .toPromise()
    .catch(() => {
      // The current count stays displayed, the next refresh retries.
    });
};

const useIntegrationsNavBadge = (): NavItemBadge | undefined => {
  const { t_i18n } = useFormatter();
  // Same capability as the connectors query: without it, nothing is fetched and no badge is shown
  const canReadConnectors = useGranted([MODULES]);
  const data = useLazyLoadQuery<useIntegrationsNavBadgeQuery>(
    integrationsNavBadgeQuery,
    {},
    { fetchPolicy: canReadConnectors ? 'store-and-network' : 'store-only' },
  );

  useEffect(() => {
    if (!canReadConnectors) {
      return undefined;
    }
    const interval = setInterval(refreshIntegrationsNavBadge, CATALOG_POLLING_INTERVAL_MS);
    document.addEventListener('visibilitychange', refreshIntegrationsNavBadge);
    return () => {
      clearInterval(interval);
      document.removeEventListener('visibilitychange', refreshIntegrationsNavBadge);
    };
  }, [canReadConnectors]);

  return useMemo(() => {
    if (!canReadConnectors) {
      return undefined;
    }
    const count = data.connectors.reduce(
      (total, connector) => total + (connector.update_available ? 1 : 0),
      0,
    );

    if (count <= 0) {
      return undefined;
    }

    return {
      content: count,
      accessibleText: t_i18n('{count} connector update available', { values: { count } }),
    };
  }, [canReadConnectors, data, t_i18n]);
};

export default useIntegrationsNavBadge;
