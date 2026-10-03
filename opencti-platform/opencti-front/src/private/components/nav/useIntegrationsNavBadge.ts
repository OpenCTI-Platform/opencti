import { useEffect, useMemo } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { useFormatter } from '../../../components/i18n';
import { fetchQuery } from '../../../relay/environment';
import useGranted, { MODULES } from '../../../utils/hooks/useGranted';
import { CATALOG_POLLING_INTERVAL_MS } from '../integrations/catalog/catalog-constants';
import { NavItemBadge } from './useNavMenu';
import { useIntegrationsNavBadgeQuery } from './__generated__/useIntegrationsNavBadgeQuery.graphql';

// latest_compatible_version and has_newer_incompatible_version are not needed for the count: they are fetched
// so that refreshing the badge also refreshes the update chips of the Deployed page (same records).
export const integrationsNavBadgeQuery = graphql`
  query useIntegrationsNavBadgeQuery {
    connectors {
      update_available
      latest_compatible_version
      has_newer_incompatible_version
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

// Loaded next to the navigation query, not after it, and only with the capability to read connectors.
// The badge reads it behind its own Suspense boundary, so the navigation never waits for it.
export const useIntegrationsNavBadgeQueryRef = () => {
  const canReadConnectors = useGranted([MODULES]);
  const [queryRef, loadQuery] = useQueryLoader<useIntegrationsNavBadgeQuery>(integrationsNavBadgeQuery);
  useEffect(() => {
    if (canReadConnectors) {
      loadQuery({}, { fetchPolicy: 'store-and-network' });
    }
  }, [canReadConnectors]);
  return canReadConnectors ? queryRef : null;
};

const useIntegrationsNavBadge = (queryRef: PreloadedQuery<useIntegrationsNavBadgeQuery>): NavItemBadge | undefined => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery<useIntegrationsNavBadgeQuery>(integrationsNavBadgeQuery, queryRef);

  useEffect(() => {
    const interval = setInterval(refreshIntegrationsNavBadge, CATALOG_POLLING_INTERVAL_MS);
    document.addEventListener('visibilitychange', refreshIntegrationsNavBadge);
    return () => {
      clearInterval(interval);
      document.removeEventListener('visibilitychange', refreshIntegrationsNavBadge);
    };
  }, []);

  return useMemo(() => {
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
  }, [data, t_i18n]);
};

export default useIntegrationsNavBadge;
