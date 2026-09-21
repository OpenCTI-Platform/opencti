import { useMemo } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useFormatter } from '../../../components/i18n';
import { NavItemBadge } from './useNavMenu';
import { useIntegrationsNavBadgeQuery } from './__generated__/useIntegrationsNavBadgeQuery.graphql';

export const integrationsNavBadgeQuery = graphql`
  query useIntegrationsNavBadgeQuery {
    connectors {
      update_available
    }
  }
`;

const useIntegrationsNavBadge = (): NavItemBadge | undefined => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<useIntegrationsNavBadgeQuery>(
    integrationsNavBadgeQuery,
    {},
    { fetchPolicy: 'store-and-network' },
  );

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
