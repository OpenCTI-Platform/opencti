import React, { createContext, ReactNode, useContext, useEffect, useRef } from 'react';
import { graphql, useLazyLoadQuery, useMutation } from 'react-relay';
import { interval } from 'rxjs';
import { ConnectorManagerStatusContextQuery } from '@components/data/connectors/__generated__/ConnectorManagerStatusContextQuery.graphql';
import type { ConnectorManagerStatusContextRefreshCatalogMutation } from '@components/data/connectors/__generated__/ConnectorManagerStatusContextRefreshCatalogMutation.graphql';
import { FIVE_SECONDS } from '../../../../utils/Time';

export const connectorManagerStatusQuery = graphql`
  query ConnectorManagerStatusContextQuery {
    connectorManagers {
      id
      active
      last_sync_execution
    }
    catalogVersionInfo {
      status
      revision
      updated_at
    }
  }
`;

const refreshCatalogMutation = graphql`
  mutation ConnectorManagerStatusContextRefreshCatalogMutation {
    refreshCatalog
  }
`;

interface ConnectorManagerStatusContextValue {
  connectorManagers: readonly { id: string; active: boolean }[] | null;
  hasRegisteredManagers: boolean;
  hasActiveManagers: boolean;
  catalogVersionInfo: {
    status: string;
    revision: string | null;
    updated_at: string | null;
  } | null;
}

const ConnectorManagerStatusContext = createContext<ConnectorManagerStatusContextValue | null>(null);

interface ConnectorManagerStatusProviderProps {
  children: ReactNode;
  onCatalogVersionChange?: (revision: string | null) => void;
}

export const ConnectorManagerStatusProvider: React.FC<ConnectorManagerStatusProviderProps> = ({
  children,
  onCatalogVersionChange,
}) => {
  const [fetchKey, setFetchKey] = React.useState(0);

  useEffect(() => {
    const subscription = interval(FIVE_SECONDS * 6).subscribe(() => {
      setFetchKey((prev) => prev + 1);
    });

    return () => subscription.unsubscribe();
  }, []);

  const data = useLazyLoadQuery<ConnectorManagerStatusContextQuery>(
    connectorManagerStatusQuery,
    {},
    {
      fetchPolicy: 'store-and-network',
      fetchKey,
    },
  );

  const connectorManagers = data?.connectorManagers || null;
  const hasRegisteredManagers = connectorManagers ? connectorManagers.length > 0 : false;
  const hasActiveManagers = connectorManagers ? connectorManagers.some((cm) => cm.active) : false;
  const rawCatalogVersionInfo = data?.catalogVersionInfo ?? null;
  const catalogVersionInfo = rawCatalogVersionInfo
    ? {
        status: rawCatalogVersionInfo.status,
        revision: rawCatalogVersionInfo.revision ?? null,
        updated_at: rawCatalogVersionInfo.updated_at ?? null,
      }
    : null;

  const [triggerRefresh] = useMutation<ConnectorManagerStatusContextRefreshCatalogMutation>(refreshCatalogMutation);
  const hasTriggeredOnDemandRefresh = useRef(false);

  // When the user lands on the catalog page and the catalog is not yet ready
  // (e.g. the remote server was unavailable at startup), fire a one-shot
  // on-demand refresh so they don't wait the full scheduled interval.
  useEffect(() => {
    if (!catalogVersionInfo) return;
    if (catalogVersionInfo.status === 'ready') return;
    if (hasTriggeredOnDemandRefresh.current) return;

    hasTriggeredOnDemandRefresh.current = true;
    triggerRefresh({ variables: {} });
  }, [catalogVersionInfo, triggerRefresh]);

  useEffect(() => {
    if (!onCatalogVersionChange) {
      return;
    }
    onCatalogVersionChange(catalogVersionInfo?.revision ?? null);
  }, [catalogVersionInfo?.revision, onCatalogVersionChange]);

  const contextValue: ConnectorManagerStatusContextValue = {
    connectorManagers,
    hasRegisteredManagers,
    hasActiveManagers,
    catalogVersionInfo,
  };

  return (
    <ConnectorManagerStatusContext.Provider value={contextValue}>
      {children}
    </ConnectorManagerStatusContext.Provider>
  );
};

export const useConnectorManagerStatus = (): ConnectorManagerStatusContextValue => {
  const context = useContext(ConnectorManagerStatusContext);

  if (!context) {
    throw new Error('useConnectorManagerStatus must be used within a ConnectorManagerStatusProvider');
  }

  return context;
};

export default useConnectorManagerStatus;
