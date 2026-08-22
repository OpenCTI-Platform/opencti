import React, { createContext, ReactNode, useContext, useEffect } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { interval } from 'rxjs';
import { ConnectorManagerStatusContextQuery } from '@components/data/connectors/__generated__/ConnectorManagerStatusContextQuery.graphql';
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
  const rawVersionInfo = data?.catalogVersionInfo ?? null;
  const catalogVersionInfo = rawVersionInfo
    ? { ...rawVersionInfo, revision: rawVersionInfo.revision ?? null, updated_at: rawVersionInfo.updated_at ?? null }
    : null;
  const hasRegisteredManagers = connectorManagers ? connectorManagers.length > 0 : false;
  const hasActiveManagers = connectorManagers ? connectorManagers.some((cm) => cm.active) : false;

  useEffect(() => {
    if (catalogVersionInfo?.status === 'ready') {
      return undefined;
    }

    // When catalog is still loading (or in error), poll faster to detect the
    // first ready revision and trigger catalog refetch promptly.
    const subscription = interval(FIVE_SECONDS).subscribe(() => {
      setFetchKey((prev) => prev + 1);
    });

    return () => subscription.unsubscribe();
  }, [catalogVersionInfo?.status]);

  useEffect(() => {
    if (!onCatalogVersionChange) {
      return;
    }

    // While catalog is loading or in error, we pass null so consumers can keep
    // waiting for the next ready revision.
    if (!catalogVersionInfo || catalogVersionInfo.status !== 'ready') {
      onCatalogVersionChange(null);
      return;
    }

    onCatalogVersionChange(catalogVersionInfo.revision ?? null);
  }, [catalogVersionInfo?.status, catalogVersionInfo?.revision, onCatalogVersionChange]);

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
