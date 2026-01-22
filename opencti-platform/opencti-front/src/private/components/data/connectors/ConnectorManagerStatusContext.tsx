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
  }
`;

interface ConnectorManagerStatusContextValue {
  connectorManagers: readonly { id: string; active: boolean }[] | null;
  hasRegisteredManagers: boolean;
  hasActiveManagers: boolean;
}

const ConnectorManagerStatusContext = createContext<ConnectorManagerStatusContextValue | null>(null);

interface ConnectorManagerStatusProviderProps {
  children: ReactNode;
}

export const ConnectorManagerStatusProvider: React.FC<ConnectorManagerStatusProviderProps> = ({
  children,
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

  const contextValue: ConnectorManagerStatusContextValue = {
    connectorManagers,
    hasRegisteredManagers,
    hasActiveManagers,
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
