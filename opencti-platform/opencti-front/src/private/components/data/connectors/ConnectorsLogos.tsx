import { graphql, usePreloadedQuery } from 'react-relay';
import type { PreloadedQuery } from 'react-relay';
import React, { useEffect, useMemo } from 'react';
import { ConnectorsLogosQuery } from './__generated__/ConnectorsLogosQuery.graphql';

export const connectorsLogosQuery = graphql`
  query ConnectorsLogosQuery {
    connectors {
      id
      catalog_identity {
        logo
      }
    }
  }
`;

interface ConnectorsLogosProps {
  queryRef: PreloadedQuery<ConnectorsLogosQuery>;
  onLoaded?: (logosByConnectorId: Map<string, string>) => void;
  children?: ({ logosByConnectorId }: { logosByConnectorId: Map<string, string> }) => React.ReactNode;
}

const ConnectorsLogos: React.FC<ConnectorsLogosProps> = ({ queryRef, onLoaded, children }) => {
  const data = usePreloadedQuery(connectorsLogosQuery, queryRef);

  // Per connector: two connectors of the same catalog entry can resolve different contract
  // versions (embedded contract versus latest catalog contract), each with its own logo.
  const logosByConnectorId = useMemo(() => {
    const logosMap = new Map<string, string>();
    for (const connector of data.connectors ?? []) {
      const logo = connector.catalog_identity?.logo;
      if (logo) {
        logosMap.set(connector.id, logo);
      }
    }
    return logosMap;
  }, [data]);

  useEffect(() => {
    onLoaded?.(logosByConnectorId);
  }, [onLoaded, logosByConnectorId]);

  if (!children) {
    return null;
  }

  return children({ logosByConnectorId });
};

export default ConnectorsLogos;
