import { graphql, usePreloadedQuery } from 'react-relay';
import type { PreloadedQuery } from 'react-relay';
import React, { useEffect, useMemo } from 'react';
import { ConnectorsLogosQuery } from './__generated__/ConnectorsLogosQuery.graphql';

export const connectorsLogosQuery = graphql`
  query ConnectorsLogosQuery {
    connectors {
      id
      manager_contract_excerpt {
        slug
        logo
      }
    }
  }
`;

interface ConnectorsLogosProps {
  queryRef: PreloadedQuery<ConnectorsLogosQuery>;
  onLoaded?: (logosBySlug: Map<string, string>) => void;
  children?: ({ logosBySlug }: { logosBySlug: Map<string, string> }) => React.ReactNode;
}

const ConnectorsLogos: React.FC<ConnectorsLogosProps> = ({ queryRef, onLoaded, children }) => {
  const data = usePreloadedQuery(connectorsLogosQuery, queryRef);

  const logosBySlug = useMemo(() => {
    const logosMap = new Map<string, string>();
    for (const connector of data.connectors ?? []) {
      const { slug, logo } = connector.manager_contract_excerpt ?? {};
      if (slug && logo && !logosMap.has(slug)) {
        logosMap.set(slug, logo);
      }
    }
    return logosMap;
  }, [data]);

  useEffect(() => {
    onLoaded?.(logosBySlug);
  }, [onLoaded, logosBySlug]);

  if (!children) {
    return null;
  }

  return children({ logosBySlug });
};

export default ConnectorsLogos;
