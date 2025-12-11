import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { IngestionConnectorsQuery } from '@components/data/IngestionCatalog/__generated__/IngestionConnectorsQuery.graphql';
import React from 'react';

export const ingestionConnectorsQuery = graphql`
  query IngestionConnectorsQuery {
    connectors {
      manager_contract_image
    }
  }
`;

interface IngestionConnectorsProps {
  queryRef: PreloadedQuery<IngestionConnectorsQuery>;
  children: ({ data }: { data: IngestionConnectorsQuery['response'] }) => React.ReactNode;
}

const IngestionConnectors: React.FC<IngestionConnectorsProps> = ({ queryRef, children }) => {
  const data = usePreloadedQuery(ingestionConnectorsQuery, queryRef);
  return children({ data });
};

export default IngestionConnectors;
