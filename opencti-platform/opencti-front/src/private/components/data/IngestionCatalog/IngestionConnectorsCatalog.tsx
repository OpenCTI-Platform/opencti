import { graphql, usePreloadedQuery } from 'react-relay';
import type { PreloadedQuery } from 'react-relay';
import React from 'react';
import { IngestionConnectorsCatalogsQuery } from '@components/data/IngestionCatalog/__generated__/IngestionConnectorsCatalogsQuery.graphql';

export const ingestionConnectorsCatalogsQuery = graphql`
  query IngestionConnectorsCatalogsQuery {
    catalogs {
      id
      name
      description
      contracts
    }
  }
`;

interface IngestionConnectorsCatalogsProps {
  queryRef: PreloadedQuery<IngestionConnectorsCatalogsQuery>;
  children: ({ data }: { data: IngestionConnectorsCatalogsQuery['response'] }) => React.ReactNode;
}

const IngestionConnectorsCatalogs: React.FC<IngestionConnectorsCatalogsProps> = ({ queryRef, children }) => {
  const data = usePreloadedQuery(ingestionConnectorsCatalogsQuery, queryRef);

  return children({ data });
};

export default IngestionConnectorsCatalogs;
