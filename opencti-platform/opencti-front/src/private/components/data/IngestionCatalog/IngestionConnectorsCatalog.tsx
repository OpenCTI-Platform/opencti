import { graphql, usePreloadedQuery } from 'react-relay';
import type { PreloadedQuery } from 'react-relay';
import React, { useEffect } from 'react';
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
  onCatalogsResolved?: (catalogs: IngestionConnectorsCatalogsQuery['response']['catalogs']) => void;
  children: ({ data }: { data: IngestionConnectorsCatalogsQuery['response'] }) => React.ReactNode;
}

const IngestionConnectorsCatalogs: React.FC<IngestionConnectorsCatalogsProps> = ({ queryRef, onCatalogsResolved, children }) => {
  const data = usePreloadedQuery(ingestionConnectorsCatalogsQuery, queryRef);

  useEffect(() => {
    onCatalogsResolved?.(data.catalogs);
  }, [data.catalogs, onCatalogsResolved]);

  return children({ data });
};

export default IngestionConnectorsCatalogs;
