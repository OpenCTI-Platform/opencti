import { graphql, useLazyLoadQuery } from 'react-relay';
import React from 'react';
import { IngestionConnectorsCatalogsQuery } from '@components/integrations/catalog/__generated__/IngestionConnectorsCatalogsQuery.graphql';

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
  // Incrementing fetchKey tells Relay to discard its cached response and issue
  // a real network request. Relay deduplicates by (query, variables), so a
  // React key remount alone is not sufficient.
  fetchKey?: number;
  children: ({ data }: { data: IngestionConnectorsCatalogsQuery['response'] }) => React.ReactNode;
}

const IngestionConnectorsCatalogs: React.FC<IngestionConnectorsCatalogsProps> = ({ fetchKey = 0, children }) => {
  const data = useLazyLoadQuery<IngestionConnectorsCatalogsQuery>(
    ingestionConnectorsCatalogsQuery,
    {},
    {
      fetchPolicy: 'network-only',
      fetchKey,
    },
  );

  return children({ data });
};

export default IngestionConnectorsCatalogs;
