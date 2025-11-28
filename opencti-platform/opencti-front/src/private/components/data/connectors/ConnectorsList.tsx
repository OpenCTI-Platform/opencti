import { graphql, usePreloadedQuery } from 'react-relay';
import type { PreloadedQuery } from 'react-relay';
import React from 'react';
import type { ConnectorsListQuery } from './__generated__/ConnectorsListQuery.graphql';

export const connectorsListQuery = graphql`
  query ConnectorsListQuery {
    connectors {
      id
      name
      container_name
      connector_type
      is_managed
      built_in
      updated_at
      manager_contract_excerpt {
        title
        slug
      }
    }
  }
`;

interface ConnectorsListProps {
  queryRef: PreloadedQuery<ConnectorsListQuery>;
  children: ({ data }: { data: ConnectorsListQuery['response'] }) => React.ReactNode;
}

const ConnectorsList: React.FC<ConnectorsListProps> = ({ queryRef, children }) => {
  const data = usePreloadedQuery(connectorsListQuery, queryRef);

  return children({ data });
};

export default ConnectorsList;
