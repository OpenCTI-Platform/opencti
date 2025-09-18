import { graphql, usePreloadedQuery } from 'react-relay';
import type { PreloadedQuery } from 'react-relay';
import React from 'react';
import type { ConnectorsListQuery } from './__generated__/ConnectorsListQuery.graphql';

export const connectorsListQuery = graphql`
  query ConnectorsListQuery($enableComposerFeatureFlag: Boolean!) {
    connectorManagers @include(if: $enableComposerFeatureFlag) {
      id
      name
    }
    connectors {
      id
      name
      connector_type
      connector_scope
      is_managed @include(if: $enableComposerFeatureFlag)
      manager_contract_image @include(if: $enableComposerFeatureFlag)
      manager_contract_definition @include(if: $enableComposerFeatureFlag)
      manager_contract_configuration @include(if: $enableComposerFeatureFlag) {
        key
        value
      }
      connector_user {
        id
        name
      }
      config {
        listen
        listen_exchange
        push
        push_exchange
      }
      built_in
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
