import React, { useEffect } from 'react';
import { interval } from 'rxjs';
import * as R from 'ramda';
import { createRefetchContainer, graphql } from 'react-relay';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import ConnectorWorkList from '../work/ConnectorWorkList';

const interval$ = interval(FIVE_SECONDS);

export const stixCoreObjectEnrichmentLinesQuery = graphql`
  query StixCoreObjectEnrichmentLinesQuery($id: String!) {
    stixCoreObject(id: $id) {
      ...StixCoreObjectEnrichmentLines_stixCoreObject
    }
    connectorsForImport {
      ...StixCoreObjectEnrichmentLines_connectorsForImport
    }
  }
`;

const stixCoreObjectEnrichmentLinesAskEnrich = graphql`
  mutation StixCoreObjectEnrichmentLinesMutation($id: ID!, $connectorId: ID!) {
    stixCoreObjectEdit(id: $id) {
      askEnrichment(connectorId: $connectorId) {
        id
      }
    }
  }
`;

const stixCoreObjectEnrichmentLinesAskJob = graphql`
  mutation StixCoreObjectEnrichmentLinesAskJobMutation(
    $fileName: ID!
    $connectorId: String
  ) {
    askJobImport(fileName: $fileName, connectorId: $connectorId) {
      id
    }
  }
`;

const StixCoreObjectEnrichment = ({
  stixCoreObject,
  connectorsForImport,
  relay,
}) => {
  const { id } = stixCoreObject;
  const file = stixCoreObject.importFiles && stixCoreObject.importFiles.edges.length > 0
    ? stixCoreObject.importFiles.edges[0].node
    : null;
  const askJob = (connectorId) => {
    commitMutation({
      mutation: stixCoreObjectEnrichmentLinesAskJob,
      variables: { fileName: file.id, connectorId },
      onCompleted: () => {
        MESSAGING$.notifySuccess('Import successfully asked');
      },
    });
  };
  const askEnrich = (connectorId) => {
    commitMutation({
      mutation: stixCoreObjectEnrichmentLinesAskEnrich,
      variables: { id, connectorId },
      onCompleted: () => relay.refetch({ id, entityType: stixCoreObject.entity_type }),
    });
  };
  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch({
        id: stixCoreObject.id,
        entityType: stixCoreObject.entity_type,
      });
    });
    return () => {
      subscription.unsubscribe();
    };
  });
  const connectors = file && file.metaData
    ? R.filter(
        (n) => R.includes(file.metaData.mimetype, n.connector_scope)
          || n.connector_scope.length === 0,
        connectorsForImport,
      )
    : [];
  const allConnectors = R.sortBy(R.prop('name'), [
    ...stixCoreObject.connectors,
    ...connectors,
  ]);
  const items = allConnectors.map((connector) => ({
    connector,
    works: connector.connector_type === 'INTERNAL_IMPORT_FILE'
      ? R.filter(
          (n) => n.connector.id === connector.id,
          R.propOr([], 'works', file),
        )
      : R.filter(
          (n) => n.connector && n.connector.id === connector.id,
          R.propOr([], 'jobs', stixCoreObject),
        ),
  }));
  return (
    <ConnectorWorkList
      items={items}
      onRefresh={(connector) => (connector.connector_type === 'INTERNAL_IMPORT_FILE'
        ? askJob(connector.id)
        : askEnrich(connector.id))
      }
      onWorkDeleted={() => relay.refetch({ id, entityType: stixCoreObject.entity_type })}
    />
  );
};

const StixCoreObjectEnrichmentLinesFragment = createRefetchContainer(
  StixCoreObjectEnrichment,
  {
    stixCoreObject: graphql`
      fragment StixCoreObjectEnrichmentLines_stixCoreObject on StixCoreObject {
        id
        entity_type
        jobs(first: 100) {
          id
          timestamp
          connector {
            id
            name
          }
          messages {
            timestamp
            message
          }
          errors {
            timestamp
            message
          }
          status
        }
        connectors(onlyAlive: false) {
          id
          connector_type
          name
          active
          updated_at
        }
        ... on Artifact {
          importFiles {
            edges {
              node {
                id
                name
                size
                metaData {
                  mimetype
                }
                works {
                  id
                  connector {
                    id
                    name
                  }
                  user {
                    name
                  }
                  received_time
                  tracking {
                    import_expected_number
                    import_processed_number
                  }
                  messages {
                    timestamp
                    message
                  }
                  errors {
                    timestamp
                    message
                  }
                  status
                  timestamp
                }
              }
            }
          }
        }
      }
    `,
    connectorsForImport: graphql`
      fragment StixCoreObjectEnrichmentLines_connectorsForImport on Connector
      @relay(plural: true) {
        id
        name
        connector_type
        active
        connector_scope
        updated_at
      }
    `,
  },
  stixCoreObjectEnrichmentLinesQuery,
);

export default StixCoreObjectEnrichmentLinesFragment;
