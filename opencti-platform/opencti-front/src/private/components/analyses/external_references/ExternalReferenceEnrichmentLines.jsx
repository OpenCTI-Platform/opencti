import React, { useEffect } from 'react';
import { interval } from 'rxjs';
import * as R from 'ramda';
import { createRefetchContainer, graphql } from 'react-relay';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import ConnectorWorkList from '../../common/work/ConnectorWorkList';

const interval$ = interval(FIVE_SECONDS);

export const externalReferenceEnrichmentLinesQuery = graphql`
  query ExternalReferenceEnrichmentLinesQuery($id: String!) {
    externalReference(id: $id) {
      ...ExternalReferenceEnrichmentLines_externalReference
    }
    connectorsForImport {
      ...ExternalReferenceEnrichmentLines_connectorsForImport
    }
  }
`;

const externalReferenceEnrichmentLinesAskEnrich = graphql`
  mutation ExternalReferenceEnrichmentLinesMutation(
    $id: ID!
    $connectorId: ID!
  ) {
    externalReferenceEdit(id: $id) {
      askEnrichment(connectorId: $connectorId) {
        id
      }
    }
  }
`;

const externalReferenceEnrichmentLinesAskJob = graphql`
  mutation ExternalReferenceEnrichmentLinesAskJobMutation(
    $fileName: ID!
    $connectorId: String
  ) {
    askJobImport(fileName: $fileName, connectorId: $connectorId) {
      id
    }
  }
`;

const ExternalReferenceEnrichment = (props) => {
  const { externalReference, connectorsForImport, relay } = props;
  const { id } = externalReference;
  const file = externalReference.importFiles
    && externalReference.importFiles.edges.length > 0
    ? externalReference.importFiles.edges[0].node
    : null;
  const askJob = (connectorId) => {
    commitMutation({
      mutation: externalReferenceEnrichmentLinesAskJob,
      variables: { fileName: file.id, connectorId },
      onCompleted: () => {
        MESSAGING$.notifySuccess('Import successfully asked');
      },
    });
  };
  const askEnrich = (connectorId) => {
    commitMutation({
      mutation: externalReferenceEnrichmentLinesAskEnrich,
      variables: { id, connectorId },
      onCompleted: () => relay.refetch({ id, entityType: externalReference.entity_type }),
    });
  };
  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch({
        id: externalReference.id,
        entityType: externalReference.entity_type,
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
    ...externalReference.connectors,
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
          R.propOr([], 'jobs', externalReference),
        ),
  }));
  return (
    <ConnectorWorkList
      items={items}
      onRefresh={(connector) => (connector.connector_type === 'INTERNAL_IMPORT_FILE'
        ? askJob(connector.id)
        : askEnrich(connector.id))
      }
      onWorkDeleted={() => relay.refetch({ id, entityType: externalReference.entity_type })}
    />
  );
};

const ExternalReferenceEnrichmentLinesFragment = createRefetchContainer(
  ExternalReferenceEnrichment,
  {
    externalReference: graphql`
      fragment ExternalReferenceEnrichmentLines_externalReference on ExternalReference {
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
      }
    `,
    connectorsForImport: graphql`
      fragment ExternalReferenceEnrichmentLines_connectorsForImport on Connector
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
  externalReferenceEnrichmentLinesQuery,
);

export default ExternalReferenceEnrichmentLinesFragment;
