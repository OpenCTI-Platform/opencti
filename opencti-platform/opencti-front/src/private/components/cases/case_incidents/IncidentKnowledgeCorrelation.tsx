import { graphql } from 'react-relay';
import React, { Suspense } from 'react';
import { IncidentKnowledgeCorrelationQuery$data } from './__generated__/IncidentKnowledgeCorrelationQuery.graphql';
import useIncidentKnowledgeCorrelationEdit from './useIncidentKnowledgeCorrelationEdit';
import { OctiGraphPositions } from '../../../../utils/graph/graph.types';
import { serializeObjectB64 } from '../../../../utils/object';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { GraphContainerCorrelationObjectsQuery } from '../../../../utils/graph/__generated__/GraphContainerCorrelationObjectsQuery.graphql';
import GraphContainerCorrelation, { graphContainerCorrelationObjectsQuery } from '../../../../utils/graph/GraphContainerCorrelation';
import Loader from '../../../../components/Loader';

export const incidentKnowledgeCorrelationQuery = graphql`
  query IncidentKnowledgeCorrelationQuery($id: String!) {
    caseIncident(id: $id) {
      ...GraphContainerCorrelationPositions_fragment
    }
  }
`;

interface IncidentKnowledgeCorrelationProps {
  data: NonNullable<IncidentKnowledgeCorrelationQuery$data['caseIncident']>
  id: string
}

const IncidentKnowledgeCorrelation = ({
  data,
  id,
}: IncidentKnowledgeCorrelationProps) => {
  const PAGE_SIZE = 500;
  const queryObjectsRef = useQueryLoading<GraphContainerCorrelationObjectsQuery>(
    graphContainerCorrelationObjectsQuery,
    { id, count: PAGE_SIZE },
  );

  const [commitEditPositions] = useIncidentKnowledgeCorrelationEdit();

  const savePositions = (positions: OctiGraphPositions) => {
    commitEditPositions({
      variables: {
        id,
        input: [{
          key: 'x_opencti_graph_data',
          value: [serializeObjectB64(positions)],
        }],
      },
    });
  };

  if (!queryObjectsRef) return null;

  return (
    <Suspense fallback={<Loader />}>
      <GraphContainerCorrelation
        queryObjectsRef={queryObjectsRef}
        pageSize={PAGE_SIZE}
        containerId={id}
        containerType='caseIncident'
        dataPositions={data}
        onPositionsChanged={savePositions}
      />
    </Suspense>
  );
};

export default IncidentKnowledgeCorrelation;
