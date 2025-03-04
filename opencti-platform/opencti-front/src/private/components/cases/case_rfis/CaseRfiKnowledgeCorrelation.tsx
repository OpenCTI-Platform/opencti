import { graphql } from 'react-relay';
import React, { Suspense } from 'react';
import { CaseRfiKnowledgeCorrelationQuery$data } from './__generated__/CaseRfiKnowledgeCorrelationQuery.graphql';
import useCaseRfiKnowledgeCorrelationEdit from './useCaseRfiKnowledgeCorrelationEdit';
import { OctiGraphPositions } from '../../../../utils/graph/graph.types';
import { serializeObjectB64 } from '../../../../utils/object';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { GraphContainerCorrelationObjectsQuery } from '../../../../utils/graph/__generated__/GraphContainerCorrelationObjectsQuery.graphql';
import GraphContainerCorrelation, { graphContainerCorrelationObjectsQuery } from '../../../../utils/graph/GraphContainerCorrelation';
import Loader from '../../../../components/Loader';

export const caseRfiKnowledgeCorrelationQuery = graphql`
  query CaseRfiKnowledgeCorrelationQuery($id: String!) {
    caseRfi(id: $id) {
      ...GraphContainerCorrelationPositions_fragment
    }
  }
`;

interface CaseRfiKnowledgeCorrelationProps {
  data: NonNullable<CaseRfiKnowledgeCorrelationQuery$data['caseRfi']>
  id: string
}

const CaseRfiKnowledgeCorrelation = ({
  data,
  id,
}: CaseRfiKnowledgeCorrelationProps) => {
  const PAGE_SIZE = 500;
  const queryObjectsRef = useQueryLoading<GraphContainerCorrelationObjectsQuery>(
    graphContainerCorrelationObjectsQuery,
    { id, count: PAGE_SIZE },
  );

  const [commitEditPositions] = useCaseRfiKnowledgeCorrelationEdit();

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
        containerType='caseRfi'
        dataPositions={data}
        onPositionsChanged={savePositions}
      />
    </Suspense>
  );
};

export default CaseRfiKnowledgeCorrelation;
