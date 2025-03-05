import { graphql } from 'react-relay';
import React, { Suspense } from 'react';
import { CaseRftKnowledgeCorrelationQuery$data } from './__generated__/CaseRftKnowledgeCorrelationQuery.graphql';
import useCaseRftKnowledgeCorrelationEdit from './useCaseRftKnowledgeCorrelationEdit';
import { OctiGraphPositions } from '../../../../utils/graph/graph.types';
import { serializeObjectB64 } from '../../../../utils/object';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { GraphContainerCorrelationObjectsQuery } from '../../../../utils/graph/__generated__/GraphContainerCorrelationObjectsQuery.graphql';
import GraphContainerCorrelation, { graphContainerCorrelationObjectsQuery } from '../../../../utils/graph/GraphContainerCorrelation';
import Loader from '../../../../components/Loader';

export const caseRftKnowledgeCorrelationQuery = graphql`
  query CaseRftKnowledgeCorrelationQuery($id: String!) {
    caseRft(id: $id) {
      ...GraphContainerCorrelationPositions_fragment
    }
  }
`;

interface CaseRftKnowledgeCorrelationProps {
  data: NonNullable<CaseRftKnowledgeCorrelationQuery$data['caseRft']>
  id: string
}

const CaseRftKnowledgeCorrelation = ({
  data,
  id,
}: CaseRftKnowledgeCorrelationProps) => {
  const PAGE_SIZE = 500;
  const queryObjectsRef = useQueryLoading<GraphContainerCorrelationObjectsQuery>(
    graphContainerCorrelationObjectsQuery,
    { id, count: PAGE_SIZE },
  );

  const [commitEditPositions] = useCaseRftKnowledgeCorrelationEdit();

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
        containerType='caseRft'
        dataPositions={data}
        onPositionsChanged={savePositions}
      />
    </Suspense>
  );
};

export default CaseRftKnowledgeCorrelation;
