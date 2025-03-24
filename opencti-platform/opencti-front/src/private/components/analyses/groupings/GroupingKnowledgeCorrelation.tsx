import { graphql } from 'react-relay';
import React, { Suspense } from 'react';
import useGroupingKnowledgeCorrelationEdit from './useGroupingKnowledgeCorrelationEdit';
import { OctiGraphPositions } from '../../../../components/graph/graph.types';
import { serializeObjectB64 } from '../../../../utils/object';
import { GroupingKnowledgeCorrelationQuery$data } from './__generated__/GroupingKnowledgeCorrelationQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { GraphContainerCorrelationObjectsQuery } from '../../../../components/graph/__generated__/GraphContainerCorrelationObjectsQuery.graphql';
import GraphContainerCorrelation, { graphContainerCorrelationObjectsQuery } from '../../../../components/graph/GraphContainerCorrelation';
import Loader from '../../../../components/Loader';

export const groupingKnowledgeCorrelationQuery = graphql`
  query GroupingKnowledgeCorrelationQuery($id: String!) {
    grouping(id: $id) {
      ...GraphContainerCorrelationPositions_fragment
    }
  }
`;

interface GroupingKnowledgeCorrelationProps {
  data: NonNullable<GroupingKnowledgeCorrelationQuery$data['grouping']>
  id: string
}

const GroupingKnowledgeCorrelation = ({
  data,
  id,
}: GroupingKnowledgeCorrelationProps) => {
  const PAGE_SIZE = 500;
  const queryObjectsRef = useQueryLoading<GraphContainerCorrelationObjectsQuery>(
    graphContainerCorrelationObjectsQuery,
    { id, count: PAGE_SIZE },
  );

  const [commitEditPositions] = useGroupingKnowledgeCorrelationEdit();

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
        containerType='grouping'
        dataPositions={data}
        onPositionsChanged={savePositions}
      />
    </Suspense>
  );
};

export default GroupingKnowledgeCorrelation;
