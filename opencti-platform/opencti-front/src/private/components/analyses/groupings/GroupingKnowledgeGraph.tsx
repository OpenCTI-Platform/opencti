import React, { Suspense } from 'react';
import { graphql } from 'react-relay';
import GroupingPopover from './GroupingPopover';
import { GroupingKnowledgeGraphQuery$data } from './__generated__/GroupingKnowledgeGraphQuery.graphql';
import useGroupingKnowledgeGraphDeleteRelation from './useGroupingKnowledgeGraphDeleteRelation';
import { OctiGraphPositions } from '../../../../utils/graph/graph.types';
import useGroupingKnowledgeGraphAddRelation from './useGroupingKnowledgeGraphAddRelation';
import useGroupingKnowledgeGraphEdit from './useGroupingKnowledgeGraphEdit';
import { GraphToolbarProps } from '../../../../utils/graph/GraphToolbar';
import { serializeObjectB64 } from '../../../../utils/object';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import { GraphContainerKnowledgeObjectsQuery } from '../../../../utils/graph/__generated__/GraphContainerKnowledgeObjectsQuery.graphql';
import GraphContainerKnowledge, { graphContainerKnowledgeObjectsQuery } from '../../../../utils/graph/GraphContainerKnowledge';

export const groupingKnowledgeGraphQuery = graphql`
  query GroupingKnowledgeGraphQuery($id: String!) {
    grouping(id: $id) {
      ...ContainerHeader_container
      ...GraphContainerKnowledgeData_fragment
      ...GraphContainerKnowledgePositions_fragment
    }
  }
`;

interface GroupingKnowledgeGraphProps {
  data: NonNullable<GroupingKnowledgeGraphQuery$data['grouping']>
  id: string
  mode: string
  enableReferences: boolean
}

const GroupingKnowledgeGraph = ({
  id,
  data,
  mode,
  enableReferences,
}: GroupingKnowledgeGraphProps) => {
  const PAGE_SIZE = 500;
  const queryObjectsRef = useQueryLoading<GraphContainerKnowledgeObjectsQuery>(
    graphContainerKnowledgeObjectsQuery,
    { id, count: PAGE_SIZE },
  );

  const [commitEditPositions] = useGroupingKnowledgeGraphEdit();
  const [commitAddRelation] = useGroupingKnowledgeGraphAddRelation();
  const [commitDeleteRelation] = useGroupingKnowledgeGraphDeleteRelation();

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

  const addRelationInGraph: GraphToolbarProps['onAddRelation'] = (rel, onCompleted) => {
    commitAddRelation({
      variables: {
        id,
        input: {
          toId: rel.id,
          relationship_type: 'object',
        },
      },
      onCompleted,
    });
  };

  const deleteRelationInGraph: GraphToolbarProps['onDeleteRelation'] = (
    relId,
    onCompleted,
  ) => {
    commitDeleteRelation({
      variables: {
        id,
        toId: relId,
        relationship_type: 'object',
      },
      onCompleted,
    });
  };

  if (!queryObjectsRef) return null;

  return (
    <Suspense fallback={<Loader />}>
      <GraphContainerKnowledge
        queryObjectsRef={queryObjectsRef}
        pageSize={PAGE_SIZE}
        containerId={id}
        containerType='grouping'
        enableReferences={enableReferences}
        dataContainer={data}
        dataHeader={data}
        dataPositions={data}
        containerHeaderProps={{
          modes: ['graph', 'content', 'correlation', 'matrix'],
          mode,
          link: `/dashboard/analyses/groupings/${id}/knowledge`,
          PopoverComponent: <GroupingPopover id={id} />,
        }}
        onAddRelation={addRelationInGraph}
        onDeleteRelation={deleteRelationInGraph}
        onPositionsChanged={savePositions}
      />
    </Suspense>
  );
};

export default GroupingKnowledgeGraph;
