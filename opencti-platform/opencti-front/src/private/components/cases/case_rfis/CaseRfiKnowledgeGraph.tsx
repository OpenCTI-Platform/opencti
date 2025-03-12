import React, { Suspense } from 'react';
import { graphql } from 'react-relay';
import CaseRfiPopover from './CaseRfiPopover';
import { CaseRfiKnowledgeGraphQuery$data } from './__generated__/CaseRfiKnowledgeGraphQuery.graphql';
import useCaseRfiKnowledgeGraphDeleteRelation from './useCaseRfiKnowledgeGraphDeleteRelation';
import { OctiGraphPositions } from '../../../../utils/graph/graph.types';
import useCaseRfiKnowledgeGraphAddRelation from './useCaseRfiKnowledgeGraphAddRelation';
import useCaseRfiKnowledgeGraphEdit from './useCaseRfiKnowledgeGraphEdit';
import { GraphToolbarProps } from '../../../../utils/graph/GraphToolbar';
import { serializeObjectB64 } from '../../../../utils/object';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import { GraphContainerKnowledgeObjectsQuery } from '../../../../utils/graph/__generated__/GraphContainerKnowledgeObjectsQuery.graphql';
import GraphContainerKnowledge, { graphContainerKnowledgeObjectsQuery } from '../../../../utils/graph/GraphContainerKnowledge';

export const caseRfiKnowledgeGraphQuery = graphql`
  query CaseRfiKnowledgeGraphQuery($id: String!) {
    caseRfi(id: $id) {
      ...ContainerHeader_container
      ...GraphContainerKnowledgeData_fragment
      ...GraphContainerKnowledgePositions_fragment
    }
  }
`;

interface CaseRfiKnowledgeGraphProps {
  data: NonNullable<CaseRfiKnowledgeGraphQuery$data['caseRfi']>
  id: string
  mode: string
  enableReferences: boolean
}

const CaseRfiKnowledgeGraph = ({
  id,
  data,
  mode,
  enableReferences,
}: CaseRfiKnowledgeGraphProps) => {
  const PAGE_SIZE = 500;
  const queryObjectsRef = useQueryLoading<GraphContainerKnowledgeObjectsQuery>(
    graphContainerKnowledgeObjectsQuery,
    { id, count: PAGE_SIZE },
  );

  const [commitEditPositions] = useCaseRfiKnowledgeGraphEdit();
  const [commitAddRelation] = useCaseRfiKnowledgeGraphAddRelation();
  const [commitDeleteRelation] = useCaseRfiKnowledgeGraphDeleteRelation();

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
        containerType='caseRfi'
        enableReferences={enableReferences}
        dataContainer={data}
        dataHeader={data}
        dataPositions={data}
        containerHeaderProps={{
          modes: ['graph', 'content', 'timeline', 'correlation', 'matrix'],
          mode,
          link: `/dashboard/cases/rfis/${id}/knowledge`,
          PopoverComponent: <CaseRfiPopover id={id} />,
        }}
        onAddRelation={addRelationInGraph}
        onDeleteRelation={deleteRelationInGraph}
        onPositionsChanged={savePositions}
      />
    </Suspense>
  );
};

export default CaseRfiKnowledgeGraph;
