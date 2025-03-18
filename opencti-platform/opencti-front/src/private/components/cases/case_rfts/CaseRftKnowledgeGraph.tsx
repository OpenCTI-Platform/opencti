import React, { Suspense } from 'react';
import { graphql } from 'react-relay';
import CaseRftPopover from './CaseRftPopover';
import { CaseRftKnowledgeGraphQuery$data } from './__generated__/CaseRftKnowledgeGraphQuery.graphql';
import useCaseRftKnowledgeGraphDeleteRelation from './useCaseRftKnowledgeGraphDeleteRelation';
import { OctiGraphPositions } from '../../../../components/graph/graph.types';
import useCaseRftKnowledgeGraphAddRelation from './useCaseRftKnowledgeGraphAddRelation';
import useCaseRftKnowledgeGraphEdit from './useCaseRftKnowledgeGraphEdit';
import { GraphToolbarProps } from '../../../../components/graph/GraphToolbar';
import { serializeObjectB64 } from '../../../../utils/object';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import { GraphContainerKnowledgeObjectsQuery } from '../../../../components/graph/__generated__/GraphContainerKnowledgeObjectsQuery.graphql';
import GraphContainerKnowledge, { graphContainerKnowledgeObjectsQuery } from '../../../../components/graph/GraphContainerKnowledge';

export const caseRftKnowledgeGraphQuery = graphql`
  query CaseRftKnowledgeGraphQuery($id: String!) {
    caseRft(id: $id) {
      ...ContainerHeader_container
      ...GraphContainerKnowledgeData_fragment
      ...GraphContainerKnowledgePositions_fragment
    }
  }
`;

interface CaseRftKnowledgeGraphProps {
  data: NonNullable<CaseRftKnowledgeGraphQuery$data['caseRft']>
  id: string
  mode: string
  enableReferences: boolean
}

const CaseRftKnowledgeGraph = ({
  id,
  data,
  mode,
  enableReferences,
}: CaseRftKnowledgeGraphProps) => {
  const PAGE_SIZE = 500;
  const queryObjectsRef = useQueryLoading<GraphContainerKnowledgeObjectsQuery>(
    graphContainerKnowledgeObjectsQuery,
    { id, count: PAGE_SIZE },
  );

  const [commitEditPositions] = useCaseRftKnowledgeGraphEdit();
  const [commitAddRelation] = useCaseRftKnowledgeGraphAddRelation();
  const [commitDeleteRelation] = useCaseRftKnowledgeGraphDeleteRelation();

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
        containerType='caseRft'
        enableReferences={enableReferences}
        dataContainer={data}
        dataHeader={data}
        dataPositions={data}
        containerHeaderProps={{
          modes: ['graph', 'content', 'timeline', 'correlation', 'matrix'],
          mode,
          link: `/dashboard/cases/rfts/${id}/knowledge`,
          PopoverComponent: <CaseRftPopover id={id} />,
        }}
        onAddRelation={addRelationInGraph}
        onDeleteRelation={deleteRelationInGraph}
        onPositionsChanged={savePositions}
      />
    </Suspense>
  );
};

export default CaseRftKnowledgeGraph;
