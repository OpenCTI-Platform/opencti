import React, { Suspense } from 'react';
import { graphql } from 'react-relay';
import IncidentPopover from './CaseIncidentPopover';
import { IncidentKnowledgeGraphQuery$data } from './__generated__/IncidentKnowledgeGraphQuery.graphql';
import useIncidentKnowledgeGraphDeleteRelation from './useIncidentKnowledgeGraphDeleteRelation';
import { OctiGraphPositions } from '../../../../components/graph/graph.types';
import useIncidentKnowledgeGraphAddRelation from './useIncidentKnowledgeGraphAddRelation';
import useIncidentKnowledgeGraphEdit from './useIncidentKnowledgeGraphEdit';
import { GraphToolbarProps } from '../../../../components/graph/GraphToolbar';
import { serializeObjectB64 } from '../../../../utils/object';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import { GraphContainerKnowledgeObjectsQuery } from '../../../../components/graph/__generated__/GraphContainerKnowledgeObjectsQuery.graphql';
import GraphContainerKnowledge, { graphContainerKnowledgeObjectsQuery } from '../../../../components/graph/GraphContainerKnowledge';

export const incidentKnowledgeGraphQuery = graphql`
  query IncidentKnowledgeGraphQuery($id: String!) {
    caseIncident(id: $id) {
      ...ContainerHeader_container
      ...GraphContainerKnowledgeData_fragment
      ...GraphContainerKnowledgePositions_fragment
    }
  }
`;

interface IncidentKnowledgeGraphProps {
  data: NonNullable<IncidentKnowledgeGraphQuery$data['caseIncident']>
  id: string
  mode: string
  enableReferences: boolean
}

const IncidentKnowledgeGraph = ({
  id,
  data,
  mode,
  enableReferences,
}: IncidentKnowledgeGraphProps) => {
  const PAGE_SIZE = 500;
  const queryObjectsRef = useQueryLoading<GraphContainerKnowledgeObjectsQuery>(
    graphContainerKnowledgeObjectsQuery,
    { id, count: PAGE_SIZE },
  );

  const [commitEditPositions] = useIncidentKnowledgeGraphEdit();
  const [commitAddRelation] = useIncidentKnowledgeGraphAddRelation();
  const [commitDeleteRelation] = useIncidentKnowledgeGraphDeleteRelation();

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
        containerType='incident'
        enableReferences={enableReferences}
        dataContainer={data}
        dataHeader={data}
        dataPositions={data}
        containerHeaderProps={{
          modes: ['graph', 'content', 'timeline', 'correlation', 'matrix'],
          mode,
          link: `/dashboard/cases/incidents/${id}/knowledge`,
          PopoverComponent: <IncidentPopover id={id} />,
        }}
        onAddRelation={addRelationInGraph}
        onDeleteRelation={deleteRelationInGraph}
        onPositionsChanged={savePositions}
      />
    </Suspense>
  );
};

export default IncidentKnowledgeGraph;
