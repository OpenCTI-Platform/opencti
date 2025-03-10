import React, { Suspense } from 'react';
import { graphql } from 'react-relay';
import ReportPopover from './ReportPopover';
import { ReportKnowledgeGraphQuery$data } from './__generated__/ReportKnowledgeGraphQuery.graphql';
import useReportKnowledgeGraphDeleteRelation from './useReportKnowledgeGraphDeleteRelation';
import { OctiGraphPositions } from '../../../../utils/graph/graph.types';
import useReportKnowledgeGraphAddRelation from './useReportKnowledgeGraphAddRelation';
import useReportKnowledgeGraphEdit from './useReportKnowledgeGraphEdit';
import { GraphToolbarProps } from '../../../../utils/graph/GraphToolbar';
import { serializeObjectB64 } from '../../../../utils/object';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import { GraphContainerKnowledgeObjectsQuery } from '../../../../utils/graph/__generated__/GraphContainerKnowledgeObjectsQuery.graphql';
import GraphContainerKnowledge, { graphContainerKnowledgeObjectsQuery } from '../../../../utils/graph/GraphContainerKnowledge';

export const reportKnowledgeGraphQuery = graphql`
  query ReportKnowledgeGraphQuery($id: String) {
    report(id: $id) {
      ...ContainerHeader_container
      ...GraphContainerKnowledgeData_fragment
      ...GraphContainerKnowledgePositions_fragment
    }
  }
`;

interface ReportKnowledgeGraphProps {
  data: NonNullable<ReportKnowledgeGraphQuery$data['report']>
  id: string
  mode: string
  enableReferences: boolean
}

const ReportKnowledgeGraph = ({
  id,
  data,
  mode,
  enableReferences,
}: ReportKnowledgeGraphProps) => {
  const PAGE_SIZE = 500;
  const queryObjectsRef = useQueryLoading<GraphContainerKnowledgeObjectsQuery>(
    graphContainerKnowledgeObjectsQuery,
    { id, count: PAGE_SIZE },
  );

  const [commitEditPositions] = useReportKnowledgeGraphEdit();
  const [commitAddRelation] = useReportKnowledgeGraphAddRelation();
  const [commitDeleteRelation] = useReportKnowledgeGraphDeleteRelation();

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
    commitMessage,
    references,
  ) => {
    commitDeleteRelation({
      variables: {
        id,
        toId: relId,
        relationship_type: 'object',
        commitMessage,
        references,
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
        containerType='report'
        enableReferences={enableReferences}
        dataContainer={data}
        dataHeader={data}
        dataPositions={data}
        containerHeaderProps={{
          modes: ['graph', 'content', 'timeline', 'correlation', 'matrix'],
          mode,
          link: `/dashboard/analyses/reports/${id}/knowledge`,
          PopoverComponent: <ReportPopover id={id} />,
        }}
        onAddRelation={addRelationInGraph}
        onDeleteRelation={deleteRelationInGraph}
        onPositionsChanged={savePositions}
      />
    </Suspense>
  );
};

export default ReportKnowledgeGraph;
