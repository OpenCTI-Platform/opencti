import { graphql } from 'react-relay';
import React, { Suspense } from 'react';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import GraphContainerCorrelation, { graphContainerCorrelationObjectsQuery } from '../../../../utils/graph/GraphContainerCorrelation';
import { GraphContainerCorrelationObjectsQuery } from '../../../../utils/graph/__generated__/GraphContainerCorrelationObjectsQuery.graphql';
import useReportKnowledgeCorrelationEdit from './useReportKnowledgeCorrelationEdit';
import { OctiGraphPositions } from '../../../../utils/graph/graph.types';
import { serializeObjectB64 } from '../../../../utils/object';
import Loader from '../../../../components/Loader';
import { ReportKnowledgeCorrelationQuery$data } from './__generated__/ReportKnowledgeCorrelationQuery.graphql';

export const reportKnowledgeCorrelationQuery = graphql`
  query ReportKnowledgeCorrelationQuery($id: String) {
    report(id: $id) {
      ...GraphContainerCorrelationPositions_fragment
    }
  }
`;

interface ReportKnowledgeCorrelationProps {
  data: NonNullable<ReportKnowledgeCorrelationQuery$data['report']>
  id: string
}

const ReportKnowledgeCorrelation = ({
  data,
  id,
}: ReportKnowledgeCorrelationProps) => {
  const PAGE_SIZE = 500;
  const queryObjectsRef = useQueryLoading<GraphContainerCorrelationObjectsQuery>(
    graphContainerCorrelationObjectsQuery,
    { id, count: PAGE_SIZE },
  );

  const [commitEditPositions] = useReportKnowledgeCorrelationEdit();

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
        containerType='report'
        dataPositions={data}
        onPositionsChanged={savePositions}
      />
    </Suspense>
  );
};

export default ReportKnowledgeCorrelation;
