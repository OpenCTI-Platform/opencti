import React from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import GraphSimilarityMatrix from '../../../../private/components/common/graph_analytics/GraphSimilarityMatrix';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import usePublicDashboardViz from '../usePublicDashboardViz';
import type { PublicGraphSimilarityMatrixQuery } from './__generated__/PublicGraphSimilarityMatrixQuery.graphql';

const publicGraphSimilarityMatrixQuery = graphql`
  query PublicGraphSimilarityMatrixQuery($startDate: DateTime, $endDate: DateTime, $uriKey: String!, $widgetId: String!) {
    publicGraphSimilarityMatrix(startDate: $startDate, endDate: $endDate, uriKey: $uriKey, widgetId: $widgetId) {
      entities {
        id
        entity_type
        representative {
          main
        }
      }
      cells {
        source_id
        target_id
        score
        shared_count
      }
    }
  }
`;

const PublicGraphSimilarityMatrixComponent = ({ queryRef }: { queryRef: PreloadedQuery<PublicGraphSimilarityMatrixQuery> }) => {
  const { publicGraphSimilarityMatrix } = usePreloadedQuery(publicGraphSimilarityMatrixQuery, queryRef);
  if (!publicGraphSimilarityMatrix || publicGraphSimilarityMatrix.entities.length < 2) {
    return <WidgetNoData />;
  }
  return <GraphSimilarityMatrix entities={publicGraphSimilarityMatrix.entities} cells={publicGraphSimilarityMatrix.cells} disableLinks />;
};

const PublicGraphSimilarityMatrix = ({ uriKey, widget, startDate, endDate, title }: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters } = widget;
  const queryRef = usePublicDashboardViz<PublicGraphSimilarityMatrixQuery>(publicGraphSimilarityMatrixQuery, {
    uriKey,
    widgetId: id,
    startDate,
    endDate,
  });
  return (
    <WidgetContainer title={parameters?.title ?? title ?? t_i18n('Similarity matrix')}>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PublicGraphSimilarityMatrixComponent queryRef={queryRef} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default PublicGraphSimilarityMatrix;
