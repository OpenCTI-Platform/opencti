import React from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import GraphClustersGrowthChart from '../../../../private/components/common/graph_analytics/GraphClustersGrowthChart';
import { formatGraphClusterLabel, trimLeadingEmptyPeriods } from '../../../../private/components/common/graph_analytics/graphAnalyticsUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Widget } from '../../../../utils/widget/widget';
import { getWidgetInterval } from '../../../../utils/widget/widgetUtils';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import usePublicDashboardViz from '../usePublicDashboardViz';
import usePublicWidgetDefaultDates from '../usePublicWidgetDefaultDates';
import type { PublicGraphClustersSizeQuery } from './__generated__/PublicGraphClustersSizeQuery.graphql';

const publicGraphClustersSizeQuery = graphql`
  query PublicGraphClustersSizeQuery($startDate: DateTime, $endDate: DateTime, $uriKey: String!, $widgetId: String!) {
    publicGraphClustersSizeTimeSeries(startDate: $startDate, endDate: $endDate, uriKey: $uriKey, widgetId: $widgetId) {
      cluster {
        id
        cluster_kind
        representatives {
          representative {
            main
          }
        }
      }
      data {
        date
        value
      }
    }
  }
`;

interface PublicGraphClustersSizeComponentProps {
  parameters: Widget['parameters'];
  queryRef: PreloadedQuery<PublicGraphClustersSizeQuery>;
}

const PublicGraphClustersSizeComponent = ({ parameters, queryRef }: PublicGraphClustersSizeComponentProps) => {
  const { t_i18n } = useFormatter();
  const { publicGraphClustersSizeTimeSeries } = usePreloadedQuery(publicGraphClustersSizeQuery, queryRef);
  if (!publicGraphClustersSizeTimeSeries || publicGraphClustersSizeTimeSeries.length === 0) {
    return <WidgetNoData message={t_i18n('No cluster yet - clusters appear when an analytics pass finds entities sharing infrastructure')} />;
  }
  const points = trimLeadingEmptyPeriods(publicGraphClustersSizeTimeSeries.map((serie) => serie.data));
  return (
    <GraphClustersGrowthChart
      series={publicGraphClustersSizeTimeSeries.map((serie, index) => ({
        name: formatGraphClusterLabel(t_i18n, serie.cluster),
        data: points[index].map((entry) => ({ x: new Date(entry.date), y: entry.value })),
      }))}
      interval={getWidgetInterval(parameters ?? undefined)}
      hasLegend={parameters?.legend ?? true}
    />
  );
};

const PublicGraphClustersSize = ({ uriKey, widget, startDate, endDate, title }: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters } = widget;
  const dates = usePublicWidgetDefaultDates(startDate, endDate);
  const queryRef = usePublicDashboardViz<PublicGraphClustersSizeQuery>(publicGraphClustersSizeQuery, {
    uriKey,
    widgetId: id,
    ...dates,
  });
  return (
    <WidgetContainer title={parameters?.title ?? title ?? t_i18n('Largest clusters - members over time')}>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PublicGraphClustersSizeComponent queryRef={queryRef} parameters={parameters} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default PublicGraphClustersSize;
