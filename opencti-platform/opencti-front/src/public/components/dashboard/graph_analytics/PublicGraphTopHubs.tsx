import React from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { ErrorBoundary } from '../../../../private/components/Error';
import { buildGraphTopHubsChart } from '../../../../private/components/common/graph_analytics/graphAnalyticsUtils';
import type { Widget } from '../../../../utils/widget/widget';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import usePublicDashboardViz from '../usePublicDashboardViz';
import usePublicWidgetDefaultDates from '../usePublicWidgetDefaultDates';
import type { PublicGraphTopHubsQuery } from './__generated__/PublicGraphTopHubsQuery.graphql';

const publicGraphTopHubsQuery = graphql`
  query PublicGraphTopHubsQuery($startDate: DateTime, $endDate: DateTime, $uriKey: String!, $widgetId: String!) {
    publicStixCoreObjects(startDate: $startDate, endDate: $endDate, uriKey: $uriKey, widgetId: $widgetId) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
          x_opencti_graph_metrics {
            degree
          }
        }
      }
    }
  }
`;

interface PublicGraphTopHubsComponentProps {
  parameters: Widget['parameters'];
  queryRef: PreloadedQuery<PublicGraphTopHubsQuery>;
}

const PublicGraphTopHubsComponent = ({ parameters, queryRef }: PublicGraphTopHubsComponentProps) => {
  const { t_i18n } = useFormatter();
  const { publicStixCoreObjects } = usePreloadedQuery(publicGraphTopHubsQuery, queryRef);
  const { series, redirectionUtils } = buildGraphTopHubsChart((publicStixCoreObjects?.edges ?? []).map((edge) => edge.node), t_i18n('Graph degree'));
  if (redirectionUtils.length === 0) {
    return <WidgetNoData />;
  }
  return <WidgetHorizontalBars series={series} distributed={parameters?.distributed ?? undefined} redirectionUtils={redirectionUtils} />;
};

// The ranking is refused when the dashboard cannot read every relationship of the platform
const PublicGraphTopHubsRestricted = () => {
  const { t_i18n } = useFormatter();
  return <WidgetNoData message={t_i18n('This widget is ranked by graph metrics, which require access to every relationship of the platform.')} />;
};

const PublicGraphTopHubs = ({ uriKey, widget, startDate, endDate, title }: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters } = widget;
  const dates = usePublicWidgetDefaultDates(startDate, endDate);
  const queryRef = usePublicDashboardViz<PublicGraphTopHubsQuery>(publicGraphTopHubsQuery, {
    uriKey,
    widgetId: id,
    ...dates,
  });
  return (
    <WidgetContainer title={parameters?.title ?? title ?? t_i18n('Top hubs - by degree')}>
      {queryRef ? (
        <ErrorBoundary display={PublicGraphTopHubsRestricted}>
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <PublicGraphTopHubsComponent queryRef={queryRef} parameters={parameters} />
          </React.Suspense>
        </ErrorBoundary>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default PublicGraphTopHubs;
