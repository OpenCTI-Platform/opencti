import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { useState } from 'react';
import ApexCharts from 'apexcharts';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import usePublicDashboardViz from '../usePublicDashboardViz';
import usePublicWidgetDefaultDates from '../usePublicWidgetDefaultDates';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetTimeSeriesBreakdown from '../../../../components/dashboard/WidgetTimeSeriesBreakdown';
import WidgetBreakdownErrorBoundary from '../../../../components/dashboard/WidgetBreakdownErrorBoundary';
import { PublicStixCoreObjectsTimeSeriesBreakdownQuery } from './__generated__/PublicStixCoreObjectsTimeSeriesBreakdownQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Widget } from '../../../../utils/widget/widget';
import { getWidgetInterval } from '../../../../utils/widget/widgetUtils';
import { getBreakdownDefaultStartDate } from '../../../../utils/widget/widgetBreakdown';

const publicStixCoreObjectsTimeSeriesBreakdownQuery = graphql`
  query PublicStixCoreObjectsTimeSeriesBreakdownQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId: String!
  ) {
    publicStixCoreObjectsTimeSeriesBreakdown(
      startDate: $startDate
      endDate: $endDate
      uriKey: $uriKey
      widgetId: $widgetId
    ) {
      truncated
      dates
      series {
        label
        isOther
        entity {
          ... on BasicObject {
            id
            entity_type
          }
          ... on StixObject {
            representative {
              main
            }
          }
          # internal objects
          ... on Creator {
            id
            name
          }
        }
        values
      }
    }
  }
`;

interface PublicStixCoreObjectsTimeSeriesBreakdownComponentProps {
  type: string;
  parameters: NonNullable<Widget['parameters']>;
  queryRef: PreloadedQuery<PublicStixCoreObjectsTimeSeriesBreakdownQuery>;
  onMounted: (chart: ApexCharts) => void;
  onWarningChange: (warning?: string) => void;
}

const PublicStixCoreObjectsTimeSeriesBreakdownComponent = ({
  type,
  parameters,
  queryRef,
  onMounted,
  onWarningChange,
}: PublicStixCoreObjectsTimeSeriesBreakdownComponentProps) => {
  const { publicStixCoreObjectsTimeSeriesBreakdown } = usePreloadedQuery(
    publicStixCoreObjectsTimeSeriesBreakdownQuery,
    queryRef,
  );
  return (
    <WidgetTimeSeriesBreakdown
      breakdown={publicStixCoreObjectsTimeSeriesBreakdown}
      type={type}
      parameters={parameters}
      onMounted={onMounted}
      onWarningChange={onWarningChange}
    />
  );
};

const PublicStixCoreObjectsTimeSeriesBreakdown = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const [warning, setWarning] = useState<string>();
  const { id, type } = widget;
  const parameters = widget.parameters ?? {};
  // Same default as the dashboard widget: a daily breakdown only looks back a short while
  const dates = usePublicWidgetDefaultDates(
    startDate,
    endDate,
    () => getBreakdownDefaultStartDate(getWidgetInterval(parameters)),
  );
  const queryRef = usePublicDashboardViz<PublicStixCoreObjectsTimeSeriesBreakdownQuery>(
    publicStixCoreObjectsTimeSeriesBreakdownQuery,
    {
      uriKey,
      widgetId: id,
      ...dates,
    },
  );

  return (
    <WidgetContainer
      title={parameters.title ?? title ?? t_i18n('Entities history')}
      chart={chart}
      warning={warning}
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <WidgetBreakdownErrorBoundary resetKey={queryRef}>
            <PublicStixCoreObjectsTimeSeriesBreakdownComponent
              queryRef={queryRef}
              type={type}
              parameters={parameters}
              onMounted={setChart}
              onWarningChange={setWarning}
            />
          </WidgetBreakdownErrorBoundary>
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsTimeSeriesBreakdown;
