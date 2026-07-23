import React, { ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiAreas from '../../../../components/dashboard/WidgetMultiAreas';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { StixCoreObjectsMultiAreaChartTimeSeriesQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsMultiAreaChartTimeSeriesQuery.graphql';
import { computeWidgetFiltersForMultiSelection } from '../../../../components/dashboard/dashboardVizUtils';
import { getWidgetInterval } from 'src/utils/widget/widgetUtils';

const stixCoreObjectsMultiAreaChartTimeSeriesQuery = graphql`
  query StixCoreObjectsMultiAreaChartTimeSeriesQuery(
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $timeSeriesParameters: [StixCoreObjectsTimeSeriesParameters]
  ) {
    stixCoreObjectsMultiTimeSeries(
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      timeSeriesParameters: $timeSeriesParameters
    ) {
      data {
        date
        value
      }
    }
  }
`;

interface StixCoreObjectsMultiAreaChartComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsMultiAreaChartTimeSeriesQuery>;
  dataSelection: Widget['dataSelection'];
  parameters: {
    title?: string;
    interval?: string;
    stacked?: boolean;
    legend?: boolean;
  };
}

const StixCoreObjectsMultiAreaChartComponent = ({
  queryRef,
  dataSelection,
  parameters,
}: StixCoreObjectsMultiAreaChartComponentProps) => {
  const { t_i18n } = useFormatter();

  const { stixCoreObjectsMultiTimeSeries } = usePreloadedQuery(
    stixCoreObjectsMultiAreaChartTimeSeriesQuery,
    queryRef,
  );

  if (stixCoreObjectsMultiTimeSeries) {
    return (
      <WidgetMultiAreas
        series={stixCoreObjectsMultiTimeSeries.map((serie, i) => ({
          name: dataSelection[i]?.label ?? t_i18n('Number of entities'),
          data: (serie?.data ?? []).map((entry) => ({
            x: new Date(entry?.date),
            y: entry?.value,
          })),
        }))}
        interval={parameters.interval}
        isStacked={parameters.stacked}
        hasLegend={parameters.legend}
      />
    );
  }

  return <WidgetNoData />;
};

interface StixCoreObjectsMultiAreaChartProps {
  variant?: string;
  height?: number;
  dataSelection: Widget['dataSelection'];
  parameters?: {
    title?: string;
    interval?: string;
    stacked?: boolean;
    legend?: boolean;
  };
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
): StixCoreObjectsMultiAreaChartTimeSeriesQuery['variables'] => {
  const { startDate, endDate, timeSeriesParameters } = computeWidgetFiltersForMultiSelection(
    resolvedDataSelection,
    config,
    DATA_SELECTION_TYPES,
    { fallbackToDefaultDates: true },
  );
  return {
    startDate,
    endDate,
    interval: getWidgetInterval(parameters),
    timeSeriesParameters,
  };
};

const StixCoreObjectsMultiAreaChart = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  config,
  refreshRate = null,
  host,
}: StixCoreObjectsMultiAreaChartProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsMultiAreaChartTimeSeriesQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsMultiAreaChartTimeSeriesQuery,
    config,
    parameters,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Entities history')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <WidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        <StixCoreObjectsMultiAreaChartComponent
          queryRef={queryRef!}
          dataSelection={resolvedDataSelection}
          parameters={parameters}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default StixCoreObjectsMultiAreaChart;
