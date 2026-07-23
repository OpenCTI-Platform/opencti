import React, { ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiLines from '../../../../components/dashboard/WidgetMultiLines';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { StixCoreObjectsMultiLineChartTimeSeriesQuery } from './__generated__/StixCoreObjectsMultiLineChartTimeSeriesQuery.graphql';
import { computeWidgetFiltersForMultiSelection } from '../../../../components/dashboard/dashboardVizUtils';
import { getWidgetInterval } from 'src/utils/widget/widgetUtils';

const stixCoreObjectsMultiLineChartTimeSeriesQuery = graphql`
  query StixCoreObjectsMultiLineChartTimeSeriesQuery(
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

interface StixCoreObjectsMultiLineChartComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsMultiLineChartTimeSeriesQuery>;
  dataSelection: Widget['dataSelection'];
  parameters: {
    title?: string;
    interval?: string;
    legend?: boolean;
  };
}

const StixCoreObjectsMultiLineChartComponent = ({
  queryRef,
  dataSelection,
  parameters,
}: StixCoreObjectsMultiLineChartComponentProps) => {
  const { t_i18n } = useFormatter();

  const { stixCoreObjectsMultiTimeSeries } = usePreloadedQuery(
    stixCoreObjectsMultiLineChartTimeSeriesQuery,
    queryRef,
  );

  if (stixCoreObjectsMultiTimeSeries) {
    return (
      <WidgetMultiLines
        series={stixCoreObjectsMultiTimeSeries.map((serie, i) => ({
          name: dataSelection[i]?.label ?? t_i18n('Number of entities'),
          data: (serie?.data ?? []).map((entry) => ({
            x: new Date(entry?.date),
            y: entry?.value,
          })),
        }))}
        interval={parameters.interval}
        hasLegend={parameters.legend}
      />
    );
  }

  return <WidgetNoData />;
};

interface StixCoreObjectsMultiLineChartProps {
  variant?: string;
  height?: number;
  dataSelection: Widget['dataSelection'];
  parameters?: {
    title?: string;
    interval?: string;
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
): StixCoreObjectsMultiLineChartTimeSeriesQuery['variables'] => {
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

const StixCoreObjectsMultiLineChart = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  config,
  refreshRate = null,
  popover,
  host,
}: StixCoreObjectsMultiLineChartProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsMultiLineChartTimeSeriesQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsMultiLineChartTimeSeriesQuery,
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
        <StixCoreObjectsMultiLineChartComponent
          queryRef={queryRef!}
          dataSelection={resolvedDataSelection}
          parameters={parameters}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default StixCoreObjectsMultiLineChart;
