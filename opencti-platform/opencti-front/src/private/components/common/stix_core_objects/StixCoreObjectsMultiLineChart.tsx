import React, { ReactNode, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiLines from '../../../../components/dashboard/WidgetMultiLines';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { StixCoreObjectsMultiLineChartTimeSeriesQuery } from './__generated__/StixCoreObjectsMultiLineChartTimeSeriesQuery.graphql';
import { computeStartEndDates } from '../../../../components/dashboard/dashboard-viz-utils';
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
  const computed = computeStartEndDates(config);
  const startDate = computed.startDate ?? monthsAgo(12);
  const endDate = computed.endDate ?? now();
  const timeSeriesParameters = resolvedDataSelection.map((selection) => {
    const dateAttribute
      = selection.date_attribute && selection.date_attribute.length > 0
        ? selection.date_attribute
        : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(
      selection.filters,
      { startDate, endDate, dateAttribute },
    );
    return {
      field: dateAttribute,
      types: DATA_SELECTION_TYPES,
      filters: normalizeFilterGroupForBackend(filters),
    };
  });
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
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsMultiLineChartTimeSeriesQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsMultiLineChartTimeSeriesQuery,
    config,
    parameters,
    buildQueryVariables,
  });

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (!queryRef) return null;

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <StixCoreObjectsMultiLineChartComponent
          queryRef={queryRef}
          dataSelection={resolvedDataSelection}
          parameters={parameters}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Entities history')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixCoreObjectsMultiLineChart;
