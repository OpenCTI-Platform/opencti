import React, { ReactNode, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiAreas from '../../../../components/dashboard/WidgetMultiAreas';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import WidgetNoSavedFilters from 'src/components/dashboard/WidgetNoSavedFilters';
import { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { StixCoreObjectsMultiAreaChartTimeSeriesQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsMultiAreaChartTimeSeriesQuery.graphql';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';
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

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (isMissingSavedFilters) {
      return <WidgetNoSavedFilters />;
    }

    if (!queryRef) return null;

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <StixCoreObjectsMultiAreaChartComponent
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

export default StixCoreObjectsMultiAreaChart;
