import React, { ReactNode, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetMultiHeatMap from '../../../../components/dashboard/WidgetMultiHeatMap';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeWidgetFiltersForMultiSelection } from '../../../../components/dashboard/dashboardVizUtils';
import ApexCharts from 'apexcharts';
import { StixCoreObjectsMultiHeatMapTimeSeriesQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsMultiHeatMapTimeSeriesQuery.graphql';
import { getWidgetInterval } from 'src/utils/widget/widgetUtils';

const stixCoreObjectsMultiHeatMapTimeSeriesQuery = graphql`
  query StixCoreObjectsMultiHeatMapTimeSeriesQuery(
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

interface StixCoreObjectsMultiHeatMapComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsMultiHeatMapTimeSeriesQuery>;
  dataSelection: WidgetDataSelection[];
  resolvedDataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  onMounted?: (chart: ApexCharts) => void;
}

const StixCoreObjectsMultiHeatMapComponent = ({
  queryRef,
  resolvedDataSelection,
  parameters,
  onMounted,
}: StixCoreObjectsMultiHeatMapComponentProps) => {
  const data = usePreloadedQuery(
    stixCoreObjectsMultiHeatMapTimeSeriesQuery,
    queryRef,
  );
  const series = data?.stixCoreObjectsMultiTimeSeries ?? [];

  if (!series.length) {
    return <WidgetNoData />;
  }

  const chartData = resolvedDataSelection.map((selection, i) => {
    const s = series?.[i];

    return {
      name: selection.label ?? 'Number of entities',
      data:
          s?.data
            ?.filter((entry): entry is { date: string; value: number } => Boolean(entry))
            .map((entry) => ({
              x: new Date(entry.date),
              y: entry.value,
            })) ?? [],
    };
  });

  const allValues = series
    .filter((s): s is NonNullable<typeof s> => !!s)
    .flatMap((s) =>
      (s.data ?? [])
        .filter((d): d is NonNullable<typeof d> => !!d)
        .map((d) => d.value),
    );
  const minValue = allValues.length ? Math.min(...allValues) : 0;
  const maxValue = allValues.length ? Math.max(...allValues) : 0;

  return (
    <WidgetMultiHeatMap
      data={chartData}
      minValue={minValue}
      maxValue={maxValue}
      isStacked={parameters?.stacked ?? undefined}
      onMounted={onMounted}
    />
  );
};

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
): StixCoreObjectsMultiHeatMapTimeSeriesQuery['variables'] => {
  const { startDate, endDate, timeSeriesParameters } = computeWidgetFiltersForMultiSelection(resolvedDataSelection, config, DATA_SELECTION_TYPES, { fallbackToDefaultDates: true });
  return {
    startDate,
    endDate,
    interval: getWidgetInterval(parameters),
    timeSeriesParameters,
  };
};

interface StixCoreObjectsMultiHeatMapProps {
  variant?: string;
  height?: number;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixCoreObjectsMultiHeatMap = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixCoreObjectsMultiHeatMapProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsMultiHeatMapTimeSeriesQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsMultiHeatMapTimeSeriesQuery,
    config,
    parameters,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters?.title ?? t_i18n('Entities history')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <WidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        <StixCoreObjectsMultiHeatMapComponent
          queryRef={queryRef!}
          dataSelection={dataSelection}
          resolvedDataSelection={resolvedDataSelection}
          parameters={parameters}
          onMounted={setChart}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default StixCoreObjectsMultiHeatMap;
