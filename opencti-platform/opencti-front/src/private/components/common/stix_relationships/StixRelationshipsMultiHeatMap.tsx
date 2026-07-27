import React, { ReactNode, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiHeatMap from '../../../../components/dashboard/WidgetMultiHeatMap';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import { StixRelationshipsMultiHeatMapTimeSeriesQuery } from './__generated__/StixRelationshipsMultiHeatMapTimeSeriesQuery.graphql';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';
import { monthsAgo, now } from '../../../../utils/Time';
import { getWidgetInterval } from 'src/utils/widget/widgetUtils';

const stixRelationshipsMultiHeatMapTimeSeriesQuery = graphql`
  query StixRelationshipsMultiHeatMapTimeSeriesQuery(
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $timeSeriesParameters: [StixRelationshipsTimeSeriesParameters]
  ) {
    stixRelationshipsMultiTimeSeries(
      operation: $operation
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

interface StixRelationshipsMultiHeatMapComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsMultiHeatMapTimeSeriesQuery>;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  onMounted: (chart: unknown) => void;
}

const StixRelationshipsMultiHeatMapComponent = ({
  queryRef,
  dataSelection,
  parameters,
  onMounted,
}: StixRelationshipsMultiHeatMapComponentProps) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(
    stixRelationshipsMultiHeatMapTimeSeriesQuery,
    queryRef,
  );
  const series = data?.stixRelationshipsMultiTimeSeries ?? [];

  if (!series.length) {
    return <WidgetNoData />;
  }

  const chartData = dataSelection.map((selection, i) => {
    const s = series?.[i];
    return {
      name: selection.label ?? t_i18n('Number of relationships'),
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

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
): StixRelationshipsMultiHeatMapTimeSeriesQuery['variables'] => {
  const { startDate, endDate } = computeStartEndDates(config);
  const timeSeriesParameters = resolvedDataSelection.map((selection) => {
    const dateAttribute
      = selection.date_attribute?.length ? selection.date_attribute : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(
      selection.filters,
      { isKnowledgeRelationshipWidget: true },
    );

    return {
      field: dateAttribute,
      filters: normalizeFilterGroupForBackend(filters),
      dynamicFrom: normalizeFilterGroupForBackend(selection.dynamicFrom),
      dynamicTo: normalizeFilterGroupForBackend(selection.dynamicTo),
    };
  });
  return {
    operation: 'count',
    startDate: startDate ?? monthsAgo(12),
    endDate: endDate ?? now(),
    interval: getWidgetInterval(parameters),
    timeSeriesParameters,
  };
};

interface StixRelationshipsMultiHeatMapProps {
  variant?: string;
  height?: number;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixRelationshipsMultiHeatMap = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsMultiHeatMapProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsMultiHeatMapTimeSeriesQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsMultiHeatMapTimeSeriesQuery,
    config,
    buildQueryVariables: (selection, cfg) =>
      buildQueryVariables(selection, cfg, parameters),
  });

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Entities history')}
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
        <StixRelationshipsMultiHeatMapComponent
          queryRef={queryRef!}
          dataSelection={resolvedDataSelection}
          parameters={parameters}
          onMounted={(chart) => setChart(chart as ApexCharts)}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default StixRelationshipsMultiHeatMap;
