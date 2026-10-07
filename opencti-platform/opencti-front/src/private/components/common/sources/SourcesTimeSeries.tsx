import React, { CSSProperties, ReactNode, useCallback, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ApexCharts from 'apexcharts';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiLines from '../../../../components/dashboard/WidgetMultiLines';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import { findSourceWidgetMetric, toWidgetValue } from '../../integrations/sources/sourceIntelligenceUtils';
import SourcesWidgetRenderContent from './SourcesWidgetRenderContent';
import { metricAxisTitle, NO_SOURCE_SCORED_MESSAGE, periodDaysFromDashboardConfig, periodFromRange, toAggregation } from './sourcesWidgetUtils';
import { SourcesTimeSeriesQuery } from './__generated__/SourcesTimeSeriesQuery.graphql';

const sourcesTimeSeriesQuery = graphql`
  query SourcesTimeSeriesQuery(
    $metric: String!
    $period: SourceScorecardPeriod
    $filters: FilterGroup
    $startDate: DateTime
    $endDate: DateTime
    $aggregation: SourceScorecardAggregation
  ) {
    sourceScorecardsTimeSeries(
      metric: $metric
      period: $period
      filters: $filters
      startDate: $startDate
      endDate: $endDate
      aggregation: $aggregation
    ) {
      date
      value
      currency
    }
  }
`;

const SourcesTimeSeriesComponent = ({ queryRef, selection, hasLegend, onMounted }: {
  queryRef: PreloadedQuery<SourcesTimeSeriesQuery>;
  selection: WidgetDataSelection;
  hasLegend: boolean;
  onMounted: (chart: ApexCharts) => void;
}) => {
  const { t_i18n } = useFormatter();
  const { sourceScorecardsTimeSeries } = usePreloadedQuery(sourcesTimeSeriesQuery, queryRef);
  const metric = findSourceWidgetMetric(selection.attribute);
  const points = sourceScorecardsTimeSeries
    .map((point) => ({ x: point.date, y: toWidgetValue(point.value, metric.type) }))
    .filter((point) => point.y !== null);
  if (points.length === 0) {
    return <WidgetNoData message={t_i18n(NO_SOURCE_SCORED_MESSAGE)} />;
  }
  return (
    <WidgetMultiLines
      series={[{ name: selection.label || metricAxisTitle(t_i18n, metric, sourceScorecardsTimeSeries.find((point) => point.currency)?.currency), data: points }]}
      interval="day"
      hasLegend={hasLegend}
      onMounted={onMounted}
    />
  );
};

interface SourcesTimeSeriesProps {
  variant?: string;
  height?: CSSProperties['height'];
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

/**
 * Daily trend of a scorecard metric over the dashboard time range, from the snapshots of the rolling window that
 * the range selects (7, 30 or 90 days), like the other Sources widgets.
 */
const SourcesTimeSeries = ({ variant, height, dataSelection, parameters = {}, popover, host, config, refreshRate = null }: SourcesTimeSeriesProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const buildQueryVariables = useCallback((resolved: WidgetDataSelection[], dashboardConfig: DashboardConfig): SourcesTimeSeriesQuery['variables'] => {
    const selection = resolved[0];
    const { startDate, endDate } = computeStartEndDates(dashboardConfig);
    return {
      metric: findSourceWidgetMetric(selection.attribute).key,
      period: periodFromRange(startDate, endDate),
      filters: normalizeFilterGroupForBackend(selection.filters),
      startDate: startDate ?? null,
      endDate: endDate ?? null,
      aggregation: toAggregation(selection.sort_mode, 'avg'),
    };
  }, []);
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<SourcesTimeSeriesQuery>({
    perspective: 'sources',
    dataSelection,
    host,
    refreshRate,
    query: sourcesTimeSeriesQuery,
    config,
    parameters,
    buildQueryVariables,
  });
  const selection = resolvedDataSelection[0] ?? dataSelection[0];
  const metric = findSourceWidgetMetric(selection?.attribute);
  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title || t_i18n('{measure} per day, scored over {days} days', {
        values: { measure: t_i18n(metric.label), days: periodDaysFromDashboardConfig(config) },
      })}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <SourcesWidgetRenderContent isMissingHostEntity={isMissingHostEntity} isMissingSavedFilters={isMissingSavedFilters} queryRef={queryRef} host={host}>
        <SourcesTimeSeriesComponent queryRef={queryRef!} selection={selection} hasLegend={parameters.legend === true} onMounted={setChart} />
      </SourcesWidgetRenderContent>
    </WidgetContainer>
  );
};

export default SourcesTimeSeries;
