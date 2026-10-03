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
import { findSourceWidgetMetric, REFERENCE_SCORECARD_PERIOD, toWidgetValue } from '../../integrations/sources/sourceIntelligenceUtils';
import SourcesWidgetRenderContent from './SourcesWidgetRenderContent';
import { toAggregation } from './sourcesWidgetUtils';
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
    return <WidgetNoData />;
  }
  return (
    <WidgetMultiLines
      series={[{ name: selection.label || t_i18n(metric.label), data: points }]}
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
 * Daily trend of a scorecard metric over the dashboard time range, from the 30 day rolling scorecard snapshots.
 */
const SourcesTimeSeries = ({ variant, height, dataSelection, parameters = {}, popover, host, config, refreshRate = null }: SourcesTimeSeriesProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const buildQueryVariables = useCallback((resolved: WidgetDataSelection[], dashboardConfig: DashboardConfig): SourcesTimeSeriesQuery['variables'] => {
    const selection = resolved[0];
    const { startDate, endDate } = computeStartEndDates(dashboardConfig);
    return {
      metric: findSourceWidgetMetric(selection.attribute).key,
      period: REFERENCE_SCORECARD_PERIOD,
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
      title={parameters.title || t_i18n(metric.label)}
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
