import React, { CSSProperties, ReactNode, useCallback, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useNavigate } from 'react-router';
import ApexCharts, { ApexOptions } from 'apexcharts';
import { useTheme } from '@mui/material/styles';
import Chart from '@components/common/charts/Chart';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import type { Theme } from '../../../../components/Theme';
import { escapeHtml, findSourceWidgetMetric, formatMetric, SourceWidgetMetric, toWidgetValue } from '../../integrations/sources/sourceIntelligenceUtils';
import SourcesWidgetRenderContent from './SourcesWidgetRenderContent';
import { metricAxisTitle, NO_SOURCE_SCORED_MESSAGE, periodDaysFromDashboardConfig, periodFromDashboardConfig } from './sourcesWidgetUtils';
import { SourcesBubbleQuery } from './__generated__/SourcesBubbleQuery.graphql';

const sourcesBubbleQuery = graphql`
  query SourcesBubbleQuery(
    $xMetric: String!
    $yMetric: String!
    $sizeMetric: String
    $period: SourceScorecardPeriod
    $filters: FilterGroup
    $first: Int
  ) {
    sourceScorecardsScatter(xMetric: $xMetric, yMetric: $yMetric, sizeMetric: $sizeMetric, period: $period, filters: $filters, first: $first) {
      label
      x
      y
      size
      currency
      entity {
        id
      }
    }
  }
`;

// Defaults of the "cost versus impact" bubble: x = cost per actionable object, y = impact, size = volume
const DEFAULT_X = 'cost_per_actionable_object';
const DEFAULT_Y = 'impact_score';
const DEFAULT_SIZE = 'volume_total';
const DEFAULT_POINTS = 50;

const axisLabel = (metric: SourceWidgetMetric, value: number, currency: string | null) => (metric.type === 'ratio' ? `${value.toFixed(0)} %` : formatMetric(value, metric.type, currency));

const SourcesBubbleComponent = ({ queryRef, xMetric, yMetric, onMounted }: {
  queryRef: PreloadedQuery<SourcesBubbleQuery>;
  xMetric: SourceWidgetMetric;
  yMetric: SourceWidgetMetric;
  onMounted: (chart: ApexCharts) => void;
}) => {
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const { sourceScorecardsScatter } = usePreloadedQuery(sourcesBubbleQuery, queryRef);
  // An unmeasured value is never drawn as a zero: the point is left out
  const points = useMemo(() => sourceScorecardsScatter.flatMap((point) => {
    const x = toWidgetValue(point.x, xMetric.type);
    const y = toWidgetValue(point.y, yMetric.type);
    if (x === null || y === null || point.size === null || point.size === undefined) return [];
    // Signed metrics (lead time) can be negative: a radius needs a non-negative size
    return [{ id: point.entity?.id, label: point.label, x, y, size: Math.max(0, point.size) }];
  }), [sourceScorecardsScatter, xMetric, yMetric]);
  const currency = sourceScorecardsScatter.find((point) => point.currency)?.currency ?? null;
  // Bubble radius proportional to the square root of the size metric, bounded so small sources stay visible
  const maxSize = Math.max(1, ...points.map((point) => point.size));
  // The tooltip renders series names as HTML
  const series = useMemo(() => points.map((point) => ({
    name: escapeHtml(point.label),
    data: [[point.x, point.y, Math.max(4, Math.round(30 * Math.sqrt(point.size / maxSize)))]],
  })), [points, maxSize]);
  const options: ApexOptions = useMemo(() => ({
    chart: {
      type: 'bubble',
      background: 'transparent',
      foreColor: theme.palette.text.secondary,
      toolbar: { show: false },
      events: {
        dataPointSelection: (_event, _chart, { seriesIndex }) => {
          const point = points[seriesIndex];
          if (point?.id) navigate(`/dashboard/integrations/sources/source/${point.id}`);
        },
      },
    },
    theme: { mode: theme.palette.mode },
    legend: { show: false },
    dataLabels: { enabled: false },
    fill: { opacity: 0.7 },
    grid: { borderColor: theme.palette.divider },
    xaxis: {
      type: 'numeric',
      tickAmount: 6,
      title: { text: metricAxisTitle(t_i18n, xMetric, currency) },
      labels: { formatter: (value: string) => axisLabel(xMetric, Number(value), currency) },
    },
    yaxis: {
      title: { text: metricAxisTitle(t_i18n, yMetric, currency) },
      labels: { formatter: (value: number) => axisLabel(yMetric, value, currency) },
    },
    tooltip: {
      theme: theme.palette.mode,
      z: { formatter: () => '', title: '' },
    },
  }), [theme, points, xMetric, yMetric, navigate, currency]);
  if (points.length === 0) {
    return <WidgetNoData message={t_i18n(NO_SOURCE_SCORED_MESSAGE)} />;
  }
  return <Chart options={options} series={series} type="bubble" width="100%" height="100%" onMounted={onMounted} />;
};

interface SourcesBubbleProps {
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
 * Bubble chart of the sources: `attribute` is the x metric, `field` the y metric and `sort_by` the size metric.
 */
const SourcesBubble = ({ variant, height, dataSelection, parameters = {}, popover, host, config, refreshRate = null }: SourcesBubbleProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const buildQueryVariables = useCallback((resolved: WidgetDataSelection[], dashboardConfig: DashboardConfig): SourcesBubbleQuery['variables'] => {
    const selection = resolved[0];
    return {
      xMetric: findSourceWidgetMetric(selection.attribute ?? DEFAULT_X).key,
      yMetric: findSourceWidgetMetric(selection.field ?? DEFAULT_Y).key,
      sizeMetric: findSourceWidgetMetric(selection.sort_by ?? DEFAULT_SIZE, 'bubble-size').key,
      period: periodFromDashboardConfig(dashboardConfig),
      filters: normalizeFilterGroupForBackend(selection.filters),
      first: selection.number ?? DEFAULT_POINTS,
    };
  }, []);
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<SourcesBubbleQuery>({
    perspective: 'sources',
    dataSelection,
    host,
    refreshRate,
    query: sourcesBubbleQuery,
    config,
    parameters,
    buildQueryVariables,
  });
  const selection = resolvedDataSelection[0] ?? dataSelection[0];
  const xMetric = findSourceWidgetMetric(selection?.attribute ?? DEFAULT_X);
  const yMetric = findSourceWidgetMetric(selection?.field ?? DEFAULT_Y);
  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title || t_i18n('{y} against {x} over the last {days} days', {
        values: { x: t_i18n(xMetric.label), y: t_i18n(yMetric.label), days: periodDaysFromDashboardConfig(config) },
      })}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <SourcesWidgetRenderContent isMissingHostEntity={isMissingHostEntity} isMissingSavedFilters={isMissingSavedFilters} queryRef={queryRef} host={host}>
        <SourcesBubbleComponent queryRef={queryRef!} xMetric={xMetric} yMetric={yMetric} onMounted={setChart} />
      </SourcesWidgetRenderContent>
    </WidgetContainer>
  );
};

export default SourcesBubble;
