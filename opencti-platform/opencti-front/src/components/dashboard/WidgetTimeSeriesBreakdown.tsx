import React, { useEffect, useMemo, useRef, useState } from 'react';
import ApexCharts from 'apexcharts';
import { useIntl } from 'react-intl';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';
import WidgetNoData from './WidgetNoData';
import WidgetVerticalBars from './WidgetVerticalBars';
import WidgetMultiLines from './WidgetMultiLines';
import WidgetMultiAreas from './WidgetMultiAreas';
import WidgetMultiHeatMap from './WidgetMultiHeatMap';
import { WidgetParameters } from '../../utils/widget/widget';
import { getWidgetInterval } from '../../utils/widget/widgetUtils';
import {
  ANIMATION_POINTS_THRESHOLD,
  coarsenSeriesForRendering,
  getBreakdownTickAmount,
  getRenderedPointsBudget,
  getWidgetBreakdownLimit,
  getWidgetBreakdownOrder,
  isSameBreakdown,
  nextBreakdownChartWidth,
  scheduleChartDraw,
} from '../../utils/widget/widgetBreakdown';
import useResizeObserver from '../../utils/hooks/useResizeObserver';
import { getMainRepresentative } from '../../utils/defaultRepresentatives';

// Structural type satisfied by the private and the public breakdown queries
export interface WidgetTimeSeriesBreakdownData {
  readonly truncated: boolean;
  // Shared by every series: each series carries one value per date
  readonly dates: ReadonlyArray<unknown>;
  readonly series: ReadonlyArray<{
    readonly label: string;
    readonly isOther: boolean;
    readonly entity?: {
      readonly entity_type?: string;
      readonly id?: string;
      readonly name?: string;
      readonly representative?: { readonly main: string };
    } | null;
    readonly values: ReadonlyArray<number>;
  }>;
}

interface WidgetTimeSeriesBreakdownProps {
  breakdown?: WidgetTimeSeriesBreakdownData | null;
  type: string;
  parameters: WidgetParameters;
  onMounted: (chart: ApexCharts) => void;
  onWarningChange: (warning?: string) => void;
}

/**
 * Draws the series of a time series breakdown, and reports the warnings about what is not displayed.
 */
const WidgetTimeSeriesBreakdown = ({
  breakdown,
  type,
  parameters,
  onMounted,
  onWarningChange,
}: WidgetTimeSeriesBreakdownProps) => {
  const { t_i18n } = useFormatter();
  // t_i18n is a new function at every render, its intl is not: memos depend on intl
  const intl = useIntl();
  const theme = useTheme<Theme>();
  const interval = getWidgetInterval(parameters);

  // A refresh hands a new breakdown even when nothing changed (its end date moved): the previous one is
  // kept then, so that no memo below is computed again and no chart is redrawn
  const [stableBreakdown, setStableBreakdown] = useState(breakdown);
  if (breakdown !== stableBreakdown && !isSameBreakdown(stableBreakdown, breakdown)) {
    setStableBreakdown(breakdown);
  }

  const series = useMemo(() => {
    // Parsed once for every series
    const dates = (stableBreakdown?.dates ?? []).map((date) => new Date(date as string));
    // The API already returns the "Other" serie last
    return (stableBreakdown?.series ?? []).map((serie) => {
      let name = serie.label;
      if (serie.isOther) {
        name = t_i18n('Other');
      } else if (parameters.breakdownBy === 'entity_type') {
        const translated = t_i18n(`entity_${serie.label}`);
        name = translated !== `entity_${serie.label}` ? translated : serie.label;
      } else if (serie.entity) {
        name = getMainRepresentative(serie.entity) || serie.label;
      }
      return {
        name,
        // The "Other" serie gets a neutral color instead of one of the palette
        ...(serie.isOther ? { color: theme.palette.common?.grey } : {}),
        data: serie.values.map((value, index) => ({ x: dates[index], y: value })),
      };
    });
  }, [stableBreakdown, parameters.breakdownBy, intl, theme]);

  // The points budget and the x axis labels follow the width of the chart. The width is only updated by
  // a large enough resize, and stays unknown until the first measure so that the chart is not drawn twice.
  const containerRef = useRef<HTMLDivElement | null>(null);
  const { width } = useResizeObserver(containerRef);
  const [chartWidth, setChartWidth] = useState<number>();
  useEffect(() => {
    if (!(width > 0)) {
      return undefined;
    }
    if (chartWidth === undefined) {
      // First draw: the charts of widgets measured together are drawn one per task, not all in one
      return scheduleChartDraw(() => setChartWidth(width));
    }
    setChartWidth((previous) => nextBreakdownChartWidth(previous, width));
    return undefined;
  }, [width]);
  const pointsBudget = chartWidth === undefined ? undefined : getRenderedPointsBudget(type, chartWidth, series.length);

  // The cost of every chart grows with its number of points, far past what its width can show:
  // sum the points into coarser intervals when needed
  const rendered = useMemo(
    () => (pointsBudget !== undefined ? coarsenSeriesForRendering(series, interval, pointsBudget) : null),
    [series, interval, pointsBudget],
  );

  const truncated = stableBreakdown?.truncated ?? false;
  const limit = getWidgetBreakdownLimit(parameters);
  const order = getWidgetBreakdownOrder(parameters);
  const coarsenedInterval = rendered && rendered.interval !== interval ? rendered.interval : undefined;
  useEffect(() => {
    const warnings = [];
    if (truncated) {
      warnings.push(order === 'asc'
        ? t_i18n('Only the {limit} lowest values are displayed.', { values: { limit } })
        : t_i18n('Only the top {limit} values are displayed.', { values: { limit } }));
    }
    if (coarsenedInterval) {
      warnings.push(t_i18n('Interval adjusted to {interval} to keep the chart responsive.', {
        values: { interval: t_i18n(coarsenedInterval.charAt(0).toUpperCase() + coarsenedInterval.slice(1)) },
      }));
    }
    onWarningChange(warnings.length > 0 ? warnings.join(' ') : undefined);
  }, [truncated, limit, order, coarsenedInterval, onWarningChange, intl]);
  // The warnings leave with the chart, when an error replaces it
  useEffect(() => () => onWarningChange(undefined), [onWarningChange]);

  const renderChart = () => {
    if (series.length === 0) {
      return <WidgetNoData />;
    }
    if (!rendered) {
      return null;
    }
    const isAnimated = rendered.pointsCount <= ANIMATION_POINTS_THRESHOLD;
    if (type === 'vertical-bar') {
      return (
        <WidgetVerticalBars
          series={rendered.series}
          interval={rendered.interval}
          isStacked={parameters.stacked ?? undefined}
          hasLegend={parameters.legend ?? undefined}
          isAnimated={isAnimated}
          isUpdateAnimated={false}
          hasHoverFilter={false}
          tickAmount={getBreakdownTickAmount(chartWidth ?? width)}
          onMounted={onMounted}
        />
      );
    }
    if (type === 'area') {
      return (
        <WidgetMultiAreas
          series={rendered.series}
          interval={rendered.interval}
          isStacked={parameters.stacked ?? undefined}
          hasLegend={parameters.legend ?? undefined}
          isAnimated={isAnimated}
          isUpdateAnimated={false}
          onMounted={onMounted}
        />
      );
    }
    if (type === 'heatmap') {
      // Not spread into Math.min / Math.max: a large series would exceed the arguments limit of some engines
      let minValue = Infinity;
      let maxValue = -Infinity;
      rendered.series.forEach((serie) => serie.data.forEach((point) => {
        minValue = Math.min(minValue, point.y);
        maxValue = Math.max(maxValue, point.y);
      }));
      return (
        <WidgetMultiHeatMap
          data={rendered.series}
          interval={rendered.interval}
          minValue={Number.isFinite(minValue) ? minValue : 0}
          maxValue={Number.isFinite(maxValue) ? maxValue : 0}
          isStacked={parameters.stacked ?? undefined}
          isAnimated={isAnimated}
          isUpdateAnimated={false}
          onMounted={onMounted}
        />
      );
    }
    return (
      <WidgetMultiLines
        series={rendered.series}
        interval={rendered.interval}
        hasLegend={parameters.legend ?? undefined}
        isAnimated={isAnimated}
        isUpdateAnimated={false}
        onMounted={onMounted}
      />
    );
  };

  // The measured container stays mounted, whatever it holds, to be observed from the first render
  return (
    <div ref={containerRef} style={{ width: '100%', height: '100%' }}>
      {renderChart()}
    </div>
  );
};

export default WidgetTimeSeriesBreakdown;
