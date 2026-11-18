import React, { useEffect, useMemo, useRef, useState } from 'react';
import ApexCharts from 'apexcharts';
import { useIntl } from 'react-intl';
import { useTheme } from '@mui/material/styles';
import Box from '@mui/material/Box';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';
import WidgetNoData from './WidgetNoData';
import Loader, { LoaderVariant } from '../Loader';
import WidgetVerticalBars from './WidgetVerticalBars';
import WidgetMultiLines from './WidgetMultiLines';
import WidgetMultiAreas from './WidgetMultiAreas';
import WidgetMultiHeatMap from './WidgetMultiHeatMap';
import { WidgetParameters } from '../../utils/widget/widget';
import { getWidgetInterval } from '../../utils/widget/widgetUtils';
import { getWidgetBreakdownLimit, getWidgetBreakdownOrder, isBreakdownTypeField } from '../../utils/widget/widgetBreakdown';
import {
  ANIMATION_POINTS_THRESHOLD,
  coarsenSeriesForRendering,
  getBreakdownLegendMaxHeight,
  getBreakdownPalette,
  getBreakdownSeriesColors,
  getBreakdownTickAmount,
  getEntityTypeColor,
  getReadableOwnColor,
  getRenderedPointsBudget,
  isSameBreakdown,
  nextBreakdownChartWidth,
  numberSharedSeriesNames,
} from './timeSeriesBreakdownRendering';
import { scheduleChartDraw } from '../../utils/chartDrawQueue';
import useResizeObserver from '../../utils/hooks/useResizeObserver';
import { getMainRepresentative } from '../../utils/defaultRepresentatives';
import { displayEntityTypeForTranslation } from '../../utils/String';

// Structural type satisfied by the private and the public breakdown queries
export interface WidgetTimeSeriesBreakdownData {
  readonly truncated: boolean;
  // Interval of the dates when the API chose it: the public breakdowns count a long period in coarser intervals
  readonly interval?: string | null;
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
      // The colors of a label and of a marking
      readonly color?: string | null;
      readonly x_opencti_color?: string | null;
    } | null;
    readonly values: ReadonlyArray<number>;
  }>;
}

interface WidgetTimeSeriesBreakdownProps {
  breakdown?: WidgetTimeSeriesBreakdownData | null;
  type: string;
  parameters: WidgetParameters;
  // Settings the breakdown was queried with, which the `parameters` of an edited widget no longer hold
  // until its next query: the ones of the `parameters` when not given
  interval?: string;
  breakdownBy?: string;
  limit?: number;
  order?: 'asc' | 'desc';
  // Called with the chart once it is drawn, and without it once it is gone
  onMounted: (chart?: ApexCharts) => void;
  onWarningChange: (warning?: string) => void;
}

/**
 * Draws the series of a time series breakdown, and reports the warnings about what is not displayed.
 */
const WidgetTimeSeriesBreakdown = ({
  breakdown,
  type,
  parameters,
  interval: queriedInterval,
  breakdownBy: queriedBreakdownBy,
  limit: queriedLimit,
  order: queriedOrder,
  onMounted,
  onWarningChange,
}: WidgetTimeSeriesBreakdownProps) => {
  const { t_i18n } = useFormatter();
  // t_i18n is a new function at every render, its intl is not: memos depend on intl
  const intl = useIntl();
  const theme = useTheme<Theme>();
  const interval = queriedInterval ?? getWidgetInterval(parameters);
  const breakdownBy = queriedBreakdownBy ?? parameters.breakdownBy;
  const limit = queriedLimit ?? getWidgetBreakdownLimit(parameters);
  const order = queriedOrder ?? getWidgetBreakdownOrder(parameters);

  // A refresh hands a new breakdown even when nothing changed (its end date moved): the previous one is
  // kept then, so that no memo below is computed again and no chart is redrawn
  const [stableBreakdown, setStableBreakdown] = useState(breakdown);
  if (breakdown !== stableBreakdown && !isSameBreakdown(stableBreakdown, breakdown)) {
    setStableBreakdown(breakdown);
  }

  const series = useMemo(() => {
    // Parsed once for every series
    const dates = (stableBreakdown?.dates ?? []).map((date) => new Date(date as string));
    const breakdownSeries = stableBreakdown?.series ?? [];
    const isTypeField = isBreakdownTypeField(breakdownBy);
    // A value has its color in every widget, two series of a widget never share one, and the "Other" serie
    // gets a neutral color instead of one of the palette. A white own color is drawn black on a light card.
    const seriesColors = getBreakdownSeriesColors(
      breakdownSeries.map((serie) => ({
        key: serie.label,
        isOther: serie.isOther,
        ownColor: getReadableOwnColor(
          isTypeField ? getEntityTypeColor(serie.label) : (serie.entity?.color ?? serie.entity?.x_opencti_color),
          theme.palette.mode,
        ),
      })),
      getBreakdownPalette(theme.palette.mode),
      theme.palette.common?.grey,
    );
    // The API already returns the "Other" serie last
    const namedSeries = breakdownSeries.map((serie, serieIndex) => {
      let name = serie.label;
      if (serie.isOther) {
        name = t_i18n('Other');
      } else if (isTypeField) {
        // An entity type or a relationship type, kept as is when it has no translation
        const translationKey = displayEntityTypeForTranslation(serie.label) ?? serie.label;
        const translated = t_i18n(translationKey);
        name = translated !== translationKey ? translated : serie.label;
      } else if (serie.entity) {
        name = getMainRepresentative(serie.entity) || serie.label;
      }
      return {
        name,
        color: seriesColors[serieIndex],
        data: serie.values.map((value, index) => ({ x: dates[index], y: value })),
      };
    });
    // Several restricted entities, or entities of the same name, would be one name repeated in the legend
    const names = numberSharedSeriesNames(namedSeries.map(({ name }) => name));
    return namedSeries.map((serie, index) => ({ ...serie, name: names[index] }));
  }, [stableBreakdown, breakdownBy, intl, theme]);

  // The points budget and the x axis labels follow the width of the chart. The width is only updated by
  // a large enough resize, and stays unknown until the first measure so that the chart is not drawn twice.
  const containerRef = useRef<HTMLDivElement | null>(null);
  const { width, height } = useResizeObserver(containerRef);
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
  const isStacked = parameters.stacked ?? false;
  const pointsBudget = chartWidth === undefined ? undefined : getRenderedPointsBudget(type, chartWidth, series.length, isStacked);

  // The cost of every chart grows with its number of points, far past what its width can show:
  // sum the points into coarser intervals when needed. The dates can already come in coarser intervals than the
  // requested one (the public breakdowns), and the warning compares the drawn interval to the requested one.
  const datesInterval = stableBreakdown?.interval ?? interval;
  const rendered = useMemo(
    () => (pointsBudget !== undefined ? coarsenSeriesForRendering(series, datesInterval, pointsBudget) : null),
    [series, datesInterval, pointsBudget],
  );

  const truncated = stableBreakdown?.truncated ?? false;
  const coarsenedInterval = rendered && rendered.interval !== interval ? rendered.interval : undefined;
  const weeksCountedByMonday = rendered?.weeksCountedByMonday ?? false;
  useEffect(() => {
    const warnings = [];
    if (truncated) {
      warnings.push(order === 'asc'
        ? t_i18n('Only the {limit} lowest values are displayed.', { values: { limit } })
        : t_i18n('Only the {limit} highest values are displayed.', { values: { limit } }));
    }
    if (coarsenedInterval) {
      // The intervals of a time series, named as in the editor
      const intervalLabels: Record<string, string> = {
        day: t_i18n('Day'),
        week: t_i18n('Week'),
        month: t_i18n('Month'),
        quarter: t_i18n('Quarter'),
        year: t_i18n('Year'),
      };
      // The period rarely starts and ends on the bounds of the coarser intervals: the first and the last one
      // only count the part of them in the period
      warnings.push(t_i18n('Interval adjusted to {interval} to keep the chart responsive. The first and last intervals may only be partly covered by the selected period.', {
        values: { interval: intervalLabels[coarsenedInterval] ?? coarsenedInterval },
      }));
    }
    if (weeksCountedByMonday) {
      warnings.push(t_i18n('Each week is counted in full in the interval that contains its Monday.'));
    }
    onWarningChange(warnings.length > 0 ? warnings.join(' ') : undefined);
  }, [truncated, limit, order, coarsenedInterval, weeksCountedByMonday, onWarningChange, intl]);
  // The warnings leave with the chart, when an error replaces it
  useEffect(() => () => onWarningChange(undefined), [onWarningChange]);
  // So does the export of the chart, once no series is drawn any more or an error replaces it
  const hasChart = series.length > 0;
  useEffect(() => {
    if (!hasChart) {
      return undefined;
    }
    return () => onMounted(undefined);
  }, [hasChart, onMounted]);

  const renderChart = () => {
    if (series.length === 0) {
      return <WidgetNoData />;
    }
    // Until measured, and drawn in its turn
    if (!rendered) {
      return <Loader variant={LoaderVariant.inElement} />;
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
          isLegendCompact
          hasIntegerTicks
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
          isLegendCompact
          hasIntegerTicks
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
        isLegendCompact
        hasIntegerTicks
        onMounted={onMounted}
      />
    );
  };

  // The measured container stays mounted, whatever it holds, to be observed from the first render.
  // In a small widget, the legend scrolls before the plot gets too small to read (ApexCharts sets its inline cap).
  const legendMaxHeight = getBreakdownLegendMaxHeight(height);
  return (
    <Box
      ref={containerRef}
      style={{ width: '100%', height: '100%' }}
      sx={legendMaxHeight !== undefined ? { '& .apexcharts-legend': { maxHeight: `${legendMaxHeight}px !important` } } : undefined}
    >
      {renderChart()}
    </Box>
  );
};

export default WidgetTimeSeriesBreakdown;
