import React, { useEffect, useMemo, useRef, useState } from 'react';
import ApexCharts from 'apexcharts';
import { useTheme } from '@mui/styles';
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
  ANIMATION_BAR_THRESHOLD,
  coarsenSeriesForRendering,
  getBreakdownTickAmount,
  getRenderedBarsBudget,
  getWidgetBreakdownLimit,
  getWidgetBreakdownOrder,
  nextBreakdownChartWidth,
} from '../../utils/widget/widgetBreakdown';
import useResizeObserver from '../../utils/hooks/useResizeObserver';
import { getMainRepresentative } from '../../utils/defaultRepresentatives';

// Structural type satisfied by the private and the public breakdown queries
export interface WidgetTimeSeriesBreakdownData {
  readonly truncated: boolean;
  readonly series: ReadonlyArray<{
    readonly label: string;
    readonly isOther: boolean;
    readonly entity?: {
      readonly entity_type?: string;
      readonly id?: string;
      readonly name?: string;
      readonly representative?: { readonly main: string };
    } | null;
    readonly data?: ReadonlyArray<{ readonly date: unknown; readonly value: number } | null | undefined> | null;
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
  const theme = useTheme<Theme>();
  const interval = getWidgetInterval(parameters);

  const series = useMemo(() => {
    // The API already returns the "Other" serie last
    return (breakdown?.series ?? []).map((serie) => {
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
        data: (serie.data ?? [])
          .filter((entry): entry is NonNullable<typeof entry> => !!entry)
          .map((entry) => ({ x: new Date(entry.date as string), y: entry.value })),
      };
    });
  }, [breakdown, parameters.breakdownBy, t_i18n, theme]);

  // The bars budget and the x axis labels follow the width of the chart. The width is only updated by
  // a large enough resize, and stays unknown until the first measure so that the chart is not drawn twice.
  const containerRef = useRef<HTMLDivElement | null>(null);
  const { width } = useResizeObserver(containerRef);
  const [chartWidth, setChartWidth] = useState<number>();
  useEffect(() => {
    if (width > 0) {
      setChartWidth((previous) => nextBreakdownChartWidth(previous, width));
    }
  }, [width]);
  const barsBudget = chartWidth === undefined ? undefined : getRenderedBarsBudget(chartWidth);

  // Bars are the only chart whose cost explodes with the number of points: sum them into coarser
  // intervals when needed. Lines, areas and heatmaps keep the requested interval.
  const bars = useMemo(
    () => (type === 'vertical-bar' && barsBudget !== undefined ? coarsenSeriesForRendering(series, interval, barsBudget) : null),
    [type, series, interval, barsBudget],
  );

  const truncated = breakdown?.truncated ?? false;
  const limit = getWidgetBreakdownLimit(parameters);
  const order = getWidgetBreakdownOrder(parameters);
  const coarsenedInterval = bars && bars.interval !== interval ? bars.interval : undefined;
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
  }, [truncated, limit, order, coarsenedInterval, onWarningChange, t_i18n]);

  // The measured container stays mounted, whatever it holds, to be observed from the first render
  if (type === 'vertical-bar') {
    return (
      <div ref={containerRef} style={{ width: '100%', height: '100%' }}>
        {series.length === 0 && <WidgetNoData />}
        {series.length > 0 && bars && (
          <WidgetVerticalBars
            series={bars.series}
            interval={bars.interval}
            isStacked={parameters.stacked ?? undefined}
            hasLegend={parameters.legend ?? undefined}
            isAnimated={bars.barsCount <= ANIMATION_BAR_THRESHOLD}
            hasHoverFilter={false}
            tickAmount={getBreakdownTickAmount(chartWidth ?? width)}
            onMounted={onMounted}
          />
        )}
      </div>
    );
  }

  if (series.length === 0) {
    return <WidgetNoData />;
  }

  if (type === 'area') {
    return (
      <WidgetMultiAreas
        series={series}
        interval={interval}
        isStacked={parameters.stacked ?? undefined}
        hasLegend={parameters.legend ?? undefined}
        onMounted={onMounted}
      />
    );
  }
  if (type === 'heatmap') {
    const values = series.flatMap((serie) => serie.data.map((point) => point.y));
    return (
      <WidgetMultiHeatMap
        data={series}
        minValue={values.length ? Math.min(...values) : 0}
        maxValue={values.length ? Math.max(...values) : 0}
        isStacked={parameters.stacked ?? undefined}
        onMounted={onMounted}
      />
    );
  }
  return (
    <WidgetMultiLines
      series={series}
      interval={interval}
      hasLegend={parameters.legend ?? undefined}
      onMounted={onMounted}
    />
  );
};

export default WidgetTimeSeriesBreakdown;
