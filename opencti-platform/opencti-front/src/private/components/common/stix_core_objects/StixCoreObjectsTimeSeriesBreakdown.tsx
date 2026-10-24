import React, { ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ApexCharts from 'apexcharts';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetVerticalBars from '../../../../components/dashboard/WidgetVerticalBars';
import WidgetMultiLines from '../../../../components/dashboard/WidgetMultiLines';
import WidgetMultiAreas from '../../../../components/dashboard/WidgetMultiAreas';
import WidgetMultiHeatMap from '../../../../components/dashboard/WidgetMultiHeatMap';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates, computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';
import { getWidgetInterval } from '../../../../utils/widget/widgetUtils';
import {
  ANIMATION_BAR_THRESHOLD,
  coarsenSeriesForRendering,
  getBreakdownDefaultStartDate,
  getBreakdownEntityTypes,
  getBreakdownTickAmount,
  getRenderedBarsBudget,
  getWidgetBreakdownLimit,
  getWidgetBreakdownOrder,
  getWidgetBreakdownOther,
  isBreakdownField,
  isBreakdownFieldSupported,
  nextBreakdownChartWidth,
} from 'src/utils/widget/widgetBreakdown';
import useResizeObserver from '../../../../utils/hooks/useResizeObserver';
import { now } from '../../../../utils/Time';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { StixCoreObjectsTimeSeriesBreakdownQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsTimeSeriesBreakdownQuery.graphql';

const stixCoreObjectsTimeSeriesBreakdownQuery = graphql`
  query StixCoreObjectsTimeSeriesBreakdownQuery(
    $field: String!
    $dateAttribute: String
    $startDate: DateTime!
    $endDate: DateTime
    $interval: String!
    $limit: Int
    $order: OrderingMode
    $includeOther: Boolean
    $types: [String]
    $filters: FilterGroup
  ) {
    stixCoreObjectsTimeSeriesBreakdown(
      field: $field
      dateAttribute: $dateAttribute
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      limit: $limit
      order: $order
      includeOther: $includeOther
      types: $types
      filters: $filters
    ) {
      truncated
      series {
        label
        isOther
        entity {
          ... on BasicObject {
            id
            entity_type
          }
          ... on StixObject {
            representative {
              main
            }
          }
          # internal objects
          ... on Creator {
            id
            name
          }
        }
        data {
          date
          value
        }
      }
    }
  }
`;

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
): StixCoreObjectsTimeSeriesBreakdownQuery['variables'] => {
  const breakdownBy = parameters?.breakdownBy;
  if (!isBreakdownField(breakdownBy)) {
    throw Error('Missing breakdown field');
  }
  const [selection] = resolvedDataSelection;
  const interval = getWidgetInterval(parameters);
  // Dates set on the dashboard are kept as is. Without a start date, a daily breakdown only looks
  // back a short while: the default 12 months would draw too many bars.
  const configuredDates = computeStartEndDates(config);
  const { dateAttribute, startDate, endDate, filters } = computeWidgetFiltersForSelection(
    selection,
    {
      ...config,
      relativeDate: null,
      startDate: configuredDates.startDate ?? getBreakdownDefaultStartDate(interval),
      endDate: configuredDates.endDate ?? now(),
    },
  );
  // The API checks the field against these types: send the ones the filters restrict to
  const entityTypes = getBreakdownEntityTypes(selection?.filters);
  return {
    field: breakdownBy,
    dateAttribute,
    startDate,
    endDate,
    interval,
    limit: getWidgetBreakdownLimit(parameters),
    order: getWidgetBreakdownOrder(parameters),
    includeOther: getWidgetBreakdownOther(parameters),
    types: entityTypes.length > 0 ? entityTypes : DATA_SELECTION_TYPES,
    filters,
  };
};

interface StixCoreObjectsTimeSeriesBreakdownComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsTimeSeriesBreakdownQuery>;
  type: string;
  parameters: WidgetParameters;
  onMounted: (chart: ApexCharts) => void;
  onWarningChange: (warning?: string) => void;
}

const StixCoreObjectsTimeSeriesBreakdownComponent = ({
  queryRef,
  type,
  parameters,
  onMounted,
  onWarningChange,
}: StixCoreObjectsTimeSeriesBreakdownComponentProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { stixCoreObjectsTimeSeriesBreakdown } = usePreloadedQuery(
    stixCoreObjectsTimeSeriesBreakdownQuery,
    queryRef,
  );
  const interval = getWidgetInterval(parameters);

  const series = useMemo(() => {
    // The API already returns the "Other" serie last
    return (stixCoreObjectsTimeSeriesBreakdown?.series ?? []).map((serie) => {
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
          .map((entry) => ({ x: new Date(entry.date), y: entry.value })),
      };
    });
  }, [stixCoreObjectsTimeSeriesBreakdown, parameters.breakdownBy, t_i18n, theme]);

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

  const truncated = stixCoreObjectsTimeSeriesBreakdown?.truncated ?? false;
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

interface StixCoreObjectsTimeSeriesBreakdownProps {
  widget: Widget;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixCoreObjectsTimeSeriesBreakdownViz = ({
  widget,
  popover,
  host,
  config,
  refreshRate = null,
}: StixCoreObjectsTimeSeriesBreakdownProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const [warning, setWarning] = useState<string>();
  const parameters = widget.parameters ?? {};
  const { renderGuards, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsTimeSeriesBreakdownQuery>({
    perspective: 'entities',
    dataSelection: widget.dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsTimeSeriesBreakdownQuery,
    config,
    parameters,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="small"
      title={parameters.title ?? t_i18n('Entities history')}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
      warning={warning}
    >
      <WidgetRenderContent
        {...renderGuards}
        queryRef={queryRef}
        host={host}
      >
        <StixCoreObjectsTimeSeriesBreakdownComponent
          queryRef={queryRef!}
          type={widget.type}
          parameters={parameters}
          onMounted={setChart}
          onWarningChange={setWarning}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

/**
 * Entities time series widget drawing one series per value of `parameters.breakdownBy`.
 * A field the dataset does not support is not queried: the API would refuse it.
 */
const StixCoreObjectsTimeSeriesBreakdown = (props: StixCoreObjectsTimeSeriesBreakdownProps) => {
  const { t_i18n } = useFormatter();
  const { schema: { filterKeysSchema } } = useAuth();
  const { widget, popover } = props;
  if (!isBreakdownFieldSupported(filterKeysSchema, widget)) {
    return (
      <WidgetContainer padding="small" title={widget.parameters?.title ?? t_i18n('Entities history')} action={popover}>
        <WidgetNoData message={t_i18n('This breakdown field is not available for the dataset of this widget. Edit the widget to choose another field.')} />
      </WidgetContainer>
    );
  }
  return <StixCoreObjectsTimeSeriesBreakdownViz {...props} />;
};

export default StixCoreObjectsTimeSeriesBreakdown;
