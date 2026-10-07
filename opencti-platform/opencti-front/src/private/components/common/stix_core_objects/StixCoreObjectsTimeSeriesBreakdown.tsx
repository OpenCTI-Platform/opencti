import React, { ReactNode, useEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ApexCharts from 'apexcharts';
import { useFormatter } from '../../../../components/i18n';
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
import { computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';
import { getWidgetInterval } from '../../../../utils/widget/widgetUtils';
import { ANIMATION_BAR_THRESHOLD, coarsenSeriesForRendering, getBreakdownEntityTypes, getWidgetBreakdownLimit, isBreakdownField } from 'src/utils/widget/widgetBreakdown';
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
      types: $types
      filters: $filters
    ) {
      truncated
      series {
        label
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
  const { dateAttribute, startDate, endDate, filters } = computeWidgetFiltersForSelection(
    selection,
    config,
    { fallbackToDefaultDates: true },
  );
  // The API checks the field against these types: send the ones the filters restrict to
  const entityTypes = getBreakdownEntityTypes(selection?.filters);
  return {
    field: breakdownBy,
    dateAttribute,
    startDate,
    endDate,
    interval: getWidgetInterval(parameters),
    limit: getWidgetBreakdownLimit(parameters),
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
  const { stixCoreObjectsTimeSeriesBreakdown } = usePreloadedQuery(
    stixCoreObjectsTimeSeriesBreakdownQuery,
    queryRef,
  );
  const interval = getWidgetInterval(parameters);

  const series = useMemo(() => (stixCoreObjectsTimeSeriesBreakdown?.series ?? []).map((serie) => {
    let name = serie.label;
    if (parameters.breakdownBy === 'entity_type') {
      const translated = t_i18n(`entity_${serie.label}`);
      name = translated !== `entity_${serie.label}` ? translated : serie.label;
    } else if (serie.entity) {
      name = getMainRepresentative(serie.entity) || serie.label;
    }
    return {
      name,
      data: (serie.data ?? [])
        .filter((entry): entry is NonNullable<typeof entry> => !!entry)
        .map((entry) => ({ x: new Date(entry.date), y: entry.value })),
    };
  }), [stixCoreObjectsTimeSeriesBreakdown, parameters.breakdownBy, t_i18n]);

  // Bars are the only chart whose cost explodes with the number of points: sum them into coarser
  // intervals when needed. Lines, areas and heatmaps keep the requested interval.
  const bars = useMemo(
    () => (type === 'vertical-bar' ? coarsenSeriesForRendering(series, interval) : null),
    [type, series, interval],
  );

  const truncated = stixCoreObjectsTimeSeriesBreakdown?.truncated ?? false;
  const limit = getWidgetBreakdownLimit(parameters);
  const coarsenedInterval = bars && bars.interval !== interval ? bars.interval : undefined;
  useEffect(() => {
    const warnings = [];
    if (truncated) {
      warnings.push(t_i18n('Only the top {limit} values are displayed.', { values: { limit } }));
    }
    if (coarsenedInterval) {
      warnings.push(t_i18n('Interval adjusted to {interval} to keep the chart responsive.', {
        values: { interval: t_i18n(coarsenedInterval.charAt(0).toUpperCase() + coarsenedInterval.slice(1)) },
      }));
    }
    onWarningChange(warnings.length > 0 ? warnings.join(' ') : undefined);
  }, [truncated, limit, coarsenedInterval, onWarningChange, t_i18n]);

  if (series.length === 0) {
    return <WidgetNoData />;
  }

  if (bars) {
    return (
      <WidgetVerticalBars
        series={bars.series}
        interval={bars.interval}
        isStacked={parameters.stacked ?? undefined}
        hasLegend={parameters.legend ?? undefined}
        isAnimated={bars.barsCount <= ANIMATION_BAR_THRESHOLD}
        onMounted={onMounted}
      />
    );
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

/**
 * Entities time series widget drawing one series per value of `parameters.breakdownBy`.
 */
const StixCoreObjectsTimeSeriesBreakdown = ({
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
  const { isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsTimeSeriesBreakdownQuery>({
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
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
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

export default StixCoreObjectsTimeSeriesBreakdown;
