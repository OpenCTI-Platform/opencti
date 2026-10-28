import React, { ReactNode, useState } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import type { GraphQLTaggedNode, OperationType } from 'relay-runtime';
import ApexCharts from 'apexcharts';
import { useFormatter } from '../i18n';
import useAuth from '../../utils/hooks/useAuth';
import WidgetContainer from './WidgetContainer';
import WidgetNoData from './WidgetNoData';
import WidgetTimeSeriesBreakdown, { WidgetTimeSeriesBreakdownData } from './WidgetTimeSeriesBreakdown';
import useDashboardViz from './useDashboardViz';
import WidgetRenderContent from './WidgetRenderContent';
import type { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../utils/widget/widget';
import type { DashboardConfig } from './dashboard-types';
import { computeStartEndDates, computeWidgetFiltersForSelection } from './dashboardVizUtils';
import { getWidgetInterval } from '../../utils/widget/widgetUtils';
import {
  getBreakdownDefaultStartDate,
  getWidgetBreakdownLimit,
  getWidgetBreakdownOrder,
  getWidgetBreakdownOther,
  isBreakdownField,
  isBreakdownFieldSupported,
} from '../../utils/widget/widgetBreakdown';
import { now } from '../../utils/Time';

/**
 * Query variables every breakdown shares: the field and the series settings of the widget,
 * the dates and the filters of its single dataset.
 */
export const buildTimeSeriesBreakdownVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
  opts: { isKnowledgeRelationshipWidget?: boolean } = {},
) => {
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
    opts,
  );
  return {
    field: breakdownBy,
    dateAttribute,
    startDate,
    endDate,
    interval,
    limit: getWidgetBreakdownLimit(parameters),
    order: getWidgetBreakdownOrder(parameters),
    includeOther: getWidgetBreakdownOther(parameters),
    filters,
  };
};

interface TimeSeriesBreakdownQueryProps<TQuery extends OperationType> {
  query: GraphQLTaggedNode;
  buildQueryVariables: (resolvedDataSelection: WidgetDataSelection[], config: DashboardConfig, parameters?: WidgetParameters) => TQuery['variables'];
  selectBreakdown: (data: TQuery['response']) => WidgetTimeSeriesBreakdownData | null | undefined;
}

export interface TimeSeriesBreakdownVizProps {
  widget: Widget;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

interface TimeSeriesBreakdownContentProps<TQuery extends OperationType> {
  query: GraphQLTaggedNode;
  queryRef: PreloadedQuery<TQuery>;
  selectBreakdown: TimeSeriesBreakdownQueryProps<TQuery>['selectBreakdown'];
  type: string;
  parameters: WidgetParameters;
  onMounted: (chart: ApexCharts) => void;
  onWarningChange: (warning?: string) => void;
}

const TimeSeriesBreakdownContent = <TQuery extends OperationType>({
  query,
  queryRef,
  selectBreakdown,
  type,
  parameters,
  onMounted,
  onWarningChange,
}: TimeSeriesBreakdownContentProps<TQuery>) => {
  const data = usePreloadedQuery<TQuery>(query, queryRef);
  return (
    <WidgetTimeSeriesBreakdown
      breakdown={selectBreakdown(data)}
      type={type}
      parameters={parameters}
      onMounted={onMounted}
      onWarningChange={onWarningChange}
    />
  );
};

const TimeSeriesBreakdownChart = <TQuery extends OperationType>({
  widget,
  popover,
  host,
  config,
  refreshRate = null,
  query,
  buildQueryVariables,
  selectBreakdown,
}: TimeSeriesBreakdownVizProps & TimeSeriesBreakdownQueryProps<TQuery>) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const [warning, setWarning] = useState<string>();
  const parameters = widget.parameters ?? {};
  const { renderGuards, isPreviewMode, queryRef } = useDashboardViz<TQuery>({
    perspective: widget.perspective ?? 'entities',
    dataSelection: widget.dataSelection,
    host,
    refreshRate,
    query,
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
        <TimeSeriesBreakdownContent<TQuery>
          query={query}
          queryRef={queryRef!}
          selectBreakdown={selectBreakdown}
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
 * Time series widget drawing one series per value of `parameters.breakdownBy`, for the entities or the
 * relationships perspective. A field the dataset does not support is not queried: the API would refuse it.
 */
const TimeSeriesBreakdownViz = <TQuery extends OperationType>(props: TimeSeriesBreakdownVizProps & TimeSeriesBreakdownQueryProps<TQuery>) => {
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
  return <TimeSeriesBreakdownChart<TQuery> {...props} />;
};

export default TimeSeriesBreakdownViz;
