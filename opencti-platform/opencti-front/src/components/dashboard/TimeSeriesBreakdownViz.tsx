import React, { ComponentType, ReactNode, useState } from 'react';
import type { GraphQLTaggedNode, OperationType } from 'relay-runtime';
import ApexCharts from 'apexcharts';
import { useFormatter } from '../i18n';
import WidgetContainer from './WidgetContainer';
import TimeSeriesBreakdownContent, { type SelectTimeSeriesBreakdown } from './TimeSeriesBreakdownContent';
import WidgetBreakdownErrorBoundary from './WidgetBreakdownErrorBoundary';
import useDashboardViz from './useDashboardViz';
import WidgetRenderContent, { type WidgetRenderGuards } from './WidgetRenderContent';
import type { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../utils/widget/widget';
import type { DashboardConfig } from './dashboard-types';
import { computeStartEndDates, computeWidgetFiltersForSelection } from './dashboardVizUtils';
import { getWidgetInterval } from '../../utils/widget/widgetUtils';
import { getBreakdownDefaultStartDate, getWidgetBreakdownLimit, getWidgetBreakdownOrder, getWidgetBreakdownOther, isBreakdownField } from '../../utils/widget/widgetBreakdown';
import { now } from '../../utils/Time';

/**
 * Query variables every perspective shares: the field and the series settings of the widget,
 * its interval and its period.
 */
export const buildTimeSeriesBreakdownSettings = (config: DashboardConfig, parameters?: WidgetParameters) => {
  const breakdownBy = parameters?.breakdownBy;
  if (!isBreakdownField(breakdownBy)) {
    throw Error('Missing breakdown field');
  }
  const interval = getWidgetInterval(parameters);
  // Dates set on the dashboard are kept as is. Without a start date, a daily breakdown only looks
  // back a short while from the end date: the default 12 months would draw too many bars.
  const { startDate, endDate } = computeStartEndDates(config);
  return {
    field: breakdownBy,
    startDate: startDate ?? getBreakdownDefaultStartDate(interval, endDate),
    endDate: endDate ?? now(),
    interval,
    limit: getWidgetBreakdownLimit(parameters),
    orderMode: getWidgetBreakdownOrder(parameters),
    includeOther: getWidgetBreakdownOther(parameters),
  };
};

/**
 * Query variables of the knowledge breakdowns: the settings shared by every perspective,
 * and the date attribute and the filters of the single dataset, restricted to the same period.
 */
export const buildTimeSeriesBreakdownVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
  opts: { isKnowledgeRelationshipWidget?: boolean } = {},
) => {
  const settings = buildTimeSeriesBreakdownSettings(config, parameters);
  const [selection] = resolvedDataSelection;
  const { dateAttribute, filters } = computeWidgetFiltersForSelection(
    selection,
    { ...config, relativeDate: null, startDate: settings.startDate, endDate: settings.endDate },
    opts,
  );
  return { ...settings, dateAttribute, filters };
};

type BreakdownRenderContentProps = WidgetRenderGuards & {
  queryRef: unknown;
  host?: WidgetHost;
  children: ReactNode;
};

type BuildQueryVariables<TQuery extends OperationType> = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
) => TQuery['variables'];

interface TimeSeriesBreakdownQueryProps<TQuery extends OperationType> {
  query: GraphQLTaggedNode;
  buildQueryVariables: BuildQueryVariables<TQuery>;
  selectBreakdown: SelectTimeSeriesBreakdown<TQuery>;
  // Title of the widget when it sets none
  defaultTitle?: string;
  // Guards of the perspective on top of the common ones, like the capabilities the audits require
  RenderContent?: ComponentType<BreakdownRenderContentProps>;
}

export interface TimeSeriesBreakdownVizProps {
  widget: Widget;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

/**
 * Time series widget drawing one series per value of `parameters.breakdownBy`, for the entities, the
 * relationships or the audits perspective: each perspective gives its query, its variables and its guards.
 * The API checks the field on the dataset the query reads, its saved filters and dashboard variables resolved:
 * a field it does not support is refused, and the widget says so (WidgetBreakdownErrorBoundary).
 */
const TimeSeriesBreakdownViz = <TQuery extends OperationType>({
  widget,
  popover,
  host,
  config,
  refreshRate = null,
  query,
  buildQueryVariables,
  selectBreakdown,
  defaultTitle,
  RenderContent = WidgetRenderContent,
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
  // The menu of the widget is only given to the users who can edit it: the others get no advice to edit it
  const readOnly = !popover;

  return (
    <WidgetContainer
      padding="small"
      title={parameters.title ?? defaultTitle ?? t_i18n('Entities history')}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
      warning={warning}
    >
      {/* The guards come first: a user without access to the data is told so, not how to change the widget */}
      <RenderContent
        {...renderGuards}
        queryRef={queryRef}
        host={host}
      >
        <WidgetBreakdownErrorBoundary resetKey={queryRef} readOnly={readOnly}>
          <TimeSeriesBreakdownContent<TQuery>
            query={query}
            queryRef={queryRef!}
            selectBreakdown={selectBreakdown}
            type={widget.type}
            parameters={parameters}
            onMounted={setChart}
            onWarningChange={setWarning}
          />
        </WidgetBreakdownErrorBoundary>
      </RenderContent>
    </WidgetContainer>
  );
};

export default TimeSeriesBreakdownViz;
