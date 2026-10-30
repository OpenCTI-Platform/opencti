import React, { ComponentType, ReactNode, useCallback, useState } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import type { GraphQLTaggedNode, OperationType } from 'relay-runtime';
import ApexCharts from 'apexcharts';
import { useFormatter } from '../i18n';
import useAuth from '../../utils/hooks/useAuth';
import WidgetContainer from './WidgetContainer';
import WidgetNoData from './WidgetNoData';
import WidgetTimeSeriesBreakdown, { WidgetTimeSeriesBreakdownData } from './WidgetTimeSeriesBreakdown';
import WidgetBreakdownErrorBoundary from './WidgetBreakdownErrorBoundary';
import useDashboardViz from './useDashboardViz';
import WidgetRenderContent, { type WidgetRenderGuards } from './WidgetRenderContent';
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
  selectBreakdown: (data: TQuery['response']) => WidgetTimeSeriesBreakdownData | null | undefined;
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

/**
 * Time series widget drawing one series per value of `parameters.breakdownBy`, for the entities, the
 * relationships or the audits perspective: each perspective gives its query, its variables and its guards.
 * A field the dataset does not support is not queried: the API would refuse it. The dataset is the one
 * the query reads, its saved filters and dashboard variables resolved.
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
  const { schema: { filterKeysSchema } } = useAuth();
  const [chart, setChart] = useState<ApexCharts>();
  const [warning, setWarning] = useState<string>();
  const parameters = widget.parameters ?? {};
  const perspective = widget.perspective ?? 'entities';
  const { breakdownBy } = parameters;
  const isSupportedOn = useCallback((dataSelection: WidgetDataSelection[]) => {
    return isBreakdownFieldSupported(filterKeysSchema, { perspective, dataSelection, parameters: { breakdownBy } });
  }, [filterKeysSchema, perspective, breakdownBy]);
  // No variables, so no query, for a field the resolved dataset does not support
  const buildSupportedQueryVariables = useCallback<(...args: Parameters<BuildQueryVariables<TQuery>>) => TQuery['variables'] | null>(
    (resolvedDataSelection, dashboardConfig, widgetParameters) => (isSupportedOn(resolvedDataSelection)
      ? buildQueryVariables(resolvedDataSelection, dashboardConfig, widgetParameters)
      : null),
    [isSupportedOn, buildQueryVariables],
  );
  const { renderGuards, isPreviewMode, queryRef, resolvedDataSelection } = useDashboardViz<TQuery>({
    perspective,
    dataSelection: widget.dataSelection,
    host,
    refreshRate,
    query,
    config,
    parameters,
    buildQueryVariables: buildSupportedQueryVariables,
  });
  // A widget that cannot be resolved says why first
  const isBlocked = renderGuards.isMissingHostEntity || renderGuards.isMissingSavedFilters || renderGuards.hasUnresolvedVariables;
  const isUnsupported = !isBlocked && resolvedDataSelection.length > 0 && !isSupportedOn(resolvedDataSelection);

  return (
    <WidgetContainer
      padding="small"
      title={parameters.title ?? defaultTitle ?? t_i18n('Entities history')}
      chart={isUnsupported ? undefined : chart}
      action={popover}
      showPreviewTag={isPreviewMode}
      warning={isUnsupported ? undefined : warning}
    >
      {isUnsupported ? (
        <WidgetNoData message={t_i18n('This breakdown field is not available for the dataset of this widget. Edit the widget to choose another field.')} />
      ) : (
        <RenderContent
          {...renderGuards}
          queryRef={queryRef}
          host={host}
        >
          <WidgetBreakdownErrorBoundary resetKey={queryRef}>
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
      )}
    </WidgetContainer>
  );
};

export default TimeSeriesBreakdownViz;
