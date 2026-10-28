import React, { ComponentType, ReactNode, useState } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import type { GraphQLTaggedNode, OperationType } from 'relay-runtime';
import ApexCharts from 'apexcharts';
import { useFormatter } from '../i18n';
import useAuth from '../../utils/hooks/useAuth';
import WidgetContainer from './WidgetContainer';
import WidgetNoData from './WidgetNoData';
import WidgetRenderContent, { type WidgetRenderGuards } from './WidgetRenderContent';
import WidgetTimeSeriesBreakdown, { type WidgetTimeSeriesBreakdownData } from './WidgetTimeSeriesBreakdown';
import useDashboardViz from './useDashboardViz';
import type { Widget, WidgetDataSelection, WidgetHost, WidgetParameters, WidgetPerspective } from '../../utils/widget/widget';
import type { DashboardConfig } from './dashboard-types';
import { isBreakdownFieldSupported } from '../../utils/widget/widgetBreakdown';

export interface TimeSeriesBreakdownWidgetProps {
  widget: Widget;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

type BreakdownRenderContentProps = WidgetRenderGuards & {
  queryRef: unknown;
  host?: WidgetHost;
  children: ReactNode;
};

interface WidgetTimeSeriesBreakdownVizProps<TQuery extends OperationType> extends TimeSeriesBreakdownWidgetProps {
  perspective: WidgetPerspective;
  query: GraphQLTaggedNode;
  buildQueryVariables: (resolvedDataSelection: WidgetDataSelection[], config: DashboardConfig, parameters?: WidgetParameters) => TQuery['variables'];
  // Reads the breakdown in the response of the query
  getBreakdown: (response: TQuery['response']) => WidgetTimeSeriesBreakdownData | null | undefined;
  defaultTitle: string;
  // Guards of the perspective on top of the common ones, like the capabilities the audits require
  RenderContent?: ComponentType<BreakdownRenderContentProps>;
}

interface BreakdownChartProps<TQuery extends OperationType> {
  query: GraphQLTaggedNode;
  queryRef: PreloadedQuery<TQuery>;
  getBreakdown: (response: TQuery['response']) => WidgetTimeSeriesBreakdownData | null | undefined;
  type: string;
  parameters: WidgetParameters;
  onMounted: (chart: ApexCharts) => void;
  onWarningChange: (warning?: string) => void;
}

const BreakdownChart = <TQuery extends OperationType>({
  query,
  queryRef,
  getBreakdown,
  type,
  parameters,
  onMounted,
  onWarningChange,
}: BreakdownChartProps<TQuery>) => {
  const response = usePreloadedQuery<TQuery>(query, queryRef);
  return (
    <WidgetTimeSeriesBreakdown
      breakdown={getBreakdown(response)}
      type={type}
      parameters={parameters}
      onMounted={onMounted}
      onWarningChange={onWarningChange}
    />
  );
};

const BreakdownViz = <TQuery extends OperationType>({
  widget,
  popover,
  host,
  config,
  refreshRate = null,
  perspective,
  query,
  buildQueryVariables,
  getBreakdown,
  defaultTitle,
  RenderContent = WidgetRenderContent,
}: WidgetTimeSeriesBreakdownVizProps<TQuery>) => {
  const [chart, setChart] = useState<ApexCharts>();
  const [warning, setWarning] = useState<string>();
  const parameters = widget.parameters ?? {};
  const { renderGuards, isPreviewMode, queryRef } = useDashboardViz<TQuery>({
    perspective,
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
      title={parameters.title ?? defaultTitle}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
      warning={warning}
    >
      <RenderContent
        {...renderGuards}
        queryRef={queryRef}
        host={host}
      >
        <BreakdownChart<TQuery>
          query={query}
          queryRef={queryRef!}
          getBreakdown={getBreakdown}
          type={widget.type}
          parameters={parameters}
          onMounted={setChart}
          onWarningChange={setWarning}
        />
      </RenderContent>
    </WidgetContainer>
  );
};

/**
 * Time series widget drawing one series per value of `parameters.breakdownBy`, whatever its perspective:
 * each perspective gives its query, its variables and its guards.
 * A field the dataset does not support is not queried: the API would refuse it.
 */
const WidgetTimeSeriesBreakdownViz = <TQuery extends OperationType>(props: WidgetTimeSeriesBreakdownVizProps<TQuery>) => {
  const { t_i18n } = useFormatter();
  const { schema: { filterKeysSchema } } = useAuth();
  const { widget, popover, defaultTitle } = props;
  if (!isBreakdownFieldSupported(filterKeysSchema, widget)) {
    return (
      <WidgetContainer padding="small" title={widget.parameters?.title ?? defaultTitle} action={popover}>
        <WidgetNoData message={t_i18n('This breakdown field is not available for the dataset of this widget. Edit the widget to choose another field.')} />
      </WidgetContainer>
    );
  }
  return <BreakdownViz<TQuery> {...props} />;
};

export default WidgetTimeSeriesBreakdownViz;
