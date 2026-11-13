import React from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import type { GraphQLTaggedNode, OperationType } from 'relay-runtime';
import ApexCharts from 'apexcharts';
import WidgetTimeSeriesBreakdown, { WidgetTimeSeriesBreakdownData } from './WidgetTimeSeriesBreakdown';
import type { WidgetParameters } from '../../utils/widget/widget';

export type SelectTimeSeriesBreakdown<TQuery extends OperationType> = (data: TQuery['response']) => WidgetTimeSeriesBreakdownData | null | undefined;

interface TimeSeriesBreakdownContentProps<TQuery extends OperationType> {
  query: GraphQLTaggedNode;
  queryRef: PreloadedQuery<TQuery>;
  selectBreakdown: SelectTimeSeriesBreakdown<TQuery>;
  type: string;
  parameters: WidgetParameters;
  onMounted: (chart?: ApexCharts) => void;
  onWarningChange: (warning?: string) => void;
}

// Settings of the breakdown its query was loaded with: a widget edited since keeps its data, and its settings
// with them, until the query of its new settings is loaded. The public queries only name the widget: none is read.
const isOrder = (value: unknown): value is 'asc' | 'desc' => value === 'asc' || value === 'desc';
const readQueriedSettings = ({ interval, field, limit, orderMode }: Record<string, unknown>) => ({
  interval: typeof interval === 'string' ? interval : undefined,
  breakdownBy: typeof field === 'string' ? field : undefined,
  limit: typeof limit === 'number' ? limit : undefined,
  order: isOrder(orderMode) ? orderMode : undefined,
});

/**
 * Draws the breakdown its query returns: shared by the dashboard widgets and the public dashboards,
 * without anything of the dashboard around them. The breakdown is drawn with the settings it was queried
 * with when the query holds them, the visualization (type, stacking, legend) with the `parameters` of the widget.
 */
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
  const { interval, breakdownBy, limit, order } = readQueriedSettings(queryRef.variables);
  return (
    <WidgetTimeSeriesBreakdown
      breakdown={selectBreakdown(data)}
      type={type}
      parameters={parameters}
      interval={interval}
      breakdownBy={breakdownBy}
      limit={limit}
      order={order}
      onMounted={onMounted}
      onWarningChange={onWarningChange}
    />
  );
};

export default TimeSeriesBreakdownContent;
