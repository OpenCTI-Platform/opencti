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

/**
 * Draws the breakdown its query returns: shared by the dashboard widgets and the public dashboards,
 * without anything of the dashboard around them.
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

export default TimeSeriesBreakdownContent;
