import { graphql } from 'react-relay';
import React from 'react';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import PublicTimeSeriesBreakdown from '../PublicTimeSeriesBreakdown';
import { PublicStixCoreObjectsTimeSeriesBreakdownQuery } from './__generated__/PublicStixCoreObjectsTimeSeriesBreakdownQuery.graphql';

const publicStixCoreObjectsTimeSeriesBreakdownQuery = graphql`
  query PublicStixCoreObjectsTimeSeriesBreakdownQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId: String!
  ) {
    publicStixCoreObjectsTimeSeriesBreakdown(
      startDate: $startDate
      endDate: $endDate
      uriKey: $uriKey
      widgetId: $widgetId
    ) {
      ...WidgetTimeSeriesBreakdown_breakdown
    }
  }
`;

const selectBreakdown = (data: PublicStixCoreObjectsTimeSeriesBreakdownQuery['response']) => data.publicStixCoreObjectsTimeSeriesBreakdown;

const PublicStixCoreObjectsTimeSeriesBreakdown = (props: PublicWidgetContainerProps) => (
  <PublicTimeSeriesBreakdown<PublicStixCoreObjectsTimeSeriesBreakdownQuery>
    {...props}
    query={publicStixCoreObjectsTimeSeriesBreakdownQuery}
    selectBreakdown={selectBreakdown}
  />
);

export default PublicStixCoreObjectsTimeSeriesBreakdown;
