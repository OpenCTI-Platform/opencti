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
      truncated
      dates
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
        values
      }
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
