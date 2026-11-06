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
      # The interval of the dates: a long period comes counted in coarser intervals
      interval
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
          # the colors of the values that have one
          ... on Label {
            color
          }
          ... on MarkingDefinition {
            x_opencti_color
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
