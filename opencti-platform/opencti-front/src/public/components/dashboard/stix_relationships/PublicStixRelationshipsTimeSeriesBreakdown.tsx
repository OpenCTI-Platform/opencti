import { graphql } from 'react-relay';
import React from 'react';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import PublicTimeSeriesBreakdown from '../PublicTimeSeriesBreakdown';
import { PublicStixRelationshipsTimeSeriesBreakdownQuery } from './__generated__/PublicStixRelationshipsTimeSeriesBreakdownQuery.graphql';

const publicStixRelationshipsTimeSeriesBreakdownQuery = graphql`
  query PublicStixRelationshipsTimeSeriesBreakdownQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId: String!
  ) {
    publicStixRelationshipsTimeSeriesBreakdown(
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

const selectBreakdown = (data: PublicStixRelationshipsTimeSeriesBreakdownQuery['response']) => data.publicStixRelationshipsTimeSeriesBreakdown;

const PublicStixRelationshipsTimeSeriesBreakdown = (props: PublicWidgetContainerProps) => (
  <PublicTimeSeriesBreakdown<PublicStixRelationshipsTimeSeriesBreakdownQuery>
    {...props}
    query={publicStixRelationshipsTimeSeriesBreakdownQuery}
    selectBreakdown={selectBreakdown}
  />
);

export default PublicStixRelationshipsTimeSeriesBreakdown;
