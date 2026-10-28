import React from 'react';
import { graphql } from 'react-relay';
import TimeSeriesBreakdownViz, { buildTimeSeriesBreakdownVariables, TimeSeriesBreakdownVizProps } from '../../../../components/dashboard/TimeSeriesBreakdownViz';
import { WidgetDataSelection, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { getBreakdownEntityTypes } from 'src/utils/widget/widgetBreakdown';
import { StixCoreObjectsTimeSeriesBreakdownQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsTimeSeriesBreakdownQuery.graphql';

const stixCoreObjectsTimeSeriesBreakdownQuery = graphql`
  query StixCoreObjectsTimeSeriesBreakdownQuery(
    $field: String!
    $dateAttribute: String
    $startDate: DateTime!
    $endDate: DateTime
    $interval: String!
    $limit: Int
    $order: OrderingMode
    $includeOther: Boolean
    $types: [String]
    $filters: FilterGroup
  ) {
    stixCoreObjectsTimeSeriesBreakdown(
      field: $field
      dateAttribute: $dateAttribute
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      limit: $limit
      order: $order
      includeOther: $includeOther
      types: $types
      filters: $filters
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

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
): StixCoreObjectsTimeSeriesBreakdownQuery['variables'] => {
  // The API checks the field against these types: send the ones the filters restrict to
  const entityTypes = getBreakdownEntityTypes(resolvedDataSelection[0]?.filters);
  return {
    ...buildTimeSeriesBreakdownVariables(resolvedDataSelection, config, parameters),
    types: entityTypes.length > 0 ? entityTypes : DATA_SELECTION_TYPES,
  };
};

const selectBreakdown = (data: StixCoreObjectsTimeSeriesBreakdownQuery['response']) => data.stixCoreObjectsTimeSeriesBreakdown;

/**
 * Entities time series widget drawing one series per value of `parameters.breakdownBy`.
 */
const StixCoreObjectsTimeSeriesBreakdown = (props: TimeSeriesBreakdownVizProps) => (
  <TimeSeriesBreakdownViz<StixCoreObjectsTimeSeriesBreakdownQuery>
    {...props}
    query={stixCoreObjectsTimeSeriesBreakdownQuery}
    buildQueryVariables={buildQueryVariables}
    selectBreakdown={selectBreakdown}
  />
);

export default StixCoreObjectsTimeSeriesBreakdown;
