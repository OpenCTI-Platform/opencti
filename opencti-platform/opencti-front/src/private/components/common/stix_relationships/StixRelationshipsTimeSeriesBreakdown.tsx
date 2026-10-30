import React from 'react';
import { graphql } from 'react-relay';
import TimeSeriesBreakdownViz, { buildTimeSeriesBreakdownVariables, TimeSeriesBreakdownVizProps } from '../../../../components/dashboard/TimeSeriesBreakdownViz';
import { WidgetDataSelection, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { getBreakdownEntityTypes } from '../../../../utils/widget/widgetBreakdown';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import { StixRelationshipsTimeSeriesBreakdownQuery } from './__generated__/StixRelationshipsTimeSeriesBreakdownQuery.graphql';

const stixRelationshipsTimeSeriesBreakdownQuery = graphql`
  query StixRelationshipsTimeSeriesBreakdownQuery(
    $field: String!
    $dateAttribute: String
    $startDate: DateTime!
    $endDate: DateTime
    $interval: String!
    $limit: Int
    $order: OrderingMode
    $includeOther: Boolean
    $relationship_type: [String!]
    $filters: FilterGroup
    $dynamicFrom: FilterGroup
    $dynamicTo: FilterGroup
  ) {
    stixRelationshipsTimeSeriesBreakdown(
      field: $field
      dateAttribute: $dateAttribute
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      limit: $limit
      order: $order
      includeOther: $includeOther
      relationship_type: $relationship_type
      filters: $filters
      dynamicFrom: $dynamicFrom
      dynamicTo: $dynamicTo
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

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
): StixRelationshipsTimeSeriesBreakdownQuery['variables'] => {
  const [selection] = resolvedDataSelection;
  // The API checks the field against these types; without them, every relationship is broken down
  const relationshipTypes = getBreakdownEntityTypes(selection?.filters, 'relationships');
  return {
    // Restricted to the relationships the widgets can display, as the relationships time series
    ...buildTimeSeriesBreakdownVariables(resolvedDataSelection, config, parameters, { isKnowledgeRelationshipWidget: true }),
    relationship_type: relationshipTypes.length > 0 ? relationshipTypes : null,
    // The displayed side of the widget plays no part in a time series: only the dynamic source and target do
    dynamicFrom: normalizeFilterGroupForBackend(selection?.dynamicFrom),
    dynamicTo: normalizeFilterGroupForBackend(selection?.dynamicTo),
  };
};

const selectBreakdown = (data: StixRelationshipsTimeSeriesBreakdownQuery['response']) => data.stixRelationshipsTimeSeriesBreakdown;

/**
 * Relationships time series widget drawing one series per value of `parameters.breakdownBy`.
 */
const StixRelationshipsTimeSeriesBreakdown = (props: TimeSeriesBreakdownVizProps) => (
  <TimeSeriesBreakdownViz<StixRelationshipsTimeSeriesBreakdownQuery>
    {...props}
    query={stixRelationshipsTimeSeriesBreakdownQuery}
    buildQueryVariables={buildQueryVariables}
    selectBreakdown={selectBreakdown}
  />
);

export default StixRelationshipsTimeSeriesBreakdown;
