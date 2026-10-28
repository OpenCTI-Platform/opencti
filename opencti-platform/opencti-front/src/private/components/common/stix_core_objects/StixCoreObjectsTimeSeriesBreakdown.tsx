import React from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetTimeSeriesBreakdownViz, { type TimeSeriesBreakdownWidgetProps } from '../../../../components/dashboard/WidgetTimeSeriesBreakdownViz';
import { WidgetDataSelection, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates, computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';
import { getWidgetInterval } from '../../../../utils/widget/widgetUtils';
import {
  getBreakdownDefaultStartDate,
  getBreakdownEntityTypes,
  getWidgetBreakdownLimit,
  getWidgetBreakdownOrder,
  getWidgetBreakdownOther,
  isBreakdownField,
} from 'src/utils/widget/widgetBreakdown';
import { now } from '../../../../utils/Time';
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
  );
  // The API checks the field against these types: send the ones the filters restrict to
  const entityTypes = getBreakdownEntityTypes(selection?.filters);
  return {
    field: breakdownBy,
    dateAttribute,
    startDate,
    endDate,
    interval,
    limit: getWidgetBreakdownLimit(parameters),
    order: getWidgetBreakdownOrder(parameters),
    includeOther: getWidgetBreakdownOther(parameters),
    types: entityTypes.length > 0 ? entityTypes : DATA_SELECTION_TYPES,
    filters,
  };
};

/**
 * Entities time series widget drawing one series per value of `parameters.breakdownBy`.
 */
const StixCoreObjectsTimeSeriesBreakdown = (props: TimeSeriesBreakdownWidgetProps) => {
  const { t_i18n } = useFormatter();
  return (
    <WidgetTimeSeriesBreakdownViz<StixCoreObjectsTimeSeriesBreakdownQuery>
      {...props}
      perspective="entities"
      query={stixCoreObjectsTimeSeriesBreakdownQuery}
      buildQueryVariables={buildQueryVariables}
      getBreakdown={(response) => response.stixCoreObjectsTimeSeriesBreakdown}
      defaultTitle={t_i18n('Entities history')}
    />
  );
};

export default StixCoreObjectsTimeSeriesBreakdown;
